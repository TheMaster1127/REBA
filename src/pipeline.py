import sys
import re
import json
import time
import shutil
import hashlib
import traceback
import subprocess
from pathlib import Path

from src.config import (
    BASE, PROMPT_FILE, HTRE_CLI, OUT_DIR, CHECKPOINTS_BASE,
    MAX_ANALYSIS_BYTES, MAX_CHUNK_BYTES, MAX_FUNCS_PER_CHUNK,
    MAX_HISTORY, MAX_ITERATIONS, MAX_FORMAT_RETRIES
)
from src.tracker import SessionTracker
from src.sandbox import SafeSandbox
from src.api import load_key, chat_with_payload, parse_json_reply, validate_schema
from src.oracle import run_byte_oracle, parse_overall_pct
from src.verifier import build_tester_context, request_adversarial_tests, run_differential_fuzz
from src.graph import build_user_functions_and_graph, topological_sort_batches, pack_chunks_for_reconstruction
from src.builder import setup_modular_output_dirs
from src.chunker import reconstruct_chunk_with_autosplit, count_uncached_chunk_calls, record_compiler_error
from src.validator import assess_binary_feasibility
from src.memory import (
    extract_safe_oracle_chunks, extract_safe_compiler_errors, pick_diverse_failures,
    load_failure_memory_hints, record_failure_memory, record_attempt_memory,
    load_warmstart_closest_winner, build_anchored_messages
)
from src.winner import (
    calc_pass_pct, score_candidate, apply_file_patches,
    save_best_output
)

def build_chunks_preview(extra_files: dict, max_total_bytes: int = 80_000) -> str:
    """
    Shows helper chunk implementations to main() so it never calls broken stubs or crashing
    helpers blindly. Prioritizes highest-numbered chunks (direct callees of main) first.
    """
    chunk_items = sorted(
        [(rel, txt) for rel, txt in extra_files.items() if rel.startswith("src/chunk_")],
        key=lambda x: x[0],
        reverse=True
    )
    selected = []
    used_bytes = 0
    for rel, txt in chunk_items:
        if used_bytes + len(txt) <= max_total_bytes or not selected:
            selected.append((rel, txt))
            used_bytes += len(txt)
        else:
            selected.append((rel, f"/* [Omitted {len(txt)} bytes due to 80KB preview cap; see declarations in reba_chunks.h] */"))
    selected.sort(key=lambda x: x[0])
    return "\n\n".join(f"--- {rel} ---\n{txt}" for rel, txt in selected)

def run_pipeline(args):
    original = Path(args.binary).resolve()
    if not original.exists():
        sys.exit(f"error: {original} not found")

    for f, name in [(HTRE_CLI, "htre_cli.py"), (BASE / "the_oracle.py", "the_oracle.py"), (PROMPT_FILE, "prompt.txt")]:
        if not f.exists():
            sys.exit(f"error: {name} not found at {f}")

    orig_sha256 = hashlib.sha256(original.read_bytes()).hexdigest()
    prot_dir  = BASE / ".reba_originals"
    prot_dir.mkdir(exist_ok=True)
    protected = prot_dir / f"{original.name}_{orig_sha256[:16]}"
    if not protected.exists():
        shutil.copy2(original, protected)

    chk_dir = CHECKPOINTS_BASE / f"{original.name}_{orig_sha256[:16]}"
    if args.clean and chk_dir.exists():
        shutil.rmtree(chk_dir)
        print(f"[*] Cleared previous checkpoints for {original.name}")
    chk_dir.mkdir(parents=True, exist_ok=True)

    OUT_DIR.mkdir(exist_ok=True)
    src_out_dir, inc_out_dir = setup_modular_output_dirs()
    api_key = load_key()
    prompt  = PROMPT_FILE.read_text()

    session = SessionTracker(original.stem, sys.argv, orig_sha256)
    session.log(f"[*] target binary -> {protected.relative_to(BASE)} (sha256={orig_sha256})")
    session.log(f"[*] checkpoint dir -> {chk_dir.relative_to(BASE)}")
    sandbox = SafeSandbox(session)

    session_best = None
    extra_files = {}
    final_hdr = ""
    warmstart = None
    prev_cw_score = None
    best_anchor = None

    try:
        t_ext0 = time.time()
        session.log(f"[*] extracting from {original.name} via Kuna / HTRE...")
        session.event("EXTRACTION_START", "Running htre_cli.py")

        htre_cmd = ["python", str(HTRE_CLI), str(original), "--raw", "--stdout"]
        if args.func:
            htre_cmd.extend(["--func", args.func])
        r = subprocess.run(htre_cmd, capture_output=True, text=True, timeout=1800, cwd=BASE)
        analysis = r.stdout
        if not analysis.strip():
            session.log(f"error: htre_cli produced no stdout\n{r.stderr}")
            session.finalize("error_extraction")
            sys.exit(1)
        session.log(f"[*] extracted {len(analysis):,} bytes")

        decomp_cmd = ["python", str(HTRE_CLI), str(original), "--only-decomp", "--stdout"]
        if args.func:
            decomp_cmd.extend(["--func", args.func])
        r_dec = subprocess.run(decomp_cmd, capture_output=True, text=True, timeout=120, cwd=BASE)
        tester_context = build_tester_context(analysis, r_dec.stdout)

        decomp_hdr_cmd = ["python", str(HTRE_CLI), str(original), "--no-info", "--no-sections", "--no-strings", "--no-disasm", "--stdout"]
        r_hdr = subprocess.run(decomp_hdr_cmd, capture_output=True, text=True, timeout=120, cwd=BASE)
        ext_elapsed = time.time() - t_ext0

        session.log_extraction(prompt, htre_cmd, r.returncode, r.stderr, analysis, decomp_cmd, r_dec.stdout, r_dec.stderr, tester_context, ext_elapsed)
        session.event("EXTRACTION_DONE", "Extraction ready", {"elapsed_s": round(ext_elapsed, 3)})

        nm_cmd = ["python", str(HTRE_CLI), str(original), "--list-funcs"]
        r_nm = subprocess.run(nm_cmd, capture_output=True, text=True, cwd=BASE)
        all_func_addrs = [m.group(1).lstrip('0') or '0' for line in r_nm.stdout.splitlines() if (m := re.match(r'^\s*0x([0-9a-fA-F]+)\s*:', line))]

        text_funcs, call_graph, main_addr, reachable = build_user_functions_and_graph(analysis, r_hdr.stdout, all_func_addrs)
        batches = topological_sort_batches(call_graph)

        session.log(f"[*] Call Graph Mapped: {len(text_funcs)} .text functions ({len(reachable)} reachable, {len(text_funcs) - len(reachable)} startup/aux)")
        for b_idx, batch in enumerate(batches):
            names = [f"{text_funcs[a]['name']}(0x{a}){'' if a in reachable else '[aux]'}" for cl in batch for a in cl]
            session.log(f"    Stage {b_idx}: {names}")

        if not args.skip_feasibility and not args.func:
            f_report = assess_binary_feasibility(analysis, r_dec.stdout, text_funcs)
            session.report["feasibility"] = {"passed": f_report.passed, "reason": f_report.reason, "details": f_report.details}
            if not f_report.passed:
                session.log(f"\n[!] PRE-FLIGHT FEASIBILITY CHECK: REJECTED\n[!] {f_report.reason}")
                session.log("[!] Run with --func <addr> to isolate smaller pieces, or --skip-feasibility to override.")
                session.finalize("feasibility_rejected")
                sys.exit(1)
            session.log("[+] Pre-flight feasibility check: PASSED (all functions within model synthesis envelopes).")

        is_chunked = (args.chunked or len(analysis) > MAX_ANALYSIS_BYTES) and (len(text_funcs) > 1) and (not args.func)
        ext = ".cpp" if "Language          : C++" in analysis else ".c"
        accumulated_headers = (
            "#ifndef REBA_CHUNKS_H\n#define REBA_CHUNKS_H\n"
            "#include <stdbool.h>\n#include <stdint.h>\n#include <stddef.h>\n"
        )
        root_analysis_content = analysis
        root_system_prompt = prompt

        cached_suite1_file = chk_dir / "stage_1_tests.json"
        cached_suite_1 = json.loads(cached_suite1_file.read_text(encoding="utf-8")) if cached_suite1_file.exists() else None
        has_cached_s1 = cached_suite_1 is not None

        warmstart = load_warmstart_closest_winner(chk_dir, ext, args.func)
        if warmstart:
            prev_cw_score = warmstart["score"]
            best_anchor = {
                "info": warmstart["info"],
                "score": warmstart["score"],
                "main_code": warmstart["main_code"],
                "file_patches": warmstart["patched_extra"],
                "failures": warmstart["failures"],
                "fail_stage": warmstart["fail_stage"],
            }
            wi = warmstart["info"]
            ws1 = wi["stage_1"]
            ws2 = wi.get("stage_2")
            ws2_txt = f" | Stage 2: {ws2['passed']}/{ws2['total']} ({ws2['pass_pct']:.2f}%)" if ws2 else ""
            session.log(f"[+] WARM-START: Loaded previous Closest Winner from checkpoint (Stage 1: {ws1['passed']}/{ws1['total']} ({ws1['pass_pct']:.2f}%){ws2_txt})")

        if is_chunked:
            session.log(f"\n[*] MULTI-PASS CHUNKED MODE ACTIVE (Chunk limit: {MAX_CHUNK_BYTES:,} bytes / max {MAX_FUNCS_PER_CHUNK} funcs)")
            aux_chunks, helper_chunks, root_addrs = pack_chunks_for_reconstruction(
                batches, text_funcs, main_addr, reachable, MAX_CHUNK_BYTES, MAX_FUNCS_PER_CHUNK
            )

            rem_aux = cached_aux = 0
            for a_idx, a_addrs in enumerate(aux_chunks, start=1):
                u, c = count_uncached_chunk_calls(f"aux_{a_idx}", a_addrs, ext, chk_dir)
                rem_aux += u
                cached_aux += c
            rem_helpers = cached_helpers = 0
            for c_idx, c_addrs in enumerate(helper_chunks, start=1):
                u, c = count_uncached_chunk_calls(f"chunk_{c_idx}", c_addrs, ext, chk_dir)
                rem_helpers += u
                cached_helpers += c

            session.set_api_plan(
                True, len(aux_chunks), len(helper_chunks), MAX_ITERATIONS, MAX_FORMAT_RETRIES,
                rem_aux=rem_aux, cached_aux=cached_aux,
                rem_helpers=rem_helpers, cached_helpers=cached_helpers,
                cached_stage1_tests=has_cached_s1
            )
            total_passes = len(aux_chunks) + len(helper_chunks) + 1
            pass_counter = 0

            reachable_text = "".join(text_funcs[a]["decomp"] + text_funcs[a]["disasm"] for a in text_funcs if a in reachable)
            for a_idx, a_addrs in enumerate(aux_chunks, start=1):
                pass_counter += 1
                session.log(f"\n[*] --- PASS {pass_counter}/{total_passes} (Startup Audit): {[text_funcs[a]['name'] for a in a_addrs]} ---")
                ok, solved = reconstruct_chunk_with_autosplit(
                    f"aux_{a_idx}", a_addrs, text_funcs, accumulated_headers + "\n#endif\n",
                    ext, True, api_key, sandbox, session, chk_dir
                )
                if not ok:
                    session.finalize("chunk_failed")
                    sys.exit(1)
                for lbl, hdr, code in solved:
                    aux_defs = re.findall(r'^(?!extern\b)[^\n;]*\b(sub_[0-9a-fA-F]+)\s*\([^;{]*\)\s*\{', code, re.MULTILINE)
                    has_ctor = bool(re.search(r'__attribute__\s*\(\s*\(\s*constructor', code))
                    if has_ctor or any(re.search(rf'\b{fn}\b', reachable_text) for fn in aux_defs):
                        accumulated_headers += f"\n/* Startup/Aux {lbl} */\n{hdr}\n"
                        extra_files[f"src/{lbl}{ext}"] = code
                    else:
                        session.log(f"    [*] {lbl} has no constructors and is unreferenced by reachable code; excluded from link.")

            for c_idx, c_addrs in enumerate(helper_chunks, start=1):
                pass_counter += 1
                session.log(f"\n[*] --- PASS {pass_counter}/{total_passes} (Helpers): {[text_funcs[a]['name'] for a in c_addrs]} ---")
                ok, solved = reconstruct_chunk_with_autosplit(
                    f"chunk_{c_idx}", c_addrs, text_funcs, accumulated_headers + "\n#endif\n",
                    ext, False, api_key, sandbox, session, chk_dir
                )
                if not ok:
                    session.finalize("chunk_failed")
                    sys.exit(1)
                for lbl, hdr, code in solved:
                    accumulated_headers += f"\n/* Chunk {lbl} */\n{hdr}\n"
                    extra_files[f"src/{lbl}{ext}"] = code

            if helper_chunks or extra_files:
                final_hdr = accumulated_headers + "\n#endif\n"
                if extra_files:
                    extra_files["include/reba_chunks.h"] = final_hdr

                if warmstart and warmstart["patched_extra"]:
                    for rel_p, patched_txt in warmstart["patched_extra"].items():
                        if rel_p in extra_files:
                            extra_files[rel_p] = patched_txt
                    final_hdr = extra_files.get("include/reba_chunks.h", final_hdr)
                    session.log("[+] Warm-start loaded patched modular files from closest_winner/modular/")

                chunks_preview = build_chunks_preview(extra_files, max_total_bytes=80_000)

                root_parts = [f"=== ROOT FUNCTION {text_funcs[a]['name']} (0x{a}) ===\n--- KUNA DECOMP ---\n{text_funcs[a]['decomp']}\n\n--- DISASM ---\n{text_funcs[a]['disasm']}\n" for a in root_addrs]
                str_lines = [l for l in analysis.splitlines() if re.match(r'^\[0x[0-9a-fA-F]+\]', l)]
                root_analysis_content = (
                    f"=== TARGET METADATA ===\n" + "\n".join(analysis.splitlines()[:10]) + "\n\n"
                    f"=== STRINGS ===\n" + "\n".join(str_lines[:250]) + "\n\n"
                    f"=== ALREADY SOLVED HELPER CHUNKS (`#include \"reba_chunks.h\"`) ===\n"
                    f"Available project files: {sorted(extra_files.keys())}\n"
                    f"The linker uses `-Wl,--allow-multiple-definition`. You can call helpers from `reba_chunks.h`,\n"
                    f"override any buggy helper directly in `main.c` (MUST be non-static & non-inline!), OR patch any chunk/header directly using `\"file_patches\"`!\n"
                    f"```c\n{final_hdr}\n```\n\n"
                    + (f"=== HELPER CHUNK IMPLEMENTATIONS (INSPECT FOR STUBS OR BAD POINTER OFFSETS!) ===\n{chunks_preview}\n\n" if chunks_preview else "") +
                    f"=== ROOT FUNCTIONS TO IMPLEMENT NOW ===\n" + "\n".join(root_parts)
                )
                root_system_prompt = (
                    "You are reconstructing the entry/main module of a program.\n"
                    "1. Helper functions are compiled via `reba_chunks.h`, EXCEPT beware of helper chunks that are empty `{0}` stubs or fragile raw pointer-offset lifts (like `sub_8ed0` reconstructing gnulib `argp` structs)!\n"
                    "2. TWO WAYS TO FIX BUGGY CHUNKS: (a) Override any buggy `sub_XXXX` as a NON-STATIC, NON-INLINE function in your `code` (linker uses `-Wl,--allow-multiple-definition`), OR (b) supply optional `\"file_patches\": {\"src/chunk_X.c\": \"full fixed file\", \"include/reba_chunks.h\": \"...\"}` in your candidate JSON.\n"
                    "3. Look closely at `stdout_diff` and `stderr_diff` on failing tests—do NOT ignore 1-char capitalization differences (e.g. 'give' vs 'Give' in argp)!\n"
                    "4. For shared globals (like `program_name` or `dat_d318`), declare `extern` if defined in `reba_chunks.h`.\n"
                    "5. Keep internal reasoning concise (under 2,000 tokens). Provide 1 clean candidate with 1-5 compile commands.\n"
                    "Reply ONLY with JSON: {\"candidates\": [{\"code\": \"...\", \"compile_commands\": [\"...\"], \"file_patches\": {}}]}"
                )
                session.log(f"\n[*] --- FINAL PASS {total_passes}/{total_passes} (Root / main) ---")
        else:
            session.set_api_plan(False, 0, 0, MAX_ITERATIONS, MAX_FORMAT_RETRIES, cached_stage1_tests=has_cached_s1)

        failure_mem_block = load_failure_memory_hints(chk_dir)
        if failure_mem_block:
            root_analysis_content += f"\n\n{failure_mem_block}"

        attempt_num = 0
        latest_feedback = None
        next_reason = "Initial reconstruction attempt (warm-started from checkpoint)" if warmstart else "Initial reconstruction attempt"

        def consider_best_overall(cc: dict, failures: list, fail_stage: int) -> bool:
            """Updates session_best and checkpointed closest_winner; returns True if this is a new best anchor."""
            nonlocal session_best, prev_cw_score, best_anchor
            sc = score_candidate(cc)
            if session_best is None or sc >= session_best[0]:
                session_best = (sc, cc)
            is_new_best = (prev_cw_score is None or sc >= prev_cw_score)
            if is_new_best:
                prev_cw_score = sc
                from src.winner import save_closest_winner_checkpoint
                _, info, _, _ = save_closest_winner_checkpoint(
                    chk_dir, cc, sandbox, session,
                    is_final_winner=bool(cc.get("stage_1_res", {}).get("all_passed") and cc.get("stage_2_res", {}).get("all_passed")),
                    func_filter=args.func
                )
                best_anchor = {
                    "info": info,
                    "score": sc,
                    "main_code": cc["code"],
                    "file_patches": cc.get("file_patches") or {},
                    "failures": failures,
                    "fail_stage": fail_stage,
                }
                record_failure_memory(chk_dir, failures, stage=fail_stage, replace=True)
            return is_new_best

        while attempt_num < MAX_ITERATIONS:
            attempt_num += 1
            iter_t0 = time.time()
            session.log(f"\n{'=' * 60}\nATTEMPT {attempt_num} of {MAX_ITERATIONS} ({MAX_ITERATIONS - attempt_num} remaining)\n{'=' * 60}")

            base_messages = build_anchored_messages(
                root_system_prompt, root_analysis_content, best_anchor, latest_feedback, chk_dir, ext
            )
            data, reply, pt, ct, llm_elapsed = None, "", 0, 0, 0.0
            retry_messages = list(base_messages)
            for fmt_try in range(MAX_FORMAT_RETRIES + 1):
                if len(retry_messages) > MAX_HISTORY:
                    retry_messages = retry_messages[:2] + retry_messages[-(MAX_HISTORY - 2):]
                req_payload = {"model": session.report["model"], "messages": retry_messages, "stream": False}
                session.init_iteration_request(attempt_num, fmt_try, req_payload, next_reason)
                session.log("[*] asking DeepSeek for candidate..." if fmt_try == 0 else f"[*] free JSON retry ({fmt_try}/{MAX_FORMAT_RETRIES})...")

                t0 = time.time()
                resp = chat_with_payload(api_key, req_payload)
                llm_elapsed += (time.time() - t0)
                finish_reason = resp["choices"][0].get("finish_reason", "")
                reply, _, r_pt, r_ct = session.log_llm_reply(attempt_num, fmt_try, resp, time.time() - t0)
                pt += r_pt; ct += r_ct
                session.log(f"[API Call #{session.report['api_calls']['total']}] received in {time.time() - t0:.1f}s (+{r_pt} in / +{r_ct} out, finish={finish_reason})")

                if finish_reason == "length":
                    retry_messages = list(base_messages) + [{"role": "user", "content": "Cut off at 65k tokens! Keep thinking under 1,000 tokens and output compact JSON."}]
                    continue
                parsed, err = parse_json_reply(reply)
                if parsed is None:
                    retry_messages = list(base_messages) + [{"role": "user", "content": f"Invalid JSON ({err}). Reply JSON ONLY."}]
                    continue
                serr = validate_schema(parsed)
                if serr:
                    retry_messages = list(base_messages) + [{"role": "user", "content": f"Schema error ({serr}). Output valid JSON."}]
                    continue
                data = parsed
                break

            if data is None:
                continue

            compiled_candidates, results = [], []
            for ci, cand in enumerate(data["candidates"]):
                code, cmds = cand["code"], cand["compile_commands"]
                file_patches = cand.get("file_patches") or {}
                cand_extra_files, cand_hdr = apply_file_patches(extra_files, file_patches)
                cand_ext = ".rs" if any("rustc" in c for c in cmds) else ext
                src_name, cand_out_name = f"reba_src{cand_ext}", f"reba_cand_{ci + 1}_out"
                cand_out_path = BASE / cand_out_name
                session.log_candidate_code(attempt_num, ci, cand_ext, code)
                best_cmd, best_pct, best_hash, best_oracle = None, -1.0, False, ""

                for cmd_i, raw_cmd in enumerate(cmds):
                    comp_res = sandbox.compile_multi_file(raw_cmd, code, src_name, cand_extra_files, cand_out_name, out_dest_path=cand_out_path)
                    if not comp_res["ok"]:
                        session.log(f"    [{ci + 1}.{cmd_i + 1}] COMPILE FAILED ({comp_res['compile_ms']:.0f}ms)")
                        record_compiler_error(chk_dir, comp_res["stderr"])
                        session.log_compile_and_oracle(attempt_num, ci, cmd_i, raw_cmd, comp_res["code"], comp_res["stdout"], comp_res["stderr"], comp_res["compile_ms"], "", 0.0, 0.0, False)
                        results.append({"ci": ci, "cmd_i": cmd_i, "cmd": raw_cmd, "ok": False, "compile_ms": comp_res["compile_ms"], "err": comp_res["stderr"]})
                        continue

                    t_o0 = time.time()
                    oracle_out = run_byte_oracle(protected, cand_out_path)
                    oracle_ms = (time.time() - t_o0) * 1000.0
                    pct = parse_overall_pct(oracle_out)
                    hash_eq = ("Hash equal: True" in oracle_out) or ("code_identical" in oracle_out)
                    session.log(f"    [{ci + 1}.{cmd_i + 1}] byte: {pct:.2f}% | code_identical={hash_eq} (compile {comp_res['compile_ms']:.0f}ms, oracle {oracle_ms:.0f}ms)")
                    session.log_compile_and_oracle(attempt_num, ci, cmd_i, raw_cmd, comp_res["code"], comp_res["stdout"], comp_res["stderr"], comp_res["compile_ms"], oracle_out, oracle_ms, pct, hash_eq)
                    results.append({"ci": ci, "cmd_i": cmd_i, "cmd": raw_cmd, "ok": True, "compile_ms": comp_res["compile_ms"], "oracle_ms": oracle_ms, "overall_pct": pct, "hash_equal": hash_eq, "oracle_out": oracle_out})

                    if (int(hash_eq), pct) > (int(best_hash), best_pct):
                        best_pct, best_hash, best_cmd, best_oracle = pct, hash_eq, raw_cmd, oracle_out

                if best_cmd and cand_out_path.exists():
                    compiled_candidates.append({
                        "attempt_num": attempt_num, "ci": ci, "code": code, "cmd": best_cmd,
                        "cand_ext": cand_ext, "bin_path": cand_out_path,
                        "oracle_pct": best_pct, "hash_eq": best_hash, "oracle_out": best_oracle,
                        "extra_files": cand_extra_files, "final_hdr": cand_hdr, "file_patches": file_patches
                    })

            session.finish_iteration(attempt_num, results, time.time() - iter_t0, llm_elapsed, pt, ct)

            if not compiled_candidates:
                err_samples = "\n\n".join(f"Command: {r['cmd']}\nError:\n{extract_safe_compiler_errors(r.get('err', ''))}" for r in results[:2])
                session.log(f"[!] All candidates failed to compile:\n{err_samples}")
                first_err = extract_safe_compiler_errors(results[0].get("err", "")).splitlines()[0] if results else "error"
                record_attempt_memory(chk_dir, f"Compile FAILED: {first_err}")
                next_reason = "All candidates failed compilation; feeding exact gcc errors back"
                latest_feedback = f"Your last attempt FAILED compilation/linking:\n\n{err_samples}\n\nFix these exact errors (or revert to the CURRENT BEST ANCHOR CANDIDATE above and make a smaller fix). Reply JSON only."
                continue

            if cached_suite_1 is None:
                session.log("\n[*] Generating Stage 1 Adversarial Test Suite (cached for all attempts)...")
                cached_suite_1, t_gen1 = request_adversarial_tests(api_key, tester_context, session, attempt_num, stage=1)
                cached_suite1_file.write_text(json.dumps(cached_suite_1, indent=2), encoding="utf-8")
            else:
                session.log(f"\n[*] Reusing cached Stage 1 Test Suite ({len(cached_suite_1)} tests, 0 API calls)...")
                t_gen1 = 0.0

            stage_1_survivors = []
            for cc in compiled_candidates:
                ci = cc["ci"]
                res_1, t_exec1 = run_differential_fuzz(protected, cc["bin_path"], cached_suite_1, sandbox, session, attempt_num, stage=1, cand_idx=ci+1)
                cc["stage_1_res"] = res_1
                s1_pct = calc_pass_pct(res_1)
                session.log_verification_summary(attempt_num, 1, ci + 1, res_1, t_gen1, t_exec1)
                session.log(f"     Candidate #{ci + 1}: {res_1['passed']}/{res_1['total']} passed ({s1_pct:.2f}%, {t_exec1:.2f}s)")
                if res_1["all_passed"]:
                    stage_1_survivors.append(cc)

            any_new_best = False
            for cc in compiled_candidates:
                if not cc["stage_1_res"]["all_passed"]:
                    if consider_best_overall(cc, cc["stage_1_res"]["failures"], fail_stage=1):
                        any_new_best = True

            stage_1_survivors.sort(key=lambda c: (int(c["hash_eq"]), c["oracle_pct"]), reverse=True)
            if stage_1_survivors:
                top_cand = stage_1_survivors[0]
                ci = top_cand["ci"]
                session.log(f"\n[+] Candidate #{ci + 1} PASSED 100% of Stage 1! Running Stage 2...")
                suite_2, t_gen2 = request_adversarial_tests(api_key, tester_context, session, attempt_num, previous_passed_tests=cached_suite_1, stage=2)
                res_2, t_exec2 = run_differential_fuzz(protected, top_cand["bin_path"], suite_2, sandbox, session, attempt_num, stage=2, cand_idx=ci+1)
                top_cand["stage_2_res"] = res_2
                s2_pct = calc_pass_pct(res_2)
                session.log_verification_summary(attempt_num, 2, ci + 1, res_2, t_gen2, t_exec2)
                session.log(f"[*] Stage 2: {res_2['passed']}/{res_2['total']} passed ({s2_pct:.2f}%, {t_exec2:.2f}s).")

                consider_best_overall(top_cand, res_2["failures"], fail_stage=2)

                if res_2["all_passed"]:
                    record_attempt_memory(chk_dir, "Stage 1: 100%, Stage 2: 100% (FULL WINNER)")
                    session.log("\n" + "#" * 60 + "\n[+] FULL BEHAVIORAL PROOF ACHIEVED!\n" + "#" * 60)
                    sc, wext = save_best_output(original.stem, top_cand, src_out_dir, inc_out_dir, sandbox, session, chk_dir, is_final_winner=True, func_filter=args.func, update_checkpoint=True)
                    session.finalize("success", winner_code=sc, winner_ext=wext)
                    return
                else:
                    record_attempt_memory(chk_dir, f"Stage 1: 100%, Stage 2: {res_2['passed']}/{len(suite_2)} ({s2_pct:.2f}%)")
                    next_reason = f"Failed Stage 2 ({res_2['passed']}/{len(suite_2)} passed, {s2_pct:.2f}%)"
                    fail_info = json.dumps(pick_diverse_failures(res_2["failures"], 8), indent=2)
                    latest_feedback = f"Passed Stage 1 (100%), FAILED Stage 2 edge cases ({res_2['passed']}/{len(suite_2)}, {s2_pct:.2f}%):\n{fail_info}\n\nFix these Stage 2 differences without breaking Stage 1! Reply JSON only."
            else:
                compiled_candidates.sort(key=score_candidate, reverse=True)
                top_cand = compiled_candidates[0]
                res_fail = top_cand["stage_1_res"]
                s1_pct = calc_pass_pct(res_fail)
                failed_nums = [f"#{f['test_num']}({repr(f.get('args', []))})" for f in res_fail["failures"][:6]]
                record_attempt_memory(chk_dir, f"Stage 1: {res_fail['passed']}/{res_fail['total']} ({s1_pct:.2f}%), failing={', '.join(failed_nums)}")
                next_reason = f"Failed Stage 1 ({res_fail['passed']}/{res_fail['total']} passed, {s1_pct:.2f}%)"
                fail_info = json.dumps(pick_diverse_failures(res_fail["failures"], 8), indent=2)
                diff_clean = extract_safe_oracle_chunks(top_cand["oracle_out"], max_chunks=3)
                sigsegv_hint = ""
                if any(f.get("cand", {}).get("code") == 139 for f in res_fail["failures"]):
                    sigsegv_hint = (
                        "\nCRITICAL: Candidate CRASHED with SIGSEGV (rc=139)! "
                        "A helper chunk (such as `sub_8ed0` in `chunk_5.c`) is likely dereferencing a wrong struct offset or NULL pointer! "
                        "DO NOT call the crashing helper chunk—override it cleanly using standard `<argp.h>` / C logic in your `code` or replace it via `\"file_patches\"`!\n"
                    )
                if not any_new_best and best_anchor is not None:
                    anchor_s1 = best_anchor["info"]["stage_1"]
                    latest_feedback = (
                        f"REGRESSION ALERT: Your last experiment dropped to {res_fail['passed']}/{res_fail['total']} ({s1_pct:.2f}%) "
                        f"(worse than CURRENT BEST ANCHOR at {anchor_s1['passed']}/{anchor_s1['total']} ({anchor_s1['pass_pct']:.2f}%)!).\n"
                        f"{sigsegv_hint}"
                        f"DISCARD that regression completely! Start directly from the CURRENT BEST ANCHOR CANDIDATE above and fix ONLY the anchor's remaining failures shown there.\nReply JSON only."
                    )
                else:
                    latest_feedback = (
                        f"Last attempt scored {res_fail['passed']}/{res_fail['total']} ({s1_pct:.2f}%) on Stage 1.\n"
                        f"{sigsegv_hint}"
                        f"Exact failures & diffs (`stdout_diff` / `stderr_diff`):\n{fail_info}\n\n"
                        f"Top Oracle Diff Chunks:\n{diff_clean}\n\n"
                        f"Inspect EVERY diff line carefully (including capitalization like 'give' vs 'Give', and exact stderr messages). "
                        f"Build on the CURRENT BEST ANCHOR CANDIDATE above and fix these exact bugs! Reply JSON only."
                    )

        session.log(f"\n[!] Maximum attempts ({MAX_ITERATIONS}) reached.")
        if session_best is not None:
            session_beat_prev = (warmstart is None) or (session_best[0] >= warmstart["score"])
            if session_beat_prev:
                session.log("[*] No 100% match found — selecting the CLOSEST WINNER by test pass percentage (most recent on tie).")
                sc, wext = save_best_output(original.stem, session_best[1], src_out_dir, inc_out_dir, sandbox, session, chk_dir, is_final_winner=False, func_filter=args.func, update_checkpoint=True)
            else:
                session.log("[*] This session's best did not beat the previous checkpointed Closest Winner; preserving previous Closest Winner in checkpoint!")
                sc, wext = save_best_output(original.stem, session_best[1], src_out_dir, inc_out_dir, sandbox, session, chk_dir, is_final_winner=False, func_filter=args.func, update_checkpoint=False)
                cw_file = warmstart["cw_dir"] / f"closest_winner{ext}"
                if cw_file.exists():
                    shutil.copy2(cw_file, OUT_DIR / f"closest_winner_{original.stem}{ext}")
            session.finalize("closest_winner", winner_code=sc, winner_ext=wext)
        else:
            session.finalize("max_iterations")

    except KeyboardInterrupt:
        session.log("\n[!] Interrupted by user (Ctrl+C).")
        if session_best is not None:
            session_beat_prev = (warmstart is None) or (session_best[0] >= warmstart["score"])
            session.log("[*] Saving this session's CLOSEST WINNER before interrupt...")
            sc, wext = save_best_output(original.stem, session_best[1], src_out_dir, inc_out_dir, sandbox, session, chk_dir, is_final_winner=False, func_filter=args.func, update_checkpoint=session_beat_prev)
            session.finalize("interrupted", winner_code=sc, winner_ext=wext)
        else:
            session.finalize("interrupted")
        sys.exit(130)
    except Exception as e:
        session.log(f"\n[!] Unhandled Exception: {e}\n{traceback.format_exc()}")
        session.finalize("crashed")
        raise
