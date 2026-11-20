import re
import json
import time
import hashlib
import difflib
import sys
from pathlib import Path
from src.config import MODEL
from src.tracker import SessionTracker
from src.sandbox import SafeSandbox
from src.api import chat_with_payload, parse_json_reply

def format_output_for_report(orig_s: str, cand_s: str, safety_cap: int = 4000) -> tuple[str, str]:
    """Keeps full output unless genuinely huge (>4KB), in which case centers around the first diff."""
    if len(orig_s) <= safety_cap and len(cand_s) <= safety_cap:
        return orig_s, cand_s
    limit = min(len(orig_s), len(cand_s))
    diff_idx = next((i for i in range(limit) if orig_s[i] != cand_s[i]), limit)
    start = max(0, diff_idx - 400)
    end = start + safety_cap
    pre = f"...[offset {start}]..." if start > 0 else ""
    return (
        pre + orig_s[start:end] + ("..." if len(orig_s) > end else ""),
        pre + cand_s[start:end] + ("..." if len(cand_s) > end else ""),
    )

def make_unified_diff_snippet(orig_s: str, cand_s: str) -> str:
    if orig_s == cand_s:
        return ""
    lines = list(difflib.unified_diff(
        orig_s.splitlines(), cand_s.splitlines(),
        fromfile="ORIG", tofile="CAND", lineterm="", n=1
    ))
    return "\n".join(lines[:40])

def build_tester_context(analysis_text: str, decomp_text: str) -> str:
    parts = []
    header_lines = analysis_text.splitlines()[:10]
    parts.append("=== METADATA ===\n" + "\n".join(header_lines))
    
    str_lines = [l for l in analysis_text.splitlines() if re.match(r'^\[0x[0-9a-fA-F]+\]', l)]
    if str_lines:
        parts.append("=== STRINGS ===\n" + "\n".join(str_lines[:250]))
        
    m_text = re.search(r'(Disassembly of section \.text:.*?)(?=\nDisassembly of section |\Z)', analysis_text, re.DOTALL)
    if m_text:
        text_lines = m_text.group(1).splitlines()[:1200]
        parts.append("=== .TEXT DISASSEMBLY ===\n" + "\n".join(text_lines))
        
    if decomp_text.strip():
        decomp_lines = decomp_text.splitlines()[:1200]
        parts.append("=== DECOMPILED C SOURCE (KUNA) ===\n" + "\n".join(decomp_lines))
        
    return "\n\n".join(parts)

def request_adversarial_tests(api_key: str, tester_context: str, session: SessionTracker,
                              iter_num: int, previous_passed_tests=None, stage=1):
    if stage == 1:
        why = "Generating Stage 1 exhaustive adversarial test suite from full binary logic"
        user_prompt = (
            "You are an adversarial testing engineer.\n"
            "Analyze the FULL program logic below (strings, .text assembly, and Kuna decompiled C).\n"
            "Craft an EXHAUSTIVE test suite that achieves 100% branch coverage.\n"
            "Rules:\n"
            "- Do NOT stop at 10-12 tests if the binary has multiple modes or switch cases!\n"
            "- Test EVERY subcommand/mode, EVERY individual switch case (e.g. 0,1,2,3,4,5,6,7 AND -1,-2,8,INT_MIN,INT_MAX).\n"
            "- Test EVERY error exit (missing args, invalid mode, missing files like /nonexistent, valid files like /dev/null).\n"
            "- Test boundary math (0, 1, overflows, division by zero, negative numbers).\n"
            "- If the binary reads stdin, craft valid AND invalid multi-line stdin sequences.\n"
            "- NEVER test /proc/self/* paths (e.g. /proc/self/cmdline, /proc/self/exe, /proc/self/maps).\n"
            "Output as many tests as needed (e.g., 20 to 60+ tests for multi-mode binaries).\n"
            "Reply ONLY with a JSON object:\n"
            "{\n"
            "  \"tests\": [\n"
            "    {\"args\": [\"arg1\", \"arg2\"], \"stdin\": \"\"},\n"
            "    {\"args\": [], \"stdin\": \"optional text\"}\n"
            "  ]\n"
            "}\n"
            "JSON ONLY. No markdown prose.\n\n"
            f"{tester_context}"
        )
    else:
        why = "Stage 1 passed 100%; generating Stage 2 harder edge-case test suite"
        passed_summary = json.dumps(previous_passed_tests[:40] if previous_passed_tests else [], indent=2)
        user_prompt = (
            "You are an adversarial testing engineer.\n"
            "Here is the program logic:\n"
            f"{tester_context}\n\n"
            "The candidate program PASSED all Stage 1 tests:\n"
            f"{passed_summary}\n\n"
            "Now POKE EVEN HARDER. Generate a SECOND, COMPLETELY DIFFERENT batch of 15 to 40+ extreme edge-case tests.\n"
            "Hunt specifically for subtle decompilation bugs:\n"
            "- Negative values passed to unsigned/switch bounds (e.g. -2, -5, -100, INT_MIN)\n"
            "- 64-bit integer overflows (LONG_MAX + 1, LONG_MIN - 1, LONG_MIN / -1)\n"
            "- Malformed strings, partial numeric strings (12abc), leading zeros/signs (+005, -0)\n"
            "- Weird whitespace, embedded nulls, Unicode, empty strings, extreme lengths\n"
            "- NEVER test /proc/self/* paths.\n"
            "- Any mode, case, or branch not thoroughly tortured in Stage 1.\n"
            "Reply ONLY with a JSON object:\n"
            "{\n"
            "  \"tests\": [\n"
            "    {\"args\": [\"extreme1\"], \"stdin\": \"\"}\n"
            "  ]\n"
            "}"
        )

    payload = {"model": MODEL, "messages": [{"role": "user", "content": user_prompt}], "stream": False}
    t_total0 = time.time()
    
    for attempt in range(1, 4):
        session.log_test_gen_request(iter_num, stage, attempt, payload, why)
        t_call0 = time.time()
        resp = chat_with_payload(api_key, payload)
        call_elapsed = time.time() - t_call0
        reply = session.log_test_gen_reply(iter_num, stage, attempt, resp, call_elapsed)
        
        data, err = parse_json_reply(reply)
        if data and "tests" in data and isinstance(data["tests"], list) and len(data["tests"]) > 0:
            session.log_parsed_tests(iter_num, stage, data["tests"])
            return data["tests"], time.time() - t_total0
        session.log(f"[!] Stage {stage} test generation JSON parse failed (attempt {attempt}/3), retrying...")

    session.event(f"ITER_{iter_num:02d}_TESTGEN_FAIL_S{stage}", "Failed to parse JSON test suite after 3 attempts")
    sys.exit(f"error: AI failed to produce valid JSON tests for Stage {stage} after 3 attempts.")

def run_differential_fuzz(orig_bin: Path, cand_bin: Path, test_cases: list, sandbox: SafeSandbox,
                          session: SessionTracker, iter_num: int, stage: int, cand_idx: int = 1):
    t_start = time.time()
    passed = 0
    failures = []
    
    jsonl_fp, txt_fp = session.open_test_streams(iter_num, stage, cand_idx)
    try:
        for idx, t in enumerate(test_cases):
            args = [str(a) for a in t.get("args", [])]
            stdin_str = t.get("stdin", "")
            stdin_bytes = stdin_str.encode("utf-8")
            
            r_orig = sandbox.execute(orig_bin, args, stdin_bytes)
            r_cand = sandbox.execute(cand_bin, args, stdin_bytes)
            
            if b"bwrap:" in r_orig["stderr"] or b"bwrap:" in r_cand["stderr"]:
                err_msg = r_orig["stderr"].decode(errors="replace")
                session.log(f"FATAL SANDBOX ERROR: {err_msg}")
                session.event("SANDBOX_ERROR", "bwrap execution failure", {"stderr": err_msg})
                sys.exit(f"FATAL SANDBOX ERROR: {err_msg}")

            match = (
                r_orig["code"] == r_cand["code"] and
                r_orig["stdout"] == r_cand["stdout"] and
                r_orig["stderr"] == r_cand["stderr"]
            )
            
            orig_out_str = r_orig["stdout"].decode("utf-8", errors="replace")
            orig_err_str = r_orig["stderr"].decode("utf-8", errors="replace")
            cand_out_str = r_cand["stdout"].decode("utf-8", errors="replace")
            cand_err_str = r_cand["stderr"].decode("utf-8", errors="replace")

            record = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "test_num": idx + 1,
                "passed": match,
                "args": args,
                "stdin": stdin_str,
                "orig": {
                    "code": r_orig["code"],
                    "timeout": r_orig["timeout"],
                    "duration_ms": r_orig["duration_ms"],
                    "stdout_sha256": hashlib.sha256(r_orig["stdout"]).hexdigest(),
                    "stdout": orig_out_str,
                    "stderr": orig_err_str,
                },
                "cand": {
                    "code": r_cand["code"],
                    "timeout": r_cand["timeout"],
                    "duration_ms": r_cand["duration_ms"],
                    "stdout_sha256": hashlib.sha256(r_cand["stdout"]).hexdigest(),
                    "stdout": cand_out_str,
                    "stderr": cand_err_str,
                }
            }
            jsonl_fp.write(json.dumps(record) + "\n")
            jsonl_fp.flush()
            
            status_tag = "PASS" if match else "FAIL"
            txt_fp.write(
                f"[Test #{idx+1:03d}] {status_tag} | orig_ms={r_orig['duration_ms']} cand_ms={r_cand['duration_ms']}\n"
                f"  ARGS : {args!r}\n"
                f"  STDIN: {stdin_str!r}\n"
                f"  ORIG (rc={r_orig['code']}): stdout={orig_out_str!r} stderr={orig_err_str!r}\n"
                f"  CAND (rc={r_cand['code']}): stdout={cand_out_str!r} stderr={cand_err_str!r}\n\n"
            )
            txt_fp.flush()
            
            if match:
                passed += 1
            else:
                orig_out_snip, cand_out_snip = format_output_for_report(orig_out_str, cand_out_str)
                orig_err_snip, cand_err_snip = format_output_for_report(orig_err_str, cand_err_str)
                fail_entry = {
                    "test_num": idx + 1,
                    "args": args,
                    "stdin": stdin_str,
                    "orig": {
                        "code": r_orig["code"],
                        "stdout": orig_out_snip,
                        "stderr": orig_err_snip,
                    },
                    "cand": {
                        "code": r_cand["code"],
                        "stdout": cand_out_snip,
                        "stderr": cand_err_snip,
                    }
                }
                out_diff = make_unified_diff_snippet(orig_out_str, cand_out_str)
                err_diff = make_unified_diff_snippet(orig_err_str, cand_err_str)
                if out_diff:
                    fail_entry["stdout_diff"] = out_diff
                if err_diff:
                    fail_entry["stderr_diff"] = err_diff
                failures.append(fail_entry)
    finally:
        jsonl_fp.close()
        txt_fp.close()
                
    exec_elapsed = time.time() - t_start
    return {
        "total": len(test_cases),
        "passed": passed,
        "all_passed": (passed == len(test_cases)),
        "failures": failures
    }, exec_elapsed
