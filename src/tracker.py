import sys
import json
import time
from pathlib import Path
from src.config import BASE, HISTORY_BASE, MODEL, API_URL

class SessionTracker:
    def __init__(self, binary_name: str, cli_args: list, binary_sha256: str):
        self.start_epoch = time.time()
        self.timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        self.session_dir = HISTORY_BASE / f"{binary_name}_{self.timestamp}"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_fp = open(self.session_dir / "session.log", "a", encoding="utf-8", buffering=1)
        self.timeline_txt_fp = open(self.session_dir / "timeline.txt", "a", encoding="utf-8", buffering=1)
        self.timeline_jsonl_fp = open(self.session_dir / "timeline.jsonl", "a", encoding="utf-8", buffering=1)
        
        self.report = {
            "target_binary": binary_name,
            "target_sha256": binary_sha256,
            "cli_invocation": cli_args,
            "cwd": str(Path.cwd()),
            "python_version": sys.version,
            "model": MODEL,
            "api_url": API_URL,
            "session_start": self.timestamp,
            "status": "running",
            "sandbox_mode": "pending",
            "feasibility": {},
            "extraction": {},
            "api_calls_plan": {},
            "api_calls": {
                "total": 0,
                "startup_audit": 0,
                "helper_chunks": 0,
                "reconstructor": 0,
                "test_stage_1": 0,
                "test_stage_2": 0,
                "format_retries": 0
            },
            "chunks": [],
            "iterations": [],
            "verification_history": [],
            "closest_winner": None,
            "tokens": {
                "reconstructor_in": 0,
                "reconstructor_out": 0,
                "tester_in": 0,
                "tester_out": 0,
                "grand_total_in": 0,
                "grand_total_out": 0
            }
        }
        self._flush_report()
        self.log(f"[*] Session history initialized -> {self.session_dir.relative_to(BASE)}")
        self.event("SESSION_START", "Pipeline started", {"binary": binary_name, "sha256": binary_sha256})

    def log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        ms = int((time.time() % 1) * 1000)
        print(msg, flush=True)
        for line in str(msg).splitlines() or [""]:
            self.log_fp.write(f"[{ts}.{ms:03d}] {line}\n")
        self.log_fp.flush()

    def event(self, phase: str, why: str, data: dict = None):
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
        elapsed = round(time.time() - self.start_epoch, 3)
        entry = {
            "timestamp": now_iso,
            "elapsed_s": elapsed,
            "phase": phase,
            "why": why,
            "data": data or {}
        }
        self.timeline_jsonl_fp.write(json.dumps(entry) + "\n")
        self.timeline_jsonl_fp.flush()
        
        extra = f" | {json.dumps(data)}" if data else ""
        self.timeline_txt_fp.write(f"[{now_iso} | +{elapsed:7.3f}s] [{phase}] {why}{extra}\n")
        self.timeline_txt_fp.flush()

    def _flush_report(self):
        self.report["tokens"]["grand_total_in"] = (
            self.report["tokens"]["reconstructor_in"] + self.report["tokens"]["tester_in"]
        )
        self.report["tokens"]["grand_total_out"] = (
            self.report["tokens"]["reconstructor_out"] + self.report["tokens"]["tester_out"]
        )
        self.report["elapsed_so_far_seconds"] = round(time.time() - self.start_epoch, 3)
        (self.session_dir / "session_report.json").write_text(
            json.dumps(self.report, indent=2), encoding="utf-8"
        )

    def write_file_now(self, rel_path: str, content: str):
        p = self.session_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def set_api_plan(self, is_chunked: bool, num_aux: int, num_helpers: int, max_iterations: int, max_format_retries: int,
                     rem_aux: int = None, cached_aux: int = 0, rem_helpers: int = None, cached_helpers: int = 0,
                     cached_stage1_tests: bool = False):
        eff_aux = num_aux if rem_aux is None else rem_aux
        eff_helpers = num_helpers if rem_helpers is None else rem_helpers
        eff_s1 = 0 if cached_stage1_tests else 1
        eff_s2 = 1

        full_pipeline_min = num_aux + num_helpers + 3   # 1 root + 1 Stage 1 + 1 Stage 2 = 3 min
        remaining_min = eff_aux + eff_helpers + 1 + eff_s1 + eff_s2
        typical_max = (3 * (eff_aux + eff_helpers)) + (max_iterations * 3)
        absolute_max = (3 * (eff_aux + eff_helpers)) + (max_iterations * (1 + max_format_retries + 6))
        self.report["api_calls_plan"] = {
            "mode": "chunked" if is_chunked else "single_shot",
            "full_pipeline_min_calls": full_pipeline_min,
            "predicted_min_calls": remaining_min,
            "typical_max_calls": typical_max,
            "absolute_worst_case_calls": absolute_max,
            "cached_from_checkpoint": {
                "startup_audit": cached_aux,
                "helper_chunks": cached_helpers,
                "stage_1_tests": cached_stage1_tests
            },
            "breakdown_min": {
                "startup_audit": eff_aux,
                "helper_chunks": eff_helpers,
                "root_main": 1,
                "stage_1_tests": eff_s1,
                "stage_2_tests": eff_s2
            }
        }
        self._flush_report()
        s1_note = " [Stage 1 cached]" if cached_stage1_tests else ""
        if is_chunked:
            aux_note = f"/{num_aux} ({cached_aux} cached)" if cached_aux else ""
            hlp_note = f"/{num_helpers} ({cached_helpers} cached)" if cached_helpers else ""
            self.log(
                f"[*] API Call Forecast: Best-case {remaining_min} remaining calls "
                f"({full_pipeline_min} full-pipeline min: {eff_aux}{aux_note} audit + {eff_helpers}{hlp_note} chunk + "
                f"1 root + {eff_s1 + eff_s2}/2 tests{s1_note}) | Max budget ~{typical_max} (worst-case {absolute_max})"
            )
        else:
            self.log(
                f"[*] API Call Forecast: Best-case {remaining_min} remaining calls "
                f"(3 full-pipeline min: 1 reconstruct + {eff_s1 + eff_s2}/2 tests{s1_note}) | "
                f"Max budget ~{typical_max} (worst-case {absolute_max})"
            )
        self.event("API_PLAN", "Calculated API call budget", self.report["api_calls_plan"])

    def log_extraction(self, system_prompt: str, htre_cmd: list, htre_rc: int, htre_stderr: str,
                       analysis: str, decomp_cmd: list, decomp: str, decomp_stderr: str,
                       tester_ctx: str, elapsed_sec: float):
        self.write_file_now("00_extraction/system_prompt_snapshot.txt", system_prompt)
        self.write_file_now(
            "00_extraction/htre_cmd_and_stderr.log",
            f"HTRE_CMD: {' '.join(htre_cmd)}\nRC: {htre_rc}\n--- STDERR ---\n{htre_stderr}\n\n"
            f"DECOMP_CMD: {' '.join(decomp_cmd)}\n--- STDERR ---\n{decomp_stderr}\n"
        )
        self.write_file_now("00_extraction/htre_full_analysis.txt", analysis)
        self.write_file_now("00_extraction/kuna_decomp.c", decomp)
        self.write_file_now("00_extraction/tester_context.txt", tester_ctx)
        self.report["extraction"] = {
            "elapsed_seconds": round(elapsed_sec, 3),
            "analysis_bytes": len(analysis),
            "decomp_bytes": len(decomp),
            "tester_context_bytes": len(tester_ctx),
        }
        self._flush_report()

    def log_chunk_step(self, chunk_label: str, attempt: int, payload: dict,
                       raw_resp: dict, elapsed_sec: float, header: str = "", code: str = "", skipped: bool = False):
        prefix = f"chunks/{chunk_label}_attempt_{attempt}"
        self.write_file_now(f"{prefix}_request_payload.json", json.dumps(payload, indent=2))
        self.write_file_now(f"{prefix}_prompt.txt", payload["messages"][-1]["content"])
        if raw_resp:
            msg = raw_resp["choices"][0]["message"]
            reply_text = msg.get("content") or ""
            thinking_text = msg.get("reasoning_content") or ""
            self.write_file_now(f"{prefix}_raw_api_response.json", json.dumps(raw_resp, indent=2))
            self.write_file_now(f"{prefix}_raw_reply.txt", reply_text)
            self.write_file_now(f"{prefix}_ai_thinking.txt", thinking_text or "[No reasoning_content]")
            
            u = raw_resp.get("usage", {})
            pt, ct = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
            self.report["tokens"]["reconstructor_in"] += pt
            self.report["tokens"]["reconstructor_out"] += ct
            
            self.report["api_calls"]["total"] += 1
            if chunk_label.startswith("aux_"):
                self.report["api_calls"]["startup_audit"] += 1
            else:
                self.report["api_calls"]["helper_chunks"] += 1
            self.log(f"    [API Call #{self.report['api_calls']['total']}] {chunk_label} reply in {elapsed_sec:.1f}s (+{pt} in / +{ct} out)")
            
        if code:
            self.write_file_now(f"chunks/{chunk_label}_verified.c", code)
            self.write_file_now(f"chunks/{chunk_label}_header.h", header)
        if skipped or code:
            self.report["chunks"].append({
                "chunk": chunk_label, "skipped_as_crt": skipped, "elapsed_s": round(elapsed_sec, 2)
            })
        self._flush_report()

    def init_iteration_request(self, iter_num: int, format_retry: int, payload: dict, why: str):
        prefix = f"iter_{iter_num:02d}_try_{format_retry}" if format_retry > 0 else f"iter_{iter_num:02d}"
        self.write_file_now(f"{prefix}/request_payload.json", json.dumps(payload, indent=2))
        
        msgs = payload.get("messages", [])
        for idx, m in enumerate(msgs):
            role = m.get("role", "unknown")
            self.write_file_now(f"{prefix}/readable_conversation/msg_{idx:02d}_{role}.txt", m.get("content", ""))
            
        self.event(f"ITER_{iter_num:02d}_LLM_REQUEST", why, {"format_retry": format_retry, "message_count": len(msgs)})

    def log_llm_reply(self, iter_num: int, format_retry: int, raw_resp: dict, elapsed_sec: float):
        prefix = f"iter_{iter_num:02d}_try_{format_retry}" if format_retry > 0 else f"iter_{iter_num:02d}"
        msg = raw_resp["choices"][0]["message"]
        reply_text = msg.get("content") or ""
        thinking_text = msg.get("reasoning_content") or ""
        
        self.write_file_now(f"{prefix}/raw_api_response.json", json.dumps(raw_resp, indent=2))
        self.write_file_now(f"{prefix}/raw_reply.txt", reply_text)
        self.write_file_now(f"{prefix}/ai_thinking.txt", thinking_text or "[No reasoning_content returned by this model]")
            
        u = raw_resp.get("usage", {})
        pt, ct = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
        self.report["tokens"]["reconstructor_in"] += pt
        self.report["tokens"]["reconstructor_out"] += ct
        
        self.report["api_calls"]["total"] += 1
        self.report["api_calls"]["reconstructor"] += 1
        if format_retry > 0:
            self.report["api_calls"]["format_retries"] += 1
            
        self._flush_report()
        self.event(f"ITER_{iter_num:02d}_LLM_REPLY", "Received reconstruction candidates", {
            "api_call_num": self.report["api_calls"]["total"],
            "elapsed_s": round(elapsed_sec, 3),
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "has_thinking": bool(thinking_text)
        })
        return reply_text, thinking_text, pt, ct

    def log_candidate_code(self, iter_num: int, cand_idx: int, ext: str, code: str):
        self.write_file_now(f"iter_{iter_num:02d}/candidates/cand_{cand_idx + 1}{ext}", code)

    def log_compile_and_oracle(self, iter_num: int, cand_idx: int, cmd_idx: int, cmd: str,
                               comp_rc: int, comp_stdout: str, comp_stderr: str, comp_ms: float,
                               oracle_out: str, oracle_ms: float, pct: float, hash_eq: bool):
        base = f"iter_{iter_num:02d}/candidates/cand_{cand_idx + 1}_cmd_{cmd_idx + 1}"
        compile_log = (
            f"TIMESTAMP: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
            f"CMD: {cmd}\n"
            f"RETURN_CODE: {comp_rc}\n"
            f"DURATION_MS: {comp_ms:.2f}\n"
            f"--- STDOUT ---\n{comp_stdout}\n"
            f"--- STDERR ---\n{comp_stderr}\n"
        )
        self.write_file_now(f"{base}_compile.log", compile_log)
        if oracle_out:
            self.write_file_now(f"{base}_oracle.txt", oracle_out)

    def finish_iteration(self, iter_num: int, results: list, total_elapsed: float, llm_elapsed: float, pt: int, ct: int):
        iter_entry = {
            "iteration": iter_num,
            "total_seconds": round(total_elapsed, 3),
            "llm_seconds": round(llm_elapsed, 3),
            "tokens_in": pt,
            "tokens_out": ct,
            "candidates": [
                {
                    "cand_idx": r.get("ci", 0) + 1,
                    "cmd_idx": r.get("cmd_i", 0) + 1,
                    "cmd": r.get("cmd", ""),
                    "compile_ok": r.get("ok", False),
                    "compile_ms": round(r.get("compile_ms", 0.0), 2),
                    "oracle_ms": round(r.get("oracle_ms", 0.0), 2),
                    "byte_sim_pct": r.get("overall_pct", 0.0),
                    "code_identical": r.get("hash_equal", False),
                    "error": r.get("err", "")
                } for r in results
            ]
        }
        self.write_file_now(f"iter_{iter_num:02d}/summary.json", json.dumps(iter_entry, indent=2))
        self.report["iterations"].append(iter_entry)
        self._flush_report()

    def log_test_gen_request(self, iter_num: int, stage: int, attempt: int, payload: dict, why: str):
        v_dir = f"iter_{iter_num:02d}/verification"
        self.write_file_now(f"{v_dir}/stage_{stage}_attempt_{attempt}_request_payload.json", json.dumps(payload, indent=2))
        self.write_file_now(f"{v_dir}/stage_{stage}_attempt_{attempt}_prompt.txt", payload["messages"][-1]["content"])
        self.event(f"ITER_{iter_num:02d}_TESTGEN_REQ_S{stage}", why, {"attempt": attempt})

    def log_test_gen_reply(self, iter_num: int, stage: int, attempt: int, raw_resp: dict, elapsed_sec: float):
        v_dir = f"iter_{iter_num:02d}/verification"
        msg = raw_resp["choices"][0]["message"]
        reply_text = msg.get("content") or ""
        thinking_text = msg.get("reasoning_content") or ""
        
        self.write_file_now(f"{v_dir}/stage_{stage}_attempt_{attempt}_raw_api_response.json", json.dumps(raw_resp, indent=2))
        self.write_file_now(f"{v_dir}/stage_{stage}_attempt_{attempt}_raw_reply.txt", reply_text)
        self.write_file_now(f"{v_dir}/stage_{stage}_attempt_{attempt}_ai_thinking.txt", thinking_text or "[No reasoning_content]")
            
        u = raw_resp.get("usage", {})
        pt, ct = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
        self.report["tokens"]["tester_in"] += pt
        self.report["tokens"]["tester_out"] += ct
        
        self.report["api_calls"]["total"] += 1
        if stage == 1:
            self.report["api_calls"]["test_stage_1"] += 1
        else:
            self.report["api_calls"]["test_stage_2"] += 1
            
        self._flush_report()
        self.log(f"[API Call #{self.report['api_calls']['total']}] Stage {stage} test suite received in {elapsed_sec:.1f}s (+{pt} in / +{ct} out)")
        self.event(f"ITER_{iter_num:02d}_TESTGEN_REPLY_S{stage}", "Received adversarial test suite", {
            "api_call_num": self.report["api_calls"]["total"],
            "attempt": attempt, "elapsed_s": round(elapsed_sec, 3), "tokens_in": pt, "tokens_out": ct
        })
        return reply_text

    def log_parsed_tests(self, iter_num: int, stage: int, tests: list):
        self.write_file_now(f"iter_{iter_num:02d}/verification/stage_{stage}_parsed_tests.json", json.dumps(tests, indent=2))

    def open_test_streams(self, iter_num: int, stage: int, cand_idx: int = 1):
        v_dir = self.session_dir / f"iter_{iter_num:02d}/verification"
        v_dir.mkdir(parents=True, exist_ok=True)
        jsonl_fp = open(v_dir / f"stage_{stage}_cand_{cand_idx}_all_tests.jsonl", "w", encoding="utf-8", buffering=1)
        txt_fp = open(v_dir / f"stage_{stage}_cand_{cand_idx}_all_tests_readable.txt", "w", encoding="utf-8", buffering=1)
        return jsonl_fp, txt_fp

    def log_verification_summary(self, iter_num: int, stage: int, cand_idx: int, results: dict,
                                 gen_elapsed: float, exec_elapsed: float):
        v_dir = f"iter_{iter_num:02d}/verification"
        pass_pct = round((results["passed"] / results["total"]) * 100.0, 4) if results["total"] > 0 else 0.0
        entry = {
            "iteration": iter_num,
            "stage": stage,
            "candidate_index": cand_idx,
            "test_gen_seconds": round(gen_elapsed, 3),
            "test_exec_seconds": round(exec_elapsed, 3),
            "total_tests": results["total"],
            "passed": results["passed"],
            "failed": results["total"] - results["passed"],
            "pass_pct": pass_pct,
            "all_passed": results["all_passed"],
            "failures": results["failures"]
        }
        self.write_file_now(f"{v_dir}/stage_{stage}_cand_{cand_idx}_summary.json", json.dumps(entry, indent=2))
        self.report["verification_history"].append(entry)
        self._flush_report()
        self.event(
            f"ITER_{iter_num:02d}_VERIFY_S{stage}_CAND_{cand_idx}",
            f"Stage {stage} verification finished: {results['passed']}/{results['total']} passed ({pass_pct:.2f}%)",
            {"all_passed": results["all_passed"], "pass_pct": pass_pct, "exec_s": round(exec_elapsed, 3)}
        )

    def set_closest_winner(self, info: dict):
        self.report["closest_winner"] = info
        self._flush_report()
        self.event("CLOSEST_WINNER", "Updated closest winner candidate", info)

    def finalize(self, status: str, winner_code: str = "", winner_ext: str = ".c"):
        total_time = time.time() - self.start_epoch
        self.report["status"] = status
        self.report["success"] = (status == "success")
        self.report["total_runtime_seconds"] = round(total_time, 3)
        self.report["session_end"] = time.strftime("%Y-%m-%d_%H-%M-%S")
        
        if winner_code:
            fname = f"winner{winner_ext}" if status == "success" else f"closest_winner{winner_ext}"
            self.write_file_now(fname, winner_code)
            
        self._flush_report()
        self.event("SESSION_END", f"Pipeline ended with status={status}", {"total_runtime_s": round(total_time, 3)})
        
        c = self.report["api_calls"]
        pred_rem = self.report.get("api_calls_plan", {}).get("predicted_min_calls", "?")
        pred_full = self.report.get("api_calls_plan", {}).get("full_pipeline_min_calls", "?")
        self.log(f"\n[+] Full session report saved -> {self.session_dir / 'session_report.json'}")
        self.log(f"[+] Total Session Runtime: {total_time:.2f} seconds")
        self.log(f"[+] API Calls Made: {c['total']} total (predicted remaining min: {pred_rem}, full-pipeline min: {pred_full})")
        self.log(f"    Breakdown -> audit: {c['startup_audit']} | chunks: {c['helper_chunks']} | "
                 f"main: {c['reconstructor']} | stage1_tests: {c['test_stage_1']} | "
                 f"stage2_tests: {c['test_stage_2']} | format_retries: {c['format_retries']}")
        self.log(f"[+] Grand Total Tokens: {self.report['tokens']['grand_total_in']} in + "
                 f"{self.report['tokens']['grand_total_out']} out")
        self.log_fp.close()
        self.timeline_txt_fp.close()
        self.timeline_jsonl_fp.close()
