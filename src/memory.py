import re
import json
from pathlib import Path

def extract_safe_oracle_chunks(oracle_out: str, max_chunks: int = 3) -> str:
    chunks = re.split(r'\n(?=\[chunk \d+\])', oracle_out)
    return "\n".join(chunks[:max_chunks])

def extract_safe_compiler_errors(stderr_text: str) -> str:
    """Extracts unique real compiler/linker errors without warning spam."""
    lines = stderr_text.splitlines()
    seen = set()
    err_lines = []
    for l in lines:
        if "error:" in l or "fatal error:" in l or "undefined reference" in l or "multiple definition" in l or "conflicting types" in l:
            if l not in seen:
                seen.add(l)
                err_lines.append(l)
    if err_lines:
        return "\n".join(err_lines[:40])
    return stderr_text

def pick_diverse_failures(failures: list, max_count: int = 8) -> list:
    """Picks evenly spaced failures across the suite so all failing modes are visible."""
    if len(failures) <= max_count:
        return failures
    step = (len(failures) - 1) / (max_count - 1)
    indices = sorted({round(i * step) for i in range(max_count)})
    return [failures[i] for i in indices]

def score_from_cw_info(info: dict) -> tuple:
    s1 = info.get("stage_1") or {}
    s2 = info.get("stage_2") or {}
    s1_all = int(bool(s1.get("all_passed")))
    s1_pct = round(float(s1.get("pass_pct", 0.0)), 6)
    s2_pct = round(float(s2.get("pass_pct", 0.0)), 6) if s2 else 0.0
    return (s1_all, s1_pct, s2_pct, 0, int(bool(info.get("code_identical", False))), float(info.get("oracle_pct", 0.0)))

def load_failure_memory_hints(chk_dir: Path) -> str:
    mem_file = chk_dir / "failure_memory.json"
    if not mem_file.exists():
        return ""
    try:
        data = json.loads(mem_file.read_text(encoding="utf-8"))
        entries = data.get("lessons", [])
        if not entries:
            return ""
        lines = "\n".join(f"- {e}" for e in entries[-10:])
        return f"=== CROSS-RUN TEST FAILURE MEMORY (REMAINING BUGS TO WATCH FOR) ===\n{lines}\n"
    except Exception:
        return ""

def record_failure_memory(chk_dir: Path, failures: list, stage: int, replace: bool = False):
    mem_file = chk_dir / "failure_memory.json"
    if replace:
        data = {"lessons": []}
    else:
        data = {"lessons": []}
        if mem_file.exists():
            try:
                data = json.loads(mem_file.read_text(encoding="utf-8"))
            except Exception:
                pass
    for f in pick_diverse_failures(failures or [], 8):
        args_s = repr(f.get("args", []))
        orig = f.get("orig", {})
        cand = f.get("cand", {})
        diff_note = f" | stdout_diff={f['stdout_diff']}" if f.get("stdout_diff") else ""
        err_diff_note = f" | stderr_diff={f['stderr_diff']}" if f.get("stderr_diff") else ""
        lesson = (
            f"Stage {stage} args={args_s}: ORIG(rc={orig.get('code')}, err={orig.get('stderr', '')!r}) "
            f"!= CAND(rc={cand.get('code')}, err={cand.get('stderr', '')!r}){diff_note}{err_diff_note}"
        )
        if lesson not in data["lessons"]:
            data["lessons"].append(lesson)
    data["lessons"] = data["lessons"][-12:]
    try:
        mem_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

def load_attempt_memory(chk_dir: Path) -> list:
    p = chk_dir / "attempt_memory.json"
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("history", [])
    except Exception:
        return []

def record_attempt_memory(chk_dir: Path, entry: str):
    p = chk_dir / "attempt_memory.json"
    hist = load_attempt_memory(chk_dir)
    if entry not in hist[-3:]:
        hist.append(entry)
    hist = hist[-15:]
    try:
        p.write_text(json.dumps({"history": hist}, indent=2), encoding="utf-8")
    except Exception:
        pass

def load_warmstart_closest_winner(chk_dir: Path, ext: str, func_filter: str | None) -> dict | None:
    cw_dir = chk_dir / "closest_winner"
    info_file = cw_dir / "closest_winner_info.json"
    main_file = cw_dir / f"closest_winner_main{ext}"
    if not info_file.exists() or not main_file.exists():
        return None
    try:
        info = json.loads(info_file.read_text(encoding="utf-8"))
        if info.get("func_filter") != func_filter:
            return None
        if (info.get("stage_1") or {}).get("passed", 0) <= 0:
            return None
        main_code = main_file.read_text(encoding="utf-8")
        if not main_code.strip():
            return None

        patched_extra = {}
        mod_src = cw_dir / "modular" / "src"
        mod_inc = cw_dir / "modular" / "include"
        if (mod_inc / "reba_chunks.h").exists():
            patched_extra["include/reba_chunks.h"] = (mod_inc / "reba_chunks.h").read_text(encoding="utf-8")
        if mod_src.exists():
            for p in sorted(mod_src.glob(f"*{ext}")):
                if p.name != f"main{ext}":
                    txt = re.sub(r'#include\s+"[^"]*reba_chunks\.h"', '#include "reba_chunks.h"', p.read_text(encoding="utf-8"))
                    patched_extra[f"src/{p.name}"] = txt

        failures = []
        fail_stage = 1
        s2_sum = cw_dir / "stage_2_summary.json"
        s1_sum = cw_dir / "stage_1_summary.json"
        if s2_sum.exists():
            d2 = json.loads(s2_sum.read_text(encoding="utf-8"))
            if d2.get("failures"):
                failures = d2["failures"]
                fail_stage = 2
        if not failures and s1_sum.exists():
            d1 = json.loads(s1_sum.read_text(encoding="utf-8"))
            failures = d1.get("failures", [])
            fail_stage = 1

        return {
            "info": info,
            "score": score_from_cw_info(info),
            "main_code": main_code,
            "patched_extra": patched_extra,
            "failures": failures,
            "fail_stage": fail_stage,
            "cw_dir": cw_dir,
        }
    except Exception:
        return None

def build_anchored_messages(root_system_prompt: str, root_analysis_content: str,
                            best_anchor: dict | None, latest_feedback: str | None,
                            chk_dir: Path, ext: str) -> list:
    """Keeps conversation anchored on the BEST candidate so far + recent attempt memory + latest feedback."""
    base_content = root_analysis_content

    attempt_hist = load_attempt_memory(chk_dir)
    if attempt_hist:
        base_content += "\n\n=== RECENT ATTEMPT MEMORY (WHAT HELPED OR FAILED) ===\n" + "\n".join(f"- {h}" for h in attempt_hist)

    if best_anchor:
        info = best_anchor["info"]
        s1 = info["stage_1"]
        s2 = info.get("stage_2")
        s2_str = f", Stage 2: {s2['passed']}/{s2['total']} ({s2['pass_pct']:.2f}%)" if s2 else ""
        fail_stage = best_anchor["fail_stage"]
        fail_dump = json.dumps(pick_diverse_failures(best_anchor["failures"], 8), indent=2) if best_anchor["failures"] else "[]"
        patches_note = ""
        if best_anchor.get("file_patches"):
            patches_note = "\nActive `file_patches` in this best candidate:\n" + "\n".join(
                f"--- {k} ---\n```c\n{v}\n```" for k, v in sorted(best_anchor["file_patches"].items())
            )
        base_content += (
            f"\n\n=== CURRENT BEST ANCHOR CANDIDATE (BUILD ON THIS — DO NOT REGRESS!) ===\n"
            f"Score: Stage 1: {s1['passed']}/{s1['total']} ({s1['pass_pct']:.2f}%){s2_str}\n"
            f"Working compile command: {info.get('cmd')}\n"
            f"--- BEST main{ext} ---\n```c\n{best_anchor['main_code']}\n```\n"
            f"{patches_note}\n"
            f"--- REMAINING FAILURES TO FIX ON THIS ANCHOR (Stage {fail_stage}) ---\n{fail_dump}\n"
        )

    msgs = [
        {"role": "system", "content": root_system_prompt},
        {"role": "user", "content": base_content},
    ]
    if latest_feedback:
        msgs.append({"role": "user", "content": latest_feedback})
    return msgs
