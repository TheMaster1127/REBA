import re
import json
import time
import shutil
from pathlib import Path
from src.config import BASE, OUT_DIR
from src.builder import write_modular_project
from src.sandbox import SafeSandbox
from src.tracker import SessionTracker

def calc_pass_pct(res: dict | None) -> float:
    if not res or res.get("total", 0) <= 0:
        return 0.0
    return (res["passed"] / res["total"]) * 100.0

def score_candidate(cc: dict) -> tuple:
    """Ranks by Stage 1 completion, Stage 1 %, Stage 2 %, and picks most recent on tie."""
    r1 = cc.get("stage_1_res")
    r2 = cc.get("stage_2_res")
    s1_all = int(bool(r1 and r1.get("all_passed")))
    s1_pct = round(calc_pass_pct(r1), 6)
    s2_pct = round(calc_pass_pct(r2), 6)
    return (s1_all, s1_pct, s2_pct, cc.get("attempt_num", 0), int(cc.get("hash_eq", False)), cc.get("oracle_pct", 0.0))

def apply_file_patches(base_extra_files: dict, patches: dict | None) -> tuple[dict, str]:
    merged = dict(base_extra_files)
    if patches:
        for rel, content in patches.items():
            norm_rel = rel.lstrip("./")
            if norm_rel in merged or norm_rel.startswith("src/") or norm_rel == "include/reba_chunks.h":
                merged[norm_rel] = content
    hdr = merged.get("include/reba_chunks.h", "")
    return merged, hdr

def build_closest_winner_info(cc: dict, func_filter: str | None = None) -> dict:
    r1 = cc.get("stage_1_res") or {"passed": 0, "total": 0, "all_passed": False}
    r2 = cc.get("stage_2_res")
    s1_pct = round(calc_pass_pct(r1), 4)
    s2_pct = round(calc_pass_pct(r2), 4) if r2 else None
    tot_passed = r1["passed"] + (r2["passed"] if r2 else 0)
    tot_tests = r1["total"] + (r2["total"] if r2 else 0)
    overall_pct = round((tot_passed / tot_tests) * 100.0, 4) if tot_tests > 0 else 0.0
    return {
        "iteration": cc.get("attempt_num", 0),
        "cand_idx": cc["ci"] + 1,
        "cmd": cc["cmd"],
        "func_filter": func_filter,
        "oracle_pct": round(cc.get("oracle_pct", 0.0), 4),
        "code_identical": bool(cc.get("hash_eq", False)),
        "patched_files": sorted(cc.get("file_patches", {}).keys()) if cc.get("file_patches") else [],
        "stage_1": {
            "passed": r1["passed"],
            "total": r1["total"],
            "pass_pct": s1_pct,
            "all_passed": bool(r1.get("all_passed")),
        },
        "stage_2": {
            "passed": r2["passed"],
            "total": r2["total"],
            "pass_pct": s2_pct,
            "all_passed": bool(r2.get("all_passed")),
        } if r2 else None,
        "overall_passed": tot_passed,
        "overall_total": tot_tests,
        "overall_pass_pct": overall_pct,
    }

def save_closest_winner_checkpoint(chk_dir: Path, best_cand: dict, sandbox: SafeSandbox,
                                   session: SessionTracker, is_final_winner: bool, func_filter: str | None = None):
    cw_dir = chk_dir / "closest_winner"
    cw_dir.mkdir(parents=True, exist_ok=True)
    ext = best_cand["cand_ext"]
    main_code = best_cand["code"]
    cand_extra = best_cand["extra_files"]
    cand_hdr = best_cand["final_hdr"]

    # Delete any stale broken standalone files
    (cw_dir / f"closest_winner{ext}").unlink(missing_ok=True)
    (cw_dir / f"closest_winner_main{ext}").write_text(main_code, encoding="utf-8")

    mod_src = cw_dir / "modular" / "src"
    mod_inc = cw_dir / "modular" / "include"
    mod_src.mkdir(parents=True, exist_ok=True)
    mod_inc.mkdir(parents=True, exist_ok=True)
    if cand_hdr:
        (mod_inc / "reba_chunks.h").write_text(cand_hdr, encoding="utf-8")
    for rel, content in cand_extra.items():
        if rel.startswith("src/"):
            (mod_src / Path(rel).name).write_text(
                re.sub(r'#\s*include\s+[<"][^">]*reba_chunks\.h[>"]', '#include "../include/reba_chunks.h"', content),
                encoding="utf-8"
            )
    (mod_src / f"main{ext}").write_text(
        re.sub(r'#\s*include\s+[<"][^">]*reba_chunks\.h[>"]', '#include "../include/reba_chunks.h"', main_code),
        encoding="utf-8"
    )

    info = build_closest_winner_info(best_cand, func_filter=func_filter)
    info["is_full_winner"] = is_final_winner
    info["saved_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    (cw_dir / "closest_winner_info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")

    attempt_num = best_cand.get("attempt_num", 1)
    cand_num = best_cand["ci"] + 1
    v_dir = session.session_dir / f"iter_{attempt_num:02d}/verification"
    for stage in (1, 2):
        for suffix in ("all_tests.jsonl", "all_tests_readable.txt", "summary.json"):
            src_f = v_dir / f"stage_{stage}_cand_{cand_num}_{suffix}"
            dst_f = cw_dir / f"stage_{stage}_{suffix}"
            if src_f.exists():
                shutil.copy2(src_f, dst_f)
            elif dst_f.exists():
                dst_f.unlink()

    session.set_closest_winner(info)
    return cw_dir, info, main_code, True

def save_best_output(stem: str, best_cand: dict, src_out_dir: Path, inc_out_dir: Path,
                     sandbox: SafeSandbox, session: SessionTracker, chk_dir: Path,
                     is_final_winner: bool, func_filter: str | None = None, update_checkpoint: bool = True):
    ext = best_cand["cand_ext"]
    main_code = best_cand["code"]
    cand_extra = best_cand["extra_files"]

    if update_checkpoint:
        cw_dir, info, _, _ = save_closest_winner_checkpoint(
            chk_dir, best_cand, sandbox, session, is_final_winner, func_filter=func_filter
        )
    else:
        info = build_closest_winner_info(best_cand, func_filter=func_filter)
        cw_dir = chk_dir / "closest_winner"

    # Remove any stale broken standalone files
    (OUT_DIR / f"winner_{stem}{ext}").unlink(missing_ok=True)
    (OUT_DIR / f"closest_winner_{stem}{ext}").unlink(missing_ok=True)
    (OUT_DIR / f"best_so_far_{stem}{ext}").unlink(missing_ok=True)

    # Write the clean modular project with the candidate's exact compiler flags in Makefile
    write_modular_project(src_out_dir, inc_out_dir, cand_extra, main_code, ext, stem, best_cmd=best_cand.get("cmd", ""))

    s1 = info["stage_1"]
    s2 = info["stage_2"]
    s2_msg = f" | Stage 2: {s2['passed']}/{s2['total']} ({s2['pass_pct']:.2f}%)" if s2 else ""
    tag = "FINAL WINNER" if is_final_winner else "CLOSEST WINNER"
    session.log(f"[+] {tag}: Attempt #{info['iteration']} Cand #{info['cand_idx']} | Stage 1: {s1['passed']}/{s1['total']} ({s1['pass_pct']:.2f}%){s2_msg}")
    if update_checkpoint:
        session.log(f"[+] Saved closest winner & test outputs -> {cw_dir.relative_to(BASE)}")
    session.log(f"[+] Modular project saved -> {OUT_DIR.relative_to(BASE)}/src & include/ (run 'cd {OUT_DIR.relative_to(BASE)} && make')")
    return main_code, ext
