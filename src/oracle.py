import re
import shlex
import subprocess
from pathlib import Path
from src.config import BASE, ORACLE

def normalize_compile_cmd(cmd: str, src_name: str, out_name: str) -> str:
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    new_toks = []
    pending_output = False
    for t in toks:
        if pending_output:
            new_toks.extend(["-o", out_name])
            pending_output = False
            continue
        if t in ("-o", "--output"):
            pending_output = True
            continue
        if t.startswith("--output="):
            new_toks.extend(["-o", out_name])
            continue
        if t.endswith((".c", ".cpp", ".cc", ".cxx", ".rs")):
            new_toks.append(src_name)
            continue
        new_toks.append(t)
    if pending_output:
        new_toks.extend(["-o", out_name])
    return " ".join(shlex.quote(t) for t in new_toks)

def run_byte_oracle(original: Path, candidate: Path) -> str:
    try:
        r = subprocess.run(
            ["python", str(ORACLE), str(original), str(candidate), 
             "--context", "3", "--line-addresses", "--max-chunks", "15"],
            capture_output=True, text=True, timeout=900, cwd=BASE,
        )
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return "[byte oracle timeout]"
    except Exception as e:
        return f"[byte oracle error: {e}]"

def parse_overall_pct(oracle_out: str) -> float:
    m = re.search(r"OVERALL\s*:\s*([\d.]+)%", oracle_out)
    return float(m.group(1)) if m else 0.0
