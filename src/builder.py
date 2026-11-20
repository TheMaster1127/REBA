import os
import re
import shlex
from pathlib import Path
from src.config import OUT_DIR

def setup_modular_output_dirs() -> tuple[Path, Path]:
    src_out = OUT_DIR / "src"
    inc_out = OUT_DIR / "include"
    src_out.mkdir(parents=True, exist_ok=True)
    inc_out.mkdir(parents=True, exist_ok=True)
    return src_out, inc_out

def parse_cmd_flags(cmd_str: str) -> tuple[str, str, str]:
    """Extracts compiler, cflags, and ldflags from candidate compile command."""
    if not cmd_str:
        return "gcc", "-O2", "-lm"
    tokens = shlex.split(cmd_str)
    if not tokens:
        return "gcc", "-O2", "-lm"
    compiler = tokens[0]
    cflags = []
    ldflags = []
    skip = False
    for t in tokens[1:]:
        if skip:
            skip = False
            continue
        if t in ("-o", "--output"):
            skip = True
            continue
        if t.startswith("-o") or t.startswith("--output="):
            continue
        if t.endswith((".c", ".cpp", ".cc", ".cxx", ".rs", ".s", ".S")):
            continue
        if t.startswith("-l"):
            ldflags.append(t)
            continue
        cflags.append(t)
    return compiler, " ".join(cflags), " ".join(ldflags)

def write_modular_project(src_out_dir: Path, inc_out_dir: Path, extra_files: dict,
                          main_code: str, ext: str, binary_name: str, best_cmd: str = ""):
    def fix_inc(code_str: str) -> str:
        return re.sub(r'#\s*include\s+[<"][^">]*reba_chunks\.h[>"]', '#include "../include/reba_chunks.h"', code_str)

    has_chunks = bool(extra_files)
    if has_chunks and "include/reba_chunks.h" in extra_files:
        (inc_out_dir / "reba_chunks.h").write_text(extra_files["include/reba_chunks.h"], encoding="utf-8")

    for rel, content in extra_files.items():
        if rel.startswith("src/"):
            fname = Path(rel).name
            (src_out_dir / fname).write_text(fix_inc(content), encoding="utf-8")

    (src_out_dir / f"main{ext}").write_text(fix_inc(main_code), encoding="utf-8")

    compiler, cflags, ldflags = parse_cmd_flags(best_cmd)
    if not cflags:
        cflags = "-O2"
    if not ldflags and "-nostdlib" not in cflags:
        ldflags = "-lm"

    if ext == ".rs":
        makefile = (
            f"all:\n\trustc -O src/main.rs -o {binary_name}_rebuilt\n\n"
            f"clean:\n\trm -f {binary_name}_rebuilt\n"
        )
    elif has_chunks:
        extra_cflags = []
        if "-fcommon" not in cflags:
            extra_cflags.append("-fcommon")
        if "-Wl,--allow-multiple-definition" not in cflags:
            extra_cflags.append("-Wl,--allow-multiple-definition")
        if "-Iinclude" not in cflags:
            extra_cflags.append("-Iinclude")
        full_cflags = f"{cflags} {' '.join(extra_cflags)}".strip()
        makefile = (
            f"CC = {compiler}\n"
            f"CFLAGS = {full_cflags}\n"
            f"SRCS = src/main{ext} $(filter-out src/main{ext},$(wildcard src/*{ext}))\n"
            f"TARGET = {binary_name}_rebuilt\n"
            f"LDFLAGS = {ldflags}\n\n"
            f"all:\n\t$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)\n\n"
            f"clean:\n\trm -f $(TARGET)\n"
        )
    else:
        makefile = (
            f"CC = {compiler}\n"
            f"CFLAGS = {cflags}\n"
            f"SRCS = src/main{ext}\n"
            f"TARGET = {binary_name}_rebuilt\n"
            f"LDFLAGS = {ldflags}\n\n"
            f"all:\n\t$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)\n\n"
            f"clean:\n\trm -f $(TARGET)\n"
        )

    (OUT_DIR / "Makefile").write_text(makefile, encoding="utf-8")

    readme = (
        f"# Rebuilt {binary_name}\n\n"
        f"Autonomously reconstructed by **REBA**.\n\n"
        f"## How to Build\n"
        f"```bash\n"
        f"make\n"
        f"./{binary_name}_rebuilt\n"
        f"```\n"
    )
    (OUT_DIR / "README.md").write_text(readme, encoding="utf-8")
