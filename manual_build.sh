#!/usr/bin/env bash
set -uo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
info() { printf '%s[*]%s %s\n' "$CYN" "$RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YEL" "$RST" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

if [ $# -lt 1 ]; then
    echo "Usage: $0 <binary_name_or_path> [output_folder_name] [iteration]"
    echo "Examples:"
    echo "  $0 hostname final_hostname"
    echo "  $0 hostname final_hostname 2"
    echo "  $0 cib_hello final_cib"
    exit 1
fi

INPUT_BIN="$1"
BIN_NAME="$(basename "$INPUT_BIN")"
OUT_DIR="${2:-rebuilt_${BIN_NAME}}"
TARGET_ITER="${3:-}"

if [ -z "$OUT_DIR" ] || [ "$OUT_DIR" = "/" ] || [ "$OUT_DIR" = "." ] || [ "$OUT_DIR" = ".." ]; then
    die "Refusing unsafe output folder name: '$OUT_DIR'"
fi

command -v bwrap >/dev/null 2>&1 || die "'bwrap' (Bubblewrap) required for sandboxed building."

# ---------------------------------------------------------
# 1. Locate history sessions (newest to oldest)
# ---------------------------------------------------------
HIST_DIRS=""
if [ -d ".reba_history" ]; then
    HIST_DIRS=$(find .reba_history -maxdepth 1 -type d -name "${BIN_NAME}_*" | sort -r || true)
fi
[ -n "$HIST_DIRS" ] || die "No history folder found for '$BIN_NAME' in .reba_history/"

# ---------------------------------------------------------
# 2. Locate matching checkpoint folder
# ---------------------------------------------------------
CHK_DIR=""
if [ -f "$INPUT_BIN" ]; then
    SHA16=$(sha256sum "$INPUT_BIN" | cut -c1-16)
    if [ -d ".reba_checkpoints/${BIN_NAME}_${SHA16}" ]; then
        CHK_DIR=".reba_checkpoints/${BIN_NAME}_${SHA16}"
    fi
fi
if [ -z "$CHK_DIR" ] && [ -d ".reba_checkpoints" ]; then
    CHK_DIR=$(find .reba_checkpoints -maxdepth 1 -type d -name "${BIN_NAME}_*" | sort | tail -n 1 || true)
fi

HAS_CHUNKS=0
CHUNK_SRCS=""
if [ -n "$CHK_DIR" ] && [ -d "$CHK_DIR" ]; then
    CHUNK_SRCS=$(find "$CHK_DIR" -maxdepth 1 -type f \( -name '*.c' -o -name '*.cpp' \) | sort || true)
    [ -n "$CHUNK_SRCS" ] && HAS_CHUNKS=1
    info "Found checkpoints      : $CHK_DIR"
else
    info "No checkpoints found (single-shot binary)"
fi

# ---------------------------------------------------------
# 3. Clean & prepare output directory
# ---------------------------------------------------------
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/src"
[ "$HAS_CHUNKS" -eq 1 ] && mkdir -p "$OUT_DIR/include"

# ---------------------------------------------------------
# 4. Sandboxed Build Runner
# ---------------------------------------------------------
run_sandboxed_cmd() {
    local abs_out
    abs_out="$(realpath "$OUT_DIR")"

    local bwrap_cmd=(
        bwrap
        --ro-bind /usr /usr
        --ro-bind /etc /etc
        --dev /dev
        --proc /proc
        --tmpfs /tmp
        --bind "$abs_out" /tmp/work
        --unshare-all
        --cap-drop ALL
        --new-session
        --die-with-parent
        --chdir /tmp/work
        --clearenv
        --setenv PATH "/usr/bin:/bin:/usr/sbin:/sbin"
    )

    for sys_link in /bin /sbin /lib /lib64; do
        if [ -L "$sys_link" ]; then
            bwrap_cmd+=(--symlink "$(readlink "$sys_link")" "$sys_link")
        elif [ -d "$sys_link" ]; then
            bwrap_cmd+=(--ro-bind "$sys_link" "$sys_link")
        fi
    done

    "${bwrap_cmd[@]}" "$@"
}

# ---------------------------------------------------------
# 5. Stage candidate files
# ---------------------------------------------------------
stage_candidate_project() {
    local idir="$1"
    local cfile="$2"
    local cand_num="$3"
    local ext="$4"
    local use_cw_mod="$5"
    local hdr_file="$OUT_DIR/include/reba_chunks.h"

    rm -f "$OUT_DIR/src"/* "$OUT_DIR/${BIN_NAME}_rebuilt"

    if [ "$HAS_CHUNKS" -eq 1 ]; then
        {
            echo "#ifndef REBA_CHUNKS_H"
            echo "#define REBA_CHUNKS_H"
            echo "#include <stdbool.h>"
            echo "#include <stdint.h>"
            echo "#include <stddef.h>"
            grep -hvE 'REBA_CHUNKS_H|^#endif$' "$CHK_DIR"/*.h 2>/dev/null || true
            echo "#endif"
        } > "$hdr_file"

        for cf in $CHUNK_SRCS; do
            cp "$cf" "$OUT_DIR/src/$(basename "$cf")"
        done

        if [ "$use_cw_mod" -eq 1 ] && [ -d "$CHK_DIR/closest_winner/modular" ]; then
            if [ -f "$CHK_DIR/closest_winner/modular/include/reba_chunks.h" ]; then
                cp "$CHK_DIR/closest_winner/modular/include/reba_chunks.h" "$hdr_file"
            fi
            for mf in "$CHK_DIR/closest_winner/modular/src"/*."$ext"; do
                [ -f "$mf" ] || continue
                [ "$(basename "$mf")" = "main.${ext}" ] && continue
                cp "$mf" "$OUT_DIR/src/$(basename "$mf")"
            done
        fi
    fi

    cp "$cfile" "$OUT_DIR/src/main.${ext}"

    python3 - "$idir" "$cand_num" "$OUT_DIR" "$ext" <<'PY'
import json, re, sys
from pathlib import Path

idir = Path(sys.argv[1])
cand_num = int(sys.argv[2])
out_dir = Path(sys.argv[3])
ext = sys.argv[4]

reply_file = idir / "raw_reply.txt"
if reply_file.exists():
    txt = reply_file.read_text(encoding="utf-8", errors="replace").strip()
    data = None
    try:
        data = json.loads(txt)
    except Exception:
        for blk in re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", txt, re.DOTALL):
            try:
                data = json.loads(blk); break
            except Exception:
                pass
        if data is None and "{" in txt and "}" in txt:
            try:
                data = json.loads(txt[txt.index("{"):txt.rindex("}") + 1])
            except Exception:
                pass
    if isinstance(data, dict):
        cands = data.get("candidates", [])
        if 1 <= cand_num <= len(cands):
            patches = cands[cand_num - 1].get("file_patches") or {}
            for rel, content in patches.items():
                norm = rel.lstrip("./")
                if norm == "include/reba_chunks.h":
                    (out_dir / "include/reba_chunks.h").write_text(content, encoding="utf-8")
                elif norm.startswith("src/"):
                    (out_dir / "src" / Path(norm).name).write_text(content, encoding="utf-8")

src_dir = out_dir / "src"
other_code = "\n".join(
    p.read_text(encoding="utf-8", errors="replace")
    for p in src_dir.glob(f"*{ext}") if not p.name.startswith("aux_")
)
for aux_p in list(src_dir.glob(f"aux_*{ext}")):
    atxt = aux_p.read_text(encoding="utf-8", errors="replace")
    has_ctor = bool(re.search(r'__attribute__\s*\(\s*\(\s*constructor', atxt))
    defs = re.findall(r'^(?!extern\b)[^\n;]*\b(sub_[0-9a-fA-F]+)\s*\([^;{]*\)\s*\{', atxt, re.MULTILINE)
    if not has_ctor and not any(re.search(rf'\b{fn}\b', other_code) for fn in defs):
        aux_p.unlink()

for sp in src_dir.glob(f"*{ext}"):
    stxt = sp.read_text(encoding="utf-8", errors="replace")
    stxt2 = re.sub(r'#\s*include\s+[<"][^">]*reba_chunks\.h[>"]', '#include "../include/reba_chunks.h"', stxt)
    if stxt2 != stxt:
        sp.write_text(stxt2, encoding="utf-8")
PY
}

# ---------------------------------------------------------
# 6. Locate verified winner and candidate command
# ---------------------------------------------------------
FOUND_FILE=""
FOUND_HIST=""
FOUND_ITER=""
FOUND_EXT="c"
WINNING_CC="gcc"
WINNING_CFLAGS="-O2"
WINNING_LDFLAGS="-lm"

while IFS= read -r hdir; do
    [ -z "$hdir" ] && continue
    info "Checking session: $hdir"

    # 6.1 Check if session_report.json identifies the winning candidate and exact command
    REP_JSON=$(python3 - "$hdir" "$TARGET_ITER" <<'PY'
import json, sys
from pathlib import Path
hdir = Path(sys.argv[1])
req_iter = sys.argv[2].strip()
rep_file = hdir / "session_report.json"
out = {}
if rep_file.exists():
    try:
        d = json.load(open(rep_file))
        cw = d.get("closest_winner") or {}
        if cw:
            iter_n = cw.get("iteration", 1)
            if not req_iter or int(req_iter) == iter_n:
                out = {
                    "iter": f"iter_{iter_n:02d}",
                    "cand_idx": cw.get("cand_idx", 1),
                    "cmd": cw.get("cmd", "")
                }
    except Exception:
        pass
print(json.dumps(out))
PY
    )

    CHOSEN_ITER=$(echo "$REP_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('iter', ''))")
    CHOSEN_CAND=$(echo "$REP_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('cand_idx', ''))")
    CHOSEN_CMD=$(echo "$REP_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('cmd', ''))")

    if [ -n "$TARGET_ITER" ]; then
        REQ_NUM=$(echo "$TARGET_ITER" | sed -E 's/[^0-9]//g')
        [ -n "$REQ_NUM" ] || die "Invalid iteration specified: '$TARGET_ITER'"
        PAD_NUM=$(printf '%02d' "$((10#$REQ_NUM))")
        ITER_DIRS=$(find "$hdir" -maxdepth 1 -type d \( -name "iter_${PAD_NUM}" -o -name "iter_${REQ_NUM}" \) || true)
    elif [ -n "$CHOSEN_ITER" ] && [ -d "$hdir/$CHOSEN_ITER" ]; then
        ITER_DIRS="$hdir/$CHOSEN_ITER"
    else
        ITER_DIRS=$(find "$hdir" -maxdepth 1 -type d -name 'iter_*' | sort -V -r || true)
    fi

    [ -n "$ITER_DIRS" ] || continue

    while IFS= read -r idir; do
        [ -z "$idir" ] && continue
        [ -d "$idir/candidates" ] || continue
        ITER_BASE=$(basename "$idir")

        if [ -n "$CHOSEN_CAND" ] && [ -f "$idir/candidates/cand_${CHOSEN_CAND}.c" ]; then
            CAND_FILES="$idir/candidates/cand_${CHOSEN_CAND}.c"
        else
            CAND_FILES=$(find "$idir/candidates" -maxdepth 1 -type f -regextype posix-extended -regex '.*/cand_[0-9]+\.(c|cpp|rs)' | sort -V || true)
        fi
        [ -n "$CAND_FILES" ] || continue

        while IFS= read -r cfile; do
            [ -z "$cfile" ] && continue
            C_NAME=$(basename "$cfile")
            EXT="${C_NAME##*.}"
            CAND_NUM=$(echo "$C_NAME" | sed -E 's/cand_([0-9]+)\..*/\1/')

            PARSED_JSON=$(python3 - "$idir" "$CAND_NUM" "$CHOSEN_CMD" <<'PY'
import json, shlex, sys
from pathlib import Path
idir = Path(sys.argv[1])
cnum = int(sys.argv[2])
chosen_cmd = sys.argv[3].strip()

cmds = []
if chosen_cmd:
    cmds.append(chosen_cmd)

sum_file = idir / "summary.json"
if sum_file.exists():
    try:
        data = json.load(open(sum_file))
        for c in data.get("candidates", []):
            if c.get("cand_idx") == cnum and c.get("compile_ok"):
                cmd_txt = c.get("cmd", "")
                if cmd_txt and cmd_txt not in cmds:
                    cmds.append(cmd_txt)
    except Exception:
        pass

parsed_cmds = []
for cmd_str in cmds:
    tokens = shlex.split(cmd_str)
    if not tokens:
        continue
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
    parsed_cmds.append({"compiler": compiler, "cflags": " ".join(cflags), "ldflags": " ".join(ldflags), "raw": cmd_str})

if not parsed_cmds:
    parsed_cmds.append({"compiler": "gcc", "cflags": "-O2", "ldflags": "-lm", "raw": ""})

print(json.dumps(parsed_cmds))
PY
            )

            COMPILE_OK=0
            LAST_ERR=""
            NUM_CMDS=$(echo "$PARSED_JSON" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

            for cmd_idx in $(seq 0 $((NUM_CMDS - 1))); do
                CC=$(echo "$PARSED_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)[$cmd_idx]['compiler'])")
                CFLAGS=$(echo "$PARSED_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)[$cmd_idx]['cflags'])")
                LDFLAGS=$(echo "$PARSED_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)[$cmd_idx]['ldflags'])")

                for use_mod in 0 1; do
                    [ "$use_mod" -eq 1 ] && [ ! -d "$CHK_DIR/closest_winner/modular" ] && continue
                    stage_candidate_project "$idir" "$cfile" "$CAND_NUM" "$EXT" "$use_mod"

                    if [ "$HAS_CHUNKS" -eq 1 ]; then
                        BUILD_CMD="shopt -s nullglob; CHUNKS=(); for f in src/*.${EXT}; do [[ \"\$f\" == \"src/main.${EXT}\" ]] || CHUNKS+=(\"\$f\"); done; $CC $CFLAGS -fcommon -Wl,--allow-multiple-definition -Iinclude src/main.${EXT} \"\${CHUNKS[@]}\" -o ${BIN_NAME}_rebuilt $LDFLAGS"
                    else
                        BUILD_CMD="$CC $CFLAGS src/main.${EXT} -o ${BIN_NAME}_rebuilt $LDFLAGS"
                    fi

                    OUT_ERR=$(run_sandboxed_cmd bash -c "$BUILD_CMD" 2>&1 || true)
                    if [ -f "$OUT_DIR/${BIN_NAME}_rebuilt" ]; then
                        # Execute smoke-test in sandbox: verify binary doesn't crash with SIGSEGV (rc 139)
                        SMOKE_RC=0
                        run_sandboxed_cmd bash -c "./${BIN_NAME}_rebuilt --version >/dev/null 2>&1 || ./${BIN_NAME}_rebuilt >/dev/null 2>&1" 2>/dev/null || SMOKE_RC=$?
                        if [ "$SMOKE_RC" -ne 139 ] && [ "$SMOKE_RC" -ne 134 ]; then
                            COMPILE_OK=1
                            WINNING_CC="$CC"
                            WINNING_CFLAGS="$CFLAGS"
                            WINNING_LDFLAGS="$LDFLAGS"
                            break 2
                        else
                            LAST_ERR="Binary crashed on launch with returncode $SMOKE_RC (SIGSEGV/SIGABRT)"
                            rm -f "$OUT_DIR/${BIN_NAME}_rebuilt"
                        fi
                    else
                        LAST_ERR="$OUT_ERR"
                    fi
                done
            done

            if [ "$COMPILE_OK" -eq 1 ]; then
                SCORE_INFO=""
                SUM_FILE="$idir/verification/stage_1_cand_${CAND_NUM}_summary.json"
                if [ -f "$SUM_FILE" ]; then
                    SCORE_INFO=$(python3 -c "import json; d=json.load(open('$SUM_FILE')); pct=(d['passed']/d['total']*100 if d['total'] else 0); print(f\"(Stage 1: {d['passed']}/{d['total']} = {pct:.2f}%)\")" 2>/dev/null || true)
                fi
                SUM2_FILE="$idir/verification/stage_2_cand_${CAND_NUM}_summary.json"
                if [ -f "$SUM2_FILE" ]; then
                    SCORE2_INFO=$(python3 -c "import json; d=json.load(open('$SUM2_FILE')); pct=(d['passed']/d['total']*100 if d['total'] else 0); print(f\"(Stage 2: {d['passed']}/{d['total']} = {pct:.2f}%)\")" 2>/dev/null || true)
                    SCORE_INFO="$SCORE_INFO $SCORE2_INFO"
                fi
                ok "Compiled and verified inside sandbox: $(basename "$hdir") / $ITER_BASE / $C_NAME $SCORE_INFO"
                FOUND_FILE="$cfile"
                FOUND_HIST="$hdir"
                FOUND_ITER="$ITER_BASE"
                FOUND_EXT="$EXT"
                break 3
            else
                FIRST_ERR=$(echo "$LAST_ERR" | head -n 2 | tr '\n' ' ')
                warn "Skipped $ITER_BASE/$C_NAME: ${FIRST_ERR:-failed to compile}"
            fi
        done <<< "$CAND_FILES"
    done <<< "$ITER_DIRS"
done <<< "$HIST_DIRS"

[ -n "$FOUND_FILE" ] || die "No compiling candidate found for '$BIN_NAME'${TARGET_ITER:+ at iteration $TARGET_ITER}"

# ---------------------------------------------------------
# 7. Generate clean Makefile & README.md (with exact winning flags)
# ---------------------------------------------------------
if [ "$HAS_CHUNKS" -eq 1 ]; then
    cat > "$OUT_DIR/Makefile" <<EOF
CC = ${WINNING_CC}
CFLAGS = ${WINNING_CFLAGS} -fcommon -Wl,--allow-multiple-definition -Iinclude
SRCS = src/main.${FOUND_EXT} \$(filter-out src/main.${FOUND_EXT},\$(wildcard src/*.${FOUND_EXT}))
TARGET = ${BIN_NAME}_rebuilt
LDFLAGS = ${WINNING_LDFLAGS}

all:
	\$(CC) \$(CFLAGS) \$(SRCS) -o \$(TARGET) \$(LDFLAGS)

clean:
	rm -f \$(TARGET)
EOF
else
    cat > "$OUT_DIR/Makefile" <<EOF
CC = ${WINNING_CC}
CFLAGS = ${WINNING_CFLAGS}
SRCS = src/main.${FOUND_EXT}
TARGET = ${BIN_NAME}_rebuilt
LDFLAGS = ${WINNING_LDFLAGS}

all:
	\$(CC) \$(CFLAGS) \$(SRCS) -o \$(TARGET) \$(LDFLAGS)

clean:
	rm -f \$(TARGET)
EOF
fi

cat > "$OUT_DIR/README.md" <<EOF
# Rebuilt ${BIN_NAME}

Autonomously reconstructed by **REBA**.

## How to Build
\`\`\`bash
make
./${BIN_NAME}_rebuilt
\`\`\`
EOF

echo
ok "=== SANDBOXED BUILD COMPLETE ==="
echo "  Session          : $(basename "$FOUND_HIST")"
echo "  Source Iteration : $FOUND_ITER"
echo "  Output Folder    : $OUT_DIR/"
echo "  Executable       : $OUT_DIR/${BIN_NAME}_rebuilt"
echo "  Modular Code     : $OUT_DIR/src/$([ "$HAS_CHUNKS" -eq 1 ] && echo " + $OUT_DIR/include/") (run 'cd $OUT_DIR && make')"
