# REBA — Reverse Engineer Basically Everything

> **An autonomous, sandbox-verified AI reverse-engineering pipeline that lifts compiled, stripped Linux ELF binaries back into clean, modular, compilable, and behaviorally equivalent C/C++/Rust source code.**

**⚠️ PLATFORM SUPPORT: LINUX ONLY.**  
*Windows is **not supported**. REBA relies directly on Linux ELF tooling (`readelf`, `nm`, `objdump`), POSIX resource limits (`RLIMIT_CPU`, `RLIMIT_FSIZE`), and Linux kernel namespaces (`bubblewrap`) for air-gapped compilation and execution.*

---

## 1. Runtime & API Pricing

### How Long Does a Run Take?
* **Small / Single-File Binaries:** Typically **a few minutes** (around 1–5 minutes).
* **Larger / Multi-Chunk Binaries:** Can take anywhere from **10 to 20 minutes, or even more** depending on function count, compiler retries, and API response speed.

### API Pricing *(as of November 20, 2026)*
> *Note: API pricing below reflects DeepSeek rates **as of November 20, 2026**, and may change in the future when you are reading this.*

REBA is **not super expensive**, especially when using the **DeepSeek Flash** model (`deepseek-flash`):
* **Small binaries:** Typically cost around **8–10 cents** (or slightly more depending on retries).
* **Larger binaries** *(like `/usr/bin/hostname` or bigger multi-function binaries)*: Expect it to cost more—anywhere up to **around $1 USD, or potentially even more** for very large targets or multi-pass runs.
* **Starter Tip:** If you have never used the DeepSeek API before, putting **3 bucks ($3)** on your account is plenty to get started and run several tests safely without worrying about burning through money.

> **Recommendation:** Don't immediately spend your tokens on a huge binary. First verify your local tools work (0 API calls), then write a tiny C program, compile it yourself, and run REBA on that first to make sure everything works smoothly on your machine.

---

## 2. Key Capabilities

* **Fast Rust Decompilation (`htre_cli.py` + Kuna):** Extracts ELF metadata, section-mapped strings, `objdump` disassembly, and clean C ASTs via **[Kuna](https://github.com/Noelo-Lab/kuna)** (~60–150ms vs. 25s+ for JVM Ghidra headless), with fallbacks to `ceasta-cli` and Ghidra.
* **Reachability-Safe Call Graph & Multi-Pass Chunking (`src/graph.py` & `src/chunker.py`):** Maps direct `call`, `jmp`, and `lea` function pointers across `.text`, groups mutual recursion via Tarjan's Strongly Connected Components (SCC), audits unreachable startup code for hidden constructors, and solves large binaries bottom-up in deterministic chunks.
* **Object-Level Link Hygiene (`src/sandbox.py` & `src/chunker.py`):** Runs `nm -u` on every compiled chunk `.o` file inside Bubblewrap to reject dangling phantom labels (`dat_*`, `unk_*`) and catches system header re-declarations before they poison downstream builds.
* **Linker Hot-Patching & Direct Chunk Patching (`src/builder.py` & `src/pipeline.py`):** Combines `-Wl,--allow-multiple-definition` with an optional AI `"file_patches"` mechanism so the root pass can fix or override buggy helper chunks on the fly.
* **Persistent Checkpointing & Cross-Run Warm-Start (`src/memory.py`):** Caches verified chunks, test suites, and your highest-scoring candidate (`closest_winner/`) in `.reba_checkpoints/` so interrupted or multi-run jobs pick up where they left off instead of starting over.
* **Two-Stage Sandboxed Adversarial Verification (`src/verifier.py` & `src/sandbox.py`):**
  * **Stage 1:** An adversarial Test AI inspects `.rodata` strings, `.text` disassembly, and Kuna C output to craft an exhaustive branch-coverage test suite.
  * **Stage 2 ("Double-Poke"):** Candidates passing 100% of Stage 1 trigger a second AI pass generating harder edge cases (integer overflows, empty/malformed args, flag combinations).
  * **Exact Unified Diffs:** Failures preserve full outputs and unified diffs (`stdout_diff` / `stderr_diff`) so even a 1-character capitalization mismatch is visible to the AI.
  * **Air-Gapped Bubblewrap Sandbox:** Every compilation and execution runs inside `bwrap --unshare-all --cap-drop ALL` with `/home` completely invisible and zero network access.
* **Recovery Packager (`manual_build.sh`):** Extracts the winning candidate and its exact compiler flags from any of your past runs in `.reba_history/`, runs a sandboxed launch check, and packages a clean `Makefile` project.

---

## 3. Prerequisites & Installation (Linux Only)

### Required Toolchain
* **Python 3.10+** + `capstone`
* **GNU Binutils & ELF Tools:** `objdump`, `readelf`, `nm`, `strings`, `file`, `ldd`
* **Compilers:** `gcc`, `g++` *(Optional: `clang`, `rustc`, `lld`)*
* **Sandboxing Runtime:** `bwrap` (**Bubblewrap** — mandatory; REBA refuses unisolated execution)
* **Decompiler Backend:** **[Kuna](https://github.com/Noelo-Lab/kuna)** + optional `ceasta-cli` *(Legacy fallback: Ghidra + JDK 17)*
* **DeepSeek API Key**

### Installation by Distribution

#### Arch Linux / Artix Linux / Manjaro
```bash
sudo pacman -S --needed python python-pip binutils file gcc clang bubblewrap rust lld
pip install capstone --break-system-packages
```

#### Debian / Ubuntu / Kali Linux
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-capstone binutils file gcc g++ clang bubblewrap rustc lld curl
```

#### Fedora / RHEL
```bash
sudo dnf install -y python3 python3-pip python3-capstone binutils file gcc gcc-c++ clang bubblewrap rust lld
```

### Installing Kuna (Primary Decompiler)

1. Download a release binary from [Noelo-Lab/kuna](https://github.com/Noelo-Lab/kuna/releases) or build from source:
   ```bash
   git clone https://github.com/Noelo-Lab/kuna.git
   cd kuna
   cargo build --release --bin kuna --features embed-specs
   sudo cp target/release/kuna /usr/local/bin/
   ```
2. Verify it is on your `PATH`:
   ```bash
   kuna --version
   ```

---

## 4. How to Test First (Before Spending Tokens)

Before running REBA on a large binary, make sure your local setup works cleanly:

### Step 1: Zero-Token Local Sanity Check
Verify Kuna, `htre_cli.py`, and `the_oracle.py` work on a tiny binary you compile yourself (0 API calls):
```bash
cat <<'EOF' > /tmp/smoke.c
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 5;
    for (int i = 0; i < n; i++) printf("%d\n", i);
    return 0;
}
EOF
gcc -O2 -s /tmp/smoke.c -o /tmp/smoke

# Test static extraction + Kuna (0 API calls)
python3 htre_cli.py /tmp/smoke --stdout | head -n 40

# Test Capstone byte oracle (0 API calls)
python3 the_oracle.py /tmp/smoke /tmp/smoke
```

### Step 2: Configure Your API Key & Run Your Small Test Binary
```bash
echo "sk-your-deepseek-api-key" > api_key.txt
python3 reba.py /tmp/smoke
```
If `/tmp/smoke` builds inside Bubblewrap, passes Stage 1 + Stage 2 verification, and finishes cleanly, your environment is functional and ready for real targets.

### Troubleshooting & Reporting Issues
If something fails on your machine:
* Inspect the logs inside `.reba_history/<binary>_<timestamp>/` (`session.log`, `timeline.txt`, `00_extraction/htre_cmd_and_stderr.log`, and `iter_XX/candidates/*_compile.log`).
* Gather diagnostic command outputs (`kuna --version`, `bwrap --version`, `gcc --version`, `python3 htre_cli.py /path/to/your_binary --list-funcs`).
* Open a GitHub Issue describing everything that went wrong along with those logs and command outputs so it can be investigated and fixed.

---

## 5. CLI Usage

```bash
# Automatic mode (single-shot under MAX_ANALYSIS_BYTES, multi-pass chunked above)
python3 reba.py /path/to/your_binary

# Force multi-pass bottom-up chunking on a smaller binary
python3 reba.py /path/to/your_binary --chunked

# Wipe previous checkpoints for this binary and start fresh
python3 reba.py /path/to/your_binary --clean

# Isolate reconstruction to a single function by name or hex address
python3 reba.py /path/to/your_binary --func 0x401140

# Override pre-flight size rejection
python3 reba.py /path/to/your_binary --skip-feasibility
```

### Packaging From Any of Your Past Runs (`manual_build.sh`)
After you run `reba.py` on a binary, its sessions are saved in `.reba_history/`. You can rebuild and package the winning (or highest-scoring) attempt from any of your completed or interrupted runs into a clean `Makefile` project folder:
```bash
chmod +x manual_build.sh

# Auto-pick the winning/best attempt for a binary you previously ran
./manual_build.sh /path/to/your_binary my_rebuilt_project

# Or target a specific attempt number (e.g., iter_03)
./manual_build.sh /path/to/your_binary my_rebuilt_project 3

cd my_rebuilt_project && make
```

### Standalone Extraction (`htre_cli.py`)
```bash
./htre_cli.py /path/to/your_binary --func main --only-decomp --stdout
./htre_cli.py /path/to/your_binary --list-funcs
./htre_cli.py /path/to/your_binary --backend kuna --format json -o report.json -v
```

---

## 6. Project Structure

```text
REBA/
├── reba.py                 # Thin CLI entry point
├── manual_build.sh         # Sandboxed project packager for your past runs in .reba_history/
├── htre_cli.py             # Headless ELF, strings, objdump & Kuna/Ghidra extractor
├── the_oracle.py           # Capstone instruction & byte-level diffing engine
├── prompt.txt              # Compiler-aware system prompt
├── DecompileBatch.java     # Optional Ghidra batch fallback script
├── DecompileHeadless.java  # Optional Ghidra single-function fallback script
├── README.md               # User guide & setup
├── DOCUMENTATION.md        # Technical architecture & engineering post-mortem
└── src/
    ├── config.py           # Paths, model selection, chunking & feasibility thresholds
    ├── pipeline.py         # Main orchestration pipeline & verification loop
    ├── memory.py           # Cross-run failure memory, attempt tracking & anchored prompts
    ├── winner.py           # Percentage-based scoring, checkpointing & output saving
    ├── builder.py          # Modular project writer & Makefile generator
    ├── chunker.py          # Bottom-up chunk solver, nm -u hygiene & compiler memory
    ├── graph.py            # Reachability-safe call graph (call/jmp/lea + Tarjan SCC)
    ├── validator.py        # Pre-flight feasibility & output budget gate
    ├── sandbox.py          # Hardened Bubblewrap (--unshare-all, hidden /home) compiler & runner
    ├── verifier.py         # Adversarial test generator & unified-diff fuzzer
    ├── tracker.py          # Real-time forensic logger (timeline, ai_thinking, JSONL test streams)
    └── api.py              # DeepSeek HTTP client with exponential-backoff retries
```

*(Runtime directories `.reba_originals/`, `.reba_checkpoints/`, `.reba_outputs/`, `.reba_history/`, `.htre_cache/` and `api_key.txt` are created locally on demand and excluded via `.gitignore`.)*

---

## 7. Security Model & Known Limits

* **Air-Gapped Compilation & Execution:** Both `gcc`/`rustc` compilation and Stage 1/2 binary execution run inside `bwrap --unshare-all --cap-drop ALL --new-session --clearenv` with `/home` completely invisible and zero network sockets.
* **Host-Level Parsers:** Static tools (`kuna`, `objdump`, `readelf`, `capstone`) read untrusted ELF bytes on the host without executing them. For analyzing live wild malware, always run REBA itself inside an isolated KVM/QEMU virtual machine with no shared host directories.
* **Known Limits:**
  * **Windows PE/DLLs:** Not supported.
  * **Packed / VM-Protected Binaries (UPX, VMProtect, Themida):** Must be unpacked before running REBA.
  * **Monolithic Single Functions (>120 KB decompiled C):** Require manual `--func` slicing or future SESE basic-block splitting.
  * **GUI / TUI Event Loops:** Pipe-based sandboxes cannot drive X11/Wayland windows or `ncurses` PTYs directly; isolate business logic via `--func <addr>`.

---

## License

This project is licensed under the [GNU General Public License v3.0 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.html).
