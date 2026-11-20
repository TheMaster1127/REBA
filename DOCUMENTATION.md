# REBA — Complete Technical Documentation & Engineering Post-Mortem

> **Document Scope:** Full architectural specification, mathematical design, security model, forensic telemetry layout, and a candid engineering post-mortem of every failure mode discovered and resolved during development.

---

## Table of Contents
1. [Core Thesis: Why Behavioral Equivalence Beats Byte-Identity](#1-core-thesis-why-behavioral-equivalence-beats-byte-identity)
2. [End-to-End Pipeline Architecture & Data Flow](#2-end-to-end-pipeline-architecture--data-flow)
3. [Module-by-Module Technical Specification](#3-module-by-module-technical-specification)
4. [Call-Graph Topology, Reachability & Tarjan SCC Decomposition](#4-call-graph-topology-reachability--tarjan-scc-decomposition)
5. [The Sandboxing & Air-Gapped Security Architecture](#5-the-sandboxing--air-gapped-security-architecture)
6. [Object-Level Link Hygiene & Linker Hot-Patching](#6-object-level-link-hygiene--linker-hot-patching)
7. [Two-Stage Adversarial Differential Verification & Diff Analysis](#7-two-stage-adversarial-differential-verification--diff-analysis)
8. [Forensic Telemetry, Checkpointing & Cross-Run Warm-Start](#8-forensic-telemetry-checkpointing--cross-run-warm-start)
9. [Engineering Post-Mortem: 16 Concrete Case Studies](#9-engineering-post-mortem-16-concrete-case-studies)

---

## 1. Core Thesis: Why Behavioral Equivalence Beats Byte-Identity

Traditional reverse engineering tools (Ghidra, IDA Pro, Binary Ninja) fail when utilized as autonomous code recovery engines for two fundamental reasons:
1. **Non-compilable pseudo-C:** They generate synthetic AST artifacts (`undefined4`, `CONCAT44`, raw register spills like `in_RAX`) and unstructured `goto` spaghetti that cannot be passed to a native compiler without manual human intervention.
2. **Zero verification signal:** Even when a Large Language Model (LLM) refactors decompiler pseudo-C into clean code, empirical research indicates an ~9–10% *silent wrongness* rate—syntactically valid code that compiles cleanly and looks plausible, yet computes the wrong answer on edge cases or boundary conditions.

### The Three Foundational Principles of REBA

1. **A Decompiler Is an AST Hint; Disassembly Is Ground Truth:**  
   Decompilers make speculative assumptions regarding calling conventions, struct shapes, and stack frames that frequently fail on stripped, hand-optimized, or obfuscated binaries. REBA uses **Kuna** as an agent-friendly structural skeleton, while `objdump` disassembly, `.rodata` string mappings, and section headers serve as immutable ground truth.
2. **The Capstone Oracle Provides a Continuous Gradient:**  
   Cryptographic whole-binary hashes (SHA-256) are binary pass/fail cliffs. Instruction-level diffing via Capstone (`the_oracle.py`) calculates precise instruction-matching ratios, providing a continuous feedback gradient that informs the AI which subroutines matched and which register operations diverged.
3. **Behavioral Proof Overrides Cosmetic Byte Mismatches:**  
   A compiled binary is the result of a many-to-one lossy projection:
   $$\text{Compile}: \mathcal{S} \times \mathcal{C} \times \mathcal{O} \to \mathcal{B}$$
   Different compiler versions ($\mathcal{C}$), optimization flags ($\mathcal{O}$), standard library implementations, and linker layouts produce radically different machine code for identical source semantics ($\mathcal{S}$). Chasing 100% byte identity on optimized `-O2`/`-O3` or C++ template code is an ill-posed inverse problem.  
   **Behavioral equivalence proven across exhaustive adversarial differential fuzzing is the true verification bar:**
   $$\forall (a, s) \in \mathcal{T}, \quad \mathcal{E}_{\text{orig}}(a, s) \equiv \mathcal{E}_{\text{cand}}(a, s)$$

---

## 2. End-to-End Pipeline Architecture & Data Flow

REBA operates as a multi-stage autonomous state machine. When presented with an arbitrary Linux ELF binary, it executes the following end-to-end pipeline:

```text
                     [ Target ELF Binary ]
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: STATIC EXTRACTION & PRE-FLIGHT ANALYSIS                        │
│ • Secure SHA-256 read-only backup in .reba_originals/                   │
│ • ELF metadata, section bounds, dynamically linked libraries            │
│ • Section-mapped strings (.rodata, .data, .dynstr) with offset indexing │
│ • Disassembly via objdump with inline RIP-relative string annotations   │
│ • High-speed Rust AST decompilation via Kuna (~60ms)                    │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: CALL-GRAPH & PRE-FLIGHT FEASIBILITY GATE                       │
│ • Isolate .text bounds (exclude .plt, .init, .fini stubs)               │
│ • Extract directed edges: call <addr>, jmp <addr>, lea reg, [rip+off]   │
│ • Group mutual recursion using Tarjan's Strongly Connected Components   │
│ • BFS reachability traversal from detected entry point                  │
│ • Feasibility check: reject functions exceeding synthesis token budget  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
               ┌─────────────────────┴─────────────────────┐
               │ (Analysis <= MAX_ANALYSIS_BYTES)          │ (Analysis > MAX_ANALYSIS_BYTES)
               ▼                                           ▼
     [ Single-Shot Mode ]                   [ PHASE 3: MULTI-PASS CHUNKING ]
               │                            • Startup Audit (aux_*): inspect unreachable
               │                              .text; exclude dead CRT boilerplate.
               │                            • Helper Chunks (chunk_*): pack bottom-up
               │                              up to MAX_CHUNK_BYTES / MAX_FUNCS_PER_CHUNK.
               │                            • Object Hygiene (nm -u): compile-check (-c)
               │                              and reject dangling phantom labels (dat_*).
               │                            • Immediate checkpointing to disk.
               └─────────────────────┬─────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 4: ROOT SYNTHESIS & BEST-ANCHORED WORKING MEMORY                  │
│ • Expose reba_chunks.h + full helper implementations to root prompt     │
│ • Warm-start from previous closest winner & active test failures        │
│ • Direct `file_patches` channel allows AI to hot-patch buggy chunks     │
│ • Compile candidate in Bubblewrap with -Wl,--allow-multiple-definition  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ PHASE 5: TWO-STAGE ADVERSARIAL VERIFICATION                             │
│ • Stage 1: Exhaustive test suite (arguments, stdin, switch coverage)    │
│ • Run differential fuzzing inside Bubblewrap (--unshare-all)            │
│ • Full unified diff extraction centered on first output mismatch        │
│ • Stage 2: Survivors trigger second AI pass for extreme edge cases      │
│ • Track best candidate by pass percentage with most-recent tie-breaker  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
               ┌─────────────────────┴─────────────────────┐
               │ (100% Stage 1 & 2 pass)                   │ (Max attempts / Ctrl+C)
               ▼                                           ▼
      [ Full Winner ]                             [ Closest Winner ]
      Modular src/ + include/ + Makefile          Modular src/ + include/ + Makefile
```

---

## 3. Module-by-Module Technical Specification

### `reba.py` (CLI Front-End)
A minimal, lightweight dispatcher (~30 lines) that isolates CLI argument parsing from execution logic.
* **Arguments:**
  * `binary`: Path to the ELF target.
  * `--func <name|addr>`: Scopes extraction and synthesis to a single isolated function.
  * `--chunked`: Forces bottom-up multi-pass chunking regardless of binary size.
  * `--clean`: Wipes cached checkpoints in `.reba_checkpoints/<bin>_<sha16>/` to force a clean re-solve.
  * `--skip-feasibility`: Overrides pre-flight safety size checks.

### `src/pipeline.py` (Core Orchestration Engine)
Contains the primary execution loop of the REBA engine:
* Drives static extraction via `htre_cli.py`.
* Constructs the topological synthesis plan.
* Manages the iterative reconstruction loop across `MAX_ITERATIONS` attempts.
* **Regression Discarding:** Detects when an experiment scores lower than the current best anchor, explicitly instructing the AI to discard the regression and return to the anchor.
* Emits the final modular project via `src/winner.py`.

### `src/memory.py` (Cross-Run Telemetry & Working Memory)
Manages forensic telemetry, state persistence, and prompt anchoring:
* **`load_warmstart_closest_winner()`**: Detects prior `closest_winner` runs from disk, restoring the previous best `main.c`, patched modular chunks, and remaining test failures into Attempt 1.
* **`build_anchored_messages()`**: Keeps LLM context windows lean (~25–35k tokens) by always anchoring on the single best candidate so far rather than stacking stale failed candidates.
* **`record_failure_memory()`**: Records up to 12 active failure lessons in `failure_memory.json`. When a new all-time best score is achieved, clears resolved failures and records only remaining active bugs.
* **`record_attempt_memory()`**: Appends attempt summaries to `attempt_memory.json` to preserve cross-attempt history.

### `src/winner.py` (Scoring & Project Packaging)
Handles candidate ranking and modular artifact generation:
* **`score_candidate()`**: Computes a ranking tuple:
  $$\text{Score} = \langle \text{Stage1\_AllPassed}, \text{Stage1\_\%}, \text{Stage2\_\%}, \text{AttemptNum}, \text{HashEq}, \text{Oracle\%} \rangle$$
* **`save_best_output()`**: Packages the final modular project into `.reba_outputs/` (`src/`, `include/`, `Makefile`, `README.md`) using the candidate's exact winning compiler command. Never emits broken single-file standalone code.

### `src/builder.py` (Modular Project Generator)
* **`parse_cmd_flags()`**: Parses compiler tokens using `shlex`, extracting the exact compiler (`gcc`, `g++`, `rustc`), `CFLAGS`, and `LDFLAGS` from the candidate command.
* **`write_modular_project()`**: Generates a standard `Makefile` incorporating necessary flags (`-nostdlib`, `-D_GNU_SOURCE`, `-Wl,--allow-multiple-definition`, etc.) so the user can build the project natively with `make`.

### `src/chunker.py` (Bottom-Up Chunk Solver & Object Hygiene)
* Enforces canonical `sub_<hex>` naming across all modules.
* **`check_chunk_link_hygiene()`**: Uses `nm -u` inside Bubblewrap to reject object files referencing dangling assembly labels (`dat_*`, `unk_*`, `off_*`, `byte_*`, `word_*`, `dword_*`, `qword_*`, `stru_*`) or re-declaring standard glibc symbols (`argp_program_version_hook`, `optind`, `errno`) in chunk headers.
* **`reconstruct_chunk_with_autosplit()`**: Auto-splits chunks in half recursively if completion tokens hit output limits (`finish_reason == "length"`) or exceed retry budgets.

### `src/graph.py` (Call-Graph Topology & Tarjan SCC)
* Isolates `.text` boundaries to prevent dynamic linking stubs (`.plt`) from contaminating analysis.
* Detects `main()` via symbols, Kuna AST heuristics, libc initialization arguments (`__libc_start_main`), or `_start` disassembly patterns.
* Computes Tarjan's Strongly Connected Components (SCC) to keep mutually recursive functions together.
* Sorts all graph nodes, SCC clusters, and batches strictly by numeric hex address to guarantee deterministic chunk ordering across runs.

### `src/sandbox.py` (Hardened Bubblewrap Isolation)
* Implements air-gapped sandboxing using `bwrap --unshare-all --cap-drop ALL --clearenv`.
* Verifies environment safety at startup using a self-test command (`echo REBA_SANDBOX_OK`).
* Enforces POSIX resource limits (`RLIMIT_CPU`, `RLIMIT_FSIZE`) and execution timeouts.
* Normalizes target execution to `./target_bin` to prevent `argv[0]`-dependent divergence.

### `src/verifier.py` (Adversarial Fuzzing & Diff Analysis)
* Generates exhaustive Stage 1 test suites (50–160+ tests) covering flags, switch cases, boundary values, and file/stdin operations.
* Triggers Stage 2 "Double-Poke" edge-case tests on candidates achieving 100% on Stage 1.
* **`format_output_for_report()`**: Preserves complete stdout/stderr strings unless exceeding 4 KB, in which case it centers a window around the first differing byte.
* **`make_unified_diff_snippet()`**: Emits standard unified diffs (`--- ORIG\n+++ CAND`) showing exact line and character disparities.

### `manual_build.sh` (Autonomous Package Recovery)
* Scans `.reba_history/` sessions from newest to oldest.
* Reads `session_report.json` to identify the winning candidate and exact compile command.
* Runs a sandboxed execution smoke test to verify the rebuilt binary does not crash (`SIGSEGV` / `rc=139`) on launch.
* Emits a standalone `Makefile` and `README.md` configured with the verified compiler flags.

---

## 4. Call-Graph Topology, Reachability & Tarjan SCC Decomposition

### Mathematical Formulation of the Call Graph
Let the program code space be represented as a directed graph $G = (V, E)$, where $V$ is the set of functions located within the `.text` segment:
$$V = \{ f \in \text{ELF} \mid \text{Addr}(f) \in [\text{text\_start}, \text{text\_end}) \}$$

The directed edge set $E \subseteq V \times V$ represents control-flow references:
$$(u, v) \in E \iff u \text{ contains a direct } \texttt{call } v, \text{ tail } \texttt{jmp } v, \text{ or } \texttt{lea reg, } [\text{rip} + \text{offset}] \to v$$

```text
               ┌─────────────┐
               │  main (u)   │
               └──────┬──────┘
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
   ┌───────────┐             ┌───────────┐
   │  sub_A    │◄───────────►│  sub_B    │   <-- Strongly Connected Component
   └─────┬─────┘   (Mutual   └─────┬─────┘       (Atomic Synthesis Cluster)
         │        Recursion)       │
         ▼                         ▼
   ┌───────────┐             ┌───────────┐
   │  sub_C    │             │  sub_D    │   <-- Leaf Helpers (Stage 0)
   └───────────┘             └───────────┘
```

### Strongly Connected Components (Tarjan's Algorithm)
If function $u$ calls $v$ and $v$ calls $u$, synthesizing them in separate chunks results in mutual unresolved dependencies. REBA computes Strongly Connected Components (SCC):
$$C \subseteq V \quad \text{such that} \quad \forall u, v \in C, \quad u \rightsquigarrow v \text{ and } v \rightsquigarrow u$$
Every SCC cluster is treated as an indivisible atomic unit and synthesized within the same translation unit.

### Deterministic Reachability & Topological Sorting
1. **Reachability Partition:** Breadth-First Search (BFS) traverses $G$ starting from $\text{root} = \text{main}$:
   $$V_{\text{reachable}} = \{ v \in V \mid \text{main} \rightsquigarrow v \}, \quad V_{\text{aux}} = V \setminus V_{\text{reachable}}$$
2. **Deterministic Ordering:** Python sets randomize iteration order due to siphash seed randomization (`PYTHONHASHSEED`). REBA sorts all clusters, neighbors, and synthesis batches strictly by numeric hexadecimal entry address:
   $$\text{SortKey}(C) = \min_{v \in C} \text{int}(\text{Addr}(v), 16)$$
3. **Synthesis Packing:** Clusters are scheduled bottom-up (leaves first, root last) and packed into translation units respecting `MAX_CHUNK_BYTES` (150 KB) and `MAX_FUNCS_PER_CHUNK` (15 functions).

---

## 5. The Sandboxing & Air-Gapped Security Architecture

Reverse engineering untrusted or stripped binaries requires strict containment. A candidate binary or compiler invocation must never have access to host credentials, private keys, or network interfaces.

### Bubblewrap (`bwrap`) Isolation Parameters

```text
Host System Filesystem               Sandboxed Execution Namespace (/tmp/work)
┌────────────────────────┐           ┌─────────────────────────────────────────┐
│ /home/user/...         │ ──[BLOCK]─┼─> (Completely invisible; unmounted)     │
│ ~/.ssh, api_key.txt    │ ──[BLOCK]─┼─> (Zero access)                         │
│ Host Network Interfaces│ ──[BLOCK]─┼─> (Unshared network namespace: loopback)│
│ /usr, /bin, /lib       │ ──[RO]────┼─> Read-only system runtime trees        │
│ /etc/ld.so.cache       │ ──[RO]────┼─> Dynamic linker cache                  │
│ Disposable Tempdir     │ ──[RW]────┼─> Mounted at /tmp/work (tmpfs)          │
└────────────────────────┘           └─────────────────────────────────────────┘
```

Every compilation and execution step runs within `SafeSandbox`:
* `--unshare-all`: Unshares CLONE_NEWNS, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWPID, CLONE_NEWUTS, and CLONE_NEWCGROUP.
* `--cap-drop ALL`: Drops all Linux capabilities (including `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_PTRACE`).
* `--new-session`: Detaches the process from the controlling terminal, blocking `TIOCSTI` terminal injection attacks.
* `--clearenv`: Clears all environment variables, passing only sanitized `PATH` and `TMPDIR`.
* Mount configuration:
  * `--ro-bind /usr /usr`, `--ro-bind /etc /etc`, `--dev /dev`, `--proc /proc`.
  * Symlink-aware bindings for `/bin`, `/sbin`, `/lib`, `/lib64`.
  * Disposable isolated `tmpfs` mounted at `/tmp/work`. `/home` is completely absent.
* **Resource Limits:** Enforces POSIX `RLIMIT_CPU` (timeout + 2 seconds) and `RLIMIT_FSIZE` (50 MB cap) to prevent CPU starvation and disk-exhaustion attacks.

---

## 6. Object-Level Link Hygiene & Linker Hot-Patching

### The Link Hygiene Gate (`nm -u`)
Independent compilation (`gcc -c`) verifies syntax but ignores link-time semantics:
```c
extern unsigned long dat_ab40; // gcc -c accepts this dangling symbol!
```
If `dat_ab40` was an uninitialized `.rodata` offset that the LLM failed to implement, `gcc -c` passes, but linking `main()` fails with `undefined reference to dat_ab40`. If `main()` works around it with dummy stubs, the helper **crashes with a segmentation fault (`rc=139`) at runtime**.

REBA inspects every compiled `.o` file with `nm -u --format=just-symbols` inside Bubblewrap:
* Any undefined symbol matching `^(dat|unk|off|byte|word|dword|qword|stru)_[0-9a-fA-F]+$` that is not declared in `existing_headers` causes immediate rejection.
* Any chunk header attempting to re-declare standard glibc/argp symbols (`argp_program_version_hook`, `optind`, `errno`) is rejected before it can poison downstream headers.

### Linker Hot-Patching Engine
When synthesizing `main()`, the linker is invoked with `-Wl,--allow-multiple-definition` and `reba_src.c` (`main.o`) placed first in link order:
$$\texttt{gcc } \dots \texttt{ -Wl,--allow-multiple-definition } \mathbf{main.o} \texttt{ chunk\_1.o chunk\_2.o } \dots$$
Under GNU `ld`, when duplicate symbol definitions occur across translation units, the first definition encountered takes precedence. This allows `main()` to override incomplete or buggy helper chunk implementations on the fly.

### The Direct `file_patches` Channel
Candidates may provide an optional `"file_patches"` dictionary in their JSON completion:
```json
{
  "candidates": [
    {
      "code": "/* main.c code */",
      "compile_commands": ["gcc -O2 ..."],
      "file_patches": {
        "src/chunk_5.c": "/* complete replacement for chunk 5 */",
        "include/reba_chunks.h": "/* updated header */"
      }
    }
  ]
}
```
If supplied, REBA applies these patches to a private translation unit overlay, verifies compilation, and updates checkpoints upon test improvement.

---

## 7. Two-Stage Adversarial Differential Verification & Diff Analysis

### Stage 1: Branch & Switch Exhaustion
The Test AI inspects strings, disassembly, and Kuna ASTs to construct an adversarial test suite (50–160+ test cases) targeting 100% control-flow branch coverage:
* Every command-line flag (short, long, concatenated e.g. `-afis`, repeated e.g. `-a -a`).
* Every switch case and subcommand.
* Ambiguous prefixes (`--=x`, `---`).
* Boundary parameters (empty string `""`, negative numbers `-1`, `-2147483648`, integer extremes).
* File inputs (valid files, `/dev/null`, `/nonexistent`, directories `/`, stdin streams `# comments`).

### Stage 2: Adversarial "Double-Poke"
Candidates achieving 100% on Stage 1 trigger an immediate second AI pass generating 15–40+ extreme edge-case tests designed to expose subtle decompilation bugs:
* 64-bit integer overflow limits (`LONG_MAX + 1`).
* Malformed numeric strings (`12abc`, `+005`).
* Embedded NULL bytes, UTF-8 sequences, whitespace variations.
* Flag precedence interactions (e.g. GNU `hostname` ignoring positional arguments when display flags like `-a`/`-d`/`-f` are present).

### Unified Diff Extraction
Previous pipelines suffered blindspots from arbitrary output truncation (e.g. slicing stdout at character 400). In GNU `hostname`, the help message mismatch was a 1-character capitalization difference (`"give this help list"` vs `"Give this help list"`) at character 459:
```text
Character 0..431: "Usage: target_bin [OPTION...] [NAME] ... -y, --yp, --nis"  (Identical)
Character 459:    ORIG: "give this help list"  vs  CAND: "Give this help list"  (Divergence)
```
REBA preserves full stdout/stderr streams up to 4 KB and extracts exact unified diffs centered on the point of divergence:
```diff
--- ORIG
+++ CAND
@@ -10,3 +10,3 @@
-  -?, --help                 give this help list
+  -?, --help                 Give this help list
```

---

## 8. Forensic Telemetry, Checkpointing & Cross-Run Warm-Start

Every session generates an audit archive under `.reba_history/<binary>_<timestamp>/`:

| File / Folder | Purpose |
| :--- | :--- |
| `session.log` | Millisecond-timestamped live terminal mirror |
| `timeline.txt` & `timeline.jsonl` | Structured chronological event log with elapsed timings |
| `session_report.json` | Master telemetry updated live after every attempt |
| `00_extraction/` | Snapshots of system prompts, Kuna C, disassembly, and strings |
| `chunks/` | Verified chunk code, headers, raw replies, and AI thinking traces |
| `iter_XX/candidates/` | Every generated candidate source file and compilation log |
| `iter_XX/verification/` | Full adversarial test suites, `all_tests.jsonl`, and readable test logs |

Persistent caches in `.reba_checkpoints/<binary>_<sha16>/` store:
* `chunk_*.c` and `chunk_*.h` verified helper chunks.
* `stage_1_tests.json` cached adversarial test suite.
* `failure_memory.json` active test failure lessons.
* `attempt_memory.json` historical attempt scores.
* `closest_winner/` highest-scoring modular source and test logs.

### Cross-Run Warm-Start
When re-running a binary, REBA detects `.reba_checkpoints/<binary>_<sha16>/closest_winner/`:
1. Restores the highest-scoring `main.c`, patched modular chunks, and active test failures into Attempt 1.
2. Injects `failure_memory.json` lessons into the prompt to prevent repeat mistakes.
3. **No-Regression Protection:** A lower-scoring attempt in a new run will **never** overwrite a higher-scoring candidate already preserved in checkpoints.

---

## 9. Engineering Post-Mortem: 16 Concrete Case Studies

### Case Study 1: Decompiler Latency Bottleneck
* **Failure:** Ghidra headless required 25–45 seconds per run due to JVM startup, slowing iteration cycles.
* **Root Cause:** Heavy JVM runtime overhead and standard-ABI cspec analysis.
* **Resolution:** Integrated **Kuna** (Rust-native decompiler) into `htre_cli.py`, reducing AST extraction to ~60–150ms while preserving Ghidra as a secondary fallback.

### Case Study 2: Stripped Binary Symbol Discovery Failure
* **Failure:** Stripped binaries emitted zero decompilation output.
* **Root Cause:** `nm -n -S` returned empty on stripped binaries; regex `^[0-9a-fA-F]+$` failed to match multi-column output from fallback scanners.
* **Resolution:** Implemented multi-column address parsing fallback via `ceasta-cli funcs` extracting the first hexadecimal token.

### Case Study 3: Silent Bubblewrap Read-Only False-Positive
* **Failure:** Flawed candidate passed test suites despite incorrect logic.
* **Root Cause:** Sandbox command `bwrap --ro-bind / / --bind tmp /sandbox` failed with `Read-only file system` identically on both original and candidate binaries. Because `orig_code == cand_code == 1` and both emitted identical errors, the fuzzer recorded false-positive passes.
* **Resolution:** Mounted private writable `tmpfs` at `/tmp`, bound disposable workdir to `/tmp/work`, and added an initial self-test (`echo REBA_SANDBOX_OK`) that aborts if sandboxing fails.

### Case Study 4: Candidate Variable Overwrite in Verification
* **Failure:** Verification tested Candidate 3 even when Candidate 2 won.
* **Root Cause:** Loop evaluating candidates sequentially wrote to the shared filename `reba_src.c`, leaving the last candidate on disk rather than the highest-scoring one.
* **Resolution:** Isolated candidate binary outputs (`reba_cand_N_out`) and added explicit `best_code` tracking before triggering verification.

### Case Study 5: Test Generation Context Truncation Blindspot
* **Failure:** Test generator produced generic tests, failing to test core binary logic.
* **Root Cause:** Slicing raw analysis text at character 15,000 cut off output inside `.dynsym`/`.rela.dyn`, starving the Test AI of `.text` disassembly and Kuna C code.
* **Resolution:** Built `build_tester_context()` stripping ELF header bloat to feed pure strings, `.text` disassembly, and Kuna C output directly to the Test AI.

### Case Study 6: False Test Failures on `argv[0]` and PID Paths
* **Failure:** Candidate failed tests despite identical logic.
* **Root Cause:** Differential fuzzer compared `/proc/self/cmdline` and process names, which differed between original (`.reba_originals/bin_hash`) and candidate (`reba_out`).
* **Resolution:** Explicitly banned `/proc/self/*` in test prompts and normalized binary execution to `./target_bin` inside the sandbox.

### Case Study 7: Non-Deterministic Python Set Ordering
* **Failure:** Identical binaries produced completely different chunk decompositions across runs.
* **Root Cause:** Unordered Python `set()` iteration in call-graph construction varied across runs due to `PYTHONHASHSEED` randomization.
* **Resolution:** Sorted all graph nodes, SCC clusters, and synthesis batches strictly by numeric hexadecimal entry address (`int(addr, 16)`).

### Case Study 8: 65,536 Token Reasoning Overflow in Multi-Candidate Prompts
* **Failure:** LLM crashed with `finish_reason == "length"` at 65k tokens during root synthesis.
* **Root Cause:** Requesting 3 full candidates on large binaries triggered runaway chain-of-thought reasoning (64k+ thinking tokens).
* **Resolution:** Clamped reasoning length, restricted root synthesis to 1 clean candidate in chunked runs, and added automatic autosplitting when completion limits are reached.

### Case Study 9: Helper Chunk Empty Struct Stubs (`{0}`)
* **Failure:** GNU `hostname` failed 108 of 112 tests with `invalid option`.
* **Root Cause:** Chunk 5 reconstructed `sub_8ed0` using `struct argp argp = {0};` because global options arrays resided in `.data`/`main()`. `main()` assumed `sub_8ed0` parsed arguments and called it blindly.
* **Resolution:** Passed full implementations of helper chunks into the root synthesis prompt so `main()` can inspect helper bodies and override stubs.

### Case Study 10: Cross-Chunk Symbol Link Collisions
* **Failure:** Linking helper chunks and root failed with `multiple definition` or `conflicting types`.
* **Root Cause:** Different chunks guessed different signatures for unexported helpers; GCC 14+ defaults to `-fno-common`.
* **Resolution:** Enforced canonical `sub_<hex>` naming, enabled `-fcommon`, and passed `-Wl,--allow-multiple-definition`.

### Case Study 11: Catastrophic Regex Backtracking in Brace Parsing
* **Failure:** Rebuilding standalone code froze CPU at 100% for over 10 minutes.
* **Root Cause:** Regex `(?:[^{}]*|\{[^{}]*\})*` suffered catastrophic backtracking on 4-level nested switch statements in `chunk_1.c`.
* **Resolution:** Replaced regex brace parsing with an $O(N)$ linear state-machine brace counter.

### Case Study 12: Character Truncation Hiding 1-Byte Help String Disparities
* **Failure:** DeepSeek stagnated at 109/112 tests on GNU `hostname` across 10 attempts without fixing `--help`.
* **Root Cause:** Differential fuzzer sliced stdout at 400 characters (`orig_out_str[:400]`). In GNU `hostname`, the help message mismatch (`"give"` vs `"Give"`) occurred at character 459, so the AI received identical output strings.
* **Resolution:** Preserved full stdout/stderr streams up to 4 KB and generated unified diff snippets (`stdout_diff` / `stderr_diff`) centered on the exact mismatch.

### Case Study 13: Function Pointer Global Variable Redefinitions
* **Failure:** Standalone single-file compilation failed with `redefinition of 'dat_d320'`.
* **Root Cause:** Both `chunk_5.c` and `main.c` defined function pointer globals (`int (*dat_d320)(const char *, size_t)`). Regex global matchers failed to match function pointer syntax, missing deduplication.
* **Resolution:** Added dedicated function pointer regex matching (`GLOBAL_FNPTR_RE`), deduplicated globals across modules, and selected one authoritative definition.

### Case Study 14: Angle-Bracket Include Leakage in Standalone Merger
* **Failure:** Merged standalone C file failed with `fatal error: reba_chunks.h: No such file or directory`.
* **Root Cause:** DeepSeek emitted `#include <reba_chunks.h>` (with angle brackets). The merger checked only quoted includes (`#include "reba_chunks.h"`), allowing the angle-bracket include to leak into the merged file.
* **Resolution:** Updated regex (`REBA_INC_RE`) to match and strip both quoted and angle-bracket include variants (`#include [<"][^">]*reba_chunks\.h[>"]`).

### Case Study 15: ELF PT_LOAD Page-Congruence Misalignment Segfault (`cib_hello`)
* **Failure:** Rebuilt `cib_hello` binary compiled with returncode 0 but segfaulted immediately on launch.
* **Root Cause:** The compile command used `-Wl,-Ttext=0x400078 -Wl,-N`. In the resulting ELF:
  $$p\_vaddr - p\_offset = 0x400078 - 0x120 = 0x3fff58 \not\equiv 0 \pmod{4096}$$
  Linux kernel `elf_map` requires $(p\_vaddr \bmod 4096) == (p\_offset \bmod 4096)$. The kernel returned `-EINVAL` on `mmap`, causing the entry point instruction fetch to fault.
* **Resolution:** Extracted winning compiler flags directly from `session_report.json` (which used `-Wl,-n` / congruent layout) and added execution smoke tests to `manual_build.sh`.

### Case Study 16: Dangling Phantom Labels (`dat_*`) Causing Runtime Segfaults
* **Failure:** Clean run failed with segfaults across 100% of tests.
* **Root Cause:** `chunk_5.c` emitted `extern dat_ab40;` without defining it. Independent compilation (`gcc -c`) passed, but linking `main()` caused crashes or link failures.
* **Resolution:** Implemented the `nm -u` hygiene gate in `compile_object_check`, rejecting any chunk referencing undeclared `dat_*` labels before it can be checkpointed.
