# REBA — Reverse Engineer Basically Everything

> **REBA** = **R**everse **E**ngineer **B**asically **E**verything  
> An AI-driven, oracle-verified pipeline for turning compiled binaries back into readable, behaviorally-equivalent source code.

**Status:** Concept + working foundation (Ghidra headless on ARM64 Termux, decompile pipeline proven)  
**Primary target:** x86-64 ELF, stripped or unstripped, any optimization level  
**Secondary targets:** ARM64 Android `.so`, old Windows games, J2ME (easy win), S60/Symbian native binaries  
**Core thesis:** The toolchain + Capstone instruction-diff loop + AI reconstruction converges on functionally-equivalent C, per-function, with confidence scores.

---

## Part 1 — The Foundation: Ghidra on a Phone

Before any of the REBA pipeline exists, we proved that serious reverse-engineering tooling can run *headless* on an Android phone in Termux. This is the seed that made everything else possible to build on.

### 1.1 The device

- Samsung SM-A346E (Galaxy A34), Android 14, ARM64
- MediaTek Dimensity 6877V (2×2.6 GHz + 6× little cores)
- 7.3 GiB RAM, 4 GiB swap, ~48 GB free on `/storage/emulated`
- Termux 0.118.2, bash 5.3.9

**Reality check:** Ghidra headless on this hardware is usable for small-to-medium binaries. Large `.so` files will take 20–40 minutes and can OOM-kill the JVM if background apps are hogging RAM. It works — it's just not a desktop.

### 1.2 The install (the actual journey)

What was attempted, in order, and what actually mattered:

1. **First tarball was fake.** Found a 649 KB `*.tar.gz` in `~/storage/downloads/` with a UUID filename. `file` said gzip, but the size was absurd — it was an incomplete/mislabeled download. **Rule: always `ls -lh` and sanity-check the size against the release page.**
2. **Real tarball is 384 MB.** Downloaded directly from GitHub via `curl -LO`:
   ```bash
   curl -LO https://github.com/dsgou66/ghidra-termux-arm64/releases/download/v11.0-dev-termux-arm64/ghidra-11.0-Dev-termux-arm64.tar.gz
   ```
3. **Extracted cleanly** to `~/ghidra-final/ghidra_11.0_DEV`.
4. **Verified Java.** JDK 17 is required for Ghidra 11.x; the phone already had `openjdk 17.0.21`. If missing:
   ```bash
   pkg install openjdk-17
   ```
5. **Verified headless launcher** with a bare `analyzeHeadless` call — printed usage text, exited cleanly. This is the smoke test before touching a real binary.

### 1.3 The two gotchas that cost time

- **`pythin` vs `python`.** An honest typo in the terminal cost one round-trip.
- **`Directory not found` on first headless run.** Ghidra does **not** create the *project location* folder — only the project folder inside it. You must `mkdir -p ~/ghidra_projects` first. This is documented nowhere obvious and it's the #1 first-run failure.

### 1.4 The working decompile script

**`decomp.sh`** — takes a binary, decompiles every function, prints `main` last, nothing else on stdout. Uses a custom Java Ghidra script to dump decompiled C to a temp file (no `INFO` noise to filter), then `awk` reorders so `main` is always the last block. Unique project name per run avoids lock collisions; `-deleteProject` keeps disk clean.

```bash
#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <binary>" >&2
    exit 1
fi

BIN="$1"
[ -f "$BIN" ] || { echo "error: not a file: $BIN" >&2; exit 1; }
BIN="$(realpath "$BIN")"

GHIDRA="${GHIDRA_HOME:-$HOME/ghidra-final/ghidra_11.0_DEV}"
SCRIPTS="$HOME/ghidra_scripts"
PROJDIR="$HOME/ghidra_projects"
OUT="$(mktemp)"
LOG="$(mktemp)"
PROJ="Decomp_$$_$(date +%s)"

[ -x "$GHIDRA/support/analyzeHeadless" ] || {
    echo "error: analyzeHeadless not found at $GHIDRA/support/analyzeHeadless" >&2
    echo "set GHIDRA_HOME to your ghidra_11.0_DEV dir" >&2
    exit 1
}

mkdir -p "$SCRIPTS" "$PROJDIR"

cat > "$SCRIPTS/DecompileAll.java" <<'JAVA'
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.*;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = System.getenv("DECOMP_OUT");
        if (outPath == null) outPath = "/tmp/decomp.txt";
        PrintWriter w = new PrintWriter(new FileWriter(outPath));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isThunk() || f.isExternal()) continue;
            DecompileResults res = decomp.decompileFunction(f, 60, monitor);
            if (res.decompileCompleted()) {
                w.println("// === " + f.getName() + " ===");
                w.println(res.getDecompiledFunction().getC());
                w.println();
            }
        }
        w.close();
    }
}
JAVA

export DECOMP_OUT="$OUT"

if ! "$GHIDRA/support/analyzeHeadless" "$PROJDIR" "$PROJ" \
        -import "$BIN" \
        -scriptPath "$SCRIPTS" \
        -postScript DecompileAll.java \
        -deleteProject >"$LOG" 2>&1; then
    echo "error: ghidra failed. last 20 lines of log:" >&2
    tail -20 "$LOG" >&2
    rm -f "$LOG" "$OUT"
    exit 1
fi
rm -f "$LOG"

[ -s "$OUT" ] || { echo "error: no decompiled output" >&2; rm -f "$OUT"; exit 1; }

awk '
  /^\/\/ === / {
    if (block != "") {
      if (is_main) main_block = block
      else printf "%s", block
    }
    block = $0 "\n"
    is_main = ($0 == "// === main ===")
    next
  }
  { block = block $0 "\n" }
  END {
    if (block != "") {
      if (is_main) main_block = block
      else printf "%s", block
    }
    if (main_block != "") printf "%s", main_block
  }
' "$OUT"

rm -f "$OUT"
```

**Usage:**
```bash
chmod +x decomp.sh
./decomp.sh ~/test
```

**What we verified it does correctly:**
- Every function decompiled, `// === name ===` header per function
- `main` forced to the last block
- Real names recovered when compiled with `-g`
- Returns `0x41` for `printf("%c\n", 0x41)` when the source was `var1 + var2` (Ghidra's own constant folding — correct, but not the source form)

**What it *doesn't* do (and why):**
- **Empty function bodies at `-O0`** — Ghidra's decompiler does its own dead-store elimination. If variables are declared and assigned but never read, Ghidra removes the stores even though the machine code is present. This is a *decompiler* artifact, not a `decomp.sh` bug. Fix: use the variables (e.g. `printf` them) so the stores are semantically live.
- **`WARNING: Unknown calling convention`** — cosmetic. Ghidra didn't auto-detect the AArch64 PIE cspec. Can be silenced with `-processor "AARCH64:LE:64:v8A" -cspec "gcc"`, but output is already correct without it.

**Why this foundation matters:** it proves the whole REBA thesis — that a pipeline can drive Ghidra headless, feed the output to whatever comes next (Capstone diff, LLM cleanup, static recompilation), and get results on hardware that fits in a pocket. That's the seed.

---

## Part 2 — The Core Idea: REBA

### 2.1 The goal

Given an arbitrary compiled binary — stripped, optimized, unknown toolchain — produce **readable C source that is functionally equivalent to the original**, with a **per-function confidence score** so the analyst knows what to trust.

Not byte-identity. That was a wrong goalpost for a long time (and byte-identity is a party trick on `-O0` demos). The real target is **behavioral equivalence** — the reconstruction runs the same, produces the same outputs on the same inputs, and survives differential fuzzing.

### 2.2 The oracle is everything

The single most important insight: **an AI is only as good as the oracle it's optimized against.**

- Dumb oracle (compile once, run once) → AI confidently converges on *wrong* C.
- Better oracle (whole-binary SHA-256, pass/fail) → works, but slowly; converges only when everything is right.
- **Best oracle (per-instruction Capstone diff, with address normalization)** → gives the AI a *gradient*, not a cliff. It knows *which function* is wrong and *which instructions* mismatch. This is the key.

The 2026 research is clear: an AI + iterative oracle loop reaches ~96% re-compilability on stripped, optimized binaries, but only ~80% re-executability (functional correctness) because the oracle isn't strong enough yet. **Improving the oracle is the highest-leverage move.**

### 2.3 The pipeline

```
input binary
  → fingerprint toolchain  (.comment, endbr64, stack canary, PIE bit, .note)
  → disassemble (objdump + Capstone)
  → decompile (Ghidra headless via decomp.sh)
  → chunk per function
  → for each function:
        ask AI to reconstruct source
        compile candidate source with N toolchain/flag candidates
        disassemble candidate
        normalize addresses (jump targets, PC-relative, GOT/PLT refs)
        Capstone-diff: candidate vs target
        if match < threshold: feed diff chunks back to AI, iterate
        else: emit source + confidence score
  → output: readable C, one function at a time, with per-function confidence
```

### 2.4 The Capstone loop — the "atoms of asm"

This is the piece that makes REBA work. The idea:

1. Disassemble target function → list of `(mnemonic, operands)` atoms.
2. Recompile candidate source → disassemble → normalized list of atoms.
3. **Normalize** addresses before diffing:
   - Jump targets → basic-block-relative labels
   - PC-relative offsets → symbolic refs (`%rip + sym` → `sym`)
   - GOT/PLT entries → resolve to function names when possible
   - Constant pool loads → `load_imm` normalization
4. **Two-tier diff** to give the AI a gradient:
   - **Tier 1 (cheap):** mnemonic-only match. Fast signal, coarse.
   - **Tier 2 (fine):** operand class + exact operand match. Tells the AI *what specifically* is wrong.
5. Score = `(matched_atoms / total_atoms)` per function, with penalties for structural mismatches (jump table shape, call graph shape).

**Why per-instruction beats whole-binary hash:** the hash is pass/fail. Capstone diff says "function `FUN_00101234` is 87% matched, mismatches at 0x00101300–0x00101308: target has `lea` where you have `mov`." That's a gradient, and gradients converge.

### 2.5 Toolchain and flag guessing

This is more solved than it feels:

- `.comment` → exact GCC version (when present).
- `endbr64` at every function entry → `-fcf-protection=full`.
- PIE bit in ELF header → `-fPIE`/`-pie` vs static.
- Stack canary in prologues → `-fstack-protector` variant.
- Inlining patterns + function reordering → guess `-O` level.
- `std::string` SSO size, libstdc++ symbol versions → pin the toolchain further.

Then: **brute-force the remaining unknowns in parallel.** Compile candidate source against all plausible flag combinations, pick the highest Capstone match. Cheap, fast, and turns "guess the compiler" from a puzzle into a search.

**Fallback:** if no flag combo converges, the AI keeps guessing and re-trying. If *still* no convergence on a function, **inline asm as a last resort** — the function becomes a wrapper around the exact target instructions. That's an admission of defeat on readability for that specific function, but it guarantees correctness and gives the analyst working code.

### 2.6 Confidence scores — the feature that makes it usable

For real security work, **silent wrongness is the only unforgivable failure mode.** The output must be honest about what it doesn't know:

```
main:         100% (12/12 atoms) — high confidence
FUN_00101234: 87%  (29/33 atoms) — review mismatched instructions
FUN_00101abc: 41%  (12/29 atoms) — LOW CONFIDENCE, asm fallback used
```

A malware analyst doesn't need every function perfect. They need to know which functions to trust and which to read themselves. This is what makes the tool *shippable* to real analysts.

---

## Part 3 — The Tool Landscape (and what we're not using, and why)

The space is crowded. Here's what exists and the honest verdict on each:

### 3.1 Open-source decompilers — the ones that matter

| Tool | Verdict |
|---|---|
| **Ghidra** | **Primary backend.** Free, open, headless, ARM64-Termux-capable. The one we're driving. |
| **RetDec** | **Secondary backend.** LLVM-based, outputs C, different failure modes from Ghidra → diversity is useful. |
| **Rizin / Radare2 + rz-ghidra** | **Tertiary check.** Lightweight CLI, but the decompiler is a Ghidra wrapper → limited diversity. Useful for its disassembler and scripting. |
| **angr** | **Research tier.** Python framework, decompiler is experimental, but its symbolic execution is a *completely different oracle* — could be a powerful cross-check. |
| **rev.ng** | **Research tier.** LLVM+QEMU-based, produces syntactically valid C. Still maturing. |
| **Ghidrust** | **Watch.** Rust, headless-first, claims faster than Ghidra headless. Early stage. |
| **Snowman** | **Toy tier.** ARM-capable CLI, but weak. |
| **Boomerang** | **Legacy tier.** Old, readable output on some targets, but unmaintained. |

### 3.2 Commercial tools — why we're not building on them

| Tool | Why not |
|---|---|
| **IDA Pro + Hex-Rays** | Best-in-class decompiler, but **paid** and the decompiler is a separate add-on. Not open, not scriptable in a free/headless workflow, not a realistic target for REBA. |
| **Binary Ninja** | Excellent headless API, but **paid for headless** (Personal/Commercial tier) and built against glibc → requires `proot-distro` Ubuntu on Termux, 8 GB RAM minimum, and a license. Not viable for a portable, open pipeline. |

**These aren't bad tools.** They're just wrong for REBA's constraints: open, portable, headless, phone-runnable, scriptable end-to-end. Ghidra + RetDec + Capstone are the stack.

### 3.3 The thing we're *not* doing

We're not "combining all decompilers into one best C." That was a wrong idea for a while. The decompilers produce *competing complete rewrites*, not mergeable pieces. The right use of multiple decompilers is **as diverse hints to an AI**, with **disassembly as the ground truth** and the **Capstone diff as the oracle.** The AI isn't merging text — it's reconstructing source using every hint available and validating against the actual instructions.

---

## Part 4 — The AI Question

The conversation got heated here, and the honest summary is worth writing down.

### 4.1 What the AI can do (proven)

The reconstruction document (Claude reconstructing `real.cpp` from `real` binary via Hex-Rays-style decompilation + full objdump + mangled symbols + bindiff loop) reached **100% byte-identity** in 5 iterations from 53% starting similarity. That's a real result on a `-O0` unstripped binary.

The methodology it used is the REBA methodology:
- Mangled symbols → function signatures and template parameters
- `char[N]` in mangled names → exact string literal lengths
- `sub rsp, N` + `[rbp-offset]` accesses → source declaration order
- `movzx/xor` vs `cmp/je` → `!x` vs `x` polarity
- `jbe` vs `ja` → branch polarity
- Operand order in `cmp` → `a < b` vs `b > a`
- Redundant checks in the binary → redundant checks in the source (don't "clean them up"!)
- **Every mismatch traced to a real source difference** — nothing was "just GCC being weird"

### 4.2 What the AI can do (research says ~96% / ~80%)

2026 benchmarks (CHISEL, ASAP, CodeInverter, GLM-4.7):

- **Re-compilability:** ~96% on stripped, optimized binaries. The output *compiles*.
- **Re-executability (behavioral):** ~80% on good oracle loops. The output *runs correctly*.
- **False-accept rate:** ~9.4% even on the best oracle loops. The AI *thinks* it's right when it's not.

That last number is the real limit. ~10% silent wrongness is catastrophic for security work — which is *exactly* why the per-function confidence score in REBA matters. It converts "silent wrongness" into "honest low confidence," which is a usable signal.

### 4.3 The disagreement (kept for the record)

- The optimistic position: **AI + tools + oracle can eventually reach ~99% on most binaries.**
- The skeptical position: **byte-identity caps at `-O0`; behavioral equivalence caps at ~80% on `-O2` with current oracles; information-theoretic limits (stripped/LTO/obfuscated) are real.**

**Where they converged:** the *direction* is right, the *methodology* is right, and the *oracle is the ceiling*. Better oracle → higher ceiling. The per-instruction Capstone diff is a better oracle than whole-binary SHA-256, and it's the piece that makes the optimistic case credible.

### 4.4 The real target

**1:1 behavior on typical binaries, with per-function confidence, using a Capstone-diff oracle.** Not "byte-identical." Not "readable source at all costs." A working reconstruction that an analyst can trust because it tells them when not to.

---

## Part 5 — Use Cases

### 5.1 Malware triage (the market that pays)

Security analysts get thousands of samples. Today: reverse-engineer each by hand, or sandbox and guess. With REBA: feed the sample in, get per-function decompiled C with confidence scores, focus human attention on the low-confidence functions (the interesting ones). **10× analyst throughput.** This is the use case that funds the project.

### 5.2 Game decompilation (the demo that makes people care)

The success criterion is "it plays," not "byte-identical." That's a much easier bar. Existing precedent: SM64 decomp, Ship of Harkinian (Zelda OoT), N64 recompilation projects. These took **years of fan-community effort**. REBA compresses the timeline.

- **Old Windows x86 games → ARM (Raspberry Pi):** Win32 + DirectX shim layer needed (SDL2/OpenGL ES). DXVK/Wine already solve this at the binary level; REBA does it at the source level for permanent ports.
- **J2ME (Nokia S40 games):** this is the *easy* win. `jadx` decompiles `.jar` → near-original Java in seconds. Shim the MIDP API (10-20 classes typically) → GraalVM native-image → x86-64 ELF. Thousands of Gameloft/EA Mobile games become portable.
- **S60/Symbian native ARM binaries:** the *hard* case, where the asm→C pipeline actually applies.

### 5.3 Porting & maintenance

Old binaries with no source → recovered source → maintainable, ported, hardened. This is a legitimate industry need (COBOL-era software, embedded systems, abandoned games).

---

## Part 6 — Architecture Summary

```
┌─────────────────────────────────────────────────────────┐
│  REBA pipeline                                          │
│                                                         │
│  input binary                                           │
│      │                                                  │
│      ▼                                                  │
│  ┌──────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │ toolchain│───▶│  Ghidra +   │───▶│  AI source  │    │
│  │fingerprint│    │  RetDec +   │    │reconstruction│   │
│  └──────────┘    │  disasm     │    │  (per func) │    │
│                  └─────────────┘    └──────┬──────┘    │
│                                            │           │
│                                            ▼           │
│                  ┌─────────────┐    ┌─────────────┐    │
│                  │  Capstone   │◀───│  compile    │    │
│                  │  per-inst   │    │  candidate  │    │
│                  │  diff       │    │  (N flags)  │    │
│                  └──────┬──────┘    └─────────────┘    │
│                         │                              │
│                         ▼                              │
│                  ┌─────────────┐                       │
│                  │ confidence  │                       │
│                  │  score      │                       │
│                  └──────┬──────┘                       │
│                         │                              │
│              ┌──────────┴──────────┐                   │
│              ▼                     ▼                   │
│      ┌─────────────┐        ┌─────────────┐           │
│      │  readable   │        │  asm fall-  │           │
│      │  C source   │        │  back (last │           │
│      │  (high conf)│        │  resort)    │           │
│      └─────────────┘        └─────────────┘           │
│                         │                              │
│                         ▼                              │
│              ┌─────────────────────┐                   │
│              │  final output:      │                   │
│              │  per-function C +   │                   │
│              │  confidence scores  │                   │
│              └─────────────────────┘                   │
└─────────────────────────────────────────────────────────┘
```

---

## Part 7 — The Honest Limits

What REBA will not do, and why these are information limits, not AI limits:

| Limit | Why |
|---|---|
| **Byte-identity on `-O2` stripped** | The compiler collapsed many source forms to the same bytes. "The one true source" may not exist. Behavioral equivalence does. |
| **Packed / VM-protected binaries** | The source was *destroyed* at pack time. REBA needs an unpacking step first (UPX, VMProtect, Themida) — different problem. |
| **LTO binaries** | 400 functions became 12. Function boundaries and symbol names may be gone. Reconstruction works at the *whole-binary* level, not per-function. |
| **Rust / Go binaries** | Different codegen model. The techniques transfer, but the specifics (e.g. Go's runtime, Rust's monomorphization) may need their own tuning. |
| **Anti-analysis / self-modifying code** | The oracle may not be able to trust the disassembly it sees. Requires a separate deobfuscation pipeline. |
| **Silent wrongness** | ~10% false-accept even on the best oracle loops. This is why **per-function confidence scoring is maybe non-negotiable**. |

**None of these make REBA useless.** They define the scope. A tool that works on "most non-adversarial binaries" is enormously valuable. A tool that works on 99% is a fantasy.

---

## Part 8 — Next Steps

1. **Implement the Capstone diff loop.** The `decomp.sh` foundation is proven. The next piece is `capstone-diff.py`: disassemble target, disassemble candidate, normalize addresses, score per function. This is the highest-leverage piece.
2. **Implement toolchain fingerprinting.** `.comment` + `endbr64` + ELF header + canary detection → candidate toolchain list.
3. **Wire the AI loop.** For each function: feed Ghidra output + disasm + toolchain candidates → AI source → compile → Capstone diff → feedback. Convergence threshold per function.
4. **Confidence scoring + asm fallback.** Per-function output with honest confidence. Low-confidence → annotated asm, not wrong C.
5. **Test against known binaries.** Start with:
   - `-O0` unstripped (easy, validates correctness)
   - `-O2` stripped (validates the Capstone loop on real optimization)
   - Real malware sample (validates the security use case)
   - Old game binary (validates the game use case)
6. **Benchmark against ground truth.** Where source is known (open-source binaries), measure precision + recall per function. Publish the numbers. Let the results speak.
7. **Extend to J2ME** (separate, easier pipeline — `jadx` → MIDP shim → GraalVM native).

**Success criterion:** on a stripped `-O2` x86-64 ELF with no source available, produce a reconstruction that compiles, survives differential fuzzing against the original, and has honest per-function confidence scores. **That's the demo that ends the debate.**

---

## Appendix — Glossary of Concepts from the Conversation

- **"Atoms of asm"** — individual instructions considered as `(mnemonic, operands)` tuples. The unit of comparison in the Capstone diff.
- **Address normalization** — replacing absolute addresses (jump targets, PC-relative offsets, GOT/PLT entries) with symbolic or relative references before diffing, so that two different compilations with different layouts can be meaningfully compared.
- **Per-instruction gradient** — the signal from a Capstone diff that tells the AI *which* instructions are wrong in *which* function, rather than a pass/fail whole-binary hash.
- **Oracle** — the verification signal. The higher the quality of the oracle, the higher the ceiling of the AI + loop. **The oracle is the ceiling.**
- **Confidence score** — a per-function measure of how much the Capstone diff matched. Non-negotiable for security work.
- **Silent wrongness** — the AI producing C that compiles and *looks* right but is behaviorally wrong. ~10% false-accept even on good oracles. The reason confidence scores matter.
- **Asm fallback** — the last resort: emit annotated asm when no source reconstruction converges. Admission of defeat on readability, but not on correctness.
- **Functional equivalence** — the actual goal. Not byte-identity. The reconstruction runs the same as the original on the same inputs.
- **`-O0` cakewalk** — the state where the compiler didn't optimize, so source-level structure is preserved and reconstruction is (relatively) easy. The `real.cpp` reconstruction lived here.
- **Readable source vs. 1:1 instructions** — at `-O2`, these trade off. The source that compiles to the *exact* optimized instructions is often ugly (hand-unrolled loops, weird expressions). The source that is *nice* won't compile to the same bytes. At `-O0`, you get both.

---

*"The goal is not byte-identity. The goal is a working reconstruction with honest confidence. Everything else is a party trick."*
