import re
import json
import time
from pathlib import Path
from src.config import CHUNK_MAX_ATTEMPTS
from src.api import chat_with_payload, parse_json_reply
from src.sandbox import SafeSandbox
from src.tracker import SessionTracker
from src.memory import extract_safe_compiler_errors

PHANTOM_DATA_RE = re.compile(r'^(?:dat|unk|off|byte|word|dword|qword|stru)_[0-9a-fA-F]+$')
PHANTOM_SUB_RE = re.compile(r'^sub_[0-9a-fA-F]+$')
STD_HEADER_POISON_SYMS = {
    "argp_program_version", "argp_program_bug_address", "argp_program_version_hook",
    "argp_err_exit_status", "argp_parse", "argp_help", "argp_state_help",
    "argp_error", "argp_failure", "argp_usage",
    "program_invocation_name", "program_invocation_short_name",
    "optind", "optarg", "opterr", "optopt", "errno", "stdin", "stdout", "stderr"
}

def strip_c_comments(text: str) -> str:
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    text = re.sub(r'//[^\n]*', '', text)
    return text

def check_chunk_link_hygiene(header: str, existing_headers: str, undef_syms: list, depth: int = 0) -> str | None:
    """
    Catches fatal cross-file problems during chunk compilation BEFORE they poison main():
    1. Undefined phantom data symbols (`dat_ab40`, `unk_...`) or unknown `sub_*` not in existing_headers.
    2. Header re-declaring standard glibc/argp globals or functions (`argp_program_version_hook`, etc.).
    """
    bad_undefs = []
    for sym in undef_syms:
        is_phantom_data = bool(PHANTOM_DATA_RE.match(sym))
        is_unknown_sub = (depth == 0 and bool(PHANTOM_SUB_RE.match(sym)))
        if (is_phantom_data or is_unknown_sub) and not re.search(rf'\b{re.escape(sym)}\b', existing_headers):
            bad_undefs.append(sym)
    if bad_undefs:
        return (
            f"Undefined phantom symbol(s) {bad_undefs} in object file! "
            f"Do NOT emit dangling `extern dat_XXXX;` or `extern sub_XXXX;` unless already declared in `reba_chunks.h`. "
            f"Either define/initialize the constant/table/string inside this chunk from the disassembly, "
            f"or implement the standard libc/POSIX call directly."
        )

    hdr_clean = strip_c_comments(header)
    for sym in STD_HEADER_POISON_SYMS:
        s_esc = re.escape(sym)
        is_var_decl = re.search(rf'(?m)^\s*(?:extern\b)[^(;]*\b{s_esc}\b[^(;]*;', hdr_clean)
        is_fnptr_decl = re.search(rf'(?m)^\s*(?:extern\b)?[^;]*\(\s*\*\s*{s_esc}\s*\)\s*\([^;]*\)\s*;', hdr_clean)
        is_fn_decl = re.search(rf'(?m)^\s*(?:extern\b)?[a-zA-Z0-9_* \t]+\b{s_esc}\s*\([^;]*\)\s*;', hdr_clean)
        if is_var_decl or is_fnptr_decl or is_fn_decl:
            return (
                f"Header `header` illegally re-declares standard system symbol `{sym}`! "
                f"NEVER put standard libc/POSIX/argp declarations in `header`—just `#include <argp.h>` / `<errno.h>` / `<unistd.h>` inside `code`."
            )
    return None

def load_compiler_memory_hints(chk_dir: Path) -> str:
    mem_file = chk_dir / "compiler_memory.json"
    if not mem_file.exists():
        return ""
    try:
        data = json.loads(mem_file.read_text(encoding="utf-8"))
        errs = data.get("common_errors", [])
        if not errs:
            return ""
        hints = "\n".join(f"- {e}" for e in errs[-6:])
        return f"\n=== PAST COMPILER ERRORS TO AVOID FOR THIS BINARY ===\n{hints}\n"
    except Exception:
        return ""

def record_compiler_error(chk_dir: Path, err_text: str):
    mem_file = chk_dir / "compiler_memory.json"
    data = {"common_errors": []}
    if mem_file.exists():
        try:
            data = json.loads(mem_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    lines = [l.strip() for l in err_text.splitlines() if "error:" in l or "undefined reference" in l]
    for line in lines[:4]:
        if line and line not in data["common_errors"]:
            data["common_errors"].append(line)
    data["common_errors"] = data["common_errors"][-20:]
    try:
        mem_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

def count_uncached_chunk_calls(chunk_label: str, chunk_addrs: list, ext: str, chk_dir: Path, depth: int = 0) -> tuple[int, int]:
    """Returns (uncached_calls_needed, cached_chunks_found) for accurate API call forecasting."""
    addrs_signature = json.dumps(chunk_addrs)
    cached_addrs_file = chk_dir / f"{chunk_label}.addrs"
    cached_code_file  = chk_dir / f"{chunk_label}{ext}"
    cached_hdr_file   = chk_dir / f"{chunk_label}.h"
    cached_skip_file  = chk_dir / f"{chunk_label}.skipped"
    cached_split_file = chk_dir / f"{chunk_label}.split"

    addrs_match = cached_addrs_file.exists() and cached_addrs_file.read_text(encoding="utf-8") == addrs_signature

    if addrs_match and cached_split_file.exists() and len(chunk_addrs) > 1 and depth < 4:
        mid = len(chunk_addrs) // 2
        u1, c1 = count_uncached_chunk_calls(f"{chunk_label}a", chunk_addrs[:mid], ext, chk_dir, depth + 1)
        u2, c2 = count_uncached_chunk_calls(f"{chunk_label}b", chunk_addrs[mid:], ext, chk_dir, depth + 1)
        return u1 + u2, c1 + c2

    if addrs_match and (cached_skip_file.exists() or (cached_code_file.exists() and cached_hdr_file.exists())):
        return 0, 1

    return 1, 0

def reconstruct_chunk_with_autosplit(chunk_label: str, chunk_addrs: list, text_funcs: dict,
                                     existing_headers: str, ext: str, is_aux_audit: bool,
                                     api_key: str, sandbox: SafeSandbox, session: SessionTracker,
                                     chk_dir: Path, depth: int = 0) -> tuple[bool, list]:
    compiler = "g++" if ext == ".cpp" else "gcc"
    addrs_signature = json.dumps(chunk_addrs)
    
    cached_addrs_file = chk_dir / f"{chunk_label}.addrs"
    cached_code_file  = chk_dir / f"{chunk_label}{ext}"
    cached_hdr_file   = chk_dir / f"{chunk_label}.h"
    cached_skip_file  = chk_dir / f"{chunk_label}.skipped"
    cached_split_file = chk_dir / f"{chunk_label}.split"
    
    addrs_match = cached_addrs_file.exists() and cached_addrs_file.read_text(encoding="utf-8") == addrs_signature

    if addrs_match and cached_split_file.exists() and len(chunk_addrs) > 1 and depth < 4:
        mid = len(chunk_addrs) // 2
        ok1, res1 = reconstruct_chunk_with_autosplit(
            f"{chunk_label}a", chunk_addrs[:mid], text_funcs, existing_headers,
            ext, is_aux_audit, api_key, sandbox, session, chk_dir, depth + 1
        )
        if not ok1:
            return False, []
        updated_hdr = existing_headers + "\n" + "\n".join(h for _, h, _ in res1)
        ok2, res2 = reconstruct_chunk_with_autosplit(
            f"{chunk_label}b", chunk_addrs[mid:], text_funcs, updated_hdr,
            ext, is_aux_audit, api_key, sandbox, session, chk_dir, depth + 1
        )
        return (ok2, res1 + res2) if ok2 else (False, [])

    if addrs_match and cached_skip_file.exists():
        session.log(f"    [+] RESUMING: {chunk_label} audited as standard CRT previously. Skipping!")
        return True, []
        
    if addrs_match and cached_code_file.exists() and cached_hdr_file.exists():
        code = cached_code_file.read_text(encoding="utf-8")
        header = cached_hdr_file.read_text(encoding="utf-8")
        temp_files = {
            "include/reba_chunks.h": existing_headers + "\n" + header,
            f"src/{chunk_label}{ext}": code
        }
        chk = sandbox.compile_object_check(compiler, temp_files, f"src/{chunk_label}{ext}")
        hygiene_err = check_chunk_link_hygiene(header, existing_headers, chk.get("undef_syms", []), depth) if (chk["ok"] and not is_aux_audit) else None
        if chk["ok"] and not hygiene_err:
            session.log(f"    [+] RESUMING: {chunk_label} verified from checkpoint! (0 API calls, compile {chk['compile_ms']:.0f}ms)")
            return True, [(chunk_label, header, code)]
        else:
            session.log(f"    [!] Cached {chunk_label} failed re-check ({hygiene_err or 'compile error'}). Re-solving...")

    func_payload_parts = []
    expected_names = []
    for addr in chunk_addrs:
        f = text_funcs[addr]
        canon_name = f["name"] if not f["name"].startswith("func_0x") else f"sub_{addr}"
        expected_names.append(f"{canon_name} (0x{addr})")
        func_payload_parts.append(
            f"=== FUNCTION {canon_name} (address 0x{addr}) ===\n"
            f"--- DECOMPILED (KUNA) ---\n{f['decomp']}\n\n"
            f"--- DISASSEMBLY ---\n{f['disasm']}\n"
        )
    
    memory_hints = load_compiler_memory_hints(chk_dir)

    if is_aux_audit:
        chunk_prompt = (
            "You are auditing .text functions that were NOT directly called by main().\n"
            "Analyze the instructions carefully:\n"
            "- If ALL of these functions are strictly standard GCC/ELF runtime startup (_start, __libc_start_main, "
            "__cxa_finalize, tm_clones with zero custom user logic), return: {\"skip\": true, \"header\": \"\", \"code\": \"\"}\n"
            "- If ANY function contains custom user logic, reconstruct ONLY the custom functions using their canonical names "
            f"({', '.join(expected_names)}) and return skip=false.\n"
            "Keep your reasoning concise (under 1000 tokens).\n"
            "Reply ONLY with JSON:\n"
            "{\n  \"skip\": false,\n  \"header\": \"/* declarations */\",\n  \"code\": \"#include <stdio.h>\\n...\"\n}\n\n"
            + memory_hints + "\n"
            + "\n".join(func_payload_parts)
        )
    else:
        chunk_prompt = (
            "You are reconstructing a module of helper functions.\n"
            "CRITICAL LINKING & NAMING RULES:\n"
            f"1. Implement EVERY function listed using its EXACT canonical name: {', '.join(expected_names)}.\n"
            "   (Using `sub_<hex>` ensures all chunks and main() link together without undefined references!)\n"
            "2. Inside function bodies, write CLEAN C with meaningful local variable names (no eax/ecx/v1).\n"
            "3. ONLY call standard libc/POSIX functions OR functions declared in `reba_chunks.h` (or in this chunk).\n"
            "4. NEVER leave dangling `extern dat_XXXX;` / `extern unk_XXXX;` references! Either define/initialize globals in this chunk (and export in `header`) OR use standard C/libc idioms instead of raw `.rodata` addresses.\n"
            "5. NEVER re-declare standard system symbols (`argp_*`, `program_invocation_*`, `optind`, `errno`, etc.) in `header`—just `#include` the standard `<argp.h>`/`<getopt.h>`/`<errno.h>` in `code`.\n"
            "6. Make all functions NON-STATIC and keep reasoning concise (under 1000 tokens).\n\n"
            f"Already-solved headers (`include/reba_chunks.h`):\n```c\n{existing_headers}\n```\n\n"
            + memory_hints + "\n"
            "Reply ONLY with JSON:\n"
            "{\n  \"skip\": false,\n  \"header\": \"long sub_1280(const char *s, int n);\",\n  \"code\": \"#include <stdio.h>\\n#include <stdlib.h>\\n#include \\\"reba_chunks.h\\\"\\n\\nlong sub_1280(...) { ... }\"\n}\n\n"
            + "\n".join(func_payload_parts)
        )

    messages = [{"role": "user", "content": chunk_prompt}]
    
    for attempt in range(1, CHUNK_MAX_ATTEMPTS + 1):
        session.log(f"    [{chunk_label} ({len(chunk_addrs)} funcs)] Asking AI (attempt {attempt}/{CHUNK_MAX_ATTEMPTS})...")
        payload = {"model": session.report["model"], "messages": messages, "stream": False}
        t0 = time.time()
        resp = chat_with_payload(api_key, payload)
        elapsed = time.time() - t0
        
        choice = resp["choices"][0]
        finish_reason = choice.get("finish_reason", "")
        reply = choice["message"].get("content") or ""

        if finish_reason == "length":
            session.log(f"    [!] {chunk_label} hit output limit (finish_reason=length)!")
            session.log_chunk_step(chunk_label, attempt, payload, resp, elapsed)
            if len(chunk_addrs) > 1 and depth < 4:
                mid = len(chunk_addrs) // 2
                session.log(f"    [*] Auto-splitting {chunk_label} into two smaller chunks ({mid} + {len(chunk_addrs)-mid} funcs)...")
                ok1, res1 = reconstruct_chunk_with_autosplit(
                    f"{chunk_label}a", chunk_addrs[:mid], text_funcs, existing_headers,
                    ext, is_aux_audit, api_key, sandbox, session, chk_dir, depth + 1
                )
                if not ok1:
                    return False, []
                updated_hdr = existing_headers
                for _, h, _ in res1:
                    updated_hdr += f"\n{h}\n"
                ok2, res2 = reconstruct_chunk_with_autosplit(
                    f"{chunk_label}b", chunk_addrs[mid:], text_funcs, updated_hdr,
                    ext, is_aux_audit, api_key, sandbox, session, chk_dir, depth + 1
                )
                if not ok2:
                    return False, []
                cached_addrs_file.write_text(addrs_signature, encoding="utf-8")
                cached_split_file.write_text("split", encoding="utf-8")
                return True, res1 + res2
            else:
                messages = [{"role": "user", "content": chunk_prompt + "\n\nCRITICAL: Keep reasoning under 500 tokens and output compact JSON."}]
                continue

        data, err = parse_json_reply(reply)
        if not data or ("skip" not in data and ("code" not in data or "header" not in data)):
            session.log(f"    [!] {chunk_label} JSON error ({err}), retrying cleanly...")
            session.log_chunk_step(chunk_label, attempt, payload, resp, elapsed)
            messages = [{"role": "user", "content": chunk_prompt + f"\n\nInvalid JSON ({err}). Reply ONLY with valid JSON."}]
            continue
            
        if is_aux_audit and data.get("skip") is True:
            session.log(f"    [+] {chunk_label} audited: standard GCC CRT startup only (safely skipped).")
            session.log_chunk_step(chunk_label, attempt, payload, resp, elapsed, skipped=True)
            cached_addrs_file.write_text(addrs_signature, encoding="utf-8")
            cached_skip_file.write_text("skipped", encoding="utf-8")
            return True, []
            
        code = data.get("code", "")
        header = data.get("header", "")
        if not code.strip():
            session.log(f"    [!] {chunk_label} returned empty code, retrying...")
            continue

        temp_files = {
            "include/reba_chunks.h": existing_headers + "\n" + header,
            f"src/{chunk_label}{ext}": code
        }
        chk = sandbox.compile_object_check(compiler, temp_files, f"src/{chunk_label}{ext}")
        hygiene_err = check_chunk_link_hygiene(header, existing_headers, chk.get("undef_syms", []), depth) if (chk["ok"] and not is_aux_audit) else None
        session.log_chunk_step(chunk_label, attempt, payload, resp, elapsed, header, code)
        
        if chk["ok"] and not hygiene_err:
            session.log(f"    [+] {chunk_label} compiled cleanly in {chk['compile_ms']:.0f}ms! (Saved to checkpoint)")
            cached_addrs_file.write_text(addrs_signature, encoding="utf-8")
            cached_code_file.write_text(code, encoding="utf-8")
            cached_hdr_file.write_text(header, encoding="utf-8")
            return True, [(chunk_label, header, code)]
        else:
            err_msg = hygiene_err if hygiene_err else extract_safe_compiler_errors(chk["stderr"])
            session.log(f"    [!] {chunk_label} rejected ({'link/header hygiene' if hygiene_err else 'compile error'}), retrying...")
            record_compiler_error(chk_dir, err_msg)
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": f"Compile/Link check failed:\n{err_msg}\nFix it and reply with JSON only."})

    if len(chunk_addrs) > 1 and depth < 4:
        mid = len(chunk_addrs) // 2
        session.log(f"    [!] {chunk_label} failed {CHUNK_MAX_ATTEMPTS} compile attempts. Auto-splitting ({mid} + {len(chunk_addrs)-mid} funcs)...")
        ok1, res1 = reconstruct_chunk_with_autosplit(
            f"{chunk_label}a", chunk_addrs[:mid], text_funcs, existing_headers,
            ext, is_aux_audit, api_key, sandbox, session, chk_dir, depth + 1
        )
        if not ok1:
            return False, []
        updated_hdr = existing_headers + "\n" + "\n".join(h for _, h, _ in res1)
        ok2, res2 = reconstruct_chunk_with_autosplit(
            f"{chunk_label}b", chunk_addrs[mid:], text_funcs, updated_hdr,
            ext, is_aux_audit, api_key, sandbox, session, chk_dir, depth + 1
        )
        if not ok2:
            return False, []
        cached_addrs_file.write_text(addrs_signature, encoding="utf-8")
        cached_split_file.write_text("split", encoding="utf-8")
        return True, res1 + res2

    session.log(f"[!] {chunk_label} failed after {CHUNK_MAX_ATTEMPTS} attempts.")
    return False, []
