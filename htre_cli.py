#!/usr/bin/env python3
import os
import sys
import json
import argparse
import hashlib
import subprocess
import re
import tempfile
import shutil

CACHE_DIR = ".htre_cache"

# ==========================================
# UTILITY FUNCTIONS
# ==========================================
def log(msg, verbose=False):
    if verbose:
        print(msg, file=sys.stderr)

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors='ignore')
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return "", str(e), 1

def get_file_hash(path):
    if not os.path.exists(path): return ""
    hasher = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return ""

def detect_language(binary_path):
    out_file, _, _ = run_cmd(f'file "{binary_path}"')
    out_d, _, _ = run_cmd(f'readelf -d "{binary_path}"')
    if "libstdc++" in out_d or "C++" in out_file:
        return "C++"
    return "C"

def load_decomp_cache(file_hash):
    if not file_hash: return {}
    os.makedirs(CACHE_DIR, exist_ok=True)
    p = os.path.join(CACHE_DIR, f"{file_hash}.json")
    if os.path.exists(p):
        try:
            with open(p, 'r') as f: return json.load(f)
        except Exception: pass
    return {}

def save_decomp_cache(file_hash, data_dict):
    if not file_hash: return
    os.makedirs(CACHE_DIR, exist_ok=True)
    p = os.path.join(CACHE_DIR, f"{file_hash}.json")
    current = load_decomp_cache(file_hash)
    current.update(data_dict)
    try:
        with open(p, 'w') as f: json.dump(current, f, indent=4)
    except Exception: pass

def get_objdump_cmd(binary_path):
    out, _, _ = run_cmd(f'readelf -h "{binary_path}"')
    if 'AArch64' in out and shutil.which('aarch64-linux-gnu-objdump'):
        return 'aarch64-linux-gnu-objdump'
    elif 'ARM' in out and shutil.which('arm-linux-gnueabihf-objdump'):
        return 'arm-linux-gnueabihf-objdump'
    return 'objdump'

def detect_best_decompiler(requested_backend=None):
    if requested_backend and requested_backend != "auto":
        return requested_backend

    if shutil.which("kuna"):
        return "kuna"
    if shutil.which("ceasta-cli"):
        return "ceasta"
    if find_ghidra_headless():
        return "ghidra"
    return "none"

def find_ghidra_headless(custom_path=None):
    if custom_path and os.path.exists(custom_path):
        return custom_path
        
    which_path = shutil.which("analyzeHeadless")
    if which_path: return which_path

    candidates = [
        os.environ.get("GHIDRA_HOME", "") + "/support/analyzeHeadless",
        "/usr/lib/ghidra/support/analyzeHeadless",
        "/opt/ghidra/support/analyzeHeadless",
        os.path.expanduser("~") + "/.local/share/ghidra/support/analyzeHeadless"
    ]
    home = os.path.expanduser("~")
    for root in [home, os.path.join(home, "Downloads"), "/opt"]:
        if os.path.exists(root):
            for d in os.listdir(root):
                if "ghidra" in d.lower():
                    candidates.append(os.path.join(root, d, "support/analyzeHeadless"))

    for c in candidates:
        if os.path.exists(c): return c
    return None

# ==========================================
# ANALYSIS MODULES
# ==========================================
def analyze_info(binary_path, language, decompiler_backend="Unknown"):
    out_ls, _, _ = run_cmd(f'ls -lh "{binary_path}"')
    out_stat, _, _ = run_cmd(f'stat "{binary_path}"')
    out_h, _, _ = run_cmd(f'readelf -h "{binary_path}"')
    out_file, _, _ = run_cmd(f'file "{binary_path}"')
    out_ldd, _, _ = run_cmd(f'ldd "{binary_path}"')
    
    arch = 'x86 / x86-64'
    if 'AArch64' in out_h: arch = 'AArch64'
    elif 'ARM' in out_h: arch = 'ARM'
    
    link_status = "Unknown"
    if "statically linked" in out_file: link_status = "Statically Linked"
    elif "dynamically linked" in out_file: link_status = "Dynamically Linked"

    return {
        "Architecture": arch,
        "Language": language,
        "Linking": link_status,
        "Decompiler_Engine": decompiler_backend.upper(),
        "File_Info": out_file.strip(),
        "Permissions": out_ls.strip(),
        "Stat": out_stat.strip(),
        "LDD": out_ldd.strip() if out_ldd.strip() else "Not dynamically linked or cross-architecture.",
        "ELF_Header": out_h.strip()
    }

def analyze_sections(binary_path):
    out_sec, _, _ = run_cmd(f'readelf -S "{binary_path}"')
    return out_sec.strip()

def parse_section_headers(binary_path):
    out, _, _ = run_cmd(f'readelf -S -W "{binary_path}"')
    sections = []
    pattern = re.compile(r'\[\s*\d+\]\s+([\.a-zA-Z0-9_-]+)\s+[A-Z_]+\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)')
    for line in out.splitlines():
        match = pattern.search(line)
        if match:
            name = match.group(1)
            file_offset = int(match.group(2), 16)
            size = int(match.group(3), 16)
            sections.append((name, file_offset, file_offset + size))
    return sections

def analyze_strings_with_sections(binary_path):
    sections = parse_section_headers(binary_path)
    out_str, _, _ = run_cmd(f'strings -a -t x "{binary_path}"')
    
    results = []
    for line in out_str.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2:
            offset_hex = parts[0]
            text = parts[1]
            try:
                offset_int = int(offset_hex, 16)
                sec_name = "Unknown"
                for s_name, start, end in sections:
                    if start <= offset_int < end:
                        sec_name = s_name
                        break
                results.append({"offset": f"0x{offset_hex}", "section": sec_name, "text": text})
            except:
                pass
    return results

def get_nm_functions(binary_path):
    out, _, _ = run_cmd(f'nm -n -S --defined-only "{binary_path}"')
    funcs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                func_type_index = next((i for i, p in enumerate(parts) if len(p) == 1 and p.upper() == 'T'), -1)
                if func_type_index > 0 and func_type_index + 1 < len(parts):
                    addr_hex = parts[0]
                    size_hex = parts[1] if func_type_index == 2 else "0"
                    
                    addr = addr_hex.lstrip('0') or '0'
                    name = parts[func_type_index + 1]
                    
                    try:
                        abs_addr_int = int(addr_hex, 16)
                        size_int = int(size_hex, 16)
                        stop_addr_int = abs_addr_int + size_int
                    except:
                        stop_addr_int = None
                        
                    funcs[addr] = {
                        "name": name, 
                        "start_addr": hex(abs_addr_int) if 'abs_addr_int' in locals() else None,
                        "stop_addr": hex(stop_addr_int) if stop_addr_int else None
                    }
            except Exception:
                pass

    # Fallback for stripped binaries via ceasta-cli if nm returned nothing
    if not funcs and shutil.which("ceasta-cli"):
        c_out, _, _ = run_cmd(f'ceasta-cli funcs "{binary_path}"')
        for line in c_out.splitlines():
            parts = line.strip().split()
            if parts and re.match(r'^[0-9a-fA-F]+$', parts[0]):
                addr_hex = parts[0]
                clean_addr = addr_hex.lstrip('0') or '0'
                funcs[clean_addr] = {
                    "name": f"func_0x{addr_hex}",
                    "start_addr": f"0x{addr_hex}",
                    "stop_addr": None
                }
    return funcs

def resolve_target_function(target_func, nm_funcs):
    clean_target = target_func.lower().replace("0x", "").lstrip('0') or '0'
    if clean_target in nm_funcs:
        return clean_target, nm_funcs[clean_target]
    
    for addr, meta in nm_funcs.items():
        if meta["name"] == target_func:
            return addr, meta
            
    return None, None

def analyze_disasm(binary_path, target_func=None, nm_funcs=None):
    objdump_cmd = get_objdump_cmd(binary_path)
    s_out, _, _ = run_cmd(f'strings -a -t x "{binary_path}"')
    str_map = {
        int(p.strip().split(maxsplit=1)[0], 16): p.strip().split(maxsplit=1)[1]
        for p in s_out.splitlines() if len(p.strip().split(maxsplit=1)) == 2
    }
    
    range_args = ""
    if target_func and nm_funcs:
        addr, func_meta = resolve_target_function(target_func, nm_funcs)
        if func_meta and func_meta["start_addr"] and func_meta["stop_addr"]:
            range_args = f"--start-address={func_meta['start_addr']} --stop-address={func_meta['stop_addr']}"
        else:
            return f"// Target function '{target_func}' not found in symbols. Disassembly aborted."
    
    cmd = f'{objdump_cmd} -D -M intel {range_args} -w "{binary_path}"'
    out, err, _ = run_cmd(cmd)
    
    if "can't disassemble" in err.lower() or not out.strip():
        cmd = f'{objdump_cmd} -D {range_args} -w "{binary_path}"'
        out, _, _ = run_cmd(cmd)
    
    resolved_lines = []
    rip_rel = re.compile(r'#\s*([0-9a-fA-F]+)\s*<')
    for line in out.splitlines():
        m = rip_rel.search(line)
        if m:
            try:
                addr = int(m.group(1), 16)
                resolved = str_map.get(addr) or str_map.get(addr - 0x400000)
                if resolved:
                    line += f'  ; "{resolved}"'
            except Exception:
                pass
        resolved_lines.append(line)
        
    return '\n'.join(resolved_lines)

# ==========================================
# DECOMPILER BACKENDS (KUNA / CEASTA / GHIDRA)
# ==========================================
def decompile_kuna(binary_path, target_ident, is_addr=False):
    addr_flag = "--addr" if is_addr else ""
    cmd = f'kuna decompile "{binary_path}" {target_ident} {addr_flag}'
    out, err, code = run_cmd(cmd)
    if code != 0 or not out.strip():
        return f"// Kuna decompilation failed for {target_ident}: {err.strip()}"
    return out.strip()

def decompile_ceasta(binary_path, target_addr):
    has_kuna = "--kuna" if shutil.which("kuna") else ""
    cmd = f'ceasta-cli decompile "{binary_path}" "{target_addr}" {has_kuna}'
    out, err, code = run_cmd(cmd)
    if code != 0 or not out.strip():
        return f"// Ceasta-cli decompilation failed for {target_addr}: {err.strip()}"
    return out.strip()

def single_decompile_ghidra(binary_path, file_hash, ghidra_path, target_addr, verbose):
    script_path = os.path.abspath("DecompileHeadless.java")
    if not os.path.exists(script_path):
        return {"error": "// ERROR: DecompileHeadless.java not found in current directory."}

    with tempfile.TemporaryDirectory() as tmpdir:
        script_dir = os.path.dirname(script_path)
        cmd = f'"{ghidra_path}" "{tmpdir}" temp_proj -import "{binary_path}" -scriptPath "{script_dir}" -postScript DecompileHeadless.java "{target_addr}" -deleteProject'
        
        log(f"[*] Running targeted Ghidra decompilation for {target_addr}...", verbose)
        out, _, _ = run_cmd(cmd)

        if "=== GHIDRA_C_START ===" in out:
            raw_c = out.split("=== GHIDRA_C_START ===")[1].split("=== GHIDRA_C_END ===")[0]
            clean_lines = [
                re.sub(r'^.*?INFO\s+DecompileHeadless\.java>\s*', '', l)
                for l in raw_c.splitlines()
                if '(GhidraScript)' not in l and not l.strip().startswith(('INFO ', 'WARN '))
            ]
            c_code = '\n'.join(clean_lines).strip()
            
            clean_addr = target_addr.replace('0x', '').lstrip('0') or '0'
            save_decomp_cache(file_hash, {clean_addr: c_code})
            return {clean_addr: c_code}
            
        return {"error": f"// Ghidra decompilation error for {target_addr}."}

def batch_decompile_ghidra(binary_path, file_hash, ghidra_path, verbose):
    script_path = os.path.abspath("DecompileBatch.java")
    if not os.path.exists(script_path):
        return {"error": "// ERROR: DecompileBatch.java not found in current directory."}
        
    with tempfile.TemporaryDirectory() as tmpdir:
        script_dir = os.path.dirname(script_path)
        cmd = f'"{ghidra_path}" "{tmpdir}" temp_proj -import "{binary_path}" -scriptPath "{script_dir}" -postScript DecompileBatch.java -deleteProject'
        
        log("[*] Running full Batch Ghidra Decompiler. This may take a minute...", verbose)
        out, _, _ = run_cmd(cmd)

        results = {}
        pattern = re.compile(r'=== FUNC_START:([0-9a-fA-F]+):([0-9a-fA-F]*):([^\s=]+) ===\s*(.*?)\s*=== FUNC_END ===', re.DOTALL)
        for match in pattern.finditer(out):
            abs_addr = match.group(1).lstrip('0') or '0'
            rel_addr = match.group(2).lstrip('0') or '0'
            code_raw = match.group(4).strip()
            
            clean_lines = [
                re.sub(r'^.*?INFO\s+DecompileBatch\.java>\s*', '', l)
                for l in code_raw.splitlines()
                if '(GhidraScript)' not in l and not l.strip().startswith(('INFO ', 'WARN '))
            ]
            c_code = '\n'.join(clean_lines).strip()
            
            results[abs_addr] = c_code
            if rel_addr: results[rel_addr] = c_code
            results[f"{abs_addr}_name"] = match.group(3)

        results['BATCH_COMPLETE'] = "true"
        save_decomp_cache(file_hash, results)
        return results

def stitch_c_code(binary_path, cache, nm_funcs, language, target_func=None, raw_decomp=False):
    combined_text = ""
    if not raw_decomp:
        combined_text = f"// =========================================\n// LANGUAGE: {language}\n// DECOMPILATION: {os.path.basename(binary_path)}\n// =========================================\n\n"
    
    funcs = []
    has_main = False
    code_map = {}
    
    target_addr, target_meta = None, None
    if target_func:
        target_addr, target_meta = resolve_target_function(target_func, nm_funcs)
    
    for addr, code in cache.items():
        if addr in ('BATCH_COMPLETE', 'COMBINED') or addr.endswith('_name'):
            continue
        if code == "true" or 'WARNING: Control flow encountered bad instruction data' in code:
            continue
            
        name = nm_funcs.get(addr, {}).get("name") or cache.get(f"{addr}_name", f"func_0x{addr}")
        
        if target_func:
            if addr != target_addr and name != target_func:
                continue
                
        if name == 'main': has_main = True
        
        if code in code_map:
            if name != "unknown_function":
                code_map[code] = {'addr': addr, 'name': name, 'code': code}
        else:
            code_map[code] = {'addr': addr, 'name': name, 'code': code}
            
    unique_names = set()
    for f in code_map.values():
        if f['name'] in unique_names and not f['name'].startswith('func_0x'):
            continue
        unique_names.add(f['name'])
        funcs.append(f)
        
    def sort_key(f):
        is_entry = f['name'] == 'main' or (not has_main and f['name'] == '_start')
        try: numeric_addr = int(f['addr'], 16)
        except Exception: numeric_addr = 0
        return (1 if is_entry else 0, numeric_addr)
        
    funcs.sort(key=sort_key)
    
    if not funcs:
        if not raw_decomp:
            combined_text += f"// No valid functions found{' for '+target_func if target_func else ''}."
    else:
        for i, f in enumerate(funcs):
            if not raw_decomp:
                combined_text += f"/* --- {f['name']} (0x{f['addr']}) --- */\n"
            combined_text += f"{f['code']}"
            if i < len(funcs) - 1 or not raw_decomp:
                combined_text += "\n\n"
            
    return combined_text

# ==========================================
# FORMATTERS
# ==========================================
def format_text_output(data, raw=False):
    out = []
    div = "=" * 80
    sub_div = "-" * 80
    
    if not raw:
        out.append(div)
        out.append(f"[ HT-RE BINARY ANALYSIS REPORT ]")
        out.append(f"Target Binary : {data.get('binary', 'Unknown')}")
        out.append(f"SHA-256 Hash  : {data.get('hash', 'Unknown')}")
        out.append(div + "\n")
    
    analysis = data.get("analysis", {})
    
    if "info" in analysis:
        if not raw:
            out.append(sub_div)
            out.append("[ FILE METADATA & INFO ]")
            out.append(sub_div)
            
        info = analysis["info"]
        out.append(f"Architecture      : {info.get('Architecture')}")
        out.append(f"Language          : {info.get('Language')}")
        out.append(f"Linking           : {info.get('Linking')}")
        out.append(f"Decompiler Engine : {info.get('Decompiler_Engine')}")
        out.append(f"\n> File Output:\n{info.get('File_Info')}")
        out.append(f"\n> Permissions:\n{info.get('Permissions')}")
        out.append(f"\n> Shared Libraries (LDD):\n{info.get('LDD')}")
        out.append(f"\n> ELF Header:\n{info.get('ELF_Header')}\n")
        
    if "sections" in analysis:
        if not raw:
            out.append(sub_div)
            out.append("[ SECTIONS ]")
            out.append(sub_div)
        out.append(analysis["sections"] + "\n")
        
    if "strings" in analysis:
        if not raw:
            out.append(sub_div)
            out.append("[ EXTRACTED STRINGS (WITH SECTION CONTEXT) ]")
            out.append(sub_div)
        for s in analysis["strings"]:
            out.append(f"[{s['offset']}] ( {s['section']:<12} ) {s['text']}")
        out.append("\n")
            
    if "disassembly" in analysis:
        if not raw:
            out.append(sub_div)
            out.append("[ DISASSEMBLY ]")
            out.append(sub_div)
        out.append(analysis["disassembly"] + "\n")
        
    if "decompiled_source" in analysis:
        if not raw:
            out.append(sub_div)
            out.append("[ DECOMPILED SOURCE ]")
            out.append(sub_div)
        out.append(analysis["decompiled_source"] + "\n")
        
    return "\n".join(out)

# ==========================================
# MAIN ROUTINE
# ==========================================
def main():
    parser = argparse.ArgumentParser(description="HT-RE CLI: Binary Analysis & Decompilation Engine", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("binary", help="Path to the target executable binary")
    
    out_group = parser.add_argument_group('Output Controls')
    out_group.add_argument("-o", "--out", help="Path to save the output report to a file", default=None)
    out_group.add_argument("--stdout", action="store_true", help="Print the report directly to standard output")
    out_group.add_argument("--format", choices=['text', 'json'], default='text', help="Format of the output report")
    out_group.add_argument("--raw", action="store_true", help="Strip all titles, headers, and dividers.")
    out_group.add_argument("--only-decomp", action="store_true", help="Output EXACTLY the decompiled C source code, nothing else.")
    out_group.add_argument("-v", "--verbose", action="store_true", help="Print progress and execution logs to stderr.")
    
    tgt_group = parser.add_argument_group('Targeted Analysis')
    tgt_group.add_argument("--func", help="Extract ONLY this function name or address (e.g., 'main' or '0x401140')")
    tgt_group.add_argument("--list-funcs", action="store_true", help="Dump all symbols and addresses, then exit.")
    
    decomp_group = parser.add_argument_group('Decompiler Backend')
    decomp_group.add_argument("--backend", choices=['auto', 'kuna', 'ceasta', 'ghidra'], default='auto',
                              help="Choose decompiler backend (Default: auto-selects Kuna -> Ceasta -> Ghidra)")
    decomp_group.add_argument("--ghidra-path", help="Explicit path to analyzeHeadless binary", default=None)

    feat_group = parser.add_argument_group('Feature Toggles')
    feat_group.add_argument("--no-info", action="store_true", help="Disable dumping ELF header and metadata")
    feat_group.add_argument("--no-sections", action="store_true", help="Disable dumping ELF sections")
    feat_group.add_argument("--no-strings", action="store_true", help="Disable dumping strings")
    feat_group.add_argument("--no-disasm", action="store_true", help="Disable objdump disassembly")
    feat_group.add_argument("--no-decomp", action="store_true", help="Disable decompilation entirely")

    args = parser.parse_args()
    
    binary_path = os.path.abspath(args.binary)
    if not os.path.exists(binary_path):
        log(f"[-] Error: Binary not found at {binary_path}", True)
        sys.exit(1)

    file_hash = get_file_hash(binary_path)
    result_data = {
        "binary": binary_path,
        "hash": file_hash,
        "analysis": {}
    }
    
    language = detect_language(binary_path)
    nm_funcs = get_nm_functions(binary_path)
    backend = detect_best_decompiler(args.backend)

    if args.list_funcs:
        print(f"=== Functions mapped in {os.path.basename(binary_path)} ===")
        for addr, meta in nm_funcs.items():
            print(f"0x{addr:<14} : {meta['name']}")
        sys.exit(0)

    # 1. INFO
    if not args.no_info and not args.func and not args.only_decomp:
        log("[*] Extracting Metadata...", args.verbose)
        result_data["analysis"]["info"] = analyze_info(binary_path, language, decompiler_backend=backend)

    # 2. SECTIONS
    if not args.no_sections and not args.func and not args.only_decomp:
        log("[*] Extracting Sections...", args.verbose)
        result_data["analysis"]["sections"] = analyze_sections(binary_path)

    # 3. STRINGS
    if not args.no_strings and not args.func and not args.only_decomp:
        log("[*] Extracting Strings...", args.verbose)
        result_data["analysis"]["strings"] = analyze_strings_with_sections(binary_path)

    # 4. DISASSEMBLY
    if not args.no_disasm and not args.only_decomp:
        log(f"[*] Generating Disassembly{' for '+args.func if args.func else ''}...", args.verbose)
        result_data["analysis"]["disassembly"] = analyze_disasm(binary_path, target_func=args.func, nm_funcs=nm_funcs)

    # 5. DECOMPILATION
    if not args.no_decomp:
        cache = load_decomp_cache(file_hash)
        
        if backend == "none":
            log("[-] No supported decompiler backend found (Kuna, ceasta-cli, or Ghidra).", args.verbose)
            result_data["analysis"]["decompiled_source"] = "// ERROR: No decompiler installed on PATH."
        
        elif backend == "kuna":
            log("[*] Using KUNA decompiler engine (Fast Rust)...", args.verbose)
            if args.func:
                addr, meta = resolve_target_function(args.func, nm_funcs)
                is_addr = (addr is not None and meta["name"] == args.func and args.func.startswith("0x")) or (addr is not None and not meta["name"])
                target_ident = f"0x{addr}" if addr else args.func
                clean_addr = (addr or target_ident).replace("0x", "").lstrip("0") or "0"
                
                if clean_addr not in cache:
                    c_code = decompile_kuna(binary_path, target_ident, is_addr=(is_addr or target_ident.startswith("0x")))
                    cache[clean_addr] = c_code
                    save_decomp_cache(file_hash, {clean_addr: c_code})
            else:
                for addr, meta in nm_funcs.items():
                    clean_addr = addr.lstrip("0") or "0"
                    if clean_addr not in cache:
                        target_ident = meta["name"] if meta["name"] and not meta["name"].startswith("func_0x") else f"0x{addr}"
                        is_addr = target_ident.startswith("0x")
                        c_code = decompile_kuna(binary_path, target_ident, is_addr=is_addr)
                        cache[clean_addr] = c_code
                        cache[f"{clean_addr}_name"] = meta["name"]
                cache['BATCH_COMPLETE'] = "true"
                save_decomp_cache(file_hash, cache)
                
            combined_source = stitch_c_code(binary_path, cache, nm_funcs, language, target_func=args.func, raw_decomp=(args.raw or args.only_decomp))
            result_data["analysis"]["decompiled_source"] = combined_source

        elif backend == "ceasta":
            log("[*] Using CEASTA-CLI decompiler engine...", args.verbose)
            if args.func:
                addr, _ = resolve_target_function(args.func, nm_funcs)
                target_hex = hex(int(addr, 16)) if addr else args.func
                clean_addr = target_hex.replace('0x', '').lstrip('0') or '0'
                if clean_addr not in cache:
                    c_code = decompile_ceasta(binary_path, target_hex)
                    cache[clean_addr] = c_code
                    save_decomp_cache(file_hash, {clean_addr: c_code})
            else:
                for addr, meta in nm_funcs.items():
                    clean_addr = addr.lstrip("0") or "0"
                    if clean_addr not in cache:
                        target_hex = f"0x{addr}"
                        c_code = decompile_ceasta(binary_path, target_hex)
                        cache[clean_addr] = c_code
                        cache[f"{clean_addr}_name"] = meta["name"]
                cache['BATCH_COMPLETE'] = "true"
                save_decomp_cache(file_hash, cache)
                
            combined_source = stitch_c_code(binary_path, cache, nm_funcs, language, target_func=args.func, raw_decomp=(args.raw or args.only_decomp))
            result_data["analysis"]["decompiled_source"] = combined_source

        elif backend == "ghidra":
            log("[*] Using GHIDRA headless decompiler engine...", args.verbose)
            ghidra_bin = find_ghidra_headless(args.ghidra_path)
            if not ghidra_bin:
                log("[-] Ghidra 'analyzeHeadless' not found.", args.verbose)
                result_data["analysis"]["decompiled_source"] = "// ERROR: Ghidra headless binary not found."
            else:
                if args.func:
                    addr, meta = resolve_target_function(args.func, nm_funcs)
                    target_hex = hex(int(addr, 16)) if addr else args.func
                    clean_addr = target_hex.replace('0x', '').lstrip('0') or '0'
                    
                    if clean_addr not in cache:
                        new_cache = single_decompile_ghidra(binary_path, file_hash, ghidra_bin, target_hex, args.verbose)
                        if "error" in new_cache:
                            result_data["analysis"]["decompiled_source"] = new_cache["error"]
                        else:
                            cache.update(new_cache)
                else:
                    if 'BATCH_COMPLETE' not in cache:
                        new_cache = batch_decompile_ghidra(binary_path, file_hash, ghidra_bin, args.verbose)
                        if "error" in new_cache:
                            result_data["analysis"]["decompiled_source"] = new_cache["error"]
                        else:
                            cache.update(new_cache)

                combined_source = stitch_c_code(binary_path, cache, nm_funcs, language, target_func=args.func, raw_decomp=(args.raw or args.only_decomp))
                result_data["analysis"]["decompiled_source"] = combined_source

    # ==========================================
    # OUTPUT DELIVERY
    # ==========================================
    if args.only_decomp:
        final_output = result_data["analysis"].get("decompiled_source", "")
    elif args.format == 'text':
        final_output = format_text_output(result_data, raw=args.raw)
    else:
        final_output = json.dumps(result_data, indent=4)
        
    if args.stdout:
        print(final_output.strip())
    else:
        out_file = args.out
        if not out_file:
            ext = ".txt" if args.format == 'text' else ".json"
            base = os.path.basename(binary_path)
            out_file = f"{base}_htre_report{ext}"
        
        with open(out_file, 'w') as f:
            f.write(final_output.strip())
        log(f"\n[+] Analysis complete! Results successfully saved to: {os.path.abspath(out_file)}", args.verbose)

if __name__ == "__main__":
    main()
