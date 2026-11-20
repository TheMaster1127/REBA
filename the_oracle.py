#!/usr/bin/env python3
"""
bindiff_report.py — detailed binary comparison report.

Usage:
    python3 bindiff_report.py A B
    python3 bindiff_report.py A B --json report.json
    python3 bindiff_report.py A B --json report.json --json-format compact
    python3 bindiff_report.py A B --byte-ranges 50 --line-addresses

Exit codes:
    0  files identical (same SHA-256)
    1  files differ
    2  error (bad args, missing input, missing objdump)

Requires: objdump (binutils). Everything else is stdlib.
"""

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field


@dataclass
class Insn:
    addr: int
    text: str
    raw: str
    func: str = ""
    func_addr: int = 0


@dataclass
class Function:
    name: str
    addr: int
    insns: list = field(default_factory=list)

    @property
    def size(self):
        return len(self.insns)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def byte_diff_ranges(a: bytes, b: bytes, max_ranges=1000):
    n = min(len(a), len(b))
    ranges = []
    count = 0
    start = None
    for i in range(n):
        if a[i] != b[i]:
            count += 1
            if start is None:
                start = i
        else:
            if start is not None:
                ranges.append((start, i))
                start = None
    if start is not None:
        ranges.append((start, n))
    if len(a) != len(b):
        ranges.append((n, max(len(a), len(b))))
    return count, ranges[:max_ranges], len(b) - len(a)


FUNC_RE = re.compile(r'^([0-9a-fA-F]+)\s+<([^>]+)>:\s*$')
INSN_RE = re.compile(
    r'^\s*([0-9a-fA-F]+):\s+'
    r'(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\s+)?'
    r'(\S+)\s*(.*)$'
)
ADDR_RE = re.compile(r'\b(?:0x)?[0-9a-fA-F]{4,}\b')
COMMENT_RE = re.compile(r'\s*#.*$')


def normalize_operands(ops, strict=False):
    ops = COMMENT_RE.sub('', ops).strip()
    if strict:
        return ops
    ops = ADDR_RE.sub('ADDR', ops)
    return re.sub(r'\s+', ' ', ops)


def _parse_disassembly(out, strict=False):
    functions = []
    current = None
    for line in out.splitlines():
        m = FUNC_RE.match(line.strip())
        if m:
            current = Function(name=m.group(2), addr=int(m.group(1), 16))
            functions.append(current)
            continue
        m = INSN_RE.match(line)
        if m and current is not None:
            addr = int(m.group(1), 16)
            mnem = m.group(2)
            ops = normalize_operands(m.group(3), strict)
            text = f"{mnem} {ops}".strip()
            insn = Insn(
                addr=addr, text=text, raw=line.strip(),
                func=current.name,
                func_addr=current.addr,
            )
            current.insns.append(insn)
    all_insns = [i for f in functions for i in f.insns]
    return functions, all_insns


def _raw_disassemble_executable(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception:
        return ""

    if len(data) < 64 or data[:4] != b'\x7fELF':
        return ""
    if data[4] != 2 or data[5] != 1:
        return ""

    try:
        e_entry     = struct.unpack_from('<Q', data, 24)[0]
        e_phoff     = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum     = struct.unpack_from('<H', data, 56)[0]
    except struct.error:
        return ""

    best = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        try:
            p_type   = struct.unpack_from('<I', data, off)[0]
            p_flags  = struct.unpack_from('<I', data, off + 4)[0]
            p_offset = struct.unpack_from('<Q', data, off + 8)[0]
            p_vaddr  = struct.unpack_from('<Q', data, off + 16)[0]
            p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
        except struct.error:
            continue
        if p_type != 1 or not (p_flags & 1):
            continue
        if p_filesz == 0 or p_offset + p_filesz > len(data):
            continue
        if best is None or p_filesz > best['filesz']:
            best = {
                'offset': p_offset, 'vaddr': p_vaddr, 'filesz': p_filesz,
            }

    if best is None:
        return ""

    header_end = max(64, e_phoff + e_phentsize * e_phnum)
    code_start_file = max(best['offset'], header_end)
    code_end_file = best['offset'] + best['filesz']
    if code_start_file >= code_end_file:
        return ""

    code = data[code_start_file:code_end_file]
    if not code:
        return ""
    code_start_vaddr = best['vaddr'] + (code_start_file - best['offset'])
    code_end_vaddr = best['vaddr'] + best['filesz']

    tmp = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
    try:
        tmp.write(code)
        tmp.close()
        try:
            out = subprocess.check_output(
                ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                 "-Mintel", "--no-show-raw-insn",
                 "--adjust-vma", f"0x{code_start_vaddr:x}", tmp.name],
                text=True, errors="replace", stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            out = subprocess.check_output(
                ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                 "-Mintel", tmp.name],
                text=True, errors="replace", stderr=subprocess.DEVNULL,
            )
    except Exception:
        return ""
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    if e_entry and code_start_vaddr < e_entry < code_end_vaddr:
        out = re.sub(
            r"^[0-9a-fA-F]+\s+<\.data>:\s*$",
            f"{code_start_vaddr:016x} <pre_entry>:",
            out, count=1, flags=re.MULTILINE,
        )
        out = re.sub(
            rf"^(\s*[0-9a-fA-F]*?{e_entry:x}:)",
            f"{e_entry:016x} <_start>:\n\\1",
            out, count=1, flags=re.MULTILINE,
        )

    return out


def disassemble(path, strict=False):
    if shutil.which("objdump") is None:
        return [], [], False, "objdump not found"

    # 1. Normal objdump
    try:
        out = subprocess.check_output(
            ["objdump", "-d", "-Mintel", "--no-show-raw-insn", path],
            text=True, errors="replace", stderr=subprocess.DEVNULL,
        )
        fns, insns = _parse_disassembly(out, strict)
        if insns:
            return fns, insns, True, ""
    except subprocess.CalledProcessError:
        pass

    # 2. Raw fallback for sectionless ELFs
    try:
        raw = _raw_disassemble_executable(path)
        if raw:
            fns, insns = _parse_disassembly(raw, strict)
            if insns:
                return fns, insns, True, ""
    except Exception:
        pass

    # 3. Last resort: objdump -d with raw bytes shown
    try:
        out = subprocess.check_output(
            ["objdump", "-d", "-Mintel", path],
            text=True, errors="replace", stderr=subprocess.DEVNULL,
        )
        fns, insns = _parse_disassembly(out, strict)
        if insns:
            return fns, insns, True, ""
    except Exception as e:
        return [], [], False, str(e)

    return [], [], True, ""


SECTION_RE = re.compile(
    r'^\s*(\d+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+'
    r'([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+'
)


def sections(path):
    try:
        out = subprocess.check_output(
            ["objdump", "-h", path], text=True, errors="replace",
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return {}
    result = {}
    for line in out.splitlines():
        m = SECTION_RE.match(line)
        if m:
            result[m.group(2)] = int(m.group(3), 16)
    return result


def function_similarity(fa, fb):
    b_by_name = {f.name: f for f in fb}
    b_pool = list(fb)
    used = set()
    rows = []
    for f in fa:
        if f.name in b_by_name:
            g = b_by_name[f.name]
            a_texts = [i.text for i in f.insns]
            b_texts = [i.text for i in g.insns]
            ratio = difflib.SequenceMatcher(
                None, a_texts, b_texts, autojunk=False
            ).ratio() if a_texts or b_texts else 1.0
            rows.append((f, g, ratio))
            used.add(id(g))
            continue
        best = None
        best_ratio = -1.0
        a_texts = [i.text for i in f.insns]
        for g in b_pool:
            if id(g) in used:
                continue
            b_texts = [i.text for i in g.insns]
            ratio = difflib.SequenceMatcher(
                None, a_texts, b_texts, autojunk=False
            ).ratio() if a_texts or b_texts else 0.0
            if ratio > best_ratio:
                best_ratio = ratio
                best = g
        if best is not None and best_ratio > 0:
            rows.append((f, best, best_ratio))
            used.add(id(best))
        else:
            rows.append((f, None, 0.0))
    for g in fb:
        if id(g) not in used:
            rows.append((None, g, 0.0))
    return rows


def build_chunks(a_texts, b_texts, max_chunks, context):
    sm = difflib.SequenceMatcher(None, a_texts, b_texts, autojunk=False)
    ops = sm.get_opcodes()
    chunks = []
    for tag, i1, i2, j1, j2 in ops:
        if tag == "equal":
            continue
        chunks.append({
            "kind": tag,
            "a_core_start": i1, "a_core_end": i2,
            "b_core_start": j1, "b_core_end": j2,
            "a_start": max(0, i1 - context),
            "a_end": min(len(a_texts), i2 + context),
            "b_start": max(0, j1 - context),
            "b_end": min(len(b_texts), j2 + context),
        })
        if max_chunks is not None and len(chunks) >= max_chunks:
            break
    return sm.ratio(), chunks


def _chunk_loc(insns, core_start, core_end):
    if not insns:
        return None
    if core_start >= len(insns):
        insn = insns[-1]
    else:
        insn = insns[core_start]
    return [insn.func, insn.addr - insn.func_addr]


def _chunk_lines(insns, start, end, core_start, core_end, marker, with_addrs):
    lines = []
    for k in range(start, end):
        insn = insns[k]
        m = marker if core_start <= k < core_end else " "
        if with_addrs:
            lines.append([m, f"0x{insn.addr:x}", insn.text])
        else:
            lines.append([m, insn.text])
    return lines


def _loc_str(loc):
    if loc is None:
        return "?"
    if len(loc) == 1:
        return loc[0]
    return f"{loc[0]}+0x{loc[1]:x}"


def make_report(path_a, path_b, *, strict=False, max_chunks=None,
                context=0, include_disassembly=False, byte_ranges=0,
                line_addresses=False):
    a_bytes = open(path_a, "rb").read()
    b_bytes = open(path_b, "rb").read()

    ha = sha256(path_a)
    hb = sha256(path_b)
    hash_equal = ha == hb

    diff_count, ranges, len_delta = byte_diff_ranges(a_bytes, b_bytes)
    max_len = max(len(a_bytes), len(b_bytes)) or 1
    byte_ratio = 1.0 - (diff_count + abs(len_delta)) / max_len

    fa, ia, a_ok, a_err = disassemble(path_a, strict=strict)
    fb, ib, b_ok, b_err = disassemble(path_b, strict=strict)

    insn_ratio = None
    raw_chunks = []
    fn_matches = []
    if a_ok and b_ok and (ia or ib):
        a_texts = [i.text for i in ia]
        b_texts = [i.text for i in ib]
        insn_ratio, raw_chunks = build_chunks(
            a_texts, b_texts, max_chunks, context
        )
        fn_matches = function_similarity(fa, fb)

    overall = (0.60 * insn_ratio + 0.40 * byte_ratio
               if insn_ratio is not None else byte_ratio)

    if hash_equal:
        verdict = "identical"
    elif insn_ratio == 1.0 and diff_count == 0:
        verdict = "code_identical_metadata_differs"
    elif insn_ratio == 1.0:
        verdict = "code_identical_data_differs"
    elif overall >= 0.999:
        verdict = "near_identical"
    elif overall >= 0.95:
        verdict = "very_similar"
    elif overall >= 0.70:
        verdict = "similar"
    else:
        verdict = "different"

    sa = sections(path_a)
    sb = sections(path_b)
    section_list = []
    for name in sorted(set(sa) | set(sb)):
        a_sz = sa.get(name)
        b_sz = sb.get(name)
        if a_sz == b_sz:
            continue
        section_list.append({"name": name, "a_size": a_sz, "b_size": b_sz})

    fn_list = []
    for a_fn, b_fn, ratio in fn_matches:
        entry = {}
        if a_fn and b_fn:
            if a_fn.name == b_fn.name:
                entry["name"] = a_fn.name
            else:
                entry["a_name"] = a_fn.name
                entry["b_name"] = b_fn.name
            entry["sim"] = round(ratio, 4)
        elif a_fn:
            entry["name"] = a_fn.name
            entry["only"] = "a"
        else:
            entry["name"] = b_fn.name
            entry["only"] = "b"
        entry["chunks"] = []
        fn_list.append(entry)

    fn_list.sort(key=lambda r: (r.get("sim", 0.0), r.get("name", "")))

    chunk_list = []
    fn_chunks = {}
    for idx, raw in enumerate(raw_chunks, start=1):
        a_loc = _chunk_loc(ia, raw["a_core_start"], raw["a_core_end"])
        b_loc = _chunk_loc(ib, raw["b_core_start"], raw["b_core_end"])
        a_lines = _chunk_lines(
            ia, raw["a_start"], raw["a_end"],
            raw["a_core_start"], raw["a_core_end"], "-", line_addresses,
        )
        b_lines = _chunk_lines(
            ib, raw["b_start"], raw["b_end"],
            raw["b_core_start"], raw["b_core_end"], "+", line_addresses,
        )
        chunk_list.append({
            "id": idx,
            "kind": raw["kind"],
            "a_loc": a_loc,
            "b_loc": b_loc,
            "a": a_lines,
            "b": b_lines,
        })
        for side_insns, side_start, side_end in [
            (ia, raw["a_core_start"], raw["a_core_end"]),
            (ib, raw["b_core_start"], raw["b_core_end"]),
        ]:
            if not side_insns or side_start >= len(side_insns):
                continue
            for k in range(side_start, min(side_end, len(side_insns))):
                fname = side_insns[k].func
                fn_chunks.setdefault(fname, [])
                if idx not in fn_chunks[fname]:
                    fn_chunks[fname].append(idx)

    for entry in fn_list:
        names = ([entry["name"]] if "name" in entry
                 else [entry["a_name"], entry["b_name"]])
        for name in names:
            if name in fn_chunks:
                entry["chunks"] = fn_chunks[name]
                break

    range_list = None
    if byte_ranges > 0:
        range_list = [
            {"start": s, "end": e, "size": e - s}
            for s, e in ranges[:byte_ranges]
        ]

    summary = {
        "a_path": path_a,
        "a_size": len(a_bytes),
        "a_sha256": ha,
        "b_path": path_b,
        "b_size": len(b_bytes),
        "b_sha256": hb,
        "hash_equal": hash_equal,
        "size_delta": len_delta,
        "differing_bytes": diff_count,
        "byte_sim": round(byte_ratio, 6),
        "insn_sim": round(insn_ratio, 6) if insn_ratio is not None else None,
        "overall_sim": round(overall, 6),
        "verdict": verdict,
        "a_insns": len(ia),
        "b_insns": len(ib),
        "a_funcs": len(fa),
        "b_funcs": len(fb),
        "chunk_count": len(chunk_list),
    }

    report = {
        "schema": 2,
        "summary": summary,
        "sections": section_list,
        "functions": fn_list,
        "chunks": chunk_list,
    }
    if range_list is not None:
        report["byte_ranges"] = range_list
    if include_disassembly:
        report["a_disassembly"] = [
            {"addr": f"0x{i.addr:x}", "function": i.func, "text": i.text}
            for i in ia
        ]
        report["b_disassembly"] = [
            {"addr": f"0x{i.addr:x}", "function": i.func, "text": i.text}
            for i in ib
        ]
    return report


def write_json(rep, path, compact=False):
    if compact:
        with open(path, "w") as f:
            json.dump(rep, f, separators=(",", ":"))
        return

    def onel(obj):
        return json.dumps(obj, separators=(",", ":"))

    with open(path, "w") as f:
        w = f.write
        w("{\n")
        w(f'  "schema": {rep["schema"]},\n')

        w('  "summary": {\n')
        items = list(rep["summary"].items())
        for i, (k, v) in enumerate(items):
            sep = "," if i < len(items) - 1 else ""
            w(f'    "{k}": {json.dumps(v)}{sep}\n')
        w("  },\n")

        w('  "sections": [\n')
        secs = rep["sections"]
        for i, sec in enumerate(secs):
            sep = "," if i < len(secs) - 1 else ""
            w(f'    {onel(sec)}{sep}\n')
        w("  ],\n")

        w('  "functions": [\n')
        fns = rep["functions"]
        for i, fn in enumerate(fns):
            sep = "," if i < len(fns) - 1 else ""
            w(f'    {onel(fn)}{sep}\n')
        w("  ],\n")

        w('  "chunks": [\n')
        chs = rep["chunks"]
        for i, ch in enumerate(chs):
            sep = "," if i < len(chs) - 1 else ""
            w("    {\n")
            w(f'      "id": {ch["id"]},\n')
            w(f'      "kind": {json.dumps(ch["kind"])},\n')
            w(f'      "a_loc": {onel(ch["a_loc"])},\n')
            w(f'      "b_loc": {onel(ch["b_loc"])},\n')
            w(f'      "a": {onel(ch["a"])},\n')
            w(f'      "b": {onel(ch["b"])}\n')
            w(f'    }}{sep}\n')
        w("  ]")

        if "byte_ranges" in rep:
            w(",\n")
            w('  "byte_ranges": [\n')
            for i, br in enumerate(rep["byte_ranges"]):
                sep = "," if i < len(rep["byte_ranges"]) - 1 else ""
                w(f'    {onel(br)}{sep}\n')
            w("  ]")
        if "a_disassembly" in rep:
            w(",\n")
            w('  "a_disassembly": [\n')
            for i, line in enumerate(rep["a_disassembly"]):
                sep = "," if i < len(rep["a_disassembly"]) - 1 else ""
                w(f'    {onel(line)}{sep}\n')
            w("  ]")
        if "b_disassembly" in rep:
            w(",\n")
            w('  "b_disassembly": [\n')
            for i, line in enumerate(rep["b_disassembly"]):
                sep = "," if i < len(rep["b_disassembly"]) - 1 else ""
                w(f'    {onel(line)}{sep}\n')
            w("  ]")

        w("\n}\n")


def _pct(x):
    return "N/A" if x is None else f"{x*100:.4f}%"


def print_report(rep):
    s = rep["summary"]
    print("=" * 78)
    print("BINARY DIFF REPORT")
    print("=" * 78)
    print(f"A: {s['a_path']}  ({s['a_size']} bytes)")
    print(f"B: {s['b_path']}  ({s['b_size']} bytes)")
    print()
    print(f"SHA-256 A : {s['a_sha256']}")
    print(f"SHA-256 B : {s['b_sha256']}")
    print(f"Hash equal: {s['hash_equal']}")
    print()
    print(f"Byte similarity       : {_pct(s['byte_sim'])}")
    print(f"  differing bytes     : {s['differing_bytes']}")
    print(f"  size delta          : {s['size_delta']:+d}")
    print(f"Instruction similarity: {_pct(s['insn_sim'])}")
    print(f"  A instructions      : {s['a_insns']}")
    print(f"  B instructions      : {s['b_insns']}")
    print(f"OVERALL               : {_pct(s['overall_sim'])}")
    print(f"VERDICT               : {s['verdict']}")
    print()

    if rep["sections"]:
        print("-" * 78)
        print("SECTION DIFFERENCES")
        print("-" * 78)
        for sec in rep["sections"]:
            a_str = "absent" if sec["a_size"] is None else f"0x{sec['a_size']:x}"
            b_str = "absent" if sec["b_size"] is None else f"0x{sec['b_size']:x}"
            print(f"  {sec['name']:<22} {a_str:>12} -> {b_str}")
        print()

    if rep["functions"]:
        print("-" * 78)
        print("FUNCTIONS (sorted by similarity, ascending)")
        print("-" * 78)
        for fn in rep["functions"]:
            if "only" in fn:
                name = f"{fn['name']} (only {fn['only'].upper()})"
                sim_str = "N/A"
            elif "a_name" in fn:
                name = f"{fn['a_name']} -> {fn['b_name']}"
                sim_str = _pct(fn["sim"])
            else:
                name = fn["name"]
                sim_str = _pct(fn["sim"])
            chunks_str = ",".join(str(c) for c in fn["chunks"]) or "-"
            print(f"  {sim_str:>10}  {name:<40} {chunks_str}")
        print()

    if rep["chunks"]:
        print("-" * 78)
        print("CHUNKS")
        print("-" * 78)
        for ch in rep["chunks"]:
            a_loc = _loc_str(ch["a_loc"])
            b_loc = _loc_str(ch["b_loc"])
            header = a_loc if a_loc == b_loc else f"A:{a_loc}  B:{b_loc}"
            print(f"\n[chunk {ch['id']}] {ch['kind']}  {header}")
            for line in ch["a"]:
                print(f"    {line[0]} A  {line[-1]}")
            for line in ch["b"]:
                print(f"    {line[0]} B  {line[-1]}")
        print()


def main():
    ap = argparse.ArgumentParser(
        description="Detailed binary diff report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  files identical\n"
            "  1  files differ\n"
            "  2  error\n"
        ),
    )
    ap.add_argument("a", help="first binary")
    ap.add_argument("b", help="second binary")
    ap.add_argument("--json", metavar="PATH", default=None,
                    help="write JSON report to PATH")
    ap.add_argument("--json-format", choices=("pretty", "compact"),
                    default="pretty",
                    help="JSON formatting: 'pretty' (default) or 'compact'")
    ap.add_argument("--text", metavar="PATH", default=None,
                    help="write text report to PATH")
    ap.add_argument("--strict", action="store_true",
                    help="don't normalize addresses in operands")
    ap.add_argument("--max-chunks", type=int, default=None, metavar="N",
                    help="maximum number of diff chunks (default: unlimited)")
    ap.add_argument("--context", type=int, default=0, metavar="N",
                    help="context lines around each chunk (default: 0)")
    ap.add_argument("--byte-ranges", type=int, default=0, metavar="N",
                    help="include up to N differing byte ranges in JSON")
    ap.add_argument("--line-addresses", action="store_true",
                    help="include per-line addresses in chunk arrays")
    ap.add_argument("--include-disassembly", action="store_true",
                    help="include full A and B disassembly in JSON")
    args = ap.parse_args()

    if args.max_chunks is not None and args.max_chunks < 0:
        ap.error("--max-chunks must be >= 0")
    if args.context < 0:
        ap.error("--context must be >= 0")
    if args.byte_ranges < 0:
        ap.error("--byte-ranges must be >= 0")

    try:
        rep = make_report(
            args.a, args.b,
            strict=args.strict,
            max_chunks=args.max_chunks,
            context=args.context,
            include_disassembly=args.include_disassembly,
            byte_ranges=args.byte_ranges,
            line_addresses=args.line_addresses,
        )
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print_report(rep)

    if args.text:
        import io
        buf = io.StringIO()
        orig = sys.stdout
        sys.stdout = buf
        try:
            print_report(rep)
        finally:
            sys.stdout = orig
        with open(args.text, "w") as f:
            f.write(buf.getvalue())
        print(f"Text report: {args.text}")

    if args.json:
        write_json(rep, args.json, compact=(args.json_format == "compact"))
        print(f"JSON report: {args.json} ({args.json_format})")

    return 0 if rep["summary"]["hash_equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
