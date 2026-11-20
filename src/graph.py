import re

def extract_text_disasm(analysis_text: str) -> tuple[list, int, int]:
    m = re.search(r'Disassembly of section \.text:\s*(.*?)(?=\nDisassembly of section |\Z)', analysis_text, re.DOTALL)
    if not m:
        return [], 0, 0
    
    insts = []
    inst_re = re.compile(r'^\s*([0-9a-fA-F]+):\s+(.*)$')
    for line in m.group(1).splitlines():
        mi = inst_re.match(line)
        if mi:
            addr_int = int(mi.group(1), 16)
            insts.append((addr_int, line.rstrip()))
            
    if not insts:
        return [], 0, 0
    return insts, insts[0][0], insts[-1][0] + 1

def extract_kuna_blocks(decomp_with_headers: str) -> dict:
    blocks = {}
    header_re = re.compile(r'^/\*\s*---\s*(\S+)\s+\(0x([0-9a-fA-F]+)\)\s*---\s*\*/$')
    
    curr_addr = None
    curr_name = None
    curr_lines = []
    
    for line in decomp_with_headers.splitlines():
        mh = header_re.match(line.strip())
        if mh:
            if curr_addr is not None:
                blocks[curr_addr] = {"name": curr_name, "code": "\n".join(curr_lines).strip()}
            curr_name = mh.group(1)
            curr_addr = mh.group(2).lower().lstrip('0') or '0'
            curr_lines = []
        else:
            if curr_addr is not None:
                curr_lines.append(line)
                
    if curr_addr is not None:
        blocks[curr_addr] = {"name": curr_name, "code": "\n".join(curr_lines).strip()}
    return blocks

def detect_main_address(kuna_blocks: dict, text_insts: list) -> str | None:
    for addr in sorted(kuna_blocks.keys(), key=lambda x: int(x, 16)):
        info = kuna_blocks[addr]
        if info["name"] == "main":
            return addr
        first_line = info["code"].splitlines()[0] if info["code"] else ""
        if re.search(r'\bmain\s*\(', first_line):
            return addr

    for addr in sorted(kuna_blocks.keys(), key=lambda x: int(x, 16)):
        info = kuna_blocks[addr]
        m = re.search(r'__libc_start_main\s*\(\s*(?:sub_)?([0-9a-fA-F]+)', info["code"])
        if m:
            return m.group(1).lower().lstrip('0') or '0'

    for i, (addr_int, line) in enumerate(text_insts):
        if "hlt" in line.split():
            for back in range(1, 8):
                if i - back >= 0:
                    prev_line = text_insts[i - back][1]
                    if "rdi" in prev_line and "#" in prev_line:
                        m = re.search(r'#\s*([0-9a-fA-F]+)', prev_line)
                        if m:
                            return m.group(1).lower().lstrip('0') or '0'
    return None

def find_reachable_from_root(graph: dict, root_addr: str | None) -> set:
    if not root_addr or root_addr not in graph:
        return set(graph.keys())
    visited = set()
    stack = [root_addr]
    while stack:
        curr = stack.pop()
        if curr not in visited:
            visited.add(curr)
            for callee in graph.get(curr, []):
                if callee not in visited:
                    stack.append(callee)
    return visited

def build_user_functions_and_graph(analysis_text: str, decomp_with_headers: str, all_func_addrs: list) -> tuple[dict, dict, str | None, set]:
    text_insts, text_start, text_end = extract_text_disasm(analysis_text)
    kuna_blocks = extract_kuna_blocks(decomp_with_headers)
    main_addr = detect_main_address(kuna_blocks, text_insts)

    sorted_addrs = sorted(
        {a.lower().lstrip('0') or '0' for a in all_func_addrs if text_start <= int(a, 16) < text_end},
        key=lambda x: int(x, 16)
    )
    if not sorted_addrs and main_addr:
        sorted_addrs = [main_addr]

    func_ranges = {}
    for idx, addr_hex in enumerate(sorted_addrs):
        start_int = int(addr_hex, 16)
        end_int = int(sorted_addrs[idx + 1], 16) if idx + 1 < len(sorted_addrs) else text_end
        func_ranges[addr_hex] = (start_int, end_int)

    raw_disasm = {addr: [] for addr in sorted_addrs}
    for addr_int, line in text_insts:
        for addr_hex, (s, e) in func_ranges.items():
            if s <= addr_int < e:
                raw_disasm[addr_hex].append(line)
                break

    text_funcs = {}
    for addr_hex in sorted_addrs:
        k_info = kuna_blocks.get(addr_hex, {"name": f"func_0x{addr_hex}", "code": ""})
        name = "main" if addr_hex == main_addr else k_info["name"]
        text_funcs[addr_hex] = {
            "addr": addr_hex,
            "name": name,
            "disasm": "\n".join(raw_disasm.get(addr_hex, [])),
            "decomp": k_info["code"]
        }

    call_re = re.compile(r'\b(?:call|jmp)\s+([0-9a-fA-F]+)\b')
    lea_re = re.compile(r'\blea\b.*?#\s*([0-9a-fA-F]+)\b')
    kuna_call_re = re.compile(r'\bsub_([0-9a-fA-F]+)\b')
    graph_sets = {addr: set() for addr in text_funcs}
    
    for addr_hex in sorted_addrs:
        fdata = text_funcs[addr_hex]
        for line in fdata["disasm"].splitlines():
            if 'call' in line or 'jmp' in line:
                mc = call_re.search(line)
                if mc:
                    target = mc.group(1).lower().lstrip('0') or '0'
                    if target in text_funcs and target != addr_hex:
                        graph_sets[addr_hex].add(target)
            if 'lea' in line and '#' in line:
                ml = lea_re.search(line)
                if ml:
                    target = ml.group(1).lower().lstrip('0') or '0'
                    if target in text_funcs and target != addr_hex:
                        graph_sets[addr_hex].add(target)
        for mc in kuna_call_re.finditer(fdata["decomp"]):
            target = mc.group(1).lower().lstrip('0') or '0'
            if target in text_funcs and target != addr_hex:
                graph_sets[addr_hex].add(target)

    # Convert to deterministic sorted lists so chunk order NEVER changes across runs
    graph = {addr: sorted(callees, key=lambda x: int(x, 16)) for addr, callees in graph_sets.items()}
    reachable = find_reachable_from_root(graph, main_addr)
    return text_funcs, graph, main_addr, reachable

def find_strongly_connected_components(graph: dict) -> list:
    index = 0
    indices = {}
    lowlinks = {}
    stack = []
    on_stack = set()
    sccs = []

    def strongconnect(node):
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for neighbor in graph.get(node, []):
            if neighbor not in indices:
                strongconnect(neighbor)
                lowlinks[node] = min(lowlinks[node], lowlinks[neighbor])
            elif neighbor in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[neighbor])

        if lowlinks[node] == indices[node]:
            cluster = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                cluster.append(w)
                if w == node:
                    break
            cluster.sort(key=lambda x: int(x, 16))
            sccs.append(cluster)

    for node in sorted(graph.keys(), key=lambda x: int(x, 16)):
        if node not in indices:
            strongconnect(node)
    return sccs

def topological_sort_batches(graph: dict) -> list:
    clusters = find_strongly_connected_components(graph)
    node_to_cluster = {node: idx for idx, c in enumerate(clusters) for node in c}
    cluster_deps = {idx: set() for idx in range(len(clusters))}
    
    for node, callees in graph.items():
        u = node_to_cluster[node]
        for callee in callees:
            v = node_to_cluster[callee]
            if u != v:
                cluster_deps[u].add(v)
                
    batches = []
    resolved = set()
    remaining = set(range(len(clusters)))
    while remaining:
        current_batch = sorted(
            [c for c in remaining if cluster_deps[c].issubset(resolved)],
            key=lambda c: int(clusters[c][0], 16)
        )
        if not current_batch:
            current_batch = sorted(remaining, key=lambda c: int(clusters[c][0], 16))
        batches.append([clusters[c] for c in current_batch])
        for c in current_batch:
            resolved.add(c)
            remaining.remove(c)
    return batches

def pack_chunks_for_reconstruction(batches: list, text_funcs: dict, main_addr: str | None,
                                   reachable: set, max_chunk_bytes: int, max_funcs_per_chunk: int = 15) -> tuple[list, list, list]:
    ordered_reachable_helpers = []
    ordered_aux = []
    root_addrs = []
    
    for batch in batches:
        for cluster in batch:
            if main_addr and main_addr in cluster:
                root_addrs.extend(cluster)
            elif any(a in reachable for a in cluster):
                ordered_reachable_helpers.extend(cluster)
            else:
                ordered_aux.extend(cluster)

    if not root_addrs and ordered_reachable_helpers:
        root_addrs = [ordered_reachable_helpers.pop()]

    def pack_list(addr_list):
        chunks = []
        curr = []
        curr_sz = 0
        for addr in addr_list:
            fsz = len(text_funcs[addr]["disasm"]) + len(text_funcs[addr]["decomp"])
            if curr and (len(curr) >= max_funcs_per_chunk or (curr_sz + fsz > max_chunk_bytes)):
                chunks.append(curr)
                curr = [addr]
                curr_sz = fsz
            else:
                curr.append(addr)
                curr_sz += fsz
        if curr:
            chunks.append(curr)
        return chunks

    return pack_list(ordered_aux), pack_list(ordered_reachable_helpers), root_addrs
