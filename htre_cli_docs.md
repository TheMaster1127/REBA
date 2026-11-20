# htre_cli

**Headless Binary Analysis & Decompilation Engine**

The `htre_cli` utility extracts execution metadata, resolves strings by section mapping, disassembles instructions, and bridges to Kuna for targeted C/C++ AST decompilation.

### Features
1. **Silent by Default:** Perfect for piping. Use `-v` or `--verbose` if you want to see execution logs in `stderr`.
2. **Language Detection:** Detects if the binary is `C` or `C++` dynamically.
3. **Smart Single Function Decompilation:** Using `--func <address_or_name>`, the script avoids decompiling the entire binary and instantly extracts ONLY the requested function.
4. **Pristine Output (`--only-decomp`):** Prints *exactly* the C/C++ code and nothing else. No headers, no footers, no hash data.
5. **Persistent Caching:** Stores decompilation runs globally in `.htre_cache/<sha256>.json`.

---

### Command Line Arguments

#### Basic Output Controls
- `-o`, `--out` : Define the file to save the report to (defaults to `[binary]_htre_report.txt`).
- `--stdout` : Outputs the report directly to standard output.
- `--format {text,json}` : Controls the structure of the data. 
- `--raw` : Strips all structural headers, borders, and metadata strings.
- `--only-decomp` : Skips all formatting and prints *only* the raw C/C++ code.
- `-v`, `--verbose` : Enable execution logs (e.g., `[*] Extracting Strings...`). 

#### Targeted Extraction
- `--func <name or address>` : Extracts disassembly and C/C++ decompilation ONLY for this specific function. E.g., `--func main` or `--func 0x401140`. Automatically turns off heavy scans like String Cross-Referencing.
- `--list-funcs` : Instantly prints a list of all symbols and their addresses found in the binary, then exits.

#### Feature Toggles
- `--no-info`, `--no-sections`, `--no-strings`, `--no-disasm`, `--no-decomp` : Explicitly disable specific extraction steps to speed up targeted queries.

---

### Workflow Examples

**1. Output exactly the C/C++ code of `main` directly to the terminal, and absolutely nothing else:**
```bash
./htre_cli.py /bin/ls --func main --only-decomp --stdout
```

**2. List all function symbols and memory addresses:**
```bash
./htre_cli.py /bin/ls --list-funcs
```

**3. Generate a clean Text Report for the whole binary, but skip Kuna decompilation (Fast):**
```bash
./htre_cli.py /bin/ls --no-decomp
```

**4. Extract everything as JSON for an external Python script, and print progress logs:**
```bash
./htre_cli.py /bin/ls --format json -o output.json --verbose
```

