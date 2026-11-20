from src.config import MAX_FUNC_DISASM_BYTES, MAX_FUNC_DECOMP_BYTES, MAX_TOTAL_ANALYSIS_CAP

class FeasibilityReport:
    def __init__(self, passed: bool, reason: str = "", details: dict = None):
        self.passed = passed
        self.reason = reason
        self.details = details or {}

def assess_binary_feasibility(analysis_text: str, decomp_text: str, text_funcs: dict) -> FeasibilityReport:
    total_len = len(analysis_text)
    if total_len > MAX_TOTAL_ANALYSIS_CAP:
        return FeasibilityReport(
            False,
            f"Binary analysis ({total_len:,} bytes) exceeds absolute engine ceiling ({MAX_TOTAL_ANALYSIS_CAP:,} bytes).",
            {"total_bytes": total_len, "limit": MAX_TOTAL_ANALYSIS_CAP}
        )

    oversized_funcs = []
    for addr, fdata in text_funcs.items():
        disasm_sz = len(fdata.get("disasm", ""))
        decomp_sz = len(fdata.get("decomp", ""))

        # Only reject if the ACTUAL decompiled C logic or raw disasm is legitimately monolithic (> 120KB C or > 350KB disasm)
        if decomp_sz > MAX_FUNC_DECOMP_BYTES or disasm_sz > MAX_FUNC_DISASM_BYTES:
            oversized_funcs.append({
                "addr": addr,
                "name": fdata.get("name", f"func_0x{addr}"),
                "disasm_bytes": disasm_sz,
                "decomp_bytes": decomp_sz
            })

    if oversized_funcs:
        worst = max(oversized_funcs, key=lambda x: x["decomp_bytes"])
        reason = (
            f"Function '{worst['name']}' (0x{worst['addr']}) is genuinely monolithic "
            f"({worst['decomp_bytes']:,} bytes decompiled C, {worst['disasm_bytes']:,} bytes disasm). "
            f"Exceeds safe single-function synthesis limit ({MAX_FUNC_DECOMP_BYTES:,} bytes C). "
            f"This function requires graph-based SESE block slicing before REBA can synthesize it without truncation."
        )
        return FeasibilityReport(False, reason, {"oversized_functions": oversized_funcs})

    return FeasibilityReport(True, "Feasibility check passed. Binary fits within safe processing envelopes.")
