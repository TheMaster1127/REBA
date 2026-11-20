from pathlib import Path

# Paths
BASE                = Path(__file__).parent.parent.resolve()
SRC_DIR             = BASE / "src"
KEY_FILE            = BASE / "api_key.txt"
PROMPT_FILE         = BASE / "prompt.txt"
HTRE_CLI            = BASE / "htre_cli.py"
ORACLE              = BASE / "the_oracle.py"
OUT_DIR             = BASE / ".reba_outputs"
HISTORY_BASE        = BASE / ".reba_history"
CHECKPOINTS_BASE    = BASE / ".reba_checkpoints"

# AI & API Configuration
API_URL             = "https://api.deepseek.com/chat/completions"
MODEL               = "deepseek-flash"   # "deepseek-flash" or "deepseek-v4-pro"
COMPILERS           = ("gcc", "g++", "clang", "clang++", "cc", "rustc")

# Pre-Flight Feasibility Thresholds
MAX_FUNC_DISASM_BYTES   = 350_000        # Max single-function assembly (~80k tokens of asm)
MAX_FUNC_DECOMP_BYTES   = 120_000        # Max single-function decompiled C (~3,000 lines of C)
MAX_TOTAL_ANALYSIS_CAP  = 3_000_000      # 3MB hard analysis ceiling

# Chunking & Retry Settings
MAX_ANALYSIS_BYTES  = 500_000            # Triggers chunking above 500KB
MAX_CHUNK_BYTES     = 150_000            # Bytes per helper chunk
MAX_FUNCS_PER_CHUNK = 15                 # Max functions per chunk
CHUNK_MAX_ATTEMPTS  = 5                  # Compiler error retry budget
MAX_HISTORY         = 8
MAX_ITERATIONS      = 10                 # Root verification attempts
MAX_FORMAT_RETRIES  = 3
SANDBOX_TIMEOUT_S   = 3.0
COMPILE_TIMEOUT_S   = 30.0
