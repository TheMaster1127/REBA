#!/usr/bin/env python3
"""
REBA — Reverse Engineer Basically Everything
Slim CLI entry point (orchestration lives in src/pipeline.py).
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.resolve()))

from src.pipeline import run_pipeline

def main():
    parser = argparse.ArgumentParser(description="REBA: Autonomous Reverse Engineering Engine")
    parser.add_argument("binary", help="Target binary to reconstruct")
    parser.add_argument("--func", help="Isolate reconstruction to a single function", default=None)
    parser.add_argument("--chunked", action="store_true", help="Force multi-pass bottom-up chunking mode")
    parser.add_argument("--clean", action="store_true", help="Wipe cached checkpoints and start fresh")
    parser.add_argument("--skip-feasibility", action="store_true", help="Override feasibility pre-check and force run")
    args = parser.parse_args()
    run_pipeline(args)

if __name__ == "__main__":
    main()
