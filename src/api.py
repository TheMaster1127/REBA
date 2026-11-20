import sys
import json
import re
import time
import urllib.request
import urllib.error
from src.config import KEY_FILE, API_URL, COMPILERS

def load_key():
    if not KEY_FILE.exists():
        sys.exit(f"error: {KEY_FILE} not found")
    k = KEY_FILE.read_text().strip()
    if not k:
        sys.exit(f"error: {KEY_FILE} is empty")
    return k

def chat_with_payload(api_key: str, payload: dict) -> dict:
    """Executes API call with automatic backoff retries on transient network or server blips."""
    delays = [5, 10, 20, 40, 60]
    for attempt in range(len(delays) + 1):
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=400) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors='replace')
            if e.code in (429, 500, 502, 503, 504) and attempt < len(delays):
                wait = delays[attempt]
                print(f"[!] API HTTP {e.code}, retrying in {wait}s...", flush=True)
                time.sleep(wait)
                continue
            sys.exit(f"HTTP {e.code}: {body}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt < len(delays):
                wait = delays[attempt]
                print(f"[!] Network error ({e}), retrying in {wait}s...", flush=True)
                time.sleep(wait)
                continue
            sys.exit(f"connection error after retries: {e}")

def parse_json_reply(reply: str):
    text = reply.strip()
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        pass
    for block in re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
        try:
            return json.loads(block), None
        except json.JSONDecodeError:
            continue
    try:
        first = text.index("{")
        last  = text.rindex("}")
        return json.loads(text[first:last + 1]), None
    except (ValueError, json.JSONDecodeError) as e:
        return None, str(e)

def validate_schema(data):
    if not isinstance(data, dict):
        return "top level must be a JSON object"
    if "candidates" not in data:
        return "missing top-level 'candidates' key"
    cs = data["candidates"]
    if not isinstance(cs, list) or not (1 <= len(cs) <= 6):
        return "'candidates' must be a list of 1-6 objects"
    for i, c in enumerate(cs):
        if not isinstance(c, dict):
            return f"candidate {i+1} is not an object"
        if "code" not in c or not isinstance(c["code"], str) or not c["code"].strip():
            return f"candidate {i+1} missing or empty 'code'"
        if "compile_commands" not in c or not isinstance(c["compile_commands"], list) or not c["compile_commands"]:
            return f"candidate {i+1} missing 'compile_commands' list"
        for j, cmd in enumerate(c["compile_commands"]):
            if not isinstance(cmd, str) or not cmd.strip():
                return f"candidate {i+1} cmd {j+1} invalid"
            if cmd.strip().split()[0] not in COMPILERS:
                return f"candidate {i+1} cmd {j+1} doesn't start with a supported compiler"
        if "file_patches" in c and c["file_patches"] is not None:
            if not isinstance(c["file_patches"], dict):
                return f"candidate {i+1} 'file_patches' must be an object mapping path->code"
            for fp_k, fp_v in c["file_patches"].items():
                if not isinstance(fp_k, str) or not isinstance(fp_v, str):
                    return f"candidate {i+1} 'file_patches' keys and values must be strings"
    return None
