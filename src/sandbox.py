import os
import sys
import time
import shutil
import subprocess
import tempfile
import resource
import shlex
from pathlib import Path
from src.config import BASE, SANDBOX_TIMEOUT_S, COMPILE_TIMEOUT_S
from src.tracker import SessionTracker

class SafeSandbox:
    def __init__(self, session: SessionTracker, timeout_sec: float = SANDBOX_TIMEOUT_S, compile_timeout_sec: float = COMPILE_TIMEOUT_S):
        self.session = session
        self.timeout = timeout_sec
        self.compile_timeout = compile_timeout_sec
        if not shutil.which("bwrap"):
            self.session.log("[!] FATAL: 'bwrap' (Bubblewrap) is required for safe execution.")
            sys.exit(1)
        self.mode = "pending"
        self.mode = self._detect_working_mode()
        self.session.report["sandbox_mode"] = self.mode
        self.session._flush_report()

    def _set_resource_limits(self, timeout_sec: float):
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (int(timeout_sec) + 2, int(timeout_sec) + 2))
            resource.setrlimit(resource.RLIMIT_FSIZE, (50 * 1024 * 1024, 50 * 1024 * 1024))
        except Exception:
            pass

    def _detect_working_mode(self) -> str:
        echo_bin = Path(shutil.which("echo") or "/bin/echo")
        res = self.execute(echo_bin, ["REBA_SANDBOX_OK"], b"")
        selftest_log = f"BWRAP_HARDENED_TEST: code={res['code']} stdout={res['stdout']!r} stderr={res['stderr']!r}"
        self.session.write_file_now("00_extraction/sandbox_selftest.txt", selftest_log)
        if res["code"] == 0 and res["stdout"] == b"REBA_SANDBOX_OK\n":
            self.session.log("[*] Hardened Sandbox verified: Bubblewrap (/home hidden, --unshare-all, --cap-drop ALL)")
            self.session.event("SANDBOX_INIT", "Hardened Bubblewrap sandbox self-test passed")
            return "bwrap_hardened"
        self.session.log(f"[!] FATAL: Hardened bwrap sandbox failed self-test: {res['stderr'].decode(errors='replace')}")
        sys.exit(1)

    def _build_bwrap_cmd(self, tmp_run_dir: str) -> list:
        cmd = ["bwrap"]
        for sys_dir in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
            if os.path.islink(sys_dir):
                try:
                    cmd.extend(["--symlink", os.readlink(sys_dir), sys_dir])
                except Exception:
                    pass
            elif os.path.exists(sys_dir):
                cmd.extend(["--ro-bind", sys_dir, sys_dir])

        for etc_item in ("/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime", "/etc/hostname"):
            if os.path.exists(etc_item):
                cmd.extend(["--ro-bind", etc_item, etc_item])
                
        cmd.extend([
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--bind", tmp_run_dir, "/tmp/work",
            "--unshare-all",
            "--cap-drop", "ALL",
            "--new-session",
            "--die-with-parent",
            "--chdir", "/tmp/work",
            "--clearenv",
            "--setenv", "PATH", "/usr/bin:/bin:/usr/sbin:/sbin",
            "--setenv", "TMPDIR", "/tmp"
        ])
        return cmd

    def compile_object_check(self, compiler: str, files_dict: dict, target_c_rel: str) -> dict:
        t0 = time.time()
        with tempfile.TemporaryDirectory() as tmp_run:
            tmp_path = Path(tmp_run)
            for rel, content in files_dict.items():
                fp = tmp_path / rel
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(content, encoding="utf-8")
                
            bwrap_cmd = self._build_bwrap_cmd(tmp_run) + [
                compiler, "-c", "-O2", "-fcommon", "-Iinclude", target_c_rel, "-o", "/tmp/work/check.o"
            ]
            try:
                p = subprocess.run(
                    bwrap_cmd, capture_output=True, timeout=self.compile_timeout,
                    preexec_fn=lambda: self._set_resource_limits(self.compile_timeout)
                )
                undef_syms = []
                if p.returncode == 0 and (tmp_path / "check.o").exists():
                    nm_cmd = self._build_bwrap_cmd(tmp_run) + ["nm", "-u", "--format=just-symbols", "/tmp/work/check.o"]
                    p_nm = subprocess.run(nm_cmd, capture_output=True, timeout=10)
                    if p_nm.returncode == 0:
                        undef_syms = [s.strip() for s in p_nm.stdout.decode("utf-8", errors="replace").splitlines() if s.strip()]
                return {
                    "ok": (p.returncode == 0),
                    "stderr": p.stderr.decode("utf-8", errors="replace"),
                    "undef_syms": undef_syms,
                    "compile_ms": round((time.time() - t0) * 1000.0, 2)
                }
            except Exception as e:
                return {"ok": False, "stderr": str(e), "undef_syms": [], "compile_ms": round((time.time() - t0) * 1000.0, 2)}

    def compile_multi_file(self, cmd_str: str, main_src_code: str, main_src_name: str,
                           extra_files: dict, out_name: str, out_dest_path: Path = None) -> dict:
        t0 = time.time()
        with tempfile.TemporaryDirectory() as tmp_run:
            tmp_path = Path(tmp_run)
            extra_c_paths = []
            for rel, content in extra_files.items():
                fp = tmp_path / rel
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(content, encoding="utf-8")
                if rel.endswith((".c", ".cpp", ".cc")):
                    extra_c_paths.append(rel)

            (tmp_path / main_src_name).write_text(main_src_code, encoding="utf-8")
            
            from src.oracle import normalize_compile_cmd
            norm_cmd = normalize_compile_cmd(cmd_str, main_src_name, out_name)
            cmd_tokens = shlex.split(norm_cmd)
            
            if extra_c_paths:
                compiler_bin = cmd_tokens[0]
                rest_tokens = cmd_tokens[1:]
                extra_flags = [
                    "-Iinclude", "-fcommon", "-Wl,--allow-multiple-definition"
                ] if "rustc" not in compiler_bin else ["-Iinclude"]
                cmd_tokens = [compiler_bin] + extra_flags + extra_c_paths + rest_tokens

            bwrap_cmd = self._build_bwrap_cmd(tmp_run) + cmd_tokens
            
            try:
                p = subprocess.run(
                    bwrap_cmd,
                    capture_output=True,
                    timeout=self.compile_timeout,
                    preexec_fn=lambda: self._set_resource_limits(self.compile_timeout)
                )
                ms = round((time.time() - t0) * 1000.0, 2)
                compiled_bin = tmp_path / out_name
                dest_bin = out_dest_path if out_dest_path else (BASE / out_name)
                
                if p.returncode == 0 and compiled_bin.exists():
                    dest_bin.unlink(missing_ok=True)
                    shutil.copy2(compiled_bin, dest_bin)
                    os.chmod(dest_bin, 0o755)
                    return {
                        "ok": True, "code": 0,
                        "stdout": p.stdout.decode("utf-8", errors="replace"),
                        "stderr": p.stderr.decode("utf-8", errors="replace"),
                        "compile_ms": ms, "bin_path": dest_bin
                    }
                else:
                    return {
                        "ok": False, "code": p.returncode,
                        "stdout": p.stdout.decode("utf-8", errors="replace"),
                        "stderr": p.stderr.decode("utf-8", errors="replace") or "Output binary not produced",
                        "compile_ms": ms, "bin_path": None
                    }
            except subprocess.TimeoutExpired:
                return {"ok": False, "code": -1, "stdout": "", "stderr": "[Compilation Timeout]", "compile_ms": round((time.time() - t0) * 1000.0, 2), "bin_path": None}
            except Exception as e:
                return {"ok": False, "code": -1, "stdout": "", "stderr": str(e), "compile_ms": round((time.time() - t0) * 1000.0, 2), "bin_path": None}

    def compile(self, cmd_str: str, src_code: str, src_name: str, out_name: str, out_dest_path: Path = None) -> dict:
        return self.compile_multi_file(cmd_str, src_code, src_name, {}, out_name, out_dest_path)

    def execute(self, binary_path: Path, args: list, stdin_bytes: bytes = b"") -> dict:
        t0 = time.time()
        with tempfile.TemporaryDirectory() as tmp_run:
            local_bin = Path(tmp_run) / "target_bin"
            shutil.copy2(binary_path.resolve(), local_bin)
            os.chmod(local_bin, 0o755)
            
            bwrap_cmd = self._build_bwrap_cmd(tmp_run) + ["./target_bin"] + args
            
            try:
                p = subprocess.run(
                    bwrap_cmd,
                    input=stdin_bytes,
                    capture_output=True,
                    timeout=self.timeout,
                    preexec_fn=lambda: self._set_resource_limits(self.timeout)
                )
                return {
                    "ok": True, "code": p.returncode, "stdout": p.stdout, "stderr": p.stderr,
                    "timeout": False, "duration_ms": round((time.time() - t0) * 1000.0, 2)
                }
            except subprocess.TimeoutExpired:
                return {
                    "ok": False, "code": -1, "stdout": b"", "stderr": b"[Timeout]",
                    "timeout": True, "duration_ms": round((time.time() - t0) * 1000.0, 2)
                }
            except Exception as e:
                return {
                    "ok": False, "code": -1, "stdout": b"", "stderr": str(e).encode(),
                    "timeout": False, "duration_ms": round((time.time() - t0) * 1000.0, 2)
                }
