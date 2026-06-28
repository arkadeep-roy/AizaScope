"""Cross-platform release checks for AizaScope.

Run from the repository root:
    python run_checks.py
"""
from __future__ import annotations

import compileall
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd: list[str]) -> None:
    print("$", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> int:
    print("[+] Python:", sys.version.split()[0])
    if sys.version_info < (3, 10):
        print("[!] Python 3.10+ required", file=sys.stderr)
        return 1

    print("[+] Compiling package and tests")
    ok = compileall.compile_dir(str(ROOT / "aizascope"), quiet=1)
    ok = compileall.compile_dir(str(ROOT / "tests"), quiet=1) and ok
    if not ok:
        return 1

    print("[+] Running unit tests")
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])

    print("[+] Checking CLI entrypoints")
    run([sys.executable, "-m", "aizascope", "--version"])
    run([sys.executable, "-m", "aizascope", "--help"])
    run([sys.executable, "-m", "aizascope", "--doctor"])
    run([sys.executable, "-m", "aizascope", "--show-probe-wordlists"])

    print("[+] Release checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
