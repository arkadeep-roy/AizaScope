from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import socket
import ssl
import sys
from pathlib import Path

from .models import VERSION
from .term_ui import rich_available


def _installed_script_path() -> str:
    found = shutil.which("aizascope")
    if found:
        return found
    candidates = []
    exe = Path(sys.executable)
    if os.name == "nt":
        candidates.append(exe.parent / "aizascope.exe")
        candidates.append(exe.parent / "aizascope-script.py")
    else:
        candidates.append(exe.parent / "aizascope")
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return "not found on PATH"


def dependency_status() -> dict[str, object]:
    return {
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "os_name": os.name,
        "cwd": str(Path.cwd()),
        "aizascope_version": VERSION,
        "rich_installed": importlib.util.find_spec("rich") is not None,
        "rich_rendering_available": rich_available(),
        "pip_available": shutil.which("pip") is not None or shutil.which("pip3") is not None,
        "aizascope_command": _installed_script_path(),
        "openssl": ssl.OPENSSL_VERSION,
    }


def network_status(timeout: float = 3.0) -> dict[str, object]:
    hosts = ["www.googleapis.com", "firestore.googleapis.com", "generativelanguage.googleapis.com", "maps.googleapis.com"]
    results: dict[str, object] = {}
    for host in hosts:
        try:
            socket.create_connection((host, 443), timeout=timeout).close()
            results[host] = "ok"
        except Exception as exc:
            results[host] = f"fail: {type(exc).__name__}: {exc}"
    return results


def print_doctor(check_network: bool = False) -> int:
    status = dependency_status()
    print("AizaScope doctor")
    print("================")
    for key, value in status.items():
        print(f"{key:24} {value}")
    if check_network:
        print("\nNetwork checks")
        print("==============")
        for host, result in network_status().items():
            print(f"{host:32} {result}")
    print("\nInstall commands")
    print("================")
    if os.name == "nt":
        print("py -3 -m venv .venv")
        print(".\\.venv\\Scripts\\activate")
        print("python -m pip install --upgrade pip setuptools wheel")
        print("python -m pip install -e .")
    else:
        print("python3 -m venv .venv")
        print("source .venv/bin/activate")
        print("python -m pip install --upgrade pip setuptools wheel")
        print("python -m pip install -e .")
    missing = []
    if not status["rich_installed"]:
        missing.append("rich")
    return 1 if missing else 0
