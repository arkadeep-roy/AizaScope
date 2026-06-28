from __future__ import annotations

import re
from pathlib import Path

AIZA_RE = re.compile(r"^AIza[0-9A-Za-z_-]{35}$")


def is_valid_aiza_key(value: str) -> bool:
    return bool(AIZA_RE.fullmatch(value.strip()))


def load_single_key(value: str) -> tuple[list[str], list[str]]:
    key = value.strip()
    if is_valid_aiza_key(key):
        return [key], []
    return [], [key]


def load_key_file(path: str) -> tuple[list[str], list[str]]:
    keys: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()

    for raw_line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if is_valid_aiza_key(line):
            if line not in seen:
                seen.add(line)
                keys.append(line)
        else:
            invalid.append(line)
    return keys, invalid
