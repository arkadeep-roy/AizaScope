from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import sha256_text, utc_now


class ScanState:
    def __init__(self, output_dir: str) -> None:
        self.root = Path(output_dir)
        self.path = self.root / "scan_state.json"
        self.root.mkdir(parents=True, exist_ok=True)
        self.data: dict[str, Any] = {"tool": "AizaScope", "version": 1, "completed": {}, "failed": {}}
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data.update(loaded)
                    self.data.setdefault("completed", {})
                    self.data.setdefault("failed", {})
            except Exception:
                backup = self.path.with_suffix(".corrupt.json")
                self.path.replace(backup)

    def completed_hashes(self) -> set[str]:
        completed = self.data.get("completed")
        if isinstance(completed, dict):
            return set(completed.keys())
        return set()

    def is_completed(self, key: str) -> bool:
        return sha256_text(key) in self.completed_hashes()

    def mark_completed(self, key: str, finding_count: int) -> None:
        key_hash = sha256_text(key)
        completed = self.data.setdefault("completed", {})
        completed[key_hash] = {"completed_at": utc_now(), "finding_count": finding_count}
        failed = self.data.setdefault("failed", {})
        failed.pop(key_hash, None)
        self.save()

    def mark_failed(self, key: str, error: str) -> None:
        key_hash = sha256_text(key)
        failed = self.data.setdefault("failed", {})
        failed[key_hash] = {"failed_at": utc_now(), "error": error}
        self.save()

    def reset(self) -> None:
        self.data = {"tool": "AizaScope", "version": 1, "completed": {}, "failed": {}, "reset_at": utc_now()}
        self.save()

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
