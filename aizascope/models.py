from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import hashlib
from importlib import metadata

TOOL_NAME = "AizaScope"
AUTHOR = "ARoy"


def get_version() -> str:
    """Return AizaScope version from the local package first.

This avoids stale editable-install metadata when a developer runs
`python -m aizascope` from a freshly cloned or updated repository.
"""
    try:
        from .version import __version__
        return __version__
    except Exception:
        try:
            return metadata.version("aizascope")
        except metadata.PackageNotFoundError:
            return "dev"


VERSION = get_version()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def mask_key(key: str) -> str:
    if len(key) <= 14:
        return key[:4] + "..."
    return f"{key[:8]}...{key[-4:]}"


@dataclass(slots=True)
class HttpResult:
    method: str
    url: str
    status: int
    headers: dict[str, str]
    body_text: str
    elapsed_ms: int
    error: str | None = None

    def json(self) -> dict[str, Any] | list[Any] | None:
        import json

        try:
            return json.loads(self.body_text) if self.body_text else None
        except Exception:
            return None


@dataclass(slots=True)
class Finding:
    key: str
    service: str
    method_name: str
    classification: str
    endpoint: str
    http_status: int | None = None
    project_id: str | None = None
    target: str | None = None
    evidence_level: str = "E0"
    suggested_priority: str = "INFO"
    manual_validation_required: bool = True
    proof_mode: str = "single_low_impact_request"
    details: dict[str, Any] = field(default_factory=dict)
    source: str = "aizascope"
    created_at: str = field(default_factory=utc_now)

    def to_dict(self, store_full_key: bool = False) -> dict[str, Any]:
        data = asdict(self)
        key = data.pop("key")
        data.update(
            {
                "tool": TOOL_NAME,
                "author": AUTHOR,
                "version": VERSION,
                "api_key": key if store_full_key else mask_key(key),
                "api_key_sha256": sha256_text(key),
            }
        )
        return data


@dataclass(slots=True)
class ScanContext:
    key: str
    profile: str
    auth_mode: str
    write_proof: str
    non_interactive: bool
    store_full_key: bool
    timeout: int
    user_agent: str
    output_dir: str
    youtube_expensive_proof: str = "ask"
    youtube_write_negative_control: str = "ask"
    gemini_token_proof: str = "ask"
    gemini_generation_proof: str = "off"
    vision_proof: str = "ask"
    translation_proof: str = "ask"
    natural_language_proof: str = "ask"
    gemini_embed_proof: str = "off"
    safe_browsing_proof: str = "ask"
    youtube_search_referrer_matrix: bool = True
    prompt_policy: str = "once"
    prompt_decisions: dict[str, bool] = field(default_factory=dict)
    project_id: str | None = None
    database_url: str | None = None
    storage_bucket: str | None = None
    id_token: str | None = None
    local_id: str | None = None
    confirmed_firestore_reads: list[str] = field(default_factory=list)
    confirmed_rtdb_reads: list[str] = field(default_factory=list)
    confirmed_storage_lists: list[str] = field(default_factory=list)
    confirmed_firestore_read_modes: dict[str, list[str]] = field(default_factory=dict)
    confirmed_rtdb_read_modes: dict[str, list[str]] = field(default_factory=dict)
    confirmed_storage_list_modes: dict[str, list[str]] = field(default_factory=dict)
    gemini_models: list[str] = field(default_factory=list)
    gemini_model_methods: dict[str, list[str]] = field(default_factory=dict)
