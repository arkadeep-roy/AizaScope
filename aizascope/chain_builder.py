from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .models import AUTHOR, TOOL_NAME, VERSION, utc_now
from .reporter import prepare_output_dirs, is_actionable_record


def _class(record: dict[str, Any]) -> str:
    return str(record.get("classification") or "")


def _has(record: dict[str, Any], needle: str) -> bool:
    return needle in _class(record)


def _rank(priority: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "REVIEW": 4, "INFO": 5}.get(priority, 9)


_FIREBASE_READ_HINTS = (
    "FIRESTORE_UNAUTH_LIST_CONFIRMED",
    "FIRESTORE_AUTH_LIST_CONFIRMED",
    "RTDB_UNAUTH_SHALLOW_READ_CONFIRMED",
    "RTDB_AUTH_SHALLOW_READ_CONFIRMED",
    "STORAGE_LIST_CONFIRMED",
    "STORAGE_AUTH_LIST_CONFIRMED",
    "STORAGE_PREFIX_LIST_CONFIRMED",
    "STORAGE_AUTH_PREFIX_LIST_CONFIRMED",
)
_FIREBASE_DISCOVERY_HINTS = ("FIRESTORE_COLLECTION_IDS_EXPOSED",)
_FIREBASE_WRITE_HINTS = ("FIRESTORE_UNAUTH_WRITE_PROOF_CONFIRMED", "FIRESTORE_AUTH_WRITE_PROOF_CONFIRMED", "RTDB_UNAUTH_WRITE_PROOF_CONFIRMED", "RTDB_AUTH_WRITE_PROOF_CONFIRMED", "STORAGE_UNAUTH_WRITE_PROOF_CONFIRMED", "STORAGE_AUTH_WRITE_PROOF_CONFIRMED")
_DRIFT_HINTS = ("GEMINI_COUNT_TOKENS_CONFIRMED", "GEMINI_GENERATE_CONTENT_CONFIRMED", "GEMINI_EMBED_CONTENT_CONFIRMED", "YOUTUBE_DATA_API_ALLOWED_FROM_ARBITRARY_CLIENT", "YOUTUBE_SEARCH_API_EXPENSIVE_ALLOWED_FROM_ARBITRARY_CLIENT", "MAPS_", "PLACES_", "VISION_", "TRANSLATION_", "NATURAL_LANGUAGE_")


def _contains_any(record: dict[str, Any], needles: tuple[str, ...]) -> bool:
    c = _class(record)
    return any(n in c for n in needles)


def build_attack_chains(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build conservative multi-surface chains from confirmed actionable evidence only.

    A chain is not a vulnerability claim by itself. It is a report-planning aid.
    We only use positive actionable records and avoid speculative language such as
    PII harvesting unless the original finding actually proves sensitive data.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record.get("api_key_sha256") or "unknown")].append(record)

    chains: list[dict[str, Any]] = []
    for key_hash, key_records in grouped.items():
        actionable = [r for r in key_records if is_actionable_record(r, min_priority="MEDIUM")]
        if not actionable:
            continue
        masked = str(next((r.get("api_key") for r in key_records if r.get("api_key")), "<masked>"))
        project = next((r.get("project_id") for r in key_records if r.get("project_id")), None)

        firebase_reads = [r for r in actionable if _contains_any(r, _FIREBASE_READ_HINTS)]
        firebase_discovery = [r for r in actionable if _contains_any(r, _FIREBASE_DISCOVERY_HINTS)]
        firebase_writes = [r for r in actionable if _contains_any(r, _FIREBASE_WRITE_HINTS)]
        drift = [r for r in actionable if _contains_any(r, _DRIFT_HINTS)]
        critical = [r for r in actionable if "CRITICAL_REVIEW_REQUIRED" in _class(r)]

        if firebase_reads or firebase_writes:
            surfaces = sorted({str(r.get("service") or "unknown") for r in firebase_reads + firebase_writes})
            severity = "HIGH" if firebase_writes or len(surfaces) >= 2 else "MEDIUM"
            chains.append({
                "tool": TOOL_NAME,
                "version": VERSION,
                "generated_at": utc_now(),
                "key_hash": key_hash,
                "api_key": masked,
                "project_id": project,
                "chain_type": "firebase_backend_authorization_exposure",
                "severity": severity,
                "confidence": "high" if any(str(r.get("evidence_level")) in {"E4", "E5"} for r in firebase_reads + firebase_writes) else "medium",
                "summary": "Confirmed Firebase backend read/list exposure" + (" plus marker write proof." if firebase_writes else "."),
                "services": surfaces,
                "evidence_classifications": sorted({str(r.get("classification")) for r in firebase_reads + firebase_writes}),
                "recommended_report_angle": "Report confirmed Firebase Security Rules / backend authorization exposure. Final severity depends on actual data sensitivity and whether write proof was explicitly enabled.",
            })
        elif firebase_discovery:
            chains.append({
                "tool": TOOL_NAME,
                "version": VERSION,
                "generated_at": utc_now(),
                "key_hash": key_hash,
                "api_key": masked,
                "project_id": project,
                "chain_type": "firebase_collection_discovery",
                "severity": "MEDIUM",
                "confidence": "medium",
                "summary": "Root collection names are exposed. Treat this as discovery/read-surface evidence, not as data exposure by itself.",
                "evidence_classifications": sorted({str(r.get("classification")) for r in firebase_discovery}),
                "recommended_report_angle": "Report only if program accepts metadata exposure or if follow-on read access is also confirmed.",
            })

        if drift:
            services = sorted({str(r.get("service") or "unknown") for r in drift})
            severity = "HIGH" if any(str(r.get("suggested_priority")) == "HIGH" for r in drift) or len(services) >= 3 else "MEDIUM"
            chains.append({
                "tool": TOOL_NAME,
                "version": VERSION,
                "generated_at": utc_now(),
                "key_hash": key_hash,
                "api_key": masked,
                "project_id": project,
                "chain_type": "google_api_service_drift",
                "severity": severity,
                "confidence": "medium",
                "summary": "The same public AIza key is usable across one or more Google API service families. This is quota/billing/service-restriction exposure, not private data exposure unless separately proven.",
                "services": services,
                "evidence_classifications": sorted({str(r.get("classification")) for r in drift}),
                "recommended_report_angle": "Report as API-key service drift / unrestricted billable API access. Include single-request proof commands and avoid claiming private data unless separately confirmed.",
            })

        if critical:
            chains.append({
                "tool": TOOL_NAME,
                "version": VERSION,
                "generated_at": utc_now(),
                "key_hash": key_hash,
                "api_key": masked,
                "project_id": project,
                "chain_type": "unexpected_privileged_endpoint_success",
                "severity": "CRITICAL",
                "confidence": "manual-review-required",
                "summary": "A request that should normally require OAuth/content-owner/server-side authorization returned an unexpected success status. Validate manually before submission.",
                "evidence_classifications": sorted({str(r.get("classification")) for r in critical}),
                "recommended_report_angle": "Validate manually. If confirmed, report as authorization boundary failure or privileged API exposure.",
            })

    chains.sort(key=lambda c: (_rank(str(c.get("severity") or "INFO")), str(c.get("key_hash"))))
    return chains


def write_attack_chain_outputs(records: list[dict[str, Any]], output_dir: str) -> tuple[Path, Path]:
    paths = prepare_output_dirs(output_dir)
    chains = build_attack_chains(records)
    json_path = paths["root"] / "attack_chains.json"
    markdown_path = paths["reports"] / "attack_chains.md"
    json_path.write_text(json.dumps({"tool": TOOL_NAME, "author": AUTHOR, "version": VERSION, "generated_at": utc_now(), "chains": chains}, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [f"# {TOOL_NAME} Attack Chain Analysis", "", f"**Author:** {AUTHOR}", f"**Version:** {VERSION}", f"**Generated:** {utc_now()}", ""]
    if not chains:
        lines.append("No confirmed multi-surface attack chains were identified from the current actionable findings.")
    for chain in chains:
        lines += [f"## {chain['severity']}: {chain['chain_type']}", "", f"- Key: `{chain['api_key']}`", f"- Key hash: `{chain['key_hash']}`"]
        if chain.get("project_id"):
            lines.append(f"- Firebase project: `{chain['project_id']}`")
        lines += [f"- Confidence: `{chain['confidence']}`", "", str(chain["summary"]), ""]
        if chain.get("services"):
            lines += ["**Services**", ""] + [f"- `{service}`" for service in chain["services"]] + [""]
        lines += ["**Evidence classifications**", ""] + [f"- `{item}`" for item in chain.get("evidence_classifications", [])] + ["", "**Recommended report angle**", "", str(chain["recommended_report_angle"]), ""]
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, markdown_path
