from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .classifier import advisory_for_classification, advisory_for_finding
from .models import AUTHOR, TOOL_NAME, VERSION, Finding, mask_key, sha256_text, utc_now
from .cvss import score_hint


def prepare_output_dirs(output_dir: str) -> dict[str, Path]:
    root = Path(output_dir)
    reports = root / "reports"
    poc = root / "poc"
    root.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    poc.mkdir(parents=True, exist_ok=True)
    return {"root": root, "reports": reports, "poc": poc}


def finding_to_record(finding: Finding, store_full_key: bool = False) -> dict[str, Any]:
    return finding.to_dict(store_full_key=store_full_key)


def write_findings_jsonl(findings: list[Finding], output_dir: str, store_full_key: bool = False) -> Path:
    paths = prepare_output_dirs(output_dir)
    path = paths["root"] / "findings.jsonl"
    with path.open("w", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding.to_dict(store_full_key=store_full_key), ensure_ascii=False, sort_keys=True) + "\n")
    return path


def append_findings_jsonl(findings: list[Finding], output_dir: str, store_full_key: bool = False) -> Path:
    paths = prepare_output_dirs(output_dir)
    path = paths["root"] / "findings.jsonl"
    with path.open("a", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding.to_dict(store_full_key=store_full_key), ensure_ascii=False, sort_keys=True) + "\n")
    return path


def load_findings_records(output_dir: str) -> list[dict[str, Any]]:
    path = prepare_output_dirs(output_dir)["root"] / "findings.jsonl"
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                records.append(data)
        except json.JSONDecodeError:
            continue
    return records


def write_summary(findings: list[Finding], output_dir: str) -> Path:
    records = [finding.to_dict(store_full_key=False) for finding in findings]
    return write_summary_records(records, output_dir)


def write_summary_records(records: list[dict[str, Any]], output_dir: str) -> Path:
    paths = prepare_output_dirs(output_dir)
    path = paths["root"] / "summary.json"
    by_priority = Counter(str(r.get("suggested_priority") or "INFO") for r in records)
    by_classification = Counter(str(r.get("classification") or "UNKNOWN") for r in records)
    by_service = Counter(str(r.get("service") or "UNKNOWN") for r in records)
    keys = {str(r.get("api_key_sha256") or "") for r in records if r.get("api_key_sha256")}
    data = {
        "tool": TOOL_NAME,
        "author": AUTHOR,
        "version": VERSION,
        "generated_at": utc_now(),
        "unique_keys_with_findings": len(keys),
        "total_findings": len(records),
        "by_priority": dict(by_priority),
        "by_service": dict(by_service),
        "by_classification": dict(by_classification),
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _finding_title_record(r: dict[str, Any]) -> str:
    target = f" on {r.get('target')}" if r.get("target") else ""
    return f"{r.get('classification', 'UNKNOWN')}{target}"


def write_markdown_report(findings: list[Finding], output_dir: str) -> Path:
    records = [finding.to_dict(store_full_key=False) for finding in findings]
    return write_markdown_report_records(records, output_dir)


def write_markdown_report_records(records: list[dict[str, Any]], output_dir: str) -> Path:
    paths = prepare_output_dirs(output_dir)
    path = paths["reports"] / "advisory.md"
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record.get("api_key_sha256") or "unknown")].append(record)

    lines: list[str] = []
    lines.append(f"# {TOOL_NAME} Advisory Report")
    lines.append("")
    lines.append(f"**Author:** {AUTHOR}")
    lines.append(f"**Version:** {VERSION}")
    lines.append(f"**Generated:** {utc_now()}")
    lines.append("")
    lines.append("This report is generated from AizaScope findings. Final bug bounty severity depends on program policy and manual validation of exposed data, write impact, billing impact, or business context.")
    lines.append("")

    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "REVIEW": 4, "INFO": 5}
    for key_hash, key_records in sorted(grouped.items()):
        key_records.sort(key=lambda r: priority_order.get(str(r.get("suggested_priority") or "INFO"), 99))
        first = key_records[0]
        lines.append(f"## Key {first.get('api_key', '<masked>')}")
        lines.append("")
        lines.append(f"- Key hash: `{key_hash}`")
        project = next((r.get("project_id") for r in key_records if r.get("project_id")), None)
        if project:
            lines.append(f"- Firebase project: `{project}`")
        lines.append("")

        for record in key_records:
            priority = str(record.get("suggested_priority") or "INFO")
            classification = str(record.get("classification") or "UNKNOWN")
            if not is_actionable_record(record, min_priority="MEDIUM"):
                continue
            advisory = advisory_for_classification(classification)
            lines.append(f"### {priority}: {_finding_title_record(record)}")
            lines.append("")
            lines.append(f"- Service: `{record.get('service')}`")
            lines.append(f"- Method: `{record.get('method_name')}`")
            lines.append(f"- Evidence level: `{record.get('evidence_level')}`")
            if record.get("http_status") is not None:
                lines.append(f"- HTTP status: `{record.get('http_status')}`")
            if record.get("target"):
                lines.append(f"- Target: `{record.get('target')}`")
            lines.append(f"- OWASP API mapping: {advisory['owasp_api_2023']}")
            cwe = advisory.get("cwe") or []
            if cwe:
                lines.append(f"- CWE mapping: {', '.join(str(x) for x in cwe)}")
            cvss = score_hint(str(advisory["cvss_vector_hint"]))
            lines.append(f"- CVSS vector hint: `{cvss['vector']}`")
            if cvss.get("score") is not None:
                lines.append(f"- Deterministic CVSS base score: `{cvss['score']}` `{cvss['severity']}`")
            lines.append("")
            lines.append("**Attack class**")
            lines.append("")
            lines.append(str(advisory["attack_class"]))
            lines.append("")
            lines.append("**Business impact**")
            lines.append("")
            lines.append(str(advisory["business_impact"]))
            lines.append("")
            lines.append("**Evidence details**")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(record.get("details") or {}, indent=2, ensure_ascii=False))
            lines.append("```")
            lines.append("")
            lines.append("**Remediation**")
            lines.append("")
            lines.append(str(advisory["remediation"]))
            lines.append("")
            lines.append("**Bug bounty report scaffold**")
            lines.append("")
            lines.append("```text")
            lines.append(f"Title: {classification} affecting {record.get('target') or record.get('service')}")
            lines.append("")
            lines.append("Summary:")
            lines.append("A publicly exposed Google/Firebase API key was tested with AizaScope. The key-only exposure is not treated as a vulnerability by itself; however, this finding confirms the behavior below.")
            lines.append("")
            lines.append("Steps to reproduce:")
            lines.append("1. Use the exposed API key from the in-scope asset.")
            lines.append(f"2. Send a request to the affected service/method: {record.get('service')} / {record.get('method_name')}.")
            lines.append(f"3. Observe the confirmed behavior: {classification}.")
            lines.append("4. Validate data sensitivity and business impact according to program rules.")
            lines.append("")
            lines.append("Impact:")
            lines.append(str(advisory["business_impact"]))
            lines.append("```")
            lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path



def _priority_rank(priority: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "REVIEW": 3, "LOW": 4, "INFO": 5}
    return order.get(str(priority or "INFO"), 99)


_NEGATIVE_CLASS_HINTS = (
    "BLOCKED",
    "RESTRICTED",
    "REQUEST_DENIED",
    "EXPECTED",
    "NOT_ENABLED",
    "NOT_CONFIRMED",
    "NOT_RESOLVED",
    "DISABLED",
    "FAILED",
    "DENIED",
    "INVALID",
    "QUOTA_LIMITED",
    "LIMITED",
)

_NON_ACTIONABLE_POSITIVE_HINTS = (
    "ALLOWED_EMPTY",
    "API_ALLOWED_EMPTY",
    "CONFIG_RESOLVED",
    "PROJECT_RESOLVED",
    "ANONYMOUS_AUTH_ENABLED",
)

_ACTIONABLE_POSITIVE_HINTS = (
    "CONFIRMED",
    "EXPOSED",
    "FROM_ARBITRARY_CLIENT",
    "MODELS_ALLOWED",
    "FILES_METADATA_EXPOSED",
    "CACHED_CONTENT_METADATA_EXPOSED",
    "BATCH_METADATA_EXPOSED",
    "WRITE_PROOF_CONFIRMED",
    "UNEXPECTED_SUCCESS",
)


def is_actionable_record(record: dict[str, Any], *, min_priority: str = "MEDIUM") -> bool:
    """Return True for findings worth showing on terminal / proof-command output.

    This intentionally excludes INFO/REVIEW noise and "allowed but empty" probes.
    AizaScope still stores those raw records in findings.jsonl for auditability.
    """
    priority = str(record.get("suggested_priority") or "INFO")
    if _priority_rank(priority) > _priority_rank(min_priority):
        return False
    classification = str(record.get("classification") or "")
    if any(hint in classification for hint in _NEGATIVE_CLASS_HINTS):
        if "CONFIRMED" not in classification and "UNEXPECTED_SUCCESS" not in classification:
            return False
    if any(hint in classification for hint in _NON_ACTIONABLE_POSITIVE_HINTS):
        return False
    return any(hint in classification for hint in _ACTIONABLE_POSITIVE_HINTS)


def _key_for_record(record: dict[str, Any], key_by_hash: dict[str, str] | None = None) -> str | None:
    api_key = str(record.get("api_key") or "")
    if api_key.startswith("AIza") and "..." not in api_key:
        return api_key
    key_hash = str(record.get("api_key_sha256") or "")
    if key_by_hash and key_hash in key_by_hash:
        return key_by_hash[key_hash]
    return None


def _youtube_url(method: str, key: str) -> str:
    urls = {
        "videos.list": f"https://www.googleapis.com/youtube/v3/videos?part=id&id=dQw4w9WgXcQ&key={key}",
        "commentThreads.list": f"https://www.googleapis.com/youtube/v3/commentThreads?part=id&videoId=dQw4w9WgXcQ&maxResults=1&key={key}",
        "channels.list": f"https://www.googleapis.com/youtube/v3/channels?part=id&id=UC_x5XG1OV2P6uZZ5FSM9Ttw&key={key}",
        "playlists.list": f"https://www.googleapis.com/youtube/v3/playlists?part=id&channelId=UC_x5XG1OV2P6uZZ5FSM9Ttw&maxResults=1&key={key}",
        "playlistItems.list": f"https://www.googleapis.com/youtube/v3/playlistItems?part=id&playlistId=PL590L5WQmH8fJ54F369BLDSqIwcs-TCfs&maxResults=1&key={key}",
        "activities.list": f"https://www.googleapis.com/youtube/v3/activities?part=id&channelId=UC_x5XG1OV2P6uZZ5FSM9Ttw&maxResults=1&key={key}",
        "subscriptions.list": f"https://www.googleapis.com/youtube/v3/subscriptions?part=id&channelId=UC_x5XG1OV2P6uZZ5FSM9Ttw&maxResults=1&key={key}",
        "channelSections.list": f"https://www.googleapis.com/youtube/v3/channelSections?part=id&channelId=UC_x5XG1OV2P6uZZ5FSM9Ttw&key={key}",
        "search.list.expensiveProof": f"https://www.googleapis.com/youtube/v3/search?part=id&q=aizascope_probe&type=video&maxResults=1&key={key}",
        "channels.list.managedByMe": f"https://www.googleapis.com/youtube/v3/channels?part=id&managedByMe=true&maxResults=1&key={key}",
        "videos.rate.writeNegativeControl": f"https://www.googleapis.com/youtube/v3/videos/rate?id=dQw4w9WgXcQ&rating=like&key={key}",
    }
    return urls.get(method, urls["videos.list"])


def proof_commands_for_record(record: dict[str, Any], key: str) -> list[str]:
    """Build ready-to-run curl commands for one positive/actionable finding."""
    service = str(record.get("service") or "")
    method = str(record.get("method_name") or "")
    target = record.get("target")
    details = record.get("details") if isinstance(record.get("details"), dict) else {}
    commands: list[str] = []

    if service == "generativelanguage.googleapis.com":
        if method == "models.list":
            commands.append(f"curl -s 'https://generativelanguage.googleapis.com/v1beta/models?key={key}' | python -m json.tool")
        elif method == "files.list":
            commands.append(f"curl -s 'https://generativelanguage.googleapis.com/v1beta/files?pageSize=1&key={key}' | python -m json.tool")
        elif method == "cachedContents.list":
            commands.append(f"curl -s 'https://generativelanguage.googleapis.com/v1beta/cachedContents?pageSize=1&key={key}' | python -m json.tool")
        elif method == "batches.list":
            commands.append(f"curl -s 'https://generativelanguage.googleapis.com/v1beta/batches?pageSize=1&key={key}' | python -m json.tool")
        elif method == "models.countTokens":
            model = str(details.get("model") or "gemini-1.5-flash")
            payload = '{"contents":[{"parts":[{"text":"AizaScope token proof"}]}]}'
            commands.append(f"curl -s -X POST -H 'Content-Type: application/json' 'https://generativelanguage.googleapis.com/v1beta/models/{model}:countTokens?key={key}' -d '{payload}' | python -m json.tool")
        elif method == "models.generateContent":
            model = str(details.get("model") or "gemini-1.5-flash")
            payload = '{"contents":[{"parts":[{"text":"AizaScope generation proof. Reply with OK."}]}]}'
            commands.append(f"curl -s -X POST -H 'Content-Type: application/json' 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}' -d '{payload}' | python -m json.tool")
        elif method == "models.embedContent":
            model = str(details.get("model") or "text-embedding-004")
            payload = '{"content":{"parts":[{"text":"AizaScope embed proof"}]}}'
            commands.append(f"curl -s -X POST -H 'Content-Type: application/json' 'https://generativelanguage.googleapis.com/v1beta/models/{model}:embedContent?key={key}' -d '{payload}' | python -m json.tool")

    elif service == "youtube.googleapis.com":
        url = _youtube_url(method, key)
        if method == "videos.rate.writeNegativeControl":
            commands.append(f"curl -s -X POST -o /dev/null -w 'Status: %{{http_code}}\\n' '{url}'")
        else:
            commands.append(f"curl -s -o /dev/null -w 'No-Referrer: %{{http_code}}\\n' '{url}'")
            commands.append(f"curl -s -o /dev/null -w 'Fake-Referrer: %{{http_code}}\\n' -H 'Referer: https://evil-attacker-site.example' '{url}'")

    elif service in {"maps.googleapis.com", "places.googleapis.com", "geolocation.googleapis.com"}:
        if method == "mapsjs.loader":
            commands.append(f"curl -s -H 'Referer: https://evil-attacker-site.example' 'https://maps.googleapis.com/maps/api/js?key={key}&callback=__aizascope_probe&v=weekly' | head -c 500")
        elif method == "places.searchText.new":
            payload = '{"textQuery":"coffee in Delhi","pageSize":1}'
            commands.append(f"curl -s -X POST -H 'Content-Type: application/json' -H 'X-Goog-Api-Key: {key}' -H 'X-Goog-FieldMask: places.id,places.displayName' 'https://places.googleapis.com/v1/places:searchText' -d '{payload}' | python -m json.tool")
        elif method == "geolocation.geolocate":
            payload = '{"considerIp":true}'
            commands.append(f"curl -s -X POST -H 'Content-Type: application/json' 'https://www.googleapis.com/geolocation/v1/geolocate?key={key}' -d '{payload}' | python -m json.tool")
        elif method == "directions.legacy":
            commands.append(f"curl -s 'https://maps.googleapis.com/maps/api/directions/json?origin=Delhi&destination=Mumbai&key={key}' | python -m json.tool")
        elif method == "distancematrix.legacy":
            commands.append(f"curl -s 'https://maps.googleapis.com/maps/api/distancematrix/json?origins=Delhi&destinations=Mumbai&key={key}' | python -m json.tool")
        elif method == "timezone.get":
            commands.append(f"curl -s 'https://maps.googleapis.com/maps/api/timezone/json?location=28.6139,77.2090&timestamp=0&key={key}' | python -m json.tool")
        elif method == "staticmap.get":
            commands.append(f"curl -s -o /dev/null -w 'Status: %{{http_code}}\\n' 'https://maps.googleapis.com/maps/api/staticmap?center=Delhi&zoom=10&size=1x1&key={key}'")
        elif method == "geocoding.geocode":
            commands.append(f"curl -s 'https://maps.googleapis.com/maps/api/geocode/json?address=New+Delhi&key={key}' | python -m json.tool")
        elif method == "places.textsearch.legacy":
            commands.append(f"curl -s 'https://maps.googleapis.com/maps/api/place/textsearch/json?query=coffee+in+Delhi&key={key}' | python -m json.tool")

    elif service == "vision.googleapis.com":
        payload = '{"requests":[{"image":{"content":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="},"features":[{"type":"LABEL_DETECTION","maxResults":1}]}]}'
        commands.append(f"curl -s -X POST -H 'Content-Type: application/json' 'https://vision.googleapis.com/v1/images:annotate?key={key}' -d '{payload}' | python -m json.tool")
    elif service == "translation.googleapis.com":
        payload = '{"q":"AizaScope proof"}'
        commands.append(f"curl -s -X POST -H 'Content-Type: application/json' 'https://translation.googleapis.com/language/translate/v2/detect?key={key}' -d '{payload}' | python -m json.tool")
    elif service == "language.googleapis.com":
        payload = '{"document":{"type":"PLAIN_TEXT","content":"AizaScope proof"},"encodingType":"UTF8"}'
        commands.append(f"curl -s -X POST -H 'Content-Type: application/json' 'https://language.googleapis.com/v1/documents:analyzeSentiment?key={key}' -d '{payload}' | python -m json.tool")
    elif service == "safebrowsing.googleapis.com":
        payload = json.dumps({
            "client": {"clientId": "aizascope", "clientVersion": VERSION},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": "http://example.com/"}],
            },
        }, separators=(",", ":"))
        commands.append(f"curl -s -X POST -H 'Content-Type: application/json' -H 'Referer: https://evil-attacker-site.example' 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}' -d '{payload}' | python -m json.tool")

    elif service == "firestore.googleapis.com" and record.get("project_id") and target:
        collection = str(target).lstrip("/").split("/")[0]
        commands.append(f"curl -s 'https://firestore.googleapis.com/v1/projects/{record.get('project_id')}/databases/(default)/documents/{collection}?pageSize=1&mask.fieldPaths=__name__' | python -m json.tool")
    elif service == "firebaseio.com" and target:
        commands.append(f"curl -s '{target}/.json?shallow=true&timeout=3s' | python -m json.tool")
    elif service == "firebasestorage.googleapis.com" and target and str(target).startswith("gs://"):
        bucket = str(target)[5:].split("/", 1)[0]
        commands.append(f"curl -s 'https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1' | python -m json.tool")

    return commands


def write_ready_commands_json_records(records: list[dict[str, Any]], output_dir: str, key_by_hash: dict[str, str] | None = None) -> Path:
    paths = prepare_output_dirs(output_dir)
    path = paths["root"] / "proof_commands.json"
    items: list[dict[str, Any]] = []
    for record in records:
        if not is_actionable_record(record, min_priority="MEDIUM"):
            continue
        key = _key_for_record(record, key_by_hash)
        if not key:
            continue
        commands = proof_commands_for_record(record, key)
        if not commands:
            continue
        items.append({
            "priority": record.get("suggested_priority"),
            "classification": record.get("classification"),
            "service": record.get("service"),
            "method": record.get("method_name"),
            "project_id": record.get("project_id"),
            "target": record.get("target"),
            "masked_key": mask_key(key),
            "api_key": key,
            "commands": commands,
            "evidence": {
                "http_status": record.get("http_status"),
                "evidence_level": record.get("evidence_level"),
                "details": record.get("details") or {},
            },
        })
    data = {
        "tool": TOOL_NAME,
        "author": AUTHOR,
        "version": VERSION,
        "generated_at": utc_now(),
        "warning": "This file intentionally contains full API keys inside ready-to-run proof commands. Do not commit or share it.",
        "min_priority": "MEDIUM",
        "count": len(items),
        "commands": items,
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_curl_pocs(findings: list[Finding], output_dir: str, key_by_hash: dict[str, str] | None = None) -> Path:
    records = [finding.to_dict(store_full_key=True) for finding in findings]
    return write_curl_pocs_records(records, output_dir, key_by_hash=key_by_hash)


def write_curl_pocs_records(records: list[dict[str, Any]], output_dir: str, key_by_hash: dict[str, str] | None = None) -> Path:
    paths = prepare_output_dirs(output_dir)
    path = paths["poc"] / "curl_pocs.sh"
    lines: list[str] = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Generated by AizaScope.",
        "# Contains only MEDIUM/HIGH/CRITICAL positive findings with ready-to-run keys.",
        "# Do not commit this file if it contains live third-party API keys.",
        "",
    ]
    written = 0
    for record in records:
        if not is_actionable_record(record, min_priority="MEDIUM"):
            continue
        key = _key_for_record(record, key_by_hash)
        if not key:
            continue
        commands = proof_commands_for_record(record, key)
        if not commands:
            continue
        written += 1
        lines.append(f"# [{record.get('suggested_priority')}] {record.get('classification')} - {record.get('service')} - {record.get('method_name')}")
        for command in commands:
            lines.append(command)
        lines.append("")
    if written == 0:
        lines.append("# No MEDIUM/HIGH/CRITICAL positive proof commands were generated.")
        lines.append("# Check findings.jsonl for INFO/REVIEW/blocked results if needed.")
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(0o755)
    return path
