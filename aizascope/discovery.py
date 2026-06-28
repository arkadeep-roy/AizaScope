from __future__ import annotations

import json
from pathlib import Path

from .http_client import HttpClient
from .models import utc_now

DISCOVERY_URL = "https://www.googleapis.com/discovery/v1/apis"

HIGH_VALUE_API_NAMES = {
    "firestore",
    "firebase",
    "firebasestorage",
    "identitytoolkit",
    "youtube",
    "generativelanguage",
    "maps",
    "places",
    "geocoding",
    "routes",
    "distanceMatrix",
    "apikeys",
}


def update_manifest(output_dir: str, timeout: int = 20, user_agent: str = "AizaScope/0.3.0") -> Path:
    client = HttpClient(timeout=timeout, user_agent=user_agent)
    res = client.request("GET", DISCOVERY_URL)
    if res.status != 200:
        raise RuntimeError(f"Discovery API returned HTTP {res.status}: {res.body_text[:300]}")
    data = res.json()
    if not isinstance(data, dict):
        raise RuntimeError("Discovery API did not return a JSON object")

    items = data.get("items") or []
    focused = []
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            title = str(item.get("title") or "")
            description = str(item.get("description") or "")
            haystack = f"{name} {title} {description}".lower()
            if any(token.lower() in haystack for token in HIGH_VALUE_API_NAMES):
                focused.append(item)

    manifest = {
        "tool": "AizaScope",
        "generated_at": utc_now(),
        "source": DISCOVERY_URL,
        "note": "Discovery docs are used for endpoint awareness. AizaScope only probes curated low-impact endpoints unless explicitly extended.",
        "focused_api_count": len(focused),
        "focused_apis": focused,
    }

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "google_api_discovery_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
