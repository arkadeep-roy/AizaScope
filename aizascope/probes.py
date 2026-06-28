from __future__ import annotations

import json
import re
import secrets
from urllib.parse import quote

from .classifier import classify_api_matrix, classify_firestore_collection
from .http_client import HttpClient, add_query, quote_path
from .models import Finding, ScanContext, VERSION

DEFAULT_COLLECTIONS = [
    "users", "user", "profiles", "profile", "customers", "customer", "clients", "members",
    "accounts", "admins", "admin", "employees", "staff", "orders", "order", "payments",
    "payment", "invoices", "subscriptions", "transactions", "wallets", "cards", "addresses",
    "sessions", "tokens", "secrets", "configs", "settings", "private", "messages", "chats",
    "notifications", "bookings", "appointments", "leads", "contacts", "reports", "tickets",
    "tasks", "posts", "comments", "events", "rooms", "uploads", "files", "documents",
    "organisation", "organisations", "organization", "organizations", "entities", "tenants",
]

STORAGE_PREFIXES = [
    "users/", "uploads/", "images/", "avatars/", "profile/", "profiles/", "documents/",
    "docs/", "receipts/", "invoices/", "private/", "public/", "media/", "attachments/",
    "chat/", "messages/", "exports/", "backups/",
]


def _body_has_permission_denied(body: str) -> bool:
    lowered = body.lower()
    return "permission_denied" in lowered or "permission denied" in lowered or "permission-denied" in lowered


def _json_get(data: object, path: list[str], default: object = None) -> object:
    current = data
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _project_id_valid(project_id: str) -> bool:
    return bool(re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project_id))


def _remember_mode(mapping: dict[str, list[str]], auth_label: str, value: str) -> None:
    values = mapping.setdefault(auth_label, [])
    if value not in values:
        values.append(value)


def _choose_gemini_model(ctx: ScanContext, required_method: str, fallback: str) -> str:
    for name, methods in ctx.gemini_model_methods.items():
        if required_method in methods and "flash" in name.lower():
            return name
    for name, methods in ctx.gemini_model_methods.items():
        if required_method in methods:
            return name
    return next((m for m in ctx.gemini_models if "flash" in m.lower()), ctx.gemini_models[0] if ctx.gemini_models else fallback)


def _maps_body_allows(method_name: str, status: int, headers: dict[str, str], data: object, body_text: str) -> bool:
    if status != 200:
        return False
    if isinstance(data, dict):
        if data.get("error") or data.get("error_message"):
            return False
        api_status = str(data.get("status") or "").upper()
        if api_status in {"REQUEST_DENIED", "INVALID_REQUEST", "OVER_DAILY_LIMIT", "OVER_QUERY_LIMIT", "PERMISSION_DENIED"}:
            return False
        if api_status in {"OK", "ZERO_RESULTS"}:
            return True
        if method_name == "places.searchText.new" and "places" in data:
            return True
        if method_name == "geolocation.geolocate" and "location" in data:
            return True
    content_type = headers.get("content-type", "").lower()
    if method_name == "staticmap.get" and content_type.startswith("image/"):
        lowered = body_text.lower()
        return "error" not in lowered and "denied" not in lowered and "invalid" not in lowered
    if method_name == "mapsjs.loader":
        lowered = body_text.lower()
        known_errors = ("referernotallowedmaperror", "invalidkeymaperror", "apinotactivatedmaperror", "billingnotenabledmaperror", "google maps javascript api error")
        return status == 200 and ("google.maps" in lowered or "__aizascope_probe" in lowered) and not any(err.lower() in lowered for err in known_errors)
    return False


def _maps_body_denied(data: object, body_text: str) -> bool:
    if isinstance(data, dict):
        api_status = str(data.get("status") or "").upper()
        error_text = str(data.get("error_message") or _json_get(data, ["error", "message"], "") or "").upper()
        return api_status in {"REQUEST_DENIED", "OVER_DAILY_LIMIT", "PERMISSION_DENIED"} or "API KEY" in error_text or "REFERER" in error_text or "REFERRER" in error_text or "NOT AUTHORIZED" in error_text
    lowered = body_text.lower()
    return (
        "request_denied" in lowered
        or "api key" in lowered
        or "not authorized" in lowered
        or "referer" in lowered
        or "referrer" in lowered
        or "referernotallowedmaperror" in lowered
        or "invalidkeymaperror" in lowered
        or "apinotactivatedmaperror" in lowered
        or "billingnotenabledmaperror" in lowered
    )


class ProbeRunner:
    def __init__(self, client: HttpClient) -> None:
        self.client = client

    def run_all(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self.firebase_config(ctx))

        if ctx.project_id:
            findings.extend(self.firestore(ctx, token=None, auth_label="unauth"))
            findings.extend(self.firestore_collection_ids(ctx, token=None, auth_label="unauth"))
            findings.extend(self.rtdb(ctx, token=None, auth_label="unauth"))
            findings.extend(self.storage(ctx, token=None, auth_label="unauth"))

            if ctx.profile in {"active", "aggressive-authorized"}:
                findings.extend(self.maybe_anonymous_auth(ctx))

            if ctx.profile == "aggressive-authorized":
                findings.extend(self.maybe_write_proofs(ctx))

            if ctx.id_token:
                findings.extend(self.cleanup_anonymous_auth(ctx))

        findings.extend(self.gemini(ctx))
        findings.extend(self.youtube(ctx))
        findings.extend(self.maps(ctx))
        findings.extend(self.cloud_ai(ctx))
        findings.extend(self.safe_browsing(ctx))
        return findings

    def firebase_config(self, ctx: ScanContext) -> list[Finding]:
        url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key={ctx.key}"
        res = self.client.request("GET", url)
        data = res.json()
        findings: list[Finding] = []

        if res.status == 200 and isinstance(data, dict):
            project_id = str(data.get("projectId") or "").strip()
            if project_id and _project_id_valid(project_id):
                ctx.project_id = project_id
                ctx.database_url = str(data.get("databaseURL") or "").strip() or None
                ctx.storage_bucket = str(data.get("storageBucket") or "").strip() or None
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="identitytoolkit.googleapis.com",
                        method_name="getProjectConfig",
                        classification="FIREBASE_PROJECT_RESOLVED",
                        endpoint="identitytoolkit/v3/relyingparty/getProjectConfig",
                        http_status=res.status,
                        project_id=project_id,
                        evidence_level="E1",
                        suggested_priority="INFO",
                        details={
                            "authorized_domains_count": len(data.get("authorizedDomains") or []),
                            "database_url_present": bool(ctx.database_url),
                            "storage_bucket_present": bool(ctx.storage_bucket),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="identitytoolkit.googleapis.com",
                        method_name="getProjectConfig",
                        classification="FIREBASE_CONFIG_RESOLVED_WITH_UNUSUAL_PROJECT_ID",
                        endpoint="identitytoolkit/v3/relyingparty/getProjectConfig",
                        http_status=res.status,
                        evidence_level="E1",
                        suggested_priority="REVIEW",
                        details={"project_id": project_id},
                    )
                )
        else:
            err = data if isinstance(data, dict) else {}
            findings.append(
                Finding(
                    key=ctx.key,
                    service="identitytoolkit.googleapis.com",
                    method_name="getProjectConfig",
                    classification="FIREBASE_PROJECT_NOT_RESOLVED",
                    endpoint="identitytoolkit/v3/relyingparty/getProjectConfig",
                    http_status=res.status,
                    evidence_level="E0",
                    suggested_priority="INFO",
                    details={"error": _json_get(err, ["error", "message"], res.error or res.body_text[:200])},
                )
            )
        return findings

    def firestore(self, ctx: ScanContext, token: str | None, auth_label: str) -> list[Finding]:
        if not ctx.project_id:
            return []
        findings: list[Finding] = []
        headers = {"Authorization": f"Bearer {token}"} if token else None

        for collection in DEFAULT_COLLECTIONS:
            path = f"https://firestore.googleapis.com/v1/projects/{ctx.project_id}/databases/(default)/documents/{collection}"
            url = add_query(path, pageSize=1, key=ctx.key)
            url += "&mask.fieldPaths=__name__"
            res = self.client.request("GET", url, headers=headers)
            data = res.json()
            docs = data.get("documents") if isinstance(data, dict) else None

            if res.status == 200:
                has_docs = isinstance(docs, list) and len(docs) > 0
                classification, evidence, priority = classify_firestore_collection(collection, has_docs)
                if auth_label != "unauth":
                    if "UNAUTH" in classification:
                        classification = classification.replace("UNAUTH", "AUTH")
                    elif classification.startswith("FIRESTORE_"):
                        classification = classification.replace("FIRESTORE_", "FIRESTORE_AUTH_", 1)
                if has_docs:
                    if collection not in ctx.confirmed_firestore_reads:
                        ctx.confirmed_firestore_reads.append(collection)
                    _remember_mode(ctx.confirmed_firestore_read_modes, auth_label, collection)
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="firestore.googleapis.com",
                        method_name=f"documents.list.{auth_label}",
                        classification=classification,
                        endpoint="firestore/v1/projects/{project}/databases/(default)/documents/{collection}",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        target=f"/{collection}",
                        evidence_level=evidence,
                        suggested_priority=priority,
                        details={
                            "auth_label": auth_label,
                            "documents_returned": len(docs) if isinstance(docs, list) else 0,
                            "field_mask": "__name__",
                            "downloaded_field_values": False,
                        },
                    )
                )
            elif res.status in {401, 403}:
                continue
            elif res.status == 429:
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="firestore.googleapis.com",
                        method_name=f"documents.list.{auth_label}",
                        classification="FIRESTORE_QUOTA_OR_RATE_LIMITED",
                        endpoint="firestore documents list",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        target=f"/{collection}",
                        evidence_level="E2",
                        suggested_priority="REVIEW",
                        details={"auth_label": auth_label},
                    )
                )
        return findings

    def firestore_collection_ids(self, ctx: ScanContext, token: str | None, auth_label: str) -> list[Finding]:
        if not ctx.project_id:
            return []
        url = f"https://firestore.googleapis.com/v1/projects/{ctx.project_id}/databases/(default)/documents:listCollectionIds?key={ctx.key}"
        headers = {"Authorization": f"Bearer {token}"} if token else None
        res = self.client.request("POST", url, headers=headers, json_body={"pageSize": 20})
        data = res.json()
        findings: list[Finding] = []

        if res.status == 200 and isinstance(data, dict):
            ids = data.get("collectionIds") or []
            if isinstance(ids, list) and ids:
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="firestore.googleapis.com",
                        method_name=f"documents.listCollectionIds.{auth_label}",
                        classification="FIRESTORE_COLLECTION_IDS_EXPOSED" if auth_label == "unauth" else "FIRESTORE_COLLECTION_IDS_EXPOSED_AUTH",
                        endpoint="firestore/v1/.../documents:listCollectionIds",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        target="/",
                        evidence_level="E4",
                        suggested_priority="HIGH",
                        details={"auth_label": auth_label, "collection_ids_sample": ids[:20], "collection_ids_count_sample": len(ids)},
                    )
                )
            else:
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="firestore.googleapis.com",
                        method_name=f"documents.listCollectionIds.{auth_label}",
                        classification="FIRESTORE_COLLECTION_IDS_ALLOWED_EMPTY",
                        endpoint="firestore/v1/.../documents:listCollectionIds",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        target="/",
                        evidence_level="E3",
                        suggested_priority="LOW",
                        details={"auth_label": auth_label},
                    )
                )
        return findings

    def rtdb(self, ctx: ScanContext, token: str | None, auth_label: str) -> list[Finding]:
        if not ctx.project_id:
            return []
        bases: list[str] = []
        if ctx.database_url:
            bases.append(ctx.database_url.rstrip("/"))
        bases.extend(
            [
                f"https://{ctx.project_id}.firebaseio.com",
                f"https://{ctx.project_id}-default-rtdb.firebaseio.com",
            ]
        )
        unique_bases = list(dict.fromkeys(bases))
        findings: list[Finding] = []

        for base in unique_bases:
            url = f"{base}/.json?shallow=true&timeout=3s"
            if token:
                url += f"&auth={quote(token)}"
            res = self.client.request("GET", url)
            data = res.json()
            if res.status == 200 and not _body_has_permission_denied(res.body_text):
                if isinstance(data, dict):
                    key_count = len(data.keys())
                    if key_count > 0:
                        if base not in ctx.confirmed_rtdb_reads:
                            ctx.confirmed_rtdb_reads.append(base)
                        _remember_mode(ctx.confirmed_rtdb_read_modes, auth_label, base)
                        findings.append(
                            Finding(
                                key=ctx.key,
                                service="firebaseio.com",
                                method_name=f"rtdb.shallowRead.{auth_label}",
                                classification="RTDB_UNAUTH_SHALLOW_READ_CONFIRMED" if auth_label == "unauth" else "RTDB_AUTH_SHALLOW_READ_CONFIRMED",
                                endpoint="/{db}/.json?shallow=true&timeout=3s",
                                http_status=res.status,
                                project_id=ctx.project_id,
                                target=base,
                                evidence_level="E4",
                                suggested_priority="HIGH",
                                details={"auth_label": auth_label, "top_level_key_count": key_count, "top_level_keys_sample": list(data.keys())[:20], "downloaded_values": False},
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                key=ctx.key,
                                service="firebaseio.com",
                                method_name=f"rtdb.shallowRead.{auth_label}",
                                classification="RTDB_READ_ALLOWED_EMPTY" if auth_label == "unauth" else "RTDB_AUTH_READ_ALLOWED_EMPTY",
                                endpoint="/{db}/.json?shallow=true&timeout=3s",
                                http_status=res.status,
                                project_id=ctx.project_id,
                                target=base,
                                evidence_level="E3",
                                suggested_priority="LOW",
                                details={"auth_label": auth_label},
                            )
                        )
                elif data is not None:
                    if base not in ctx.confirmed_rtdb_reads:
                        ctx.confirmed_rtdb_reads.append(base)
                    _remember_mode(ctx.confirmed_rtdb_read_modes, auth_label, base)
                    findings.append(
                        Finding(
                            key=ctx.key,
                            service="firebaseio.com",
                            method_name=f"rtdb.shallowRead.{auth_label}",
                            classification="RTDB_UNAUTH_PRIMITIVE_ROOT_READ_CONFIRMED" if auth_label == "unauth" else "RTDB_AUTH_PRIMITIVE_ROOT_READ_CONFIRMED",
                            endpoint="/{db}/.json?shallow=true&timeout=3s",
                            http_status=res.status,
                            project_id=ctx.project_id,
                            target=base,
                            evidence_level="E4",
                            suggested_priority="HIGH",
                            details={"auth_label": auth_label, "json_type": type(data).__name__},
                        )
                    )
            elif res.status == 429:
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="firebaseio.com",
                        method_name=f"rtdb.shallowRead.{auth_label}",
                        classification="RTDB_QUOTA_OR_RATE_LIMITED",
                        endpoint="/{db}/.json?shallow=true&timeout=3s",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        target=base,
                        evidence_level="E2",
                        suggested_priority="REVIEW",
                    )
                )
        return findings

    def storage(self, ctx: ScanContext, token: str | None, auth_label: str) -> list[Finding]:
        if not ctx.project_id:
            return []
        buckets: list[str] = []
        if ctx.storage_bucket:
            buckets.append(ctx.storage_bucket)
        buckets.extend([f"{ctx.project_id}.appspot.com", f"{ctx.project_id}.firebasestorage.app"])
        buckets = list(dict.fromkeys([b for b in buckets if b]))
        headers = {"Authorization": f"Bearer {token}"} if token else None
        findings: list[Finding] = []

        for bucket in buckets:
            url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1"
            res = self.client.request("GET", url, headers=headers)
            data = res.json()
            if res.status == 200 and isinstance(data, dict):
                items = data.get("items") or []
                prefixes = data.get("prefixes") or []
                count = (len(items) if isinstance(items, list) else 0) + (len(prefixes) if isinstance(prefixes, list) else 0)
                if count > 0:
                    if bucket not in ctx.confirmed_storage_lists:
                        ctx.confirmed_storage_lists.append(bucket)
                    _remember_mode(ctx.confirmed_storage_list_modes, auth_label, bucket)
                    findings.append(
                        Finding(
                            key=ctx.key,
                            service="firebasestorage.googleapis.com",
                            method_name=f"storage.objects.list.{auth_label}",
                            classification="STORAGE_LIST_CONFIRMED" if auth_label == "unauth" else "STORAGE_AUTH_LIST_CONFIRMED",
                            endpoint="firebasestorage/v0/b/{bucket}/o?maxResults=1",
                            http_status=res.status,
                            project_id=ctx.project_id,
                            target=f"gs://{bucket}",
                            evidence_level="E4",
                            suggested_priority="HIGH",
                            details={"auth_label": auth_label, "objects_or_prefixes_sample_count": count, "object_content_downloaded": False},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            key=ctx.key,
                            service="firebasestorage.googleapis.com",
                            method_name=f"storage.objects.list.{auth_label}",
                            classification="STORAGE_LIST_ALLOWED_EMPTY" if auth_label == "unauth" else "STORAGE_AUTH_LIST_ALLOWED_EMPTY",
                            endpoint="firebasestorage/v0/b/{bucket}/o?maxResults=1",
                            http_status=res.status,
                            project_id=ctx.project_id,
                            target=f"gs://{bucket}",
                            evidence_level="E3",
                            suggested_priority="LOW",
                            details={"auth_label": auth_label},
                        )
                    )

            if ctx.profile in {"active", "aggressive-authorized"}:
                for prefix in STORAGE_PREFIXES:
                    purl = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?prefix={quote(prefix)}&maxResults=1"
                    pres = self.client.request("GET", purl, headers=headers)
                    pdata = pres.json()
                    if pres.status == 200 and isinstance(pdata, dict):
                        items = pdata.get("items") or []
                        prefixes = pdata.get("prefixes") or []
                        count = (len(items) if isinstance(items, list) else 0) + (len(prefixes) if isinstance(prefixes, list) else 0)
                        if count > 0:
                            if bucket not in ctx.confirmed_storage_lists:
                                ctx.confirmed_storage_lists.append(bucket)
                            _remember_mode(ctx.confirmed_storage_list_modes, auth_label, bucket)
                            findings.append(
                                Finding(
                                    key=ctx.key,
                                    service="firebasestorage.googleapis.com",
                                    method_name=f"storage.objects.prefixList.{auth_label}",
                                    classification="STORAGE_PREFIX_LIST_CONFIRMED" if auth_label == "unauth" else "STORAGE_AUTH_PREFIX_LIST_CONFIRMED",
                                    endpoint="firebasestorage/v0/b/{bucket}/o?prefix={prefix}&maxResults=1",
                                    http_status=pres.status,
                                    project_id=ctx.project_id,
                                    target=f"gs://{bucket}/{prefix}",
                                    evidence_level="E4",
                                    suggested_priority="HIGH",
                                    details={"auth_label": auth_label, "prefix": prefix, "objects_or_prefixes_sample_count": count},
                                )
                            )
                            break
        return findings

    def gemini(self, ctx: ScanContext) -> list[Finding]:
        probes = [
            ("models.list", f"https://generativelanguage.googleapis.com/v1beta/models?key={ctx.key}"),
            ("files.list", f"https://generativelanguage.googleapis.com/v1beta/files?pageSize=1&key={ctx.key}"),
            ("cachedContents.list", f"https://generativelanguage.googleapis.com/v1beta/cachedContents?pageSize=1&key={ctx.key}"),
            ("batches.list", f"https://generativelanguage.googleapis.com/v1beta/batches?pageSize=1&key={ctx.key}"),
        ]
        findings: list[Finding] = []
        for method_name, url in probes:
            res = self.client.request("GET", url)
            data = res.json()
            if res.status == 200:
                classification = "GEMINI_API_ALLOWED"
                priority = "MEDIUM"
                evidence = "E3"
                details: dict[str, object] = {}
                if isinstance(data, dict):
                    if method_name == "models.list":
                        models = data.get("models") or []
                        if isinstance(models, list):
                            ctx.gemini_models = []
                            ctx.gemini_model_methods = {}
                            for m in models:
                                if not isinstance(m, dict) or not m.get("name"):
                                    continue
                                name = str(m.get("name") or "").replace("models/", "")
                                methods = [str(x) for x in (m.get("supportedGenerationMethods") or [])]
                                ctx.gemini_models.append(name)
                                ctx.gemini_model_methods[name] = methods
                            details["model_count_sample"] = len(models)
                            details["models_sample"] = ctx.gemini_models[:8]
                            details["supported_generation_methods_sample"] = {name: ctx.gemini_model_methods.get(name, []) for name in ctx.gemini_models[:8]}
                        else:
                            details["model_count_sample"] = 0
                        if details["model_count_sample"]:
                            evidence = "E4"
                            classification = "GEMINI_MODELS_ALLOWED"
                    if method_name == "files.list":
                        files = data.get("files") or []
                        details["file_metadata_count_sample"] = len(files) if isinstance(files, list) else 0
                        if isinstance(files, list) and files:
                            details["file_metadata_sample"] = [
                                {"name": f.get("name"), "displayName": f.get("displayName"), "mimeType": f.get("mimeType"), "sizeBytes": f.get("sizeBytes")}
                                for f in files[:3] if isinstance(f, dict)
                            ]
                        classification = "GEMINI_FILES_METADATA_EXPOSED" if details["file_metadata_count_sample"] else "GEMINI_FILES_API_ALLOWED_EMPTY"
                        priority = "HIGH" if details["file_metadata_count_sample"] else "LOW"
                        evidence = "E4" if details["file_metadata_count_sample"] else "E3"
                    if method_name == "cachedContents.list":
                        cached = data.get("cachedContents") or []
                        details["cached_contents_count_sample"] = len(cached) if isinstance(cached, list) else 0
                        if isinstance(cached, list) and cached:
                            details["cached_contents_sample"] = [{"name": c.get("name"), "model": c.get("model")} for c in cached[:3] if isinstance(c, dict)]
                        classification = "GEMINI_CACHED_CONTENT_METADATA_EXPOSED" if details["cached_contents_count_sample"] else "GEMINI_CACHED_CONTENT_API_ALLOWED_EMPTY"
                        priority = "HIGH" if details["cached_contents_count_sample"] else "LOW"
                        evidence = "E4" if details["cached_contents_count_sample"] else "E3"
                    if method_name == "batches.list":
                        batches = data.get("batches") or data.get("operations") or []
                        details["batch_metadata_count_sample"] = len(batches) if isinstance(batches, list) else 0
                        if isinstance(batches, list) and batches:
                            details["batch_metadata_sample"] = [{"name": b.get("name"), "done": b.get("done")} for b in batches[:3] if isinstance(b, dict)]
                        classification = "GEMINI_BATCH_METADATA_EXPOSED" if details["batch_metadata_count_sample"] else "GEMINI_BATCH_API_ALLOWED_EMPTY"
                        priority = "HIGH" if details["batch_metadata_count_sample"] else "LOW"
                        evidence = "E4" if details["batch_metadata_count_sample"] else "E3"
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="generativelanguage.googleapis.com",
                        method_name=method_name,
                        classification=classification,
                        endpoint=url.split("?", 1)[0],
                        http_status=res.status,
                        project_id=ctx.project_id,
                        evidence_level=evidence,
                        suggested_priority=priority,
                        details=details,
                    )
                )
            elif res.status == 429:
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="generativelanguage.googleapis.com",
                        method_name=method_name,
                        classification="GEMINI_QUOTA_OR_RATE_LIMITED",
                        endpoint=url.split("?", 1)[0],
                        http_status=res.status,
                        project_id=ctx.project_id,
                        evidence_level="E2",
                        suggested_priority="REVIEW",
                    )
                )
        if ctx.profile in {"active", "aggressive-authorized"}:
            findings.extend(self.gemini_optional_active_proofs(ctx))
        return findings

    def gemini_optional_active_proofs(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        token_model = _choose_gemini_model(ctx, "countTokens", "gemini-1.5-flash")
        generation_model = _choose_gemini_model(ctx, "generateContent", token_model)
        embed_model = _choose_gemini_model(ctx, "embedContent", "embedding-001")

        if ctx.gemini_token_proof != "off":
            allowed = ctx.gemini_token_proof == "auto" or self._confirm(ctx, f"Run Gemini countTokens proof with model {token_model}? [y/N] ")
            if allowed:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{token_model}:countTokens?key={ctx.key}"
                payload = {"contents": [{"parts": [{"text": "AizaScope authorized token-count proof."}]}]}
                res = self.client.request("POST", url, json_body=payload)
                data = res.json()
                if res.status == 200:
                    total_tokens = data.get("totalTokens") if isinstance(data, dict) else None
                    findings.append(
                        Finding(
                            key=ctx.key,
                            service="generativelanguage.googleapis.com",
                            method_name="models.countTokens",
                            classification="GEMINI_COUNT_TOKENS_CONFIRMED",
                            endpoint=f"generativelanguage/v1beta/models/{token_model}:countTokens",
                            http_status=res.status,
                            project_id=ctx.project_id,
                            evidence_level="E5",
                            suggested_priority="MEDIUM",
                            proof_mode="active_low_cost_token_count",
                            details={"model": token_model, "total_tokens": total_tokens, "selection_reason": "supportedGenerationMethods.countTokens"},
                        )
                    )
                elif res.status in {401, 403, 429}:
                    findings.append(
                        Finding(
                            key=ctx.key,
                            service="generativelanguage.googleapis.com",
                            method_name="models.countTokens",
                            classification="GEMINI_COUNT_TOKENS_BLOCKED_OR_LIMITED",
                            endpoint=f"generativelanguage/v1beta/models/{token_model}:countTokens",
                            http_status=res.status,
                            project_id=ctx.project_id,
                            evidence_level="E2",
                            suggested_priority="INFO" if res.status in {401, 403} else "REVIEW",
                            details={"model": token_model, "selection_reason": "supportedGenerationMethods.countTokens"},
                        )
                    )

        if ctx.gemini_generation_proof != "off":
            allowed = ctx.gemini_generation_proof == "auto" or self._confirm(ctx, f"Run one tiny Gemini generateContent proof with model {generation_model}? [y/N] ")
            if allowed:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{generation_model}:generateContent?key={ctx.key}"
                payload = {"contents": [{"parts": [{"text": "Return the word OK only."}]}], "generationConfig": {"maxOutputTokens": 4}}
                res = self.client.request("POST", url, json_body=payload)
                classification = "GEMINI_GENERATE_CONTENT_CONFIRMED" if res.status == 200 else "GEMINI_GENERATE_CONTENT_BLOCKED_OR_LIMITED"
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="generativelanguage.googleapis.com",
                        method_name="models.generateContent",
                        classification=classification,
                        endpoint=f"generativelanguage/v1beta/models/{generation_model}:generateContent",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        evidence_level="E5" if res.status == 200 else "E2",
                        suggested_priority="HIGH" if res.status == 200 else ("REVIEW" if res.status == 429 else "INFO"),
                        proof_mode="explicit_generation_proof",
                        details={"model": generation_model, "max_output_tokens": 4, "selection_reason": "supportedGenerationMethods.generateContent"},
                    )
                )
        if ctx.gemini_embed_proof != "off":
            allowed = ctx.gemini_embed_proof == "auto" or self._confirm(ctx, f"Run one Gemini embedContent proof with model {embed_model}? [y/N] ")
            if allowed:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{embed_model}:embedContent?key={ctx.key}"
                payload = {"content": {"parts": [{"text": "AizaScope authorized embed proof."}]}}
                res = self.client.request("POST", url, json_body=payload)
                data = res.json()
                embedding_values = None
                if isinstance(data, dict):
                    embedding = data.get("embedding") or {}
                    if isinstance(embedding, dict):
                        values = embedding.get("values") or []
                        if isinstance(values, list):
                            embedding_values = len(values)
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="generativelanguage.googleapis.com",
                        method_name="models.embedContent",
                        classification="GEMINI_EMBED_CONTENT_CONFIRMED" if res.status == 200 else "GEMINI_EMBED_CONTENT_BLOCKED_OR_LIMITED",
                        endpoint=f"generativelanguage/v1beta/models/{embed_model}:embedContent",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        evidence_level="E5" if res.status == 200 else "E2",
                        suggested_priority="MEDIUM" if res.status == 200 else ("REVIEW" if res.status == 429 else "INFO"),
                        proof_mode="explicit_embedding_proof",
                        details={"model": embed_model, "embedding_value_count": embedding_values, "selection_reason": "supportedGenerationMethods.embedContent"},
                    )
                )
        return findings

    def youtube(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = [
            ("videos.list", f"https://www.googleapis.com/youtube/v3/videos?part=id&id=dQw4w9WgXcQ&key={ctx.key}", "low"),
        ]
        if ctx.profile in {"active", "aggressive-authorized"}:
            endpoints.extend(
                [
                    ("commentThreads.list", f"https://www.googleapis.com/youtube/v3/commentThreads?part=id&videoId=dQw4w9WgXcQ&maxResults=1&key={ctx.key}", "low"),
                    ("channels.list", f"https://www.googleapis.com/youtube/v3/channels?part=id&id=UC_x5XG1OV2P6uZZ5FSM9Ttw&key={ctx.key}", "low"),
                    ("playlists.list", f"https://www.googleapis.com/youtube/v3/playlists?part=id&channelId=UC_x5XG1OV2P6uZZ5FSM9Ttw&maxResults=1&key={ctx.key}", "low"),
                    ("playlistItems.list", f"https://www.googleapis.com/youtube/v3/playlistItems?part=id&playlistId=PL590L5WQmH8fJ54F369BLDSqIwcs-TCfs&maxResults=1&key={ctx.key}", "low"),
                    ("activities.list", f"https://www.googleapis.com/youtube/v3/activities?part=id&channelId=UC_x5XG1OV2P6uZZ5FSM9Ttw&maxResults=1&key={ctx.key}", "low"),
                    ("subscriptions.list", f"https://www.googleapis.com/youtube/v3/subscriptions?part=id&channelId=UC_x5XG1OV2P6uZZ5FSM9Ttw&maxResults=1&key={ctx.key}", "low"),
                    ("channelSections.list", f"https://www.googleapis.com/youtube/v3/channelSections?part=id&channelId=UC_x5XG1OV2P6uZZ5FSM9Ttw&key={ctx.key}", "low"),
                ]
            )

        for method_name, url, cost_tier in endpoints:
            statuses: dict[str, int] = {}
            body_hints: dict[str, str] = {}
            tests = {"no_referrer": None, "fake_referrer": "https://evil-attacker-site.example", "blank_referrer": ""}
            for label, ref in tests.items():
                headers = {"Referer": ref} if ref is not None else None
                res = self.client.request("GET", url, headers=headers)
                statuses[label] = res.status
                data = res.json()
                if isinstance(data, dict):
                    error = _json_get(data, ["error", "message"], "")
                    body_hints[label] = str(error or data.get("kind") or "")[:180]
            classification, evidence, priority = classify_api_matrix(statuses, "YOUTUBE_DATA_API")
            if classification != "YOUTUBE_DATA_API_NOT_CONFIRMED":
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="youtube.googleapis.com",
                        method_name=method_name,
                        classification=classification,
                        endpoint=url.split("?", 1)[0],
                        http_status=statuses.get("fake_referrer") or statuses.get("no_referrer"),
                        project_id=ctx.project_id,
                        evidence_level=evidence,
                        suggested_priority=priority,
                        details={"referrer_matrix": statuses, "body_hints": body_hints, "cost_tier": cost_tier},
                    )
                )
        if ctx.profile == "aggressive-authorized":
            findings.extend(self.youtube_negative_controls(ctx))
            findings.extend(self.youtube_expensive_proof(ctx))
        return findings

    def youtube_negative_controls(self, ctx: ScanContext) -> list[Finding]:
        if ctx.youtube_write_negative_control == "off":
            return []
        if ctx.youtube_write_negative_control == "ask" and not self._confirm(ctx, "Run YouTube OAuth-only negative-control probes? [y/N] "):
            return []
        probes = [
            ("channels.list.managedByMe", f"https://www.googleapis.com/youtube/v3/channels?part=id&managedByMe=true&maxResults=1&key={ctx.key}"),
            ("videos.rate.writeNegativeControl", f"https://www.googleapis.com/youtube/v3/videos/rate?id=dQw4w9WgXcQ&rating=like&key={ctx.key}"),
        ]
        findings: list[Finding] = []
        for method_name, url in probes:
            method = "POST" if "rate" in method_name else "GET"
            res = self.client.request(method, url, headers={"Content-Type": "application/json"} if method == "POST" else None)
            if res.status in {200, 204}:
                classification = "YOUTUBE_OAUTH_ONLY_ENDPOINT_UNEXPECTED_SUCCESS_CRITICAL_REVIEW_REQUIRED"
                priority = "CRITICAL"
                evidence = "E5"
            else:
                classification = "YOUTUBE_OAUTH_ONLY_ENDPOINT_BLOCKED_EXPECTED"
                priority = "INFO"
                evidence = "E2"
            findings.append(
                Finding(
                    key=ctx.key,
                    service="youtube.googleapis.com",
                    method_name=method_name,
                    classification=classification,
                    endpoint=url.split("?", 1)[0],
                    http_status=res.status,
                    project_id=ctx.project_id,
                    evidence_level=evidence,
                    suggested_priority=priority,
                    proof_mode="negative_control_oauth_required",
                    details={"expected_status": "401_or_403", "note": "Success requires manual review before severity claim."},
                )
            )
        return findings

    def youtube_expensive_proof(self, ctx: ScanContext) -> list[Finding]:
        if ctx.youtube_expensive_proof == "off":
            return []
        if ctx.youtube_expensive_proof == "ask" and not self._confirm(ctx, "Run one YouTube search.list proof? This endpoint has a separate limited default allocation; run only when authorized. [y/N] "):
            return []
        url = f"https://www.googleapis.com/youtube/v3/search?part=id&q=aizascope_probe&type=video&maxResults=1&key={ctx.key}"
        if ctx.youtube_search_referrer_matrix:
            tests = {"no_referrer": None, "fake_referrer": "https://evil-attacker-site.example", "blank_referrer": ""}
        else:
            tests = {"fake_referrer": "https://evil-attacker-site.example"}
        statuses: dict[str, int] = {}
        for label, ref in tests.items():
            headers = {"Referer": ref} if ref is not None else None
            res = self.client.request("GET", url, headers=headers)
            statuses[label] = res.status
        classification, evidence, priority = classify_api_matrix(statuses, "YOUTUBE_SEARCH_API_EXPENSIVE")
        return [
            Finding(
                key=ctx.key,
                service="youtube.googleapis.com",
                method_name="search.list.expensiveProof",
                classification=classification,
                endpoint=url.split("?", 1)[0],
                http_status=statuses.get("fake_referrer") or statuses.get("no_referrer"),
                project_id=ctx.project_id,
                evidence_level=evidence,
                suggested_priority="HIGH" if "ARBITRARY" in classification else priority,
                proof_mode="explicit_expensive_quota_proof",
                details={"referrer_matrix": statuses, "documented_quota_note": "Current YouTube docs describe search.list as a separate default allocation, and every API request costs at least one quota point.", "requests_sent": len(statuses), "matrix_enabled": ctx.youtube_search_referrer_matrix},
            )
        ]

    def maps(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        probes = [
            ("geocoding.geocode", f"https://maps.googleapis.com/maps/api/geocode/json?address=New+Delhi&key={ctx.key}", "MAPS_GEOCODING_API", "maps.googleapis.com", "GET", None, None),
            ("staticmap.get", f"https://maps.googleapis.com/maps/api/staticmap?center=Delhi&zoom=10&size=1x1&key={ctx.key}", "MAPS_STATIC_API", "maps.googleapis.com", "GET", None, None),
            ("mapsjs.loader", f"https://maps.googleapis.com/maps/api/js?key={ctx.key}&callback=__aizascope_probe&v=weekly", "MAPS_JAVASCRIPT_API", "maps.googleapis.com", "GET", None, None),
        ]
        if ctx.profile in {"active", "aggressive-authorized"}:
            probes.extend([
                ("places.textsearch.legacy", f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=coffee+in+Delhi&key={ctx.key}", "PLACES_LEGACY_API", "maps.googleapis.com", "GET", None, None),
                ("places.searchText.new", "https://places.googleapis.com/v1/places:searchText", "PLACES_NEW_API", "places.googleapis.com", "POST", {"X-Goog-Api-Key": ctx.key, "X-Goog-FieldMask": "places.id,places.displayName"}, {"textQuery": "coffee in Delhi", "pageSize": 1}),
                ("directions.legacy", f"https://maps.googleapis.com/maps/api/directions/json?origin=Delhi&destination=Mumbai&key={ctx.key}", "MAPS_DIRECTIONS_API", "maps.googleapis.com", "GET", None, None),
                ("distancematrix.legacy", f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=Delhi&destinations=Mumbai&key={ctx.key}", "MAPS_DISTANCE_MATRIX_API", "maps.googleapis.com", "GET", None, None),
                ("timezone.get", f"https://maps.googleapis.com/maps/api/timezone/json?location=28.6139,77.2090&timestamp=0&key={ctx.key}", "MAPS_TIMEZONE_API", "maps.googleapis.com", "GET", None, None),
                ("geolocation.geolocate", f"https://www.googleapis.com/geolocation/v1/geolocate?key={ctx.key}", "MAPS_GEOLOCATION_API", "geolocation.googleapis.com", "POST", None, {"considerIp": True}),
            ])

        for method_name, url, label, service, method, extra_headers, payload in probes:
            statuses: dict[str, int] = {}
            api_statuses: dict[str, str] = {}
            allowed_labels: list[str] = []
            denied_labels: list[str] = []
            tests = {"no_referrer": None, "fake_referrer": "https://evil-attacker-site.example", "blank_referrer": ""}
            for test_label, ref in tests.items():
                headers = dict(extra_headers or {})
                if ref is not None:
                    headers["Referer"] = ref
                res = self.client.request(method, url, headers=headers or None, json_body=payload if method == "POST" else None)
                statuses[test_label] = res.status
                data = res.json()
                status_hint = ""
                if isinstance(data, dict):
                    status_hint = str(data.get("status") or data.get("error_message") or _json_get(data, ["error", "message"], "") or ("places" if "places" in data else "") or ("location" if "location" in data else ""))[:180]
                api_statuses[test_label] = status_hint
                if _maps_body_allows(method_name, res.status, res.headers, data, res.body_text):
                    allowed_labels.append(test_label)
                elif _maps_body_denied(data, res.body_text):
                    denied_labels.append(test_label)

            classification, evidence, priority = classify_api_matrix(statuses, label)
            if allowed_labels:
                classification = f"{label}_ALLOWED_FROM_ARBITRARY_CLIENT" if "fake_referrer" in allowed_labels else f"{label}_ALLOWED"
                evidence = "E4"
                priority = "MEDIUM"
            elif denied_labels:
                classification = f"{label}_REQUEST_DENIED_OR_RESTRICTED"
                evidence = "E2"
                priority = "INFO"
            if classification != f"{label}_NOT_CONFIRMED":
                findings.append(
                    Finding(
                        key=ctx.key,
                        service=service,
                        method_name=method_name,
                        classification=classification,
                        endpoint=url.split("?", 1)[0],
                        http_status=statuses.get("fake_referrer") or statuses.get("no_referrer"),
                        project_id=ctx.project_id,
                        evidence_level=evidence,
                        suggested_priority=priority,
                        details={"referrer_matrix": statuses, "api_statuses": api_statuses, "allowed_referrer_tests": allowed_labels, "denied_referrer_tests": denied_labels},
                    )
                )
        return findings

    def cloud_ai(self, ctx: ScanContext) -> list[Finding]:
        if ctx.profile not in {"active", "aggressive-authorized"}:
            return []
        findings: list[Finding] = []
        one_px_png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
        probes = [
            ("vision.images.annotate", ctx.vision_proof, "Run one Cloud Vision images.annotate proof? This can consume Cloud Vision quota. [y/N] ", "POST", f"https://vision.googleapis.com/v1/images:annotate?key={ctx.key}", "vision.googleapis.com", "VISION_IMAGES_ANNOTATE_CONFIRMED", "VISION_IMAGES_ANNOTATE_BLOCKED_OR_LIMITED", {"requests":[{"image":{"content":one_px_png},"features":[{"type":"LABEL_DETECTION","maxResults":1}]}]}),
            ("translation.detect", ctx.translation_proof, "Run one Cloud Translation detect proof? This can consume Translation API quota. [y/N] ", "POST", f"https://translation.googleapis.com/language/translate/v2/detect?key={ctx.key}", "translation.googleapis.com", "TRANSLATION_DETECT_CONFIRMED", "TRANSLATION_DETECT_BLOCKED_OR_LIMITED", {"q":"AizaScope authorized proof."}),
            ("documents.analyzeSentiment", ctx.natural_language_proof, "Run one Cloud Natural Language analyzeSentiment proof? This can consume Natural Language API quota. [y/N] ", "POST", f"https://language.googleapis.com/v1/documents:analyzeSentiment?key={ctx.key}", "language.googleapis.com", "NATURAL_LANGUAGE_SENTIMENT_CONFIRMED", "NATURAL_LANGUAGE_SENTIMENT_BLOCKED_OR_LIMITED", {"document":{"type":"PLAIN_TEXT","content":"AizaScope authorized proof."},"encodingType":"UTF8"}),
        ]
        for method_name, mode, prompt, method, url, service, success_class, fail_class, payload in probes:
            if mode == "off":
                continue
            if not (mode == "auto" or self._confirm(ctx, prompt)):
                continue
            statuses: dict[str, int] = {}
            body_hints: dict[str, str] = {}
            for label, ref in {"no_referrer": None, "fake_referrer": "https://evil-attacker-site.example", "blank_referrer": ""}.items():
                headers = {"Referer": ref} if ref is not None else None
                res = self.client.request(method, url, headers=headers, json_body=payload)
                statuses[label] = res.status
                data = res.json()
                if isinstance(data, dict):
                    body_hints[label] = str(_json_get(data, ["error", "message"], "") or list(data.keys())[:5])[:180]
            if any(code == 200 for code in statuses.values()):
                classification = success_class + ("_FROM_ARBITRARY_CLIENT" if statuses.get("fake_referrer") == 200 else "")
                evidence, priority = "E5", ("HIGH" if statuses.get("fake_referrer") == 200 else "MEDIUM")
            elif any(code == 429 for code in statuses.values()):
                classification, evidence, priority = fail_class, "E2", "REVIEW"
            else:
                classification, evidence, priority = fail_class, "E2", "INFO"
            findings.append(Finding(key=ctx.key, service=service, method_name=method_name, classification=classification, endpoint=url.split("?",1)[0], http_status=statuses.get("fake_referrer") or statuses.get("no_referrer"), project_id=ctx.project_id, evidence_level=evidence, suggested_priority=priority, proof_mode="explicit_active_cloud_ai_probe", details={"referrer_matrix":statuses,"body_hints":body_hints,"billable_api_probe":True}))
        return findings

    def safe_browsing(self, ctx: ScanContext) -> list[Finding]:
        if ctx.profile not in {"active", "aggressive-authorized"}:
            return []
        if ctx.safe_browsing_proof == "off":
            return []
        if ctx.safe_browsing_proof == "ask" and not self._confirm(ctx, "Run one Google Safe Browsing threatMatches.find proof? [y/N] "):
            return []
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={ctx.key}"
        payload = {
            "client": {"clientId": "aizascope", "clientVersion": VERSION},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": "http://example.com/"}],
            },
        }
        statuses: dict[str, int] = {}
        body_hints: dict[str, str] = {}
        for label, ref in {"no_referrer": None, "fake_referrer": "https://evil-attacker-site.example", "blank_referrer": ""}.items():
            headers = {"Referer": ref} if ref is not None else None
            res = self.client.request("POST", url, headers=headers, json_body=payload)
            statuses[label] = res.status
            data = res.json()
            if isinstance(data, dict):
                body_hints[label] = str(_json_get(data, ["error", "message"], "") or list(data.keys())[:5])[:180]
        if any(code == 200 for code in statuses.values()):
            classification = "SAFE_BROWSING_API_CALLABLE" + ("_FROM_ARBITRARY_CLIENT" if statuses.get("fake_referrer") == 200 else "")
            evidence = "E3"
            priority = "LOW"
        elif any(code == 429 for code in statuses.values()):
            classification, evidence, priority = "SAFE_BROWSING_API_QUOTA_LIMITED_OR_ENABLED", "E2", "REVIEW"
        else:
            classification, evidence, priority = "SAFE_BROWSING_API_BLOCKED_OR_DISABLED", "E2", "INFO"
        return [Finding(key=ctx.key, service="safebrowsing.googleapis.com", method_name="threatMatches.find", classification=classification, endpoint=url.split("?",1)[0], http_status=statuses.get("fake_referrer") or statuses.get("no_referrer"), project_id=ctx.project_id, evidence_level=evidence, suggested_priority=priority, proof_mode="single_safe_browsing_lookup", details={"referrer_matrix": statuses, "body_hints": body_hints, "checked_url": "http://example.com/"})]

    def maybe_anonymous_auth(self, ctx: ScanContext) -> list[Finding]:
        if ctx.auth_mode == "off":
            return []
        if ctx.auth_mode == "ask" and not self._confirm(ctx, f"Create temporary anonymous Firebase Auth user for project {ctx.project_id}? [y/N] "):
            return []

        findings: list[Finding] = []
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={ctx.key}"
        res = self.client.request("POST", url, json_body={"returnSecureToken": True})
        data = res.json()
        if res.status == 200 and isinstance(data, dict) and data.get("idToken"):
            ctx.id_token = str(data["idToken"])
            ctx.local_id = str(data.get("localId") or "")
            findings.append(
                Finding(
                    key=ctx.key,
                    service="identitytoolkit.googleapis.com",
                    method_name="accounts.signUp.anonymous",
                    classification="ANONYMOUS_AUTH_ENABLED",
                    endpoint="identitytoolkit/v1/accounts:signUp",
                    http_status=res.status,
                    project_id=ctx.project_id,
                    evidence_level="E3",
                    suggested_priority="INFO",
                    details={"local_id": ctx.local_id, "standalone_vulnerability": False},
                )
            )
            findings.extend(self.firestore(ctx, token=ctx.id_token, auth_label="anon_auth"))
            findings.extend(self.firestore_collection_ids(ctx, token=ctx.id_token, auth_label="anon_auth"))
            findings.extend(self.rtdb(ctx, token=ctx.id_token, auth_label="anon_auth"))
            findings.extend(self.storage(ctx, token=ctx.id_token, auth_label="anon_auth"))
        elif res.status in {400, 401, 403}:
            findings.append(
                Finding(
                    key=ctx.key,
                    service="identitytoolkit.googleapis.com",
                    method_name="accounts.signUp.anonymous",
                    classification="ANONYMOUS_AUTH_NOT_ENABLED_OR_BLOCKED",
                    endpoint="identitytoolkit/v1/accounts:signUp",
                    http_status=res.status,
                    project_id=ctx.project_id,
                    evidence_level="E1",
                    suggested_priority="INFO",
                )
            )
        return findings

    def cleanup_anonymous_auth(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.id_token:
            return []
        delete_url = f"https://identitytoolkit.googleapis.com/v1/accounts:delete?key={ctx.key}"
        delete_res = self.client.request("POST", delete_url, json_body={"idToken": ctx.id_token})
        finding = Finding(
            key=ctx.key,
            service="identitytoolkit.googleapis.com",
            method_name="accounts.delete.anonymous",
            classification="ANONYMOUS_AUTH_CLEANUP_ATTEMPTED",
            endpoint="identitytoolkit/v1/accounts:delete",
            http_status=delete_res.status,
            project_id=ctx.project_id,
            evidence_level="E1",
            suggested_priority="INFO",
            details={"cleanup_success": delete_res.status == 200},
        )
        ctx.id_token = None
        return [finding]

    def maybe_write_proofs(self, ctx: ScanContext) -> list[Finding]:
        if ctx.write_proof == "off":
            return []
        findings: list[Finding] = []
        firestore_modes = list(ctx.confirmed_firestore_read_modes.keys()) or (["anon_auth"] if ctx.id_token and ctx.confirmed_firestore_reads else (["unauth"] if ctx.confirmed_firestore_reads else []))
        rtdb_modes = list(ctx.confirmed_rtdb_read_modes.keys()) or (["anon_auth"] if ctx.id_token and ctx.confirmed_rtdb_reads else (["unauth"] if ctx.confirmed_rtdb_reads else []))
        storage_modes = list(ctx.confirmed_storage_list_modes.keys()) or (["anon_auth"] if ctx.id_token and ctx.confirmed_storage_lists else (["unauth"] if ctx.confirmed_storage_lists else []))

        if firestore_modes and (ctx.write_proof == "auto" or self._confirm(ctx, f"Firestore read/list was confirmed for {ctx.project_id}. Try marker write/delete proof using matching auth modes? [y/N] ")):
            for auth_label in firestore_modes:
                findings.extend(self.firestore_write_proof(ctx, auth_label))
        if rtdb_modes and (ctx.write_proof == "auto" or self._confirm(ctx, f"RTDB read was confirmed for {ctx.project_id}. Try marker write/delete proof using matching auth modes? [y/N] ")):
            for auth_label in rtdb_modes:
                findings.extend(self.rtdb_write_proof(ctx, auth_label))
        if storage_modes and (ctx.write_proof == "auto" or self._confirm(ctx, f"Storage list was confirmed for {ctx.project_id}. Try marker upload/delete proof using matching auth modes? [y/N] ")):
            for auth_label in storage_modes:
                findings.extend(self.storage_write_proof(ctx, auth_label))
        return findings

    def _headers_for_auth_label(self, ctx: ScanContext, auth_label: str) -> dict[str, str] | None:
        if auth_label != "unauth" and ctx.id_token:
            return {"Authorization": f"Bearer {ctx.id_token}"}
        return None

    def firestore_write_proof(self, ctx: ScanContext, auth_label: str = "unauth") -> list[Finding]:
        nonce = secrets.token_hex(8)
        collection = "aizascope_bbp_probe"
        url = f"https://firestore.googleapis.com/v1/projects/{ctx.project_id}/databases/(default)/documents/{collection}?documentId={nonce}&key={ctx.key}"
        payload = {
            "fields": {
                "tool": {"stringValue": "AizaScope"},
                "purpose": {"stringValue": "authorized-bug-bounty-marker"},
                "delete_me": {"booleanValue": True},
            }
        }
        headers = self._headers_for_auth_label(ctx, auth_label)
        res = self.client.request("POST", url, headers=headers, json_body=payload)
        findings: list[Finding] = []
        if res.status == 200:
            doc_name = None
            data = res.json()
            if isinstance(data, dict):
                doc_name = data.get("name")
            delete_success = False
            if doc_name:
                del_url = f"https://firestore.googleapis.com/v1/{doc_name}?key={ctx.key}"
                del_res = self.client.request("DELETE", del_url, headers=headers)
                delete_success = del_res.status == 200
            findings.append(
                Finding(
                    key=ctx.key,
                    service="firestore.googleapis.com",
                    method_name=f"documents.create.writeProof.{auth_label}",
                    classification="FIRESTORE_UNAUTH_WRITE_PROOF_CONFIRMED" if auth_label == "unauth" else "FIRESTORE_AUTH_WRITE_PROOF_CONFIRMED",
                    endpoint="firestore documents.create",
                    http_status=res.status,
                    project_id=ctx.project_id,
                    target=f"/{collection}/{nonce}",
                    evidence_level="E5",
                    suggested_priority="HIGH",
                    proof_mode="interactive_marker_write_delete",
                    details={"auth_label": auth_label, "delete_attempted": bool(doc_name), "delete_success": delete_success, "used_anonymous_auth_token": bool(headers)},
                )
            )
        return findings

    def rtdb_write_proof(self, ctx: ScanContext, auth_label: str = "unauth") -> list[Finding]:
        findings: list[Finding] = []
        nonce = secrets.token_hex(8)
        payload = {"tool": "AizaScope", "purpose": "authorized-bug-bounty-marker", "delete_me": True}
        bases = ctx.confirmed_rtdb_read_modes.get(auth_label) or ctx.confirmed_rtdb_reads
        for base in list(dict.fromkeys(bases)):
            url = f"{base}/aizascope_bbp_probe/{nonce}.json"
            request_url = url + (f"?auth={quote(ctx.id_token)}" if auth_label != "unauth" and ctx.id_token else "")
            res = self.client.request("PUT", request_url, json_body=payload)
            if res.status == 200:
                del_res = self.client.request("DELETE", request_url)
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="firebaseio.com",
                        method_name=f"rtdb.writeProof.{auth_label}",
                        classification="RTDB_UNAUTH_WRITE_PROOF_CONFIRMED" if auth_label == "unauth" else "RTDB_AUTH_WRITE_PROOF_CONFIRMED",
                        endpoint="/{db}/aizascope_bbp_probe/{nonce}.json",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        target=f"{base}/aizascope_bbp_probe/{nonce}",
                        evidence_level="E5",
                        suggested_priority="HIGH",
                        proof_mode="interactive_marker_write_delete",
                        details={"auth_label": auth_label, "delete_success": del_res.status == 200, "used_anonymous_auth_token": auth_label != "unauth" and bool(ctx.id_token)},
                    )
                )
                break
        return findings

    def storage_write_proof(self, ctx: ScanContext, auth_label: str = "unauth") -> list[Finding]:
        findings: list[Finding] = []
        nonce = secrets.token_hex(8)
        raw_body = b"AizaScope authorized bug bounty marker. Delete me.\n"
        buckets = ctx.confirmed_storage_list_modes.get(auth_label) or ctx.confirmed_storage_lists
        for bucket in list(dict.fromkeys(buckets)):
            object_name = f"aizascope_bbp_probe/{nonce}.txt"
            upload_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?uploadType=media&name={quote(object_name)}"
            headers = {"Content-Type": "text/plain"}
            if auth_label != "unauth" and ctx.id_token:
                headers["Authorization"] = f"Bearer {ctx.id_token}"
            res = self.client.request("POST", upload_url, headers=headers, raw_body=raw_body)
            if res.status == 200:
                del_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{quote_path(object_name)}"
                del_headers = {"Authorization": f"Bearer {ctx.id_token}"} if auth_label != "unauth" and ctx.id_token else None
                del_res = self.client.request("DELETE", del_url, headers=del_headers)
                findings.append(
                    Finding(
                        key=ctx.key,
                        service="firebasestorage.googleapis.com",
                        method_name=f"storage.upload.writeProof.{auth_label}",
                        classification="STORAGE_UNAUTH_WRITE_PROOF_CONFIRMED" if auth_label == "unauth" else "STORAGE_AUTH_WRITE_PROOF_CONFIRMED",
                        endpoint="firebasestorage uploadType=media",
                        http_status=res.status,
                        project_id=ctx.project_id,
                        target=f"gs://{bucket}/{object_name}",
                        evidence_level="E5",
                        suggested_priority="HIGH",
                        proof_mode="interactive_marker_write_delete",
                        details={"auth_label": auth_label, "delete_success": del_res.status == 200, "used_anonymous_auth_token": auth_label != "unauth" and bool(ctx.id_token)},
                    )
                )
                break
        return findings

    def _prompt_category(self, prompt: str) -> str:
        lowered = prompt.lower()
        if "counttokens" in lowered:
            return "gemini.countTokens"
        if "generatecontent" in lowered:
            return "gemini.generateContent"
        if "embedcontent" in lowered:
            return "gemini.embedContent"
        if "cloud vision" in lowered:
            return "cloudai.vision"
        if "cloud translation" in lowered:
            return "cloudai.translation"
        if "natural language" in lowered:
            return "cloudai.naturalLanguage"
        if "youtube search.list" in lowered:
            return "youtube.searchList"
        if "youtube oauth-only" in lowered:
            return "youtube.oauthNegativeControls"
        if "anonymous firebase auth" in lowered:
            return "firebase.anonymousAuth"
        if "firestore read/list" in lowered:
            return "writeProof.firestore"
        if "rtdb read" in lowered:
            return "writeProof.rtdb"
        if "storage list" in lowered:
            return "writeProof.storage"
        return "generic." + lowered[:80]

    def _confirm(self, ctx: ScanContext, prompt: str) -> bool:
        if ctx.non_interactive or ctx.prompt_policy == "never":
            return False
        category = self._prompt_category(prompt)
        if ctx.prompt_policy == "once" and category in ctx.prompt_decisions:
            return ctx.prompt_decisions[category]
        try:
            answer = input(prompt).strip().lower() in {"y", "yes"}
        except EOFError:
            answer = False
        if ctx.prompt_policy == "once":
            ctx.prompt_decisions[category] = answer
        return answer
