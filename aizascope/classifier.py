from __future__ import annotations

from .models import Finding

SENSITIVE_COLLECTION_HINTS = {
    "users", "user", "profiles", "profile", "customers", "customer", "clients", "members",
    "accounts", "admins", "admin", "employees", "staff", "orders", "order", "payments",
    "payment", "invoices", "subscriptions", "transactions", "wallets", "cards", "addresses",
    "sessions", "tokens", "secrets", "private", "messages", "chats", "bookings", "leads",
}


def classify_firestore_collection(collection: str, has_docs: bool) -> tuple[str, str, str]:
    lowered = collection.lower()
    if has_docs and lowered in SENSITIVE_COLLECTION_HINTS:
        return "FIRESTORE_UNAUTH_LIST_CONFIRMED", "E4", "HIGH"
    if has_docs:
        return "FIRESTORE_UNAUTH_LIST_CONFIRMED", "E4", "MEDIUM"
    return "FIRESTORE_LIST_ALLOWED_EMPTY", "E3", "LOW"


def classify_api_matrix(statuses: dict[str, int], service_label: str) -> tuple[str, str, str]:
    success_codes = {200, 204}
    no_ref = statuses.get("no_referrer") in success_codes
    fake_ref = statuses.get("fake_referrer") in success_codes
    blank_ref = statuses.get("blank_referrer") in success_codes

    if no_ref and fake_ref and blank_ref:
        return f"{service_label}_ALLOWED_FROM_ARBITRARY_CLIENT", "E4", "MEDIUM"
    if no_ref or fake_ref or blank_ref:
        return f"{service_label}_PARTIALLY_ALLOWED_FROM_NON_STANDARD_CLIENT", "E3", "LOW"
    if any(code == 429 for code in statuses.values()):
        return f"{service_label}_QUOTA_OR_RATE_LIMITED", "E2", "REVIEW"
    if any(code in {401, 403} for code in statuses.values()):
        return f"{service_label}_RESTRICTED_OR_BLOCKED", "E2", "INFO"
    return f"{service_label}_NOT_CONFIRMED", "E1", "INFO"



def advisory_for_classification(c: str) -> dict[str, object]:
    if "WRITE_PROOF_CONFIRMED" in c:
        return {"attack_class":"Unauthenticated or weakly authenticated write access confirmed","owasp_api_2023":"API5:2023 Broken Function Level Authorization","cwe":["CWE-862 Missing Authorization","CWE-863 Incorrect Authorization"],"cvss_vector_hint":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L","business_impact":"An attacker can write marker data to a backend resource, proving missing write authorization controls on at least one path.","remediation":"Deny unauthenticated writes and enforce owner/role checks in Firebase Security Rules. Review inherited wildcard rules."}
    if c.startswith("FIRESTORE_UNAUTH_LIST_CONFIRMED") or c.startswith("FIRESTORE_AUTH_LIST_CONFIRMED"):
        return {
            "attack_class": "Improper authorization on Firestore data access",
            "owasp_api_2023": "API3:2023 Broken Object Property Level Authorization / API5:2023 Broken Function Level Authorization",
            "cwe": ["CWE-284 Improper Access Control", "CWE-862 Missing Authorization"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "business_impact": "An attacker can enumerate Firestore document names and may access application data depending on rules and data sensitivity.",
            "remediation": "Tighten Firestore Security Rules so only authenticated and authorized principals can list/read sensitive collections. Review rule conditions for list vs get separately.",
        }
    if c.startswith("FIRESTORE_COLLECTION_IDS_EXPOSED"):
        return {
            "attack_class": "Root collection discovery through Firestore listCollectionIds",
            "owasp_api_2023": "API3:2023 Broken Object Property Level Authorization / API5:2023 Broken Function Level Authorization",
            "cwe": ["CWE-200 Exposure of Sensitive Information", "CWE-284 Improper Access Control"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "business_impact": "Attackers can enumerate root collection names, improving data-discovery and follow-on read/write testing.",
            "remediation": "Deny listCollectionIds to unauthenticated or unauthorized users through Firestore Security Rules and least-privilege rule structure.",
        }
    if c.startswith("RTDB_UNAUTH_SHALLOW_READ_CONFIRMED") or c.startswith("RTDB_AUTH_SHALLOW_READ_CONFIRMED"):
        return {
            "attack_class": "Improper authorization on Realtime Database read access",
            "owasp_api_2023": "API5:2023 Broken Function Level Authorization",
            "cwe": ["CWE-284 Improper Access Control"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "business_impact": "Attackers can enumerate top-level Realtime Database keys, exposing application structure and possible sensitive data paths.",
            "remediation": "Update Realtime Database Security Rules to require authenticated and authorized reads/writes and validate path ownership.",
        }
    if c.startswith("STORAGE_LIST_CONFIRMED") or c.startswith("STORAGE_AUTH_LIST_CONFIRMED") or c.startswith("STORAGE_PREFIX_LIST_CONFIRMED") or c.startswith("STORAGE_AUTH_PREFIX_LIST_CONFIRMED"):
        return {
            "attack_class": "Improper authorization on Firebase Storage object listing",
            "owasp_api_2023": "API3:2023 Broken Object Property Level Authorization",
            "cwe": ["CWE-200 Exposure of Sensitive Information", "CWE-284 Improper Access Control"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "business_impact": "Attackers can list Storage object names/prefixes, potentially exposing private filenames, user IDs, document paths, or upload structure.",
            "remediation": "Use Firebase Storage Rules v2 and restrict list/get to authorized users and expected object paths. Split public and private buckets/paths.",
        }
    if "CRITICAL_REVIEW_REQUIRED" in c:
        return {
            "attack_class": "Unexpected success on endpoint that normally requires OAuth/content-owner authorization",
            "owasp_api_2023": "API5:2023 Broken Function Level Authorization",
            "cwe": ["CWE-862 Missing Authorization", "CWE-863 Incorrect Authorization"],
            "cvss_vector_hint": "Manual scoring required",
            "business_impact": "The endpoint returned success where API-key-only access should normally fail. Manual validation is required before claiming sensitive access.",
            "remediation": "Verify OAuth/API-key restrictions, disable unintended APIs, rotate exposed keys, and review YouTube/Google Cloud project access.",
        }

    if any(token in c for token in ["VISION_", "TRANSLATION_", "NATURAL_LANGUAGE_"]):
        return {"attack_class":"Google Cloud AI API key service drift / unrestricted billable API access","owasp_api_2023":"API4:2023 Unrestricted Resource Consumption","cwe":["CWE-770 Allocation of Resources Without Limits or Throttling","CWE-400 Uncontrolled Resource Consumption"],"cvss_vector_hint":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L","business_impact":"A public client key may be usable against billable Google Cloud AI APIs, creating quota and billing exposure depending on project configuration and API restrictions.","remediation":"Restrict the API key to only required APIs and expected applications/origins. Move server-side AI calls behind backend services and rotate exposed keys when needed."}
    if "GEMINI" in c:
        return {
            "attack_class": "Google API key service drift / unrestricted Generative Language API access",
            "owasp_api_2023": "API4:2023 Unrestricted Resource Consumption",
            "cwe": ["CWE-770 Allocation of Resources Without Limits or Throttling"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "business_impact": "A public client key may be usable against Gemini APIs, creating quota, billing, and resource metadata exposure risk depending on enabled methods.",
            "remediation": "Remove Generative Language API from public client keys, use separate server-side keys, enforce API restrictions, and restrict application origins/IPs.",
        }
    if "SAFE_BROWSING" in c:
        return {
            "attack_class": "Google API key service drift / Safe Browsing API callable",
            "owasp_api_2023": "API4:2023 Unrestricted Resource Consumption",
            "cwe": ["CWE-770 Allocation of Resources Without Limits or Throttling"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "business_impact": "A public client key may be callable against Safe Browsing lookup endpoints. This is quota/API-restriction exposure, not private data exposure.",
            "remediation": "Restrict the API key by application and API, and separate public browser keys from backend service keys.",
        }
    if "YOUTUBE" in c:
        return {
            "attack_class": "Unrestricted Google API key usable against YouTube Data API",
            "owasp_api_2023": "API4:2023 Unrestricted Resource Consumption",
            "cwe": ["CWE-770 Allocation of Resources Without Limits or Throttling"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "business_impact": "Attackers may reuse the public key from arbitrary origins to consume YouTube Data API quota and query public YouTube data under the victim project configuration. This is not private YouTube data access unless OAuth-only endpoints unexpectedly succeed.",
            "remediation": "Restrict the API key by application origin and limit the key to only required YouTube APIs. Rotate if exposure is widespread.",
        }
    if "MAPS" in c or "PLACES" in c:
        return {
            "attack_class": "Unrestricted Google Maps Platform API key",
            "owasp_api_2023": "API4:2023 Unrestricted Resource Consumption",
            "cwe": ["CWE-770 Allocation of Resources Without Limits or Throttling"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "business_impact": "Attackers may reuse the public key from arbitrary origins to consume billable Maps Platform APIs.",
            "remediation": "Apply HTTP referrer, IP, Android, or iOS application restrictions and API restrictions in Google Cloud Console.",
        }
    if "WRITE_PROOF_CONFIRMED" in c:
        return {
            "attack_class": "Unauthenticated or weakly authenticated write access confirmed",
            "owasp_api_2023": "API5:2023 Broken Function Level Authorization",
            "cwe": ["CWE-862 Missing Authorization", "CWE-863 Incorrect Authorization"],
            "cvss_vector_hint": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "business_impact": "An attacker can write marker data to a backend resource, proving missing write authorization controls on at least one path.",
            "remediation": "Deny unauthenticated writes and enforce owner/role checks in Firebase Security Rules. Review inherited wildcard rules.",
        }
    return {
        "attack_class": "Informational or inconclusive API key behavior",
        "owasp_api_2023": "Review manually",
        "cwe": [],
        "cvss_vector_hint": "Not scored",
        "business_impact": "No direct security impact confirmed from this finding alone.",
        "remediation": "Review API restrictions and Firebase rules for least privilege.",
    }


def advisory_for_finding(finding: Finding) -> dict[str, object]:
    return advisory_for_classification(finding.classification)
