from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .models import HttpResult


class HttpClient:
    def __init__(self, timeout: int = 12, user_agent: str = "AizaScope/0.5.0") -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.ssl_context = ssl.create_default_context()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
    ) -> HttpResult:
        method = method.upper()
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json,text/plain,*/*",
        }
        if headers:
            request_headers.update(headers)

        body: bytes | None = None
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        elif raw_body is not None:
            body = raw_body

        start = time.perf_counter()
        req = urllib.request.Request(url, data=body, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                body_bytes = resp.read(256_000)
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                return HttpResult(
                    method=method,
                    url=url,
                    status=resp.status,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body_text=body_bytes.decode("utf-8", errors="replace"),
                    elapsed_ms=elapsed_ms,
                )
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read(128_000)
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return HttpResult(
                method=method,
                url=url,
                status=exc.code,
                headers={k.lower(): v for k, v in exc.headers.items()},
                body_text=body_bytes.decode("utf-8", errors="replace"),
                elapsed_ms=elapsed_ms,
                error=str(exc),
            )
        except Exception as exc:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return HttpResult(
                method=method,
                url=url,
                status=0,
                headers={},
                body_text="",
                elapsed_ms=elapsed_ms,
                error=f"{type(exc).__name__}: {exc}",
            )


def add_query(url: str, **params: str | int | None) -> str:
    parsed = urllib.parse.urlsplit(url)
    existing = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in params.items():
        if value is not None:
            existing[key] = str(value)
    query = urllib.parse.urlencode(existing)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def quote_path(value: str) -> str:
    return urllib.parse.quote(value, safe="")
