"""Trusted HTTP subprocess, supervised by bounded_provider. No candidate execution."""
from __future__ import annotations

import base64
import http.client
import json
import resource
import ssl
import sys
from urllib.parse import urlsplit

from .provider import InferenceRequest, MAX_RESPONSE_BYTES, NebiusProvider, ProviderError, classify_http_status


def get_json(url, key, timeout):
    parts = urlsplit(url)
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout,
                                       context=ssl.create_default_context())
    try:
        headers = {"Accept": "application/json"}
        if key is not None:
            headers["Authorization"] = "Bearer " + key
        conn.request("GET", parts.path, headers=headers)
        response = conn.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ProviderError("oversized_response", submission="uncertain")
        if response.status != 200:
            category, submission = classify_http_status(response.status)
            raise ProviderError(category, submission=submission, status=response.status)
        return body
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("connection_error", submission="not_submitted") from None
    finally:
        conn.close()


def main():
    # File-backed stdout cannot fill disk or block the supervisor on a full pipe.
    resource.setrlimit(resource.RLIMIT_FSIZE, (24 * 1024 * 1024, 24 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    events = []
    error = None

    def sink(kind, data):
        events.append((kind, base64.b64encode(data).decode("ascii")))

    try:
        data = json.loads(sys.stdin.buffer.read(2 * 1024 * 1024 + 1))
        if data["operation"] == "complete":
            provider = NebiusProvider(data["key"], allow_live=True, evidence_sink=sink)
            provider.complete(InferenceRequest.model_validate(data["request"]), timeout=data["timeout"])
        elif data["operation"] == "catalogue":
            sink("account_models", get_json("https://api.tokenfactory.nebius.com/v1/models", data["key"], data["timeout"]))
            sink("public_catalogue", get_json("https://tokenfactory.nebius.com/api/public/models_info", None, data["timeout"]))
        else:
            raise ValueError("invalid_operation")
    except ProviderError as exc:
        error = {name: getattr(exc, name) for name in (
            "category", "submission", "status", "retry_after_status", "retry_after_seconds",
            "provider_type", "provider_code", "body_sha256", "body_bytes")}
    except Exception:
        error = {"category": "connection_error", "submission": "uncertain"}
    sys.stdout.write(json.dumps({"events": events, "error": error}, ensure_ascii=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
