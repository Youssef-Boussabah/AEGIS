"""Typed inference-provider interface and a Nebius Token Factory transport.

This module has one responsibility: turn a bounded ``InferenceRequest`` into a
strictly parsed ``InferenceResponse`` or a typed ``ProviderError``. It does not
build prompts, read evidence, decide retries, account budgets across attempts or
decide whether a disclosure is authorized; ``aegis_lab.reconstruction`` does.

Endpoint identity. ``canonical_endpoint`` reduces a base URL to
``https://<host>:<port><base path>``: lowercase host name (LDH labels only, no IP
literals), explicit effective port, and a normalized path without ``.``/``..``,
empty segments or percent escapes. URLs with userinfo, a query, a fragment, a
non-HTTPS scheme or any non-ASCII/whitespace character are rejected with a fixed
code. ``EndpointError`` never repeats the URL, so credentials embedded in a
rejected URL cannot reach a log.

Submission state. Every ``ProviderError`` says how far the request got:

- ``not_submitted``: the failure happened before any request byte was handed to
  the socket (DNS, TCP or TLS setup, or no time left). Nothing can have been
  processed or billed.
- ``rejected``: the provider answered with an HTTP 3xx/4xx status, or 503/529.
  This records that an explicit error response arrived; it is *not* evidence
  that the request was not processed or billed.
- ``uncertain``: bytes may have reached the provider but no usable answer came
  back (send/read failure, timeout after sending, other 5xx, unexpected 1xx/2xx).
- ``completed``: an HTTP 200 body arrived but it is invalid or oversized.

``ProviderError.retryable`` is true only for ``not_submitted`` failures (nothing
can have reached the provider). No HTTP status, including 429, 503 and 529, makes
a request retryable: the provider documents neither that such responses mean the
request was not processed nor an idempotency mechanism, so a POST that may have
been accepted is never sent again automatically.

Deadline: logical checks, not a hard wall-clock bound. ``complete(request,
timeout=...)`` derives a logical deadline from ``timeout``. It checks that
deadline before connecting, before sending, before waiting for the status line
and between body chunks, and it sets each socket timeout to no more than the
time left. A socket timeout is an *inactivity* timeout for one blocking
operation, not a cap on total time: a server that keeps trickling bytes, the
buffered reads inside ``http.client`` and name resolution inside ``connect`` can
all run past the deadline before control returns. The call then reports
``deadline_exceeded`` (or ``timeout``) *after* the fact. Guaranteed wall-clock
interruption is **not** established by this HTTP implementation alone. Operational
live inference uses ``aegis_lab.bounded_provider.BoundedNebiusProvider`` to run it
under a separate process-group wall deadline.

Response validation (``parse_completion``): strict UTF-8 JSON without duplicate
keys or non-finite numbers; exactly one choice; a string (or explicitly absent)
assistant content with no NUL and no lone surrogate; strictly typed, non-negative
usage integers with ``total = prompt + completion``; and explicit classification
of refusals, tool calls, unsupported message fields and unknown finish reasons.
Nothing is coerced: absent usage stays absent, invalid usage is marked invalid.

Credentials come from ``NEBIUS_API_KEY`` at runtime, live only in a private slot,
and are never placed in a record, log line, ``repr`` or exception.
"""

from __future__ import annotations

import email.utils
import hashlib
import http.client
import json
import math
import re
import socket
import ssl
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

from .safe_io import LoadError, parse_strict_json

NEBIUS_BASE_URL = "https://api.tokenfactory.nebius.com/v1"
NEBIUS_API_KEY_ENV = "NEBIUS_API_KEY"
# Operator convenience only. The pipeline always takes the model id from the trial
# manifest. Confirm ids against the live catalogue before any run; they change.
DEFAULT_NEBIUS_MODEL = "nvidia/nemotron-3-super-120b-a12b"

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_URL_CHARS = 2048
DEFAULT_CONNECT_TIMEOUT = 15.0
DEFAULT_READ_TIMEOUT = 120.0
_READ_CHUNK = 65536

PROVIDER_ERROR_CATEGORIES = frozenset({
    "timeout",               # a connect/send/read deadline expired
    "deadline_exceeded",     # the caller's overall time budget ran out inside the call
    "connection_error",      # DNS/TCP/TLS/socket failure
    "rate_limited",          # HTTP 429
    "service_unavailable",   # HTTP 503
    "overloaded",            # HTTP 529
    "server_error",          # other HTTP 5xx (processing outcome unknown)
    "authentication",        # HTTP 401, or no credential configured
    "forbidden",             # HTTP 403
    "insufficient_quota",    # HTTP 402
    "model_not_found",       # HTTP 404
    "invalid_request",       # HTTP 400/422 and other 4xx
    "unexpected_redirect",   # HTTP 3xx; redirects are never followed
    "unexpected_status",     # 1xx or any 2xx other than 200
    "malformed_response",    # HTTP 200 whose envelope is not a valid completion
    "oversized_response",    # body exceeded MAX_RESPONSE_BYTES
})

Submission = Literal["not_submitted", "rejected", "uncertain", "completed"]
SUBMISSION_STATES = ("not_submitted", "rejected", "uncertain", "completed")
RetryAfterStatus = Literal["absent", "valid", "invalid"]

_RETRYABLE_NOT_SUBMITTED = frozenset({"timeout", "connection_error", "deadline_exceeded"})

_STATUS_CATEGORY = {
    400: "invalid_request",
    401: "authentication",
    402: "insufficient_quota",
    403: "forbidden",
    404: "model_not_found",
    422: "invalid_request",
    429: "rate_limited",
    503: "service_unavailable",
    529: "overloaded",
}

def classify_http_status(status: int) -> tuple[str, Submission]:
    """Map a non-200 HTTP status to (category, submission). Shared by transport and record checks."""
    if type(status) is not int or not 100 <= status <= 599 or status == 200:
        raise ValueError("expected a non-200 HTTP status")
    if 300 <= status < 400:
        return "unexpected_redirect", "rejected"
    if status < 300:
        return "unexpected_status", "uncertain"
    category = _STATUS_CATEGORY.get(status) or ("server_error" if status >= 500 else "invalid_request")
    # A 5xx other than 503/529 can follow processing (e.g. a gateway timeout).
    return category, ("uncertain" if category == "server_error" else "rejected")


# Finish reasons this pipeline understands. Anything else is classified "unknown".
KNOWN_FINISH_REASONS = ("stop", "length", "content_filter", "tool_calls")
FinishReason = Literal["stop", "length", "content_filter", "tool_calls", "unknown", "absent"]
# Assistant message fields that are understood. Any other non-null field makes the
# response "unsupported" rather than silently ignored.
_KNOWN_MESSAGE_FIELDS = frozenset({"role", "content", "refusal", "tool_calls", "function_call"})
_IGNORABLE_NULL_FIELDS = frozenset({"audio", "annotations", "reasoning_content", "reasoning"})


# --- Endpoint identity ----------------------------------------------------------------------------

ENDPOINT_ERROR_CODES = frozenset({
    "endpoint_malformed",
    "endpoint_scheme_not_https",
    "endpoint_userinfo_forbidden",
    "endpoint_query_forbidden",
    "endpoint_fragment_forbidden",
    "endpoint_host_invalid",
    "endpoint_port_invalid",
    "endpoint_path_invalid",
})


class EndpointError(ValueError):
    """A base URL is not an acceptable endpoint. The message never contains the URL."""

    def __init__(self, code: str) -> None:
        if code not in ENDPOINT_ERROR_CODES:
            raise AssertionError(f"unregistered endpoint error code {code!r}")
        self.code = code
        super().__init__(f"invalid provider endpoint: {code}")


_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_NUMERIC_HOST_RE = re.compile(r"^[0-9.]+$")


def canonical_endpoint(url: str) -> str:
    """Return ``https://host:port/path`` for an acceptable base URL, else raise ``EndpointError``."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        raise EndpointError("endpoint_malformed")
    if any(ord(ch) <= 0x20 or ord(ch) >= 0x7F for ch in url):
        raise EndpointError("endpoint_malformed")
    if "#" in url:
        raise EndpointError("endpoint_fragment_forbidden")
    if "?" in url:
        raise EndpointError("endpoint_query_forbidden")
    if "\\" in url or "%" in url:
        raise EndpointError("endpoint_malformed")
    try:
        parts = urlsplit(url)
    except ValueError:
        raise EndpointError("endpoint_malformed") from None
    if parts.scheme.lower() != "https":
        raise EndpointError("endpoint_scheme_not_https")
    if "@" in parts.netloc:
        raise EndpointError("endpoint_userinfo_forbidden")
    netloc = parts.netloc
    if not netloc or netloc.startswith("["):
        raise EndpointError("endpoint_host_invalid")
    host, sep, port_text = netloc.partition(":")
    host = host.lower()
    if not _HOST_RE.match(host) or _NUMERIC_HOST_RE.match(host):
        raise EndpointError("endpoint_host_invalid")
    if sep:
        if not port_text.isdigit() or len(port_text) > 5 or port_text.startswith("0"):
            raise EndpointError("endpoint_port_invalid")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise EndpointError("endpoint_port_invalid")
    else:
        port = 443
    path = parts.path
    if path in ("", "/"):
        path = ""
    else:
        if not path.startswith("/"):
            raise EndpointError("endpoint_path_invalid")
        trimmed = path[1:-1] if path.endswith("/") else path[1:]
        segments = trimmed.split("/")
        if any(s in (".", "..") or not _SEGMENT_RE.match(s) for s in segments):
            raise EndpointError("endpoint_path_invalid")
        path = "/" + "/".join(segments)
    return f"https://{host}:{port}{path}"


OFFLINE_PROVIDER_NAME = "FakeOffline"
OFFLINE_ENDPOINT = "offline:fake"


class ProviderIdentity(BaseModel):
    """Non-secret identity of the configured provider, recorded with every run.

    A network provider has a canonical HTTPS ``endpoint``. The only offline
    identity is ``FakeOffline`` at ``offline:fake``: an offline provider cannot
    carry another provider's name, and no network provider may use the offline
    name, so a record always shows unambiguously whether a model was contacted.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    provider: str = Field(min_length=1, max_length=200)
    endpoint: str = Field(min_length=1, max_length=MAX_URL_CHARS)
    external_disclosure: StrictBool

    @model_validator(mode="after")
    def _endpoint_form(self) -> ProviderIdentity:
        if self.external_disclosure:
            if canonical_endpoint(self.endpoint) != self.endpoint:
                raise ValueError("external endpoint is not in canonical form")
            if self.provider.casefold() == OFFLINE_PROVIDER_NAME.casefold():
                raise ValueError("the offline provider name is reserved")
        elif (self.provider, self.endpoint) != (OFFLINE_PROVIDER_NAME, OFFLINE_ENDPOINT):
            raise ValueError("an offline provider must identify as FakeOffline at offline:fake")
        if not self.provider.isprintable() or self.provider != self.provider.strip():
            raise ValueError("provider name must be printable without surrounding whitespace")
        return self


# --- Errors ---------------------------------------------------------------------------------------

class ProviderError(RuntimeError):
    """A provider call did not return a usable completion envelope.

    ``submission`` is how far the request is known to have got (module docstring).
    ``retryable`` is derived from the category *and* the submission state, so an
    uncertain submission is never retryable. ``retry_after_status`` distinguishes
    an absent header from a valid or an invalid one; ``retry_after_seconds`` is
    only set when it is valid. ``provider_type``/``provider_code`` are short
    printable identifiers from the error body; free-form messages are dropped.
    ``body_sha256``/``body_bytes`` identify a received body that was rejected.
    """

    def __init__(
        self,
        category: str,
        *,
        submission: Submission,
        status: int | None = None,
        retry_after_seconds: float | None = None,
        retry_after_status: RetryAfterStatus = "absent",
        provider_type: str | None = None,
        provider_code: str | None = None,
        body_sha256: str | None = None,
        body_bytes: int | None = None,
    ) -> None:
        if category not in PROVIDER_ERROR_CATEGORIES:
            raise AssertionError(f"unregistered provider error category {category!r}")
        if submission not in SUBMISSION_STATES:
            raise AssertionError(f"unregistered submission state {submission!r}")
        if (retry_after_status == "valid") != (retry_after_seconds is not None):
            raise AssertionError("retry_after_seconds must be set exactly when the header is valid")
        if retry_after_seconds is not None and not (math.isfinite(retry_after_seconds) and retry_after_seconds >= 0):
            raise AssertionError("retry_after_seconds must be finite and non-negative")
        if status is not None and submission == "not_submitted":
            raise AssertionError("an HTTP status implies the request was submitted")
        if retry_after_status != "absent" and status is None:
            raise AssertionError("a Retry-After observation needs an HTTP response")
        if status == 200 and (submission != "completed"
                              or category not in ("malformed_response", "oversized_response")):
            raise AssertionError("an HTTP 200 error is a completed, malformed or oversized response")
        if status is not None and status != 200:
            expected_category, expected_submission = classify_http_status(status)
            if submission != expected_submission or category not in (expected_category, "oversized_response"):
                raise AssertionError("category/submission inconsistent with the HTTP status")
        self.category = category
        self.submission = submission
        self.retryable = submission == "not_submitted" and category in _RETRYABLE_NOT_SUBMITTED
        self.status = status
        self.retry_after_seconds = retry_after_seconds
        self.retry_after_status = retry_after_status
        self.provider_type = provider_type
        self.provider_code = provider_code
        self.body_sha256 = body_sha256
        self.body_bytes = body_bytes
        detail = f" (http {status})" if status is not None else ""
        super().__init__(f"provider call failed: {category}{detail} [{submission}]")


# --- Request and response -------------------------------------------------------------------------

class Message(BaseModel):
    """One chat message. Content is plain text; no tool calls or media."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=1_000_000)


class InferenceRequest(BaseModel):
    """A bounded, provider-agnostic generation request (always one candidate)."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    model: str = Field(min_length=1, max_length=200)
    messages: tuple[Message, ...] = Field(min_length=1, max_length=64)
    max_output_tokens: StrictInt = Field(ge=1, le=100_000)
    temperature: float = Field(ge=0.0, le=2.0, default=0.0)
    top_p: float | None = Field(gt=0.0, le=1.0, default=None)
    seed: int | None = Field(ge=0, le=2**63 - 1, default=None)
    stop: tuple[str, ...] = Field(max_length=4, default=())
    n: Literal[1] = 1
    store: Literal[False] | None = None

    def unsupported_options(self) -> tuple[str, ...]:
        """Options whose effect the provider does not guarantee; recorded, not asserted."""
        return ("seed_forwarded_without_guaranteed_determinism",) if self.seed is not None else ()

    def to_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in self.messages],
            "max_tokens": self.max_output_tokens,
            "temperature": self.temperature,
            "n": self.n,
            "stream": False,
        }
        if self.top_p is not None:
            body["top_p"] = self.top_p
        if self.stop:
            body["stop"] = list(self.stop)
        if self.seed is not None:
            body["seed"] = self.seed
        if self.store is not None:
            body["store"] = self.store
            # Live requests cap reasoning tokens as well as visible output.
            body["max_completion_tokens"] = self.max_output_tokens
            body["service_tier"] = "default"
        return body


class Usage(BaseModel):
    """Provider-reported token usage. Strict integers; ``total = prompt + completion``."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    prompt_tokens: StrictInt = Field(ge=0, le=10**9)
    completion_tokens: StrictInt = Field(ge=0, le=10**9)
    total_tokens: StrictInt = Field(ge=0, le=2 * 10**9)

    @model_validator(mode="after")
    def _sum(self) -> Usage:
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("total_tokens must equal prompt_tokens + completion_tokens")
        return self


ContentStatus = Literal["present", "absent", "invalid_text"]
UsageStatus = Literal["reported", "absent", "invalid"]


class InferenceResponse(BaseModel):
    """A strictly parsed HTTP 200 completion envelope. Every field is an observation.

    ``content`` is set only when ``content_status == "present"``. ``usage`` is set
    only when ``usage_status == "reported"``. ``body_sha256``/``body_bytes``
    identify the exact response body.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    content: str | None
    content_status: ContentStatus
    refusal: StrictBool
    tool_calls: StrictBool
    unsupported_fields: StrictBool
    finish_reason: FinishReason
    model: str | None = Field(default=None, max_length=200)
    response_id: str | None = Field(default=None, max_length=200)
    system_fingerprint: str | None = Field(default=None, max_length=200)
    created: StrictInt | None = None
    usage: Usage | None
    usage_status: UsageStatus
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_bytes: StrictInt = Field(ge=1, le=MAX_RESPONSE_BYTES)

    @model_validator(mode="after")
    def _consistency(self) -> InferenceResponse:
        # The same text rules parse_completion applies, so a response built any other way
        # (an offline provider, model_construct) cannot carry text the record cannot hold.
        if self.content is not None and not _valid_text(self.content):
            raise ValueError("content must be valid Unicode text without NUL")
        for value in (self.model, self.response_id, self.system_fingerprint):
            if value is not None and (not value or not value.isprintable() or not _valid_text(value)):
                raise ValueError("identity fields must be non-empty printable text")
        if (self.content is not None) != (self.content_status == "present"):
            raise ValueError("content must be set exactly when content_status is present")
        if (self.usage is not None) != (self.usage_status == "reported"):
            raise ValueError("usage must be set exactly when usage_status is reported")
        return self


@runtime_checkable
class InferenceProvider(Protocol):
    """Identity plus a single-shot completion call with a logical ``timeout``. No internal retries.

    ``timeout`` is the remaining wall budget. Implementations check it between
    operations; it is not a guaranteed wall-clock interruption.
    """

    @property
    def identity(self) -> ProviderIdentity: ...

    def complete(self, request: InferenceRequest, *, timeout: float) -> InferenceResponse: ...


# --- Retry-After ----------------------------------------------------------------------------------

_DELTA_SECONDS_RE = re.compile(r"^[0-9]{1,9}(?:\.[0-9]{1,6})?$")
MAX_RETRY_AFTER_SECONDS = 86_400.0


def parse_retry_after(value: str | None, *, now: float) -> tuple[RetryAfterStatus, float | None]:
    """Parse ``Retry-After`` as delta-seconds or an HTTP-date relative to wall time ``now``.

    Returns ``("absent", None)``, ``("valid", seconds)`` or ``("invalid", None)``.
    Negative, non-finite, exponent-form or unparseable values are invalid; a date in
    the past is a zero wait. A value above one day is invalid rather than shortened.
    """
    if value is None:
        return "absent", None
    text = value.strip()
    if not text:
        return "invalid", None
    if _DELTA_SECONDS_RE.match(text):
        seconds = float(text)
    else:
        if len(text) > 64 or not text.isascii():
            return "invalid", None
        try:
            when = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return "invalid", None
        if when is None or when.tzinfo is None or when.utcoffset() != UTC.utcoffset(None):
            return "invalid", None  # HTTP-dates are always GMT
        seconds = max(0.0, when.timestamp() - now)
    if not math.isfinite(seconds) or seconds < 0 or seconds > MAX_RETRY_AFTER_SECONDS:
        return "invalid", None
    return "valid", seconds


# --- Response parsing -----------------------------------------------------------------------------

def _short_identifier(value: Any) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 64 and value.isprintable() else None


def _error_identifiers(body: bytes) -> tuple[str | None, str | None]:
    """Pull only the short ``type``/``code`` identifiers from an error body."""
    try:
        document = parse_strict_json(body)
    except LoadError:
        return None, None
    if not isinstance(document, dict) or not isinstance(document.get("error"), dict):
        return None, None
    error = document["error"]
    return _short_identifier(error.get("type")), _short_identifier(error.get("code"))


def _valid_text(value: str) -> bool:
    if "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogate from a \\ud800 escape
        return False
    return True


def _optional_text(document: dict[str, Any], key: str, limit: int = 200) -> str | None:
    """A present value must be a printable string within ``limit``; null/absent is None."""
    value = document.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not 0 < len(value) <= limit or not value.isprintable() or not _valid_text(value):
        raise ValueError(key)
    return value


def _parse_usage(raw: Any) -> tuple[UsageStatus, Usage | None]:
    if raw is None:
        return "absent", None
    if not isinstance(raw, dict):
        return "invalid", None
    values: dict[str, int] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = raw.get(key)
        if type(value) is not int:  # rejects bool, float, str and None without coercion
            return "invalid", None
        values[key] = value
    try:
        return "reported", Usage(**values)
    except ValueError:
        return "invalid", None


def parse_completion(payload: bytes) -> InferenceResponse:
    """Strictly parse an HTTP 200 chat-completion body. Raises ``ProviderError`` if invalid.

    The size bound is checked first, so every caller (network transport or offline
    provider) gets the same typed ``oversized_response`` error and an oversized
    body is never decoded, hashed or retained.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ProviderError("oversized_response", submission="completed", status=200)
    digest = hashlib.sha256(payload).hexdigest()

    def malformed() -> ProviderError:
        return ProviderError("malformed_response", submission="completed", status=200,
                             body_sha256=digest, body_bytes=len(payload))

    if not payload:
        raise malformed()
    try:
        document = parse_strict_json(payload)
    except LoadError:
        raise malformed() from None
    if not isinstance(document, dict) or "error" in document:
        raise malformed()
    if document.get("object", "chat.completion") != "chat.completion":
        raise malformed()
    choices = document.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise malformed()
    choice = choices[0]
    if choice.get("index", 0) != 0 or type(choice.get("index", 0)) is not int:
        raise malformed()
    message = choice.get("message")
    if not isinstance(message, dict):
        raise malformed()
    if message.get("role", "assistant") != "assistant":
        raise malformed()

    content = message.get("content")
    if content is None:
        content_status: ContentStatus = "absent"
    elif not isinstance(content, str):
        raise malformed()
    elif not _valid_text(content):
        content_status, content = "invalid_text", None
    else:
        content_status = "present"

    refusal_value = message.get("refusal")
    if refusal_value is not None and not isinstance(refusal_value, str):
        raise malformed()
    refusal = bool(refusal_value)
    tool_calls_value = message.get("tool_calls")
    if tool_calls_value is not None and not isinstance(tool_calls_value, list):
        raise malformed()
    tool_calls = bool(tool_calls_value) or message.get("function_call") is not None
    unsupported = any(
        key not in _KNOWN_MESSAGE_FIELDS and not (key in _IGNORABLE_NULL_FIELDS and value is None)
        for key, value in message.items()
    )

    raw_finish = choice.get("finish_reason")
    if raw_finish is None:
        finish_reason: FinishReason = "absent"
    elif not isinstance(raw_finish, str):
        raise malformed()
    else:
        finish_reason = raw_finish if raw_finish in KNOWN_FINISH_REASONS else "unknown"  # type: ignore[assignment]

    created = document.get("created")
    if created is not None and (type(created) is not int or created < 0):
        raise malformed()
    try:
        model = _optional_text(document, "model")
        response_id = _optional_text(document, "id")
        fingerprint = _optional_text(document, "system_fingerprint")
    except ValueError:
        raise malformed() from None
    usage_status, usage = _parse_usage(document.get("usage"))
    return InferenceResponse(
        content=content,
        content_status=content_status,
        refusal=refusal,
        tool_calls=tool_calls,
        unsupported_fields=unsupported,
        finish_reason=finish_reason,
        model=model,
        response_id=response_id,
        system_fingerprint=fingerprint,
        created=created,
        usage=usage,
        usage_status=usage_status,
        body_sha256=digest,
        body_bytes=len(payload),
    )


# --- Nebius transport -----------------------------------------------------------------------------

class _OutOfTime(Exception):
    pass


class NebiusProvider:
    """OpenAI-compatible Nebius Token Factory transport over ``http.client`` + TLS.

    One ``complete`` call is at most one ``POST <base path>/chat/completions``. The
    API key is private and never recorded. The ``timeout`` is a logical deadline
    plus per-operation socket inactivity timeouts, not a hard wall-clock bound
    (see the module docstring). ``external_disclosure`` is True: the
    inference-only runner refuses to drive this unbounded HTTP implementation
    directly. It uses ``BoundedNebiusProvider`` with a separate operator approval;
    generated-candidate execution still requires Core authorization.
    """

    external_disclosure = True
    __slots__ = ("_allow_live", "_evidence_sink", "_api_key", "_endpoint", "_host", "_port", "_path_prefix", "_connect_timeout",
                 "_read_timeout", "_ssl_context", "_provider_name", "_monotonic", "_wall_clock")

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = NEBIUS_BASE_URL,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
        provider_name: str = "Nebius",
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        allow_live: bool = False,
        evidence_sink: Callable[[str, bytes], None] | None = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip() or not api_key.isprintable():
            raise ValueError("a non-empty printable API key is required")
        endpoint = canonical_endpoint(base_url)
        if not (0 < connect_timeout <= 600 and 0 < read_timeout <= 3600):
            raise ValueError("timeouts out of range")
        parts = urlsplit(endpoint)
        self._api_key = api_key
        self._endpoint = endpoint
        self._host = parts.hostname
        self._port = parts.port
        self._path_prefix = parts.path
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._ssl_context = ssl_context or ssl.create_default_context()
        self._provider_name = provider_name
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._allow_live = allow_live is True
        self._evidence_sink = evidence_sink

    @classmethod
    def from_environment(cls, environ: dict[str, str] | None = None, **kwargs: Any) -> NebiusProvider:
        """Read the API key from ``NEBIUS_API_KEY``. Raises ``ProviderError`` if unset."""
        import os

        source = os.environ if environ is None else environ
        key = source.get(NEBIUS_API_KEY_ENV, "")
        if not key.strip():
            raise ProviderError("authentication", submission="not_submitted")
        return cls(key, **kwargs)

    def __repr__(self) -> str:  # never expose the key
        return f"NebiusProvider(endpoint={self._endpoint!r}, provider={self._provider_name!r})"

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(provider=self._provider_name, endpoint=self._endpoint, external_disclosure=True)

    def _connect(self) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(
            self._host, self._port, timeout=self._connect_timeout, context=self._ssl_context
        )

    def complete(self, request: InferenceRequest, *, timeout: float) -> InferenceResponse:
        if not self._allow_live:
            raise PermissionError("live_opt_in_required")
        if not (isinstance(timeout, (int, float)) and math.isfinite(timeout)):
            raise ValueError("timeout must be a finite number")
        deadline = self._monotonic() + timeout

        def left(cap: float) -> float:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise _OutOfTime
            return min(cap, remaining)

        body = json.dumps(request.to_body(), ensure_ascii=False, allow_nan=False).encode("utf-8")
        if self._evidence_sink is not None:
            self._evidence_sink("request", body)  # never headers or credentials
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "aegis-lab/0.2 (+offline-research)",
        }
        submission: Submission = "not_submitted"
        connection = self._connect()
        try:
            try:
                connection.timeout = left(self._connect_timeout)
                connection.connect()
                connection.sock.settimeout(left(self._read_timeout))
                submission = "uncertain"  # from here on, bytes may reach the provider
                connection.request("POST", f"{self._path_prefix}/chat/completions", body=body, headers=headers)
                connection.sock.settimeout(left(self._read_timeout))
                response = connection.getresponse()
                status = response.status
                retry_after = parse_retry_after(response.getheader("Retry-After"), now=self._wall_clock())
                declared_length = response.getheader("Content-Length")
                if declared_length is not None and declared_length.strip().isdigit() \
                        and int(declared_length.strip()) > MAX_RESPONSE_BYTES:
                    payload = None
                else:
                    chunks: list[bytes] = []
                    total = 0
                    while total <= MAX_RESPONSE_BYTES:
                        connection.sock.settimeout(left(self._read_timeout))
                        chunk = response.read(min(_READ_CHUNK, MAX_RESPONSE_BYTES + 1 - total))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                    payload = b"".join(chunks) if total <= MAX_RESPONSE_BYTES else None
            except _OutOfTime:
                raise ProviderError("deadline_exceeded", submission=submission) from None
            except (socket.timeout, TimeoutError):
                raise ProviderError("timeout", submission=submission) from None
            except (ssl.SSLError, OSError, http.client.HTTPException):
                raise ProviderError("connection_error", submission=submission) from None
        finally:
            connection.close()

        if payload is None:
            # A 200 means the request was processed (and possibly billed) even though the body is unusable.
            submission = "completed" if status == 200 else classify_http_status(status)[1]
            raise ProviderError("oversized_response", submission=submission, status=status)
        if self._evidence_sink is not None:
            self._evidence_sink("response", payload)
        if status == 200:
            return parse_completion(payload)
        provider_type, provider_code = _error_identifiers(payload)
        category, status_submission = classify_http_status(status)
        ra_status, ra_seconds = retry_after
        raise ProviderError(
            category, submission=status_submission, status=status,
            retry_after_status=ra_status, retry_after_seconds=ra_seconds,
            provider_type=provider_type, provider_code=provider_code,
            body_sha256=hashlib.sha256(payload).hexdigest(), body_bytes=len(payload),
        )
