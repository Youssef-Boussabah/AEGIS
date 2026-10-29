"""Unit tests for the inference-provider boundary (no real network calls).

``NebiusProvider.complete`` is exercised with a fake ``http.client`` connection, so
endpoint identity, submission state, deadline handling, Retry-After parsing,
bounded reads and strict response parsing are covered without any request or token.
"""

from __future__ import annotations

import email.utils
import json
import socket

import pytest
from pydantic import ValidationError

from aegis_lab import provider as provider_module
from aegis_lab.provider import (
    DEFAULT_NEBIUS_MODEL,
    NEBIUS_API_KEY_ENV,
    EndpointError,
    InferenceRequest,
    Message,
    NebiusProvider,
    ProviderError,
    ProviderIdentity,
    Usage,
    canonical_endpoint,
    parse_completion,
    parse_retry_after,
)

CANONICAL_NEBIUS = "https://api.tokenfactory.nebius.com:443/v1"


def req(**kwargs) -> InferenceRequest:
    base = dict(
        model="vendor/model-1",
        messages=(Message(role="system", content="s"), Message(role="user", content="u")),
        max_output_tokens=256,
    )
    base.update(kwargs)
    return InferenceRequest(**base)


# --- Request model ------------------------------------------------------------------------------

def test_request_body_only_sets_provided_fields():
    body = req(seed=7, top_p=0.9, stop=("END",)).to_body()
    assert body["model"] == "vendor/model-1"
    assert body["max_tokens"] == 256
    assert body["n"] == 1 and body["stream"] is False
    assert body["seed"] == 7 and body["top_p"] == 0.9 and body["stop"] == ["END"]


def test_request_body_omits_unset_optional_fields():
    body = req().to_body()
    assert "seed" not in body and "top_p" not in body and "stop" not in body


def test_seed_is_flagged_as_unsupported_for_determinism():
    assert req(seed=1).unsupported_options() == ("seed_forwarded_without_guaranteed_determinism",)
    assert req().unsupported_options() == ()


def test_request_rejects_unbounded_or_multi_candidate():
    for bad in ({"max_output_tokens": 0}, {"n": 2}, {"temperature": 3.0}, {"top_p": 0.0},
                {"max_output_tokens": True}):
        with pytest.raises(ValidationError):
            req(**bad)


# --- Endpoint identity (Finding 1) --------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://api.tokenfactory.nebius.com/v1", CANONICAL_NEBIUS),
    ("https://API.TokenFactory.Nebius.com/v1/", CANONICAL_NEBIUS),
    ("HTTPS://api.tokenfactory.nebius.com:443/v1", CANONICAL_NEBIUS),
    ("https://api.tokenfactory.nebius.com:8443/other-tenant", "https://api.tokenfactory.nebius.com:8443/other-tenant"),
    ("https://example.com", "https://example.com:443"),
])
def test_canonical_endpoint(url, expected):
    assert canonical_endpoint(url) == expected


def test_regression_port_and_path_are_part_of_endpoint_identity():
    """Audit reproduction: host-only matching accepted another port and API path."""
    identities = {canonical_endpoint(u) for u in (
        "https://api.tokenfactory.nebius.com/v1",
        "https://api.tokenfactory.nebius.com:8443/other-tenant",
        "https://api.tokenfactory.nebius.com/other-api",
    )}
    assert len(identities) == 3


@pytest.mark.parametrize("url,code", [
    ("http://api.example.com/v1", "endpoint_scheme_not_https"),
    ("ftp://api.example.com/v1", "endpoint_scheme_not_https"),
    ("https://user:SECRET-TOKEN@api.example.com/v1", "endpoint_userinfo_forbidden"),
    ("https://SECRET-TOKEN@api.example.com/v1", "endpoint_userinfo_forbidden"),
    ("https://api.example.com/v1?key=SECRET-TOKEN", "endpoint_query_forbidden"),
    ("https://api.example.com/v1?", "endpoint_query_forbidden"),
    ("https://api.example.com/v1#frag", "endpoint_fragment_forbidden"),
    ("https://127.0.0.1/v1", "endpoint_host_invalid"),
    ("https://[::1]/v1", "endpoint_host_invalid"),
    ("https:///v1", "endpoint_host_invalid"),
    ("https://bad_host.example/v1", "endpoint_host_invalid"),
    ("https://api.example.com:0/v1", "endpoint_port_invalid"),
    ("https://api.example.com:65536/v1", "endpoint_port_invalid"),
    ("https://api.example.com:08/v1", "endpoint_port_invalid"),
    ("https://api.example.com:x/v1", "endpoint_port_invalid"),
    ("https://api.example.com/v1/../admin", "endpoint_path_invalid"),
    ("https://api.example.com//v1", "endpoint_path_invalid"),
    ("https://api.example.com/v1/./x", "endpoint_path_invalid"),
    ("https://api.example.com/v%31", "endpoint_malformed"),
    ("https://api.example.com/v1 x", "endpoint_malformed"),
    ("https://api.exämple.com/v1", "endpoint_malformed"),
    ("https://api.example.com\\v1", "endpoint_malformed"),
    ("", "endpoint_malformed"),
])
def test_rejected_endpoints_never_echo_the_url(url, code):
    with pytest.raises(EndpointError) as info:
        canonical_endpoint(url)
    assert info.value.code == code
    assert "SECRET-TOKEN" not in str(info.value) and "example" not in str(info.value)


def test_provider_identity_requires_canonical_external_endpoint():
    ProviderIdentity(provider="Nebius", endpoint=CANONICAL_NEBIUS, external_disclosure=True)
    with pytest.raises(ValidationError):
        ProviderIdentity(provider="Nebius", endpoint="https://api.tokenfactory.nebius.com/v1",
                         external_disclosure=True)
    with pytest.raises(ValidationError):
        ProviderIdentity(provider="Fake", endpoint=CANONICAL_NEBIUS, external_disclosure=False)
    with pytest.raises(ValidationError):
        ProviderIdentity(provider="Fake", endpoint="offline:fake", external_disclosure=True)


# --- Retry-After (Finding 10) -------------------------------------------------------------------

NOW = 1_800_000_000.0


@pytest.mark.parametrize("value,expected", [
    (None, ("absent", None)),
    ("2", ("valid", 2.0)),
    ("0", ("valid", 0.0)),
    ("120", ("valid", 120.0)),
    ("1.5", ("valid", 1.5)),
    ("", ("invalid", None)),
    ("-3", ("invalid", None)),
    ("soon", ("invalid", None)),
    ("Infinity", ("invalid", None)),
    ("inf", ("invalid", None)),
    ("NaN", ("invalid", None)),
    ("1e3", ("invalid", None)),
    ("100000", ("invalid", None)),       # more than a day: invalid, never shortened
    ("9999999999", ("invalid", None)),
])
def test_regression_parse_retry_after(value, expected):
    """Audit reproduction: 'Infinity' was accepted and HTTP-dates were ignored."""
    assert parse_retry_after(value, now=NOW) == expected


def test_retry_after_http_date():
    future = email.utils.formatdate(NOW + 90, usegmt=True)
    assert parse_retry_after(future, now=NOW) == ("valid", 90.0)
    past = email.utils.formatdate(NOW - 90, usegmt=True)
    assert parse_retry_after(past, now=NOW) == ("valid", 0.0)
    assert parse_retry_after("Wed, 28 Oct 2026 12:00:00 +0200", now=NOW) == ("invalid", None)
    assert parse_retry_after("Wed, 99 Oct 2026 12:00:00 GMT", now=NOW) == ("invalid", None)


# --- Response parsing (Finding 7) ---------------------------------------------------------------

def completion_bytes(**overrides) -> bytes:
    document = {
        "id": "cmpl-1",
        "object": "chat.completion",
        "created": 123,
        "model": "vendor/model-1",
        "system_fingerprint": "fp-1",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "code"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    for key, value in overrides.items():
        if value is None:
            document.pop(key, None)
        else:
            document[key] = value
    return json.dumps(document).encode()


def choice(message=None, **extra):
    return [{"index": 0, "message": {"role": "assistant", "content": "code", **(message or {})}, **extra}]


def test_parse_completion_normal():
    response = parse_completion(completion_bytes())
    assert response.content == "code" and response.content_status == "present"
    assert response.finish_reason == "stop"
    assert response.model == "vendor/model-1"
    assert response.usage == Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    assert response.usage_status == "reported"
    assert not (response.refusal or response.tool_calls or response.unsupported_fields)


@pytest.mark.parametrize("choices,field,value", [
    (choice(finish_reason="length"), "finish_reason", "length"),
    (choice(finish_reason="weird"), "finish_reason", "unknown"),
    (choice(), "finish_reason", "absent"),
    (choice({"content": None}, finish_reason="stop"), "content_status", "absent"),
    (choice({"content": "\ud800"}, finish_reason="stop"), "content_status", "invalid_text"),
    (choice({"content": "a\x00b"}, finish_reason="stop"), "content_status", "invalid_text"),
    (choice({"refusal": "no"}, finish_reason="stop"), "refusal", True),
    (choice({"tool_calls": [{"id": "x"}]}, finish_reason="tool_calls"), "tool_calls", True),
    (choice({"function_call": {"name": "f"}}, finish_reason="stop"), "tool_calls", True),
    (choice({"surprise": 1}, finish_reason="stop"), "unsupported_fields", True),
    (choice({"reasoning_content": None}, finish_reason="stop"), "unsupported_fields", False),
])
def test_parse_completion_classifies_without_coercion(choices, field, value):
    assert getattr(parse_completion(completion_bytes(choices=choices)), field) == value


@pytest.mark.parametrize("usage,status", [
    (None, "absent"),
    ({}, "invalid"),
    ("nonsense", "invalid"),
    ({"prompt_tokens": True, "completion_tokens": 1, "total_tokens": 2}, "invalid"),
    ({"prompt_tokens": 1.0, "completion_tokens": 1, "total_tokens": 2}, "invalid"),
    ({"prompt_tokens": "1", "completion_tokens": 1, "total_tokens": 2}, "invalid"),
    ({"prompt_tokens": -1, "completion_tokens": 1, "total_tokens": 0}, "invalid"),
    ({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 3}, "invalid"),
    ({"prompt_tokens": 1, "completion_tokens": 1}, "invalid"),
    ({"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2, "prompt_tokens_details": {}}, "reported"),
])
def test_regression_usage_is_never_coerced_or_invented(usage, status):
    """Audit reproduction: {} became zero usage and True/1.9/'999' were coerced."""
    response = parse_completion(completion_bytes(usage=usage if usage is not None else None))
    assert response.usage_status == status
    assert (response.usage is not None) == (status == "reported")


@pytest.mark.parametrize("payload", [
    b"",
    b"{not json",
    b"[]",
    b'{"choices": []}',
    b'{"choices": [{}]}',
    b'{"choices": [{"message": {"content": 123}}]}',
    b'{"choices": [{"message": {"content": "a"}}, {"message": {"content": "b"}}]}',
    b'{"choices": [{"message": {"role": "user", "content": "a"}}]}',
    b'{"choices": [{"index": 1, "message": {"content": "a"}}]}',
    b'{"choices": [{"message": {"content": "a"}, "finish_reason": 3}]}',
    b'{"object": "chat.completion.chunk", "choices": [{"message": {"content": "a"}}]}',
    b'{"error": {"message": "x"}, "choices": [{"message": {"content": "a"}}]}',
    b'{"model": "a", "model": "b", "choices": [{"message": {"content": "a"}}]}',
    b'{"model": 5, "choices": [{"message": {"content": "a"}}]}',
    b'{"model": "a\\nb", "choices": [{"message": {"content": "a"}}]}',
    b'{"created": 1.5, "choices": [{"message": {"content": "a"}}]}',
    b'{"choices": [{"message": {"content": "a"}}], "usage": {"total_tokens": 1e999}}',
    b'{"choices": [{"message": {"content": "a"}}], "usage": {"total_tokens": NaN}}',
    b'\xff\xfe{}',
])
def test_regression_malformed_envelopes_raise_typed_errors(payload):
    """Audit reproduction: duplicate keys were accepted and 1e999 raised OverflowError."""
    with pytest.raises(ProviderError) as info:
        parse_completion(payload)
    assert info.value.category == "malformed_response"
    assert info.value.submission == "completed"
    assert info.value.retryable is False


# --- Provider errors ----------------------------------------------------------------------------

def test_retryable_depends_on_submission_state():
    assert ProviderError("timeout", submission="not_submitted").retryable is True
    assert ProviderError("timeout", submission="uncertain").retryable is False
    # No HTTP response is retryable, including 429/503/529 (second audit).
    for category, status in (("rate_limited", 429), ("service_unavailable", 503), ("overloaded", 529)):
        assert ProviderError(category, submission="rejected", status=status).retryable is False
    assert ProviderError("server_error", submission="uncertain", status=500).retryable is False
    assert ProviderError("invalid_request", submission="rejected", status=400).retryable is False
    with pytest.raises(AssertionError):
        ProviderError("rate_limited", submission="not_submitted", status=429)
    with pytest.raises(AssertionError):
        ProviderError("rate_limited", submission="uncertain", status=429)  # contradicts the status mapping
    with pytest.raises(AssertionError):
        ProviderError("invalid_request", submission="rejected", status=429)
    with pytest.raises(AssertionError):
        ProviderError("timeout", submission="uncertain", retry_after_status="invalid")
    with pytest.raises(AssertionError):
        ProviderError("rate_limited", submission="rejected", retry_after_status="valid")


# --- Fake connection to drive complete() --------------------------------------------------------

class FakeResponse:
    def __init__(self, status, body, headers=None, on_read=None):
        self.status = status
        self._body = body
        self._headers = headers or {}
        self._on_read = on_read

    def read(self, amt=None):
        if self._on_read is not None:
            self._on_read()
        chunk, self._body = (self._body, b"") if amt is None else (self._body[:amt], self._body[amt:])
        return chunk

    def getheader(self, name, default=None):
        return self._headers.get(name, default)


class FakeConnection:
    instances: list = []

    def __init__(self, status=200, body=b"", headers=None, raise_on=None, on_read=None):
        self._status, self._body, self._headers = status, body, headers
        self._raise_on, self._on_read = raise_on, on_read
        self.timeout = None
        self.timeouts: list[float] = []
        self.requests: list[dict] = []
        self.sock = type("S", (), {"settimeout": lambda _s, t: self.timeouts.append(t)})()
        FakeConnection.instances.append(self)

    def connect(self):
        self.timeouts.append(self.timeout)
        if self._raise_on == "connect":
            raise OSError("no route")
        if self._raise_on == "connect_timeout":
            raise socket.timeout("connect timed out")

    def request(self, method, path, body, headers):
        self.requests.append({"method": method, "path": path, "body": body, "headers": headers})
        if self._raise_on == "request":
            raise BrokenPipeError("connection reset while sending")

    def getresponse(self):
        if self._raise_on == "response":
            raise socket.timeout("read timed out")
        return FakeResponse(self._status, self._body, self._headers, self._on_read)

    def close(self):
        pass


def make_provider(monkeypatch, *, clock=None, **conn_kwargs) -> NebiusProvider:
    FakeConnection.instances = []
    kwargs = {} if clock is None else {"monotonic": clock}
    nebius = NebiusProvider("secret-key-123", wall_clock=lambda: NOW, **kwargs)
    monkeypatch.setattr(NebiusProvider, "_connect", lambda self: FakeConnection(**conn_kwargs))
    return nebius


def sent(index=0):
    return FakeConnection.instances[index].requests


def test_complete_success(monkeypatch):
    nebius = make_provider(monkeypatch, status=200, body=completion_bytes())
    response = nebius.complete(req(), timeout=30)
    assert response.content == "code"
    request = sent()[0]
    assert json.loads(request["body"])["model"] == "vendor/model-1"
    assert request["headers"]["Authorization"] == "Bearer secret-key-123"
    assert request["path"] == "/v1/chat/completions"
    assert len(sent()) == 1


@pytest.mark.parametrize("status,category,submission,retryable", [
    (400, "invalid_request", "rejected", False),
    (401, "authentication", "rejected", False),
    (402, "insufficient_quota", "rejected", False),
    (403, "forbidden", "rejected", False),
    (404, "model_not_found", "rejected", False),
    (422, "invalid_request", "rejected", False),
    (429, "rate_limited", "rejected", False),
    (500, "server_error", "uncertain", False),
    (502, "server_error", "uncertain", False),
    (504, "server_error", "uncertain", False),
    (503, "service_unavailable", "rejected", False),
    (529, "overloaded", "rejected", False),
    (301, "unexpected_redirect", "rejected", False),
    (307, "unexpected_redirect", "rejected", False),
    (204, "unexpected_status", "uncertain", False),
])
def test_complete_status_mapping(monkeypatch, status, category, submission, retryable):
    body = json.dumps({"error": {"type": "some_error", "code": "x_code", "message": "free text"}}).encode()
    nebius = make_provider(monkeypatch, status=status, body=body,
                           headers={"Retry-After": "4", "Location": "https://evil.example/"})
    with pytest.raises(ProviderError) as info:
        nebius.complete(req(), timeout=30)
    error = info.value
    assert (error.category, error.submission, error.retryable, error.status) == (category, submission, retryable,
                                                                                 status)
    assert error.provider_type == "some_error" and error.provider_code == "x_code"
    assert error.retry_after_status == "valid" and error.retry_after_seconds == 4.0
    assert "free text" not in str(error)
    assert len(FakeConnection.instances) == 1  # a redirect is never followed


def test_invalid_retry_after_header_is_classified(monkeypatch):
    nebius = make_provider(monkeypatch, status=429, body=b"{}", headers={"Retry-After": "Infinity"})
    with pytest.raises(ProviderError) as info:
        nebius.complete(req(), timeout=30)
    assert info.value.retry_after_status == "invalid" and info.value.retry_after_seconds is None


@pytest.mark.parametrize("raise_on,category,submission,retryable", [
    ("connect", "connection_error", "not_submitted", True),
    ("connect_timeout", "timeout", "not_submitted", True),
    ("request", "connection_error", "uncertain", False),
    ("response", "timeout", "uncertain", False),
])
def test_regression_submission_state_of_transport_failures(monkeypatch, raise_on, category, submission, retryable):
    """Audit reproduction: a lost response after an accepted POST was marked retryable."""
    nebius = make_provider(monkeypatch, status=200, body=completion_bytes(), raise_on=raise_on)
    with pytest.raises(ProviderError) as info:
        nebius.complete(req(), timeout=30)
    assert (info.value.category, info.value.submission, info.value.retryable) == (category, submission, retryable)


def test_oversized_response_by_content_length(monkeypatch):
    nebius = make_provider(monkeypatch, status=200, body=b"{}",
                           headers={"Content-Length": str(provider_module.MAX_RESPONSE_BYTES + 1)})
    with pytest.raises(ProviderError) as info:
        nebius.complete(req(), timeout=30)
    assert info.value.category == "oversized_response" and info.value.submission == "completed"


def test_oversized_response_body(monkeypatch):
    big = b" " * (provider_module.MAX_RESPONSE_BYTES + 1)
    nebius = make_provider(monkeypatch, status=200, body=big)
    with pytest.raises(ProviderError) as info:
        nebius.complete(req(), timeout=30)
    assert info.value.category == "oversized_response"


class StepClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_regression_socket_timeouts_never_exceed_remaining_deadline(monkeypatch):
    """Audit reproduction: transport timeouts ignored the remaining wall budget."""
    nebius = make_provider(monkeypatch, status=200, body=completion_bytes())
    nebius.complete(req(), timeout=2.5)
    timeouts = FakeConnection.instances[0].timeouts
    assert timeouts and all(0 < t <= 2.5 for t in timeouts)


def test_slow_body_read_stops_at_the_deadline(monkeypatch):
    clock = StepClock()

    def slow():
        clock.t += 4.0

    nebius = make_provider(monkeypatch, clock=clock, status=200, body=completion_bytes() * 3, on_read=slow)
    monkeypatch.setattr(provider_module, "_READ_CHUNK", 16)
    with pytest.raises(ProviderError) as info:
        nebius.complete(req(), timeout=10)
    assert info.value.category == "deadline_exceeded"
    assert info.value.submission == "uncertain"


def test_no_time_left_fails_before_submission(monkeypatch):
    nebius = make_provider(monkeypatch, status=200, body=completion_bytes())
    with pytest.raises(ProviderError) as info:
        nebius.complete(req(), timeout=0)
    assert info.value.category == "deadline_exceeded" and info.value.submission == "not_submitted"
    assert sent() == []


def test_error_body_identifiers_are_bounded_and_printable(monkeypatch):
    body = json.dumps({"error": {"type": "x" * 500, "code": "bad\ncode"}}).encode()
    nebius = make_provider(monkeypatch, status=400, body=body)
    with pytest.raises(ProviderError) as info:
        nebius.complete(req(), timeout=30)
    assert info.value.provider_type is None and info.value.provider_code is None


# --- Identity, credentials, configuration -------------------------------------------------------

def test_identity_and_repr_hide_the_key():
    nebius = NebiusProvider("super-secret", provider_name="Nebius")
    assert nebius.identity == ProviderIdentity(provider="Nebius", endpoint=CANONICAL_NEBIUS,
                                               external_disclosure=True)
    assert "super-secret" not in repr(nebius)
    assert "super-secret" not in str(nebius.identity)


def test_from_environment_requires_key():
    with pytest.raises(ProviderError) as info:
        NebiusProvider.from_environment({})
    assert info.value.category == "authentication" and info.value.submission == "not_submitted"
    assert NebiusProvider.from_environment({NEBIUS_API_KEY_ENV: "k"}).identity.endpoint == CANONICAL_NEBIUS


def test_rejects_invalid_base_url_and_key():
    with pytest.raises(EndpointError):
        NebiusProvider("k", base_url="http://insecure.example/v1")
    with pytest.raises(EndpointError) as info:
        NebiusProvider("k", base_url="https://user:SECRET@api.example.com/v1")
    assert "SECRET" not in str(info.value)
    with pytest.raises(ValueError):
        NebiusProvider("", base_url="https://api.example.com/v1")


def test_default_model_is_a_documented_constant():
    assert DEFAULT_NEBIUS_MODEL.startswith("nvidia/")


def test_regression2_oversized_body_is_rejected_before_parsing():
    """Second audit: leading whitespace past 8 MiB raised a raw ValidationError."""
    body = b" " * provider_module.MAX_RESPONSE_BYTES + completion_bytes()
    with pytest.raises(ProviderError) as info:
        parse_completion(body)
    assert info.value.category == "oversized_response"
    assert info.value.submission == "completed" and info.value.status == 200
    assert info.value.body_sha256 is None and info.value.body_bytes is None
    exact = b" " * (provider_module.MAX_RESPONSE_BYTES - len(completion_bytes())) + completion_bytes()
    assert parse_completion(exact).content == "code"  # the limit itself is still accepted
