"""An offline, scripted inference provider for repeatable tests and demos.

It performs **no** network I/O and no external disclosure, so it needs no token
and no disclosure approval. It implements ``InferenceProvider``: each call either
raises the next scripted ``ProviderError`` or builds a chat-completion JSON body
and passes it through the production parser (``provider.parse_completion``), so
offline runs exercise the same strict response validation as a network provider.

By default the reply is a valid ``aegis.lab.candidate.v1`` envelope for the
task in the request, with a fixed placeholder source. Nothing it returns is
evidence of reconstruction.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .provider import (
    OFFLINE_ENDPOINT,
    OFFLINE_PROVIDER_NAME,
    InferenceRequest,
    InferenceResponse,
    ProviderError,
    ProviderIdentity,
    Usage,
    parse_completion,
)

FAKE_PROVIDER_NAME = OFFLINE_PROVIDER_NAME
FAKE_ENDPOINT = OFFLINE_ENDPOINT
DEFAULT_FAKE_SOURCE = "/* offline fake candidate: not a real reconstruction */\nint target_function(void) { return 0; }\n"
_UNSET: Any = object()


def candidate_envelope(request: InferenceRequest, source: str) -> str:
    """Wrap ``source`` in the candidate envelope the request's task asks for."""
    try:
        task = json.loads(request.messages[-1].content)["task"]
        language, interface = task["language"], task["expected_interface"]
    except (ValueError, KeyError, TypeError):
        language, interface = "c", "unknown()->void"
    return json.dumps({"schema": "aegis.lab.candidate.v1", "language": language,
                       "interface": interface, "source": source})


class FakeProvider:
    """Scripted offline provider.

    ``source`` is wrapped in a valid envelope; ``content`` (if given) is returned
    verbatim as the assistant content instead, to exercise invalid replies.
    ``usage`` may be a ``Usage``, a raw dict (sent as-is, even if invalid), or
    ``None`` to omit it. ``reported_model=None`` with ``echo_requested_model=False``
    omits the model. ``on_call`` runs inside ``complete`` (e.g. to advance a test clock).

    Identity: an offline fake is always ``FakeOffline`` at ``offline:fake``; passing
    another ``provider`` name is refused, so a fake can never be recorded as Nebius.
    ``external_disclosure=True`` (with a provider name and canonical HTTPS endpoint)
    builds a stub that *claims* to be external. It exists only to test that the live
    gate refuses such providers before any call.
    """

    def __init__(
        self,
        *,
        source: str = DEFAULT_FAKE_SOURCE,
        content: Any = _UNSET,
        finish_reason: Any = "stop",
        reported_model: str | None = None,
        echo_requested_model: bool = True,
        response_id: str | None = "fake-response-0001",
        system_fingerprint: str | None = "fake-fp",
        usage: Any = _UNSET,
        message_extra: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        provider: str | None = None,
        endpoint: str | None = None,
        external_disclosure: bool = False,
        errors: list[ProviderError] | None = None,
        on_call: Callable[[InferenceRequest, float], None] | None = None,
        evidence_sink: Callable[[str, bytes], None] | None = None,
    ) -> None:
        self._source = source
        self._content = content
        self._finish_reason = finish_reason
        self._reported_model = reported_model
        self._echo_requested_model = echo_requested_model
        self._response_id = response_id
        self._system_fingerprint = system_fingerprint
        if usage is _UNSET:
            usage = Usage(prompt_tokens=128, completion_tokens=32, total_tokens=160)
        self._usage = usage
        self._message_extra = dict(message_extra or {})
        self._raw_body = raw_body
        if not external_disclosure and (provider not in (None, FAKE_PROVIDER_NAME)
                                        or endpoint not in (None, FAKE_ENDPOINT)):
            raise ValueError("an offline fake provider cannot use another provider identity")
        if external_disclosure and (provider is None or endpoint is None):
            raise ValueError("an external stub needs an explicit provider name and endpoint")
        self._identity = ProviderIdentity(
            provider=provider or FAKE_PROVIDER_NAME, endpoint=endpoint or FAKE_ENDPOINT,
            external_disclosure=external_disclosure,
        )
        self.external_disclosure = external_disclosure
        self._pending_errors = list(errors or [])
        self._on_call = on_call
        self._evidence_sink = evidence_sink
        self.requests: list[InferenceRequest] = []
        self.timeouts: list[float] = []

    @property
    def identity(self) -> ProviderIdentity:
        return self._identity

    def _body(self, request: InferenceRequest) -> bytes:
        content = candidate_envelope(request, self._source) if self._content is _UNSET else self._content
        message: dict[str, Any] = {"role": "assistant", "content": content, **self._message_extra}
        choice: dict[str, Any] = {"index": 0, "message": message}
        if self._finish_reason is not None:
            choice["finish_reason"] = self._finish_reason
        document: dict[str, Any] = {
            "id": self._response_id,
            "object": "chat.completion",
            "created": 1_700_000_000,
            "system_fingerprint": self._system_fingerprint,
            "choices": [choice],
        }
        reported = self._reported_model
        if reported is None and self._echo_requested_model:
            reported = request.model
        if reported is not None:
            document["model"] = reported
        if isinstance(self._usage, Usage):
            document["usage"] = self._usage.model_dump()
        elif self._usage is not None:
            document["usage"] = self._usage
        # ensure_ascii keeps lone surrogates encodable as \\ud800 escapes, as a server could send.
        return json.dumps(document, ensure_ascii=True).encode("ascii")

    def complete(self, request: InferenceRequest, *, timeout: float) -> InferenceResponse:
        if self._evidence_sink:
            self._evidence_sink("request", json.dumps(request.to_body(), ensure_ascii=False,
                                                     allow_nan=False).encode("utf-8"))
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self._on_call is not None:
            self._on_call(request, timeout)
        if self._pending_errors:
            raise self._pending_errors.pop(0)
        payload = self._raw_body if self._raw_body is not None else self._body(request)
        if self._evidence_sink:
            self._evidence_sink("response", payload)
        return parse_completion(payload)
