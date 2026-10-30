"""POSIX supervisor for the trusted Nebius HTTP worker; never runs candidate code.

DNS, TLS, status/header reads and body reads all run in a killable process group.
Secrets cross an anonymous stdin pipe, never argv, environment, diagnostics or disk.
The supervisor retains only bounded, credential-free worker output in private scratch.
"""
from __future__ import annotations

import base64
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from .provider import (
    InferenceRequest, NebiusProvider, ProviderError, canonical_endpoint, parse_completion,
)
from .safe_io import parse_strict_json, read_regular_file

MAX_WORKER_BYTES = 24 * 1024 * 1024
PUBLIC_CATALOGUE_URL = "https://tokenfactory.nebius.com/api/public/models_info"


def supervise(argv: list[str], payload: bytes, *, timeout: float) -> bytes:
    """Bound a trusted worker, including stalled DNS and trickling HTTP responses.

    A timeout or crash is conservatively uncertain; the parent cannot prove that
    no POST reached the provider. No automatic retry is safe. POSIX is required.
    """
    if os.name != "posix":
        raise ProviderError("connection_error", submission="not_submitted")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ProviderError("deadline_exceeded", submission="not_submitted")
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryDirectory(prefix="aegis-inference-") as scratch:
        root = Path(scratch)
        env = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
               "HOME": scratch, "TMPDIR": scratch,
               "PYTHONPATH": str(Path(__file__).resolve().parent.parent), "PYTHONDONTWRITEBYTECODE": "1"}
        output = root / "worker.json"
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            try:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=out, stderr=subprocess.DEVNULL,
                                           cwd=scratch, env=env, start_new_session=True, close_fds=True)
            except OSError:
                raise ProviderError("connection_error", submission="not_submitted") from None
            try:
                process.communicate(payload, timeout=max(0.001, deadline - time.monotonic()))
                if time.monotonic() > deadline:
                    raise ProviderError("deadline_exceeded", submission="uncertain")
                if process.returncode != 0:
                    raise ProviderError("connection_error", submission="uncertain")
            except subprocess.TimeoutExpired:
                raise ProviderError("deadline_exceeded", submission="uncertain") from None
            finally:
                # Also kill descendants of a worker that has already exited.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                if process.stdin is not None:
                    process.stdin.close()
        try:
            return read_regular_file(output, MAX_WORKER_BYTES)
        except Exception:
            raise ProviderError("oversized_response", submission="uncertain") from None


class BoundedNebiusProvider(NebiusProvider):
    """Operational transport. Legacy NebiusProvider is the HTTP implementation only."""

    hard_deadline = True

    def _worker(self, operation, *, timeout, request=None):
        if not self._allow_live:
            raise PermissionError("live_opt_in_required")
        if self.identity.endpoint != canonical_endpoint("https://api.tokenfactory.nebius.com/v1"):
            raise PermissionError("endpoint_not_approved")
        payload = json.dumps({"operation": operation, "key": self._api_key, "timeout": timeout,
                              "request": None if request is None else request.model_dump(mode="json")},
                             ensure_ascii=False, allow_nan=False).encode()
        raw = supervise([sys.executable, "-m", "aegis_lab.provider_worker"], payload, timeout=timeout)
        try:
            result = parse_strict_json(raw)
            events = result["events"]
            for kind, encoded in events:
                if kind not in ("request", "response", "account_models", "public_catalogue"):
                    raise ValueError("invalid_worker_event")
                data = base64.b64decode(encoded, validate=True)
                if len(data) > 8 * 1024 * 1024:
                    raise ValueError("oversized_worker_event")
                if self._evidence_sink is not None:
                    self._evidence_sink(kind, data)
            if result["error"] is not None:
                raise ProviderError(**result["error"])
            return {kind: base64.b64decode(encoded, validate=True) for kind, encoded in events}
        except ProviderError:
            raise
        except Exception:
            raise ProviderError("malformed_response", submission="uncertain") from None

    def complete(self, request: InferenceRequest, *, timeout: float):
        if request.store is not False:
            raise PermissionError("store_false_required")
        events = self._worker("complete", timeout=timeout, request=request)
        return parse_completion(events["response"])

    def verify_model(self, model: str, *, context_tokens: int, input_price: int, output_price: int,
                     timeout: float) -> None:
        """Fresh authenticated availability plus public NVIDIA context/pricing check.

        Prices are microusd per million tokens. Ceiling reservations deliberately
        use the complete published context, avoiding an unverified tokenizer bound.
        """
        from decimal import Decimal

        events = self._worker("catalogue", timeout=timeout)
        account = parse_strict_json(events["account_models"])
        if account.get("object") != "list" or not any(row.get("id") == model for row in account["data"]):
            raise ProviderError("model_not_found", submission="not_submitted")
        public = parse_strict_json(events["public_catalogue"])
        matches = [flavor for row in public if row.get("vendor", "").lower() == "nvidia"
                   and row.get("status") == "active" and row.get("license", {}).get("url")
                   for flavor in row.get("flavors", []) if flavor.get("model_id") == model]
        if len(matches) != 1 or not model.startswith("nvidia/"):
            raise ProviderError("model_not_found", submission="not_submitted")
        info = matches[0]
        if (type(info.get("max_model_len")) is not int or info["max_model_len"] != context_tokens
                or info.get("external_provider") is not False
                or Decimal(str(info["input_price_per_million_tokens"])) * 1_000_000 > input_price
                or Decimal(str(info["output_price_per_million_tokens"])) * 1_000_000 > output_price):
            raise ProviderError("invalid_request", submission="not_submitted")
