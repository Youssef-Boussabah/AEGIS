"""Exception type carrying a stable, machine-readable error code."""

from __future__ import annotations

from typing import Any

from .models import ErrorCode, ErrorInfo


class AegisError(Exception):
    def __init__(self, code: ErrorCode, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_info(self) -> ErrorInfo:
        return ErrorInfo(code=self.code, message=self.message, details=self.details)

    @classmethod
    def from_info(cls, info: ErrorInfo) -> AegisError:
        return cls(info.code, info.message, dict(info.details))

    def __str__(self) -> str:
        return f"{self.code.value}: {self.message}"
