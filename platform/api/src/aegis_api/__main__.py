"""`aegis-api` / `python -m aegis_api`: serve the API with uvicorn."""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys

from aegis_core.errors import AegisError

from .app import TOKEN_ENV_VAR, create_app


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis-api", description="Serve the AEGIS API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    if not _is_loopback(args.host) and not os.environ.get(TOKEN_ENV_VAR):
        print(
            f"error: refusing to listen on non-loopback host {args.host!r} without "
            f"{TOKEN_ENV_VAR} set.",
            file=sys.stderr,
        )
        return 2
    try:
        app = create_app()
    except AegisError as exc:
        print(f"error[{exc.code.value}]: {exc.message}", file=sys.stderr)
        return 3

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
