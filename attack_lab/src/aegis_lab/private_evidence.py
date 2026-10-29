"""Private, bounded content-addressed evidence; never an attacker workspace."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .safe_io import publish_new_file, read_regular_file

MAX_BLOB_BYTES = 64 * 1024 * 1024


class PrivateEvidence:
    def __init__(self, root: Path, *, create: bool = True):
        self.root = Path(root)
        if create:
            self.root.mkdir(mode=0o700)
        st = self.root.lstat()
        if not self.root.is_dir() or self.root.is_symlink() or st.st_mode & 0o077:
            raise ValueError("private_directory_required")
        self._identity = (st.st_dev, st.st_ino)

    def _check(self):
        st = self.root.lstat()
        if self.root.is_symlink() or (st.st_dev, st.st_ino) != self._identity or st.st_mode & 0o077:
            raise ValueError("private_directory_replaced")

    def put(self, data: bytes) -> str:
        if type(data) is not bytes or len(data) > MAX_BLOB_BYTES:
            raise ValueError("private_blob_too_large")
        self._check()
        digest = hashlib.sha256(data).hexdigest()
        path = self.root / digest
        if os.path.lexists(path):
            if self.get(digest) != data:
                raise ValueError("private_blob_conflict")
        else:
            publish_new_file(path, data, MAX_BLOB_BYTES)
        return digest

    def get(self, digest: str) -> bytes:
        import re

        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid_blob_digest")
        self._check()
        data = read_regular_file(self.root / digest, MAX_BLOB_BYTES)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("private_blob_digest_mismatch")
        return data
