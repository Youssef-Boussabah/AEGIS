#!/usr/bin/env python3
"""Rootless, reproducible Debian-package tree builder for the AEGIS guest (stdlib only).

No mmdebstrap, no root, no host package changes. It never runs maintainer scripts.

    # 1. fetch (network; needs approval): verified InRelease -> Packages -> .debs into a cache
    python3 -I debpack.py fetch --spec guest-packages.json --cache DIR \\
        --keyring debian-archive.gpg --fingerprint <40-hex> [--fingerprint ...]
    # 2. build (offline): deterministic, root-owned tarball for `mke2fs -d`
    python3 -I debpack.py build --spec guest-packages.json --cache DIR --overlay DIR --out rootfs.tar

Trust chain: gpgv verifies InRelease against an operator-supplied keyring and the
signing key must be one of the --fingerprint values (confirm them against
https://ftp-master.debian.org/keys.html). InRelease pins Packages by SHA-256 and
size; Packages pins every .deb by SHA-256 and size. A mismatch anywhere aborts.

Output tree rules: members sorted, mtimes clamped to SOURCE_DATE_EPOCH, owners
kept from the packages, **all setuid/setgid bits removed**, documentation and
locales dropped, merged-/usr symlinks and the overlay added.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import os
import re
import subprocess
import sys
import tarfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

DROP_PREFIXES = ("./usr/share/doc/", "./usr/share/man/", "./usr/share/info/", "./usr/share/locale/",
                 "./usr/share/lintian/", "./usr/share/bug/")
MERGED_USR = {"./bin": "usr/bin", "./sbin": "usr/sbin", "./lib": "usr/lib", "./lib64": "usr/lib64"}


class BuildError(Exception):
    pass


# ------------------------------------------------------------------ indexes


def gpgv_verify(inrelease: Path, keyring: Path, fingerprints: set[str], gpgv: str = "gpgv") -> bytes:
    """Verify a clearsigned InRelease; return the signed text. The key must be pinned."""
    proc = subprocess.run(
        [gpgv, "--status-fd", "1", "--keyring", str(keyring), str(inrelease)],
        capture_output=True, check=False, shell=False,
    )
    valid = {line.split()[2] for line in proc.stdout.decode(errors="replace").splitlines()
             if line.startswith("[GNUPG:] VALIDSIG ")} if proc.returncode == 0 else set()
    if not valid & {f.upper() for f in fingerprints}:
        raise BuildError("InRelease is not signed by a pinned key")
    return _clearsigned_body(inrelease.read_bytes())


def _clearsigned_body(data: bytes) -> bytes:
    text = data.decode("utf-8")
    start = text.index("-----BEGIN PGP SIGNED MESSAGE-----")
    body_start = text.index("\n\n", start) + 2
    end = text.index("\n-----BEGIN PGP SIGNATURE-----", body_start)
    lines = text[body_start:end].split("\n")
    return "\n".join(line[2:] if line.startswith("- ") else line for line in lines).encode("utf-8") + b"\n"


def parse_stanzas(text: str) -> list[dict[str, str]]:
    stanzas, current, last = [], {}, None
    for line in text.splitlines():
        if not line.strip():
            if current:
                stanzas.append(current)
            current, last = {}, None
        elif line[0] in " \t" and last:
            current[last] += "\n" + line.strip()
        else:
            key, _, value = line.partition(":")
            current[key] = value.strip()
            last = key
    if current:
        stanzas.append(current)
    return stanzas


def release_sha256(release: bytes) -> dict[str, tuple[str, int]]:
    [stanza] = parse_stanzas(release.decode("utf-8"))[:1]
    entries = {}
    for line in stanza.get("SHA256", "").splitlines():
        parts = line.split()
        if len(parts) == 3:
            entries[parts[2]] = (parts[0], int(parts[1]))
    return entries


def check_digest(data: bytes, sha256: str, size: int, what: str) -> None:
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise BuildError(f"{what} does not match its pinned digest")


# --------------------------------------------------------------- resolution


@dataclass
class Index:
    packages: dict[str, dict[str, str]] = field(default_factory=dict)
    provides: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_text(cls, text: str) -> Index:
        index = cls()
        for st in parse_stanzas(text):
            name = st["Package"]
            index.packages.setdefault(name, st)
            for prov in _names(st.get("Provides", "")):
                index.provides.setdefault(prov, []).append(name)
        return index


def _names(field_value: str) -> list[str]:
    return [re.split(r"[\s(:]", alt.strip(), maxsplit=1)[0]
            for part in field_value.split(",") for alt in [part.split("|")[0]] if alt.strip()]


def _alternatives(field_value: str) -> list[list[str]]:
    groups = []
    for part in field_value.split(","):
        alts = [re.split(r"[\s(:]", a.strip(), maxsplit=1)[0] for a in part.split("|") if a.strip()]
        if alts:
            groups.append(alts)
    return groups


def resolve(index: Index, roots: list[str], exclude: set[str]) -> list[str]:
    """Dependency closure over Pre-Depends and Depends, first satisfiable alternative,
    virtual packages via Provides. Excluded names are never pulled in."""
    chosen: list[str] = []
    seen: set[str] = set()
    stack = list(reversed(roots))
    while stack:
        name = stack.pop()
        if name in seen or name in exclude:
            continue
        stanza = index.packages.get(name)
        if stanza is None:
            providers = [p for p in index.provides.get(name, []) if p not in exclude]
            if not providers:
                raise BuildError(f"unsatisfiable dependency {name}")
            stack.append(sorted(providers)[0])
            continue
        seen.add(name)
        chosen.append(name)
        for key in ("Pre-Depends", "Depends"):
            for alts in _alternatives(stanza.get(key, "")):
                if any(a in seen for a in alts):
                    continue
                pick = next((a for a in alts if a not in exclude and (a in index.packages or a in index.provides)),
                            None)
                if pick is None:
                    if all(a in exclude for a in alts):
                        continue
                    raise BuildError(f"unsatisfiable dependency {'|'.join(alts)} of {name}")
                stack.append(pick)
    return sorted(chosen)


# --------------------------------------------------------------------- .deb


def deb_data(deb: bytes) -> tarfile.TarFile:
    """The data.tar.* member of an ar archive, opened for reading."""
    if not deb.startswith(b"!<arch>\n"):
        raise BuildError("not a Debian package")
    offset = 8
    while offset + 60 <= len(deb):
        header = deb[offset:offset + 60]
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58].decode().strip())
        body = deb[offset + 60:offset + 60 + size]
        if name.startswith("data.tar"):
            if name.endswith(".xz"):
                body = lzma.decompress(body)
            elif name.endswith(".zst"):
                from compression import zstd  # Python 3.14+

                body = zstd.decompress(body)
            elif name != "data.tar":
                raise BuildError(f"unsupported data member {name}")
            return tarfile.open(fileobj=io.BytesIO(body), mode="r:")
        offset += 60 + size + (size & 1)
    raise BuildError("no data member")


@dataclass
class TreeStats:
    members: int = 0
    setid_stripped: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)


def build_tar(debs: list[bytes], overlay: Path | None, out: Path, epoch: int,
              extra_symlinks: dict[str, str] | None = None) -> TreeStats:
    stats = TreeStats()
    members: dict[str, tuple[tarfile.TarInfo, bytes | None]] = {}

    def add(info: tarfile.TarInfo, data: bytes | None) -> None:
        name = "./" + info.name.lstrip("./") if info.name not in (".", "./") else "."
        if any(name.startswith(p) for p in DROP_PREFIXES):
            return
        if name in members:
            if not info.isdir():
                stats.duplicates.append(name)
            return
        if info.mode & 0o6000:
            stats.setid_stripped.append(name)
            info.mode &= ~0o6000
        info.name = name
        info.mtime = min(int(info.mtime), epoch)
        members[name] = (info, data)

    for deb in debs:
        with deb_data(deb) as tar:
            for info in tar.getmembers():
                data = tar.extractfile(info).read() if info.isfile() else None
                add(info, data)
    for link, target in {**MERGED_USR, **(extra_symlinks or {})}.items():
        info = tarfile.TarInfo(link)
        info.type, info.linkname, info.mode, info.mtime = tarfile.SYMTYPE, target, 0o777, epoch
        add(info, None)
    for directory, mode in (("./proc", 0o555), ("./sys", 0o555), ("./dev", 0o755), ("./run", 0o755),
                            ("./tmp", 0o1777), ("./scratch", 0o755)):
        info = tarfile.TarInfo(directory)
        info.type, info.mode, info.mtime = tarfile.DIRTYPE, mode, epoch
        add(info, None)
    if overlay is not None:
        for path in sorted(Path(overlay).rglob("*")):
            rel = "./" + path.relative_to(overlay).as_posix()
            info = tarfile.TarInfo(rel)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = epoch
            if path.is_symlink():
                info.type, info.linkname, info.mode = tarfile.SYMTYPE, os.readlink(path), 0o777
                data = None
            elif path.is_dir():
                info.type, info.mode, data = tarfile.DIRTYPE, 0o755, None
            else:
                data = path.read_bytes()
                info.size, info.mode = len(data), 0o755 if os.access(path, os.X_OK) else 0o444
            members.pop(rel, None)  # the overlay wins over packages
            add(info, data)
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tar:
        for name in sorted(members):
            info, data = members[name]
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
            stats.members += 1
    return stats


def tree_file(tar_path: Path, path: str, max_links: int = 8) -> tuple[str, bytes]:
    """Resolve ``path`` (absolute, inside the tree) through symlinks; return (real path, bytes)."""
    with tarfile.open(tar_path, "r:") as tar:
        names = {m.name: m for m in tar.getmembers()}
        current = "./" + path.lstrip("/")
        for _ in range(max_links):
            member = names.get(current)
            if member is None:
                raise BuildError(f"{path} not in tree")
            if member.issym():
                target = member.linkname
                base = os.path.dirname(current)
                current = "./" + os.path.normpath(target.lstrip("/") if target.startswith("/")
                                                  else os.path.join(base[2:], target))
                continue
            return "/" + current[2:], tar.extractfile(member).read()
    raise BuildError("too many symlinks")


# ---------------------------------------------------------------------- CLI


def _spec(path: Path) -> dict:
    return json.loads(path.read_text())


def cmd_fetch(args: argparse.Namespace) -> None:  # pragma: no cover - network, needs approval
    spec = _spec(args.spec)
    if not re.fullmatch(r"\d{8}T\d{6}Z", spec["snapshot"]):
        raise BuildError("pin a snapshot.debian.org timestamp in the spec first")
    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    base = f"{spec['mirror']}/{spec['snapshot']}"
    dist = f"{base}/dists/{spec['suite']}"

    def get(url: str) -> bytes:
        with urllib.request.urlopen(url, timeout=120) as response:
            return response.read()

    inrelease = cache / "InRelease"
    inrelease.write_bytes(get(f"{dist}/InRelease"))
    release = gpgv_verify(inrelease, Path(args.keyring), set(args.fingerprint))
    entries = release_sha256(release)
    rel = f"main/binary-{spec['architecture']}/Packages.xz"
    packages_xz = get(f"{dist}/{rel}")
    check_digest(packages_xz, *entries[rel], rel)
    (cache / "Packages.xz").write_bytes(packages_xz)
    index = Index.from_text(lzma.decompress(packages_xz).decode("utf-8"))
    for name in resolve(index, spec["packages"], set(spec["exclude"])):
        st = index.packages[name]
        target = cache / Path(st["Filename"]).name
        if not target.exists():
            data = get(f"{base}/{st['Filename']}")
            check_digest(data, st["SHA256"], int(st["Size"]), name)
            target.write_bytes(data)


def cmd_build(args: argparse.Namespace) -> None:
    spec = _spec(args.spec)
    cache = Path(args.cache)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", spec["source_date_epoch"]))
    index = Index.from_text(lzma.decompress((cache / "Packages.xz").read_bytes()).decode("utf-8"))
    names = resolve(index, spec["packages"], set(spec["exclude"]))
    debs = []
    for name in names:
        st = index.packages[name]
        data = (cache / Path(st["Filename"]).name).read_bytes()
        check_digest(data, st["SHA256"], int(st["Size"]), name)
        debs.append(data)
    stats = build_tar(debs, Path(args.overlay) if args.overlay else None, Path(args.out), epoch,
                      spec.get("symlinks"))
    sys.stdout.write(json.dumps({"packages": names, "members": stats.members,
                                 "setid_stripped": stats.setid_stripped, "duplicates": stats.duplicates,
                                 "tar_sha256": hashlib.sha256(Path(args.out).read_bytes()).hexdigest()},
                                indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="debpack.py")
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--spec", type=Path, required=True)
    fetch.add_argument("--cache", type=Path, required=True)
    fetch.add_argument("--keyring", type=Path, required=True)
    fetch.add_argument("--fingerprint", action="append", required=True)
    build = sub.add_parser("build")
    build.add_argument("--spec", type=Path, required=True)
    build.add_argument("--cache", type=Path, required=True)
    build.add_argument("--overlay", type=Path)
    build.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        {"fetch": cmd_fetch, "build": cmd_build}[args.command](args)
    except BuildError as exc:
        sys.stderr.write(f"debpack: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
