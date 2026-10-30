#!/usr/bin/env bash
# Reproducible, rootless build of the AEGIS candidate guest image. NOT RUN in this revision.
# Needs no host package changes: python3 (stdlib), gpgv and mke2fs with libarchive (all present).
# The fetch step needs network access and operator approval.
#
#   KEYRING=debian-archive.gpg FPR=<40-hex signing key> core/guest/build-guest-image.sh OUT_DIR
#
# 1. Pin "snapshot" in guest-packages.json. 2. Confirm FPR at https://ftp-master.debian.org/keys.html.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$HERE/../src/aegis_core
OUT=${1:?output directory}
: "${KEYRING:?operator-supplied Debian archive keyring}" "${FPR:?pinned signing key fingerprint}"
SPEC=$HERE/guest-packages.json
EPOCH=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_date_epoch"])' "$SPEC")
export SOURCE_DATE_EPOCH=$EPOCH
mkdir -p "$OUT/cache" "$OUT/overlay/opt/aegis" "$OUT/overlay/usr/sbin" "$OUT/overlay/etc/aegis"

python3 -I "$HERE/debpack.py" fetch --spec "$SPEC" --cache "$OUT/cache" --keyring "$KEYRING" --fingerprint "$FPR"

cp "$SRC/lab_guest_agent.py" "$SRC/lab_vm_protocol.py" "$OUT/overlay/opt/aegis/"
cp "$HERE/aegis-init" "$OUT/overlay/usr/sbin/aegis-init"          # /sbin -> usr/sbin
chmod 0444 "$OUT"/overlay/opt/aegis/*.py; chmod 0755 "$OUT/overlay/usr/sbin/aegis-init"
printf 'root:x:0:0:root:/nonexistent:/nonexistent\nrunner:x:1000:1000::/scratch:/nonexistent\n' \
  > "$OUT/overlay/etc/passwd"
printf 'root:x:0:\nrunner:x:1000:\n' > "$OUT/overlay/etc/group"

# Pass 1: find the real compiler and its digest; pass 2: embed them as /etc/aegis/guest.json.
python3 -I "$HERE/debpack.py" build --spec "$SPEC" --cache "$OUT/cache" --overlay "$OUT/overlay" \
  --out "$OUT/pass1.tar" > /dev/null
python3 -I - "$OUT/pass1.tar" "$OUT/overlay/etc/aegis/guest.json" "$HERE" <<'PY'
import hashlib, json, re, sys
sys.path.insert(0, sys.argv[3])
import debpack
real, data = debpack.tree_file(sys.argv[1], "/usr/bin/gcc")
version = re.search(r"gcc-(\d+)$", real) or re.search(r"(\d+)$", real)
json.dump({"compiler": {"name": "gcc", "version": version.group(1) if version else "unknown", "path": real,
                        "sha256": hashlib.sha256(data).hexdigest()}}, open(sys.argv[2], "w"), sort_keys=True)
PY
python3 -I "$HERE/debpack.py" build --spec "$SPEC" --cache "$OUT/cache" --overlay "$OUT/overlay" \
  --out "$OUT/rootfs.tar" > "$OUT/build.json"
rm -f "$OUT/pass1.tar"

# Deterministic ext4: fixed UUID and hash seed, no journal; read-only afterwards.
rm -f "$OUT/rootfs.ext4"
E2FSPROGS_FAKE_TIME=$EPOCH mkfs.ext4 -q -F -d "$OUT/rootfs.tar" -L aegis-guest -O ^has_journal \
  -U 6f1a3c52-5a1e-4b6e-9a0d-0a3e6c1b7a10 -E hash_seed=0b5c7d2e-9f40-4b8a-8e33-2b1e2a6f4c01,root_owner=0:0 \
  "$OUT/rootfs.ext4" 1G
chmod 0444 "$OUT/rootfs.ext4"

python3 -I - "$OUT" "$SRC/lab_guest_agent.py" <<'PY'
import hashlib, json, sys
out, agent = sys.argv[1], sys.argv[2]
digest = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
guest = json.load(open(f"{out}/overlay/etc/aegis/guest.json"))["compiler"]
build = json.load(open(f"{out}/build.json"))
manifest = {"rootfs_sha256": digest(f"{out}/rootfs.ext4"), "guest_agent_sha256": digest(agent),
            "compiler_name": guest["name"], "compiler_version": guest["version"], "compiler_sha256": guest["sha256"],
            "rootfs_tar_sha256": build["tar_sha256"], "packages": build["packages"],
            "setid_stripped": build["setid_stripped"]}
json.dump(manifest, open(f"{out}/guest-manifest.json", "w"), indent=2, sort_keys=True)
print(json.dumps({k: manifest[k] for k in ("rootfs_sha256", "guest_agent_sha256", "compiler_version",
                                           "compiler_sha256")}, indent=2))
PY
