#!/usr/bin/env bash
# Reproducible, rootless guest-kernel build. NOT RUN in this revision; network fetch needs approval.
# The toolchain comes from a pinned Debian tree (debpack.py, builder-packages.json) used inside bwrap,
# so the host needs no new packages (it lacks `bc`, which the kernel build requires).
#
#   KVER=6.1.<latest> KSHA=<sha256 of linux-$KVER.tar.xz> FCCFG_SHA=<sha256 of the Firecracker config> \
#   KEYRING=debian-archive.gpg FPR=<Debian signing key> core/guest/build-guest-kernel.sh OUT_DIR
#
# KSHA must come from kernel.org's signed sha256sums.asc (verify with gpgv against the stable
# maintainer's key, fingerprint confirmed at https://www.kernel.org/signature.html).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?output directory}
: "${KVER:?}" "${KSHA:?}" "${FCCFG_SHA:?}" "${KEYRING:?}" "${FPR:?}"
[[ $KVER =~ ^6\.1\.[0-9]+$ ]] || { echo "KVER must be a 6.1.y release" >&2; exit 2; }
SPEC=$HERE/builder-packages.json
EPOCH=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_date_epoch"])' "$SPEC")
mkdir -p "$OUT/cache" "$OUT/builder" "$OUT/src"

# Fetch (network): kernel source, Firecracker's v1.17.0 6.1 guest config, builder packages.
curl -fsSL --proto '=https' -o "$OUT/linux-$KVER.tar.xz" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz"
echo "$KSHA  $OUT/linux-$KVER.tar.xz" | sha256sum -c -
curl -fsSL --proto '=https' -o "$OUT/microvm.config" \
  "https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.17.0/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config"
echo "$FCCFG_SHA  $OUT/microvm.config" | sha256sum -c -
python3 -I "$HERE/debpack.py" fetch --spec "$SPEC" --cache "$OUT/cache" --keyring "$KEYRING" --fingerprint "$FPR"

# Offline from here.
python3 -I "$HERE/debpack.py" build --spec "$SPEC" --cache "$OUT/cache" --out "$OUT/builder.tar" > "$OUT/builder.json"
tar -xf "$OUT/builder.tar" -C "$OUT/builder"
tar -xf "$OUT/linux-$KVER.tar.xz" -C "$OUT/src" --strip-components=1
cp "$OUT/microvm.config" "$OUT/src/.config"
cp "$HERE/aegis-kernel.fragment" "$OUT/src/aegis-kernel.fragment"
TS=$(date -u -d "@$EPOCH" '+%Y-%m-%d %H:%M:%S UTC')

bwrap --unshare-all --die-with-parent --new-session --uid 0 --gid 0 \
  --bind "$OUT/builder" / --bind "$OUT/src" /build --dev /dev --proc /proc --tmpfs /tmp \
  --clearenv --setenv PATH /usr/bin --setenv LANG C --setenv HOME /tmp \
  --setenv KBUILD_BUILD_TIMESTAMP "$TS" --setenv KBUILD_BUILD_USER aegis --setenv KBUILD_BUILD_HOST aegis \
  --chdir /build -- /usr/bin/sh -c \
  'scripts/kconfig/merge_config.sh -m .config aegis-kernel.fragment && make olddefconfig && make -j"$(nproc)" vmlinux'

python3 -I "$HERE/kernel_config_check.py" "$OUT/src/.config" "$HERE/aegis-kernel.fragment"
install -m 0444 "$OUT/src/vmlinux" "$OUT/vmlinux-$KVER"
sha256sum "$OUT/vmlinux-$KVER"
