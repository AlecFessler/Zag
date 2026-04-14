#!/usr/bin/env bash
# Build a statically-linked arm64 busybox and pack it into rootfs.cpio.gz
# with a minimal /init shell script.
#
# Output: $OUT_DIR/rootfs.cpio.gz
#
# Requires: aarch64-linux-gnu-gcc, make, cpio, gzip, curl, tar.
# See README.md in this directory.

set -euo pipefail

BUSYBOX_VERSION="${BUSYBOX_VERSION:-1.36.1}"
BUSYBOX_TARBALL="busybox-${BUSYBOX_VERSION}.tar.bz2"
BUSYBOX_URL="https://busybox.net/downloads/${BUSYBOX_TARBALL}"
# sha256 of busybox-1.36.1.tar.bz2 (busybox.net).
BUSYBOX_SHA256="${BUSYBOX_SHA256:-b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-${SCRIPT_DIR}/out}"
SRC_DIR="${SRC_DIR:-${SCRIPT_DIR}/src}"
BB_CONFIG="${SCRIPT_DIR}/busybox.config"

export ARCH=arm64
export CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"

mkdir -p "${OUT_DIR}" "${SRC_DIR}"
cd "${SRC_DIR}"

if [ ! -f "${BUSYBOX_TARBALL}" ]; then
    echo "[busybox] fetching ${BUSYBOX_URL}"
    curl -fLO "${BUSYBOX_URL}"
fi

echo "${BUSYBOX_SHA256}  ${BUSYBOX_TARBALL}" | sha256sum -c -

if [ ! -d "busybox-${BUSYBOX_VERSION}" ]; then
    echo "[busybox] extracting"
    tar -xf "${BUSYBOX_TARBALL}"
fi

cd "busybox-${BUSYBOX_VERSION}"

# Start from defconfig, then apply our delta (static linking, drop
# inapplicable applets). Keep it minimal.
make defconfig
./scripts/kconfig/merge_config.sh -m .config "${BB_CONFIG}"
make oldconfig </dev/null

make -j"$(nproc)"
make install  # populates ./_install with the applet tree

# Assemble initramfs root.
ROOT="${SRC_DIR}/initramfs-root"
rm -rf "${ROOT}"
mkdir -p "${ROOT}"/{bin,sbin,etc,proc,sys,dev,usr/bin,usr/sbin}
cp -a _install/. "${ROOT}/"

cat > "${ROOT}/init" <<'EOF'
#!/bin/sh
/bin/mount -t proc  none /proc 2>/dev/null || true
/bin/mount -t sysfs none /sys  2>/dev/null || true
/bin/echo "hello from guest"
# Halt politely if /sbin/poweroff exists, else spin.
if [ -x /sbin/poweroff ]; then
    /sbin/poweroff -f
fi
while :; do /bin/sleep 3600; done
EOF
chmod +x "${ROOT}/init"

# Pack cpio (newc) + gzip.
cd "${ROOT}"
find . -print0 | cpio --null -ov --format=newc | gzip -9 > "${OUT_DIR}/rootfs.cpio.gz"
echo "[busybox] wrote ${OUT_DIR}/rootfs.cpio.gz"
