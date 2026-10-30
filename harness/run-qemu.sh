#!/bin/bash
# Boots a given kernel with the CVE-2026-98432 harness as /init.
#
# Usage: ./run-qemu.sh <path-to-bzImage> [timeout-seconds] [extra /init args...]
#
# Examples:
#   ./run-qemu.sh ../vmlinuz-6.18.55-vuln 600
#   ./run-qemu.sh ../vmlinuz-6.18.55-vuln 60 selftest
#
# Serial console goes to stdout and is also tee'd to qemu.log.
set -euo pipefail
cd "$(dirname "$0")"

if [ $# -lt 1 ]; then
	echo "usage: $0 <path-to-bzImage> [timeout-seconds] [init args...]" >&2
	exit 2
fi

KERNEL=$1
shift
TIMEOUT=${1:-600}
shift || true
INITARGS="$*"

MEM=${MEM:-2048}
SMP=${SMP:-4}

if [ ! -f "$KERNEL" ]; then
	echo "kernel not found: $KERNEL" >&2
	exit 2
fi
if [ ! -f initramfs.cpio.gz ]; then
	echo "initramfs.cpio.gz missing; run ./mkinitramfs.sh first" >&2
	exit 2
fi

ACCEL=()
if [ -w /dev/kvm ]; then
	ACCEL=(-enable-kvm -cpu host)
	echo "# using KVM"
else
	echo "# no writable /dev/kvm, using TCG (slow, expect fewer race windows)"
fi

# shellcheck disable=SC2086
CMDLINE="console=ttyS0 nokaslr panic=-1 $INITARGS"

set +e
timeout --foreground -k 10 "$TIMEOUT" qemu-system-x86_64 \
	"${ACCEL[@]}" \
	-machine q35 \
	-m "$MEM" -smp "$SMP" \
	-kernel "$KERNEL" \
	-initrd initramfs.cpio.gz \
	-append "$CMDLINE" \
	-display none -serial stdio -monitor none \
	-no-reboot 2>&1 | tee qemu.log
rc=${PIPESTATUS[0]}
set -e

echo "# qemu exit=$rc (124 = timeout reached)"
if grep -q "RESULT: KASAN_UAF_DETECTED" qemu.log; then
	echo "# VERDICT: kernel reported the use-after-free"
elif grep -q "RESULT: NO_UAF" qemu.log; then
	echo "# VERDICT: harness finished without a KASAN report"
else
	echo "# VERDICT: inconclusive (no RESULT line; see qemu.log)"
fi
