#!/bin/bash
# Boots a kernel with the harness as /init.
#
#   scripts/run.sh vuln 300              -> expect KASAN use-after-free
#   scripts/run.sh patched 300           -> expect no KASAN
#   scripts/run.sh vuln 90 selftest      -> only check the harness wiring
set -euo pipefail
cd "$(dirname "$0")/.."

VARIANT=${1:-vuln}
SECS=${2:-300}
shift 2 || true

case "$VARIANT" in
vuln) KERNEL=out/vmlinuz-vuln ;;
patched) KERNEL=out/vmlinuz-patched ;;
*) KERNEL=$VARIANT ;;
esac

[ -f "$KERNEL" ] || {
	echo "no kernel at $KERNEL; run scripts/build-kernel.sh $VARIANT" >&2
	exit 2
}

SMP=${SMP:-8} exec harness/run-qemu.sh "$KERNEL" "$SECS" "$@"
