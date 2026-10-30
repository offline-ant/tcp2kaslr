#!/bin/bash
# Builds a KASAN kernel from ./linux
#
#   scripts/build-kernel.sh vuln      -> out/vmlinuz-vuln    (no fix)
#   scripts/build-kernel.sh patched   -> out/vmlinuz-patched (with fix)
#
# The fix is patches/0001-*.patch. It is applied only for "patched", and it is
# reverted again afterwards, so ./linux stays pristine.
set -euo pipefail
cd "$(dirname "$0")/.."

VARIANT=${1:-vuln}
case "$VARIANT" in
vuln | patched) ;;
*)
	echo "usage: $0 vuln|patched" >&2
	exit 2
	;;
esac

SRC=${KERNEL_SRC:-linux}
PATCH=$(ls patches/0001-*.patch)
JOBS=${JOBS:-$(nproc)}

[ -f "$SRC/Makefile" ] || {
	echo "no kernel source; run scripts/get-kernel.sh" >&2
	exit 2
}
mkdir -p out

applied=0
cleanup() {
	if [ "$applied" = 1 ]; then
		patch -R -p1 -d "$SRC" <"$PATCH" >/dev/null
	fi
}
trap cleanup EXIT

if [ "$VARIANT" = patched ]; then
	patch -p1 -d "$SRC" --dry-run <"$PATCH" >/dev/null
	patch -p1 -d "$SRC" <"$PATCH" >/dev/null
	applied=1
	echo "applied $(basename "$PATCH")"
fi

# KASAN is the detector. TUN is needed by the harness. MPTCP stays on to show
# that it is not used.
make -C "$SRC" defconfig >/dev/null
"$SRC/scripts/config" --file "$SRC/.config" \
	--enable KASAN --enable KASAN_GENERIC --enable KASAN_INLINE \
	--enable KALLSYMS_ALL --enable MPTCP --enable TUN
make -C "$SRC" olddefconfig >/dev/null

for k in KASAN KASAN_GENERIC MPTCP TUN SMP; do
	printf '%-14s %s\n' "$k" "$(grep -m1 "^CONFIG_$k=" "$SRC/.config" || echo '(unset!)')"
done

make -C "$SRC" -j"$JOBS" >"out/build-$VARIANT.log" 2>&1
cp "$SRC/arch/x86/boot/bzImage" "out/vmlinuz-$VARIANT"
echo "built out/vmlinuz-$VARIANT"
