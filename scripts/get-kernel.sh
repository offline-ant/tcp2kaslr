#!/bin/bash
# Gets the kernel source for CVE-2026-98432 into ./linux
#
# Two ways: git submodule (full tree, slow) or the release tarball (fast).
# The tarball is the default. It is the same code.
set -euo pipefail
cd "$(dirname "$0")/.."

TARBALL=linux-6.18.55.tar.xz
SHA256=f410638061a165c12f42ab871d2f3fcd525515359b5faeee80969cff84524df9
URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/$TARBALL"

if [ -f linux/Makefile ] && grep -q '^SUBLEVEL = 55$' linux/Makefile 2>/dev/null; then
	echo "kernel source already present in linux/"
	exit 0
fi

mkdir -p linux

if [ "${USE_SUBMODULE:-0}" = "1" ]; then
	echo "== git submodule =="
	git submodule update --init --depth 1 linux
else
	echo "== tarball =="
	if [ ! -f "$TARBALL" ]; then
		curl -fLO "$URL"
	fi
	echo "$SHA256  $TARBALL" | sha256sum -c -
	tar xf "$TARBALL" -C linux --strip-components=1
fi

echo "kernel source ready in linux/: $(grep -m1 '^SUBLEVEL' linux/Makefile)"
