#!/bin/bash
# Builds initramfs.cpio.gz from trigger.c. The result is a kernel-with-no-
# userspace setup: /init is the harness itself, statically linked.
set -euo pipefail
cd "$(dirname "$0")"

CFLAGS=(-Wall -Wextra -O2 -pthread -static)

echo "== compile =="
gcc "${CFLAGS[@]}" -o init trigger.c
file init
ls -l init

echo "== initramfs =="
rm -rf root initramfs.cpio.gz
mkdir -p root
cp init root/init
chmod 0755 root/init
( cd root && find . -print0 | cpio --null -o -H newc --quiet ) | gzip -9 > initramfs.cpio.gz
rm -rf root

ls -l initramfs.cpio.gz
echo "== contents =="
zcat initramfs.cpio.gz | cpio -tv --quiet
echo "DONE"
