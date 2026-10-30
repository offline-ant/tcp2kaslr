#!/bin/bash
# Compiles harness/trigger.c to a static /init and packs the initramfs.
set -euo pipefail
cd "$(dirname "$0")/../harness"

gcc -Wall -Wextra -O2 -pthread -static -o init trigger.c
./mkinitramfs.sh
