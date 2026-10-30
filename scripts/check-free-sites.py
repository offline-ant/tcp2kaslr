#!/usr/bin/env python3
"""Check whether a running kernel carries the CVE-2026-98432 fix.

Looks at the two free sites named in the patch and reports which function they
call: plain kfree (vulnerable) or kvfree_call_rcu (fixed).

Usage: scripts/check-free-sites.py [image]

Default image is /boot/vmlinuz-$(uname -r). Needs linux/scripts/extract-vmlinux,
which comes with the kernel source (scripts/get-kernel.sh).
"""
import bisect
import os
import re
import subprocess
import sys
import tempfile

LINK_BASE = 0xFFFFFFFF81000000
TARGETS = ("inet_sock_destruct", "tcp_v4_reqsk_destructor")


def kallsyms() -> list[tuple[int, str]]:
    syms: list[tuple[int, str]] = []
    with open("/proc/kallsyms") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                syms.append((int(parts[0], 16), parts[2]))
    syms.sort()
    return syms


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = os.environ.get("KERNEL_SRC", os.path.join(root, "linux"))
    image = sys.argv[1] if len(sys.argv) > 1 else f"/boot/vmlinuz-{os.uname().release}"
    extract = os.path.join(src, "scripts", "extract-vmlinux")
    if not os.path.exists(extract):
        sys.exit(f"missing {extract}; run scripts/get-kernel.sh first")

    syms = kallsyms()
    addrs: list[int] = [a for a, _ in syms]
    by_name: dict[str, int] = {}
    for a, n in syms:
        by_name.setdefault(n, a)

    if "_text" not in by_name or by_name["_text"] == 0:
        sys.exit("cannot read /proc/kallsyms addresses (try as root, or kptr_restrict)")

    slide: int = by_name["_text"] - LINK_BASE
    print(f"running kernel: {os.uname().release}   slide={slide:#x}")
    print(f"image:          {image}")

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        vmlinux = tmp.name
    try:
        with open(vmlinux, "wb") as out:
            subprocess.run([extract, image], stdout=out, check=True)

        verdicts: dict[str, list[str]] = {}
        for name in TARGETS:
            if name not in by_name:
                print(f"{name}: not in kallsyms")
                continue
            start = by_name[name]
            end = addrs[bisect.bisect_right(addrs, start)]
            dis = subprocess.run(
                ["objdump", "-d", f"--start-address={start - slide:#x}",
                 f"--stop-address={end - slide:#x}", vmlinux],
                capture_output=True, text=True).stdout
            called: set[str] = set()
            for line in dis.splitlines():
                m = re.search(r"\b(call|jmp)\s+0x([0-9a-f]+)", line)
                if m:
                    tgt = int(m.group(2), 16) + slide
                    i = bisect.bisect_right(addrs, tgt) - 1
                    called.add(syms[i][1] if i >= 0 else "?")
            free = sorted(n for n in called if "rcu" in n or n.startswith("kfree"))
            verdicts[name] = free
            print(f"{name}: {', '.join(free) if free else 'no free call found'}")

        patched = all(
            any("rcu" in n for n in verdicts.get(t, [])) for t in TARGETS
        )
        print()
        print("VERDICT: fixed (kvfree_call_rcu)" if patched
              else "VERDICT: does NOT look fixed (plain kfree) - investigate")
    finally:
        os.unlink(vmlinux)


if __name__ == "__main__":
    main()
