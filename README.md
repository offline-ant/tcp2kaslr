# CVE-2026-98432: it is not an MPTCP bug

A small proof of concept. It shows that a normal IPv4 TCP server reaches the bug.
MPTCP is not needed. Many people said MPTCP is the trigger. That is wrong.

## What this PoC is

It is a **bug trigger, not an exploit**. It answers one question:

> Can a plain `IPPROTO_TCP` IPv4 listener reach the use-after-free, with no MPTCP?

KASAN is the judge. When the kernel reads freed memory, KASAN prints a report and
the harness stops.

Not in scope, and not attempted: KASLR leak, heap shaping, control-flow hijack,
running a command. So this proves the bug is real and reachable on stock TCP. It
says nothing about how easy the full exploit is.

## Result

| Kernel | MPTCP | Attempts | Time | Result |
|---|---|---|---|---|
| 6.18.55, no fix | not used | 134,955 | 34 s | **KASAN use-after-free** |
| 6.18.55, no fix | switched off | 191,431 | 80 s | **KASAN use-after-free** |
| 6.18.55 + fix | not used | 439,316 | 411 s | clean |

In no run did the guest create an MPTCP socket. The listener is a plain
`IPPROTO_TCP` socket.

**The race is hard to win.** It fired twice. Later runs of several hundred
thousand attempts found nothing. That is expected, not a defect. A run of a few
minutes is roughly a coin flip. See `ANALYSIS.md` for the numbers.

## What the bug is

A TCP server gets a SYN. The SYN has an IPv4 option (Record Route or Timestamp).
The kernel saves the option in the request socket.

A second SYN for the same connection arrives. The kernel builds a SYNACK. It
reads the saved option.

At the same time the handshake finishes. The child socket gets the same option
pointer, not a copy. The server closes the child. The memory is freed with plain
`kfree()`.

The SYNACK code still reads that memory. That is the use-after-free.

## Reproduce

```sh
scripts/get-kernel.sh              # linux/ (tarball, verified by sha256)
scripts/build-kernel.sh vuln       # KASAN kernel, no fix
scripts/build-kernel.sh patched    # KASAN kernel, with fix
scripts/build-harness.sh           # harness/init + initramfs
scripts/run.sh vuln 300            # expect KASAN
scripts/run.sh patched 300         # expect nothing
```

`scripts/run.sh vuln 90 selftest` only checks the wiring. Run that first.

Needs: gcc, make, bison, flex, bc, qemu-system-x86_64, KVM if you have it, and
about 2 GB RAM for the VM. `SMP=8` is the tested setting. Do not lower it.

Because the race is rare, run it more than once. Each boot is a fresh try.

## Check your own kernel

Do not trust the version number. Look at the code in the binary.

```sh
scripts/check-free-sites.py
```

It reads the two free sites from the running kernel and shows which function
they call: `kfree` (bad) or `kvfree_call_rcu` (good).

On this machine (6.18.59_1) both sites use `kvfree_call_rcu`. It is fixed.

## Who is exposed

- inbound IPv4 TCP on a listening socket, and
- the peer sends SYN with IP options, and
- the program closes the accepted socket soon.

That is most internet servers. An attacker can add the IP option, so
"we do not use MPTCP" is not a defence.

`accept_source_route=0` does not help. That sysctl is about source routing only.
To block the bug you must drop SYNs that carry any IP option. Patching is better.

## Files

| Path | What |
|---|---|
| `ANALYSIS.md` | source path, design choices, hit statistics, KASAN report |
| `harness/trigger.c` | the PoC (static `/init`, runs in QEMU) |
| `patches/` | the upstream fix, used for the control build |
| `evidence/` | run logs, KASAN report, byte-identical build check |
| `scripts/` | get, build, run, and check helpers |
