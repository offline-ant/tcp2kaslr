# CVE-2026-98432

_Written by DeepSeek._

**A plain IPv4 TCP server is vulnerable. MPTCP is not the trigger.**

We built Linux 6.18.55 from the release tarball and made the kernel read freed
memory on a normal `IPPROTO_TCP` listener. KASAN reported it twice. No MPTCP
socket was ever created, and one run had MPTCP switched off in the kernel.

The same bug makes the kernel copy bytes out of a freed object into the reply it
sends back. That is the primitive a KASLR break needs, and we have observed it
happen in unpublished work. We did **not** build a kernel-address leak, and we
did **not** prove a write.

What is proven here, with code and logs: the use-after-free is real, stock TCP
reaches it, and the upstream fix stops it.

## The runs

| Kernel | MPTCP | Attempts | Time | Result |
|---|---|---:|---:|---|
| 6.18.55, no fix | not used | 134,955 | 34 s | **KASAN use-after-free** |
| 6.18.55, no fix | switched off | 191,431 | 80 s | **KASAN use-after-free** |
| 6.18.55 + fix | not used | 439,316 | 411 s | clean |

## How hard is it to hit?

Very hard. With KASAN the reader is slow, so the bug shows up within a few
hundred thousand attempts. On a normal kernel it is far rarer: across about
**48 million attempts we saw two events, both inside the same five seconds**.

That is too few to state a rate. The most we will claim is a bound of roughly
`1e-7` per attempt, and even that is a best case, because our harness forces the
two packets onto two CPUs and a real NIC usually sends one flow to one CPU.

So a clean run does **not** mean a safe kernel. Read `ANALYSIS.md` sections 5.2
and 6 before quoting any number.

## The bug in plain words

A TCP server gets a SYN. The SYN carries an IPv4 option (Record Route or
Timestamp). The kernel saves those options on the request socket.

A second SYN for the same connection arrives. The kernel builds a SYNACK for it
and reads the saved options.

At the same time the handshake finishes. The child socket gets **the same
pointer**, not a copy. The server closes the child, and the kernel frees the
options with plain `kfree()`.

The SYNACK code is still reading that memory. That is the use-after-free. The
same read is what puts freed bytes into the packet.

## What this repo is not

It is a **bug trigger**, not an exploit. It does not leak kernel addresses, does
not write kernel memory, and does not get root. It shows the kernel reading freed
memory; KASAN is the judge.

The repo stops there on purpose. Later stages were worked on privately and are
not published here.

## Reproduce it

```sh
scripts/get-kernel.sh              # fetch 6.18.55, sha256 checked, into linux/
scripts/build-kernel.sh vuln       # KASAN kernel, no fix
scripts/build-kernel.sh patched    # KASAN kernel, with the fix
scripts/build-harness.sh           # builds harness/init + initramfs
scripts/run.sh vuln 90 selftest    # checks the wiring only
scripts/run.sh vuln 600            # expect a KASAN report
scripts/run.sh patched 600         # expect nothing
```

You need gcc, make, bison, flex, bc and `qemu-system-x86_64`. KVM helps a lot.
The VM takes 2 GB RAM and 8 vCPUs.

**One run may show nothing.** That is not evidence of a safe kernel. Run it
several times, and read the caveats in `ANALYSIS.md`.

## Check your own kernel

Do not trust the version string. Look at the code in the binary.

```sh
scripts/check-free-sites.py
```

It finds the two free sites in the running kernel and shows which function they
call: `kfree` (bad) or `kvfree_call_rcu` (fixed).

On the machine this was written on (6.18.59_1) both sites use
`kvfree_call_rcu`, so that kernel is fixed.

## Who is exposed

A host is exposed if all three are true:

1. it listens on IPv4 TCP, and
2. the peer sends a SYN with IP options, and
3. the program closes the accepted socket soon.

The attacker controls point 2. So most internet servers are exposed, and "we do
not use MPTCP" does not help.

Two notes:

- `accept_source_route=0` does **not** protect you. It only blocks source
  routing, not Record Route or Timestamp.
- If you cannot patch yet, drop inbound SYNs that carry IP options. Then the
  kernel never saves options for the request socket. Patching is better.

## Files

| Path | What |
|---|---|
| `ANALYSIS.md` | the full report: source path, method, results, limits |
| `harness/` | the bug trigger that runs as `/init` in QEMU |
| `patches/` | the upstream fix, used for the control build |
| `scripts/` | fetch, build, run and check helpers |
| `evidence/` | KASAN reports, run logs, build comparison |

## Scope

Test kernels only, and only ones you own. Nothing here should be pointed at
systems you do not control.

## Licence

MIT for our code and text. `patches/` contains a Linux kernel commit and stays
under GPL-2.0. See `LICENSE`.
