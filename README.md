# CVE-2026-98432: a normal TCP server is vulnerable. MPTCP is not the trigger.

This repo shows one thing. A plain IPv4 TCP server reaches the
use-after-free in CVE-2026-98432. You do not need MPTCP. Many reports said MPTCP
was the trigger. That is wrong.

We did not take this from a CVSS score or a blog post. We built the kernel from
the release tarball and made the bug happen.

## The short answer

| Kernel | MPTCP | Attempts | Time | Result |
|---|---|---:|---:|---|
| 6.18.55, no fix | not used | 134,955 | 34 s | **KASAN use-after-free** |
| 6.18.55, no fix | switched off | 191,431 | 80 s | **KASAN use-after-free** |
| 6.18.55 + fix | not used | 439,316 | 411 s | clean |

The listener in every run is a normal `IPPROTO_TCP` socket. No MPTCP socket is
ever created. In the second run MPTCP is also switched off in the kernel.

The race is hard to win. See `ANALYSIS.md` for the real numbers and for the
limits of our measurement.

## What the bug is, in plain words

A TCP server gets a SYN. The SYN carries an IPv4 option (Record Route or
Timestamp). The kernel saves those options in the request socket.

Then a second SYN for the same connection arrives. The kernel builds a SYNACK
and reads the saved options.

At the same time the handshake finishes. The child socket gets **the same
pointer**, not a copy. The server closes the child. The kernel frees the options
with plain `kfree()`.

The SYNACK code is still reading that memory. That is the use-after-free.

## What this PoC is and is not

It is a **bug trigger**. It shows the kernel reads freed memory. KASAN is the
judge. It is not an exploit. It does not leak addresses, does not write memory
and does not get root.

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
The VM uses 2 GB RAM and 8 vCPUs; the host needs about 16 cores to keep the
timing realistic.

**Because the race is rare, one run may show nothing.** That is not evidence that
the kernel is safe. Run it several times, and read the caveats in `ANALYSIS.md`
before you quote any rate.

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

The attacker controls point 2. So most internet servers are exposed. Saying "we
do not use MPTCP" does not help.

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
| `evidence/` | KASAN report, run logs, build comparison |

## Scope

Test kernels only, and only ones you own. Nothing here should be pointed at
systems you do not control.

## Licence

MIT for our code and text. `patches/` contains a Linux kernel commit and stays
under GPL-2.0. See `LICENSE`.
