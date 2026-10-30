# CVE-2026-98432: full analysis

This is a plain-language report of what we did and what we found. Every number
here came from our own test kernel, not from a score or an advisory.

Short version: the use-after-free is real, a plain IPv4 TCP listener reaches it,
and MPTCP is not needed. The race is hard to win. Our measured rates are upper
bounds, for reasons explained at the end.

## 1. What the bug is

A TCP server gets a SYN. The SYN carries an IPv4 option: Record Route or
Timestamp. The kernel copies those options into a new object and stores it on the
request socket (`ireq->ireq_opt`).

A retransmitted SYN for the same connection arrives. The kernel builds a SYNACK
for it, and that code reads the saved options. It only holds `rcu_read_lock()`.

At the same time the third ACK finishes the handshake. The child socket takes
over the same pointer. Nothing is copied. Then `ireq->ireq_opt` is cleared.

The application accepts the child and closes it. Child sockets are not
`SOCK_RCU_FREE`, and `inet_sock_destruct()` frees the options with plain
`kfree()`.

The SYNACK builder is still reading that memory. That is the bug.

## 2. The source path

Plain `IPPROTO_TCP` listener, IPv4, peer SYN with a Record Route option:

1. `tcp_conn_request()` → `tcp_v4_route_req()` → `tcp_v4_save_options()`.
   `__ip_options_echo()` allocates `ireq->ireq_opt` from the SYN options.
2. Retransmitted SYN: `tcp_check_req()` → `tcp_rtx_synack()` →
   `tcp_v4_send_synack()` → `inet_csk_route_req()`. This reads the pointer.
3. Handshake completes: `tcp_v4_syn_recv_sock()` moves the same pointer into
   `newinet->inet_opt` and clears `ireq->ireq_opt`.
4. The app closes the child: `inet_sock_destruct()` → `kfree()`
   (`net/ipv4/af_inet.c:159` in 6.18.55).
5. Step 2 is still reading.

Nothing here involves MPTCP, IPv6, or an unusual option type. A second reviewer
went through the same path independently; that write-up is in
`evidence/source-analysis.md`, with file and line numbers.

## 3. Why MPTCP is not the trigger

The public write-up said the exploit targeted servers with a multipath TCP
listener. People read that as "MPTCP is required". It is not:

- The code path above is the ordinary TCP path. MPTCP has no role in it.
- Our runs use a plain `IPPROTO_TCP` listener. No MPTCP socket is created.
- In one run we also set `net.mptcp.enabled=0` and the bug still fires.
- On an MPTCP listener, a SYN without `MP_CAPABLE` falls back to plain TCP and
  then goes through the same `tcp_v4_syn_recv_sock()` transfer.

We also tested whether MPTCP is *easier* (section 6). It is not.

## 4. How we test it

We build 6.18.55 from the stable tarball with KASAN. Then we boot it in QEMU with
a tiny initramfs. The only program in the VM is our harness, which runs as
`/init`.

The harness does two jobs:

- **Victim.** A plain TCP listener. It accepts a child, sets `SO_LINGER(0)` and
  closes it at once. That close is what frees the options.
- **Attacker.** Builds IPv4/TCP packets by hand. It sends a SYN with a Record
  Route option, reads the SYNACK, then sends the completing ACK and a duplicate
  SYN for the same 4-tuple at the same time, from two threads on two vCPUs.

The KASAN report is read from `/dev/kmsg`. A lost race does not crash the
machine, so the loop simply tries again.

### Four traps we hit

These cost most of the time. They are worth writing down, because anyone who
tries this will meet them.

1. **Loopback cannot race.** On loopback the receive path runs in the sender's
   context. Two packets from one thread are handled one after the other. They
   are never concurrent. You need two threads on two vCPUs.

2. **A local spoofed address kills the handshake.** If every address is local,
   the local stack receives our SYNACK, finds no socket for it, and answers with
   an RST. That RST destroys the request socket before our ACK arrives, so the
   handshake never completes. A real remote attacker has no such local stack.
   Fix: put the peer on `tun<N>` with client address `10.N.0.2`, which is not
   assigned to anything. SYNACKs then leave through the device and we read them.

3. **`dup()` of one tun fd shares one queue.** Every reader then steals the
   packets meant for the others, and throughput falls to about 0.5 attempts per
   second. Give each race pair its own tun device.

4. **SYN cookies.** After a few minutes of a few thousand SYNs per second the
   kernel logs `Possible SYN flooding ... Sending cookies`. Cookie requests never
   allocate `ireq_opt`, so the vulnerable path is gone. The harness raises
   `somaxconn` and `tcp_max_syn_backlog` at startup, which is what real servers
   run with, to stay on the vulnerable path.

## 5. Results

### 5.1 The bug fires under KASAN

| Kernel | MPTCP | Attempts | Time | Result |
|---|---|---:|---:|---|
| 6.18.55, no fix | on, unused | 134,955 | 34 s | KASAN slab-use-after-free |
| 6.18.55, no fix | `net.mptcp.enabled=0` | 191,431 | 80 s | KASAN slab-use-after-free |
| 6.18.55 + fix | on, unused | 439,316 | 411 s | clean |

The KASAN report names exactly the code in section 2:

```
BUG: KASAN: slab-use-after-free in inet_csk_route_req
Read of size 1 at addr ffff888007d70f9c by task init/118

Call Trace:
 inet_csk_route_req
 tcp_v4_send_synack
 tcp_rtx_synack
 tcp_check_req
 tcp_v4_rcv

Allocated by task 114:
 tcp_v4_route_req
 tcp_conn_request

Freed by task 110:
 kfree
 inet_sock_destruct
 __sk_destruct
 inet_release
 sock_close
```

The freed object is in `kmalloc-64`, and the read is at offset 28, which is the
options length field.

Related evidence:

- `evidence/vuln-6.18.55-kasan.log` - this run, trimmed to the report.
- `evidence/mptcp-disabled-kasan.log` - the run with `net.mptcp.enabled=0`.
- `evidence/patched-6.18.55-control.log` - the same harness on a kernel with the
  fix: no report.
- `evidence/kasan-excerpt.txt` - the report alone, no surrounding noise.

The logs are trimmed, not rewritten: boot messages and the five-second progress
lines are removed, and the KASAN lines that the harness echoes from `/dev/kmsg`
are de-duplicated. Nothing in the reports is edited.

### 5.2 How often it fires

Honest answer: it is rare, and it comes in bursts.

- The two KASAN reports came early, within the first 200k attempts of their runs.
- On a normal (non-KASAN) kernel we could only observe *consequences* of the
  race, not the race itself. In unpublished work we watched the freed object get
  reused and its bytes come back in a SYNACK. We saw this twice, and both events
  fell inside the **same five-second window**, after 3.29M clean attempts.
- Adding every run on a normal kernel together: **about 48.3M attempts, two
  events, both in that one window.** That is 4e-8 per attempt, which is a bound,
  not a rate.

So the process is not steady. It clusters. Any single number is a poor summary,
and a short run proves nothing either way.

What we can say:

- The rate is low. Order 1e-7 per attempt at the very best in our harness.
- It is bursty, so a fixed rate model is wrong.

### 5.3 MPTCP does not make it easier

Linux falls back to plain TCP when a SYN arrives at an MPTCP listener without
`MP_CAPABLE`. So the attacker packets can stay identical; only the listening
socket changes. We ran MPTCP and plain TCP alternately, to cancel host-load
drift:

| Round | Mode | Attempts | attempts/s | Events |
|---|---|---:|---:|---:|
| 1 | MPTCP | 5,803,429 | 24,200 | 0 |
| 1 | plain TCP | 3,304,597 | 13,800 | 0 |
| 2 | MPTCP | 4,657,067 | 19,400 | 0 |
| 2 | plain TCP | 5,466,421 | 22,800 | 0 |

MPTCP: 10.46M attempts, 0 events. Plain TCP: 8.77M, 0 events. The throughput
difference flips between rounds, so it is host load, not the protocol.

With no events in 10.46M attempts, the 95% upper bound for MPTCP is about
2.9e-7 per attempt. We can exclude a large difference (100x or more). We cannot
resolve a small one.

## 6. What limits our numbers

Every rate here is a best case for the attacker. Read these before quoting.

**We force the concurrency.** The race needs the completing ACK and the
retransmitted SYN to be processed on two CPUs at the same time. Our harness pins
them to two vCPUs, so that always happens. On real hardware, NIC receive hashing
sends both packets of one flow to the *same* CPU by default, where they are
handled in order and no race is possible at all. This inflates our rate.

**Our server closes instantly.** There is no work between `accept()` and
`close()`. Most real servers do some work first, which delays the free and makes
the race much harder. This also inflates our rate.

**KASAN widens the window.** Instrumented code is slower, so the reader stays in
the window longer. The KASAN runs are for detection, not for rates.

**The host mattered.** We measured attempts per second from 816 to 33,600
depending on thread layout and host load. A naive layout is 40x slower than a
tuned one. Anyone comparing numbers across machines must control for this.

**Preemption alone did not help.** The kernel is `PREEMPT(voluntary)`, so the
only way a reader can be parked mid-window is the hypervisor not scheduling that
vCPU. We sampled the guest's `steal` time every 2 s and ran with the host
oversubscribed (load 29 on 16 cores, about 40% of vCPU time stolen, peaks of
20.8 s per 2 s window). Result: 0 events in 4.86M attempts, and throughput just
halved. So load in general is not the trigger for the bursts. We do not yet know
what is.

## 7. Is a given kernel fixed?

Version numbers are not proof. Look at the binary.

`scripts/check-free-sites.py` reads `/proc/kallsyms`, works out the KASLR slide,
extracts the running image, and disassembles the two free sites:
`inet_sock_destruct()` and `tcp_v4_reqsk_destructor()`.

- Fixed: both call `kvfree_call_rcu`.
- Vulnerable: both call `kfree`.

Result on our machine (6.18.59_1):

```
inet_sock_destruct: kvfree_call_rcu
tcp_v4_reqsk_destructor: kvfree_call_rcu
VERDICT: fixed
```

We also checked that our own two builds are the same code: the kernel that fired
and a fresh build from the tarball differ in 40 bytes out of 96 MB, none of them
inside `.text`, and all six functions on the path are byte-identical
(`evidence/build-comparison.txt`).

## 8. Exposure and mitigation

A host is exposed if it listens on IPv4 TCP, the peer sends a SYN with IP
options, and the program closes the accepted socket soon. The attacker controls
the second point, so "we do not use MPTCP" is not a defence.

- Best fix: update the kernel. The fix is small: the two frees become
  `kfree_rcu()`.
- If you cannot patch: drop inbound SYN packets that carry IP options. Then the
  options object is never allocated. Validate the filter for fragments and for
  every ingress path.
- `accept_source_route=0` is not this filter. It only blocks source routing.

## 9. What we did not do

This repository stops at the use-after-free. It does not contain a KASLR leak, a
write primitive, or a root exploit, and it does not show one end to end.

One result from the private work is worth stating, because it bears on severity:
the freed object can be reclaimed, and its bytes then come back to the peer in
the SYNACK. We observed that twice on a kernel without KASAN. That is the
disclosure primitive, not a KASLR break: the bytes we caused to be copied were
bytes we had put there ourselves, and no kernel address was ever produced.

We did examine the write side in the source, and it is worth knowing about for
severity: `ip_options_build()` has no bounds checks. It copies `opt->optlen`
bytes from the freed object into the SYNACK, and when `srr` is set it writes four
attacker-chosen bytes at an offset computed from two bytes of the freed object.
Any such write needs the same race win and the same reuse of the freed slot as
the read, so it cannot be more likely than the read.

## 10. Notes on the scores

The kernel CVE team says 9.8 with low attack complexity. Red Hat, Oracle and SUSE
say 8.1 with high complexity. Ubuntu gives high priority with no fixed package at
the time of writing.

Our data supports "hard to win". It does not support "low complexity". But it
also does not support treating this as a minor issue: the precondition is just an
exposed IPv4 TCP port, the fix is one line, and until it is applied any
connection attempt can try to win the race again.

The two claims we can settle from our own work:

- "MPTCP only" is wrong. A plain TCP listener is vulnerable.
- "MPTCP makes it much easier" is unsupported. We tested it.
