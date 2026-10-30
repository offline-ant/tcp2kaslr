# Analysis

All of this was done on one machine. Nothing here depends on a CVSS score, a
vendor advisory, or a blog post.

## Result

The bug is reachable on a normal IPv4 TCP listener. MPTCP is not required.

We reproduced it with KASAN on Linux 6.18.55, built from the pristine stable
tarball. The same kernel with the upstream fix did not produce a report.

The KASAN report matches the patch text exactly. A freed `struct ip_options_rcu`
(kmalloc-64) is read by `inet_csk_route_req()`. The child socket that inherited
the pointer is destroyed by the application calling `close()`.

What we proved: the use-after-free is real and a remote peer can trigger it.
This repository stops at the use-after-free. Turning it into disclosure, a
controlled write, or root is out of scope here and is not done in this repo.

Note on the rates below: they also depend on how fast the victim application
accepts and closes the child, not just on the kernel. A server that does real
work between accept() and close() is much harder to hit than the test server
here, which closes instantly. Treat every number below as a best-case bound.

## Source path

Plain `IPPROTO_TCP` listener. IPv4. The peer SYN carries a Record Route option.

1. `tcp_conn_request()` -> `tcp_v4_route_req()` -> `tcp_v4_save_options()`.
   `__ip_options_echo()` allocates `ireq->ireq_opt` from the SYN options.
2. A retransmitted SYN hits `tcp_check_req()` -> `tcp_rtx_synack()` ->
   `tcp_v4_send_synack()` -> `inet_csk_route_req()`. This reads the pointer, with
   only `rcu_read_lock()` held.
3. At the same time the third ACK finishes the handshake.
   `tcp_v4_syn_recv_sock()` moves the same pointer into `newinet->inet_opt`. It
   does not copy. It then clears `ireq->ireq_opt`.
4. The program accepts the child and closes it. TCP children are not
   `SOCK_RCU_FREE`. `inet_sock_destruct()` frees the option with plain `kfree()`
   (`net/ipv4/af_inet.c:159` in 6.18.55).
5. Step 2 is still reading that memory.

No MPTCP. No IPv6. No unusual option type.

## Harness design

- Victim: plain listener. `accept()`, then `SO_LINGER(0)` and `close()` at once.
  The child dies fast, so the free comes quickly.
- Attacker: builds IPv4/TCP by hand. Sends SYN with a Record Route option, reads
  the SYNACK, then sends the ACK and a duplicate SYN for the same 4-tuple at the
  same time, from two threads on two vCPUs. The spin delay is swept.
- The KASAN report is read from `/dev/kmsg`. A lost race does not crash the
  machine, so the loop just retries.

Nothing else is added. There is no heap shaping, no extra protocol, no special
socket option. The PoC stays close to a normal client and a normal server.

### Three traps we hit

These cost most of the time. Write them down.

1. **Loopback cannot race.** On loopback the receive path runs in the sender's
   context. Two packets from one thread are handled in order. Never concurrent.
   Use two threads on two vCPUs.

2. **A local spoofed address kills the handshake.** With all addresses local, the
   sniffed SYNACK is delivered to the local stack. No socket matches it. The
   stack answers with an RST. That RST destroys the request socket before the
   ACK arrives, so the handshake never completes and the bug is out of reach.
   A real remote attacker has no such local stack.
   Fix: put the peer on `tun<N>`, client `10.N.0.2`, never assigned anywhere.
   SYNACKs then leave through the device instead of being delivered locally.

3. **`dup()` of one tun fd shares one queue.** Every sniffer thread then steals
   the other threads' SYNACKs. Throughput drops to about 0.5 attempts/s.
   Give each race pair its own tun device.

### One trap in the run, not the code

After a few minutes at a few thousand SYN/s the kernel logs
`Possible SYN flooding ... Sending cookies`. Cookie requests never allocate
`ireq_opt`, so the vulnerable path disappears and the run stops being useful.
The harness now raises `somaxconn` and `tcp_max_syn_backlog` at startup, which is
what a real server runs with, so the run stays on the vulnerable path.

## How often it fires

This is the honest part.

| Kernel | MPTCP | Attempts | Time | Result |
|---|---|---|---|---|
| 6.18.55, no fix | on, unused | 134,955 | 34 s | KASAN slab-use-after-free |
| 6.18.55, no fix | `net.mptcp.enabled=0` | 191,431 | 80 s | KASAN slab-use-after-free |
| 6.18.55 + fix | on, unused | 439,316 | 411 s | clean |
| 6.18.55, no fix | on, unused | 413,369 | 300 s | no report |
| 6.18.55, no fix | on, unused | 728,627 | 600 s | no report |

Both successes came early, inside the first 200k attempts. Later runs of similar
size found nothing. The per-attempt chance is therefore very small, on the order
of one in a million, and a single run is close to a coin flip.

Why it is so rare: the reader has only a short window between loading the pointer
and using it. The free needs the handshake to finish, the accept queue to be
served, and `close()` to run, all inside that window. The kernel is
`PREEMPT(voluntary)`, so the reader cannot be preempted in the window by guest
scheduling. Only the hypervisor can park that vCPU, which is why the result moves
around between hosts and boots.

This does not weaken the finding. A rare race that a remote peer can retry
forever is still a real bug. It does mean the PoC is not a reliable alarm: if it
prints nothing, that is not evidence of safety.

## The two builds are the same code

To rule out "the rebuild behaves differently", we compared the binary that fired
against a fresh build from the tarball:

- 40 differing bytes in the whole 96 MB image.
- All of them outside `.text`.
- Every function on the path is byte-identical: `inet_sock_destruct`,
  `tcp_v4_reqsk_destructor`, `tcp_v4_syn_recv_sock`, `tcp_v4_send_synack`,
  `tcp_rtx_synack`, `ip_options_build`.

So the difference between a run that fires and one that does not is scheduling,
not code. See `evidence/build-comparison.txt`.

## KASAN report

```
BUG: KASAN: slab-use-after-free in inet_csk_route_req+0x9f9/0xa80
Read of size 1 at addr ffff888007d70f9c by task init/118

Call Trace:
 inet_csk_route_req
 tcp_v4_send_synack
 tcp_rtx_synack
 tcp_check_req
 tcp_v4_rcv

Allocated by task 114:
 __kmalloc_noprof
 tcp_v4_route_req
 tcp_conn_request

Freed by task 110:
 kfree
 inet_sock_destruct
 __sk_destruct
 inet_release
 __sock_release
 sock_close
 __x64_sys_close

The buggy address belongs to the object at ffff888007d70f80
 which belongs to the cache kmalloc-64 of size 64
The buggy address is located 28 bytes inside of
 freed 64-byte region [ffff888007d70f80, ffff888007d70fc0)
```

Offset 28 in a 64-byte object is the options length field. The read has size 1.
That is the "attacker-controlled length" primitive used for the KASLR leak in
the public writeup. Full log: `evidence/vuln-6.18.55-stress.log`.

## Is a given kernel fixed?

Version numbers are not proof. Look at the two free sites in the binary.

`scripts/check-free-sites.py` does this. It reads symbols from `/proc/kallsyms`,
works out the KASLR slide, extracts the image, disassembles both functions, and
reports the callee.

Patched: `inet_sock_destruct` and `tcp_v4_reqsk_destructor` use
`kvfree_call_rcu`. Vulnerable: they use `kfree`.

Result for this machine, 6.18.59_1:

```
inet_sock_destruct: kvfree_call_rcu
tcp_v4_reqsk_destructor: kvfree_call_rcu
VERDICT: fixed
```

## Exposure and mitigation

A host is exposed if:

- it listens on IPv4 TCP, and
- the peer's SYN carries IP options, and
- the program closes the accepted socket quickly.

The attacker controls the second point. So most servers are exposed, and
"no MPTCP" does not help.

To reduce risk before patching: drop inbound SYNs that carry IP options, at the
edge or on the host. Then `ireq_opt` is never allocated. Note that
`accept_source_route=0` is not this filter. It only blocks source routing.

## Notes on scores

Red Hat, Oracle and SUSE score 8.1. The kernel CVE team says 9.8. Ubuntu says
priority High and has no fixed package. The difference is attack complexity:
Red Hat says the race is hard to win.

Our result agrees that the race is hard. It is not 9.8 in practice. But it is
also not unreachable, and the precondition is only "an exposed IPv4 TCP port".
The 5.9 rating is about difficulty, not about who is exposed.
