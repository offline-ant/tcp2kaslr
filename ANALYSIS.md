# Analysis

All of this was done on one machine. Nothing here depends on a CVSS score, a
vendor advisory, or a blog post.

## Result

The bug is reachable on a normal IPv4 TCP listener. MPTCP is not required.

We reproduced it with KASAN on Linux 6.18.55, built from the pristine stable
tarball. The same kernel with the upstream fix is clean.

The KASAN report matches the patch text exactly. A freed `struct ip_options_rcu`
(kmalloc-64) is read by `inet_csk_route_req()`. The child socket that inherited
the pointer is destroyed by the application calling `close()`.

What we proved: the use-after-free is real and a remote peer can trigger it.
We did not try to turn it into root or RCE.

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

## Runs

| Kernel | MPTCP | Attempts | Time | Result |
|---|---|---|---|---|
| 6.18.55, no fix | on, unused | 134,955 | 34 s | KASAN slab-use-after-free |
| 6.18.55, no fix | `net.mptcp.enabled=0` | 191,431 | 80 s | KASAN slab-use-after-free |
| 6.18.55 + fix | on, unused | 439,316 | 411 s | clean |

"Attempts" means: SYNACK received, then ACK and duplicate SYN sent. The accept
count in the logs is the number of children created and closed.

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

Our result does not settle that argument. It shows the race is winnable in a
VM with 8 vCPUs in under a minute, without any special setup. That says the race
is not as hard as the 5.9 score implies, but it is not a measured field result.
