## Conclusion

**The underlying use-after-free is reachable through ordinary IPv4 TCP listeners. MPTCP is not a prerequisite.** This follows from the downloaded **Linux 6.18.55** source, independently of any published severity score.

This does **not** establish reliable remote code execution against every ordinary TCP service. It establishes a shared vulnerable lifetime/ownership path; actual exploitation additionally depends on packet reachability, concurrency, child-socket destruction timing, and memory reuse.

All paths below are relative to the 6.18.55 source tree (`linux/`). Source was not modified.

### Ordinary TCP path

| Stage | Source evidence |
|---|---|
| Ordinary TCP selects this implementation | `net/ipv4/af_inet.c:1152–1156` registers `SOCK_STREAM` / `IPPROTO_TCP` with `tcp_prot`. `net/ipv4/tcp_ipv4.c:2538` installs `ipv4_specific`, whose callbacks at **2497–2498** are `tcp_v4_conn_request` and `tcp_v4_syn_recv_sock`. |
| Listener receives a SYN | `net/ipv4/tcp_input.c:6959–6979` handles `TCP_LISTEN`, calling `icsk_af_ops->conn_request`. `net/ipv4/tcp_ipv4.c:1735–1743` dispatches to generic `tcp_conn_request`. |
| Request and options allocation | `net/ipv4/tcp_input.c:7457` allocates the request; **7488** calls its IPv4 routing/initialization callback. `net/ipv4/tcp_ipv4.c:1681–1704` initializes `ireq->ireq_opt` using `tcp_v4_save_options`. |
| Options come from incoming IPv4 headers | `include/net/tcp.h:2650–2666` allocates an options object when incoming `optlen` is nonzero and fills it using `__ip_options_echo`. `net/ipv4/ip_options.c:92–141` handles Record Route and Timestamp options. **These are IPv4 options, not TCP timestamp options.** |
| Request becomes independently discoverable | `net/ipv4/inet_connection_sock.c:1173–1187` inserts the request into the established hash table and initializes its reference count. `net/ipv4/tcp_input.c:7567–7575` invokes that path for normal, non-cookie requests. |
| Retransmitted SYN reads options | `net/ipv4/tcp_minisocks.c:726–765` recognizes a retransmitted SYN and calls `tcp_rtx_synack`. `net/ipv4/tcp_output.c:4575–4586` invokes the IPv4 `send_synack` callback. `net/ipv4/tcp_ipv4.c:1221–1226` reads `ireq_opt` inside an RCU read-side section and passes it to `ip_build_and_send_pkt`. |
| Handshake completion transfers ownership | `net/ipv4/tcp_minisocks.c:921–922` creates the child through `syn_recv_sock`. `net/ipv4/tcp_ipv4.c:1788–1789` assigns **the same options pointer**, without copying, to `newinet->inet_opt`. After winning ownership, **1842–1846** clears `ireq->ireq_opt`. |
| Child destruction immediately frees options | `net/ipv4/af_inet.c:159` uses plain `kfree(inet->inet_opt)`. `net/ipv4/inet_connection_sock.c:1257–1258` explicitly clears `SOCK_RCU_FREE` on TCP children. Thus RCU readers do not prevent this free. |

### Why locking and references do not save it

* **Request processing is not serialized by the listener lock.** In `net/ipv4/tcp_ipv4.c:2263–2336`, `TCP_NEW_SYN_RECV` packets go directly to `tcp_check_req`, before the normal socket-lock acquisition at **2376**.
* Hash lookup takes a reference to **the request**, not the future child: `net/ipv4/inet_hashtables.c:547–557`.
* Keeping that request alive does not keep the transferred options alive. Once ownership transfers, the child owns them and the request pointer is cleared.
* Clearing the request pointer cannot invalidate a pointer already loaded by another CPU.
* `inet_csk_complete_hashdance` drops the request from the pending queue at `net/ipv4/inet_connection_sock.c:1431–1435`. The drop synchronizes with the **request timer** using `timer_delete_sync` at **1032**, but does not wait for independently executing receive-side `tcp_check_req` calls.

Consequently, one CPU can already be building a retransmission reply using the options while another completes the handshake and the resulting child is subsequently destroyed.

### Can an ordinary TCP child actually be freed independently?

Yes, although **a remote reset alone does not necessarily immediately free an unaccepted child**.

The ordinary accept path retrieves `req->sk` and drops the queue’s request reference independently: `net/ipv4/inet_connection_sock.c:679–681,726–727`. A concurrent receive-side reference can keep the old request alive without pinning the accepted child.

Normal child teardown includes:

* `net/ipv4/tcp.c:3154–3176`: already-reset sockets, closing with unread data, and zero-linger handling.
* `net/ipv4/tcp.c:3203–3284`: orphaning and destruction of closed sockets.
* `net/ipv4/tcp.c:3292–3299`: `tcp_close` drops its final socket reference.
* `net/ipv4/inet_connection_sock.c:1290–1309`: child destruction drops another reference.
* `include/net/sock.h:1975–1978`: the final reference calls `sk_free`.
* `net/core/sock.c:2386–2398`: without `SOCK_RCU_FREE`, destruction can execute immediately.

Therefore ordinary application accept/close behavior can provide the required destruction side. **The narrow race and service-dependent teardown timing remain significant caveats; this analysis does not measure their practical exploitability.**

### Resulting unsafe accesses

`net/ipv4/ip_output.c:161` reads the options length when reserving header space; **186–188** rereads it and invokes `ip_options_build`.

`net/ipv4/ip_options.c:49–50` copies the options metadata and then copies option bytes using `opt->optlen`. Further fields control header writes at **53–65**.

After the object is freed/reused, these accesses can consume stale or changed lengths and offsets. The source supports a memory-safety vulnerability, **not a claim that every race produces disclosure, corruption, or RCE**.

### Scope and operational caveats

* **Not “every TCP socket”:** the demonstrated entry point is incoming IPv4 connection establishment to a listener, involving saved IP options and overlapping request processing/child destruction. It is not a demonstrated attack on arbitrary existing or outbound-only TCP sockets.
* **MPTCP disabled is not a complete mitigation.** None of the essential paths above requires MPTCP.
* `accept_source_route=0` is insufficient: `net/ipv4/ip_input.c:293–308` applies that gate to source routing, not Record Route or Timestamp options.
* Reliably preventing incoming IPv4 options from reaching affected listeners removes the options allocation used by this path. Any filtering mitigation needs separate validation, including fragmentation and alternate ingress paths.
* Native IPv6 uses duplicated options at `net/ipv6/tcp_ipv6.c:1489–1494`, avoiding this ownership-transfer mechanism. **Dual-stack listeners receiving IPv4 are not excluded:** **1417–1420** dispatch IPv4 packets to `tcp_v4_syn_recv_sock`.
* Enabling SYN cookies normally does not mean every connection uses them; the ordinary request path remains active. See `net/ipv4/tcp_input.c:7443–7449`.
* The separate request-migration lifetime issue is not necessary for the ordinary child-transfer path established here.

**Parent-facing recommendation:** do not classify unpatched ordinary IPv4 TCP servers as unaffected merely because they lack MPTCP. Prioritize patching or restricting the vulnerable ingress path; source analysis alone cannot justify either universal emergency shutdown or a universal assurance of safety. Also, the previously reported running version `6.18.59_1` is suggestive, not verification that the deployed kernel contains the fix.