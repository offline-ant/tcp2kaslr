# harness

The bug trigger. It is one static C program. It runs as `/init` in a tiny
initramfs, so it is PID 1 in the VM. There is no shell, no busybox and no disk.

## What it does

- **victim**: a plain `IPPROTO_TCP` listener on `0.0.0.0:38979`. It accepts, sets
  `SO_LINGER(0)`, and closes at once. That close frees the saved IP options.
- **attacker**: 4 threads. Each sends a SYN with an IPv4 Record Route option to
  `10.N.0.1`, reads the SYNACK, then sends the ACK and a duplicate SYN for the
  same 4-tuple.
- **partner threads**: 4 more. They send the duplicate SYN, so the ACK and the
  SYN are processed on two CPUs at once. One thread alone cannot do this; see
  below.
- **kmsg watcher**: reads `/dev/kmsg`. On a KASAN report it prints
  `RESULT: KASAN_UAF_DETECTED` and powers off.
- **setup**: raises `somaxconn` and `tcp_max_syn_backlog` so the kernel does not
  fall back to SYN cookies mid-run (cookie requests have no saved options), and
  switches MPTCP off, so the run cannot be accused of using it.

## Why tun devices and not loopback

- Loopback runs the receive path in the sender's context. Two packets from one
  thread are handled one after the other, so no race. Two threads are required.
- Each race pair gets its own `tun<N>` with `10.N.0.1/24`. The client address
  `10.N.0.2` is not assigned to anything. So the SYNACK leaves through the device
  and we read it. If the client address were local, the stack would answer the
  SYNACK with an RST and kill the request socket before we could ACK.
- One tun device per pair, because `dup()` of one fd shares one queue. Otherwise
  the readers steal each other's packets.

## Chance of firing

Low. The two reports we have came within the first 200k attempts of their runs,
but later runs of millions of attempts produced nothing. The events cluster, so a
single run is not a measurement. Run it several times.

If it prints nothing, that is **not** evidence that the kernel is safe.

## Build and run

```sh
../scripts/build-harness.sh
../scripts/run.sh vuln 90 selftest     # wiring check only
../scripts/run.sh vuln 600             # expect a KASAN report
```

`run-qemu.sh <kernel> <seconds> [init args]` does the boot. It writes the serial
log to `qemu.log` and prints a verdict at the end.

SMP must be at least 4. Use 8. You need one attacker thread, one partner, one
server thread and one kmsg watcher, and the pairs must not share a CPU.

## Files

| File | What |
|---|---|
| `trigger.c` | the whole trigger |
| `mkinitramfs.sh` | builds `initramfs.cpio.gz` with `/init` only |
| `run-qemu.sh` | boots a kernel with that initramfs |
