# harness

The PoC. One static C program. It is the `/init` of a tiny initramfs, so it runs
as PID 1 in QEMU. No shell, no busybox, no disk.

## Parts

- **victim**: plain `IPPROTO_TCP` listener on `0.0.0.0:38979`.
  It accepts, sets `SO_LINGER(0)`, and closes at once. This is the free side.
- **attacker**: 4 threads. Each one sends a SYN with an IPv4 Record Route option
  to `10.N.0.1`, reads the SYNACK, then sends the ACK and a duplicate SYN for the
  same 4-tuple at the same time.
- **partner threads**: 4 more. They send the duplicate SYN, so the ACK and the
  SYN land on two CPUs at once. One thread alone cannot do this (see below).
- **kmsg watcher**: reads `/dev/kmsg`. On a KASAN report it prints
  `RESULT: KASAN_UAF_DETECTED` and powers off.

## Why tun devices

- Loopback runs the receive path in the sender's context. Two packets from one
  thread are handled one after the other. No race. So each attempt uses two
  threads.
- Each race pair gets its own `tun<N>` with `10.N.0.1/24`. The client address
  `10.N.0.2` is not assigned to anything. So the SYNACK leaves through the
  device and we read it. If the client address were local, the stack would
  answer the SYNACK with an RST and kill the request socket.
- One tun device per pair, because `dup()` of one fd shares one queue. All
  sniffers would fight over the same packets.

## Build and run

```sh
../scripts/build-harness.sh
../scripts/run.sh vuln 300
../scripts/run.sh vuln 90 selftest     # wiring check only
```

`run-qemu.sh <kernel> <seconds> [init args]` does the boot. It writes the serial
log to `qemu.log` and prints a verdict.

SMP must be at least 4. Use 8. One attacker thread, one partner, one server
thread, one kmsg watcher.

## Files

| File | What |
|---|---|
| `trigger.c` | the whole PoC |
| `mkinitramfs.sh` | builds `initramfs.cpio.gz` with `/init` only |
| `run-qemu.sh` | boots a kernel with that initramfs |
