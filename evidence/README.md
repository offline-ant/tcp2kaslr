# evidence

What each file is, and how it was produced.

| File | What it shows |
|---|---|
| `vuln-6.18.55-kasan.log` | the use-after-free on 6.18.55 with no fix, MPTCP enabled but never used |
| `mptcp-disabled-kasan.log` | the same, with `net.mptcp.enabled=0` |
| `patched-6.18.55-control.log` | the same harness on 6.18.55 plus the fix: 439,316 attempts, no report |
| `kasan-excerpt.txt` | the KASAN report alone, for quoting |
| `build-comparison.txt` | the kernel that fired vs a fresh build from the tarball |
| `source-analysis.md` | an independent read of the vulnerable path, with file and line numbers |

## How the logs were trimmed

The logs are trimmed, not edited. Boot messages and the five-second progress
lines are removed, and KASAN lines are de-duplicated: the harness reads
`/dev/kmsg`, so every KASAN line appears twice in a raw serial capture, once
whole and once cut off mid-line. The report text itself is untouched.

If you want the untrimmed capture, run the harness yourself; it writes
`harness/qemu.log`.

## Reproducing them

```sh
scripts/get-kernel.sh
scripts/build-kernel.sh vuln
scripts/build-harness.sh
scripts/run.sh vuln 600        # the vulnerable run
scripts/build-kernel.sh patched
scripts/run.sh patched 600     # the control run
```

The single run that produced `build-comparison.txt` is described in
`ANALYSIS.md` section 7.
