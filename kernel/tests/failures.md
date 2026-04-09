# Test Failures Log

No known failures.

## Fixed

### §2.6.21 — BSS not decommitted on restart
**Fixed**: `performRestart` now zeroes the partial-page BSS (bytes between data segment end and the next page boundary). These bytes live in the `.preserve` VMM node and were not covered by the `.decommit` BSS node.

### §4.22.6 — `futex_wait` hangs when timed waiter slots exhausted
**Fixed**: `addTimedWaiter` silently dropped the request when all 64 slots were full. The thread was already marked blocked and in the wait bucket, but had no timer — blocking forever. Now returns `E_NORES` and unwinds the block.

### §2.3.3 / §4.10.4 — restart permission check
**Fixed**: The check existed in `sysProcCreate` but root service has restart capability. Tests updated to call `disable_restart` first.

### §2.6.3 / §4.17.5 / §2.11.32 / §2.11.33 — kill() doesn't wake blocked threads
**Fixed**: `Process.kill()` now collects blocked threads, removes them from futex buckets and IPC server wait queues, and deinits them directly.

### §3.10 (was §3.22) — All user faults are non-recursive
**Fixed**: Test was using `revoke_perm` (recursive killSubtree) instead of letting middleman crash via `ud2` (non-recursive fault).
