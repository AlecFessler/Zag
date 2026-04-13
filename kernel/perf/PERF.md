# Kernel Performance Testing

## Quick Start

```bash
# Run all perf benchmarks (sequential, ~10 min with RUNS=3)
./test.sh perf

# Results are written to kernel/perf/perf_results/latest.txt
# Auto-compares against baseline if perf_baseline.txt exists
# Shows top 10 most expensive operations at the end
```

## Agent Optimization Workflow

```bash
# 1. Capture baseline (if not already set)
./test.sh perf
cp kernel/perf/perf_results/latest.txt kernel/perf/perf_baseline.txt

# 2. Make a kernel change (e.g., optimize scheduler path)
# ... edit kernel code ...

# 3. Re-run benchmarks — auto-compares against baseline
./test.sh perf
# Exits non-zero if any `min` metric regressed >20% AND >200 cycles

# 4. Run correctness gate
PARALLEL=8 ./test.sh pre-commit

# 5. Commit if improved and passing
```

## Framework Design

### Multi-run with mean-of-min aggregation

Each benchmark runs N times (default 3, set via `RUNS=5 ./test.sh perf`).
Within each run, `bench.zig` takes the minimum of 10k internal samples
(robust to interrupts/cache pollution since noise only pushes samples
*upward*). The runner then averages those mins across N runs, reducing
inter-run KVM jitter by ~√N.

### Why `min`, not `median`

Every source of KVM noise (host scheduler preemption, cache eviction by
neighbors, VM-exit jitter) makes measurements *slower*. The minimum
represents the fastest observed path, which is lower-bounded by the
actual code cost. Median is affected by noise at every percentile,
making it 2-3x noisier than min in practice.

### Regression threshold: 20% + 200 cycles (both required)

- **20%**: Matches observed KVM-guest run-to-run noise (nested virt has
  10-20% inherent jitter). Real kernel-code regressions typically show
  at 25-50%+.
- **200 cycles absolute floor**: Prevents false positives on very cheap
  ops where rdtscp precision (~40 cycles) dominates. Without it,
  `ioport_write` (546 cycles) would flag at +42 cycles as "+7%".

A lower threshold (e.g. 5%) would require bare-metal runs or N=20+ with
statistical significance testing — too expensive for CI.

### QEMU pinning

Runner uses `taskset -c 0-3` to pin QEMU's 4 vCPU threads to specific
host cores. Without this, the host scheduler migrates QEMU across cores
between runs, polluting cache state and adding ~5-7% jitter.

## Output Format

All benchmarks emit machine-parseable `[PERF]` lines:
```
[PERF] bench_name metric=value unit
```

Metrics per benchmark: `min`, `median`, `mean`, `p99`, `max`, `stddev`, `iterations`.
The profiler emits `[PROF]` lines with sampled RIP addresses and hit counts.

## Resolving Profiler Symbols

```bash
# Auto-runs after perf suite; can also run manually:
kernel/perf/resolve_symbols.sh kernel/perf/perf_results/latest.txt kernel/perf/bin/perf_profiler.elf
```

Requires `addr2line`. Adjusts for ASLR using `load_base` from profiler output.

## Benchmark Inventory

| Bench | What it measures | Key metric |
|-------|-----------------|------------|
| `perf_syscall_yield` | Null syscall floor | ~68K cycles |
| `perf_syscall_micro` | 25 individual syscalls | varies |
| `perf_clock_gettime` | HPET read path | ~38K cycles |
| `perf_ctx_switch` | Scheduler yield pair (2 switches) | ~134K cycles |
| `perf_thread_create` | Thread lifecycle | ~400K cycles |
| `perf_ipc` | Cross-process IPC (4 variants) | 31-220K cycles |
| `perf_cap_lookup` | Cap table scan (valid vs bogus) | 4-5K cycles |
| `perf_futex` | Futex paths (4 variants) | 4-95K cycles |
| `perf_mem_reserve` | Page alloc + demand fault | 12-13K cycles |
| `perf_mem_perms` | TLB shootdown (1 + 4 pages) | 33-98K cycles |
| `perf_shm_cycle` | SHM create/map/unmap/full | 9-75K cycles |
| `perf_pmu_self` | PMU start+stop cold (MSR path) | ~37K cycles |
| `perf_profiler` | Sampling profiler self-test | [PROF] output |
| `perf_fault_cycle` | Fault recv+reply (int3 loop) | ~1.5M cycles |
| `perf_fault_debugger` | Full debugger round trip | ~1.7M cycles |
| `perf_fault_mem` | Cross-addr-space read/write | 5-10K cycles |
| `perf_device_io` | Real ioport + mmio map | 0.6-9K cycles |
| `perf_vm_exit` | Vmexit round trip (HLT guest) | ~150K cycles |

## Adding a New Benchmark

1. Create `kernel/perf/tests/perf_yourname.zig`
2. Use `lib.bench.runBench()` for the measurement loop
3. `zig build` in `kernel/perf/` auto-discovers `perf_*.zig`
4. `run_perf.sh` auto-discovers `perf_*.elf`
5. Emit `[PERF] yourname metric=value cycles` lines via `bench.report()`

## Files

- `build.zig` — ReleaseSafe build for perf tests (separate from correctness tests)
- `run_perf.sh` — runner (multi-run, taskset-pinned, auto-compare, outlier summary)
- `compare_perf.sh` — regression detector (min-based, 20% + 200-cycle floor)
- `resolve_symbols.sh` — addr2line wrapper for `[PROF]` addresses
- `perf_baseline.txt` — checked-in baseline (update intentionally after verified improvements)
- `perf_results/latest.txt` — most recent run output
- `bench.zig` — rdtscp, runBench, stats, reporting
- `profiler.zig` — PMU overflow sampling
