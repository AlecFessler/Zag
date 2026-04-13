# Kernel Performance Testing

## Quick Start

```bash
# Run all perf benchmarks (sequential, ~5 min)
./test.sh perf

# Results are written to kernel/tests/perf_results/latest.txt
# Auto-compares against baseline if perf_baseline.txt exists
# Shows top 10 most expensive operations at the end
```

## Agent Optimization Workflow

```bash
# 1. Capture baseline
./test.sh perf
cp kernel/tests/perf_results/latest.txt kernel/tests/perf_baseline.txt

# 2. Make a kernel change (e.g., optimize scheduler path)
# ... edit kernel code ...

# 3. Re-run benchmarks
./test.sh perf

# 4. Check for regressions (exits non-zero if any median regressed >15%)
kernel/tests/compare_perf.sh kernel/tests/perf_baseline.txt kernel/tests/perf_results/latest.txt

# 5. Run correctness gate
PARALLEL=8 ./test.sh pre-commit

# 6. Commit if improved and passing
```

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
kernel/tests/resolve_symbols.sh kernel/tests/perf_results/latest.txt kernel/tests/bin/perf_profiler.elf
```

Requires `addr2line`. Adjusts for ASLR using `load_base` from profiler output.

## Benchmark Inventory

| Bench | What it measures | Key metric |
|-------|-----------------|------------|
| `perf_syscall_yield` | Null syscall floor | ~68K cycles |
| `perf_syscall_micro` | 25 individual syscalls | varies |
| `perf_clock_gettime` | HPET read path | ~38K cycles |
| `perf_ctx_switch` | Scheduler yield pair (2 switches) | ~134K cycles |
| `perf_thread_create` | Thread lifecycle | ~412K cycles |
| `perf_ipc` | Cross-process IPC (4 variants) | 31-219K cycles |
| `perf_cap_lookup` | Cap table scan (valid vs bogus) | 4-5K cycles |
| `perf_futex` | Futex paths (4 variants) | 4-91K cycles |
| `perf_mem_reserve` | Page alloc + demand fault | 12-13K cycles |
| `perf_mem_perms` | TLB shootdown (1 + 4 pages) | 32-94K cycles |
| `perf_shm_cycle` | SHM create/map/unmap/full | 13-83K cycles |
| `perf_pmu_self` | PMU start+stop cold (MSR path) | ~37K cycles |
| `perf_profiler` | Sampling profiler self-test | [PROF] output |
| `perf_fault_cycle` | Fault recv+reply (int3 loop) | ~1.5M cycles |
| `perf_fault_debugger` | Full debugger round trip | ~1.7M cycles |
| `perf_fault_mem` | Cross-addr-space read/write | 5-10K cycles |
| `perf_device_io` | Real ioport + mmio map/unmap | 0.6-27K cycles |
| `perf_vm_exit` | Vmexit round trip (HLT guest) | ~180K cycles |

## Adding a New Benchmark

1. Create `kernel/tests/tests/perf_yourname.zig`
2. Use `lib.bench.runBench()` for the measurement loop
3. `zig build` in `kernel/tests/` auto-discovers `perf_*.zig`
4. `run_perf.sh` auto-discovers `perf_*.elf`
5. Emit `[PERF] yourname metric=value cycles` lines

## Files

- `run_perf.sh` — runner (sequential, auto-resolve, auto-compare, outlier summary)
- `compare_perf.sh` — regression detector (diff two result files)
- `resolve_symbols.sh` — addr2line wrapper for `[PROF]` addresses
- `perf_baseline.txt` — checked-in baseline (update intentionally)
- `perf_results/latest.txt` — most recent run output
- `libz/bench.zig` — rdtscp, runBench, stats, reporting
- `libz/profiler.zig` — PMU overflow sampling
