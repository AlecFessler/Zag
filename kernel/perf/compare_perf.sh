#!/bin/bash
# Compare two performance result files and detect regressions.
#
# Usage: ./compare_perf.sh baseline.txt current.txt [threshold_pct] [min_delta]
#
# A regression requires BOTH:
#   - percentage change > threshold_pct (default 20%)
#   - absolute delta > min_delta cycles (default 200)
#
# The 20% default matches observed KVM-guest run-to-run noise on this
# framework (taskset-pinned QEMU + RUNS=3). Nested-virt microbenchmarks
# inherently have 10-20% jitter from host scheduler / cache effects.
# Real kernel-code regressions typically show up at 25-50%+, so 20%
# catches them while keeping the false-positive rate near zero. For bare
# metal or compile-time-tracker precision (1-2%) you'd need N=20+ runs
# with statistical significance testing, which is too expensive here.
#
# The absolute floor prevents false positives on very cheap operations
# where rdtscp measurement jitter (~40 cycles) is a large fraction of the
# baseline. Without it, ioport_write (546 cycles) would flag at +42 cycles
# as "+7% regression" even though that's pure noise.
#
# Uses `min` values (not median) — min is more robust against system
# noise (interrupts, cache pollution) because noise only pushes samples
# upward. With multi-run runners (mean-of-N-runs), inter-run variance is
# further reduced by ~√N.

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <baseline.txt> <current.txt> [threshold_pct] [min_delta]"
    echo "  Compares [PERF] min values between two result files."
    echo "  Flags a regression only if pct_change > threshold_pct AND"
    echo "  abs_delta > min_delta cycles."
    exit 1
fi

BASELINE="$1"
CURRENT="$2"
THRESHOLD="${3:-20}"
MIN_DELTA="${4:-200}"

if [ ! -f "$BASELINE" ]; then
    echo "Error: baseline file not found: $BASELINE"
    exit 1
fi

if [ ! -f "$CURRENT" ]; then
    echo "Error: current file not found: $CURRENT"
    exit 1
fi

regressions=0

printf "%-30s %10s %10s %8s  %s\n" "Benchmark" "Baseline" "Current" "Change" "Status"
printf "%-30s %10s %10s %8s  %s\n" "------------------------------" "----------" "----------" "--------" "------"

# Extract min values from both files
while IFS= read -r line; do
    # Parse: [PERF] bench_name min=VALUE cycles
    bench=$(echo "$line" | awk '{print $2}')
    value=$(echo "$line" | awk '{print $3}' | sed 's/min=//')

    # Find matching min in current
    current_line=$(grep "^\[PERF\] $bench min=" "$CURRENT" 2>/dev/null || true)
    if [ -z "$current_line" ]; then
        printf "%-30s %10s %10s %8s  %s\n" "$bench" "$value" "MISSING" "-" "SKIP"
        continue
    fi

    current_value=$(echo "$current_line" | awk '{print $3}' | sed 's/min=//')

    if [ "$value" -eq 0 ]; then
        printf "%-30s %10s %10s %8s  %s\n" "$bench" "$value" "$current_value" "N/A" "SKIP"
        continue
    fi

    # Compute percentage change (positive = slower = regression) and
    # absolute delta. A regression requires BOTH pct > threshold AND
    # abs(delta) > min_delta, so cheap ops below the rdtscp noise floor
    # don't produce false positives.
    change=$(( (current_value - value) * 100 / value ))
    delta=$(( current_value - value ))
    abs_delta=${delta#-}

    if [ "$change" -gt "$THRESHOLD" ] && [ "$abs_delta" -gt "$MIN_DELTA" ]; then
        status="[REGRESSION]"
        regressions=$((regressions + 1))
    elif [ "$change" -lt "-$THRESHOLD" ] && [ "$abs_delta" -gt "$MIN_DELTA" ]; then
        status="[IMPROVED]"
    else
        status="OK"
    fi

    printf "%-30s %10s %10s %7s%%  %s\n" "$bench" "$value" "$current_value" "$change" "$status"

done < <(grep '^\[PERF\] .* min=' "$BASELINE")

echo ""
if [ "$regressions" -gt 0 ]; then
    echo "FAILED: $regressions regression(s) detected (threshold: >${THRESHOLD}% AND >${MIN_DELTA} cycles)"
    exit 1
else
    echo "PASSED: No regressions detected (threshold: >${THRESHOLD}% AND >${MIN_DELTA} cycles)"
    exit 0
fi
