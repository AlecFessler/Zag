#!/bin/bash
# Compare two performance result files and detect regressions.
#
# Usage: ./compare_perf.sh baseline.txt current.txt [threshold_pct]
# Exits non-zero if any median regressed by more than threshold (default 15%).

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <baseline.txt> <current.txt> [threshold_pct]"
    echo "  Compares [PERF] median values between two result files."
    echo "  Exits non-zero if any regression exceeds threshold."
    exit 1
fi

BASELINE="$1"
CURRENT="$2"
THRESHOLD="${3:-1}"

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

# Extract median values from both files
while IFS= read -r line; do
    # Parse: [PERF] bench_name median=VALUE cycles
    bench=$(echo "$line" | awk '{print $2}')
    value=$(echo "$line" | awk '{print $3}' | sed 's/median=//')

    # Find matching median in current
    current_line=$(grep "^\[PERF\] $bench median=" "$CURRENT" 2>/dev/null || true)
    if [ -z "$current_line" ]; then
        printf "%-30s %10s %10s %8s  %s\n" "$bench" "$value" "MISSING" "-" "SKIP"
        continue
    fi

    current_value=$(echo "$current_line" | awk '{print $3}' | sed 's/median=//')

    if [ "$value" -eq 0 ]; then
        printf "%-30s %10s %10s %8s  %s\n" "$bench" "$value" "$current_value" "N/A" "SKIP"
        continue
    fi

    # Compute percentage change (positive = slower = regression)
    change=$(( (current_value - value) * 100 / value ))

    if [ "$change" -gt "$THRESHOLD" ]; then
        status="[REGRESSION]"
        regressions=$((regressions + 1))
    elif [ "$change" -lt "-$THRESHOLD" ]; then
        status="[IMPROVED]"
    else
        status="OK"
    fi

    printf "%-30s %10s %10s %7s%%  %s\n" "$bench" "$value" "$current_value" "$change" "$status"

done < <(grep '^\[PERF\] .* median=' "$BASELINE")

echo ""
if [ "$regressions" -gt 0 ]; then
    echo "FAILED: $regressions regression(s) detected (threshold: ${THRESHOLD}%)"
    exit 1
else
    echo "PASSED: No regressions detected (threshold: ${THRESHOLD}%)"
    exit 0
fi
