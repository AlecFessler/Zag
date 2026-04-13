#!/bin/bash
# Run kernel performance benchmarks sequentially.
# Each benchmark is run N times (default 3) and metrics are averaged
# across runs to reduce KVM/host-scheduler jitter. Within each run,
# `bench.zig` already takes the minimum of 10k internal samples, so
# the final number is mean-of-mins — noise-robust inside the run,
# variance-reduced across runs.
#
# Output: [PERF] and [PROF] lines in perf_results/latest.txt

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMEOUT=120
RUNS="${RUNS:-3}"
QEMU_CMD="taskset -c 0-3 qemu-system-x86_64 -m 2G -bios /usr/share/ovmf/x64/OVMF.4m.fd -serial stdio -display none -no-reboot -enable-kvm -cpu host,+invtsc -machine q35 -device intel-iommu,intremap=off -net none -smp cores=4"

IMG_DIR="$ZAG_ROOT/zig-out/img"
BIN_DIR="$SCRIPT_DIR/bin"
RESULTS_DIR="$SCRIPT_DIR/perf_results"
mkdir -p "$RESULTS_DIR"

# Build all test ELFs
echo "Building test ELFs..."
cd "$SCRIPT_DIR"
zig build

# Create placeholder root_service.elf for kernel build
first_elf=$(find "$BIN_DIR" -name 'perf_*.elf' | head -1)
if [ -z "$first_elf" ]; then
    echo "No perf_*.elf files found. Build failed?"
    exit 1
fi
cp "$first_elf" "$BIN_DIR/root_service.elf"

# Build kernel
echo "Building kernel..."
cd "$ZAG_ROOT"
zig build -Dprofile=test
echo ""

# Run one benchmark once, capture [PERF]/[PROF] lines to stdout.
run_one_qemu() {
    local elf="$1"
    local workdir=$(mktemp -d)
    mkdir -p "$workdir/efi/boot"
    ln -s "$IMG_DIR/efi/boot/BOOTX64.EFI" "$workdir/efi/boot/"
    ln -s "$IMG_DIR/kernel.elf" "$workdir/"
    cp "$IMG_DIR/NvVars" "$workdir/" 2>/dev/null || true
    cp "$elf" "$workdir/root_service.elf"

    timeout "$TIMEOUT" $QEMU_CMD -drive "file=fat:rw:$workdir,format=raw" 2>/dev/null \
        | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
        | grep -oE '\[(PERF|PROF|PASS|FAIL)\].*$' || true

    rm -rf "$workdir"
}

# Run one benchmark N times and average metrics across runs.
# For each "[PERF] name metric=VALUE ..." line, take the mean of VALUE
# across runs. [PROF] and [PASS]/[FAIL] lines are passed through from
# the first run only.
run_one_bench() {
    local elf="$1"
    local name=$(basename "$elf" .elf)

    echo "--- $name (${RUNS}x) ---"

    local tmpfile=$(mktemp)
    local run
    for run in $(seq 1 "$RUNS"); do
        run_one_qemu "$elf" >> "$tmpfile"
    done

    # Aggregate: group by "name metric" (first 2 fields after [PERF]),
    # average the numeric value, preserve unit. Emit one [PERF] line per
    # unique metric, in the order first seen.
    local aggregated
    aggregated=$(awk -v runs="$RUNS" '
        /^\[PERF\]/ {
            name = $2
            # Split "key=val" into key and val.
            split($3, kv, "=")
            key = kv[1]
            val = kv[2]
            unit = $4
            id = name " " key
            if (!(id in sum)) {
                order[++n] = id
                units[id] = unit
            }
            sum[id] += val
            count[id]++
            next
        }
        /^\[(PROF|PASS|FAIL)\]/ {
            # Pass through once — use a seen-tracker keyed on whole line.
            if (!(seen_pass[$0]++)) passthrough[++m] = $0
        }
        END {
            for (i = 1; i <= n; i++) {
                id = order[i]
                mean = int(sum[id] / count[id])
                split(id, parts, " ")
                printf "[PERF] %s %s=%d", parts[1], parts[2], mean
                if (units[id] != "") printf " %s", units[id]
                printf "\n"
            }
            for (i = 1; i <= m; i++) print passthrough[i]
        }
    ' "$tmpfile")

    rm -f "$tmpfile"

    if [ -z "$aggregated" ]; then
        echo "  (no output)"
    else
        echo "$aggregated" | while IFS= read -r line; do
            echo "  $line"
        done
        echo "$aggregated" >> "$RESULTS_DIR/latest.txt"
    fi
    echo ""
}

# Collect perf test ELFs, sorted
mapfile -t perf_elfs < <(find "$BIN_DIR" -name 'perf_*.elf' | sort)
total=${#perf_elfs[@]}

if [ "$total" -eq 0 ]; then
    echo "No performance tests found."
    exit 0
fi

# Clear previous results
> "$RESULTS_DIR/latest.txt"

echo "Running $total benchmarks × $RUNS runs each (sequential)..."
echo ""

for elf in "${perf_elfs[@]}"; do
    run_one_bench "$elf"
done

echo "================================"
echo "Results written to: $RESULTS_DIR/latest.txt"
echo "Total benchmarks: $total (${RUNS} runs each)"

# --- Auto-resolve profiler symbols ---
if grep -q '^\[PROF\]' "$RESULTS_DIR/latest.txt" 2>/dev/null; then
    echo ""
    echo "=== Resolving profiler symbols ==="
    child_elf="$BIN_DIR/child_perf_workload.elf"
    if [ ! -f "$child_elf" ]; then
        child_elf="$BIN_DIR/perf_profiler.elf"
    fi
    bash "$SCRIPT_DIR/resolve_symbols.sh" "$RESULTS_DIR/latest.txt" "$child_elf" 2>/dev/null || true
fi

# --- Auto-compare against baseline ---
BASELINE="$SCRIPT_DIR/perf_baseline.txt"
if [ -f "$BASELINE" ]; then
    echo ""
    echo "=== Regression check vs baseline ==="
    bash "$SCRIPT_DIR/compare_perf.sh" "$BASELINE" "$RESULTS_DIR/latest.txt" 20 || true
    echo ""
fi

# --- Outlier summary for agents ---
echo ""
echo "=== Top 10 most expensive operations (by min cycles) ==="
printf "%-35s %12s\n" "Benchmark" "Min"
printf "%-35s %12s\n" "-----------------------------------" "------------"
grep '^\[PERF\] .* min=' "$RESULTS_DIR/latest.txt" 2>/dev/null | \
    awk '{
        name=$2;
        for(i=3;i<=NF;i++){
            if($i ~ /^min=/){
                split($i,a,"=");
                printf "%-35s %12s\n", name, a[2]
            }
        }
    }' | sort -t' ' -k2 -rn | head -10
