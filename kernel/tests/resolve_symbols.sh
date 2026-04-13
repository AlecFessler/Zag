#!/bin/bash
# Resolve [PROF] addresses to function names using addr2line.
#
# Usage: ./resolve_symbols.sh [results_file] [kernel_elf]
#
# Reads [PROF] lines from results file (default: perf_results/latest.txt),
# resolves hex addresses against kernel ELF debug info, and prints
# annotated output.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RESULTS_FILE="${1:-$SCRIPT_DIR/perf_results/latest.txt}"
KERNEL_ELF="${2:-$ZAG_ROOT/zig-out/img/kernel.elf}"

if [ ! -f "$RESULTS_FILE" ]; then
    echo "Error: results file not found: $RESULTS_FILE"
    exit 1
fi

if [ ! -f "$KERNEL_ELF" ]; then
    echo "Warning: kernel ELF not found: $KERNEL_ELF"
    echo "Build with 'zig build -Dprofile=test' first."
    echo "Falling back to raw addresses."
    grep '^\[PROF\]' "$RESULTS_FILE"
    exit 0
fi

# Check if addr2line is available
if ! command -v addr2line &>/dev/null; then
    echo "Warning: addr2line not found. Showing raw addresses."
    grep '^\[PROF\]' "$RESULTS_FILE"
    exit 0
fi

echo "Resolving symbols from $KERNEL_ELF"
echo ""

while IFS= read -r line; do
    # Lines look like: [PROF] workload_name 0x0000000000401234 count=892 pct=19.7
    # or header:        [PROF] workload_name total_samples=4523

    # Check if line contains a hex address
    addr=$(echo "$line" | grep -oP '0x[0-9a-fA-F]+' || true)

    if [ -z "$addr" ]; then
        # Header line, print as-is
        echo "$line"
        continue
    fi

    # Resolve address to function name
    resolved=$(addr2line -e "$KERNEL_ELF" -f -C "$addr" 2>/dev/null || echo "??")
    func_name=$(echo "$resolved" | head -1)
    source_loc=$(echo "$resolved" | tail -1)

    # Print annotated line
    echo "$line  $func_name ($source_loc)"

done < <(grep '^\[PROF\]' "$RESULTS_FILE")
