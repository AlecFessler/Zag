#!/bin/bash
# Resolve [PROF] addresses to function names using addr2line.
#
# Usage: ./resolve_symbols.sh [results_file] [elf_file]
#
# Reads [PROF] lines from results file (default: perf_results/latest.txt),
# resolves hex addresses against the provided ELF's debug info.
#
# IMPORTANT: ASLR/PIE means runtime addresses differ from ELF addresses.
# If the profiler output includes a [PROF] load_base=0xNNNN line, this
# script adjusts addresses automatically. Otherwise, provide the load
# base via the LOAD_BASE env var:
#   LOAD_BASE=0x200000 ./resolve_symbols.sh
#
# For profiling userspace code, pass the test ELF (not kernel.elf):
#   ./resolve_symbols.sh perf_results/latest.txt bin/perf_profiler.elf

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZAG_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RESULTS_FILE="${1:-$SCRIPT_DIR/perf_results/latest.txt}"
ELF_FILE="${2:-$SCRIPT_DIR/bin/perf_profiler.elf}"

if [ ! -f "$RESULTS_FILE" ]; then
    echo "Error: results file not found: $RESULTS_FILE"
    exit 1
fi

if [ ! -f "$ELF_FILE" ]; then
    echo "Warning: ELF not found: $ELF_FILE"
    echo "Pass the test ELF as second argument."
    echo "Falling back to raw addresses."
    grep '^\[PROF\]' "$RESULTS_FILE"
    exit 0
fi

if ! command -v addr2line &>/dev/null; then
    echo "Warning: addr2line not found. Showing raw addresses."
    grep '^\[PROF\]' "$RESULTS_FILE"
    exit 0
fi

# Try to extract load_base from profiler output
FILE_BASE="${LOAD_BASE:-}"
if [ -z "$FILE_BASE" ]; then
    FILE_BASE=$(grep -oP '^\[PROF\].*load_base=\K0x[0-9a-fA-F]+' "$RESULTS_FILE" 2>/dev/null | head -1 || true)
fi

if [ -n "$FILE_BASE" ]; then
    echo "Using load base: $FILE_BASE (subtracting from RIPs before resolution)"
else
    echo "Warning: No load base found. Addresses may not resolve correctly due to ASLR."
    echo "Set LOAD_BASE=0xNNNN or have the profiler emit [PROF] load_base=0xNNNN"
    FILE_BASE="0x0"
fi
echo "Resolving against: $ELF_FILE"
echo ""

base_dec=$((FILE_BASE))

while IFS= read -r line; do
    # Extract hex address from lines like: [PROF] name 0x0000000000401234 count=892 pct=19.7
    addr=$(echo "$line" | grep -oP '0x[0-9a-fA-F]{8,}' || true)

    if [ -z "$addr" ]; then
        echo "$line"
        continue
    fi

    # Subtract load base to get file offset
    addr_dec=$((addr))
    offset_dec=$((addr_dec - base_dec))
    offset=$(printf "0x%x" "$offset_dec")

    resolved=$(addr2line -e "$ELF_FILE" -f -C "$offset" 2>/dev/null || echo "??")
    func_name=$(echo "$resolved" | head -1)
    source_loc=$(echo "$resolved" | tail -1)

    echo "$line  $func_name ($source_loc)"

done < <(grep '^\[PROF\]' "$RESULTS_FILE")
