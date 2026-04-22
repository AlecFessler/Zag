#!/bin/bash
# Batch red-team regression runner.
#
# Iterates every PoC in tests/redteam/ that actually emits a
# `POC-<id>: PATCHED` marker (i.e., entry-point PoCs, not the _child_
# helpers that get spawned into those PoCs). For each one:
#
#   - Build + boot via `run.sh <poc>` (reuses the existing single-PoC
#     pipeline — no second QEMU recipe to keep in sync).
#   - Scan the serial capture for a `POC-*: PATCHED` / `VULNERABLE` /
#     `SKIPPED` line.
#
# Exit 0 if every PoC either PATCHED or SKIPPED. Non-zero — with the
# culprit list and the tail of each failing log — otherwise. SKIPPED
# is a legitimate "no hardware for this PoC" outcome (e.g. VMX
# missing) and does not fail the gate.
#
# This is the runner `tests/precommit.sh` stage 5 depends on.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Discover entry-point PoCs: files that actually *emit* a PATCHED
# marker. The `child_*.zig` helpers can mention PATCHED in their
# comment header but never call syscall.write with it, so this
# pattern filters them out without a hand-maintained allowlist.
ENTRIES=()
for f in "$SCRIPT_DIR"/*.zig; do
    if grep -qE 'syscall\.write\(".*PATCHED' "$f"; then
        ENTRIES+=("$(basename "$f")")
    fi
done

total=${#ENTRIES[@]}
if [[ $total -eq 0 ]]; then
    echo "No PoC entry points found under $SCRIPT_DIR" >&2
    exit 2
fi

PASSED=()
SKIPPED=()
FAILED=()

echo "Running $total red-team PoC regressions..."
i=0
for src in "${ENTRIES[@]}"; do
    i=$((i + 1))
    printf '[%d/%d] %s ... ' "$i" "$total" "$src"

    log=$(mktemp)
    # run.sh exits 0 after timeout even if QEMU hit a panic — it's a
    # "best effort" driver. Classification is purely by serial content.
    bash "$SCRIPT_DIR/run.sh" "$src" > "$log" 2>&1 || true

    if grep -qE 'POC-.+: PATCHED' "$log"; then
        echo "PATCHED"
        PASSED+=("$src")
        rm -f "$log"
    elif grep -qE 'POC-.+: SKIPPED' "$log"; then
        echo "SKIPPED"
        SKIPPED+=("$src")
        rm -f "$log"
    elif grep -qE 'POC-.+: VULNERABLE' "$log"; then
        echo "VULNERABLE"
        FAILED+=("$src [VULNERABLE]")
        echo "--- $src tail ---"
        tail -15 "$log"
        echo "--- end ---"
        rm -f "$log"
    else
        # No recognised marker — PoC either panicked the kernel before
        # its AFTER line or the build didn't boot at all. Both outcomes
        # are regressions.
        echo "UNEXPECTED"
        FAILED+=("$src [no PATCHED marker — likely kernel panic]")
        echo "--- $src tail ---"
        tail -15 "$log"
        echo "--- end ---"
        rm -f "$log"
    fi
done

echo ""
echo "Red-team regression summary:"
echo "  passed:  ${#PASSED[@]}"
echo "  skipped: ${#SKIPPED[@]}"
echo "  failed:  ${#FAILED[@]}"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo ""
    echo "Failures:"
    printf '  %s\n' "${FAILED[@]}"
    exit 1
fi
exit 0
