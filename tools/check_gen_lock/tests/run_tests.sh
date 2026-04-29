#!/usr/bin/env bash
# Test harness for check_gen_lock per-path release coverage.
#
# Each fixture file under tests/fixtures/ defines a small slab type and
# one or more `pub fn sys*` entry points exercising a canonical
# leak-or-not-leak pattern. The first comment line of each fixture
# declares the expected outcome:
#
#   // EXPECT: clean
#   // EXPECT: errors=N
#
# We materialize a temp tree shaped like `kernel/syscall/<fixture>.zig`
# plus a `kernel/<slab>.zig` so the analyzer's hard-coded directory
# detection accepts the entry points.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
TOOL_DIR="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
ANALYZER="$TOOL_DIR/zig-out/bin/check_gen_lock"

if [[ ! -x "$ANALYZER" ]]; then
    echo "Analyzer not built; running zig build first." >&2
    (cd "$TOOL_DIR" && zig build) >&2
fi

TMP_ROOT="$(mktemp -d -t check_gen_lock_test.XXXXXX)"
trap 'rm -rf "$TMP_ROOT"' EXIT

mkdir -p "$TMP_ROOT/kernel/syscall"
# Slab-type backing module — every fixture needs at least one
# slab-backed type discoverable by the analyzer (`_gen_lock` field).
cat > "$TMP_ROOT/kernel/slab.zig" <<'EOF'
pub const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};
EOF

pass=0
fail=0
fail_list=()

for fixture in "$FIXTURES_DIR"/*.zig; do
    name="$(basename "$fixture" .zig)"
    expect_line="$(head -n 1 "$fixture")"
    expected=""
    if [[ "$expect_line" =~ ^//[[:space:]]*EXPECT:[[:space:]]*(.*)$ ]]; then
        expected="${BASH_REMATCH[1]}"
    fi
    if [[ -z "$expected" ]]; then
        echo "SKIP $name (no EXPECT directive)"
        continue
    fi

    cp "$fixture" "$TMP_ROOT/kernel/syscall/$name.zig"
    out="$("$ANALYZER" --root "$TMP_ROOT/kernel" --summary 2>&1 || true)"
    rm "$TMP_ROOT/kernel/syscall/$name.zig"

    # If you want to debug an individual fixture, uncomment:
    # echo "$out" | sed 's/^/  >>> /'

    err_count="$(echo "$out" | sed -n 's/.*err= *\([0-9]\+\).*/\1/p' | head -n 1)"
    err_count="${err_count:-0}"

    case "$expected" in
        clean)
            if [[ "$err_count" == "0" ]]; then
                echo "PASS $name (clean)"
                pass=$((pass + 1))
            else
                echo "FAIL $name (expected clean, got err=$err_count)"
                echo "$out" | sed 's/^/    /'
                fail=$((fail + 1))
                fail_list+=("$name")
            fi
            ;;
        errors=*)
            want="${expected#errors=}"
            if [[ "$err_count" == "$want" ]]; then
                echo "PASS $name (errors=$want)"
                pass=$((pass + 1))
            else
                echo "FAIL $name (expected errors=$want, got err=$err_count)"
                echo "$out" | sed 's/^/    /'
                fail=$((fail + 1))
                fail_list+=("$name")
            fi
            ;;
        *)
            echo "FAIL $name (unknown EXPECT: $expected)"
            fail=$((fail + 1))
            fail_list+=("$name")
            ;;
    esac
done

echo ""
echo "Results: $pass pass, $fail fail"
if (( fail > 0 )); then
    printf '  failed: %s\n' "${fail_list[@]}"
    exit 1
fi
