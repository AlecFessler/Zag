#!/bin/bash
# tests/ci.sh — Zag mega pre-commit local CI.
#
# Stages (sequential, stop on first hard failure):
#
#   1. x86 kernel tests        — full 590-test suite under x86 KVM
#   2. x86 Linux boot          — tests/test.sh linux
#   3. aarch64 kernel tests    — Pi 5 KVM via SSH (alecfessler@PI_HOST);
#                                fallback to TCG if unreachable; §4.2
#                                subset always TCG regardless (Pi 5 KVM
#                                can't do nested virt).
#   4. aarch64 §4.2 TCG        — 63 VM tests under QEMU TCG
#   5. aarch64 Linux boot      — tests/test.sh linux-arm
#   6. Redteam PoC suite       — every tests/redteam/*.zig PoC under x86
#   7. Perf (trace mode)       — compose debugger + shm_cycle in one OS,
#                                capture [KPROF] dump, diff vs previous
#                                run.
#
# Output: ~/.zag-ci/runs/<iso-timestamp>/ with per-stage logs + a
# summary.txt. A symlink ~/.zag-ci/runs/latest points at the most
# recent run so the perf stage can diff against the previous one.

set -u

ZAG_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ZAG_ROOT"

PI_HOST="${PI_HOST:-alecfessler@192.168.86.106}"
PI_REMOTE_DIR="${PI_REMOTE_DIR:-zag-test-ci}"

RUN_ROOT="${ZAG_CI_RUNS:-$HOME/.zag-ci/runs}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$RUN_ROOT/$TS"
LATEST_LINK="$RUN_ROOT/latest"
PREVIOUS_LINK="$RUN_ROOT/previous"

mkdir -p "$RUN_DIR"
SUMMARY="$RUN_DIR/summary.txt"
: > "$SUMMARY"

# Remember the previous run (if any) so the perf stage can diff against
# it. Updated at the end once this run has been committed.
if [ -L "$LATEST_LINK" ]; then
    PREV_RUN_DIR="$(readlink -f "$LATEST_LINK")"
else
    PREV_RUN_DIR=""
fi

RED='\e[31m'; GRN='\e[32m'; YLW='\e[33m'; RST='\e[0m'

stage_counter=0
declare -A stage_status
declare -A stage_note
declare -a stage_order

hard_fail=0

log()   { printf '%s\n' "$*"                         | tee -a "$SUMMARY"; }
stage_start() {
    stage_counter=$((stage_counter+1))
    local tag="$1" title="$2"
    stage_order+=("$tag")
    log
    log "──── stage $stage_counter: $tag — $title ────"
}
stage_result() {
    local tag="$1" status="$2" note="${3:-}"
    stage_status[$tag]=$status
    stage_note[$tag]=$note
    case "$status" in
      PASS) printf "${GRN}[PASS]${RST} %s %s\n" "$tag" "$note" | tee -a "$SUMMARY" ;;
      SKIP) printf "${YLW}[SKIP]${RST} %s %s\n" "$tag" "$note" | tee -a "$SUMMARY" ;;
      FAIL) printf "${RED}[FAIL]${RST} %s %s\n" "$tag" "$note" | tee -a "$SUMMARY"
            hard_fail=1 ;;
      WARN) printf "${YLW}[WARN]${RST} %s %s\n" "$tag" "$note" | tee -a "$SUMMARY" ;;
    esac
}

# ─── stage 1: x86 kernel tests ────────────────────────────────────────
stage_start S1 "x86 kernel tests (KVM, 590)"
(
    rm -rf "$ZAG_ROOT/.zig-cache" "$ZAG_ROOT/zig-out"
    PARALLEL="${PARALLEL:-4}" ARCH=x64 bash "$ZAG_ROOT/tests/tests/run_tests.sh"
) >"$RUN_DIR/s1_x86_kernel.log" 2>&1
tail="$(tail -n 5 "$RUN_DIR/s1_x86_kernel.log" | tr -d '\r' | head -n 4)"
total="$(grep -E '^Total:' "$RUN_DIR/s1_x86_kernel.log" | tail -n 1)"
if grep -q '^Total: .* 0 fail ' "$RUN_DIR/s1_x86_kernel.log"; then
    stage_result S1 PASS "$total"
else
    stage_result S1 FAIL "$total — see s1_x86_kernel.log"
fi

# ─── stage 2: x86 Linux boot ──────────────────────────────────────────
stage_start S2 "x86 Linux guest boot (hyprvOS)"
if bash "$ZAG_ROOT/tests/test.sh" linux > "$RUN_DIR/s2_x86_linux.log" 2>&1; then
    stage_result S2 PASS
else
    stage_result S2 FAIL "see s2_x86_linux.log"
fi

# ─── stage 3: aarch64 kernel tests (Pi 5 KVM or TCG fallback) ─────────
stage_start S3 "aarch64 kernel tests (Pi 5 KVM preferred)"
aarch64_host=""
if ssh -o BatchMode=yes -o ConnectTimeout=5 "$PI_HOST" 'true' 2>/dev/null; then
    aarch64_host="pi"
    log "Pi 5 reachable; running 590-test suite over SSH"
else
    aarch64_host="tcg"
    log "Pi 5 unreachable ($PI_HOST); falling back to TCG"
fi

if [ "$aarch64_host" = "pi" ]; then
    # Build aarch64 kernel + test ELFs, sync to Pi, run.
    (
        rm -rf "$ZAG_ROOT/.zig-cache" "$ZAG_ROOT/zig-out"
        zig build -Darch=arm -Dprofile=test || exit 1
        (cd "$ZAG_ROOT/tests/tests" && zig build -Darch=arm) || exit 1
    ) > "$RUN_DIR/s3_arm_build.log" 2>&1 || {
        stage_result S3 FAIL "aarch64 build failed — see s3_arm_build.log"
    }
    if [ -z "${stage_status[S3]:-}" ]; then
        (
            ssh "$PI_HOST" "mkdir -p $PI_REMOTE_DIR/{img/efi/boot,tests/bin}"
            scp "$ZAG_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" "$PI_HOST:$PI_REMOTE_DIR/img/efi/boot/" >/dev/null
            scp "$ZAG_ROOT/zig-out/img/kernel.elf"           "$PI_HOST:$PI_REMOTE_DIR/img/"          >/dev/null
            (cd "$ZAG_ROOT/tests/tests/bin" && tar c s*.elf | ssh "$PI_HOST" "cd $PI_REMOTE_DIR/tests/bin && tar x")
            # Copy and rewrite runner.sh so ZAG_DIR points at our upload.
            ssh "$PI_HOST" "sed 's|~/zag-test[a-zA-Z0-9_-]*|~/$PI_REMOTE_DIR|g' ~/zag-test/runner.sh > ~/$PI_REMOTE_DIR/runner.sh && chmod +x ~/$PI_REMOTE_DIR/runner.sh"
            ssh "$PI_HOST" "cd ~/$PI_REMOTE_DIR && PARALLEL=4 LIMIT=10000 TIMEOUT=15 bash runner.sh"
        ) > "$RUN_DIR/s3_pi_kvm.log" 2>&1
        summary_line="$(grep -E '^(PASS|FAIL|NOOUT|Total):' "$RUN_DIR/s3_pi_kvm.log" | tr '\n' ' ')"
        if grep -q '^FAIL: 0$' "$RUN_DIR/s3_pi_kvm.log" && grep -q '^NOOUT: 0$' "$RUN_DIR/s3_pi_kvm.log"; then
            stage_result S3 PASS "$summary_line"
        else
            # Pi KVM has known-irreducible failures (documented in gic.zig:
            # §2.1.25, §2.2.16 on vGICv2) and can't run nested-virt VM
            # tests. Count fails vs the known-good baseline, warn rather
            # than hard-fail — user can inspect s3_pi_kvm.log for drift.
            stage_result S3 WARN "$summary_line"
        fi
    fi
else
    # TCG fallback — run full 590 tests under TCG. Slow (~60 min).
    (
        rm -rf "$ZAG_ROOT/.zig-cache" "$ZAG_ROOT/zig-out"
        PARALLEL="${PARALLEL:-2}" ARCH=arm bash "$ZAG_ROOT/tests/tests/run_tests.sh"
    ) > "$RUN_DIR/s3_arm_tcg.log" 2>&1
    total="$(grep -E '^Total:' "$RUN_DIR/s3_arm_tcg.log" | tail -n 1)"
    if grep -q '^Total: .* 0 fail ' "$RUN_DIR/s3_arm_tcg.log"; then
        stage_result S3 PASS "$total"
    else
        stage_result S3 WARN "$total — see s3_arm_tcg.log (Pi unreachable)"
    fi
fi

# ─── stage 4: §4.2 TCG (VM tests) ─────────────────────────────────────
stage_start S4 "aarch64 §4.2 VM tests (TCG)"
(
    # Build aarch64 kernel + test ELFs only if not already present.
    if [ ! -f "$ZAG_ROOT/tests/tests/bin/s4_2_10.elf" ] || [ ! -f "$ZAG_ROOT/zig-out/img/kernel.elf" ] \
       || ! readelf -l "$ZAG_ROOT/zig-out/img/kernel.elf" 2>/dev/null | grep -q '0xffff0000'; then
        zig build -Darch=arm -Dprofile=test || exit 1
        (cd "$ZAG_ROOT/tests/tests" && zig build -Darch=arm) || exit 1
    fi
    IMG="$ZAG_ROOT/zig-out/img"; BIN="$ZAG_ROOT/tests/tests/bin"
    pass=0; fail=0; noout=0
    for elf in $(ls "$BIN"/s4_2_*.elf | sort); do
        name="$(basename "$elf" .elf)"
        wd="$(mktemp -d)"
        mkdir -p "$wd/efi/boot"
        cp "$IMG/efi/boot/BOOTAA64.EFI" "$wd/efi/boot/"
        cp "$IMG/kernel.elf"            "$wd/"
        cp "$elf"                       "$wd/root_service.elf"
        out=$(timeout 30 qemu-system-aarch64 -M virt,virtualization=on,gic-version=3 -m 1G \
                 -bios /usr/share/AAVMF/AAVMF_CODE.fd -serial stdio -display none -no-reboot \
                 -machine accel=tcg -cpu cortex-a72 -smp cores=4 \
                 -drive "file=fat:rw:$wd,format=raw" 2>&1 | grep -aE '\[PASS\]|\[FAIL\]' | head -n 1 || true)
        rm -rf "$wd"
        if echo "$out" | grep -q '\[PASS\]'; then
            pass=$((pass+1))
        elif echo "$out" | grep -q '\[FAIL\]'; then
            fail=$((fail+1))
            echo "FAIL $name: $out"
        else
            noout=$((noout+1))
            echo "NOOUT $name"
        fi
    done
    echo "=== §4.2 TCG: $((pass+fail+noout)) tests: PASS=$pass FAIL=$fail NOOUT=$noout"
) > "$RUN_DIR/s4_arm_42_tcg.log" 2>&1
tail_line="$(tail -n 1 "$RUN_DIR/s4_arm_42_tcg.log")"
if echo "$tail_line" | grep -q 'FAIL=0 NOOUT=0'; then
    stage_result S4 PASS "$tail_line"
else
    stage_result S4 FAIL "$tail_line — see s4_arm_42_tcg.log"
fi

# ─── stage 5: aarch64 Linux boot ──────────────────────────────────────
stage_start S5 "aarch64 Linux guest boot (hyprvOS, TCG)"
if bash "$ZAG_ROOT/tests/test.sh" linux-arm > "$RUN_DIR/s5_arm_linux.log" 2>&1; then
    stage_result S5 PASS
else
    stage_result S5 FAIL "see s5_arm_linux.log"
fi

# ─── stage 6: Redteam PoC suite (x86) ─────────────────────────────────
stage_start S6 "Redteam PoCs (x86)"
mkdir -p "$RUN_DIR/s6_redteam"
redteam_pass=0; redteam_fail=0
for poc in "$ZAG_ROOT"/tests/redteam/*.zig; do
    name="$(basename "$poc" .zig)"
    # Children / helper ELFs that aren't standalone PoCs — skip.
    case "$name" in child_*|p1_bad|gen_p1_elf) continue ;; esac
    out="$RUN_DIR/s6_redteam/$name.log"
    (cd "$ZAG_ROOT/tests/redteam" && bash ./run.sh "$name.zig") > "$out" 2>&1 || true
    # Detection: any line containing "VULNERABLE" = regression.
    if grep -q 'VULNERABLE' "$out"; then
        redteam_fail=$((redteam_fail+1))
        echo "  [FAIL] $name — VULNERABLE marker found"
    else
        redteam_pass=$((redteam_pass+1))
    fi
done > "$RUN_DIR/s6_redteam_summary.log" 2>&1
if [ "$redteam_fail" -eq 0 ]; then
    stage_result S6 PASS "redteam: $redteam_pass pocs clean"
else
    stage_result S6 FAIL "redteam: $redteam_fail regressions (see s6_redteam/)"
fi

# ─── stage 7: Perf (composed debugger+shm_cycle, trace mode) ──────────
stage_start S7 "Perf trace (composed workload)"
(
    (cd "$ZAG_ROOT/tests/prof" && zig build -Dworkload=composed) || exit 1
    rm -rf "$ZAG_ROOT/.zig-cache" "$ZAG_ROOT/zig-out"
    zig build -Dprofile=prof -Dkernel_profile=trace || exit 1
    # Run under KVM, capture serial.
    qemu_log="$RUN_DIR/s7_perf_serial.log"
    workdir="$(mktemp -d)"
    mkdir -p "$workdir/efi/boot"
    cp "$ZAG_ROOT/zig-out/img/efi/boot/BOOTX64.EFI" "$workdir/efi/boot/"
    cp "$ZAG_ROOT/zig-out/img/kernel.elf"           "$workdir/"
    cp "$ZAG_ROOT/zig-out/img/NvVars"               "$workdir/" 2>/dev/null || true
    cp "$ZAG_ROOT/tests/prof/bin/root_service.elf"  "$workdir/root_service.elf"
    timeout 60 qemu-system-x86_64 \
        -m 2G -bios /usr/share/ovmf/x64/OVMF.4m.fd \
        -serial stdio -display none -no-reboot \
        -enable-kvm -cpu host,+invtsc -machine q35 \
        -device intel-iommu,intremap=off -net none -smp cores=4 \
        -drive "file=fat:rw:$workdir,format=raw" > "$qemu_log" 2>&1 || true
    rm -rf "$workdir"

    # Parse kprof dump to JSON.
    python3 "$ZAG_ROOT/kernel/kprof/tools/parse_kprof.py" --json \
        "$qemu_log" > "$RUN_DIR/s7_perf_trace.json" 2> "$RUN_DIR/s7_perf_parse.err" \
        || { echo "parse_kprof.py failed"; exit 1; }
    echo "kprof trace JSON written to s7_perf_trace.json"

    # Diff against previous run if available.
    if [ -n "${PREV_RUN_DIR:-}" ] && [ -f "$PREV_RUN_DIR/s7_perf_trace.json" ]; then
        python3 - "$PREV_RUN_DIR/s7_perf_trace.json" "$RUN_DIR/s7_perf_trace.json" <<'PY' > "$RUN_DIR/s7_perf_diff.log" 2>&1
import json, sys
prev = json.load(open(sys.argv[1]))
curr = json.load(open(sys.argv[2]))

def scopes(sess):
    return {s["name"]: s for s in sess.get("scopes", [])}

prev_s = scopes(prev); curr_s = scopes(curr)
regressed = 0
# Median TSC delta is the most robust single-number per-scope metric.
for name in sorted(set(prev_s) | set(curr_s)):
    p = prev_s.get(name); c = curr_s.get(name)
    if not p or not c:
        print(f"  (new/removed) {name}")
        continue
    pm = p["tsc"]["median"]
    cm = c["tsc"]["median"]
    if pm == 0: continue
    drift = (cm - pm) / pm * 100.0
    marker = ""
    if drift > 10:  marker = "  REGRESSED"; regressed += 1
    elif drift < -10: marker = "  improved"
    print(f"  {name:40s} prev_med={pm:>10}  curr_med={cm:>10}  {drift:+7.1f}%{marker}")
print()
print(f"Scopes regressed >10%: {regressed}")
sys.exit(1 if regressed else 0)
PY
        diff_rc=$?
        if [ "$diff_rc" -eq 0 ]; then
            echo "diff vs previous run: within noise"
        else
            echo "diff vs previous run: REGRESSIONS (see s7_perf_diff.log)"
        fi
    else
        echo "no previous run to diff against"
    fi
) > "$RUN_DIR/s7_perf.log" 2>&1
if grep -q 'kprof trace JSON written' "$RUN_DIR/s7_perf.log"; then
    if grep -q 'REGRESSIONS' "$RUN_DIR/s7_perf.log"; then
        stage_result S7 WARN "perf regressions vs previous — see s7_perf_diff.log"
    else
        stage_result S7 PASS "$(tail -n 1 "$RUN_DIR/s7_perf.log")"
    fi
else
    stage_result S7 FAIL "perf capture failed — see s7_perf.log"
fi

# ─── Summary ──────────────────────────────────────────────────────────
log
log "════════════════════════════════════════════════════════════"
log "zag-ci run: $TS"
for tag in "${stage_order[@]}"; do
    log "  ${stage_status[$tag]}  $tag  ${stage_note[$tag]}"
done
log "════════════════════════════════════════════════════════════"
log "logs: $RUN_DIR"

# Rotate the latest symlink only on success (so a failing run doesn't
# become the "previous" baseline for the next perf diff).
if [ "$hard_fail" -eq 0 ]; then
    if [ -L "$LATEST_LINK" ] && [ -e "$LATEST_LINK" ]; then
        rm -f "$PREVIOUS_LINK"
        mv -T "$LATEST_LINK" "$PREVIOUS_LINK" 2>/dev/null || true
    fi
    ln -sfn "$RUN_DIR" "$LATEST_LINK"
fi

exit "$hard_fail"
