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
date -u +%s > "$RUN_DIR/.start_ts"

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

# ─── stage 0: zig fmt --check ─────────────────────────────────────────
stage_start fmt "zig fmt --check on all .zig sources"
(
    # `zig fmt --check <path>` walks directories recursively, so we
    # point it at the top-level source roots and let it find every
    # .zig file. Skip .zig-cache (build artifacts, auto-generated).
    targets=(bootloader hyprvOS kernel routerOS tests)
    existing=()
    for t in "${targets[@]}"; do
        [ -d "$ZAG_ROOT/$t" ] && existing+=("$ZAG_ROOT/$t")
    done
    [ -f "$ZAG_ROOT/build.zig" ] && existing+=("$ZAG_ROOT/build.zig")
    zig fmt --check "${existing[@]}"
) > "$RUN_DIR/fmt.log" 2>&1
if [ -s "$RUN_DIR/fmt.log" ]; then
    bad="$(wc -l < "$RUN_DIR/fmt.log")"
    stage_result fmt FAIL "$bad files would be reformatted — see fmt.log (run \`zig fmt\` to fix)"
else
    stage_result fmt PASS
fi

# ─── stage 1: x86 kernel tests ────────────────────────────────────────
stage_start x64_kernel "x86 kernel tests (KVM, 590)"
(
    rm -rf "$ZAG_ROOT/.zig-cache" "$ZAG_ROOT/zig-out"
    PARALLEL="${PARALLEL:-4}" ARCH=x64 bash "$ZAG_ROOT/tests/tests/run_tests.sh"
) >"$RUN_DIR/x64_kernel.log" 2>&1
# KVM at PARALLEL=4..8 has a well-known flake rate on the s2_2_34 /
# s4_1_107 / s6_11 noise-sensitive tests. Re-run each failing test
# serially once with a fresh QEMU boot before declaring x64_kernel a failure.
# Any test that fails BOTH runs is a real regression.
x64_kernel_fails="$(grep -aE '^\s*\[FAIL\] s[0-9]+_[0-9]+_[0-9]+' "$RUN_DIR/x64_kernel.log" | sed 's/.*\[FAIL\] //; s/ .*//' | sort -u)"
if [ -n "$x64_kernel_fails" ]; then
    echo "== retrying ${x64_kernel_fails} serially ==" >> "$RUN_DIR/x64_kernel.log"
    real_fails=0
    flakes=0
    IMG="$ZAG_ROOT/zig-out/img"; BIN="$ZAG_ROOT/tests/tests/bin"
    for t in $x64_kernel_fails; do
        wd="$(mktemp -d)"
        mkdir -p "$wd/efi/boot"
        cp "$IMG/efi/boot/BOOTX64.EFI" "$wd/efi/boot/"
        cp "$IMG/kernel.elf" "$wd/"
        cp "$BIN/$t.elf" "$wd/root_service.elf" 2>/dev/null || { echo "  retry $t: no elf" >> "$RUN_DIR/x64_kernel.log"; real_fails=$((real_fails+1)); continue; }
        res="$(timeout 60 qemu-system-x86_64 -m 2G -bios /usr/share/ovmf/x64/OVMF.4m.fd -serial stdio -display none -no-reboot -enable-kvm -cpu host,+invtsc -machine q35 -device intel-iommu,intremap=off -net none -smp cores=4 -drive "file=fat:rw:$wd,format=raw" 2>&1 | grep -aE '\[PASS\]|\[FAIL\]' | head -n 1 || true)"
        rm -rf "$wd"
        if echo "$res" | grep -q '\[PASS\]'; then
            flakes=$((flakes+1))
            echo "  retry $t: FLAKE (pass alone)" >> "$RUN_DIR/x64_kernel.log"
        else
            real_fails=$((real_fails+1))
            echo "  retry $t: REAL ($res)" >> "$RUN_DIR/x64_kernel.log"
        fi
    done
    total="$(grep -E '^Total:' "$RUN_DIR/x64_kernel.log" | tail -n 1)"
    if [ "$real_fails" -eq 0 ]; then
        stage_result x64_kernel PASS "$total ($flakes flake(s) recovered)"
    else
        stage_result x64_kernel FAIL "$total — $real_fails real fail(s), $flakes flake(s) — see x64_kernel.log"
    fi
else
    total="$(grep -E '^Total:' "$RUN_DIR/x64_kernel.log" | tail -n 1)"
    stage_result x64_kernel PASS "$total"
fi

# ─── stage 2: x86 Linux boot ──────────────────────────────────────────
stage_start x64_linux "x86 Linux guest boot (hyprvOS)"
if bash "$ZAG_ROOT/tests/test.sh" linux > "$RUN_DIR/x64_linux.log" 2>&1; then
    stage_result x64_linux PASS
else
    stage_result x64_linux FAIL "see x64_linux.log"
fi

# ─── stage 3: aarch64 kernel tests (Pi 5 KVM or TCG fallback) ─────────
stage_start arm_kernel "aarch64 kernel tests (Pi 5 KVM preferred)"
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
    ) > "$RUN_DIR/arm_kernel_build.log" 2>&1 || {
        stage_result arm_kernel FAIL "aarch64 build failed — see arm_kernel_build.log"
    }
    if [ -z "${stage_status[arm_kernel]:-}" ]; then
        (
            ssh "$PI_HOST" "mkdir -p $PI_REMOTE_DIR/{img/efi/boot,tests/bin} && rm -f $PI_REMOTE_DIR/tests/bin/s*.elf"
            scp "$ZAG_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" "$PI_HOST:$PI_REMOTE_DIR/img/efi/boot/" >/dev/null
            scp "$ZAG_ROOT/zig-out/img/kernel.elf"           "$PI_HOST:$PI_REMOTE_DIR/img/"          >/dev/null
            # Exclude s4_2_* (VM tests) from the Pi sweep — Pi 5 KVM
            # doesn't support nested virt, so they'd all NOOUT and
            # drown the result. arm_vm runs §4.2 under local TCG instead.
            (cd "$ZAG_ROOT/tests/tests/bin" && tar c --exclude='s4_2_*.elf' s*.elf | ssh "$PI_HOST" "cd $PI_REMOTE_DIR/tests/bin && tar x")
            # Copy and rewrite runner.sh so ZAG_DIR points at our upload.
            ssh "$PI_HOST" "sed 's|~/zag-test[a-zA-Z0-9_-]*|~/$PI_REMOTE_DIR|g' ~/zag-test/runner.sh > ~/$PI_REMOTE_DIR/runner.sh && chmod +x ~/$PI_REMOTE_DIR/runner.sh"
            # Pi 5 has 4 cores but the KVM vCPU count per test (smp=4)
            # plus the runner's fan-out oversubscribes the host — tests
            # start timing out under contention, which shows up as NOOUT
            # rather than real failures. Keep PARALLEL low and TIMEOUT
            # generous so the baseline is as stable as the kernel allows.
            ssh "$PI_HOST" "cd ~/$PI_REMOTE_DIR && PARALLEL=${PI_PARALLEL:-2} LIMIT=10000 TIMEOUT=${PI_TIMEOUT:-30} bash runner.sh"
        ) > "$RUN_DIR/arm_kernel_pi.log" 2>&1
        summary_line="$(grep -E '^(PASS|FAIL|NOOUT|Total):' "$RUN_DIR/arm_kernel_pi.log" | tr '\n' ' ')"
        # One-shot retry — every FAIL/NOOUT gets re-run alone on the Pi
        # at the full per-test timeout. Flakes (timing-sensitive tests
        # that couldn't complete under vCPU contention) recover; real
        # failures stay failures.
        arm_kernel_flaky="$(grep -aE '^s[0-9]+_[0-9]+_[0-9]+: (\[NOOUT\]|.*\[FAIL\])' "$RUN_DIR/arm_kernel_pi.log" | cut -d: -f1 | sort -u)"
        if [ -n "$arm_kernel_flaky" ]; then
            echo "" >> "$RUN_DIR/arm_kernel_pi.log"
            echo "== arm_kernel retry (serial, one-shot) ==" >> "$RUN_DIR/arm_kernel_pi.log"
            arm_kernel_real_fails=0; arm_kernel_recovered=0
            for t in $arm_kernel_flaky; do
                pf=$(ssh "$PI_HOST" "cd ~/$PI_REMOTE_DIR && wd=\$(mktemp -d) && mkdir -p \$wd/efi/boot && cp img/efi/boot/BOOTAA64.EFI \$wd/efi/boot/ && cp img/kernel.elf \$wd/ && cp tests/bin/$t.elf \$wd/root_service.elf && timeout 30 qemu-system-aarch64 -M virt,gic-version=2 -m 1G -bios /usr/share/AAVMF/AAVMF_CODE.fd -serial stdio -display none -no-reboot -machine accel=kvm -cpu host -smp cores=4 -drive \"file=fat:rw:\$wd,format=raw\" 2>&1 | grep -aE '\\[PASS\\]|\\[FAIL\\]' | head -n 1 ; rm -rf \$wd" 2>/dev/null)
                if echo "$pf" | grep -q '\[PASS\]'; then
                    arm_kernel_recovered=$((arm_kernel_recovered+1))
                    echo "  retry $t: FLAKE (recovered alone)" >> "$RUN_DIR/arm_kernel_pi.log"
                else
                    arm_kernel_real_fails=$((arm_kernel_real_fails+1))
                    echo "  retry $t: REAL ($pf)" >> "$RUN_DIR/arm_kernel_pi.log"
                fi
            done
            summary_line="$summary_line (retry: $arm_kernel_recovered flakes recovered, $arm_kernel_real_fails real)"
            if [ "$arm_kernel_real_fails" -eq 0 ]; then
                stage_result arm_kernel PASS "$summary_line"
            else
                stage_result arm_kernel FAIL "$summary_line — $arm_kernel_real_fails real fail(s) after retry, see arm_kernel_pi.log"
            fi
        else
            stage_result arm_kernel PASS "$summary_line"
        fi
    fi
else
    # TCG fallback — run full 590 tests under TCG. Slow (~60 min).
    (
        rm -rf "$ZAG_ROOT/.zig-cache" "$ZAG_ROOT/zig-out"
        PARALLEL="${PARALLEL:-2}" ARCH=arm bash "$ZAG_ROOT/tests/tests/run_tests.sh"
    ) > "$RUN_DIR/arm_kernel_tcg.log" 2>&1
    total="$(grep -E '^Total:' "$RUN_DIR/arm_kernel_tcg.log" | tail -n 1)"
    # One-shot retry like x64_kernel: re-run any failing test serially with a
    # fresh QEMU boot. Flakes under parallel-TCG recover; real regressions
    # stay real.
    arm_kernel_tcg_fails="$(grep -aE '^\s*\[FAIL\] s[0-9]+_[0-9]+_[0-9]+' "$RUN_DIR/arm_kernel_tcg.log" | sed 's/.*\[FAIL\] //; s/ .*//' | sort -u)"
    if [ -n "$arm_kernel_tcg_fails" ]; then
        echo "== retrying ${arm_kernel_tcg_fails} serially ==" >> "$RUN_DIR/arm_kernel_tcg.log"
        real_fails=0; flakes=0
        IMG="$ZAG_ROOT/zig-out/img"; BIN="$ZAG_ROOT/tests/tests/bin"
        for t in $arm_kernel_tcg_fails; do
            wd="$(mktemp -d)"
            mkdir -p "$wd/efi/boot"
            cp "$IMG/efi/boot/BOOTAA64.EFI" "$wd/efi/boot/"
            cp "$IMG/kernel.elf" "$wd/"
            cp "$BIN/$t.elf" "$wd/root_service.elf" 2>/dev/null || { echo "  retry $t: no elf" >> "$RUN_DIR/arm_kernel_tcg.log"; real_fails=$((real_fails+1)); continue; }
            res="$(timeout 60 qemu-system-aarch64 -M virt,virtualization=on,gic-version=3 -m 1G -bios /usr/share/AAVMF/AAVMF_CODE.fd -serial stdio -display none -no-reboot -machine accel=tcg -cpu cortex-a72 -smp cores=4 -drive "file=fat:rw:$wd,format=raw" 2>&1 | grep -aE '\[PASS\]|\[FAIL\]' | head -n 1 || true)"
            rm -rf "$wd"
            if echo "$res" | grep -q '\[PASS\]'; then
                flakes=$((flakes+1))
                echo "  retry $t: FLAKE (pass alone)" >> "$RUN_DIR/arm_kernel_tcg.log"
            else
                real_fails=$((real_fails+1))
                echo "  retry $t: REAL ($res)" >> "$RUN_DIR/arm_kernel_tcg.log"
            fi
        done
        if [ "$real_fails" -eq 0 ]; then
            stage_result arm_kernel PASS "$total ($flakes flake(s) recovered)"
        else
            stage_result arm_kernel FAIL "$total — $real_fails real fail(s) after retry, $flakes flake(s) — see arm_kernel_tcg.log"
        fi
    elif grep -q '^Total: .* 0 fail ' "$RUN_DIR/arm_kernel_tcg.log"; then
        stage_result arm_kernel PASS "$total"
    else
        stage_result arm_kernel FAIL "$total — see arm_kernel_tcg.log"
    fi
fi

# ─── stage 4: §4.2 TCG (VM tests) ─────────────────────────────────────
stage_start arm_vm "aarch64 §4.2 VM tests (TCG)"
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
) > "$RUN_DIR/arm_vm.log" 2>&1
tail_line="$(tail -n 1 "$RUN_DIR/arm_vm.log")"
if echo "$tail_line" | grep -q 'FAIL=0 NOOUT=0'; then
    stage_result arm_vm PASS "$tail_line"
else
    stage_result arm_vm FAIL "$tail_line — see arm_vm.log"
fi

# ─── stage 5: aarch64 Linux boot ──────────────────────────────────────
stage_start arm_linux "aarch64 Linux guest boot (hyprvOS, TCG)"
if bash "$ZAG_ROOT/tests/test.sh" linux-arm > "$RUN_DIR/arm_linux.log" 2>&1; then
    stage_result arm_linux PASS
else
    stage_result arm_linux FAIL "see arm_linux.log"
fi

# ─── stage 6: Redteam PoC suite (x86) ─────────────────────────────────
stage_start redteam "Redteam PoCs (x86)"
mkdir -p "$RUN_DIR/redteam"
redteam_pass=0; redteam_fail=0
for poc in "$ZAG_ROOT"/tests/redteam/*.zig; do
    name="$(basename "$poc" .zig)"
    # Children / helper ELFs that aren't standalone PoCs — skip.
    case "$name" in child_*|p1_bad|gen_p1_elf) continue ;; esac
    out="$RUN_DIR/redteam/$name.log"
    (cd "$ZAG_ROOT/tests/redteam" && bash ./run.sh "$name.zig") > "$out" 2>&1 || true
    # Detection: any line containing "VULNERABLE" = regression.
    if grep -q 'VULNERABLE' "$out"; then
        redteam_fail=$((redteam_fail+1))
        echo "  [FAIL] $name — VULNERABLE marker found"
    else
        redteam_pass=$((redteam_pass+1))
    fi
done > "$RUN_DIR/redteam_summary.log" 2>&1
if [ "$redteam_fail" -eq 0 ]; then
    stage_result redteam PASS "redteam: $redteam_pass pocs clean"
else
    stage_result redteam FAIL "redteam: $redteam_fail regressions (see redteam/)"
fi

# ─── perf report helper ─────────────────────────────────────────────
# Write a human-readable perf report comparing two parse_kprof --json
# dumps. Covers: session metadata, per-scope tsc/cycles/cache/branch
# tables sorted by total-time-spent, and a regression section listing
# any scope whose median drifted by ≥10% in either direction. Emits
# `perf_regressions: <N>` on the last line for the CI to count.
# Exit 0 if no regressions ≥10%, 1 otherwise.
perf_diff_scopes() {
    local prev_json="$1" curr_json="$2" out="$3"
    python3 - "$prev_json" "$curr_json" <<'PY' > "$out" 2>&1
import json, sys

REGR_PCT = 10.0  # scopes drifting ≥ this much are flagged

def load(p):
    with open(p) as fh: return json.load(fh)

prev = load(sys.argv[1])
curr = load(sys.argv[2])

def scopes(sess):
    return {s["name"]: s for s in sess.get("scopes", [])}

prev_s = scopes(prev); curr_s = scopes(curr)
names  = sorted(set(prev_s) | set(curr_s))

# ── 1. header ───────────────────────────────────────────────────
print("═════ kprof perf report ═════")
print(f"mode:        {curr.get('mode','?')}")
print(f"cpus:        {curr.get('cpus','?')}")
print(f"reason:      {curr.get('reason','?')}")
print(f"records:     {curr.get('records','?')} (prev: {prev.get('records','?')})")
print(f"scopes:      {len(curr_s)} (prev: {len(prev_s)})")
oe_p, oe_c = prev.get('orphan_enters',0), curr.get('orphan_enters',0)
ox_p, ox_c = prev.get('orphan_exits',0),  curr.get('orphan_exits',0)
if oe_c or ox_c or oe_p or ox_p:
    print(f"orphans:     enters {oe_p}→{oe_c}, exits {ox_p}→{ox_c}")
print()

# ── 2. per-metric tables: top scopes by current total ───────────
def metric_table(metric, title):
    rows = []
    for n in names:
        c = curr_s.get(n); p = prev_s.get(n)
        cm = c[metric] if c else None
        pm = p[metric] if p else None
        curr_total  = cm["total"]  if cm else 0
        curr_median = cm["median"] if cm else 0
        curr_count  = cm["count"]  if cm else 0
        prev_median = pm["median"] if pm else 0
        if prev_median > 0 and curr_median > 0:
            drift = (curr_median - prev_median) / prev_median * 100.0
        else:
            drift = None
        rows.append((n, curr_count, curr_median, curr_total, prev_median, drift, cm is None, pm is None))
    rows.sort(key=lambda r: r[3], reverse=True)  # by current total

    print(f"─── {title} (sorted by total, top 20) ───")
    print(f"  {'scope':<36} {'count':>7} {'med':>12} {'total':>15} {'prev_med':>12} {'drift%':>8}")
    for row in rows[:20]:
        n, cnt, med, tot, pmed, drift, missing_c, missing_p = row
        if missing_c:
            line = f"  {n:<36} {'—':>7} {'—':>12} {'—':>15}"
            line += f" {pmed:>12} {'REMOVED':>8}"
        elif missing_p:
            line = f"  {n:<36} {cnt:>7} {med:>12} {tot:>15} {'—':>12} {'NEW':>8}"
        else:
            d = f"{drift:+6.1f}%" if drift is not None else "—"
            marker = ""
            if drift is not None:
                if drift >=  REGR_PCT: marker = "  ↑"
                elif drift <= -REGR_PCT: marker = "  ↓"
            line = f"  {n:<36} {cnt:>7} {med:>12} {tot:>15} {pmed:>12} {d:>8}{marker}"
        print(line)
    print()

for key, title in (("tsc","tsc (wall cycles)"),
                   ("cycles","cycles (PMC)"),
                   ("cache_misses","cache_misses (PMC)"),
                   ("branch_misses","branch_misses (PMC)")):
    metric_table(key, title)

# ── 3. regressions & improvements section ───────────────────────
regressions = []
improvements = []
for n in names:
    p = prev_s.get(n); c = curr_s.get(n)
    if not p or not c: continue
    pm = p["tsc"]["median"]; cm = c["tsc"]["median"]
    if pm == 0: continue
    drift = (cm - pm) / pm * 100.0
    row = (n, pm, cm, drift, p["tsc"]["count"], c["tsc"]["count"])
    if   drift >=  REGR_PCT: regressions.append(row)
    elif drift <= -REGR_PCT: improvements.append(row)

regressions.sort(key=lambda r: -r[3])
improvements.sort(key=lambda r: r[3])

print(f"─── regressions (median tsc ≥ {REGR_PCT:.0f}%) ───")
if not regressions:
    print("  (none)")
else:
    for n, pm, cm, d, pc, cc in regressions:
        print(f"  {n:<36} prev_med={pm:>10}  curr_med={cm:>10}  {d:+7.1f}%  (n={pc}→{cc})")
print()
print(f"─── improvements (median tsc ≤ -{REGR_PCT:.0f}%) ───")
if not improvements:
    print("  (none)")
else:
    for n, pm, cm, d, pc, cc in improvements:
        print(f"  {n:<36} prev_med={pm:>10}  curr_med={cm:>10}  {d:+7.1f}%  (n={pc}→{cc})")
print()

# ── 4. new/removed scopes ───────────────────────────────────────
new_scopes     = [n for n in names if n in curr_s and n not in prev_s]
removed_scopes = [n for n in names if n in prev_s and n not in curr_s]
print("─── scope set changes ───")
if new_scopes:
    print(f"  NEW:     {', '.join(new_scopes)}")
if removed_scopes:
    print(f"  REMOVED: {', '.join(removed_scopes)}")
if not new_scopes and not removed_scopes:
    print("  (no changes)")
print()

# ── 5. trailer — one-line result used by the CI driver ──────────
print(f"perf_regressions: {len(regressions)}")
sys.exit(1 if regressions else 0)
PY
}

# ─── stage 7a: Perf x86 (composed debugger+shm_cycle, trace mode) ─────
stage_start perf_x64 "Perf trace (composed workload, x86 KVM)"
(
    (cd "$ZAG_ROOT/tests/prof" && zig build -Dworkload=composed) || exit 1
    rm -rf "$ZAG_ROOT/.zig-cache" "$ZAG_ROOT/zig-out"
    zig build -Dprofile=prof -Dkernel_profile=trace || exit 1
    qemu_log="$RUN_DIR/perf_x64_serial.log"
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

    python3 "$ZAG_ROOT/kernel/kprof/tools/parse_kprof.py" \
        "$qemu_log" --json > "$RUN_DIR/perf_x64.json" 2> "$RUN_DIR/perf_x64_parse.err" \
        || { echo "parse_kprof.py failed"; exit 1; }
    echo "kprof x86 trace JSON written to perf_x64.json"

    if [ -n "${PREV_RUN_DIR:-}" ] && [ -f "$PREV_RUN_DIR/perf_x64.json" ]; then
        if perf_diff_scopes "$PREV_RUN_DIR/perf_x64.json" "$RUN_DIR/perf_x64.json" "$RUN_DIR/perf_x64_diff.log"; then
            echo "x86 diff vs previous run: within noise"
        else
            echo "x86 diff vs previous run: REGRESSIONS (see perf_x64_diff.log)"
        fi
    else
        echo "no previous x86 run to diff against"
    fi
) > "$RUN_DIR/perf_x64.log" 2>&1
if [ -s "$RUN_DIR/perf_x64.json" ]; then
    if [ -f "$RUN_DIR/perf_x64_diff.log" ]; then
        regr="$(grep -E '^perf_regressions:' "$RUN_DIR/perf_x64_diff.log" | awk '{print $2}')"
        scopes_n="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1])).get("scopes",[])))' "$RUN_DIR/perf_x64.json" 2>/dev/null || echo 0)"
        if [ "${regr:-0}" -gt 0 ]; then
            stage_result perf_x64 WARN "$scopes_n scopes traced; $regr regression(s) ≥10% — see perf_x64_diff.log"
        else
            stage_result perf_x64 PASS "$scopes_n scopes traced; no regressions"
        fi
    else
        scopes_n="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1])).get("scopes",[])))' "$RUN_DIR/perf_x64.json" 2>/dev/null || echo 0)"
        stage_result perf_x64 PASS "$scopes_n scopes traced (no previous run to diff)"
    fi
else
    stage_result perf_x64 FAIL "x86 perf capture failed — see perf_x64.log"
fi

# ─── stage 7b: Perf aarch64 (composed workload, Pi KVM or TCG) ────────
stage_start perf_arm "Perf trace (composed workload, aarch64)"
(
    # Build arm composed root_service + arm kernel with trace mode.
    (cd "$ZAG_ROOT/tests/prof" && zig build -Darch=arm -Dworkload=composed) || exit 1
    rm -rf "$ZAG_ROOT/.zig-cache" "$ZAG_ROOT/zig-out"
    zig build -Darch=arm -Dprofile=prof -Dkernel_profile=trace || exit 1

    qemu_log="$RUN_DIR/perf_arm_serial.log"
    if [ "$aarch64_host" = "pi" ]; then
        # Copy artifacts to Pi and boot under real KVM there.
        ssh "$PI_HOST" "mkdir -p ~/zag-perf-ci/{img/efi/boot}"
        scp "$ZAG_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" "$PI_HOST:zag-perf-ci/img/efi/boot/" >/dev/null
        scp "$ZAG_ROOT/zig-out/img/kernel.elf"           "$PI_HOST:zag-perf-ci/img/"          >/dev/null
        scp "$ZAG_ROOT/tests/prof/bin/root_service.elf"  "$PI_HOST:zag-perf-ci/"              >/dev/null
        ssh "$PI_HOST" "cd zag-perf-ci && wd=\$(mktemp -d) && mkdir -p \$wd/efi/boot && cp img/efi/boot/BOOTAA64.EFI \$wd/efi/boot/ && cp img/kernel.elf \$wd/ && cp root_service.elf \$wd/root_service.elf && timeout 60 qemu-system-aarch64 -M virt,gic-version=2 -m 1G -bios /usr/share/AAVMF/AAVMF_CODE.fd -serial stdio -display none -no-reboot -machine accel=kvm -cpu host -smp cores=4 -drive \"file=fat:rw:\$wd,format=raw\" ; rm -rf \$wd" > "$qemu_log" 2>&1 || true
    else
        workdir="$(mktemp -d)"
        mkdir -p "$workdir/efi/boot"
        cp "$ZAG_ROOT/zig-out/img/efi/boot/BOOTAA64.EFI" "$workdir/efi/boot/"
        cp "$ZAG_ROOT/zig-out/img/kernel.elf"            "$workdir/"
        cp "$ZAG_ROOT/tests/prof/bin/root_service.elf"   "$workdir/root_service.elf"
        timeout 120 qemu-system-aarch64 \
            -M virt,virtualization=on,gic-version=3 -m 1G \
            -bios /usr/share/AAVMF/AAVMF_CODE.fd \
            -serial stdio -display none -no-reboot \
            -machine accel=tcg -cpu cortex-a72 -smp cores=4 \
            -drive "file=fat:rw:$workdir,format=raw" > "$qemu_log" 2>&1 || true
        rm -rf "$workdir"
    fi

    python3 "$ZAG_ROOT/kernel/kprof/tools/parse_kprof.py" \
        "$qemu_log" --json > "$RUN_DIR/perf_arm.json" 2> "$RUN_DIR/perf_arm_parse.err" \
        || { echo "parse_kprof.py failed"; exit 1; }
    echo "kprof arm trace JSON written to perf_arm.json"

    if [ -n "${PREV_RUN_DIR:-}" ] && [ -f "$PREV_RUN_DIR/perf_arm.json" ]; then
        if perf_diff_scopes "$PREV_RUN_DIR/perf_arm.json" "$RUN_DIR/perf_arm.json" "$RUN_DIR/perf_arm_diff.log"; then
            echo "arm diff vs previous run: within noise"
        else
            echo "arm diff vs previous run: REGRESSIONS (see perf_arm_diff.log)"
        fi
    else
        echo "no previous arm run to diff against"
    fi
) > "$RUN_DIR/perf_arm.log" 2>&1
if [ -s "$RUN_DIR/perf_arm.json" ]; then
    if [ -f "$RUN_DIR/perf_arm_diff.log" ]; then
        regr="$(grep -E '^perf_regressions:' "$RUN_DIR/perf_arm_diff.log" | awk '{print $2}')"
        scopes_n="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1])).get("scopes",[])))' "$RUN_DIR/perf_arm.json" 2>/dev/null || echo 0)"
        if [ "${regr:-0}" -gt 0 ]; then
            stage_result perf_arm WARN "$scopes_n scopes traced; $regr regression(s) ≥10% — see perf_arm_diff.log"
        else
            stage_result perf_arm PASS "$scopes_n scopes traced; no regressions"
        fi
    else
        scopes_n="$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1])).get("scopes",[])))' "$RUN_DIR/perf_arm.json" 2>/dev/null || echo 0)"
        stage_result perf_arm PASS "$scopes_n scopes traced (no previous run to diff)"
    fi
else
    stage_result perf_arm FAIL "arm perf capture failed — see perf_arm.log"
fi

# ─── Summary ──────────────────────────────────────────────────────────
run_end_ts="$(date -u +%s)"
run_start_ts_file="$RUN_DIR/.start_ts"
if [ -f "$run_start_ts_file" ]; then
    dur="$(($run_end_ts - $(cat "$run_start_ts_file")))"
    dur_fmt="$(printf '%02d:%02d:%02d' $((dur/3600)) $(((dur%3600)/60)) $((dur%60)))"
else
    dur_fmt="?"
fi

log
log "════════════════════════════════════════════════════════════"
log "zag-ci run: $TS  (wall: $dur_fmt)"
for tag in "${stage_order[@]}"; do
    log "  ${stage_status[$tag]}  $tag  ${stage_note[$tag]}"
done
log "════════════════════════════════════════════════════════════"

# Inline the top regressions in the summary so they're visible without
# chasing log files.
for arch in x64 arm; do
    diff_log="$RUN_DIR/perf_${arch}_diff.log"
    [ -f "$diff_log" ] || continue
    regr_count="$(grep -E '^perf_regressions:' "$diff_log" | awk '{print $2}')"
    [ "${regr_count:-0}" -gt 0 ] || continue
    log
    log "─── perf ($arch) regressions ≥10% ───"
    awk '/^─── regressions/{flag=1; next} /^─── improvements/{flag=0} flag' "$diff_log" \
        | head -n 10 | while IFS= read -r line; do log "$line"; done
done

log
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
