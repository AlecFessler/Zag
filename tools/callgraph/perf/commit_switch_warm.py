#!/usr/bin/env python3
"""Warm-only commit-switch perf — what the user actually feels.

Pre-requisite: a callgraph server already running with the target
commits warmed (their /var/tmp/cg-worktrees entries built). The script
does NOT spawn a server; pass --port and the existing server is used.
This skips the multi-minute zig-build cold path entirely so the harness
finishes in ~30s.

Output JSON has per-switch total_ms + the per-phase breakdown read from
window.__cgPerfMarks (see app.js cgPerfMark).
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PERF_DIR = Path(__file__).resolve().parent
DEFAULT_PORT = 8082
DEFAULT_OUT = PERF_DIR / "commit_switch_warm.json"

# Pairs of pre-built commits to ping-pong between. The harness verifies
# each is "ready" via /api/load_commit/status before starting; any not-
# ready ones get skipped (they're already cold and we don't want to
# trigger a build inside the perf loop).
DEFAULT_COMMITS = [
    "9945b32cf2a8c0773df5f9a5a9b39a9c79edc3b6",
    "e8a2d3702b0e969f4be3f1b99a5038339849f822",
    "8f260a5044ceb1e34c4fa53a48bdafbe385f1d64",
    "27b32b084bb82d25d671ced3fcccf081b3c44293",
    "c210d289662ec2782e8297afde4491ad961ed51e",
]
REPS = 3


def first_mark(marks, name):
    for m in marks:
        if m["name"] == name:
            return float(m["t"])
    return None


def phase_ms(marks, start, end):
    s = first_mark(marks, start)
    e = first_mark(marks, end)
    if s is None or e is None or e < s:
        return None
    return round(e - s, 2)


def run(port, out_path, commits, reps):
    from playwright.sync_api import sync_playwright

    measurements = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1800, "height": 1200})
        page = ctx.new_page()
        page.on("pageerror", lambda exc: print(f"[pageerror] {exc}", flush=True))

        page.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")
        page.wait_for_function("() => window.__cgRenderCount >= 1", timeout=30000)

        # Verify the targets are cg-compatible. Then trigger loads for
        # each (server skips zig build when IR is already on disk under
        # /var/tmp/cg-worktrees/<sha>/zig-out, so this only pays the
        # AST walk + IR parse + graph build cost — slow but bounded).
        compat = page.evaluate("""async () => {
            const r = await fetch('/api/commits?limit=80');
            const j = await r.json();
            const c = new Set();
            for (const x of (j.commits || [])) if (x.cg_compatible) c.add(x.sha);
            return Array.from(c);
        }""")
        compat_set = set(compat)
        targets = [c for c in commits if c in compat_set]
        if len(targets) < 2:
            raise SystemExit(
                f"need 2+ cg-compatible commits; got {len(targets)} from {commits}"
            )

        print(f"[harness] priming {len(targets)} commits "
              f"(this is the slow part — server-side load)", flush=True)
        # Kick off all loads in parallel.
        page.evaluate("""async (shas) => {
            await Promise.all(shas.map(s =>
                fetch('/api/load_commit?sha=' + s).then(r => r.json())
            ));
        }""", targets)
        # Poll status until all are ready (or errored).
        deadline = time.monotonic() + 600
        ready: list[str] = []
        while time.monotonic() < deadline and len(ready) < len(targets):
            statuses = page.evaluate("""async (shas) => {
                const out = {};
                for (const s of shas) {
                  const r = await fetch('/api/load_commit/status?sha=' + s);
                  out[s] = r.ok ? (await r.json()).status : 'fetch_error';
                }
                return out;
            }""", targets)
            ready = [s for s, st in statuses.items() if st == "ready"]
            building = [(s, st) for s, st in statuses.items() if st in ("building", "not_loaded")]
            errored = [(s, st) for s, st in statuses.items() if st not in ("ready", "building", "not_loaded")]
            if errored:
                print(f"[skip] errored: {[(s[:7], st) for s, st in errored]}", flush=True)
            print(f"[prime] ready={len(ready)}/{len(targets)} "
                  f"building={len(building)}", flush=True)
            if len(ready) + len(errored) >= len(targets):
                break
            time.sleep(5)
        if len(ready) < 2:
            raise SystemExit(f"only {len(ready)} commits primed: {ready}")
        print(f"[harness] testing warm switches across {len(ready)} commits: "
              f"{[c[:7] for c in ready]}", flush=True)

        # Pin entry to kEntry (worst case).
        page.click(".mode_button[data-mode='trace']")
        page.wait_for_function(
            "() => document.querySelectorAll('#trace_view .trace_box').length > 0",
            timeout=30000,
        )
        kentry_id = page.evaluate("""() => {
            const opts = Array.from(document.getElementById('entry_select').options);
            const m = opts.find(o => /kEntry/.test(o.textContent));
            return m ? m.value : null;
        }""")
        if kentry_id:
            page.evaluate(
                "(v) => { const s = document.getElementById('entry_select');"
                "  s.value = v; s.dispatchEvent(new Event('change', {bubbles:true})); }",
                kentry_id,
            )
            page.wait_for_function("() => window.__cgRenderCount >= 2")

        # Use HEAD mode (X vs working tree) so the picked commit IS the
        # secondary — simplifies the "ready: <sha>" wait check. Parent
        # mode uses the same recomputeDiffSets / ensureSecGraph paths,
        # so warm timings transfer directly.
        page.select_option("#compare_mode", "head")
        page.wait_for_function(
            "() => document.getElementById('compare_commit').options.length > 1",
        )

        # Prime: load each commit once so secGraphs is populated. We don't
        # measure these — they're cold-from-the-frontend's perspective.
        for sha in ready:
            short = sha[:7]
            page.evaluate(
                "(v) => { const s = document.getElementById('compare_commit');"
                "  s.value = v; s.dispatchEvent(new Event('change', {bubbles:true})); }",
                sha,
            )
            page.wait_for_function(
                f"() => document.getElementById('compare_status').textContent.startsWith('ready: {short}')",
                timeout=120000,
            )

        # Now measure: cycle each commit `reps` times.
        rotation = ready * reps
        for i, sha in enumerate(rotation):
            short = sha[:7]
            page.evaluate("() => window.__cgPerfReset && window.__cgPerfReset()")
            t0 = page.evaluate("performance.now()")
            page.evaluate(
                "(v) => { const s = document.getElementById('compare_commit');"
                "  s.value = v; s.dispatchEvent(new Event('change', {bubbles:true})); }",
                sha,
            )
            page.wait_for_function(
                f"() => document.getElementById('compare_status').textContent.startsWith('ready: {short}')",
                timeout=120000,
            )
            page.wait_for_function(
                "() => document.querySelectorAll('#trace_view_b .trace_box').length > 0",
                timeout=120000,
            )
            t1 = page.evaluate("performance.now()")
            marks = page.evaluate("() => window.__cgPerfMarks ? window.__cgPerfMarks.slice() : []")
            phases = {
                "activateCompare_ms": phase_ms(marks, "activateCompare:start", "activateCompare:done"),
                "ensureSecGraph_fetch_ms": phase_ms(marks, "ensureSecGraph:fetchStart", "ensureSecGraph:bodyDone"),
                "ensureSecGraph_total_ms": phase_ms(marks, "ensureSecGraph:fetchStart", "ensureSecGraph:done"),
                "ensureSecGraph_cacheHit": any(m["name"] == "ensureSecGraph:cacheHit" for m in marks),
                "recomputeDiffSets_ms": phase_ms(marks, "recomputeDiffSets:start", "recomputeDiffSets:done"),
            }
            total = round(float(t1) - float(t0), 2)
            print(f"[#{i:02d}] {short} total={total:8.1f}ms  "
                  f"activate={phases['activateCompare_ms']}  "
                  f"graphFetch={phases['ensureSecGraph_fetch_ms']}  "
                  f"recompute={phases['recomputeDiffSets_ms']}  "
                  f"cacheHit={phases['ensureSecGraph_cacheHit']}", flush=True)
            measurements.append({
                "commit": sha,
                "total_ms": total,
                "phases": phases,
            })

        ctx.close()
        browser.close()

    # Aggregate medians per phase
    def med(xs):
        xs = [x for x in xs if x is not None]
        return round(statistics.median(xs), 2) if xs else None

    totals = [m["total_ms"] for m in measurements if m.get("total_ms") is not None]
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "port": port,
        "n": len(measurements),
        "summary": {
            "total_ms_median": med(totals),
            "total_ms_min": round(min(totals), 2) if totals else None,
            "total_ms_max": round(max(totals), 2) if totals else None,
            "activateCompare_ms_median": med([m["phases"].get("activateCompare_ms") for m in measurements]),
            "ensureSecGraph_fetch_ms_median": med([m["phases"].get("ensureSecGraph_fetch_ms") for m in measurements]),
            "recomputeDiffSets_ms_median": med([m["phases"].get("recomputeDiffSets_ms") for m in measurements]),
        },
        "measurements": measurements,
    }
    out_path.write_text(json.dumps(payload, indent=2))
    print(f"\n[summary] {payload['summary']}")
    print(f"[harness] wrote {out_path}", flush=True)
    return 0


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--commits", nargs="+", default=DEFAULT_COMMITS)
    p.add_argument("--reps", type=int, default=REPS)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sys.exit(run(args.port, args.out, args.commits, args.reps))
