#!/usr/bin/env python3
"""Commit-switch latency harness for the callgraph review feature.

Drives the Compare picker through a mix of cold (never-loaded) and warm
(cached) commits and records:

  - end-to-end wall-clock from "user picked commit X" until the trace
    pane is rendered with the OLDER side filled in,
  - per-phase breakdown read from window.__cgPerfMarks (each mark is
    {name, t_ms_since_navigationStart}):
      * activateCompare:start -> activateCompare:done
      * ensureSecGraph:fetchStart -> ensureSecGraph:bodyDone
      * recomputeDiffSets:start -> recomputeDiffSets:done

Cold commits exercise the worst case (server build can be slow) and
warm commits show the steady-state cost the user actually feels when
flipping back and forth between two reviews.

Output: JSON file consumable by `diff.py`. Fields per measurement:
  { "commit": "<sha>", "kind": "cold"|"warm",
    "total_ms": float,
    "phases": {"activateCompare_ms": float,
               "ensureSecGraph_fetch_ms": float,
               "recomputeDiffSets_ms": float},
  }
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

PERF_DIR = Path(__file__).resolve().parent
REPO_ROOT = PERF_DIR.parents[2]
KERNEL_ROOT = REPO_ROOT / "kernel"
CG_BIN = REPO_ROOT / "tools" / "callgraph" / "zig-out" / "bin" / "callgraph"
DEFAULT_PORT = 18845
DEFAULT_OUT = PERF_DIR / "commit_switch_results.json"

SERVER_BOOT_TIMEOUT_S = 90.0
RENDER_READY_TIMEOUT_MS = 90_000
COMMIT_LOAD_TIMEOUT_MS = 600_000  # cold builds can run several minutes

# Subset of recent commits we know (a) are post-emit_ir and (b) build
# cleanly enough to land "ready". The harness verifies via /api/commits
# and skips any sha that isn't cg_compatible.
DEFAULT_COMMITS = [
    "9945b32cf2a8c0773df5f9a5a9b39a9c79edc3b6",
    "e8a2d3702b0e969f4be3f1b99a5038339849f822",
    "8f260a5044ceb1e34c4fa53a48bdafbe385f1d64",
    "27b32b084bb82d25d671ced3fcccf081b3c44293",
    "c210d289662ec2782e8297afde4491ad961ed51e",
]


@contextmanager
def callgraph_server(port: int, build_root: Path, kernel_root: Path):
    if not CG_BIN.exists():
        raise SystemExit(f"callgraph binary missing at {CG_BIN}")
    cmd = [
        str(CG_BIN),
        "--build-root", str(build_root),
        "--kernel-root", str(kernel_root),
        "--port", str(port),
        "--no-build",
    ]
    print(f"[harness] launching {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, preexec_fn=os.setsid,
    )
    try:
        deadline = time.monotonic() + SERVER_BOOT_TIMEOUT_S
        while time.monotonic() < deadline:
            line = proc.stdout.readline() if proc.stdout else ""
            if line == "" and proc.poll() is not None:
                raise SystemExit(f"callgraph exited rc={proc.poll()}")
            if line:
                sys.stdout.write(f"[server] {line}")
                sys.stdout.flush()
                if "Listening" in line:
                    break
        else:
            raise SystemExit(f"callgraph did not start within {SERVER_BOOT_TIMEOUT_S:.0f}s")
        yield proc
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=5)
        except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True,
        ).strip()
    except Exception:
        return "unknown"


def read_marks(page) -> list[dict]:
    """Pull the mark buffer from window.__cgPerfMarks (set by app.js)."""
    return page.evaluate("() => window.__cgPerfMarks ? window.__cgPerfMarks.slice() : []")


def first_mark(marks: list[dict], name: str) -> float | None:
    for m in marks:
        if m["name"] == name:
            return float(m["t"])
    return None


def phase_ms(marks: list[dict], start: str, end: str) -> float | None:
    s = first_mark(marks, start)
    e = first_mark(marks, end)
    if s is None or e is None or e < s:
        return None
    return round(e - s, 2)


def select_commit(page, sha: str) -> None:
    """Drive the dropdown change deterministically via .value + dispatchEvent
    — Playwright's select_option occasionally races the change handler in
    headless chromium."""
    page.evaluate(
        "(v) => { const s = document.getElementById('compare_commit');"
        "  s.value = v; s.dispatchEvent(new Event('change', {bubbles:true})); }",
        sha,
    )


def wait_compare_ready(page, sha_short: str, timeout_ms: int) -> None:
    """Wait until #compare_status reads 'ready: <short>' and the OLDER
    trace pane has at least one trace_box (the user-visible done signal)."""
    page.wait_for_function(
        f"() => document.getElementById('compare_status').textContent.startsWith('ready: {sha_short}')",
        timeout=timeout_ms,
    )
    page.wait_for_function(
        "() => document.querySelectorAll('#trace_view_b .trace_box').length > 0",
        timeout=timeout_ms,
    )


def measure_switch(page, sha: str, label: str) -> dict:
    short = sha[:7]
    page.evaluate("() => window.__cgPerfReset && window.__cgPerfReset()")
    t0 = page.evaluate("performance.now()")
    select_commit(page, sha)
    wait_compare_ready(page, short, COMMIT_LOAD_TIMEOUT_MS)
    t1 = page.evaluate("performance.now()")
    marks = read_marks(page)
    return {
        "commit": sha,
        "label": label,
        "total_ms": round(float(t1) - float(t0), 2),
        "phases": {
            "activateCompare_ms": phase_ms(marks, "activateCompare:start", "activateCompare:done"),
            "ensureSecGraph_fetch_ms": phase_ms(marks, "ensureSecGraph:fetchStart", "ensureSecGraph:bodyDone"),
            "ensureSecGraph_total_ms": phase_ms(marks, "ensureSecGraph:fetchStart", "ensureSecGraph:done"),
            "recomputeDiffSets_ms": phase_ms(marks, "recomputeDiffSets:start", "recomputeDiffSets:done"),
        },
        "marks": marks,  # full timeline for post-hoc analysis
    }


def run(port: int, out_path: Path, build_root: Path, kernel_root: Path,
        commits: list[str]) -> int:
    from playwright.sync_api import sync_playwright

    measurements: list[dict] = []

    with callgraph_server(port, build_root, kernel_root) as _server, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(viewport={"width": 1800, "height": 1200})
        page = ctx.new_page()
        page.set_default_timeout(RENDER_READY_TIMEOUT_MS)
        page.on("pageerror", lambda exc: print(f"[pageerror] {exc}", flush=True))

        page.goto(f"http://127.0.0.1:{port}/", wait_until="domcontentloaded")
        page.wait_for_function("() => window.__cgRenderCount >= 1",
                               timeout=RENDER_READY_TIMEOUT_MS)

        # Filter to only commits the server says are cg-compatible.
        compat = page.evaluate("""async () => {
            const r = await fetch('/api/commits?limit=80');
            const j = await r.json();
            const ok = new Set();
            for (const c of (j.commits || [])) {
              if (c.cg_compatible) ok.add(c.sha);
            }
            return Array.from(ok);
        }""")
        compat_set = set(compat)
        commits = [c for c in commits if c in compat_set]
        if len(commits) < 2:
            raise SystemExit(
                f"need at least 2 cg-compatible commits in DEFAULT_COMMITS; "
                f"got {len(commits)}"
            )
        print(f"[harness] testing {len(commits)} commits: "
              f"{[c[:7] for c in commits]}", flush=True)

        # Park on a fixed entry so cycles are comparable across commits.
        # kEntry is the worst-case fan-out and reflects what the user
        # complains about most.
        page.click(".mode_button[data-mode='trace']")
        page.wait_for_function(
            "() => document.querySelectorAll('#trace_view .trace_box').length > 0",
            timeout=RENDER_READY_TIMEOUT_MS,
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

        # Switch to parent-mode comparison.
        page.select_option("#compare_mode", "parent")
        page.wait_for_function(
            "() => document.getElementById('compare_commit').options.length > 1",
            timeout=10000,
        )

        # 1) Cold pass: drive each commit fresh. The first switch to a
        #    sha pays the server build cost; subsequent reps see the
        #    in-memory cache.
        print("[harness] cold pass (commits in declared order)", flush=True)
        for sha in commits:
            try:
                m = measure_switch(page, sha, "cold")
                print(f"  cold  {sha[:7]} total={m['total_ms']:.0f}ms phases={m['phases']}", flush=True)
                measurements.append(m)
            except Exception as exc:
                print(f"[FAIL] cold {sha[:7]}: {exc}", flush=True)
                measurements.append({"commit": sha, "label": "cold",
                                     "total_ms": None, "phases": {}, "error": str(exc)})

        # 2) Warm pass: re-cycle the same commits in reverse order. All
        #    secondary graphs are now in compareState.secGraphs so this
        #    reflects steady-state UI cost (no /api/graph fetch, just
        #    diff fetch + recompute + render).
        print("[harness] warm pass (reverse order)", flush=True)
        for sha in reversed(commits):
            try:
                m = measure_switch(page, sha, "warm")
                print(f"  warm  {sha[:7]} total={m['total_ms']:.0f}ms phases={m['phases']}", flush=True)
                measurements.append(m)
            except Exception as exc:
                print(f"[FAIL] warm {sha[:7]}: {exc}", flush=True)
                measurements.append({"commit": sha, "label": "warm",
                                     "total_ms": None, "phases": {}, "error": str(exc)})

        # 3) Ping-pong: alternate between two commits 3x to highlight
        #    fully-cached cycle cost.
        if len(commits) >= 2:
            a, b = commits[0], commits[1]
            print(f"[harness] ping-pong {a[:7]}<->{b[:7]} x3", flush=True)
            for i in range(3):
                for sha in (a, b):
                    try:
                        m = measure_switch(page, sha, "pingpong")
                        print(f"  pp[{i}] {sha[:7]} total={m['total_ms']:.0f}ms", flush=True)
                        measurements.append(m)
                    except Exception as exc:
                        print(f"[FAIL] pp {sha[:7]}: {exc}", flush=True)

        ctx.close()
        browser.close()

    # Roll up median/min/max per (label, commit), and per-label aggregate.
    def median(xs: list[float]) -> float | None:
        xs = [x for x in xs if x is not None]
        return round(statistics.median(xs), 2) if xs else None

    by_label: dict[str, list[dict]] = {}
    for m in measurements:
        by_label.setdefault(m["label"], []).append(m)

    aggregates = {}
    for label, ms in by_label.items():
        totals = [m["total_ms"] for m in ms if m.get("total_ms") is not None]
        agg = {
            "n": len(ms),
            "n_ok": len(totals),
            "total_ms_median": median(totals),
            "total_ms_min": round(min(totals), 2) if totals else None,
            "total_ms_max": round(max(totals), 2) if totals else None,
        }
        for phase in ("activateCompare_ms", "ensureSecGraph_fetch_ms",
                      "ensureSecGraph_total_ms", "recomputeDiffSets_ms"):
            xs = [m["phases"].get(phase) for m in ms if m.get("phases")]
            agg[phase + "_median"] = median([x for x in xs if x is not None])
        aggregates[label] = agg

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit": git_head(),
        "port": port,
        "measurements": measurements,
        "aggregates": aggregates,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    print(f"[harness] wrote {out_path}", flush=True)

    print("\n[summary] medians (ms):")
    for label, a in aggregates.items():
        print(f"  {label:>9}  total={a['total_ms_median']}  "
              f"activate={a['activateCompare_ms_median']}  "
              f"graph_fetch={a['ensureSecGraph_fetch_ms_median']}  "
              f"recompute={a['recomputeDiffSets_ms_median']}")

    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--build-root", type=Path, default=REPO_ROOT)
    p.add_argument("--kernel-root", type=Path, default=KERNEL_ROOT)
    p.add_argument("--commits", nargs="+", default=DEFAULT_COMMITS,
                   help="Full SHAs to cycle through (must be cg-compatible)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sys.exit(run(args.port, args.out, args.build_root, args.kernel_root,
                 args.commits))
