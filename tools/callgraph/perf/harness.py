#!/usr/bin/env python3
"""Latency harness for the Zag callgraph explorer.

Spawns the callgraph server with --no-build, drives the page through
Playwright/Chromium, and records min/median/max wall-clock for the actions
the user perceives as slow:

  - initial_load   : navigation start -> first render-ready signal
  - arch_switch    : x86_64 <-> aarch64 in the picker
  - entry_switch   : pick a different entry from the dropdown (BFS rebuild)
  - mode_toggle    : Graph <-> Trace
  - source_fetch   : click a node, wait for source pane to populate

Output is a JSON file (--out) that tools/callgraph/perf/diff.py can compare
across runs. Exits non-zero if any action fails to complete (timeout etc.).
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

# We import playwright lazily after argparse so --help works even if the
# venv isn't fully set up.

PERF_DIR = Path(__file__).resolve().parent
REPO_ROOT = PERF_DIR.parents[2]  # tools/callgraph/perf -> repo root
KERNEL_ROOT = REPO_ROOT / "kernel"
CG_BIN = REPO_ROOT / "tools" / "callgraph" / "zig-out" / "bin" / "callgraph"

DEFAULT_PORT = 18844
DEFAULT_OUT = PERF_DIR / "results.json"

# How long to wait, in seconds, for the server to print its "Listening" line
# (IR parsing dominates startup; 60s is generous for a cold cache).
SERVER_BOOT_TIMEOUT_S = 90.0

# How long to wait, in milliseconds, for a single render-ready signal.
# Has to be generous: kEntry-class entries can produce >5k node graphs.
RENDER_READY_TIMEOUT_MS = 90_000

# Repetitions per action so we get a stable median.
REPS_ARCH_SWITCH = 5
REPS_ENTRY_SWITCH = 5
REPS_MODE_TOGGLE = 5

# Stable entry-point label substrings to drive entry_switch. The harness
# picks whichever options actually exist in the dropdown that match these
# substrings, in order. Reaching 5 distinct entries is the goal.
#
# We mix big (kEntry, exceptionHandler) and small entries so the median
# isn't dominated by either extreme — the user perceives slowness on the
# big ones and we want both visible in the runs[] list.
ENTRY_LABEL_SUBSTRINGS = [
    "kEntry",
    "trap vec: exceptionHandler",
    "pageFaultHandler",
    "syscall: write",
    "syscall: mem_reserve",
    "syscall: mem_shm_create",
    "syscall: process_create",
    "irq spurious_int_vec",
    "syscall: thread_create",
]


# --------------------------------------------------------------- server

@contextmanager
def callgraph_server(port: int):
    """Spawn callgraph --no-build on `port`, yield the popen, kill on exit."""
    if not CG_BIN.exists():
        raise SystemExit(
            f"callgraph binary missing at {CG_BIN} — build it first "
            "(cd tools/callgraph && zig build)"
        )

    cmd = [
        str(CG_BIN),
        "--build-root", str(REPO_ROOT),
        "--kernel-root", str(KERNEL_ROOT),
        "--port", str(port),
        "--no-build",
    ]
    print(f"[harness] launching {' '.join(cmd)}", flush=True)
    # Merge stderr into stdout so we can scan for "Listening" with one read.
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,  # line-buffered
        # New process group so we can SIGKILL the whole tree if needed.
        preexec_fn=os.setsid,
    )

    listening_line: str | None = None
    deadline = time.monotonic() + SERVER_BOOT_TIMEOUT_S
    try:
        # Spin until the server prints "Listening" or we time out.
        while time.monotonic() < deadline:
            line = proc.stdout.readline() if proc.stdout else ""
            if line == "" and proc.poll() is not None:
                rc = proc.poll()
                raise SystemExit(f"callgraph exited prematurely with rc={rc}")
            if line:
                # Mirror output for visibility — useful for debugging slow boots.
                sys.stdout.write(f"[server] {line}")
                sys.stdout.flush()
                if "Listening" in line:
                    listening_line = line.strip()
                    break

        if listening_line is None:
            raise SystemExit(
                f"callgraph did not print 'Listening' within "
                f"{SERVER_BOOT_TIMEOUT_S:.0f}s"
            )

        yield proc
    finally:
        # Kill the process group so any orphans go too.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait(timeout=2)


# --------------------------------------------------------------- helpers

def stats(runs: list[float]) -> dict:
    """Compact summary for the JSON output."""
    if not runs:
        return {"runs": [], "min": None, "median": None, "max": None}
    return {
        "runs": [round(r, 2) for r in runs],
        "min": round(min(runs), 2),
        "median": round(statistics.median(runs), 2),
        "max": round(max(runs), 2),
    }


def git_head() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True
        )
        return out.strip()
    except Exception:
        return "unknown"


def wait_for_render(page, prev_count: int, timeout_ms: int = RENDER_READY_TIMEOUT_MS) -> None:
    """Block until window.__cgRenderCount > prev_count.

    The frontend bumps the counter at the end of every full render
    (cytoscape layoutstop, trace tree appended, mode swap settled).
    """
    page.wait_for_function(
        "(prev) => window.__cgRenderCount > prev",
        arg=prev_count,
        timeout=timeout_ms,
    )


def get_render_count(page) -> int:
    return int(page.evaluate("window.__cgRenderCount || 0"))


def now_ms(page) -> float:
    return float(page.evaluate("performance.now()"))


def measure_action(page, label: str, do_action) -> float:
    """Bracket `do_action` between performance.now() reads, waiting for the
    render-counter to advance after the action so we capture user-visible
    latency end-to-end."""
    prev = get_render_count(page)
    t0 = now_ms(page)
    do_action()
    wait_for_render(page, prev)
    t1 = now_ms(page)
    dt = t1 - t0
    print(f"[measure] {label}: {dt:.2f} ms", flush=True)
    return dt


# --------------------------------------------------------------- main

def run(port: int, out_path: Path) -> int:
    from playwright.sync_api import sync_playwright

    results: dict[str, dict] = {}
    failures: list[str] = []

    with callgraph_server(port) as _server, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1600, "height": 1000})
        page = context.new_page()
        page.set_default_timeout(RENDER_READY_TIMEOUT_MS)

        # Capture console errors and uncaught exceptions for diagnostics —
        # silent rendering failures otherwise look identical to "render took
        # >timeout". Cytoscape spams a wheelSensitivity warning + a "label
        # is deprecated for width" warning we don't care about; we filter
        # those out so signal stays high.
        IGNORED_WARNINGS = (
            "custom wheel sensitivity",
            "style value of `label` is deprecated",
        )
        def on_console(msg):
            if msg.type not in ("error", "warning"):
                return
            text = msg.text or ""
            if any(w in text for w in IGNORED_WARNINGS):
                return
            print(f"[browser-{msg.type}] {text}", flush=True)
        page.on("console", on_console)
        page.on("pageerror", lambda exc: print(
            f"[pageerror] {exc}", flush=True
        ))

        # 1) initial_load --------------------------------------------------
        # Navigate, then wait for the first render-counter bump. Bracket with
        # performance.now() reads on both sides; the first read needs the
        # page to have a `window` object, which is true after `goto` returns.
        url = f"http://127.0.0.1:{port}/"
        try:
            t0 = time.monotonic()
            page.goto(url, wait_until="domcontentloaded")
            # The harness signal/counter is installed by app.js on first
            # script run; wait for it to exist before reading.
            page.wait_for_function(
                "() => typeof window.__cgRenderCount === 'number'"
            )
            page.wait_for_function(
                "() => window.__cgRenderCount >= 1",
                timeout=RENDER_READY_TIMEOUT_MS,
            )
            initial_ms = (time.monotonic() - t0) * 1000.0
            print(f"[measure] initial_load: {initial_ms:.2f} ms", flush=True)
            results["initial_load"] = stats([initial_ms])
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] initial_load: {exc}", flush=True)
            failures.append(f"initial_load: {exc}")
            results["initial_load"] = stats([])

        # 2) arch_switch ---------------------------------------------------
        # Need both arches present. If only one is available the toggle is
        # disabled and the action is skipped (recorded as empty stats).
        arch_runs: list[float] = []
        try:
            arches = page.evaluate(
                "() => Array.from(document.querySelectorAll('#arch_picker option')).map(o => o.value)"
            )
            if "x86_64" in arches and "aarch64" in arches:
                # Make sure we start from x86_64 so the toggle pattern below
                # is deterministic regardless of localStorage state.
                cur = page.evaluate("document.getElementById('arch_picker').value")
                if cur != "x86_64":
                    arch_runs.append(measure_action(
                        page,
                        "arch_switch (warmup -> x86_64)",
                        lambda: page.select_option("#arch_picker", "x86_64"),
                    ))
                    arch_runs.clear()  # warmup, drop

                for i in range(REPS_ARCH_SWITCH):
                    arch_runs.append(measure_action(
                        page,
                        f"arch_switch [#{i}] x86_64->aarch64",
                        lambda: page.select_option("#arch_picker", "aarch64"),
                    ))
                    arch_runs.append(measure_action(
                        page,
                        f"arch_switch [#{i}] aarch64->x86_64",
                        lambda: page.select_option("#arch_picker", "x86_64"),
                    ))
            else:
                print(
                    f"[skip] arch_switch: need both x86_64 and aarch64, got {arches}",
                    flush=True,
                )
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] arch_switch: {exc}", flush=True)
            failures.append(f"arch_switch: {exc}")
        results["arch_switch"] = stats(arch_runs)

        # 3) entry_switch -------------------------------------------------
        # Pick distinct option values whose textContent contains one of our
        # known-stable substrings. We need at least 5 to satisfy the spec.
        entry_runs: list[float] = []
        try:
            options = page.evaluate("""() => {
                const sel = document.getElementById('entry_select');
                return Array.from(sel.options).map(o => ({
                    value: o.value, text: o.textContent || ''
                }));
            }""")
            # Match in declared substring order, then collect any extras
            # so we always reach REPS_ENTRY_SWITCH if the dropdown is big enough.
            picked_values: list[tuple[str, str]] = []
            seen = set()
            for needle in ENTRY_LABEL_SUBSTRINGS:
                for opt in options:
                    if (
                        opt["value"]
                        and needle.lower() in opt["text"].lower()
                        and opt["value"] not in seen
                    ):
                        picked_values.append((opt["value"], opt["text"]))
                        seen.add(opt["value"])
                        break
                if len(picked_values) >= REPS_ENTRY_SWITCH:
                    break
            # Pad from any remaining options with a real fn_id.
            for opt in options:
                if len(picked_values) >= REPS_ENTRY_SWITCH:
                    break
                if opt["value"] and opt["value"] not in seen:
                    picked_values.append((opt["value"], opt["text"]))
                    seen.add(opt["value"])

            if len(picked_values) < REPS_ENTRY_SWITCH:
                raise RuntimeError(
                    f"only {len(picked_values)} usable entry options found"
                )

            # Drop the currently-selected entry from the head of the pick list
            # so the very first select_option triggers an actual change event.
            cur_entry = page.evaluate(
                "document.getElementById('entry_select').value"
            )
            picked_values = [pv for pv in picked_values if pv[0] != cur_entry]
            if len(picked_values) < REPS_ENTRY_SWITCH:
                # Pad again now that we filtered.
                for opt in options:
                    if len(picked_values) >= REPS_ENTRY_SWITCH:
                        break
                    if (
                        opt["value"]
                        and opt["value"] != cur_entry
                        and opt["value"] not in {pv[0] for pv in picked_values}
                    ):
                        picked_values.append((opt["value"], opt["text"]))
            if len(picked_values) < REPS_ENTRY_SWITCH:
                raise RuntimeError(
                    f"only {len(picked_values)} usable distinct entry options "
                    f"after filtering current ({cur_entry!r})"
                )

            print(f"[entry_switch] starting from cur={cur_entry!r}; "
                  f"will pick {len(picked_values[:REPS_ENTRY_SWITCH])} entries:",
                  flush=True)
            for v, t in picked_values[:REPS_ENTRY_SWITCH]:
                print(f"  - {t!r} (id={v})", flush=True)

            for val, text in picked_values[:REPS_ENTRY_SWITCH]:
                entry_runs.append(measure_action(
                    page,
                    f"entry_switch -> {text!r} (id={val})",
                    # Set value + dispatch change manually. select_option in
                    # Playwright's chromium headless doesn't reliably reach
                    # the addEventListener callback registered by app.js.
                    lambda v=val: page.evaluate(
                        "(v) => { const s = document.getElementById('entry_select');"
                        "  s.value = v; s.dispatchEvent(new Event('change', {bubbles:true})); }",
                        v,
                    ),
                ))
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] entry_switch: {exc}", flush=True)
            failures.append(f"entry_switch: {exc}")
        results["entry_switch"] = stats(entry_runs)

        # 4) mode_toggle --------------------------------------------------
        # Park on kEntry first so mode_toggle exercises a "big" entry — it
        # is the worst case the user actually complains about. Falls back to
        # whatever's currently selected if kEntry isn't in the dropdown.
        mode_runs: list[float] = []
        try:
            kentry_opts = page.evaluate("""() => {
                const sel = document.getElementById('entry_select');
                return Array.from(sel.options)
                    .filter(o => o.value && /kEntry/.test(o.textContent))
                    .map(o => o.value);
            }""")
            if kentry_opts:
                cur = page.evaluate("document.getElementById('entry_select').value")
                if cur != kentry_opts[0]:
                    measure_action(
                        page,
                        f"mode_toggle setup: entry -> kEntry (id={kentry_opts[0]})",
                        lambda v=kentry_opts[0]: page.evaluate(
                            "(v) => { const s = document.getElementById('entry_select');"
                            "  s.value = v; s.dispatchEvent(new Event('change', {bubbles:true})); }",
                            v,
                        ),
                    )
            for i in range(REPS_MODE_TOGGLE):
                mode_runs.append(measure_action(
                    page,
                    f"mode_toggle [#{i}] graph->trace",
                    lambda: page.click("#mode_toggle .mode_button[data-mode='trace']"),
                ))
                mode_runs.append(measure_action(
                    page,
                    f"mode_toggle [#{i}] trace->graph",
                    lambda: page.click("#mode_toggle .mode_button[data-mode='graph']"),
                ))
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] mode_toggle: {exc}", flush=True)
            failures.append(f"mode_toggle: {exc}")
        results["mode_toggle"] = stats(mode_runs)

        # 5) source_fetch -------------------------------------------------
        # Click on the entry node in cytoscape; the source pane fills
        # asynchronously via /api/source. We wait until #info_source has at
        # least one .source_line child.
        source_runs: list[float] = []
        try:
            # Make sure we're in graph mode for this measurement.
            page.click("#mode_toggle .mode_button[data-mode='graph']")
            # The above click bumps the render counter once; sync up.
            wait_for_render(page, get_render_count(page) - 1)

            # Tap the first node Cytoscape rendered (the entry root). The
            # graph view's data-fnid lives on a synthetic id `n<entry>`; we
            # can use cy's API directly via window.cy if exposed, but
            # app.js keeps cy module-private. Instead, dispatch a tap event
            # via the cytoscape API by injecting a small script that finds
            # the underlying canvas and clicks center. Simpler: run a
            # JS-level "click first node" by reading entry id and using the
            # page's own showNodePanel through cytoscape.
            #
            # Cytoscape exposes its container, but not the cy instance. The
            # cleanest stable hook: click the entry option-value node by
            # firing a synthetic 'tap' on the cy graph through its public
            # API — except it's not public. Fall back to a DOM-level
            # workaround: we hover/click the source via the indirect_panel
            # button? No — that opens the list panel.
            #
            # Practical hook: trigger a node tap via cy.nodes()[0].emit('tap')
            # by getting at cy through a known global. app.js doesn't expose
            # one, so we reach in: the graph container's `_cyreg` is set by
            # cytoscape internally (`cytoscape.use`-style). It's brittle but
            # cytoscape DOES expose `container.__cy` in v3.x.
            t0 = now_ms(page)
            page.evaluate("""() => {
                // cytoscape stashes the instance on the container element
                // through its private '_cyreg' slot in v3.x. Best-effort.
                const c = document.getElementById('graph');
                let cy = (c && c._cyreg && c._cyreg.cy) || null;
                if (!cy && c && c.firstChild && c.firstChild._cyreg) {
                    cy = c.firstChild._cyreg.cy;
                }
                if (!cy) {
                    // Walk children (cytoscape inserts a <div> wrapper).
                    const all = c ? c.querySelectorAll('*') : [];
                    for (const el of all) {
                        if (el._cyreg && el._cyreg.cy) { cy = el._cyreg.cy; break; }
                    }
                }
                if (!cy) throw new Error('cytoscape instance not found');
                const node = cy.$('node.entry').first();
                if (!node || node.length === 0) throw new Error('no entry node in cy');
                node.emit('tap');
            }""")
            page.wait_for_function(
                "() => document.querySelectorAll('#info_source .source_line').length > 0",
                timeout=RENDER_READY_TIMEOUT_MS,
            )
            t1 = now_ms(page)
            source_runs.append(t1 - t0)
            print(f"[measure] source_fetch: {t1 - t0:.2f} ms", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] source_fetch: {exc}", flush=True)
            failures.append(f"source_fetch: {exc}")
        results["source_fetch"] = stats(source_runs)

        context.close()
        browser.close()

    # ----------------------------------------------------------- write JSON
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit": git_head(),
        "port": port,
        "actions": results,
        "failures": failures,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    print(f"[harness] wrote {out_path}", flush=True)

    # Sanity: every action must have at least one run, otherwise we count
    # as failed. (Empty stats from a skipped action — like arch_switch when
    # only one arch is loaded — are tolerated only if not in failures.)
    for name, s in results.items():
        if not s["runs"] and not any(name in f for f in failures):
            # Skipped, not failed. OK.
            continue
        if not s["runs"]:
            failures.append(f"{name}: no runs recorded")

    if failures:
        print(f"[harness] FAILURES: {failures}", flush=True)
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"port for the callgraph server (default {DEFAULT_PORT})")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT,
                   help=f"where to write the JSON results (default {DEFAULT_OUT})")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sys.exit(run(args.port, args.out))
