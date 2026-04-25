# Callgraph perf harness

Records baseline latency for the actions the user perceives as slow in the
callgraph explorer:

- `initial_load` — page nav -> first ready signal
- `arch_switch` — picker x86_64 <-> aarch64 (swaps the whole graph)
- `entry_switch` — entry-point dropdown (BFS rebuild + cytoscape relayout)
- `mode_toggle` — Graph view <-> Trace view
- `source_fetch` — click an entry node, wait for source pane

The frontend cooperates via `window.__cgRenderCount` (bumped after every
completed render) and `window.__cgReady`. Both live in `app.js`. They are
inert when no harness is watching.

## One-time setup

```sh
cd tools/callgraph/perf
python3 -m venv .venv
.venv/bin/pip install playwright
.venv/bin/playwright install chromium
```

Pre-built IRs at `zig-out/kernel.x86_64.ll` and `zig-out/kernel.aarch64.ll`
are required (`--no-build` is passed so the harness skips the rebuild).

## Run

```sh
.venv/bin/python harness.py
# defaults: --port 18844, --out results.json
```

The script:
1. Spawns `callgraph --no-build --port <port>` and waits for `Listening`.
2. Drives headless Chromium through Playwright.
3. Repeats each action 5x, records min/median/max per action.
4. Writes JSON to `--out`. Exits non-zero if any action failed.

Port 18844 is used by default. Avoid 8080 — the developer keeps a server
running there.

## Compare two runs

```sh
.venv/bin/python diff.py before.json after.json
```

Prints a side-by-side of medians with %-delta. Useful between optimization
iterations.

## Files

- `harness.py` — the measurement driver
- `diff.py` — side-by-side comparator
- `.venv/` — local Python environment (gitignored)
- `results*.json` — gitignored output
