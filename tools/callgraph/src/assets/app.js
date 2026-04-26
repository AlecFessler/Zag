/* Zag callgraph explorer — Phase 1 frontend.
 *
 * Vanilla JS. Pulls /api/graph, lets the user pick an entry point, BFS-walks
 * callees down to a depth, and renders the result with Cytoscape.js. Click a
 * node or edge to see metadata in the right side panel. ?demo=1 in the URL
 * activates a hardcoded demo graph for offline preview.
 */

(function () {
  "use strict";

  // ------------------------------------------------------------------ state

  /** Whole /api/graph payload (the "currentGraph"), stashed for lookups
   *  during BFS. Updated whenever the arch picker changes. */
  let graph = null;
  /** Per-arch cache of parsed /api/graph payloads. The server's call-graph
   *  is fixed at startup (it parses IRs once), so a fetched graph stays
   *  valid for the whole session — no need to re-fetch and re-parse on
   *  every arch switch. Saves ≈20ms per swap on the harness. */
  const archGraphCache = new Map();
  /** id -> function object index for O(1) lookup. Rebuilt on every graph
   *  swap (arch change). */
  const fnById = new Map();
  /** Current Cytoscape instance. Recreated on each entry-point switch. */
  let cy = null;
  /** List of arch tags loaded by the server, e.g. ["x86_64", "aarch64"]. */
  let availableArches = [];
  /** Currently-selected arch tag (matches a key in availableArches). */
  let currentArch = null;
  /** When true (default), hide Zig stdlib + compiler infrastructure from
   *  every view. Persisted in localStorage so reload preserves the choice. */
  let hideLibrary = (function () {
    try {
      return localStorage.getItem("hideLibrary") !== "false";
    } catch (_e) {
      return true;
    }
  })();

  /** When true (default), hide debug-only call sites: std.debug.*, kprof
   *  tracing, *.assert helpers, panic helpers, kernel/utils/debug.zig and
   *  the downstream of kernel/panic.zig (panic.panic itself stays visible).
   *  Persisted in localStorage so reload preserves the choice. */
  let hideDebug = (function () {
    try {
      return localStorage.getItem("hideDebug") !== "false";
    } catch (_e) {
      return true;
    }
  })();

  /** "graph" | "trace". Persisted in localStorage so reload preserves it. */
  let currentMode = (function () {
    try {
      const m = localStorage.getItem("mode");
      return m === "trace" ? "trace" : "graph";
    } catch (_e) {
      return "graph";
    }
  })();

  /** A function counts as "library" if it lives under /usr/lib/zig/ or its
   *  mangled name is one of the compiler-synthesized / runtime prefixes.
   *  See the spec at the top of this file for the full criteria. */
  function isLibrary(fn) {
    if (!fn) return false;
    const file = (fn.def_loc && fn.def_loc.file) || "";
    if (file.startsWith("/usr/lib/zig/")) return true;
    const m = fn.mangled || "";
    if (m.startsWith("__zig_")) return true;
    if (m.startsWith("__ubsan_")) return true;
    if (m.startsWith("ubsan_rt.")) return true;
    if (m.startsWith("compiler_rt.")) return true;
    return false;
  }

  /** True when the library filter is on AND fn is library. */
  function isFiltered(fn) {
    return hideLibrary && isLibrary(fn);
  }

  /** A function (or call atom with a `name`/`def_loc`) counts as "debug" if
   *  any of: name/mangled is std.debug.*, name contains .assert, name starts
   *  with kprof. or panic / contains .panic, name ends with `Panic`, defined
   *  in kernel/utils/debug.zig, or defined in kernel/panic.zig (except for
   *  `panic.panic` itself — we keep the user-visible panic entry).
   *
   *  Accepts either a Function record (with mangled/name/def_loc) or a call
   *  atom (with .name and optionally .site/.def_loc — the call atom will
   *  miss the def_loc; for atoms we lean on the name. */
  function isDebug(fn) {
    if (!fn) return false;
    const name = fn.name || "";
    const mangled = fn.mangled || "";
    const file = (fn.def_loc && fn.def_loc.file) || "";

    if (mangled.startsWith("std.debug.") || name.startsWith("std.debug.")) return true;
    if (name.indexOf(".assert") >= 0) return true;
    if (name.startsWith("kprof.")) return true;
    if (name.startsWith("panic") || name.indexOf(".panic") >= 0) {
      // Spare the user-visible panic entry: `panic.panic` is the entry the
      // user wants to see. Filter only its downstream (caught by the
      // kernel/panic.zig file rule below).
      if (name !== "panic.panic") return true;
    }
    if (name.endsWith("Panic")) return true;
    if (file.endsWith("kernel/utils/debug.zig")) return true;
    if (file.endsWith("kernel/panic.zig") && name !== "panic.panic") return true;
    return false;
  }

  /** True when the debug filter is on AND fn is debug. */
  function isFilteredDebug(fn) {
    return hideDebug && isDebug(fn);
  }

  // ------------------------------------------------------------------ DOM

  const els = {
    archPicker: document.getElementById("arch_picker"),
    entrySelect: document.getElementById("entry_select"),
    depthSlider: document.getElementById("depth_slider"),
    depthValue: document.getElementById("depth_value"),
    indirectToggle: document.getElementById("include_indirect"),
    hideLibraryToggle: document.getElementById("hide_library"),
    hideDebugToggle: document.getElementById("hide_debug"),
    fitBtn: document.getElementById("fit_btn"),
    indirectPanelBtn: document.getElementById("indirect_panel_btn"),
    deadPanelBtn: document.getElementById("dead_panel_btn"),
    graph: document.getElementById("graph"),
    info: document.getElementById("info"),
    infoResizeHandle: document.getElementById("info_resize_handle"),
    infoTitle: document.getElementById("info_title"),
    infoMeta: document.getElementById("info_meta"),
    infoSourceWrap: document.getElementById("info_source_wrap"),
    infoSource: document.getElementById("info_source"),
    infoSourceB: document.getElementById("info_source_b"),
    infoSourceSplit: document.getElementById("info_source_split"),
    infoSourcePaneA: document.getElementById("info_source_pane_a"),
    infoSourcePaneB: document.getElementById("info_source_pane_b"),
    infoSourceLabelA: document.getElementById("info_source_label_a"),
    infoSourceLabelB: document.getElementById("info_source_label_b"),
    infoSourceError: document.getElementById("info_source_error"),
    infoIntraWrap: document.getElementById("info_intra_wrap"),
    infoIntra: document.getElementById("info_intra"),
    infoClose: document.getElementById("info_close"),
    status: document.getElementById("status"),
    listPanel: document.getElementById("list_panel"),
    listTitle: document.getElementById("list_title"),
    listClose: document.getElementById("list_close"),
    listFilter: document.getElementById("list_filter"),
    listSummary: document.getElementById("list_summary"),
    listRows: document.getElementById("list_rows"),
    modeToggle: document.getElementById("mode_toggle"),
    traceView: document.getElementById("trace_view"),
    traceViewWrap: document.getElementById("trace_view_wrap"),
    traceViewB: document.getElementById("trace_view_b"),
    tracePaneColA: document.getElementById("trace_pane_col_a"),
    tracePaneColB: document.getElementById("trace_pane_col_b"),
    traceLabelA: document.getElementById("trace_label_a"),
    traceLabelB: document.getElementById("trace_label_b"),
    diffChangesPanel: document.getElementById("diff_changes_panel"),
    diffChangesList: document.getElementById("diff_changes_list"),
    diffChangesCount: document.getElementById("diff_changes_count"),
    reviewProgressBar: document.getElementById("review_progress_bar"),
    reviewProgressFill: document.getElementById("review_progress_fill"),
    reviewTrackerCol: document.getElementById("review_tracker_col"),
    traceBreadcrumb: document.getElementById("trace_breadcrumb"),
    graphPane: document.getElementById("graph"),
    compareMode: document.getElementById("compare_mode"),
    compareCommit: document.getElementById("compare_commit"),
    compareStatus: document.getElementById("compare_status"),
  };

  /** ID of the currently-selected entry-point function. */
  let currentEntryFnId = null;

  // ---- Perf harness ready signal ----------------------------------------
  // The harness in tools/callgraph/perf/ reads window.__cgReady (bool) and
  // window.__cgRenderCount (int, bumped after each completed render) so it
  // can wait for "next render after I clicked something". Inert metadata —
  // no behavior change, no effect when no harness is watching.
  if (typeof window.__cgRenderCount === "undefined") {
    window.__cgRenderCount = 0;
    window.__cgReady = false;
  }
  function cgSignalReady() {
    window.__cgRenderCount += 1;
    window.__cgReady = true;
  }
  function cgClearReady() {
    window.__cgReady = false;
  }
  // Expose for trace.js (its render is synchronous so it bumps the counter
  // directly when it finishes building the tree).
  window.__cgSignalReady = cgSignalReady;
  window.__cgClearReady = cgClearReady;

  // ------------------------------------------------------------------ utils

  function setStatus(text, persist) {
    if (!text) {
      els.status.classList.remove("visible");
      return;
    }
    els.status.textContent = text;
    els.status.classList.add("visible");
    if (!persist) {
      clearTimeout(setStatus._t);
      setStatus._t = setTimeout(function () {
        els.status.classList.remove("visible");
      }, 1800);
    }
  }

  function fmtLoc(loc) {
    if (!loc || !loc.file) return "(unknown)";
    const file = loc.file;
    const line = loc.line != null ? loc.line : 0;
    const col = loc.col != null ? loc.col : 0;
    return file + ":" + line + ":" + col;
  }

  function shortName(name) {
    if (!name) return "(anon)";
    // Take last two dotted segments to keep node labels readable.
    const parts = name.split(".");
    if (parts.length <= 2) return name;
    return parts.slice(-2).join(".");
  }

  // ------------------------------------------------------------------ graph load

  /** Boot path. Demo mode hardcodes a synthetic graph and skips arch
   *  negotiation; otherwise we consult /api/arches first, then fetch the
   *  graph for whichever arch the user (or localStorage) selected last. */
  async function loadGraph() {
    const params = new URLSearchParams(window.location.search);
    if (params.get("demo") === "1") {
      graph = demoGraph();
      availableArches = ["x86_64"];
      currentArch = "x86_64";
      populateArchPicker();
      indexCurrentGraph();
      onGraphReady();
      setStatus("demo graph loaded", false);
      return;
    }

    setStatus("loading /api/arches...", true);
    let archesResp;
    try {
      const r = await fetch("/api/arches");
      if (!r.ok) throw new Error("HTTP " + r.status);
      archesResp = await r.json();
    } catch (err) {
      console.error("/api/arches fetch failed", err);
      setStatus("/api/arches fetch failed: " + err.message, true);
      return;
    }

    availableArches = (archesResp.arches || []).slice();
    if (availableArches.length === 0) {
      setStatus("server reported no loaded arches", true);
      return;
    }

    // Pick initial arch: localStorage value if it's still loaded, else the
    // server's default, else the first available.
    let initial = null;
    try {
      const saved = localStorage.getItem("arch");
      if (saved && availableArches.indexOf(saved) >= 0) initial = saved;
    } catch (_e) {}
    if (initial == null) {
      initial = availableArches.indexOf(archesResp.default) >= 0
        ? archesResp.default
        : availableArches[0];
    }
    currentArch = initial;
    populateArchPicker();

    await fetchGraphForArch(currentArch, /*preserveEntry=*/false);
  }

  /** Fetch /api/graph?arch=<arch>, swap currentGraph, rebuild fnById,
   *  re-render. When `preserveEntry` is true and the previously-selected
   *  entry survives by name in the new graph, keep it as the focused entry.
   *  Otherwise pick the first visible entry. */
  async function fetchGraphForArch(archTag, preserveEntry) {
    const _t0 = performance.now();
    setStatus("loading /api/graph (arch=" + archTag + ")...", true);
    let prevEntryName = null;
    if (preserveEntry && currentEntryFnId != null) {
      const prevFn = fnById.get(currentEntryFnId);
      if (prevFn) prevEntryName = prevFn.name;
    }

    const cached = archGraphCache.get(archTag);
    if (cached) {
      graph = cached;
      window.__cgGraph = graph;
      setStatus("graph loaded (" + archTag + ")", false);
    } else {
      try {
        const r = await fetch("/api/graph?arch=" + encodeURIComponent(archTag));
        if (!r.ok) throw new Error("HTTP " + r.status);
        graph = await r.json();
        archGraphCache.set(archTag, graph);
        window.__cgGraph = graph;
        setStatus("graph loaded (" + archTag + ")", false);
      } catch (err) {
        console.error("graph fetch failed", err);
        setStatus("graph fetch failed: " + err.message, true);
        return;
      }
    }
    const _t1 = performance.now();

    indexCurrentGraph();
    const _t2 = performance.now();

    populateDropdown(graph.entry_points || []);
    const _t3 = performance.now();

    // Try to preserve the prior entry by name.
    let nextEntryId = null;
    if (prevEntryName) {
      for (const e of graph.entry_points || []) {
        const fn = fnById.get(e.fn_id);
        if (fn && fn.name === prevEntryName) {
          if (!isFiltered(fn) && !isFilteredDebug(fn)) {
            nextEntryId = e.fn_id;
            break;
          }
        }
      }
    }
    if (nextEntryId == null) {
      nextEntryId = firstVisibleEntryId(graph.entry_points || []);
    }

    onGraphReady();
    const _t4 = performance.now();

    if (nextEntryId != null) {
      els.entrySelect.value = String(nextEntryId);
      renderForEntry(nextEntryId);
    } else {
      currentEntryFnId = null;
    }
    const _t5 = performance.now();
    window.__cgArchTimings = {
      fetch_parse: _t1 - _t0,
      index: _t2 - _t1,
      populate: _t3 - _t2,
      onGraphReady: _t4 - _t3,
      render: _t5 - _t4,
      total: _t5 - _t0,
    };
  }

  /** Rebuild fnById from the current `graph` and re-wire trace.js. */
  function indexCurrentGraph() {
    fnById.clear();
    for (const fn of graph.functions || []) fnById.set(fn.id, fn);
    if (window.traceMode) {
      window.traceMode.setContext({
        fnById: fnById,
        isLibrary: isLibrary,
        isDebug: isDebug,
        getHideLibrary: function () { return hideLibrary; },
        getHideDebug: function () { return hideDebug; },
        getDepth: function () { return parseInt(els.depthSlider.value, 10) || 4; },
        showNodePanel: showNodePanel,
      });
    }
  }

  /** Apply persisted mode after a graph load. Call only after fnById and
   *  the entry dropdown are wired. */
  function onGraphReady() {
    // Apply persisted mode now that the DOM is wired and trace.js exists.
    setMode(currentMode);
  }

  function populateArchPicker() {
    if (!els.archPicker) return;
    els.archPicker.innerHTML = "";
    for (const a of availableArches) {
      const opt = document.createElement("option");
      opt.value = a;
      opt.textContent = a;
      els.archPicker.appendChild(opt);
    }
    els.archPicker.value = currentArch;
    if (availableArches.length <= 1) {
      els.archPicker.disabled = true;
    } else {
      els.archPicker.disabled = false;
    }
  }

  /** First entry point that survives the library + debug filters, or null.
   *  Used on initial load and whenever toggling a filter forces us to pick
   *  a new sensible default. */
  function firstVisibleEntryId(entries) {
    for (const e of entries) {
      const fn = fnById.get(e.fn_id);
      if (isFiltered(fn)) continue;
      if (isFilteredDebug(fn)) continue;
      return e.fn_id;
    }
    return null;
  }

  function populateDropdown(entries) {
    els.entrySelect.innerHTML = "";

    // Drop library/debug entry points when the filter is on. Entry
    // discovery is tuned for kernel patterns so this should be empty in
    // practice, but it keeps the dropdown honest if the heuristics ever
    // pick something up.
    const visibleEntries = entries.filter(function (e) {
      const fn = fnById.get(e.fn_id);
      if (isFiltered(fn)) return false;
      if (isFilteredDebug(fn)) return false;
      return true;
    });

    if (visibleEntries.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "(no entry points)";
      els.entrySelect.appendChild(opt);
      return;
    }

    // Group by entry kind so the dropdown is navigable.
    const groups = new Map();
    for (const e of visibleEntries) {
      const kind = e.kind || "manual";
      if (!groups.has(kind)) groups.set(kind, []);
      groups.get(kind).push(e);
    }

    const kindOrder = ["syscall", "trap", "irq", "boot", "manual"];
    const sorted = Array.from(groups.keys()).sort(function (a, b) {
      const ai = kindOrder.indexOf(a);
      const bi = kindOrder.indexOf(b);
      if (ai === -1 && bi === -1) return a.localeCompare(b);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });

    // Diff-mode flags: prefix entries whose reachable subtree touches any
    // file changed between live and the secondary commit. Empty set when
    // compare is off, so the prefix is invisible in normal use.
    const needsReview = (compareState && compareState.entryNeedsReview)
      ? compareState.entryNeedsReview
      : new Set();

    for (const kind of sorted) {
      const og = document.createElement("optgroup");
      const items = groups.get(kind).slice().sort(function (a, b) {
        return (a.label || "").localeCompare(b.label || "");
      });
      const flaggedInGroup = items.reduce(function (acc, e) {
        return acc + (needsReview.has(e.fn_id) ? 1 : 0);
      }, 0);
      const labelSuffix = flaggedInGroup > 0
        ? " (" + items.length + ", " + flaggedInGroup + " ●)"
        : " (" + items.length + ")";
      og.label = kind + labelSuffix;
      for (const e of items) {
        const opt = document.createElement("option");
        opt.value = String(e.fn_id);
        const marker = needsReview.has(e.fn_id) ? "● " : "";
        opt.textContent = marker + "[" + kind + "] " + (e.label || "(anon)");
        og.appendChild(opt);
      }
      els.entrySelect.appendChild(og);
    }
  }

  // ------------------------------------------------------------------ BFS build

  function buildElements(entryFnId, depth, includeIndirect) {
    const elements = [];
    const visited = new Set();
    const queue = [{ id: entryFnId, depth: 0 }];
    let unresolvedCount = 0;
    let userspaceCount = 0;

    if (!fnById.has(entryFnId)) {
      console.warn("entry fn id not found in graph", entryFnId);
      return elements;
    }

    // If the entry itself is library/debug and the filter is on, render
    // nothing. (In practice entry discovery shouldn't pick up library/debug
    // fns; this is a safety net so we never silently emit only synthetic
    // nodes.)
    if (isFiltered(fnById.get(entryFnId))) {
      return elements;
    }
    if (isFilteredDebug(fnById.get(entryFnId))) {
      return elements;
    }

    while (queue.length > 0) {
      const cur = queue.shift();
      if (visited.has(cur.id)) continue;
      visited.add(cur.id);

      const fn = fnById.get(cur.id);
      if (!fn) continue;

      elements.push({
        group: "nodes",
        data: {
          id: "n" + fn.id,
          label: shortName(fn.name),
          fullName: fn.name,
          mangled: fn.mangled,
          file: fn.def_loc ? fn.def_loc.file : "",
          line: fn.def_loc ? fn.def_loc.line : 0,
          col: fn.def_loc ? fn.def_loc.col : 0,
          isEntry: !!fn.is_entry,
          entryKind: fn.entry_kind || "",
          kind: "fn",
        },
        classes: fn.is_entry ? "entry" : "fn",
      });

      if (cur.depth >= depth) continue;

      const callees = fn.callees || [];
      for (let i = 0; i < callees.length; i += 1) {
        const c = callees[i];
        const edgeKind = c.kind || "direct";

        if (!includeIndirect && (edgeKind === "indirect" || edgeKind === "vtable")) {
          continue;
        }

        let targetNodeId;

        if (edgeKind === "leaf_userspace") {
          // Synthetic terminal node — one per parent fn so positions don't pile.
          userspaceCount += 1;
          targetNodeId = "u" + fn.id + "_" + i;
          elements.push({
            group: "nodes",
            data: {
              id: targetNodeId,
              label: "userspace",
              fullName: "(userspace return)",
              kind: "userspace",
            },
            classes: "synthetic userspace",
          });
        } else if (c.to == null) {
          // Indirect / unresolved.
          unresolvedCount += 1;
          targetNodeId = "x" + fn.id + "_" + i;
          elements.push({
            group: "nodes",
            data: {
              id: targetNodeId,
              label: "?",
              fullName: c.target_name || "(unresolved indirect target)",
              kind: "unresolved",
            },
            classes: "synthetic unresolved",
          });
        } else {
          // Resolved direct/dispatch/vtable target. If the target is
          // library or debug infrastructure and the matching filter is on,
          // drop both the edge and any expansion past it: the caller node
          // simply has fewer outgoing edges. The user wanted their kernel
          // code, not what Zig wires in or what their debug tracing
          // generated.
          const targetFn = fnById.get(c.to);
          if (isFiltered(targetFn)) {
            continue;
          }
          if (isFilteredDebug(targetFn)) {
            continue;
          }
          targetNodeId = "n" + c.to;
          if (!visited.has(c.to) && fnById.has(c.to)) {
            queue.push({ id: c.to, depth: cur.depth + 1 });
          }
        }

        elements.push({
          group: "edges",
          data: {
            id: "e" + fn.id + "_" + i,
            source: "n" + fn.id,
            target: targetNodeId,
            kind: edgeKind,
            targetName: c.target_name || "",
            file: c.site ? c.site.file : "",
            line: c.site ? c.site.line : 0,
            col: c.site ? c.site.col : 0,
          },
          classes: edgeKind,
        });
      }
    }

    if (unresolvedCount > 0 || userspaceCount > 0) {
      console.log(
        "BFS: " + visited.size + " fns, " +
        unresolvedCount + " unresolved indirect, " +
        userspaceCount + " userspace leaves",
      );
    }

    return elements;
  }

  // ------------------------------------------------------------------ render

  function cyStyle() {
    return [
      {
        selector: "node",
        style: {
          "background-color": "#2c313c",
          "border-color": "#3a4150",
          "border-width": 1,
          "label": "data(label)",
          "color": "#d8dde6",
          "font-size": "11px",
          "font-family": "ui-monospace, SF Mono, Consolas, monospace",
          "text-valign": "center",
          "text-halign": "center",
          "text-wrap": "wrap",
          "text-max-width": "140px",
          "width": "label",
          "height": "28px",
          "padding": "8px",
          "shape": "round-rectangle",
        },
      },
      {
        selector: "node.entry",
        style: {
          "background-color": "#1f3550",
          "border-color": "#4a9eff",
          "border-width": 2,
          "color": "#ffffff",
          "font-weight": "bold",
        },
      },
      {
        selector: "node.synthetic",
        style: {
          "background-color": "#22252c",
          "border-style": "dashed",
          "color": "#8a93a3",
          "font-style": "italic",
        },
      },
      {
        selector: "node.userspace",
        style: {
          "border-color": "#f0a050",
        },
      },
      {
        selector: "node.unresolved",
        style: {
          "border-color": "#f06060",
          "shape": "diamond",
          "width": "32px",
          "height": "32px",
        },
      },
      {
        selector: "node:selected",
        style: {
          "border-color": "#ffffff",
          "border-width": 2,
        },
      },
      {
        selector: "edge",
        style: {
          "width": 1.5,
          "line-color": "#888888",
          "target-arrow-color": "#888888",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "arrow-scale": 0.9,
        },
      },
      { selector: "edge.direct",          style: { "line-color": "#888888", "target-arrow-color": "#888888" } },
      { selector: "edge.dispatch_x64",    style: { "line-color": "#4a9eff", "target-arrow-color": "#4a9eff" } },
      { selector: "edge.dispatch_aarch64", style: { "line-color": "#3ec9c9", "target-arrow-color": "#3ec9c9" } },
      { selector: "edge.vtable",          style: { "line-color": "#b06ef0", "target-arrow-color": "#b06ef0" } },
      {
        selector: "edge.indirect",
        style: {
          "line-color": "#f06060",
          "target-arrow-color": "#f06060",
          "line-style": "dashed",
        },
      },
      {
        selector: "edge.leaf_userspace",
        style: {
          "line-color": "#f0a050",
          "target-arrow-color": "#f0a050",
          "line-style": "dashed",
          "target-arrow-shape": "tee",
        },
      },
      {
        selector: "edge:selected",
        style: { "width": 3 },
      },
    ];
  }

  function renderForEntry(entryFnId) {
    const _t0 = performance.now();
    currentEntryFnId = entryFnId;
    // Refresh the diff-changes summary; it filters by what's reachable
    // from the current entry, so it changes whenever the entry changes.
    if (typeof updateChangesPanel === "function") updateChangesPanel();
    // Trace mode owns its own rendering pipeline; only let the graph
    // builder run when the graph pane is the visible view.
    if (currentMode === "trace") {
      cgClearReady();
      if (window.traceMode) window.traceMode.onEntryChange(entryFnId);
      return;
    }
    const depth = parseInt(els.depthSlider.value, 10) || 4;
    const includeIndirect = els.indirectToggle.checked;

    const elements = buildElements(entryFnId, depth, includeIndirect);
    const _t1 = performance.now();

    cgClearReady();
    if (cy) {
      // Reuse existing instance: swap elements in a batch so the canvas
      // and event engine stay alive. Cuts ≈10-15ms off arch/entry switches
      // vs cy.destroy() + new cytoscape({...}). Events were wired on first
      // creation and survive element swaps.
      cy.batch(function () {
        cy.elements().remove();
        cy.add(elements);
      });
    } else {
      cy = cytoscape({
        container: els.graph,
        elements: elements,
        style: cyStyle(),
        wheelSensitivity: 0.6,
        minZoom: 0.05,
        maxZoom: 5.0,
      });
      // Wire events once; they survive element swaps via cy reuse.
      cy.on("tap", "node", function (evt) { showNodePanel(evt.target.data()); });
      cy.on("tap", "edge", function (evt) { showEdgePanel(evt.target.data()); });
      cy.on("tap", function (evt) {
        // Background tap closes the panel.
        if (evt.target === cy) hidePanel();
      });
    }
    const _t3 = performance.now();

    if (elements.length === 0) {
      // No layout to run; signal immediately so the perf harness doesn't hang.
      cgSignalReady();
    } else {
      const layout = cy.layout({
        name: "breadthfirst",
        directed: true,
        roots: ["n" + entryFnId],
        padding: 30,
        spacingFactor: 1.1,
        animate: false,
      });
      layout.one("layoutstop", function () { cgSignalReady(); });
      layout.run();
    }
    const _t4 = performance.now();

    // Initial fit-to-view: after the layout completes, fit the graph then
    // clamp zoom up to a level where node labels stay readable. For wide
    // entry points like kEntry, plain cy.fit() leaves you at ~0.1 zoom
    // where you only see the silhouette.
    fitWithMinZoom();
    const _t5 = performance.now();
    window.__cgRenderTimings = {
      build_elements: _t1 - _t0,
      cy_swap: _t3 - _t1,
      layout_run: _t4 - _t3,
      fit: _t5 - _t4,
      total: _t5 - _t0,
    };
  }

  // Refit + min-zoom guard. Call after any layout-changing operation or
  // when the user hits the fit button.
  function fitWithMinZoom() {
    if (!cy) return;
    cy.fit(undefined, 50);
    if (cy.zoom() < 0.7) {
      cy.zoom({
        level: 0.7,
        renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
      });
    }
  }

  // ------------------------------------------------------------------ side panel

  function metaRow(label, value) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    if (value && value.nodeType) {
      dd.appendChild(value);
    } else {
      dd.textContent = value == null || value === "" ? "—" : String(value);
    }
    return [dt, dd];
  }

  // Monotonic token so an in-flight fetch from a previous selection can't
  // overwrite the source for the current one when responses arrive out of
  // order.
  let sourceFetchToken = 0;

  function clearSource() {
    sourceFetchToken += 1;
    els.infoSource.innerHTML = "";
    if (els.infoSourceB) {
      els.infoSourceB.innerHTML = "";
      els.infoSourceB.style.display = "none";
    }
    if (els.infoSourceSplit) els.infoSourceSplit.classList.remove("compare_active");
    els.infoSourceWrap.style.display = "none";
    els.infoSourceError.style.display = "none";
    els.infoSourceError.textContent = "";
  }

  function clearIntra() {
    if (!els.infoIntra) return;
    els.infoIntra.innerHTML = "";
    els.infoIntraWrap.style.display = "none";
  }

  function showSourceError(msg) {
    els.infoSourceWrap.style.display = "none";
    els.infoSource.innerHTML = "";
    els.infoSourceError.style.display = "block";
    els.infoSourceError.textContent = "Could not load source: " + msg;
  }

  /** Render a tokenized source snippet into a target block.
   *  diffOpts (optional): { hunks: [{old_start, old_count, start, count}],
   *  side: "old" | "new" } — when present, lines whose absolute number
   *  falls inside a hunk's add/remove range get a `.added` / `.removed`
   *  class so CSS can tint them green/red. Inert when diffOpts is null
   *  (compare off, or file has no hunks). */
  /** Emit a plain-text fragment into a parent, but wrap any identifier
   *  whose name matches a changed Definition in a clickable span.
   *  Identifiers are matched as `[a-zA-Z_][a-zA-Z0-9_]*` runs. When
   *  compare is off (or no matches found), the call degenerates to a
   *  single text node. */
  const IDENT_RE = /[A-Za-z_][A-Za-z0-9_]*/g;
  function emitTextWithChangedIdents(parent, text) {
    if (text.length === 0) return;
    const byName = compareState && compareState.changedDefByName;
    if (!byName || byName.size === 0) {
      parent.appendChild(document.createTextNode(text));
      return;
    }
    let cursor = 0;
    let m;
    IDENT_RE.lastIndex = 0;
    while ((m = IDENT_RE.exec(text)) !== null) {
      const def = byName.get(m[0]);
      if (!def) continue;
      if (m.index > cursor) {
        parent.appendChild(document.createTextNode(text.slice(cursor, m.index)));
      }
      const a = document.createElement("span");
      a.className = "tok_changed_dep";
      a.textContent = m[0];
      a.title = def.qualified_name + " — click to jump to def";
      a.dataset.defid = String(def.id);
      a.addEventListener("click", function (e) {
        e.stopPropagation();
        jumpToDef(def);
      });
      parent.appendChild(a);
      cursor = m.index + m[0].length;
    }
    if (cursor < text.length) {
      parent.appendChild(document.createTextNode(text.slice(cursor)));
    }
  }

  /** Drill the source pane to a Definition's location. Loads the def's
   *  full file and scrolls to its first line. The clicked def is the
   *  one in the LIVE graph (since the source pane on side A shows live);
   *  for the OLDER side, the secondary's matching def location applies
   *  but we don't currently jump on the secondary. */
  function jumpToDef(def) {
    if (!def || !def.file) return;
    setLastClickedFn(def.qualified_name || null);
    fetchSource(def.file, 1, 10000000, def.line_start || 1);
  }

  function renderSourceSnippet(file, startLine, lines, highlightLine, tokens, targetBlock, diffOpts) {
    // Build header with selectable absolute path.
    const block = targetBlock || els.infoSource;
    block.innerHTML = "";

    // Pre-compute, per absolute line on this side, whether the line is
    // added (new side) or removed (old side). Lines not in any hunk are
    // unchanged context.
    let addedSet = null;
    let removedSet = null;
    if (diffOpts && diffOpts.hunks) {
      addedSet = new Set();
      removedSet = new Set();
      const isOld = diffOpts.side === "old";
      for (const h of diffOpts.hunks) {
        if (isOld) {
          // On the old side, the removed range is [old_start, old_start+old_count-1]
          // (count==0 means pure insertion: nothing removed on this side).
          for (let i = 0; i < h.old_count; i += 1) {
            removedSet.add(h.old_start + i);
          }
        } else {
          // On the new side, the added range is [start, start+count-1]
          // (count==0 means pure deletion: nothing added on this side).
          for (let i = 0; i < h.count; i += 1) {
            addedSet.add(h.start + i);
          }
        }
      }
    }

    const header = document.createElement("div");
    header.className = "source_header";
    const link = document.createElement("span");
    link.className = "open_file";
    link.textContent = file;
    link.title = "Path (selectable for copy)";
    header.appendChild(link);
    block.appendChild(header);

    const pre = document.createElement("pre");
    pre.className = "source";

    const table = document.createElement("table");
    table.className = "source_table";
    const tbody = document.createElement("tbody");

    // Group tokens by absolute line so we can paint each row independently.
    // Tokens are byte-positioned server-side; for ASCII Zig source byte
    // columns line up with JS string indices. Multi-byte UTF-8 in source
    // would shift highlights but never crash — fine for now.
    const tokensByLine = new Map();
    if (tokens) {
      for (const t of tokens) {
        let arr = tokensByLine.get(t.line);
        if (!arr) {
          arr = [];
          tokensByLine.set(t.line, arr);
        }
        arr.push(t);
      }
      for (const arr of tokensByLine.values()) {
        arr.sort(function (a, b) { return a.col - b.col; });
      }
    }

    for (let i = 0; i < lines.length; i += 1) {
      const absLine = startLine + i;
      const tr = document.createElement("tr");
      tr.className = "source_line";
      if (absLine === highlightLine) tr.classList.add("highlight");
      if (addedSet && addedSet.has(absLine)) tr.classList.add("added");
      if (removedSet && removedSet.has(absLine)) tr.classList.add("removed");

      const tdNum = document.createElement("td");
      tdNum.className = "source_gutter";
      tdNum.textContent = String(absLine);
      // Review checkbox: drawn at the FIRST line of every unit whose
      // start matches absLine on this pane's side. Click toggles the
      // unit's reviewed state (POSTs to /api/review_state in parent
      // mode, in-memory otherwise). When the unit is reviewed, the
      // line(s) get a `.unit_reviewed` class so CSS can desaturate
      // the diff tint and signal "I've looked at this".
      const sideTag = diffOpts && diffOpts.side ? diffOpts.side : null;
      if (sideTag === "new" || sideTag === "old") {
        const fileRel = sideTag === "new" ?
          defLocToRepoRel(file) :
          secondaryPathToRepoRel(file);
        if (fileRel && compareState.unitsByFileSide) {
          const sideKey = sideTag === "new" ? "added" : "removed";
          const unitsHere = unitsStartingAt(fileRel, sideKey, absLine);
          if (unitsHere.length > 0) {
            const u = unitsHere[0];
            const cb = document.createElement("input");
            cb.type = "checkbox";
            cb.className = "unit_checkbox";
            cb.dataset.unitId = u.id;
            const rec = compareState.reviewed.get(u.id);
            cb.checked = !!(rec && rec.reviewed);
            if (rec && rec.at) {
              const when = rec.at;
              const who = rec.by || "";
              cb.title = "reviewed" + (who ? " by " + who : "") +
                " at " + when;
            } else {
              cb.title = "mark this " + u.kind + " hunk reviewed";
            }
            cb.addEventListener("click", function (e) {
              e.stopPropagation();
              toggleUnitReviewed(u.id, cb.checked);
            });
            tdNum.insertBefore(cb, tdNum.firstChild);
            if (cb.checked) {
              tr.classList.add("unit_reviewed");
              // Also fade the trailing lines of the unit. We add the
              // class on subsequent rows during the loop below by
              // tracking `pendingReviewedLines`.
            }
          }
        }
        // Mark interior lines of any unit currently being-reviewed.
        if (sideTag === "new" || sideTag === "old") {
          if (isLineInsideReviewedUnit(file, sideTag, absLine)) {
            tr.classList.add("unit_reviewed");
          }
        }
      }

      const tdCode = document.createElement("td");
      tdCode.className = "source_code";
      const lineText = lines[i];
      const lineTokens = tokensByLine.get(absLine);
      if (lineText.length === 0) {
        // Single trailing space keeps row height consistent.
        tdCode.textContent = " ";
      } else if (!lineTokens || lineTokens.length === 0) {
        // No tokenized highlights on this line. Still scan for changed-
        // def identifier hits when compare is active.
        emitTextWithChangedIdents(tdCode, lineText);
      } else {
        // Walk tokens left-to-right, emitting plain text for gaps and
        // <span class="tok_X"> for highlighted regions. Text gaps get
        // scanned for changed-def identifiers in compare mode so the
        // user can see (and click through to) refs to changed types.
        let cursor = 0;
        for (const t of lineTokens) {
          const startIdx = t.col - 1; // server is 1-indexed
          if (startIdx < cursor) continue; // overlap; skip
          if (startIdx > cursor) {
            emitTextWithChangedIdents(tdCode, lineText.slice(cursor, startIdx));
          }
          const span = document.createElement("span");
          span.className = "tok_" + t.kind;
          span.textContent = lineText.slice(startIdx, startIdx + t.len);
          tdCode.appendChild(span);
          cursor = startIdx + t.len;
        }
        if (cursor < lineText.length) {
          emitTextWithChangedIdents(tdCode, lineText.slice(cursor));
        }
      }

      tr.appendChild(tdNum);
      tr.appendChild(tdCode);
      tbody.appendChild(tr);
    }

    table.appendChild(tbody);
    pre.appendChild(table);
    block.appendChild(pre);

    els.infoSourceWrap.style.display = "block";
    els.infoSourceError.style.display = "none";

    // Scroll the source block so the highlighted line is at the top of
    // the viewport. Done after the wrap is shown so layout has settled
    // and the row has a real bounding rect to scroll to.
    if (highlightLine != null) {
      const row = block.querySelector(".source_line.highlight");
      if (row) {
        // scrollIntoView walks ancestors and scrolls each as needed.
        // The .source_block scrollable container takes the row to its
        // top edge with `block: "start"`; behavior:"instant" avoids the
        // smooth-scroll jitter that's noticeable on big files.
        row.scrollIntoView({ block: "start", behavior: "instant" });
      }
    }
  }

  async function fetchSource(file, start, end, highlightLine, opts) {
    if (!file) {
      showSourceError("no file path on selection");
      return;
    }
    if (start < 1) start = 1;
    if (end < start) end = start;
    opts = opts || {};

    // Remember the fetch params so the review-toggle path can replay
    // the same render in-place (no entry change, no scroll loss).
    lastFetchedSource = { file: file, line: highlightLine };

    const myToken = sourceFetchToken + 1;
    sourceFetchToken = myToken;

    const url = "/api/source?path=" + encodeURIComponent(file) +
      "&start=" + start + "&end=" + end;

    try {
      const r = await fetch(url);
      if (myToken !== sourceFetchToken) return; // superseded
      if (!r.ok) {
        showSourceError("HTTP " + r.status);
        return;
      }
      const payload = await r.json();
      if (myToken !== sourceFetchToken) return;

      // payload: { lines: string[], tokens: {line,col,len,kind}[] }
      // Non-.zig files come back with an empty tokens array (no
      // highlight). lines never includes trailing newlines — server
      // already strips them.
      const lines = payload.lines && payload.lines.length > 0
        ? payload.lines
        : [""];
      // Tint added lines green when compare is active and this file has
      // hunks. Path lookup uses the same kernel-rooted convention as the
      // changed-fn check (defLocToRepoRel).
      const primaryDiffOpts = computeDiffOptsForPrimary(file);
      renderSourceSnippet(
        file, start, lines, highlightLine, payload.tokens || [],
        els.infoSource, primaryDiffOpts,
      );

      // Side-by-side: if compare mode is active and the secondary commit
      // has a function with the same name, fetch and render its source
      // into #info_source_b. Path comes from the secondary's own def_loc
      // (worktree-rooted), so no path translation is needed here.
      //
      // `opts.secondaryByFile = repoRelPath` overrides this default and
      // shows the same file in the secondary commit instead — used by
      // the review tracker so dep-unit clicks display the same hunk on
      // both sides instead of jumping to the contributing fn's def.
      if (opts.secondaryByFile) {
        renderSecondarySourceByFile(
          opts.secondaryByFile,
          opts.secondaryHighlight || highlightLine,
        );
      } else {
        maybeRenderSecondarySource(payload && payload.fn_name, highlightLine);
      }
    } catch (err) {
      if (myToken !== sourceFetchToken) return;
      showSourceError(err && err.message ? err.message : String(err));
    }
  }

  /** When compare is active: look up the same fn name in the secondary's
   *  graph, fetch the source for that fn's def file, and render side-by-side.
   *  fnName comes from the primary's selection — we don't trust the server
   *  payload to carry it (older API didn't), so callers can pass it
   *  explicitly via setLastFnName. */
  let lastClickedFnName = null;
  /// File + highlight line of the last fetchSource call. Lets us
  /// re-trigger the same render in-place when reviewed-state changes
  /// (gutter checkboxes need to flip without losing scroll position
  /// or panel state). Updated alongside lastClickedFnName.
  let lastFetchedSource = { file: null, line: null };
  function setLastClickedFn(name) { lastClickedFnName = name || null; }

  function clearSecondarySource() {
    if (els.infoSourceB) els.infoSourceB.innerHTML = "";
    if (els.infoSourcePaneB) els.infoSourcePaneB.style.display = "none";
    if (els.infoSourceLabelA) els.infoSourceLabelA.style.display = "none";
    if (els.infoSourceLabelB) els.infoSourceLabelB.style.display = "none";
    if (els.infoSourceSplit) els.infoSourceSplit.classList.remove("compare_active");
  }

  /** Same label shape as the trace pane labels but smaller — sits above
   *  each .source_block so the user always knows which side is live. */
  function updateSourceLabel(labelEl, side, sha) {
    if (!labelEl) return;
    labelEl.style.display = "";
    labelEl.classList.remove("live", "older");
    labelEl.classList.add(side);
    labelEl.innerHTML = "";
    const tag = document.createElement("span");
    tag.className = "pane_tag";
    tag.textContent = side === "live" ? "LIVE" : "OLDER";
    labelEl.appendChild(tag);
    if (side === "older" && sha) {
      const shaEl = document.createElement("span");
      shaEl.className = "pane_sha";
      shaEl.textContent = sha.slice(0, 7);
      labelEl.appendChild(shaEl);
    } else if (side === "live") {
      const note = document.createElement("span");
      note.className = "pane_subj";
      note.textContent = "working tree";
      labelEl.appendChild(note);
    }
  }

  /** Render the same file (by repo-relative path) from the secondary
   *  commit's worktree. Used by the review tracker's unit-row clicks,
   *  where we want both panes to show the same hunk side-by-side
   *  rather than the contributing fn's def_loc (which for dep units
   *  lives in a different file entirely). The secondary worktree path
   *  is built from the sha-keyed convention `/var/tmp/cg-worktrees/
   *  <sha>/<repo-rel>` — symmetric with `secondaryPathToRepoRel`. */
  async function renderSecondarySourceByFile(repoRelPath, highlightLine) {
    if (!els.infoSourceB || !els.infoSourceSplit) return;
    if (compareState.mode === "off") {
      clearSecondarySource();
      return;
    }
    const sec = secondarySha();
    if (!sec) {
      clearSecondarySource();
      return;
    }
    if (!repoRelPath) {
      clearSecondarySource();
      return;
    }
    const secPath = "/var/tmp/cg-worktrees/" + sec + "/" + repoRelPath;
    try {
      const url = "/api/source?path=" + encodeURIComponent(secPath) +
        "&start=1&end=10000000";
      const r = await fetch(url);
      if (!r.ok) {
        // File missing in OLDER commit — render a clear placeholder.
        els.infoSourceSplit.classList.add("compare_active");
        els.infoSourcePaneB.style.display = "";
        els.infoSourceB.innerHTML = "";
        updateSourceLabel(els.infoSourceLabelA, "live", null);
        updateSourceLabel(els.infoSourceLabelB, "older", sec);
        const note = document.createElement("div");
        note.className = "source_header";
        note.textContent = `(${repoRelPath} not present in ${shortSha(sec)})`;
        els.infoSourceB.appendChild(note);
        return;
      }
      const payload = await r.json();
      const lines = payload.lines && payload.lines.length > 0
        ? payload.lines : [""];
      els.infoSourceSplit.classList.add("compare_active");
      els.infoSourcePaneB.style.display = "";
      updateSourceLabel(els.infoSourceLabelA, "live", null);
      updateSourceLabel(els.infoSourceLabelB, "older", sec);
      const secDiffOpts = computeDiffOptsForSecondary(secPath);
      renderSourceSnippet(
        secPath, 1, lines, highlightLine || 1, payload.tokens || [],
        els.infoSourceB, secDiffOpts,
      );
      const row = els.infoSourceB.querySelector(".source_line.highlight");
      if (row) row.scrollIntoView({ block: "start", behavior: "instant" });
    } catch (err) {
      console.error("secondary source-by-file fetch failed", err);
      clearSecondarySource();
    }
  }

  async function maybeRenderSecondarySource(_unused, highlightLine) {
    if (!els.infoSourceB || !els.infoSourceSplit) return;
    if (compareState.mode === "off") {
      clearSecondarySource();
      return;
    }
    const sec = secondarySha();
    if (!sec) {
      clearSecondarySource();
      return;
    }
    const data = compareState.secGraphs.get(sec);
    if (!data) {
      clearSecondarySource();
      return;
    }
    const name = lastClickedFnName;
    if (!name) {
      clearSecondarySource();
      return;
    }
    const secFn = data.fnByName.get(name);
    if (!secFn || !secFn.def_loc || !secFn.def_loc.file) {
      // Function absent in the secondary commit — render a placeholder so
      // the user sees that explicitly, instead of an empty pane.
      els.infoSourceSplit.classList.add("compare_active");
      els.infoSourcePaneB.style.display = "";
      els.infoSourceB.innerHTML = "";
      updateSourceLabel(els.infoSourceLabelA, "live", null);
      updateSourceLabel(els.infoSourceLabelB, "older", sec);
      const note = document.createElement("div");
      note.className = "source_header";
      note.textContent = `(no \`${name}\` in ${shortSha(sec)})`;
      els.infoSourceB.appendChild(note);
      return;
    }
    const file = secFn.def_loc.file;
    const line = secFn.def_loc.line || 1;
    try {
      const url = "/api/source?path=" + encodeURIComponent(file) +
        "&start=1&end=10000000";
      const r = await fetch(url);
      if (!r.ok) throw new Error("HTTP " + r.status);
      const payload = await r.json();
      const lines = payload.lines && payload.lines.length > 0
        ? payload.lines
        : [""];
      els.infoSourceSplit.classList.add("compare_active");
      els.infoSourcePaneB.style.display = "";
      updateSourceLabel(els.infoSourceLabelA, "live", null);
      updateSourceLabel(els.infoSourceLabelB, "older", sec);
      // Tint removed lines red on the secondary side. The hunks are
      // keyed by the file's path on the WORKING-TREE side; the
      // secondary file may live under a different path (worktree
      // mount), but it's the same repo-relative path. Use the secondary
      // fn's repo-relative path for the lookup.
      const secDiffOpts = computeDiffOptsForSecondary(file);
      renderSourceSnippet(
        file, 1, lines, line, payload.tokens || [],
        els.infoSourceB, secDiffOpts,
      );
      // Mirror the primary's scroll-to-highlight on the secondary.
      const row = els.infoSourceB.querySelector(".source_line.highlight");
      if (row) row.scrollIntoView({ block: "start", behavior: "instant" });
      void highlightLine; // not used; secondary has its own line
    } catch (err) {
      console.error("secondary source fetch failed", err);
      clearSecondarySource();
    }
  }

  // ------------------------------------------------------------------ intra (call tree)

  function renderIntra(intra) {
    if (!els.infoIntra || !els.infoIntraWrap) return;
    els.infoIntra.innerHTML = "";
    if (!intra || intra.length === 0) {
      const empty = document.createElement("div");
      empty.className = "intra_empty";
      empty.textContent = "no outgoing calls";
      els.infoIntra.appendChild(empty);
      els.infoIntraWrap.style.display = "block";
      return;
    }
    const list = document.createElement("ul");
    list.className = "atom_list";
    for (const atom of intra) {
      list.appendChild(renderAtom(atom));
    }
    els.infoIntra.appendChild(list);
    els.infoIntraWrap.style.display = "block";
  }

  function renderAtom(atom) {
    if (atom.call) return renderCallAtom(atom.call);
    if (atom.branch) return renderBranchAtom(atom.branch);
    const li = document.createElement("li");
    li.textContent = "(unknown atom)";
    return li;
  }

  function renderCallAtom(c) {
    const li = document.createElement("li");
    li.className = "atom_call";

    const name = document.createElement("span");
    const kindClass = "kind_" + (c.kind || "direct");
    name.className = "callee_name " + kindClass + (c.to == null ? " unresolved" : "");
    name.textContent = c.to == null ? (c.name + " ?") : c.name;
    name.title = c.to == null ? "(unresolved indirect target)" : c.name;

    name.addEventListener("click", function () {
      // If the target is in the current cy view, center + flash; else
      // refresh source snippet to the call site.
      if (c.to != null && cy) {
        const node = cy.$id("n" + c.to);
        if (node && node.length > 0) {
          cy.animate({ center: { eles: node }, duration: 200 });
          node.flashClass("cy_flash", 600);
          return;
        }
      }
      if (c.site && c.site.file) {
        const start = Math.max(1, (c.site.line || 1) - 10);
        const end = (c.site.line || 1) + 20;
        fetchSource(c.site.file, start, end, c.site.line);
      }
    });

    const loc = document.createElement("span");
    loc.className = "callee_loc";
    loc.textContent = c.site ? ("@line " + c.site.line) : "";

    li.appendChild(name);
    li.appendChild(loc);
    return li;
  }

  function renderBranchAtom(b) {
    const det = document.createElement("details");
    det.className = "atom_branch";
    det.open = true;

    const summ = document.createElement("summary");
    const kw = document.createElement("span");
    kw.className = "branch_kw";
    kw.textContent = b.kind === "if_else" ? "if / else" : "switch";
    const loc = document.createElement("span");
    loc.className = "branch_loc";
    loc.textContent = b.loc ? ("@line " + b.loc.line) : "";
    summ.appendChild(kw);
    summ.appendChild(loc);

    summ.addEventListener("click", function (e) {
      // Default behavior toggles the details. Also pull source for context.
      if (b.loc && b.loc.file) {
        const start = Math.max(1, (b.loc.line || 1) - 1);
        const end = (b.loc.line || 1) + 4;
        fetchSource(b.loc.file, start, end, b.loc.line);
      }
      // Don't preventDefault — keep the toggle.
      e.stopPropagation();
    });

    det.appendChild(summ);

    for (const arm of (b.arms || [])) {
      const armDiv = document.createElement("div");
      armDiv.className = "arm";

      const lab = document.createElement("div");
      lab.className = "arm_label";
      lab.textContent = arm.label || "(arm)";
      armDiv.appendChild(lab);

      if (arm.seq && arm.seq.length > 0) {
        const sublist = document.createElement("ul");
        sublist.className = "atom_list";
        for (const a of arm.seq) sublist.appendChild(renderAtom(a));
        armDiv.appendChild(sublist);
      } else {
        const noop = document.createElement("div");
        noop.className = "intra_empty";
        noop.textContent = "(no calls)";
        armDiv.appendChild(noop);
      }

      det.appendChild(armDiv);
    }
    return det;
  }

  function showNodePanel(d) {
    els.infoTitle.textContent = d.kind === "fn" ? "Function" : "Synthetic Node";
    els.infoMeta.innerHTML = "";
    clearSource();
    clearIntra();

    if (d.kind === "fn") {
      const rows = [
        metaRow("name", d.fullName || d.label || ""),
        metaRow("mangled", d.mangled || ""),
        metaRow("file:line", fmtLoc({ file: d.file, line: d.line, col: d.col })),
      ];
      if (d.isEntry) {
        const badge = document.createElement("span");
        badge.className = "badge";
        badge.textContent = d.entryKind || "entry";
        rows.push(metaRow("entry", badge));
      }
      // Unreachable badge — pulled from the original Function record so we
      // see the field even if the graph BFS didn't actually traverse here.
      const fnIdNum = parseInt(String(d.id || "").replace(/^n/, ""), 10);
      const fnRec = !Number.isNaN(fnIdNum) ? fnById.get(fnIdNum) : null;
      if (fnRec && fnRec.reachable === false) {
        const badge = document.createElement("span");
        badge.className = "badge unreachable";
        badge.textContent = "unreachable";
        badge.title = "Not reachable from any discovered entry point via direct/dispatch IR call edges";
        rows.push(metaRow("status", badge));
      }
      for (const pair of rows) {
        els.infoMeta.appendChild(pair[0]);
        els.infoMeta.appendChild(pair[1]);
      }

      els.info.classList.add("visible");

      // Remember the fn name so the side-by-side source can resolve the
      // same function in the secondary commit's graph. fullName carries
      // the qualified name (e.g. `sched.scheduler.wake`) — that's what
      // fnByName maps in both panes.
      setLastClickedFn(d.fullName || d.label || null);

      // Load the whole file and scroll so the function def lands at the
      // top of the source block. Lets the user read up/down freely
      // without re-fetching, which matches the code-review usage of the
      // pane. The server caps reads at SOURCE_MAX_BYTES (1 MB) and the
      // tokenizer runs once per request — both fast on kernel files.
      if (d.file && d.line) {
        fetchSource(d.file, 1, 10_000_000, d.line);
      }

      // Render intra (call tree).
      const fnId = parseInt(String(d.id || "").replace(/^n/, ""), 10);
      const lookupId = Number.isNaN(fnId) ? null : fnId;
      const fn = lookupId != null ? fnById.get(lookupId) : null;
      renderIntra(fn ? fn.intra : null);
    } else {
      const rows = [
        metaRow("kind", d.kind),
        metaRow("note", d.fullName || d.label || ""),
      ];
      for (const pair of rows) {
        els.infoMeta.appendChild(pair[0]);
        els.infoMeta.appendChild(pair[1]);
      }
      els.info.classList.add("visible");
    }
  }

  function showEdgePanel(d) {
    els.infoTitle.textContent = "Call Site";
    els.infoMeta.innerHTML = "";
    clearSource();
    clearIntra();

    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = d.kind || "direct";

    const rows = [
      metaRow("kind", badge),
      metaRow("target", d.targetName || "(unresolved)"),
      metaRow("site", fmtLoc({ file: d.file, line: d.line, col: d.col })),
    ];
    for (const pair of rows) {
      els.infoMeta.appendChild(pair[0]);
      els.infoMeta.appendChild(pair[1]);
    }

    els.info.classList.add("visible");

    // 11-line window centered on the call site.
    if (d.file && d.line) {
      const start = Math.max(1, d.line - 5);
      const end = d.line + 5;
      fetchSource(d.file, start, end, d.line);
    }
  }

  function hidePanel() {
    els.info.classList.remove("visible");
    clearSource();
    clearIntra();
  }

  // ------------------------------------------------------------------ list panel

  /** All rows currently rendered in the list panel, kept around for filtering. */
  let listRows = [];
  /** "indirect" or "dead" — used by the row click handler. */
  let listMode = null;

  function showListPanel(title, rows, mode) {
    listMode = mode;
    listRows = rows;
    els.listTitle.textContent = title;
    els.listFilter.value = "";
    renderListRows(rows, "");
    els.listPanel.classList.add("visible");
  }

  function hideListPanel() {
    els.listPanel.classList.remove("visible");
    listRows = [];
    listMode = null;
  }

  function renderListRows(rows, filter) {
    els.listRows.innerHTML = "";
    const needle = (filter || "").toLowerCase();
    let shown = 0;
    for (const row of rows) {
      if (needle && !row.searchKey.includes(needle)) continue;
      shown += 1;
      const li = document.createElement("li");
      li.className = "list_row";

      const marker = document.createElement("span");
      marker.className = "marker" + (row.markerClass ? " " + row.markerClass : "");
      marker.textContent = row.marker || "?";
      li.appendChild(marker);

      const name = document.createElement("span");
      name.className = "row_name";
      name.textContent = row.name;
      li.appendChild(name);

      if (row.loc) {
        const loc = document.createElement("span");
        loc.className = "row_loc";
        loc.textContent = row.loc;
        li.appendChild(loc);
      }

      if (row.kindTag) {
        const kt = document.createElement("span");
        kt.className = "kind_tag";
        kt.textContent = row.kindTag;
        li.appendChild(kt);
      }

      li.addEventListener("click", function () {
        handleListRowClick(row);
      });

      els.listRows.appendChild(li);
    }

    if (shown === 0) {
      const empty = document.createElement("li");
      empty.className = "list_empty";
      empty.textContent = needle ? "no matches" : "(empty)";
      els.listRows.appendChild(empty);
    }

    els.listSummary.textContent = filter
      ? shown + " of " + rows.length + " shown"
      : rows.length + " total";
  }

  function handleListRowClick(row) {
    if (listMode === "indirect") {
      // Row knows the caller fn id and the call-site location.
      if (row.callerFnId != null && cy) {
        const node = cy.$id("n" + row.callerFnId);
        if (node && node.length > 0) {
          cy.animate({ center: { eles: node }, duration: 200 });
          node.flashClass("cy_flash", 600);
        }
      }
      if (row.site && row.site.file) {
        const start = Math.max(1, (row.site.line || 1) - 5);
        const end = (row.site.line || 1) + 5;
        // Show edge-style metadata in the right-hand info panel.
        showEdgePanel({
          kind: row.kindTag || "indirect",
          targetName: row.targetName || "(unresolved)",
          file: row.site.file,
          line: row.site.line,
          col: row.site.col || 0,
        });
        fetchSource(row.site.file, start, end, row.site.line);
      }
      return;
    }
    if (listMode === "dead") {
      // Synthesize a function-detail panel even though Cytoscape's BFS
      // graph won't have this node (it's unreachable from the current
      // entry by definition).
      if (row.fn) {
        showNodePanel({
          id: "n" + row.fn.id,
          fullName: row.fn.name,
          label: row.fn.name,
          mangled: row.fn.mangled,
          file: row.fn.def_loc ? row.fn.def_loc.file : "",
          line: row.fn.def_loc ? row.fn.def_loc.line : 0,
          col: row.fn.def_loc ? row.fn.def_loc.col : 0,
          isEntry: !!row.fn.is_entry,
          entryKind: row.fn.entry_kind || "",
          kind: "fn",
        });
      }
    }
  }

  /// Collect every indirect-call site reachable from the current entry,
  /// using the same BFS rules as the graph view (depth from the slider,
  /// indirect-toggle ignored — we always include them when the user
  /// explicitly opens this panel).
  function collectIndirectCalls(entryFnId, depth) {
    const out = [];
    if (entryFnId == null || !fnById.has(entryFnId)) return out;
    if (isFiltered(fnById.get(entryFnId))) return out;
    if (isFilteredDebug(fnById.get(entryFnId))) return out;
    const visited = new Set();
    const queue = [{ id: entryFnId, depth: 0 }];
    while (queue.length > 0) {
      const cur = queue.shift();
      if (visited.has(cur.id)) continue;
      visited.add(cur.id);
      const fn = fnById.get(cur.id);
      if (!fn) continue;
      // Skip indirect rows where the *caller* is library or debug; vector
      // tables in stdlib formatters or debug tracing aren't interesting
      // for kernel work.
      const callerFiltered = isFiltered(fn) || isFilteredDebug(fn);
      const callees = fn.callees || [];
      for (const c of callees) {
        const k = c.kind || "direct";
        if (!callerFiltered && (k === "indirect" || k === "vtable")) {
          const file = c.site ? c.site.file : "";
          out.push({
            marker: "?",
            markerClass: "",
            name: fn.name + "  ->  " + (c.target_name || "(unresolved)"),
            loc: file
              ? shortenFile(file) + ":" + (c.site.line || 0)
              : "",
            kindTag: "kind: " + k,
            searchKey: (
              fn.name + " " +
              (c.target_name || "") + " " +
              file + " " + k
            ).toLowerCase(),
            callerFnId: fn.id,
            targetName: c.target_name || "",
            site: c.site || null,
          });
        }
        if (c.to != null && fnById.has(c.to)) {
          // Don't descend into library/debug callees — keeps the BFS
          // frontier anchored to the user's non-debug kernel code.
          if (isFiltered(fnById.get(c.to))) continue;
          if (isFilteredDebug(fnById.get(c.to))) continue;
          if (cur.depth < depth && !visited.has(c.to)) {
            queue.push({ id: c.to, depth: cur.depth + 1 });
          }
        }
      }
    }
    // Sort: caller name ASC, then site line.
    out.sort(function (a, b) {
      if (a.name === b.name) return 0;
      return a.name < b.name ? -1 : 1;
    });
    return out;
  }

  function collectDeadFunctions() {
    const out = [];
    if (!graph || !graph.functions) return out;
    for (const f of graph.functions) {
      if (f.reachable === false) {
        // Library functions are unreachable from kernel entry points by
        // design — most of stdlib isn't used. Surfacing them here buries
        // the genuinely interesting cases (kernel functions nothing calls).
        if (isFiltered(f)) continue;
        // Debug helpers (asserts, kprof tracing, panic downstream) skew
        // the dead-code list when the toggle is on.
        if (isFilteredDebug(f)) continue;
        const file = f.def_loc ? f.def_loc.file : "";
        const line = f.def_loc ? f.def_loc.line : 0;
        out.push({
          marker: "x",
          markerClass: "dead",
          name: f.name,
          loc: file ? shortenFile(file) + ":" + line : "",
          kindTag: "",
          searchKey: (f.name + " " + (f.mangled || "") + " " + file).toLowerCase(),
          fn: f,
        });
      }
    }
    out.sort(function (a, b) {
      if (a.name === b.name) return 0;
      return a.name < b.name ? -1 : 1;
    });
    return out;
  }

  function shortenFile(file) {
    if (!file) return "";
    // Trim absolute prefix up through "/kernel/" or "/usr/lib/zig/" so
    // rows fit on screen.
    const k = file.indexOf("/kernel/");
    if (k >= 0) return file.slice(k + 1);
    const z = file.indexOf("/usr/lib/zig/");
    if (z >= 0) return file.slice(z + 1);
    return file;
  }

  function openIndirectPanel() {
    if (currentEntryFnId == null) {
      setStatus("pick an entry point first", false);
      return;
    }
    const depth = parseInt(els.depthSlider.value, 10) || 4;
    const rows = collectIndirectCalls(currentEntryFnId, depth);
    const suffix = hideLibrary ? " — " + rows.length + " in your code" : "";
    showListPanel(
      "Indirect calls (current entry, depth " + depth + ")" + suffix,
      rows,
      "indirect",
    );
  }

  function openDeadPanel() {
    const rows = collectDeadFunctions();
    const suffix = hideLibrary ? " — " + rows.length + " in your code" : "";
    showListPanel(
      "Dead code  (unreachable from any entry)" + suffix,
      rows,
      "dead",
    );
  }

  /** Repopulate the dropdown and re-render the current view after a
   *  visibility filter (library or debug) toggle. Preserves the current
   *  selection if it survives both filters; else falls back to the first
   *  visible entry. In trace mode, prefer rerender() so the user keeps
   *  their drill stack. */
  function applyVisibilityFilters() {
    populateDropdown(graph ? (graph.entry_points || []) : []);
    let target = currentEntryFnId;
    let entryStillValid = false;
    if (target != null) {
      const fn = fnById.get(target);
      if (isFiltered(fn) || isFilteredDebug(fn)) target = null;
      else entryStillValid = true;
    }
    if (target == null && graph) {
      target = firstVisibleEntryId(graph.entry_points || []);
    }
    if (target != null) {
      els.entrySelect.value = String(target);
      if (currentMode === "trace" && entryStillValid && window.traceMode) {
        // Keep the user's drill stack — the entry hasn't actually changed.
        window.traceMode.rerender();
      } else {
        renderForEntry(target);
      }
    }
    refreshOpenListPanel();
  }

  /** Re-run whichever list panel is currently open. Called when the library
   *  filter is toggled so the visible counts/rows stay in sync. */
  function refreshOpenListPanel() {
    if (!els.listPanel || !els.listPanel.classList.contains("visible")) return;
    if (listMode === "indirect") openIndirectPanel();
    else if (listMode === "dead") openDeadPanel();
  }

  // ------------------------------------------------------------------ events

  function wireEvents() {
    if (els.archPicker) {
      els.archPicker.addEventListener("change", function () {
        const next = els.archPicker.value;
        if (!next || next === currentArch) return;
        currentArch = next;
        try { localStorage.setItem("arch", next); } catch (_e) {}
        fetchGraphForArch(next, /*preserveEntry=*/true);
      });
    }

    els.entrySelect.addEventListener("change", function () {
      const v = parseInt(els.entrySelect.value, 10);
      if (!Number.isNaN(v)) renderForEntry(v);
    });

    els.depthSlider.addEventListener("input", function () {
      els.depthValue.textContent = els.depthSlider.value;
    });
    els.depthSlider.addEventListener("change", function () {
      const v = parseInt(els.entrySelect.value, 10);
      if (!Number.isNaN(v)) renderForEntry(v);
    });

    els.indirectToggle.addEventListener("change", function () {
      const v = parseInt(els.entrySelect.value, 10);
      if (!Number.isNaN(v)) renderForEntry(v);
    });

    if (els.hideLibraryToggle) {
      els.hideLibraryToggle.checked = hideLibrary;
      els.hideLibraryToggle.addEventListener("change", function () {
        hideLibrary = els.hideLibraryToggle.checked;
        try { localStorage.setItem("hideLibrary", hideLibrary ? "true" : "false"); } catch (_e) {}
        applyVisibilityFilters();
      });
    }

    if (els.hideDebugToggle) {
      els.hideDebugToggle.checked = hideDebug;
      els.hideDebugToggle.addEventListener("change", function () {
        hideDebug = els.hideDebugToggle.checked;
        try { localStorage.setItem("hideDebug", hideDebug ? "true" : "false"); } catch (_e) {}
        applyVisibilityFilters();
      });
    }

    els.fitBtn.addEventListener("click", function () {
      fitWithMinZoom();
    });

    // Keyboard shortcuts: +/= zoom in, - zoom out, 0/f refit. Centered on
    // the current viewport center so the zoom feels anchored. Skip when
    // the user is typing in the side-panel filter input.
    document.addEventListener("keydown", function (e) {
      const tag = e.target && e.target.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (!cy) return;
      if (e.key === "+" || e.key === "=") {
        cy.zoom({
          level: cy.zoom() * 1.25,
          renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
        });
      } else if (e.key === "-") {
        cy.zoom({
          level: cy.zoom() * 0.8,
          renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
        });
      } else if (e.key === "0" || e.key === "f") {
        fitWithMinZoom();
      }
    });

    els.infoClose.addEventListener("click", hidePanel);

    if (els.indirectPanelBtn) {
      els.indirectPanelBtn.addEventListener("click", openIndirectPanel);
    }
    if (els.deadPanelBtn) {
      els.deadPanelBtn.addEventListener("click", openDeadPanel);
    }
    if (els.listClose) {
      els.listClose.addEventListener("click", hideListPanel);
    }
    if (els.listFilter) {
      els.listFilter.addEventListener("input", function () {
        renderListRows(listRows, els.listFilter.value);
      });
    }

    // Source pane resize handle. The user drags the left edge of #info to
    // grow/shrink the source review area. Width persists in localStorage so
    // each session opens at the size the user picked. The handle is purely
    // pointer-driven; we don't fall back to keyboard since the slider for
    // depth already has the keyboard role on the topbar.
    if (els.infoResizeHandle && els.info) {
      // Restore persisted width on load. Stored as integer pixels.
      try {
        const saved = parseInt(localStorage.getItem("infoWidth"), 10);
        if (Number.isFinite(saved) && saved >= 320) {
          els.info.style.flex = "0 0 " + saved + "px";
        }
      } catch (_e) {}

      let dragStartX = 0;
      let dragStartWidth = 0;
      let dragging = false;

      function onMove(e) {
        if (!dragging) return;
        // Pointer moves left → wider panel; right → narrower.
        const dx = dragStartX - e.clientX;
        const next = Math.max(320, Math.min(window.innerWidth - 240, dragStartWidth + dx));
        els.info.style.flex = "0 0 " + next + "px";
        // Cy lives in #graph; the flex re-layout shrinks/grows #graph and
        // cytoscape needs `resize()` to recompute its canvas. Cheap enough
        // to call every move; cytoscape no-ops if size hasn't changed.
        if (cy) cy.resize();
      }
      function onUp() {
        if (!dragging) return;
        dragging = false;
        document.body.classList.remove("cg_resizing");
        els.infoResizeHandle.classList.remove("dragging");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        // Persist final width.
        try {
          const m = /([0-9]+)px/.exec(els.info.style.flex || "");
          if (m) localStorage.setItem("infoWidth", m[1]);
        } catch (_e) {}
      }
      els.infoResizeHandle.addEventListener("mousedown", function (e) {
        e.preventDefault();
        dragging = true;
        dragStartX = e.clientX;
        dragStartWidth = els.info.getBoundingClientRect().width;
        document.body.classList.add("cg_resizing");
        els.infoResizeHandle.classList.add("dragging");
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", onUp);
      });
    }

    // Mode toggle (Graph | Trace). Switching modes hides the other view's
    // container but does not reset the entry selection. Drill state is
    // preserved per-entry inside trace.js.
    if (els.modeToggle) {
      const buttons = els.modeToggle.querySelectorAll(".mode_button");
      buttons.forEach(function (btn) {
        btn.addEventListener("click", function () {
          const m = btn.getAttribute("data-mode");
          if (m && m !== currentMode) setMode(m);
        });
      });
    }
  }

  /** Show one mode + hide the other; wires/unwires trace.js as needed. */
  function setMode(mode) {
    currentMode = mode;
    try { localStorage.setItem("mode", mode); } catch (_e) {}

    // Toggle button active state.
    if (els.modeToggle) {
      els.modeToggle.querySelectorAll(".mode_button").forEach(function (btn) {
        if (btn.getAttribute("data-mode") === mode) btn.classList.add("active");
        else btn.classList.remove("active");
      });
    }

    if (mode === "trace") {
      cgClearReady();
      if (els.graphPane) els.graphPane.style.display = "none";
      if (window.traceMode) {
        window.traceMode.show();
        if (currentEntryFnId != null) window.traceMode.onEntryChange(currentEntryFnId);
        else cgSignalReady();
      } else {
        cgSignalReady();
      }
    } else {
      if (window.traceMode) window.traceMode.hide();
      if (els.graphPane) els.graphPane.style.display = "";
      // Re-render graph if we have an entry but no live cy (e.g. coming
      // back from Trace mode).
      if (currentEntryFnId != null && !cy) {
        renderForEntry(currentEntryFnId);
      } else {
        // No work to do (graph already live or no entry) — signal so the
        // perf harness doesn't hang waiting for a render that won't come.
        cgSignalReady();
      }
    }
  }

  // ------------------------------------------------------------------ compare

  // Diff/compare state. Mode=off: single-pane (current behavior).
  //
  // In v1, the primary pane always renders the live working tree (whatever
  // currentArch points at) — the topbar's arch/entry/depth wiring is
  // unchanged. The secondary pane shows ONE other commit's view:
  //   mode=parent X → secondary shows X^ (parent of X)
  //   mode=head   X → secondary shows X
  // Both panes track the same selected entry (matched by qualified name; fn
  // ids differ between builds). Drilling on the primary updates the secondary
  // via traceMode.setOnRendered.
  // Exposed via window.__cgCompareState for in-page debugging probes.
  // Read-only; mutations go through the regular code paths.
  const compareState = window.__cgCompareState = {
    mode: "off",
    commits: [],
    selectedSha: "",
    statuses: {}, // sha -> { status, default_arch, arches, error }
    pollTimer: null,
    // Cache of secondary graph blobs and derived lookups: sha -> { graph,
    // fnById, fnByName }. Only populated for shas in `ready` state.
    secGraphs: new Map(),
    // Set<fn_id> of entry-point fns whose reachable subtree contains at
    // least one *changed* function (line range overlaps a diff hunk).
    // The dropdown reads this to prefix flagged entries with "● ".
    entryNeedsReview: new Set(),
    // Set<fn_id> of fns in the live graph that themselves have changed
    // source between live and the secondary commit. The trace renderer
    // reads this (via tctx.isChangedFn) to mark each box with a diamond
    // glyph + accent stripe so the user knows where to drill.
    changedFnIds: new Set(),
    // Mirror of changedFnIds keyed by qualified name. The secondary
    // pane's fns have different fn ids (separate build), so we match by
    // name on that side.
    changedFnNames: new Set(),
    // Set<fn_id> of fns whose REACHABLE SUBTREE contains at least one
    // changed fn (including the fn itself). Computed by reverse-BFS
    // from changedFnIds. The trace renderer uses this to mark
    // depth-capped leaves as "drill to find diff" — without it, the
    // dropdown might flag an entry whose actual changed code lies past
    // the depth limit and the trace view shows nothing highlighted.
    subtreeChangedFnIds: new Set(),
    subtreeChangedFnNames: new Set(),
    // Set<DefId> of Definitions whose line_start..line_end overlaps a
    // diff hunk. Drives the def_deps extension of changedFnIds and the
    // identifier highlighting in the source pane.
    changedDefIds: new Set(),
    // simpleName → Definition for changed defs. Source pane uses this
    // to wrap matching identifiers in a clickable span. Multiple defs
    // can share a simple name (across files); we keep the first one
    // found and the resolver picks based on import context at click
    // time.
    changedDefByName: new Map(),
    // Map<repoRelativePath, [{ old_start, old_count, start, count }, …]>.
    // Populated by recomputeDiffSets so the source pane can tint each
    // line as added/removed/unchanged. Empty when compare is off.
    hunksByFile: new Map(),
    // Review unit catalog derived from hunksByFile in recomputeDiffSets.
    // Each unit: { id, kind: "added"|"removed", file, new_start,
    // new_count, old_start, old_count }. Stable IDs follow the schema
    // <file>:<new_start>:<a|r> so they can be persisted across sessions
    // (parent mode only; head mode is in-memory).
    units: [],
    // Map<unit_id, {file, kind, new_start, new_count, old_start,
    // old_count}> for quick lookup by id.
    unitById: new Map(),
    // Per-(file, side) → [unit] lookup. Side is "added" (new side, primary
    // pane) or "removed" (old side, secondary pane). Source rendering
    // walks this to draw a checkbox at the start of each unit.
    unitsByFileSide: new Map(),
    // Map<unit_id, {reviewed, at, by}>. Loaded from /api/review_state in
    // parent mode (and on POST responses). Head mode keeps it
    // in-memory (toggles persist within the session only). Missing entry
    // means "not reviewed yet" — equivalent to {reviewed: false}.
    reviewed: new Map(),
    // True when persistent review state is available (parent mode with
    // both shas being full hex commits). When false, toggles still work
    // but only in-memory.
    canPersistReview: false,
  };

  function setCompareStatus(text, kind) {
    if (!els.compareStatus) return;
    els.compareStatus.textContent = text || "";
    els.compareStatus.classList.remove("building", "ready", "errored");
    if (kind) els.compareStatus.classList.add(kind);
  }

  async function fetchCommitsList() {
    try {
      const r = await fetch("/api/commits?limit=80");
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      compareState.commits = (j.commits || []);
    } catch (err) {
      console.error("/api/commits failed", err);
      compareState.commits = [];
    }
  }

  function populateCommitDropdown() {
    if (!els.compareCommit) return;
    els.compareCommit.innerHTML = "";
    if (compareState.commits.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "(no commits)";
      els.compareCommit.appendChild(opt);
      return;
    }
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "(select commit)";
    els.compareCommit.appendChild(placeholder);
    for (const c of compareState.commits) {
      const opt = document.createElement("option");
      opt.value = c.sha;
      // Show: short sha + truncated subject. Commits older than the
      // -Demit_ir scaffold are tagged so the user knows they can't be
      // loaded — the build would fail with "invalid option: -Demit_ir".
      // The option stays selectable so the user can still see the tag
      // and understand why it's unavailable; loading itself fails fast
      // with a clear message ("commit predates the -Demit_ir build
      // option") via the server preflight.
      const subj = c.subject || "";
      const truncated = subj.length > 60 ? subj.slice(0, 57) + "…" : subj;
      const compat = c.cg_compatible !== false; // default-true if absent
      const prefix = compat ? "" : "[no cg] ";
      opt.textContent = `${prefix}${c.short}  ${truncated}`;
      opt.title = compat
        ? `${c.short}\n${c.author}  ${c.date}\n${subj}`
        : `${c.short}\n${c.author}  ${c.date}\n${subj}\n\nThis commit predates the -Demit_ir kernel build option (commit 207770e), so the callgraph tool can't review it.`;
      if (!compat) opt.classList.add("opt_incompatible");
      els.compareCommit.appendChild(opt);
    }
  }

  /** Returns the parent sha for a given selected sha by walking the
   * recent-commits list. Returns null if not found or no parent in list
   * (e.g. user picked the very last commit in the dropdown). */
  function parentShaOf(sha) {
    const idx = compareState.commits.findIndex((c) => c.sha === sha);
    if (idx < 0 || idx + 1 >= compareState.commits.length) return null;
    return compareState.commits[idx + 1].sha;
  }

  /** Resolves the sha that should populate the secondary pane.
   *  Returns null if compare is off or selection is incomplete. */
  function secondarySha() {
    if (compareState.mode === "off") return null;
    const sel = compareState.selectedSha;
    if (!sel) return null;
    if (compareState.mode === "parent") {
      return parentShaOf(sel);
    }
    return sel; // mode === "head"
  }

  function shasNeedingLoad() {
    const s = secondarySha();
    return s ? [s] : [];
  }

  async function triggerLoad(sha) {
    try {
      const r = await fetch("/api/load_commit?sha=" + encodeURIComponent(sha));
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      compareState.statuses[sha] = j;
      return j;
    } catch (err) {
      console.error("load_commit failed for", sha, err);
      compareState.statuses[sha] = { status: "errored", error: String(err), arches: [], default_arch: "" };
      return compareState.statuses[sha];
    }
  }

  async function refreshStatus(sha) {
    try {
      const r = await fetch("/api/load_commit/status?sha=" + encodeURIComponent(sha));
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      compareState.statuses[sha] = j;
      return j;
    } catch (err) {
      console.error("load_commit/status failed for", sha, err);
      return null;
    }
  }

  function shortSha(sha) {
    return sha ? sha.slice(0, 7) : "";
  }

  function recomputeCompareStatus() {
    if (compareState.mode === "off") {
      setCompareStatus("");
      hideSecondaryPane();
      recomputeDiffSets(); // clears the sets and refreshes trace/dropdown
      return;
    }
    if (!compareState.selectedSha) {
      setCompareStatus("select commit");
      hideSecondaryPane();
      recomputeDiffSets();
      return;
    }
    const sec = secondarySha();
    if (!sec) {
      setCompareStatus("no parent commit available");
      hideSecondaryPane();
      recomputeDiffSets();
      return;
    }
    const status = compareState.statuses[sec];
    const secShort = shortSha(sec);
    if (status && status.status === "errored") {
      setCompareStatus(`error: ${status.error || "load failed"}`, "errored");
      hideSecondaryPane();
      return;
    }
    if (!status || status.status !== "ready") {
      setCompareStatus(`loading ${secShort}…`, "building");
      hideSecondaryPane();
      return;
    }
    setCompareStatus(`ready: ${secShort}`, "ready");
    showSecondaryPaneAndRender(sec);
    // Compute "needs review" flags for the entry dropdown — fire and
    // forget; the dropdown updates whenever the fetch returns. Repeated
    // calls (mode flip, commit reselect) are cheap on a localhost server.
    recomputeDiffSets();
  }

  /** Show the secondary trace pane and trigger a render. Idempotent. */
  function showSecondaryPaneAndRender(sec) {
    if (els.tracePaneColB) els.tracePaneColB.style.display = "";
    if (els.tracePaneColA) updateTraceLabel(els.traceLabelA, "live", null);
    if (els.tracePaneColB) updateTraceLabel(els.traceLabelB, "older", sec);
    ensureSecGraph(sec).then(function () {
      requestSecondaryRender();
    });
  }

  function hideSecondaryPane() {
    if (els.tracePaneColB) els.tracePaneColB.style.display = "none";
    if (els.traceViewB) els.traceViewB.innerHTML = "";
    // Hide the live label too — the user only sees one pane and doesn't
    // need a label telling them so. The label reappears the next time
    // compare is enabled.
    if (els.traceLabelA) els.traceLabelA.style.display = "none";
    if (els.traceLabelB) els.traceLabelB.style.display = "none";
    // Source pane labels stick around until the next fn click otherwise.
    // Clearing them here keeps the two panes' labelling state in sync
    // with whether the user is in compare mode.
    clearSecondarySource();
  }

  /** Populate a pane label with side-of-diff tag + sha + commit subject.
   *  side="live" renders a green "LIVE" tag with no sha; side="older"
   *  renders a red tag plus the short sha and subject from the recent-
   *  commits list (when available). */
  function updateTraceLabel(labelEl, side, sha) {
    if (!labelEl) return;
    labelEl.style.display = "";
    labelEl.classList.remove("live", "older");
    labelEl.classList.add(side);
    labelEl.innerHTML = "";

    const tag = document.createElement("span");
    tag.className = "pane_tag";
    tag.textContent = side === "live" ? "LIVE" : "OLDER";
    labelEl.appendChild(tag);

    if (side === "live") {
      const note = document.createElement("span");
      note.className = "pane_subj";
      note.textContent = "working tree";
      labelEl.appendChild(note);
      return;
    }

    if (sha) {
      const shaEl = document.createElement("span");
      shaEl.className = "pane_sha";
      shaEl.textContent = sha.slice(0, 7);
      labelEl.appendChild(shaEl);
      const commit = compareState.commits.find(function (c) { return c.sha === sha; });
      if (commit && commit.subject) {
        const subj = document.createElement("span");
        subj.className = "pane_subj";
        subj.textContent = commit.subject;
        subj.title = commit.subject;
        labelEl.appendChild(subj);
      }
    }
  }

  /** Fetch + cache the secondary graph blob for a sha. Reuses live arch
   *  picker so the comparison is apples-to-apples (x86_64 vs x86_64). */
  async function ensureSecGraph(sha) {
    if (compareState.secGraphs.has(sha)) return compareState.secGraphs.get(sha);
    try {
      const url = "/api/graph?sha=" + encodeURIComponent(sha) +
                  "&arch=" + encodeURIComponent(currentArch);
      const r = await fetch(url);
      if (!r.ok) throw new Error("HTTP " + r.status);
      const g = await r.json();
      const ix = new Map();
      for (const fn of g.functions || []) ix.set(fn.id, fn);
      const byName = window.traceMode ? window.traceMode.buildFnByName(ix) : new Map();
      const entry = { graph: g, fnById: ix, fnByName: byName };
      compareState.secGraphs.set(sha, entry);
      return entry;
    } catch (err) {
      console.error("secondary graph fetch failed", err);
      return null;
    }
  }

  /** Re-run populateDropdown, preserving the user's current selection.
   *  Used after `entryNeedsReview` updates so the dropdown can show the
   *  "●" prefix on entries whose subtree touches a changed file. */
  function repopulateEntriesPreservingSelection() {
    if (!graph) return;
    const saved = els.entrySelect.value;
    populateDropdown(graph.entry_points || []);
    if (saved) {
      // value setter silently ignores ids that aren't options anymore.
      els.entrySelect.value = saved;
    }
  }

  /** Strip the kernel-root prefix from an absolute def_loc path so it
   *  matches `git diff --name-only` output (which is repo-relative).
   *  Heuristic: find the LAST `/kernel/` substring and slice from there.
   *  Mirrors the trace-view shortenFile heuristic. Returns null if the
   *  file is outside the kernel tree (e.g. /usr/lib/zig stdlib paths). */
  function defLocToRepoRel(file) {
    if (!file) return null;
    const idx = file.lastIndexOf("/kernel/");
    if (idx >= 0) return file.slice(idx + 1);
    if (file.startsWith("kernel/")) return file;
    return null;
  }

  /** Compute changed-fn sets for the current compare state.
   *
   *  A function is "changed" iff its source line range on the live side
   *  overlaps any hunk in `git diff --unified=0 <sec>`. Line ranges come
   *  from def_loc.line; we approximate the end-of-fn by the start of the
   *  next fn in the same file (sorted), or +∞ for the last fn. This
   *  tracks fn-level edits even when the file has unrelated changes
   *  elsewhere — the dropdown only flags entries whose reachable subtree
   *  contains a *changed fn*, not just a changed file.
   *
   *  Updates compareState.changedFnIds, .changedFnNames, .entryNeedsReview
   *  in one shot, then repopulates the dropdown and rerenders the trace
   *  so both panes pick up the updated `isChangedFn` predicate. */
  function simpleName(qname) {
    if (!qname) return "";
    const idx = qname.lastIndexOf(".");
    return idx >= 0 ? qname.slice(idx + 1) : qname;
  }

  async function recomputeDiffSets() {
    const clear = function () {
      compareState.changedFnIds = new Set();
      compareState.changedFnNames = new Set();
      compareState.changedDefIds = new Set();
      compareState.changedDefByName = new Map();
      compareState.entryNeedsReview = new Set();
      compareState.hunksByFile = new Map();
      repopulateEntriesPreservingSelection();
      refreshTraceForDiff();
    };
    if (compareState.mode === "off" || !graph) { clear(); return; }
    const sec = secondarySha();
    if (!sec) { clear(); return; }

    let hunksByFile;
    try {
      const r = await fetch("/api/diff_hunks?sha=" + encodeURIComponent(sec));
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      hunksByFile = new Map();
      for (const f of (j.files || [])) {
        hunksByFile.set(f.path, f.hunks || []);
      }
      compareState.hunksByFile = hunksByFile;
    } catch (err) {
      console.error("/api/diff_hunks failed", err);
      return;
    }

    const changedFnIds = new Set();
    const changedFnNames = new Set();
    // Definitions whose source range overlaps a hunk. Computed alongside
    // changedFnIds so we can extend the fn set with anything that
    // depends on a changed def — the user's mental model is "a struct
    // changed → every fn touching that struct should be flagged".
    const changedDefIds = new Set();

    if (hunksByFile.size > 0) {
      // Bucket fns AND defs by repo-relative file path; we only care
      // about files that have at least one hunk.
      const fnsByFile = new Map();
      for (const fn of (graph.functions || [])) {
        const rel = defLocToRepoRel(fn.def_loc && fn.def_loc.file);
        if (!rel || !hunksByFile.has(rel)) continue;
        if (!fnsByFile.has(rel)) fnsByFile.set(rel, []);
        fnsByFile.get(rel).push(fn);
      }
      const defsByFile = new Map();
      for (const def of (graph.definitions || [])) {
        const rel = defLocToRepoRel(def.file);
        if (!rel || !hunksByFile.has(rel)) continue;
        if (!defsByFile.has(rel)) defsByFile.set(rel, []);
        defsByFile.get(rel).push(def);
      }

      for (const [path, fns] of fnsByFile.entries()) {
        // Sort by def_loc.line so we can use the next fn's start as
        // an upper bound for the current fn's range. The last fn in
        // the file gets +∞ — a conservative end that may over-flag
        // trailing helpers but never under-flags a real change.
        fns.sort(function (a, b) {
          return (a.def_loc.line || 0) - (b.def_loc.line || 0);
        });
        const hunks = hunksByFile.get(path);
        for (let i = 0; i < fns.length; i += 1) {
          const startLine = fns[i].def_loc.line || 0;
          const endLine = i + 1 < fns.length
            ? Math.max(startLine, (fns[i + 1].def_loc.line || 0) - 1)
            : Infinity;
          for (const h of hunks) {
            const hstart = h.start;
            // count=0 represents pure deletions; treat as a single
            // boundary line so insert/delete-only hunks still count.
            const span = h.count === 0 ? 1 : h.count;
            const hend = hstart + span - 1;
            if (hend < startLine) continue;
            if (hstart > endLine) continue;
            changedFnIds.add(fns[i].id);
            if (fns[i].name) changedFnNames.add(fns[i].name);
            if (fns[i].mangled) changedFnNames.add(fns[i].mangled);
            break;
          }
        }
      }

      // Defs use their own line_start..line_end (the walker captured the
      // full body extent). No "next def" trickery needed — defs don't
      // overlap each other.
      for (const [path, defs] of defsByFile.entries()) {
        const hunks = hunksByFile.get(path);
        for (const def of defs) {
          const startLine = def.line_start || 0;
          const endLine = def.line_end || startLine;
          for (const h of hunks) {
            const hstart = h.start;
            const span = h.count === 0 ? 1 : h.count;
            const hend = hstart + span - 1;
            if (hend < startLine) continue;
            if (hstart > endLine) continue;
            changedDefIds.add(def.id);
            break;
          }
        }
      }

      // Extend changedFnIds with any fn whose def_deps intersect
      // changedDefIds. This is the "struct edit flags every fn that uses
      // it" rule — the user's review-driven mental model.
      if (changedDefIds.size > 0) {
        for (const fn of (graph.functions || [])) {
          const deps = fn.def_deps;
          if (!deps || deps.length === 0) continue;
          if (changedFnIds.has(fn.id)) continue;
          for (const did of deps) {
            if (changedDefIds.has(did)) {
              changedFnIds.add(fn.id);
              if (fn.name) changedFnNames.add(fn.name);
              if (fn.mangled) changedFnNames.add(fn.mangled);
              break;
            }
          }
        }
      }
    }

    compareState.changedFnIds = changedFnIds;
    compareState.changedFnNames = changedFnNames;
    compareState.changedDefIds = changedDefIds;

    // Derive review-unit catalog from hunks. Each hunk yields up to two
    // units: one "removed" (when old_count > 0) and one "added" (when
    // new_count > 0). IDs are stable so the persistence file can key
    // by them across sessions in parent mode.
    rebuildUnitsFromHunks();
    // Fetch persisted review state (parent mode only) — fire and forget;
    // checkboxes update when the response arrives.
    fetchReviewStateIfPersistable();

    // Build simpleName → Definition map for source-pane ident highlight.
    // We index by simpleName (last dotted segment of qualified_name) so a
    // bare identifier in source like `Foo` matches the changed `<mod>.Foo`
    // def. First-write-wins on simpleName collisions (rare; user is
    // accepting some over-flagging when distinct defs share a name).
    const byName = new Map();
    for (const did of changedDefIds) {
      const def = (graph.definitions || []).find(function (d) { return d.id === did; });
      if (!def) continue;
      const simple = simpleName(def.qualified_name);
      if (!byName.has(simple)) byName.set(simple, def);
    }
    compareState.changedDefByName = byName;

    // Compute the "subtree contains a changed fn" closure via reverse-
    // BFS from changedFnIds. Without this, entries flagged in the
    // dropdown look unhighlighted in the trace view when their actual
    // changes are deeper than the depth slider — the trace view caps
    // expansion, so changed leaves never render.
    //
    // Approach: build the reverse adjacency once (callee → callers),
    // then BFS from every changedFnId following those reverse edges.
    // Both the source and the target have to share id-space, so this
    // operates on the LIVE graph only; the secondary pane uses the
    // matching `changedSubtreeFnNames` mirror computed below.
    const subtreeIds = new Set(changedFnIds);
    const reverse = new Map(); // callee_id → [caller_id, ...]
    for (const fn of (graph.functions || [])) {
      for (const c of (fn.callees || [])) {
        if (c.to == null) continue;
        if (!reverse.has(c.to)) reverse.set(c.to, []);
        reverse.get(c.to).push(fn.id);
      }
    }
    {
      const queue = Array.from(changedFnIds);
      while (queue.length > 0) {
        const id = queue.shift();
        const callers = reverse.get(id);
        if (!callers) continue;
        for (const cid of callers) {
          if (subtreeIds.has(cid)) continue;
          subtreeIds.add(cid);
          queue.push(cid);
        }
      }
    }
    compareState.subtreeChangedFnIds = subtreeIds;

    // Mirror as qualified names for the secondary pane (different ids).
    const subtreeNames = new Set();
    for (const id of subtreeIds) {
      const fn = fnById.get(id);
      if (!fn) continue;
      if (fn.name) subtreeNames.add(fn.name);
      if (fn.mangled) subtreeNames.add(fn.mangled);
    }
    compareState.subtreeChangedFnNames = subtreeNames;

    // Entry-needs-review: BFS from each entry over direct/dispatch
    // callee edges; flagged if any reachable fn is in changedFnIds.
    const flagged = new Set();
    const entries = graph.entry_points || [];
    for (const e of entries) {
      const root = e.fn_id;
      if (root == null) continue;
      if (changedFnIds.has(root)) { flagged.add(root); continue; }
      const visited = new Set([root]);
      const queue = [root];
      let hit = false;
      while (queue.length > 0) {
        const id = queue.shift();
        const fn = fnById.get(id);
        if (!fn) continue;
        for (const c of (fn.callees || [])) {
          const to = c.to;
          if (to == null) continue;
          if (visited.has(to)) continue;
          visited.add(to);
          if (changedFnIds.has(to)) { hit = true; break; }
          queue.push(to);
        }
        if (hit) break;
      }
      if (hit) flagged.add(root);
    }
    compareState.entryNeedsReview = flagged;

    repopulateEntriesPreservingSelection();
    refreshTraceForDiff();
  }

  /** Build the diffOpts argument for renderSourceSnippet on the primary
   *  (live / new) side. Returns null when compare is off, the file isn't
   *  in the change set, or paths can't be resolved. */
  function computeDiffOptsForPrimary(filePath) {
    if (!compareState || compareState.mode === "off") return null;
    if (!compareState.hunksByFile || compareState.hunksByFile.size === 0) return null;
    const rel = defLocToRepoRel(filePath);
    if (!rel) return null;
    const hunks = compareState.hunksByFile.get(rel);
    if (!hunks || hunks.length === 0) return null;
    return { hunks: hunks, side: "new" };
  }

  /** Same, but for the secondary (older / commit) side. The secondary's
   *  file path lives under /var/tmp/cg-worktrees/<sha>/... but its
   *  repo-relative form is identical to the primary's, so the hunks
   *  table can be keyed by the same path. */
  function computeDiffOptsForSecondary(filePath) {
    if (!compareState || compareState.mode === "off") return null;
    if (!compareState.hunksByFile || compareState.hunksByFile.size === 0) return null;
    const rel = secondaryPathToRepoRel(filePath);
    if (!rel) return null;
    const hunks = compareState.hunksByFile.get(rel);
    if (!hunks || hunks.length === 0) return null;
    return { hunks: hunks, side: "old" };
  }

  /** Strip the worktree prefix from a secondary-side path. Format is
   *  always /var/tmp/cg-worktrees/<sha>/<repo-rel>; we slice past the
   *  sha segment. Falls back to the kernel/-prefix heuristic when the
   *  path doesn't follow the worktree convention. */
  function secondaryPathToRepoRel(file) {
    if (!file) return null;
    const marker = "/cg-worktrees/";
    const idx = file.indexOf(marker);
    if (idx >= 0) {
      const after = file.slice(idx + marker.length);
      const slash = after.indexOf("/");
      if (slash >= 0) return after.slice(slash + 1);
    }
    return defLocToRepoRel(file);
  }

  // ---------------------------------------------------------------- review
  //
  // Each contiguous +/- hunk run becomes a "unit of review". The user
  // checks a unit off in the source pane gutter or in the third panel,
  // and the state persists across sessions (parent mode only — both
  // shas have to be immutable for IDs to be stable). The schema lives
  // at <git_root>/.callgraph/review/<sha_a>..<sha_b>.json.

  /** True when the current secondary commit is a full hex sha AND the
   *  primary side has one too. The frontend only knows the secondary
   *  sha; for parent mode the "primary" side IS the selected commit
   *  and the secondary is its parent — both are commits, both stable.
   *  For head mode the primary is the live working tree and there's
   *  no stable sha for it, so we can't persist. */
  function reviewPair() {
    if (compareState.mode === "parent") {
      const sel = compareState.selectedSha;
      const parent = parentShaOf(sel);
      if (sel && parent) return { sha_a: parent, sha_b: sel };
    }
    return null;
  }

  function rebuildUnitsFromHunks() {
    compareState.units = [];
    compareState.unitById = new Map();
    compareState.unitsByFileSide = new Map();
    if (!compareState.hunksByFile) return;
    for (const [path, hunks] of compareState.hunksByFile.entries()) {
      for (const h of hunks) {
        if (h.old_count > 0) {
          const u = {
            id: path + ":" + h.start + ":r",
            kind: "removed",
            file: path,
            new_start: h.start,
            new_count: h.count,
            old_start: h.old_start,
            old_count: h.old_count,
          };
          compareState.units.push(u);
          compareState.unitById.set(u.id, u);
          pushIntoFileSide(path, "removed", u);
        }
        if (h.count > 0) {
          const u = {
            id: path + ":" + h.start + ":a",
            kind: "added",
            file: path,
            new_start: h.start,
            new_count: h.count,
            old_start: h.old_start,
            old_count: h.old_count,
          };
          compareState.units.push(u);
          compareState.unitById.set(u.id, u);
          pushIntoFileSide(path, "added", u);
        }
      }
    }
  }

  function pushIntoFileSide(file, side, unit) {
    const key = file + ":" + side;
    if (!compareState.unitsByFileSide.has(key)) {
      compareState.unitsByFileSide.set(key, []);
    }
    compareState.unitsByFileSide.get(key).push(unit);
  }

  /** Lookup units that start exactly at `line` on `side` of file. Used
   *  by the source render to draw a checkbox at that line. Returns
   *  empty array when no unit matches. */
  function unitsStartingAt(file, side, line) {
    const key = file + ":" + side;
    const list = compareState.unitsByFileSide.get(key);
    if (!list) return [];
    return list.filter(function (u) {
      const start = side === "added" ? u.new_start : u.old_start;
      return start === line;
    });
  }

  /** True when `line` (on `sideTag` "new"|"old" of `filePath`) is inside
   *  any unit whose reviewed state is true. Used by the source render
   *  to apply `.unit_reviewed` to interior lines of reviewed units, so
   *  the entire diff hunk visibly fades, not just the first row. */
  function isLineInsideReviewedUnit(filePath, sideTag, line) {
    const fileRel = sideTag === "new"
      ? defLocToRepoRel(filePath)
      : secondaryPathToRepoRel(filePath);
    if (!fileRel) return false;
    const sideKey = sideTag === "new" ? "added" : "removed";
    const list = compareState.unitsByFileSide.get(fileRel + ":" + sideKey);
    if (!list) return false;
    for (const u of list) {
      const start = sideKey === "added" ? u.new_start : u.old_start;
      const count = sideKey === "added" ? u.new_count : u.old_count;
      if (count === 0) continue;
      if (line < start || line >= start + count) continue;
      const rec = compareState.reviewed.get(u.id);
      if (rec && rec.reviewed) return true;
    }
    return false;
  }

  async function fetchReviewStateIfPersistable() {
    const pair = reviewPair();
    compareState.canPersistReview = pair != null;
    if (!pair) {
      // Head mode: keep an empty in-memory state. We DON'T clobber an
      // existing in-session reviewed map — it's session-only by design.
      return;
    }
    try {
      const url = "/api/review_state?sha_a=" + encodeURIComponent(pair.sha_a) +
        "&sha_b=" + encodeURIComponent(pair.sha_b);
      const r = await fetch(url);
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      compareState.reviewed = new Map();
      const units = (j && j.units) || {};
      for (const id of Object.keys(units)) {
        compareState.reviewed.set(id, units[id]);
      }
      // Refresh whichever surfaces care about reviewed state.
      if (typeof rerenderSourceForReview === "function") rerenderSourceForReview();
    } catch (err) {
      console.error("/api/review_state GET failed", err);
    }
  }

  /** Toggle a unit's reviewed state. Updates compareState.reviewed
   *  immediately for snappy UI, then POSTs to the server (parent mode
   *  only — head mode is in-memory). On success the server response
   *  is the new authoritative state; we fold it back in. */
  async function toggleUnitReviewed(unitId, reviewed) {
    const prior = compareState.reviewed.get(unitId);
    compareState.reviewed.set(unitId, {
      reviewed: !!reviewed,
      at: prior ? prior.at : "",
      by: prior ? prior.by : "",
    });
    rerenderSourceForReview();

    if (!compareState.canPersistReview) return;
    const pair = reviewPair();
    if (!pair) return;
    try {
      const url = "/api/review_state?sha_a=" + encodeURIComponent(pair.sha_a) +
        "&sha_b=" + encodeURIComponent(pair.sha_b);
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          unit_id: unitId,
          reviewed: !!reviewed,
          by: "",
        }),
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      const units = (j && j.units) || {};
      compareState.reviewed = new Map();
      for (const id of Object.keys(units)) {
        compareState.reviewed.set(id, units[id]);
      }
      rerenderSourceForReview();
    } catch (err) {
      console.error("/api/review_state POST failed", err);
      // Roll back the optimistic update.
      if (prior) compareState.reviewed.set(unitId, prior);
      else compareState.reviewed.delete(unitId);
      rerenderSourceForReview();
    }
  }

  /** Re-render the currently-displayed source so checkbox state in the
   *  gutter reflects the latest reviewed map. Cheaper to refetch the
   *  same source than to traverse and patch checkboxes in place. Also
   *  refreshes the review tracker so its progress counters and group
   *  rollups reflect the toggle. */
  function rerenderSourceForReview() {
    if (typeof updateChangesPanel === "function") updateChangesPanel();
    if (!els.infoSource || els.infoSource.children.length === 0) return;
    if (!lastFetchedSource.file) return;
    fetchSource(lastFetchedSource.file, 1, 10000000, lastFetchedSource.line || 1);
  }

  /** Push the updated isChangedFn predicate into traceMode and force a
   *  re-render so the new diamond markers appear without requiring the
   *  user to click anything. Inert when trace mode isn't visible. */
  function refreshTraceForDiff() {
    if (!window.traceMode) return;
    const ids = compareState.changedFnIds;
    const subtreeIds = compareState.subtreeChangedFnIds;
    window.traceMode.setContext({
      isChangedFn: function (fn) {
        return fn != null && fn.id != null && ids.has(fn.id);
      },
      hasChangedDescendant: function (fn) {
        return fn != null && fn.id != null && subtreeIds.has(fn.id);
      },
    });
    if (currentMode === "trace") {
      window.traceMode.invalidate();
      window.traceMode.rerender();
    }
    updateChangesPanel();
  }

  /** Render the review tracker above the primary trace pane. Lists
   *  every reviewable Unit (diff hunk) reachable from the current entry,
   *  grouped file → containing fn → unit. Each unit row carries a
   *  checkbox bound to compareState.reviewed (server-persisted in parent
   *  mode) plus a click-to-jump that scrolls the source pane to the
   *  hunk's start line. File and fn group headers carry rollup
   *  counters and a "mark all" button. The panel header shows overall
   *  progress as "X of Y reviewed" plus a thin progress bar.
   *
   *  Rendering is recomputed in full on every call — cheap relative to
   *  the rest of the diff path, and lets the source-gutter checkbox
   *  toggles re-call this and stay in sync without per-row patching. */
  function updateChangesPanel() {
    if (!els.diffChangesPanel) return;
    const show = function (visible) {
      if (els.reviewTrackerCol) {
        els.reviewTrackerCol.style.display = visible ? "" : "none";
      }
    };
    if (compareState.mode === "off" || compareState.changedFnIds.size === 0) {
      show(false);
      return;
    }
    if (currentEntryFnId == null) {
      show(false);
      return;
    }

    // BFS from currentEntryFnId over direct/dispatch callees, collecting
    // any fn that's in changedFnIds.
    const root = currentEntryFnId;
    const visited = new Set([root]);
    const queue = [root];
    const found = [];
    if (compareState.changedFnIds.has(root)) {
      const f = fnById.get(root);
      if (f) found.push(f);
    }
    while (queue.length > 0) {
      const id = queue.shift();
      const fn = fnById.get(id);
      if (!fn) continue;
      for (const c of (fn.callees || [])) {
        const to = c.to;
        if (to == null) continue;
        if (visited.has(to)) continue;
        visited.add(to);
        queue.push(to);
        if (compareState.changedFnIds.has(to)) {
          const tfn = fnById.get(to);
          if (tfn) found.push(tfn);
        }
      }
    }
    // De-duplicate by qualified name; the IR can emit one Function per
    // generic instantiation (same name, same def_loc) which would clutter
    // the list.
    const seenFn = new Set();
    const reachableFns = [];
    for (const f of found) {
      const key = f.name || f.mangled || ("id:" + f.id);
      if (seenFn.has(key)) continue;
      seenFn.add(key);
      reachableFns.push(f);
    }

    // Build per-file fn line ranges via next-fn-start-1, used both for
    // "own-body unit" matching and for inferring a unit's containing fn
    // when grouping.
    const fnEndLineByFnId = new Map();
    const fnsByPath = new Map();
    for (const f of (graph.functions || [])) {
      const rel = defLocToRepoRel(f.def_loc && f.def_loc.file);
      if (!rel) continue;
      if (!fnsByPath.has(rel)) fnsByPath.set(rel, []);
      fnsByPath.get(rel).push(f);
    }
    for (const list of fnsByPath.values()) {
      list.sort(function (a, b) {
        return (a.def_loc.line || 0) - (b.def_loc.line || 0);
      });
      for (let i = 0; i < list.length; i += 1) {
        const startLine = list[i].def_loc.line || 0;
        const endLine = i + 1 < list.length
          ? Math.max(startLine, (list[i + 1].def_loc.line || 0) - 1)
          : Number.MAX_SAFE_INTEGER;
        fnEndLineByFnId.set(list[i].id, endLine);
      }
    }

    // defId → Definition record (line range + name) for resolving
    // dep-def units back to their source label.
    const defById = new Map();
    for (const def of (graph.definitions || [])) defById.set(def.id, def);

    // Walk reachable fns and collect every contributing unit. We attach
    // unit → contributingFn pairs so the renderer can group under the
    // fn each contribution is "for". A given unit can appear under
    // multiple fns (e.g. a struct edit flags every dependent fn) — we
    // record each (unit, fn) pair separately.
    //
    // Each contribution: { unit, kind, file, line, fn, dep } where
    //   - unit is the unit record (may be null for synthetic "no unit
    //     overlaps the def" fallbacks),
    //   - kind ∈ {"added", "removed", "dep"},
    //   - dep is the Definition record when kind === "dep".
    const contribs = [];
    for (const fn of reachableFns) {
      const fnFileRel = defLocToRepoRel(fn.def_loc && fn.def_loc.file);
      const fnStart = fn.def_loc ? (fn.def_loc.line || 0) : 0;
      const fnEnd = fnEndLineByFnId.get(fn.id) || fnStart;

      // Own-body units. Match by repo-relative path; fnStart/fnEnd are
      // LIVE-side line numbers, so we test against the unit's new_start
      // (the position in the new file). For removed-only hunks
      // new_start is the position where the deletion sits in the new
      // file — close enough to belong to the same fn for grouping
      // purposes.
      if (fnFileRel) {
        for (const u of (compareState.units || [])) {
          if (u.file !== fnFileRel) continue;
          const matchLine = u.new_start || u.old_start || 0;
          if (matchLine < fnStart || matchLine > fnEnd) continue;
          contribs.push(makeContrib(u, "own", fn, null));
        }
      }

      // Dep-def units. Iterate fn.def_deps ∩ changedDefIds. Definition
      // records store absolute paths (`/home/alec/Zag/...`); units use
      // repo-relative (`kernel/...`). Normalize before matching.
      for (const did of (fn.def_deps || [])) {
        if (!compareState.changedDefIds.has(did)) continue;
        const def = defById.get(did);
        if (!def) continue;
        const defFileRel = defLocToRepoRel(def.file) || def.file;
        const defStart = def.line_start || 0;
        const defEnd = def.line_end || defStart;
        let matched = 0;
        for (const u of (compareState.units || [])) {
          if (u.file !== defFileRel) continue;
          const matchLine = u.new_start || u.old_start || 0;
          if (matchLine < defStart || matchLine > defEnd) continue;
          contribs.push(makeContrib(u, "dep", fn, def));
          matched += 1;
        }
        if (matched === 0) {
          // Fallback row when no unit cleanly overlaps the def — give
          // the user a jump target on the def's first line in both
          // sides.
          contribs.push({
            unit: null,
            relation: "dep",
            file: defFileRel,
            unitKind: "dep",
            displayLine: defStart,
            displaySide: "live",
            liveLine: defStart,
            olderLine: defStart,
            fn: fn,
            dep: def,
          });
        }
      }
    }

    /** Build a contribution record from a real unit. The unit's kind
     *  ("added" | "removed") drives which side's line number we
     *  surface — for a removed hunk the "removed text" actually sits
     *  on the OLDER side at old_start; new_start is just the position
     *  in the post-edit file where the deletion happened, which is
     *  confusing as a label. Click handlers also pass both lines so
     *  each pane scrolls to where the change is on its own side. */
    function makeContrib(u, relation, fn, def) {
      const liveLine = u.new_start || 0;
      const olderLine = u.old_start || 0;
      const isAdd = u.kind === "added";
      return {
        unit: u,
        relation: relation, // "own" | "dep"
        unitKind: u.kind,   // "added" | "removed"
        file: u.file,
        liveLine: liveLine,
        olderLine: olderLine,
        displayLine: isAdd ? liveLine : olderLine,
        displaySide: isAdd ? "live" : "older",
        fn: fn,
        dep: def,
      };
    }

    if (contribs.length === 0) {
      show(true);
      els.diffChangesList.innerHTML = "";
      const empty = document.createElement("div");
      empty.className = "diff_changes_empty";
      empty.textContent = "No reviewable hunks reachable from this entry.";
      els.diffChangesList.appendChild(empty);
      if (els.diffChangesCount) els.diffChangesCount.textContent = "0 of 0";
      if (els.reviewProgressBar) els.reviewProgressBar.style.display = "none";
      return;
    }

    // Group by file → fn (under each contribution's fn, since the same
    // dep unit can appear under multiple fns). Within fn, sort by line.
    const grouped = new Map(); // file → Map(fnKey → { fn, contribs[] })
    for (const c of contribs) {
      if (!grouped.has(c.file)) grouped.set(c.file, new Map());
      const fnMap = grouped.get(c.file);
      const fnKey = c.fn.name || c.fn.mangled || ("id:" + c.fn.id);
      if (!fnMap.has(fnKey)) fnMap.set(fnKey, { fn: c.fn, contribs: [] });
      fnMap.get(fnKey).contribs.push(c);
    }
    // Compute total unique-unit count for the panel-level progress bar.
    // A single unit shared across multiple fns counts once for the
    // overall denominator; each row still has its own checkbox but they
    // all bind to the same compareState.reviewed entry.
    const allUnitIds = new Set();
    for (const c of contribs) {
      if (c.unit) allUnitIds.add(c.unit.id);
    }
    const totalUnique = allUnitIds.size;
    let reviewedUnique = 0;
    for (const id of allUnitIds) {
      const r = compareState.reviewed.get(id);
      if (r && r.reviewed) reviewedUnique += 1;
    }

    show(true);
    if (els.diffChangesCount) {
      els.diffChangesCount.textContent = reviewedUnique + " of " + totalUnique +
        (totalUnique > 0
          ? "  (" + Math.round(100 * reviewedUnique / totalUnique) + "%)"
          : "");
    }
    if (els.reviewProgressBar) {
      els.reviewProgressBar.style.display = totalUnique > 0 ? "" : "none";
    }
    if (els.reviewProgressFill) {
      const pct = totalUnique > 0 ? (100 * reviewedUnique / totalUnique) : 0;
      els.reviewProgressFill.style.width = pct.toFixed(1) + "%";
    }
    els.diffChangesList.innerHTML = "";

    // Render: file groups in alphabetical order, fn groups in line
    // order within file, contribs in line order within fn.
    const sortedFiles = Array.from(grouped.keys()).sort();
    for (const file of sortedFiles) {
      const fnMap = grouped.get(file);
      const fnEntries = Array.from(fnMap.values());
      fnEntries.sort(function (a, b) {
        return (a.fn.def_loc.line || 0) - (b.fn.def_loc.line || 0);
      });

      // File-group rollup: count of unique units in this file group +
      // how many are reviewed.
      const fileUnitIds = new Set();
      for (const fnEntry of fnEntries) {
        for (const c of fnEntry.contribs) {
          if (c.unit) fileUnitIds.add(c.unit.id);
        }
      }
      let fileReviewed = 0;
      for (const id of fileUnitIds) {
        const r = compareState.reviewed.get(id);
        if (r && r.reviewed) fileReviewed += 1;
      }
      const fileTotal = fileUnitIds.size;

      const fileGroup = document.createElement("div");
      fileGroup.className = "review_file_group";

      const fileHeader = document.createElement("div");
      fileHeader.className = "review_file_header";
      if (fileTotal > 0 && fileReviewed === fileTotal) {
        fileHeader.classList.add("fully_reviewed");
      }
      const fileName = document.createElement("span");
      fileName.className = "file_name";
      fileName.textContent = shortenFile(file);
      fileHeader.appendChild(fileName);

      const fileProgress = document.createElement("span");
      fileProgress.className = "file_progress";
      fileProgress.textContent = fileReviewed + " of " + fileTotal;
      fileHeader.appendChild(fileProgress);

      const fileMarkBtn = document.createElement("button");
      fileMarkBtn.className = "review_group_action";
      fileMarkBtn.type = "button";
      fileMarkBtn.textContent = (fileReviewed === fileTotal && fileTotal > 0)
        ? "unmark file"
        : "mark file";
      fileMarkBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        // Toggle direction: if any unit in the file is unreviewed, mark
        // the rest reviewed; otherwise unmark all.
        const targetState = !(fileTotal > 0 && fileReviewed === fileTotal);
        for (const id of fileUnitIds) {
          const cur = compareState.reviewed.get(id);
          const isReviewed = !!(cur && cur.reviewed);
          if (isReviewed !== targetState) toggleUnitReviewed(id, targetState);
        }
      });
      fileHeader.appendChild(fileMarkBtn);

      fileHeader.addEventListener("click", function () {
        // Click on file header opens the file in both panes (live +
        // older) at line 1 — handy for browsing context.
        els.info.classList.add("visible");
        fetchSource(file, 1, 10000000, 1, { secondaryByFile: file });
      });
      fileGroup.appendChild(fileHeader);

      for (const fnEntry of fnEntries) {
        const fn = fnEntry.fn;
        const cs = fnEntry.contribs.slice();
        cs.sort(function (a, b) {
          // Own units first, then dep, then by display line so the
          // visual order tracks where the user will see the hunk.
          if (a.relation === "dep" && b.relation !== "dep") return 1;
          if (a.relation !== "dep" && b.relation === "dep") return -1;
          return a.displayLine - b.displayLine;
        });

        // Per-fn rollup: unique unit count + reviewed.
        const fnUnitIds = new Set();
        for (const c of cs) {
          if (c.unit) fnUnitIds.add(c.unit.id);
        }
        let fnReviewed = 0;
        for (const id of fnUnitIds) {
          const r = compareState.reviewed.get(id);
          if (r && r.reviewed) fnReviewed += 1;
        }
        const fnTotal = fnUnitIds.size;

        const fnGroup = document.createElement("div");
        fnGroup.className = "review_fn_group";

        const fnHeader = document.createElement("div");
        fnHeader.className = "review_fn_header";
        if (fnTotal > 0 && fnReviewed === fnTotal) {
          fnHeader.classList.add("fully_reviewed");
        }
        const fnName = document.createElement("span");
        fnName.className = "fn_name";
        fnName.textContent = fn.name || fn.mangled || ("#" + fn.id);
        fnHeader.appendChild(fnName);

        const fnProgress = document.createElement("span");
        fnProgress.className = "fn_progress";
        fnProgress.textContent = fnReviewed + " of " + fnTotal;
        fnHeader.appendChild(fnProgress);

        if (fnTotal > 0) {
          const fnMarkBtn = document.createElement("button");
          fnMarkBtn.className = "review_group_action";
          fnMarkBtn.type = "button";
          fnMarkBtn.textContent = fnReviewed === fnTotal ? "unmark fn" : "mark fn";
          fnMarkBtn.addEventListener("click", function (ev) {
            ev.stopPropagation();
            const targetState = !(fnTotal > 0 && fnReviewed === fnTotal);
            for (const id of fnUnitIds) {
              const cur = compareState.reviewed.get(id);
              const isReviewed = !!(cur && cur.reviewed);
              if (isReviewed !== targetState) toggleUnitReviewed(id, targetState);
            }
          });
          fnHeader.appendChild(fnMarkBtn);
        }

        fnHeader.addEventListener("click", function () {
          // Click on fn header drills the trace and opens the fn's def
          // line in source pane.
          if (window.traceMode && window.traceMode.pushDrillByName) {
            window.traceMode.pushDrillByName(fn.name);
          }
          showNodePanel({
            id: "n" + fn.id,
            fullName: fn.name,
            label: fn.name,
            mangled: fn.mangled,
            file: fn.def_loc ? fn.def_loc.file : "",
            line: fn.def_loc ? fn.def_loc.line : 0,
            col: fn.def_loc ? fn.def_loc.col : 0,
            isEntry: !!fn.is_entry,
            entryKind: fn.entry_kind || "",
            kind: "fn",
          });
        });
        fnGroup.appendChild(fnHeader);

        for (const c of cs) {
          const row = document.createElement("div");
          row.className = "review_unit_row";
          const unitId = c.unit ? c.unit.id : null;
          const rec = unitId ? compareState.reviewed.get(unitId) : null;
          const isReviewed = !!(rec && rec.reviewed);
          if (isReviewed) row.classList.add("unit_reviewed");

          // Checkbox — only for real units. Synthetic dep-fallback rows
          // (no overlapping unit) get an em-dash placeholder so the row
          // visually aligns but isn't checkable.
          if (unitId) {
            const cb = document.createElement("input");
            cb.type = "checkbox";
            cb.className = "unit_checkbox";
            cb.dataset.unitId = unitId;
            cb.checked = isReviewed;
            cb.addEventListener("click", function (ev) {
              ev.stopPropagation();
              toggleUnitReviewed(unitId, cb.checked);
            });
            row.appendChild(cb);
          } else {
            // Synthetic dep-fallback row (no overlapping unit). Use a
            // distinct class so DOM queries targeting real checkboxes
            // don't accidentally pick this up.
            const placeholder = document.createElement("span");
            placeholder.className = "unit_checkbox_placeholder";
            row.appendChild(placeholder);
          }

          // Glyph: "+" for added, "−" for removed. The relation
          // ("own" vs "dep") drives the *color* — dep-via-def hunks
          // use the purple "dep" tint regardless of whether the
          // underlying unit is an addition or deletion. The synthetic
          // dep-fallback rows have no real unit and use Δ.
          const glyph = document.createElement("span");
          const colorClass = c.relation === "dep" ? "dep"
            : (c.unitKind === "added" ? "added" : "removed");
          glyph.className = "unit_glyph " + colorClass;
          glyph.textContent = c.unit
            ? (c.unitKind === "added" ? "+" : "−")
            : "Δ";
          row.appendChild(glyph);

          // Label: show the line on the side where the change actually
          // exists. For "removed" units, that's old_start in the OLDER
          // commit; for "added", new_start in LIVE. Without this, a
          // removed hunk at OLDER:1055 would label as "1053" (its
          // post-deletion position in the new file), which is the
          // surprising number the user pointed out.
          const label = document.createElement("span");
          label.className = "unit_label";
          const sideTag = c.displaySide === "older" ? "older" : "live";
          if (c.relation === "dep") {
            label.textContent = (c.dep && c.dep.name ? c.dep.name : "<def>") +
              "  " + shortenFile(c.file) + ":" + c.displayLine;
          } else {
            label.textContent = "line " + c.displayLine;
          }
          row.appendChild(label);

          // Side tag — small chip telling the user whether the
          // displayed line lives in the LIVE or OLDER side. Avoids
          // ambiguity when a fn has both added and removed units (the
          // line numbers are otherwise indistinguishable).
          if (c.unit) {
            const sideChip = document.createElement("span");
            sideChip.className = "unit_side_chip side_" + sideTag;
            sideChip.textContent = sideTag;
            row.appendChild(sideChip);
          }
          if (c.relation === "dep") {
            const via = document.createElement("span");
            via.className = "unit_dep_via";
            via.textContent = "[dep]";
            row.appendChild(via);
          }

          const kindStr = c.relation === "dep"
            ? "dep-def hunk via " + (c.dep && c.dep.name ? c.dep.name : "?")
            : (c.unitKind === "added" ? "added hunk" : "removed hunk");
          const tooltipParts = [
            kindStr,
            shortenFile(c.file) + ":" + c.displayLine + " (" + sideTag + ")",
          ];
          if (rec && rec.at) {
            tooltipParts.push("reviewed at " + rec.at);
          }
          row.title = tooltipParts.join(" · ");

          row.addEventListener("click", function () {
            // Show the SAME repo-relative file on both sides; each pane
            // scrolls to where the change exists on its own side
            // (LIVE → liveLine, OLDER → olderLine). For an "added"
            // hunk those are the same line in two timelines; for
            // "removed" they differ — old_start sits in the OLDER pane
            // where the deleted text actually appears, and liveLine
            // (= new_start) is the corresponding position in the
            // post-edit file (so the user lands at the deletion site).
            els.info.classList.add("visible");
            setLastClickedFn(c.fn.name || c.fn.mangled || null);
            fetchSource(c.file, 1, 10000000, c.liveLine || 1, {
              secondaryByFile: c.file,
              secondaryHighlight: c.olderLine || 1,
            });
          });

          fnGroup.appendChild(row);
        }
        fileGroup.appendChild(fnGroup);
      }
      els.diffChangesList.appendChild(fileGroup);
    }
  }


  /** Render the secondary trace pane to mirror the primary's current
   *  root. `rootNameOverride` lets the primary pass its actually-rendered
   *  root (e.g. after a drill push); when omitted we fall back to the
   *  selected entry, which matches the initial state before any drill. */
  function requestSecondaryRender(rootNameOverride) {
    if (compareState.mode === "off") return;
    const sec = secondarySha();
    if (!sec) return;
    if (currentMode !== "trace") return;
    const data = compareState.secGraphs.get(sec);
    if (!data) return;
    if (!els.traceViewB) return;
    let rootName = rootNameOverride || null;
    if (!rootName) {
      if (currentEntryFnId == null) return;
      const primaryFn = fnById.get(currentEntryFnId);
      rootName = primaryFn ? primaryFn.name : null;
    }
    if (!window.traceMode || !window.traceMode.renderSecondary) return;
    window.traceMode.renderSecondary({
      view: els.traceViewB,
      fnById: data.fnById,
      fnByName: data.fnByName,
      rootName: rootName,
      depth: parseInt(els.depthSlider.value, 10) || 4,
      helpers: {
        isLibrary: isLibrary,
        isDebug: isDebug,
        getHideLibrary: function () { return hideLibrary; },
        getHideDebug: function () { return hideDebug; },
        // Secondary fn ids belong to a different build, so we match
        // changes by qualified name instead. Mangled names are also
        // stored so callee atoms with `mangled` resolution still match.
        isChangedFn: function (fn) {
          if (!fn) return false;
          const names = compareState.changedFnNames;
          if (fn.name && names.has(fn.name)) return true;
          if (fn.mangled && names.has(fn.mangled)) return true;
          return false;
        },
        hasChangedDescendant: function (fn) {
          if (!fn) return false;
          const names = compareState.subtreeChangedFnNames;
          if (fn.name && names.has(fn.name)) return true;
          if (fn.mangled && names.has(fn.mangled)) return true;
          return false;
        },
      },
    });
  }

  function startStatusPoll() {
    if (compareState.pollTimer) return;
    compareState.pollTimer = setInterval(async function () {
      const need = shasNeedingLoad();
      let allDone = true;
      for (const sha of need) {
        const cur = compareState.statuses[sha];
        if (!cur || cur.status === "building") {
          await refreshStatus(sha);
          const after = compareState.statuses[sha];
          if (!after || after.status === "building") allDone = false;
        }
      }
      recomputeCompareStatus();
      if (allDone) {
        clearInterval(compareState.pollTimer);
        compareState.pollTimer = null;
      }
    }, 1500);
  }

  async function activateCompare() {
    const need = shasNeedingLoad();
    if (need.length === 0) {
      recomputeCompareStatus();
      return;
    }
    setCompareStatus("starting builds…", "building");
    // Kick off loads (server is single-flight per sha).
    for (const sha of need) {
      const cur = compareState.statuses[sha];
      if (cur && cur.status === "ready") continue;
      await triggerLoad(sha);
    }
    recomputeCompareStatus();
    startStatusPoll();
  }

  function onCompareModeChange() {
    const v = els.compareMode.value;
    compareState.mode = v;
    if (v === "off") {
      els.compareCommit.style.display = "none";
      // recomputeCompareStatus also clears the entry flags + repopulates
      // the dropdown without markers.
      recomputeCompareStatus();
      return;
    }
    els.compareCommit.style.display = "";
    if (compareState.commits.length === 0) {
      fetchCommitsList().then(populateCommitDropdown).then(recomputeCompareStatus);
    } else {
      populateCommitDropdown();
    }
    recomputeCompareStatus();
    if (compareState.selectedSha) activateCompare();
  }

  function onCompareCommitChange() {
    compareState.selectedSha = els.compareCommit.value || "";
    if (compareState.mode !== "off" && compareState.selectedSha) {
      activateCompare();
    } else {
      recomputeCompareStatus();
    }
  }

  // Probe-only debug hook: inject a "loaded" secondary commit by sha, mode,
  // and a graph blob (typically the live one for end-to-end testing without
  // running a real build). Inert in production — only the perf/probe
  // harnesses call it. Lives on `window` because compareState is closure-
  // private and the harness can't reach into it otherwise.
  window.__cgInjectSecondary = function (opts) {
    if (!opts || !opts.sha || !opts.graph) return false;
    const ix = new Map();
    for (const fn of opts.graph.functions || []) ix.set(fn.id, fn);
    const byName = window.traceMode ? window.traceMode.buildFnByName(ix) : new Map();
    compareState.secGraphs.set(opts.sha, { graph: opts.graph, fnById: ix, fnByName: byName });
    compareState.statuses[opts.sha] = {
      sha: opts.sha,
      short: opts.sha.slice(0, 7),
      status: "ready",
      arches: [currentArch],
      default_arch: currentArch,
      error: null,
    };
    if (opts.mode) compareState.mode = opts.mode;
    compareState.selectedSha = opts.sha;
    if (els.compareMode && opts.mode) els.compareMode.value = opts.mode;
    recomputeCompareStatus();
    return true;
  };

  function wireCompareEvents() {
    if (!els.compareMode || !els.compareCommit) return;
    els.compareMode.addEventListener("change", onCompareModeChange);
    els.compareCommit.addEventListener("change", onCompareCommitChange);
    // Mirror primary trace renders into the secondary pane. Fires after
    // every entry change, drill push/pop, and depth change.
    if (window.traceMode && window.traceMode.setOnRendered) {
      window.traceMode.setOnRendered(function (info) {
        requestSecondaryRender(info && info.rootName);
      });
    }

    // Secondary-pane drill gestures: dblclick to drill in, right-click
    // dblclick to pop. Both gestures resolve a target fn in the
    // SECONDARY graph (the data-fnid lives there), then drive the
    // primary by qualified name. The primary's render callback will
    // mirror the new root back to the secondary, so both panes stay
    // in lockstep without the secondary needing its own drill state.
    if (els.traceViewB) {
      let lastRightClickB = 0;
      const RIGHT_DBLCLICK_MS = 400;

      els.traceViewB.addEventListener("contextmenu", function (e) {
        e.preventDefault();
        const now = Date.now();
        if (now - lastRightClickB < RIGHT_DBLCLICK_MS) {
          lastRightClickB = 0;
          if (window.traceMode && window.traceMode.popDrill) {
            window.traceMode.popDrill();
          }
        } else {
          lastRightClickB = now;
        }
      });

      els.traceViewB.addEventListener("dblclick", function (e) {
        const box = e.target.closest && e.target.closest(".trace_box[data-fnid]");
        if (!box) return;
        const sec = secondarySha();
        if (!sec) return;
        const data = compareState.secGraphs.get(sec);
        if (!data) return;
        const secId = parseInt(box.getAttribute("data-fnid"), 10);
        if (Number.isNaN(secId)) return;
        const secFn = data.fnById.get(secId);
        if (!secFn || !secFn.name) return;
        // Don't drill if the matching primary fn isn't found — the
        // primary couldn't render its body anyway. Flash the secondary
        // box briefly so the user knows the gesture registered but the
        // target was absent. (Cheap CSS class; same UX as the primary's
        // breadcrumb-flash on overflowing pop.)
        e.preventDefault();
        e.stopPropagation();
        const drilled = window.traceMode &&
          window.traceMode.pushDrillByName &&
          window.traceMode.pushDrillByName(secFn.name);
        if (!drilled) {
          box.classList.add("flash");
          setTimeout(function () { box.classList.remove("flash"); }, 250);
        }
      });
    }
    // Pre-fetch the commit list so the dropdown is instant when the user
    // flips compare on. Cheap (~50 commits over localhost).
    fetchCommitsList().then(function () {
      if (compareState.mode !== "off") populateCommitDropdown();
    });
  }

  // ------------------------------------------------------------------ demo data

  function demoGraph() {
    return {
      entry_points: [
        { fn_id: 1, label: "syscall_open", kind: "syscall" },
        { fn_id: 2, label: "syscall_send", kind: "syscall" },
        { fn_id: 50, label: "page_fault", kind: "trap" },
        { fn_id: 60, label: "timer_irq", kind: "irq" },
        { fn_id: 70, label: "kernel_main", kind: "boot" },
      ],
      functions: [
        {
          id: 1,
          name: "syscall.dispatch.open",
          mangled: "syscall.dispatch.open",
          def_loc: { file: "/kernel/syscall/dispatch.zig", line: 120, col: 0 },
          is_entry: true,
          entry_kind: "syscall",
          callees: [
            { to: 10, target_name: "vmm.alloc", kind: "direct",
              site: { file: "/kernel/syscall/dispatch.zig", line: 130, col: 12 } },
            { to: 11, target_name: "perms.check", kind: "direct",
              site: { file: "/kernel/syscall/dispatch.zig", line: 132, col: 8 } },
            { to: 20, target_name: "arch.dispatch.flushTLB", kind: "dispatch_x64",
              site: { file: "/kernel/syscall/dispatch.zig", line: 138, col: 8 } },
            { to: null, target_name: null, kind: "indirect",
              site: { file: "/kernel/syscall/dispatch.zig", line: 145, col: 4 } },
            { to: null, target_name: null, kind: "leaf_userspace",
              site: { file: "/kernel/syscall/dispatch.zig", line: 150, col: 4 } },
          ],
        },
        {
          id: 2,
          name: "syscall.dispatch.send",
          mangled: "syscall.dispatch.send",
          def_loc: { file: "/kernel/syscall/dispatch.zig", line: 200, col: 0 },
          is_entry: true,
          entry_kind: "syscall",
          callees: [
            { to: 11, target_name: "perms.check", kind: "direct",
              site: { file: "/kernel/syscall/dispatch.zig", line: 210, col: 8 } },
            { to: 30, target_name: "msgbox.push", kind: "direct",
              site: { file: "/kernel/syscall/dispatch.zig", line: 215, col: 8 } },
          ],
        },
        {
          id: 10,
          name: "memory.vmm.alloc",
          mangled: "memory.vmm.alloc",
          def_loc: { file: "/kernel/memory/vmm.zig", line: 50, col: 0 },
          is_entry: false,
          callees: [
            { to: 12, target_name: "pmm.allocPage", kind: "direct",
              site: { file: "/kernel/memory/vmm.zig", line: 60, col: 12 } },
            { to: 13, target_name: "paging.map", kind: "dispatch_x64",
              site: { file: "/kernel/memory/vmm.zig", line: 65, col: 12 } },
            { to: 13, target_name: "paging.map", kind: "dispatch_aarch64",
              site: { file: "/kernel/memory/vmm.zig", line: 65, col: 12 } },
          ],
        },
        {
          id: 11,
          name: "perms.check",
          mangled: "perms.check",
          def_loc: { file: "/kernel/perms/check.zig", line: 22, col: 0 },
          is_entry: false,
          callees: [
            { to: 14, target_name: "perms.lookup", kind: "direct",
              site: { file: "/kernel/perms/check.zig", line: 28, col: 8 } },
          ],
        },
        {
          id: 12,
          name: "memory.pmm.allocPage",
          mangled: "memory.pmm.allocPage",
          def_loc: { file: "/kernel/memory/pmm.zig", line: 100, col: 0 },
          is_entry: false,
          callees: [],
        },
        {
          id: 13,
          name: "arch.x64.paging.map",
          mangled: "arch.x64.paging.map",
          def_loc: { file: "/kernel/arch/x64/paging.zig", line: 200, col: 0 },
          is_entry: false,
          callees: [
            { to: 15, target_name: "arch.x64.paging.invlpg", kind: "direct",
              site: { file: "/kernel/arch/x64/paging.zig", line: 220, col: 8 } },
          ],
        },
        {
          id: 14,
          name: "perms.lookup",
          mangled: "perms.lookup",
          def_loc: { file: "/kernel/perms/lookup.zig", line: 10, col: 0 },
          is_entry: false,
          callees: [
            { to: null, target_name: "fn ptr (rights table)", kind: "vtable",
              site: { file: "/kernel/perms/lookup.zig", line: 18, col: 4 } },
          ],
        },
        {
          id: 15,
          name: "arch.x64.paging.invlpg",
          mangled: "arch.x64.paging.invlpg",
          def_loc: { file: "/kernel/arch/x64/paging.zig", line: 280, col: 0 },
          is_entry: false,
          callees: [],
        },
        {
          id: 20,
          name: "arch.dispatch.flushTLB",
          mangled: "arch.dispatch.flushTLB",
          def_loc: { file: "/kernel/arch/dispatch.zig", line: 88, col: 0 },
          is_entry: false,
          callees: [
            { to: 21, target_name: "arch.x64.paging.flushTLB", kind: "dispatch_x64",
              site: { file: "/kernel/arch/dispatch.zig", line: 92, col: 8 } },
            { to: 22, target_name: "arch.aarch64.paging.flushTLB", kind: "dispatch_aarch64",
              site: { file: "/kernel/arch/dispatch.zig", line: 94, col: 8 } },
          ],
        },
        {
          id: 21,
          name: "arch.x64.paging.flushTLB",
          mangled: "arch.x64.paging.flushTLB",
          def_loc: { file: "/kernel/arch/x64/paging.zig", line: 310, col: 0 },
          is_entry: false,
          callees: [],
        },
        {
          id: 22,
          name: "arch.aarch64.paging.flushTLB",
          mangled: "arch.aarch64.paging.flushTLB",
          def_loc: { file: "/kernel/arch/aarch64/paging.zig", line: 310, col: 0 },
          is_entry: false,
          callees: [],
        },
        {
          id: 30,
          name: "proc.message_box.push",
          mangled: "proc.message_box.push",
          def_loc: { file: "/kernel/proc/message_box.zig", line: 75, col: 0 },
          is_entry: false,
          callees: [
            { to: 31, target_name: "sched.notification.signal", kind: "direct",
              site: { file: "/kernel/proc/message_box.zig", line: 90, col: 8 } },
          ],
        },
        {
          id: 31,
          name: "sched.notification.signal",
          mangled: "sched.notification.signal",
          def_loc: { file: "/kernel/sched/notification.zig", line: 40, col: 0 },
          is_entry: false,
          callees: [
            { to: 32, target_name: "sched.scheduler.wake", kind: "direct",
              site: { file: "/kernel/sched/notification.zig", line: 55, col: 8 } },
          ],
        },
        {
          id: 32,
          name: "sched.scheduler.wake",
          mangled: "sched.scheduler.wake",
          def_loc: { file: "/kernel/sched/scheduler.zig", line: 220, col: 0 },
          is_entry: false,
          callees: [],
        },
        {
          id: 50,
          name: "memory.fault.handle",
          mangled: "memory.fault.handle",
          def_loc: { file: "/kernel/memory/fault.zig", line: 30, col: 0 },
          is_entry: true,
          entry_kind: "trap",
          callees: [
            { to: 10, target_name: "vmm.alloc", kind: "direct",
              site: { file: "/kernel/memory/fault.zig", line: 60, col: 8 } },
          ],
        },
        {
          id: 60,
          name: "arch.x64.timers.tick",
          mangled: "arch.x64.timers.tick",
          def_loc: { file: "/kernel/arch/x64/timers.zig", line: 88, col: 0 },
          is_entry: true,
          entry_kind: "irq",
          callees: [
            { to: 32, target_name: "scheduler.wake", kind: "direct",
              site: { file: "/kernel/arch/x64/timers.zig", line: 102, col: 8 } },
          ],
        },
        {
          id: 70,
          name: "kernel.main",
          mangled: "kernel.main",
          def_loc: { file: "/kernel/main.zig", line: 1, col: 0 },
          is_entry: true,
          entry_kind: "boot",
          callees: [
            { to: 71, target_name: "memory.pmm.init", kind: "direct",
              site: { file: "/kernel/main.zig", line: 30, col: 4 } },
            { to: 72, target_name: "memory.vmm.init", kind: "direct",
              site: { file: "/kernel/main.zig", line: 32, col: 4 } },
            { to: 73, target_name: "sched.scheduler.init", kind: "direct",
              site: { file: "/kernel/main.zig", line: 34, col: 4 } },
          ],
        },
        { id: 71, name: "memory.pmm.init", mangled: "memory.pmm.init",
          def_loc: { file: "/kernel/memory/pmm.zig", line: 10, col: 0 },
          is_entry: false, callees: [] },
        { id: 72, name: "memory.vmm.init", mangled: "memory.vmm.init",
          def_loc: { file: "/kernel/memory/vmm.zig", line: 10, col: 0 },
          is_entry: false, callees: [] },
        { id: 73, name: "sched.scheduler.init", mangled: "sched.scheduler.init",
          def_loc: { file: "/kernel/sched/scheduler.zig", line: 10, col: 0 },
          is_entry: false, callees: [] },
      ],
    };
  }

  // ------------------------------------------------------------------ boot

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn);
    } else {
      fn();
    }
  }

  ready(function () {
    if (typeof cytoscape === "undefined") {
      setStatus("cytoscape.min.js failed to load", true);
      console.error("cytoscape global missing — script load failed");
      return;
    }
    wireEvents();
    wireCompareEvents();
    loadGraph();
  });
})();
