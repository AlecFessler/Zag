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

  // ------------------------------------------------------------------ DOM

  const els = {
    archPicker: document.getElementById("arch_picker"),
    entrySelect: document.getElementById("entry_select"),
    depthSlider: document.getElementById("depth_slider"),
    depthValue: document.getElementById("depth_value"),
    indirectToggle: document.getElementById("include_indirect"),
    hideLibraryToggle: document.getElementById("hide_library"),
    fitBtn: document.getElementById("fit_btn"),
    indirectPanelBtn: document.getElementById("indirect_panel_btn"),
    deadPanelBtn: document.getElementById("dead_panel_btn"),
    graph: document.getElementById("graph"),
    info: document.getElementById("info"),
    infoTitle: document.getElementById("info_title"),
    infoMeta: document.getElementById("info_meta"),
    infoSourceWrap: document.getElementById("info_source_wrap"),
    infoSource: document.getElementById("info_source"),
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
    traceBreadcrumb: document.getElementById("trace_breadcrumb"),
    graphPane: document.getElementById("graph"),
  };

  /** ID of the currently-selected entry-point function. */
  let currentEntryFnId = null;

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
    setStatus("loading /api/graph (arch=" + archTag + ")...", true);
    let prevEntryName = null;
    if (preserveEntry && currentEntryFnId != null) {
      const prevFn = fnById.get(currentEntryFnId);
      if (prevFn) prevEntryName = prevFn.name;
    }

    try {
      const r = await fetch("/api/graph?arch=" + encodeURIComponent(archTag));
      if (!r.ok) throw new Error("HTTP " + r.status);
      graph = await r.json();
      setStatus("graph loaded (" + archTag + ")", false);
    } catch (err) {
      console.error("graph fetch failed", err);
      setStatus("graph fetch failed: " + err.message, true);
      return;
    }

    indexCurrentGraph();

    populateDropdown(graph.entry_points || []);

    // Try to preserve the prior entry by name.
    let nextEntryId = null;
    if (prevEntryName) {
      for (const e of graph.entry_points || []) {
        const fn = fnById.get(e.fn_id);
        if (fn && fn.name === prevEntryName) {
          if (!isFiltered(fn)) {
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

    if (nextEntryId != null) {
      els.entrySelect.value = String(nextEntryId);
      renderForEntry(nextEntryId);
    } else {
      currentEntryFnId = null;
    }
  }

  /** Rebuild fnById from the current `graph` and re-wire trace.js. */
  function indexCurrentGraph() {
    fnById.clear();
    for (const fn of graph.functions || []) fnById.set(fn.id, fn);
    if (window.traceMode) {
      window.traceMode.setContext({
        fnById: fnById,
        isLibrary: isLibrary,
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

  /** First entry point that survives the library filter, or null. Used both
   *  on initial load and when the user toggles the filter and we need to
   *  pick a sensible default. */
  function firstVisibleEntryId(entries) {
    for (const e of entries) {
      if (!hideLibrary || !isFiltered(fnById.get(e.fn_id))) return e.fn_id;
    }
    return null;
  }

  function populateDropdown(entries) {
    els.entrySelect.innerHTML = "";

    // Drop library entry points when the filter is on. Entry discovery is
    // tuned for kernel patterns so this should be empty in practice, but it
    // keeps the dropdown honest if the heuristics ever pick something up.
    const visibleEntries = entries.filter(function (e) {
      return !hideLibrary || !isFiltered(fnById.get(e.fn_id));
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

    for (const kind of sorted) {
      const og = document.createElement("optgroup");
      og.label = kind + " (" + groups.get(kind).length + ")";
      const items = groups.get(kind).slice().sort(function (a, b) {
        return (a.label || "").localeCompare(b.label || "");
      });
      for (const e of items) {
        const opt = document.createElement("option");
        opt.value = String(e.fn_id);
        opt.textContent = "[" + kind + "] " + (e.label || "(anon)");
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

    // If the entry itself is library and the filter is on, render nothing.
    // (In practice entry discovery shouldn't pick up library fns; this is a
    // safety net so we never silently emit only synthetic nodes.)
    if (isFiltered(fnById.get(entryFnId))) {
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
          // Resolved direct/dispatch/vtable target. If the target is library
          // infrastructure and the filter is on, drop both the edge and any
          // expansion past it: the caller node simply has fewer outgoing
          // edges. The user wanted their kernel code, not what Zig wires in.
          const targetFn = fnById.get(c.to);
          if (isFiltered(targetFn)) {
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
    currentEntryFnId = entryFnId;
    // Trace mode owns its own rendering pipeline; only let the graph
    // builder run when the graph pane is the visible view.
    if (currentMode === "trace") {
      if (window.traceMode) window.traceMode.onEntryChange(entryFnId);
      return;
    }
    const depth = parseInt(els.depthSlider.value, 10) || 4;
    const includeIndirect = els.indirectToggle.checked;

    const elements = buildElements(entryFnId, depth, includeIndirect);

    if (cy) {
      cy.destroy();
      cy = null;
    }

    cy = cytoscape({
      container: els.graph,
      elements: elements,
      style: cyStyle(),
      layout: {
        name: "breadthfirst",
        directed: true,
        roots: ["n" + entryFnId],
        padding: 30,
        spacingFactor: 1.1,
        animate: false,
      },
      wheelSensitivity: 0.6,
      minZoom: 0.05,
      maxZoom: 5.0,
    });

    cy.on("tap", "node", function (evt) {
      showNodePanel(evt.target.data());
    });
    cy.on("tap", "edge", function (evt) {
      showEdgePanel(evt.target.data());
    });
    cy.on("tap", function (evt) {
      // Background tap closes the panel.
      if (evt.target === cy) hidePanel();
    });

    // Initial fit-to-view: after the layout completes, fit the graph then
    // clamp zoom up to a level where node labels stay readable. For wide
    // entry points like kEntry, plain cy.fit() leaves you at ~0.1 zoom
    // where you only see the silhouette.
    fitWithMinZoom();
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

  function renderSourceSnippet(file, startLine, lines, highlightLine) {
    // Build header with selectable absolute path.
    const block = els.infoSource;
    block.innerHTML = "";

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

    for (let i = 0; i < lines.length; i += 1) {
      const absLine = startLine + i;
      const tr = document.createElement("tr");
      tr.className = "source_line";
      if (absLine === highlightLine) tr.classList.add("highlight");

      const tdNum = document.createElement("td");
      tdNum.className = "source_gutter";
      tdNum.textContent = String(absLine);

      const tdCode = document.createElement("td");
      tdCode.className = "source_code";
      // Render the line as plain text. Use a single trailing space when the
      // line is empty so the row keeps the right height.
      tdCode.textContent = lines[i].length === 0 ? " " : lines[i];

      tr.appendChild(tdNum);
      tr.appendChild(tdCode);
      tbody.appendChild(tr);
    }

    table.appendChild(tbody);
    pre.appendChild(table);
    block.appendChild(pre);

    els.infoSourceWrap.style.display = "block";
    els.infoSourceError.style.display = "none";
  }

  async function fetchSource(file, start, end, highlightLine) {
    if (!file) {
      showSourceError("no file path on selection");
      return;
    }
    if (start < 1) start = 1;
    if (end < start) end = start;

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
      const text = await r.text();
      if (myToken !== sourceFetchToken) return;

      // Server returns lines [start..end] separated by newlines. Trim a
      // trailing newline so we don't render an extra blank row.
      let body = text;
      if (body.endsWith("\n")) body = body.slice(0, -1);
      const lines = body.length === 0 ? [""] : body.split("\n");

      renderSourceSnippet(file, start, lines, highlightLine);
    } catch (err) {
      if (myToken !== sourceFetchToken) return;
      showSourceError(err && err.message ? err.message : String(err));
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
        const start = Math.max(1, (c.site.line || 1) - 5);
        const end = (c.site.line || 1) + 5;
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

      // 15-line window starting at the def line so the user sees the
      // signature plus a few lines of body.
      if (d.file && d.line) {
        const start = Math.max(1, d.line);
        const end = start + 14;
        fetchSource(d.file, start, end, d.line);
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
    const visited = new Set();
    const queue = [{ id: entryFnId, depth: 0 }];
    while (queue.length > 0) {
      const cur = queue.shift();
      if (visited.has(cur.id)) continue;
      visited.add(cur.id);
      const fn = fnById.get(cur.id);
      if (!fn) continue;
      // Skip indirect rows where the *caller* is library; vector tables in
      // stdlib formatters etc. aren't interesting for kernel work.
      const callerFiltered = isFiltered(fn);
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
          // Don't descend into library callees — keeps the BFS frontier
          // anchored to the user's kernel code.
          if (isFiltered(fnById.get(c.to))) continue;
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
        // Repopulate the dropdown — entries themselves can be filtered.
        // Preserve the current selection if it survives the filter; else
        // fall back to the first visible entry.
        populateDropdown(graph ? (graph.entry_points || []) : []);
        let target = currentEntryFnId;
        if (target != null) {
          const fn = fnById.get(target);
          if (hideLibrary && isFiltered(fn)) target = null;
        }
        if (target == null && graph) {
          target = firstVisibleEntryId(graph.entry_points || []);
        }
        if (target != null) {
          els.entrySelect.value = String(target);
          renderForEntry(target);
        }
        refreshOpenListPanel();
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
      if (els.graphPane) els.graphPane.style.display = "none";
      if (window.traceMode) {
        window.traceMode.show();
        if (currentEntryFnId != null) window.traceMode.onEntryChange(currentEntryFnId);
      }
    } else {
      if (window.traceMode) window.traceMode.hide();
      if (els.graphPane) els.graphPane.style.display = "";
      // Re-render graph if we have an entry but no live cy (e.g. coming
      // back from Trace mode).
      if (currentEntryFnId != null && !cy) {
        renderForEntry(currentEntryFnId);
      }
    }
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
    loadGraph();
  });
})();
