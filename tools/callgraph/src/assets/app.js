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

  /** Whole /api/graph payload, stashed for lookups during BFS. */
  let graph = null;
  /** id -> function object index for O(1) lookup. */
  const fnById = new Map();
  /** Current Cytoscape instance. Recreated on each entry-point switch. */
  let cy = null;

  // ------------------------------------------------------------------ DOM

  const els = {
    entrySelect: document.getElementById("entry_select"),
    depthSlider: document.getElementById("depth_slider"),
    depthValue: document.getElementById("depth_value"),
    indirectToggle: document.getElementById("include_indirect"),
    fitBtn: document.getElementById("fit_btn"),
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
  };

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

  async function loadGraph() {
    const params = new URLSearchParams(window.location.search);
    if (params.get("demo") === "1") {
      graph = demoGraph();
      setStatus("demo graph loaded", false);
    } else {
      setStatus("loading /api/graph...", true);
      try {
        const r = await fetch("/api/graph");
        if (!r.ok) throw new Error("HTTP " + r.status);
        graph = await r.json();
        setStatus("graph loaded", false);
      } catch (err) {
        console.error("graph fetch failed", err);
        setStatus("graph fetch failed: " + err.message, true);
        return;
      }
    }

    fnById.clear();
    for (const fn of graph.functions || []) fnById.set(fn.id, fn);

    populateDropdown(graph.entry_points || []);
    if ((graph.entry_points || []).length > 0) {
      els.entrySelect.value = String(graph.entry_points[0].fn_id);
      renderForEntry(graph.entry_points[0].fn_id);
    }
  }

  function populateDropdown(entries) {
    els.entrySelect.innerHTML = "";

    if (entries.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "(no entry points)";
      els.entrySelect.appendChild(opt);
      return;
    }

    // Group by entry kind so the dropdown is navigable.
    const groups = new Map();
    for (const e of entries) {
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
      wheelSensitivity: 0.2,
      minZoom: 0.1,
      maxZoom: 4,
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

  // ------------------------------------------------------------------ events

  function wireEvents() {
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

    els.fitBtn.addEventListener("click", function () {
      if (cy) cy.fit(null, 30);
    });

    els.infoClose.addEventListener("click", hidePanel);
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
