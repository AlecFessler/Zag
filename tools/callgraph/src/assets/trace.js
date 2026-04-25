/* Zag callgraph explorer — Trace mode.
 *
 * Renders the same /api/graph data as Graph mode but as recursively-nested
 * boxes (Nassi-Shneiderman style, extended across function-call boundaries).
 *
 * Public interface (called from app.js):
 *   - traceMode.render(rootFnId)         — rebuild #trace_view from scratch
 *   - traceMode.show()                   — make trace UI visible, hide graph
 *   - traceMode.hide()                   — restore graph view
 *   - traceMode.onEntryChange(rootFnId)  — entry dropdown changed; clear stack
 *   - traceMode.setContext(ctx)          — wire shared helpers (fnById,
 *                                          isLibrary, showNodePanel)
 *
 * Drill stack:
 *   - Double-left-click on any nested box → push current root, re-root to
 *     clicked box's fn id.
 *   - Double-right-click anywhere in the trace view → pop stack.
 *   - Breadcrumb above the view shows the stack; click any crumb to jump.
 *   - Per-entry stack persisted in `entryStacks[entryId]` so toggling Graph
 *     ↔ Trace doesn't lose state for that entry.
 */

(function () {
  "use strict";

  // ------------------------------------------------------------------ shared context
  // app.js calls setContext at startup with these helpers; we keep them as
  // module-locals to avoid coupling the trace renderer to app.js's globals.
  let ctx = {
    fnById: null,           // Map<fnId, fn>
    isLibrary: function () { return false; },
    isDebug: function () { return false; },
    getHideLibrary: function () { return true; },
    getHideDebug: function () { return true; },
    showNodePanel: null,    // open the right-hand info panel for a fn
  };

  /** name-or-mangled -> Function record index, rebuilt every time
   *  setContext fires with a fresh fnById. Used for the name-fallback
   *  lookup when a call atom has `to: null` but the resolver gave it a
   *  qualified name (typical for fully-inlined helpers like
   *  `arch.dispatch.cpu.kEntry`). */
  let fnByName = new Map();

  function rebuildFnByName(fnById) {
    fnByName = new Map();
    if (!fnById) return;
    fnById.forEach(function (fn) {
      if (!fn) return;
      if (fn.name) fnByName.set(fn.name, fn);
      if (fn.mangled && !fnByName.has(fn.mangled)) fnByName.set(fn.mangled, fn);
    });
  }

  // ------------------------------------------------------------------ state

  /** entryFnId currently driving the trace view (top of breadcrumb). */
  let originEntryId = null;
  /** Drill stack for the *current* origin entry. Top of stack is current root. */
  let drillStack = [];
  /** Per-entry remembered drill stack so Graph<->Trace flips preserve state. */
  const entryStacks = new Map();

  /** Right-click double-click bookkeeping for popping the drill stack. */
  let lastRightClick = 0;
  const RIGHT_DBLCLICK_MS = 400;

  // ------------------------------------------------------------------ DOM

  const els = {
    view: null,           // #trace_view (scrollable container)
    breadcrumb: null,     // #trace_breadcrumb
  };

  function ensureDom() {
    if (els.view) return;
    els.view = document.getElementById("trace_view");
    els.breadcrumb = document.getElementById("trace_breadcrumb");
    if (!els.view) return;

    // Right-click anywhere in the trace view: count as a "back" gesture if
    // the previous right-click was within RIGHT_DBLCLICK_MS. Always suppress
    // the browser context menu in the trace area.
    els.view.addEventListener("contextmenu", function (e) {
      e.preventDefault();
      const now = Date.now();
      if (now - lastRightClick < RIGHT_DBLCLICK_MS) {
        lastRightClick = 0;
        popDrill();
      } else {
        lastRightClick = now;
      }
    });

    // Double-left-click on a box → drill in. Use event delegation; the
    // closest `.trace_box[data-fnid]` to the event target wins.
    els.view.addEventListener("dblclick", function (e) {
      const box = e.target.closest && e.target.closest(".trace_box[data-fnid]");
      if (!box) return;
      const fnId = parseInt(box.getAttribute("data-fnid"), 10);
      if (Number.isNaN(fnId)) return;
      // Don't drill into the current root (it's the outermost box).
      if (drillStack.length > 0 && drillStack[drillStack.length - 1] === fnId) return;
      e.preventDefault();
      e.stopPropagation();
      pushDrill(fnId);
    });
  }

  // ------------------------------------------------------------------ helpers

  function fmtLoc(loc) {
    if (!loc || !loc.file) return "";
    const file = loc.file;
    const line = loc.line != null ? loc.line : 0;
    return shortenFile(file) + ":" + line;
  }

  function fullLoc(loc) {
    if (!loc || !loc.file) return "";
    const line = loc.line != null ? loc.line : 0;
    return loc.file + ":" + line;
  }

  /** Strip the kernel-root prefix from a path so it displays as
   *  `proc/process.zig:705` rather than `/home/alec/Zag/kernel/proc/...`.
   *
   *  Heuristic: find the LAST `/kernel/` substring and strip everything up
   *  to and including it. Works for absolute paths originating in the Zag
   *  worktree as well as relative paths that already start with `kernel/`.
   *  Limitation: a source path with `/kernel/` baked in further down (e.g.
   *  some forwarded shim file) would be over-stripped, but in practice the
   *  callgraph IR never produces such paths.
   *
   *  Falls back to `/usr/lib/zig/` stripping for stdlib paths, then to the
   *  raw input. */
  function shortenFile(file) {
    if (!file) return "";
    const k = file.lastIndexOf("/kernel/");
    if (k >= 0) return file.slice(k + 1);
    if (file.startsWith("kernel/")) return file.slice("kernel/".length);
    const z = file.indexOf("/usr/lib/zig/");
    if (z >= 0) return file.slice(z + 1);
    return file;
  }

  function shortName(name) {
    if (!name) return "(anon)";
    const parts = name.split(".");
    if (parts.length <= 2) return name;
    return parts.slice(-2).join(".");
  }

  // ------------------------------------------------------------------ public api

  function setContext(c) {
    if (c.fnById) {
      ctx.fnById = c.fnById;
      rebuildFnByName(c.fnById);
    }
    if (c.isLibrary) ctx.isLibrary = c.isLibrary;
    if (c.isDebug) ctx.isDebug = c.isDebug;
    if (c.getHideLibrary) ctx.getHideLibrary = c.getHideLibrary;
    if (c.getHideDebug) ctx.getHideDebug = c.getHideDebug;
    if (c.showNodePanel) ctx.showNodePanel = c.showNodePanel;
  }

  /** Called by app.js when the entry dropdown changes. Clears the drill
   *  stack for the new entry (or restores a remembered one). */
  function onEntryChange(rootFnId) {
    originEntryId = rootFnId;
    if (entryStacks.has(rootFnId)) {
      drillStack = entryStacks.get(rootFnId).slice();
    } else {
      drillStack = [rootFnId];
      entryStacks.set(rootFnId, drillStack.slice());
    }
    render();
  }

  function show() {
    ensureDom();
    if (els.view) els.view.style.display = "";
    if (els.breadcrumb) els.breadcrumb.style.display = "";
  }

  function hide() {
    ensureDom();
    if (els.view) els.view.style.display = "none";
    if (els.breadcrumb) els.breadcrumb.style.display = "none";
  }

  // ------------------------------------------------------------------ drill stack

  function pushDrill(fnId) {
    drillStack.push(fnId);
    if (originEntryId != null) entryStacks.set(originEntryId, drillStack.slice());
    render();
  }

  function popDrill() {
    if (drillStack.length <= 1) {
      // Flash the breadcrumb so the user knows the gesture registered.
      if (els.breadcrumb) {
        els.breadcrumb.classList.add("flash");
        setTimeout(function () {
          if (els.breadcrumb) els.breadcrumb.classList.remove("flash");
        }, 250);
      }
      return;
    }
    drillStack.pop();
    if (originEntryId != null) entryStacks.set(originEntryId, drillStack.slice());
    render();
  }

  function jumpTo(level) {
    // Pop until drillStack.length === level + 1.
    if (level < 0 || level >= drillStack.length) return;
    drillStack = drillStack.slice(0, level + 1);
    if (originEntryId != null) entryStacks.set(originEntryId, drillStack.slice());
    render();
  }

  // ------------------------------------------------------------------ render

  function render(rootFnIdOverride) {
    ensureDom();
    if (!els.view || !ctx.fnById) return;

    if (rootFnIdOverride != null) {
      // External re-render (re-show, no drill change).
      // (Currently unused — onEntryChange/pushDrill already drive render().)
    }

    const rootId = drillStack.length > 0
      ? drillStack[drillStack.length - 1]
      : originEntryId;

    renderBreadcrumb();

    els.view.innerHTML = "";
    if (rootId == null) {
      const empty = document.createElement("div");
      empty.className = "trace_empty";
      empty.textContent = "(no entry selected)";
      els.view.appendChild(empty);
      return;
    }

    const fn = ctx.fnById.get(rootId);
    if (!fn) {
      const empty = document.createElement("div");
      empty.className = "trace_empty";
      empty.textContent = "(function not in graph)";
      els.view.appendChild(empty);
      return;
    }

    // Build the entire tree as an in-memory subtree first, then attach in
    // one shot. Avoids per-node reflow on big trees (kEntry can produce
    // many thousands of nested boxes).
    //
    // Recursion guard: visited keys are node-identity strings (`id:N` for
    // fns we expanded by id, `name:foo` for fns we expanded by name
    // fallback). The string-keyed approach keeps name-resolved-but-id-null
    // call atoms protected from infinite recursion the same way id-based
    // expansion is.
    const rootKey = nodeKeyFor(fn);
    const visited = new Set([rootKey]);
    const tree = buildFnBox(fn, visited);
    visited.delete(rootKey);

    els.view.appendChild(tree);
  }

  /** Build the recursion-guard key for a Function record. Prefer `id` when
   *  the IR knows the function; fall back to qualified name (so
   *  name-resolved fns with `id == null` still get protected). */
  function nodeKeyFor(fn) {
    if (!fn) return "name:?";
    if (fn.id != null) return "id:" + fn.id;
    if (fn.name) return "name:" + fn.name;
    return "name:?";
  }

  function renderBreadcrumb() {
    if (!els.breadcrumb) return;
    els.breadcrumb.innerHTML = "";
    if (drillStack.length === 0) return;

    for (let i = 0; i < drillStack.length; i += 1) {
      const id = drillStack[i];
      const fn = ctx.fnById ? ctx.fnById.get(id) : null;
      const crumb = document.createElement("span");
      crumb.className = "crumb";
      if (i === drillStack.length - 1) crumb.classList.add("current");
      crumb.textContent = fn ? shortName(fn.name) : ("#" + id);
      crumb.title = fn ? fn.name : ("fn id " + id);
      const idx = i;
      crumb.addEventListener("click", function () { jumpTo(idx); });
      els.breadcrumb.appendChild(crumb);
      if (i < drillStack.length - 1) {
        const sep = document.createElement("span");
        sep.className = "crumb_sep";
        sep.textContent = " ▸ ";
        els.breadcrumb.appendChild(sep);
      }
    }
  }

  // ------------------------------------------------------------------ tree builders

  /** Build the outermost-or-inner box for a fully-known function. */
  function buildFnBox(fn, visited) {
    const box = document.createElement("div");
    box.className = "trace_box trace_fn";
    box.setAttribute("data-fnid", String(fn.id));
    if (fn.is_entry) box.classList.add("entry");
    if (fn.is_ast_only) box.classList.add("ast_only");

    box.appendChild(buildHeader(shortName(fn.name), fn.def_loc, {
      fullName: fn.name,
      // AST-only fns have no IR `define` because the compiler inlined every
      // call site. The body shown here is reconstructed from the source AST,
      // so we mark the header with a small "↪ inlined" badge so the user
      // knows they're looking at a synthesized record.
      badge: fn.is_ast_only ? "↪ inlined" : null,
      onClick: function () {
        if (ctx.showNodePanel) {
          ctx.showNodePanel({
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
        }
      },
    }));

    const body = document.createElement("div");
    body.className = "trace_body";

    const intra = fn.intra || [];
    if (intra.length === 0) {
      const e = document.createElement("div");
      e.className = "trace_empty";
      e.textContent = "(no calls)";
      body.appendChild(e);
    } else {
      for (const atom of intra) {
        body.appendChild(buildAtom(atom, visited));
      }
    }
    box.appendChild(body);
    return box;
  }

  function buildHeader(title, loc, opts) {
    opts = opts || {};
    const h = document.createElement("div");
    h.className = "trace_header";

    const name = document.createElement("span");
    name.className = "trace_title";
    name.textContent = title;
    if (opts.fullName) name.title = opts.fullName;
    if (opts.onClick) {
      name.classList.add("clickable");
      name.addEventListener("click", function (e) {
        e.stopPropagation();
        opts.onClick();
      });
    }
    h.appendChild(name);

    if (opts.badge) {
      const badge = document.createElement("span");
      badge.className = "trace_badge";
      badge.textContent = opts.badge;
      badge.title = "Inlined by the compiler — body reconstructed from source AST";
      h.appendChild(badge);
    }

    if (loc) {
      const locSpan = document.createElement("span");
      locSpan.className = "trace_loc";
      locSpan.textContent = fmtLoc(loc);
      locSpan.title = fullLoc(loc);
      h.appendChild(locSpan);
    }
    return h;
  }

  /** Dispatch on atom shape: call / branch / loop. */
  function buildAtom(atom, visited) {
    if (atom.call) return buildCallBox(atom.call, visited);
    if (atom.branch) return buildBranchBox(atom.branch, visited);
    if (atom.loop) return buildLoopBox(atom.loop, visited);
    const u = document.createElement("div");
    u.className = "trace_box trace_unknown";
    u.textContent = "(unknown atom)";
    return u;
  }

  function buildCallBox(c, visited) {
    const kind = c.kind || "direct";

    // Resolve the target function via two lookups:
    //   1) `to` (id) — present when LLVM emitted a `define` for the callee.
    //   2) `name` / `mangled` — name-fallback for inlined helpers etc.
    //      The AST resolver attaches a qualified name to the call atom even
    //      when the IR has no separate function record (e.g. `inline fn`s
    //      get inlined into the caller). Without this fallback, trace mode
    //      dead-ends at boxes like `arch.dispatch.cpu.kEntry` even though
    //      we *do* have a function record under that name.
    let fn = null;
    if (c.to != null && ctx.fnById) fn = ctx.fnById.get(c.to) || null;
    if (!fn && c.name) fn = fnByName.get(c.name) || null;
    if (!fn && c.mangled) fn = fnByName.get(c.mangled) || null;

    // Apply the debug filter *before* the indirect render so that a debug
    // helper that happens to be reached indirectly still renders as a
    // closed debug leaf (and we don't traverse callees).
    if (fn && ctx.getHideDebug && ctx.getHideDebug() && ctx.isDebug && ctx.isDebug(fn)) {
      return makeLeafBox("↓ debug: " + shortName(fn.name), c.site, "trace_debug");
    }
    if (!fn && ctx.getHideDebug && ctx.getHideDebug() && ctx.isDebug && ctx.isDebug(c)) {
      return makeLeafBox("↓ debug: " + (c.name || "(debug)"), c.site, "trace_debug");
    }

    // Genuinely indirect: kind says so AND we have nothing resolved.
    if (!fn && kind === "indirect") {
      return makeLeafBox("? indirect: " + (c.name || "(unresolved)"), c.site, "trace_indirect");
    }

    // Direct/dispatch/vtable target whose IR record we don't have. The
    // most common case: a direct call to an `inline fn` that LLVM
    // dropped. Render the qualified name as a leaf with a dimmer border
    // (NOT red, NOT marked indirect — it's a known target).
    if (!fn) {
      if (kind === "direct" && c.name) {
        return makeLeafBox(c.name, c.site, "trace_inlined");
      }
      return makeLeafBox("? " + (c.name || "(unknown)"), c.site, "trace_unknown");
    }

    // Library leaf.
    if (ctx.isLibrary && ctx.isLibrary(fn) && ctx.getHideLibrary && ctx.getHideLibrary()) {
      return makeLeafBox("→ stdlib: " + shortName(fn.name), c.site, "trace_library");
    }

    // Recursion guard — fn already on the active call stack from this path.
    // Use a node-identity key (id-or-name) so name-fallback expansions are
    // protected the same way id-based expansions are.
    const key = nodeKeyFor(fn);
    if (visited.has(key)) {
      return makeLeafBox("↻ recursive: " + shortName(fn.name), c.site, "trace_recursive");
    }

    // Recurse into the callee.
    visited.add(key);
    const inner = buildFnBox(fn, visited);
    visited.delete(key);

    // Color-code the box border by edge kind so the user sees how the
    // call resolved (direct / dispatch_x64 / vtable / ...).
    inner.classList.add("kind_" + kind);

    return inner;
  }

  function makeLeafBox(label, site, klass) {
    const box = document.createElement("div");
    box.className = "trace_box " + klass;

    const h = document.createElement("div");
    h.className = "trace_header";
    const name = document.createElement("span");
    name.className = "trace_title";
    name.textContent = label;
    name.title = label;
    h.appendChild(name);
    if (site && site.file) {
      const locSpan = document.createElement("span");
      locSpan.className = "trace_loc";
      locSpan.textContent = fmtLoc(site);
      locSpan.title = fullLoc(site);
      h.appendChild(locSpan);
    }
    box.appendChild(h);
    return box;
  }

  function buildBranchBox(b, visited) {
    const wrap = document.createElement("div");
    wrap.className = "trace_branch";

    const arms = b.arms || [];
    // Title row (kind + loc) above the columns.
    const head = document.createElement("div");
    head.className = "trace_branch_head";
    const kw = document.createElement("span");
    kw.className = "trace_branch_kw";
    kw.textContent = b.kind === "if_else" ? "if / else" : "switch";
    head.appendChild(kw);
    if (b.loc) {
      const locSpan = document.createElement("span");
      locSpan.className = "trace_loc";
      locSpan.textContent = fmtLoc(b.loc);
      locSpan.title = fullLoc(b.loc);
      head.appendChild(locSpan);
    }
    wrap.appendChild(head);

    // Columns flex horizontally with a fixed 280px min-width per arm and
    // overflow-x:auto on the parent (see CSS). This keeps each arm
    // readable even in 65-arm syscall switches, at the cost of a
    // horizontal scrollbar.
    const cols = document.createElement("div");
    cols.className = "trace_branch_cols";

    for (const arm of arms) {
      const col = document.createElement("div");
      col.className = "trace_arm";

      const lab = document.createElement("div");
      lab.className = "trace_arm_label";
      const labelText = arm.label || "(arm)";
      lab.textContent = labelText;
      lab.title = labelText;
      col.appendChild(lab);

      const armBody = document.createElement("div");
      armBody.className = "trace_arm_body";
      const seq = arm.seq || [];
      if (seq.length === 0) {
        const e = document.createElement("div");
        e.className = "trace_empty";
        e.textContent = "(no calls)";
        armBody.appendChild(e);
      } else {
        for (const a of seq) {
          armBody.appendChild(buildAtom(a, visited));
        }
      }
      col.appendChild(armBody);
      cols.appendChild(col);
    }
    wrap.appendChild(cols);
    return wrap;
  }

  function buildLoopBox(l, visited) {
    const box = document.createElement("div");
    box.className = "trace_box trace_loop";

    const h = document.createElement("div");
    h.className = "trace_header";
    const name = document.createElement("span");
    name.className = "trace_title";
    name.textContent = "↻ loop";
    h.appendChild(name);
    if (l.loc) {
      const locSpan = document.createElement("span");
      locSpan.className = "trace_loc";
      locSpan.textContent = "@ " + fmtLoc(l.loc);
      locSpan.title = fullLoc(l.loc);
      h.appendChild(locSpan);
    }
    box.appendChild(h);

    const body = document.createElement("div");
    body.className = "trace_body";
    const inner = l.body || [];
    if (inner.length === 0) {
      const e = document.createElement("div");
      e.className = "trace_empty";
      e.textContent = "(no calls)";
      body.appendChild(e);
    } else {
      for (const a of inner) {
        body.appendChild(buildAtom(a, visited));
      }
    }
    box.appendChild(body);
    return box;
  }

  /** Re-run the current render without disturbing the drill stack. Useful
   *  after a filter-toggle change (library/debug) where the user expects
   *  the same drilled-into view, just with newly-filtered leaves. */
  function rerender() {
    render();
  }

  // ------------------------------------------------------------------ export
  window.traceMode = {
    setContext: setContext,
    onEntryChange: onEntryChange,
    show: show,
    hide: hide,
    render: render,
    rerender: rerender,
  };
})();
