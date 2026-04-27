//! MCP (Model Context Protocol) server bridging Claude Code to the
//! callgraph HTTP daemon.
//!
//! Architecture:
//!   1. The MCP process speaks JSON-RPC 2.0 over stdio (one message per
//!      line) — that's what Claude Code's MCP transport expects.
//!   2. On the first tool call, the process pings the daemon at
//!      127.0.0.1:<port>. If nothing answers, it fork-execs `callgraph`
//!      with `--port <port> --build-root … --kernel-root …` *detached*
//!      (setsid + stdio→/dev/null) so the daemon outlives this MCP
//!      process. It then polls `/api/arches` until ready or a timeout.
//!   3. Each MCP `tools/call` is translated into one HTTP GET against the
//!      daemon, and the response body becomes the tool's text content.
//!
//! Reading the spec (https://modelcontextprotocol.io/specification): the
//! MCP server MUST handle `initialize`, `notifications/initialized`,
//! `tools/list`, and `tools/call`. `ping` and `shutdown` are also nice
//! to support for completeness.

const std = @import("std");

pub const Args = struct {
    daemon_port: u16 = 18845,
    build_root: []const u8,
    kernel_root: []const u8,
    /// Path to the callgraph binary used to spawn the daemon. Resolved
    /// from /proc/self/exe when not provided.
    self_path: ?[]const u8 = null,
    /// How long to poll for the daemon coming up after a spawn, in
    /// milliseconds. Cold start now includes a full kernel rebuild + IR
    /// regeneration per arch (we dropped --no-build to keep the index
    /// honest), which can take 1–2 minutes on a 900-file kernel; default
    /// 240s gives headroom for both arches plus the graph build pass.
    spawn_timeout_ms: u32 = 240_000,
};

const TOOLS_JSON =
    \\[
    \\  {
    \\    "name": "callgraph_entries",
    \\    "description": "Use this FIRST when orienting yourself in the Zag kernel codebase. Lists every entry point — boot handlers, syscalls, traps, IRQs — that the kernel exposes, with file:line locations. This is how you find which code paths exist before exploring any of them. Vastly more efficient than grepping the source tree for entry-point patterns. Output is one entry per line: `<label> (<kind>) <file>:<line>`.\n\nPass `kind=syscall` (or any comma-separated subset of `syscall,irq,trap,boot,manual`) to scope the output to one subsystem when investigating a specific code path. Default is no filter — every entry returned.",
    \\    "inputSchema": {"type":"object","properties":{"arch":{"type":"string","description":"CPU architecture tag — typically x86_64 (default) or aarch64. Use callgraph_arches to see what's loaded."},"kind":{"type":"string","description":"Comma-separated list of entry kinds to keep: any of `syscall`, `irq`, `trap`, `boot`, `manual`. Empty/omitted = no filter. Use this to scope orientation to one subsystem (e.g. `kind=syscall` when investigating an ABI question, `kind=irq,trap` when chasing fault handling)."}},"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_trace",
    \\    "description": "PREFER THIS over reading kernel source files when you need to understand control flow in the Zag kernel. Renders the full call hierarchy from one function as a compact indented tree, including if/else, switch, and loop control-flow blocks. One trace replaces dozens of Read calls and uses a fraction of the tokens. Use this any time the question is 'what does X do', 'what gets called when X happens', or 'how does control flow reach Y'. Drill in by re-tracing the callee whose behavior matters; expand depth gradually rather than reading source. The output mirrors the visual call-graph the user reviews in the web UI, so your understanding will line up with theirs.",
    \\    "inputSchema": {"type":"object","properties":{"entry":{"type":"string","description":"Qualified function name to root the trace at (e.g. `main.kEntry`, `proc.process.start`). Use callgraph_find or callgraph_entries to discover names."},"arch":{"type":"string","description":"CPU architecture tag — x86_64 (default) or aarch64."},"depth":{"type":"integer","minimum":1,"maximum":36,"description":"Max traversal depth. Default 6. Increase only when the leaves you care about are still capped at the previous depth."},"hide_debug":{"type":"boolean","description":"Fold `debug.*` calls into one-line leaves. Default true. Pass false for full fidelity (e.g. when investigating panic/assert sites)."},"hide_library":{"type":"boolean","description":"Fold `std.*`/`builtin.*` calls into one-line leaves. Default true. Pass false to see stdlib internals."},"hide_assertions":{"type":"boolean","description":"Drop `debug.assert` / `debug.FullPanic.*` / `builtin.returnError` lines entirely. Default true — these are 0-signal noise in most traces. Pass false to keep them (e.g. when investigating which calls can fail)."},"hide_ref_captures":{"type":"boolean","description":"Drop `&<bare_ident>` lines (e.g. `&self`, `&buckets`) that are usually argument captures the IR analyzer flagged as indirect calls. Default true. Pass false to see them all."},"exclude":{"type":"string","description":"Comma-separated list of patterns to fold as `-` leaves in the trace. Each pattern is either a `module.*` prefix glob (matches qualified names starting with the prefix) or a bare substring. Use this to prune known-uninteresting subtrees per question (e.g. `exclude=memory.allocators.*,utils.elf.*` when investigating spawn flow but not the ELF parser internals)."},"format":{"type":"string","enum":["compact","text"],"description":"Output format. Default `compact` — pure-control-flow line format optimized for LLM token efficiency (~3-5× smaller than `text`). Each line: `<depth><payload>` for a descended fn, `<depth><tag><payload>` for a tagged node. `<depth>` is one base-36 char (`0`-`9`, then `a`-`z`). The full tag legend (`^@~&!%=?>*-` plus header format) lives in the MCP server `instructions` field — read it once at session start. Use `format=text` for the indented human-readable tree."}},"required":["entry"],"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_src",
    \\    "description": "PREFER THIS over Read for fetching a Zag kernel function's source code by qualified name. Returns just the function body — no need to know the file path or line range. Use it after callgraph_trace identifies a function whose implementation you actually need to read. Far cheaper than opening the whole file.",
    \\    "inputSchema": {"type":"object","properties":{"name":{"type":"string","description":"Qualified function name (e.g. `proc.process.start`). Same name format that callgraph_trace consumes."},"arch":{"type":"string","description":"CPU architecture tag. Default x86_64."}},"required":["name"],"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_find",
    \\    "description": "Use this to discover Zag kernel function names by substring search before reaching for callgraph_trace or callgraph_src. Vastly faster and more focused than grepping the source tree when all you need is a function's qualified name. Match is case-sensitive across qualified names (e.g. `kEntry`, `vmm.alloc`, `Process.start`).\n\nOutput annotations:\n  • `(reached by N)` — N distinct entry points (boot/syscall/trap/irq) can transitively reach this function via direct call edges (indirect/vtable edges are NOT walked). High N = load-bearing hub reached from many syscall paths; low or absent = local helper. Use it as a hotness signal when picking which name to investigate first.\n  • `(syscall)` / `(irq)` / `(trap)` / `(boot)` — appears when the function is itself an entry point.\n\nLayout:\n  • Up to 50 matches: each result includes the inline signature (`fn name(args) Ret`) so you can pick without a follow-up `loc` / `src`.\n  • Over 30 matches: results are grouped under a `# <file>` header so a flood is easy to scan by file.",
    \\    "inputSchema": {"type":"object","properties":{"query":{"type":"string","description":"Substring to match against qualified function names."},"arch":{"type":"string","description":"CPU architecture tag. Default x86_64."},"limit":{"type":"integer","minimum":1,"maximum":1000,"description":"Cap on returned matches. Default 200."}},"required":["query"],"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_modules",
    \\    "description": "Returns the static module-to-module call graph aggregated from all function-level edges. PREFER THIS when you need the kernel's layering at a glance — which top-level module depends on which — before investigating any specific function path. One call replaces dozens of `callgraph_trace`s when the question is structural ('does memory call into sched?', 'what depends on caps?') rather than behavioral. Output groups outgoing edges per source module, sorted by edge count. Module identity is derived from each function's source file path; `level=1` (default) is the top-level directory (`syscall`, `capdom`, `arch`...), `level=2` keeps one more component (`arch.x64`, `arch.dispatch`), `level=0` returns the full file path so the most fine-grained layering is visible. At `level=2` and finer, single-edge connections dominate the output — pass `min_edges=2` (or higher) to suppress them. Pass `exclude_external=true` to drop the synthetic `std`/`external` buckets so kernel layering isn't buried under stdlib noise. Pass `direction=in` to flip the view to inbound edges (per-dst, with `<- src (count)` lines) — useful for blast-radius questions like 'who depends on caps?'. `direction=both` emits both views in one call.",
    \\    "inputSchema": {"type":"object","properties":{"arch":{"type":"string","description":"CPU architecture tag. Default x86_64."},"level":{"type":"integer","minimum":0,"maximum":8,"description":"Path-component depth for the module identifier. 1=top dir (default), 2=top dir + subdir, 0=full file path."},"intra":{"type":"boolean","description":"Include intra-module edges (src module == dst module). Default false — at the layering granularity, intra edges are noise."},"min_edges":{"type":"integer","minimum":1,"description":"Suppress (src,dst) pairs with fewer than this many edges. Default 1 (no filter). Bump to 2-3 at level=2+ to drop trivial cross-module noise."},"exclude_external":{"type":"boolean","description":"Drop edges to/from the synthetic `std` and `external` modules so kernel-internal layering isn't buried by stdlib noise. Default false."},"direction":{"type":"string","enum":["out","in","both"],"description":"Edge direction to render. `out` (default) groups by src module and lists outgoing edges. `in` groups by dst module and lists inbound edges (`<- src (count)`); use this for blast-radius questions like 'who depends on caps?'. `both` emits both views."}},"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_type",
    \\    "description": "Read a Zig type definition (struct/union/enum/opaque/const/global var) by qualified name. PREFER THIS over Read when you encounter an unknown type in a trace or function body and want to see its fields/variants without opening the whole file. Returns a header line `<vis> <qname> (<kind>) — <file>:<start>-<end>` followed by the type's source body, fenced with `---`. If you pass a function name by mistake, the tool tells you and points at the function's location.",
    \\    "inputSchema": {"type":"object","properties":{"name":{"type":"string","description":"Qualified type name (e.g. `capdom.capability_domain.CapabilityDomain`) or just the simple name."},"arch":{"type":"string","description":"CPU architecture tag. Default x86_64."}},"required":["name"],"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_reaches",
    \\    "description": "Find the shortest call path between two Zig kernel functions. Returns the chain of qnames from `from` to `to` if one exists. PREFER THIS over `callgraph_trace` when you have a specific question of the form 'how does X reach Y' — it answers in one tool call instead of a wide trace + visual scan. Walks the same intra-atom edges as the trace, skipping indirect/vtable. Returns one line per hop: `<index> <qname>`. If `to` is unreachable from `from` within `max` hops, says so explicitly.",
    \\    "inputSchema": {"type":"object","properties":{"from":{"type":"string","description":"Source qualified function name."},"to":{"type":"string","description":"Target qualified function name."},"max":{"type":"integer","minimum":1,"maximum":64,"description":"Max hops to search. Default 24. Increase only when a sane path is plausible but exceeds the default."},"arch":{"type":"string","description":"CPU architecture tag. Default x86_64."}},"required":["from","to"],"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_loc",
    \\    "description": "Look up the source-file definition location of a Zig kernel function. Use this when you have a name from a `callgraph_trace` (compact format strips locations to save tokens) and need the file:line — typically as a precursor to opening the file with Read or Edit. Returns one line: `<qname>  <file>:<line>  [(kind)]  [inlined]`. Cheaper than `callgraph_src` when you only want to know *where* a function lives, not *what* it does.",
    \\    "inputSchema": {"type":"object","properties":{"name":{"type":"string","description":"Qualified function name."},"arch":{"type":"string","description":"CPU architecture tag. Default x86_64."}},"required":["name"],"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_callers",
    \\    "description": "Reverse lookup: list every call site that invokes the named Zig kernel function. PREFER THIS over grepping the source tree for callers — the index is built from the same call-graph that callgraph_trace renders, so it captures inlined-body calls and dispatch shims that grep would miss. Use this when you need to know who depends on a function before changing its signature, when assessing the blast radius of a refactor, or when answering 'how is X reached'. Each line is `<caller_name> (<edge_kind>) @ <file>:<line>`; repeated callers collapse with a `↳` continuation under the first occurrence so caller groups are visually obvious.",
    \\    "inputSchema": {"type":"object","properties":{"name":{"type":"string","description":"Qualified function name (camelCase) — same form callgraph_trace consumes."},"arch":{"type":"string","description":"CPU architecture tag. Default x86_64."}},"required":["name"],"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_arches",
    \\    "description": "Use this when you need to confirm which CPU architectures (typically x86_64 and aarch64) the Zag kernel daemon currently has loaded. Call this if a tool errors with `unknown arch` or you're not sure which arch tag to pass.",
    \\    "inputSchema": {"type":"object","properties":{},"additionalProperties":false}
    \\  },
    \\  {
    \\    "name": "callgraph_commits",
    \\    "description": "Use this to see recent commits in the Zag kernel repo when orienting yourself in the project's history. Output: one commit per line — `<short_sha>  <iso8601_date>  <subject>` with a trailing `  [stale]` marker on commits that predate the `-Demit_ir` build option (those commits can't be loaded by the callgraph tool — older than the scaffold).",
    \\    "inputSchema": {"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":500,"description":"Number of recent commits. Default 30."}},"additionalProperties":false}
    \\  }
    \\]
;

// MCP stdio transport is line-delimited JSON: each message MUST be one
// line, no embedded newlines. The raw multi-line literal above is for
// readability; flatten it at comptime before sending to the client.
fn stripNewlines(comptime s: []const u8) []const u8 {
    @setEvalBranchQuota(s.len * 4);
    comptime var n: usize = 0;
    inline for (s) |c| if (c != '\n') {
        n += 1;
    };
    var buf: [n]u8 = undefined;
    comptime var i: usize = 0;
    inline for (s) |c| if (c != '\n') {
        buf[i] = c;
        i += 1;
    };
    const final = buf;
    return &final;
}

const TOOLS_JSON_FLAT: []const u8 = stripNewlines(TOOLS_JSON);

const INSTRUCTIONS =
    "These tools provide structured exploration of the Zag kernel codebase " ++
    "(github.com/.../Zag — a capability-based microkernel in Zig). Prefer them " ++
    "over Read/Grep/Glob when investigating kernel code:\n\n" ++
    "  • Orient yourself → `callgraph_entries` (entry points) or `callgraph_modules` (module-level layering).\n" ++
    "  • Understand control flow / what a code path does → `callgraph_trace`.\n" ++
    "  • Reverse lookup — who calls X → `callgraph_callers`.\n" ++
    "  • Find a function name → `callgraph_find`.\n" ++
    "  • Look up a function's def location → `callgraph_loc` (cheap; trace strips locations).\n" ++
    "  • Read a function's source body → `callgraph_src`.\n\n" ++
    "These are typically 5–20× cheaper in tokens than reading source files directly, " ++
    "and they reflect the same call-graph the user reviews in the web UI, so your " ++
    "understanding stays aligned with theirs. Use them for anything kernel-related " ++
    "before falling back to filesystem tools.\n\n" ++
    "## callgraph_trace compact format\n\n" ++
    "Default `format=compact` is a terse single-line-per-node form (~3-5× smaller than " ++
    "`text`). Lines are self-describing — first char = depth, second = tag or start of " ++
    "a function name.\n\n" ++
    "Header (always first line):\n" ++
    "  `T fns=N cap=N d=N [top=<name>/<count>] [cap_top=<n1>/<c1>,...]`\n" ++
    "  `cap` is the count of nodes that hit the depth limit; `cap_top` lists up to 3 of them " ++
    "by call-site count. Use `cap_top` to deepen surgically instead of cranking `depth` blindly. " ++
    "Suppressed when every capped fn has only one call site (the `^` markers locate them and `/1` adds noise).\n\n" ++
    "Body line shapes:\n" ++
    "  `<depth><name>`         — descended function (the default; `name` starts with a letter or `_`)\n" ++
    "  `<depth><tag><payload>` — tagged node (`tag` is one of the symbols below)\n\n" ++
    "Depth is a single base-36 char: `0`-`9` for 0-9, then `a`-`z` for 10-35.\n\n" ++
    "Tags:\n" ++
    "  `^` capped — fn HAS callees but hit `depth` (deepen to expand)\n" ++
    "  `@` no-body leaf — typically a compiler-inlined helper. Deepening will NOT expand it.\n" ++
    "  `~` body shown elsewhere — followed by ANOTHER base-36 depth char then the name. Shape: `<this_depth>~<body_depth><name>`. The body was rendered earlier in the trace at line depth `<body_depth>` — either an ancestor on the call path (recursion) or a sibling-repeat. Scan upward for a line whose leading char matches `<body_depth>` and whose payload is the same name.\n" ++
    "  `&` indirect call — fn pointer / vtable / unresolved ref\n" ++
    "  `!` unresolved direct call — name has no body in this graph\n" ++
    "  `%` folded `debug.*` call\n" ++
    "  `=` folded `std.*` / `builtin.*` call\n" ++
    "  `?` branch (payload: `if_else` or `switch`)\n" ++
    "  `*` loop (no payload)\n" ++
    "  `>` branch arm label (payload truncated at 80 chars)\n" ++
    "  `-` excluded by an `exclude` pattern\n\n" ++
    "No file:line in the trace — use `callgraph_loc <name>` for source location, or " ++
    "`callgraph_src <name>` to read a body.";

const SERVER_INFO_JSON =
    \\{"name":"callgraph","version":"0.1.0"}
;

const CAPABILITIES_JSON =
    \\{"tools":{"listChanged":false},"logging":{}}
;

const PROTOCOL_VERSION = "2024-11-05";

pub fn run(gpa: std.mem.Allocator, args: Args) !void {
    var ctx = Ctx{
        .gpa = gpa,
        .args = args,
        .daemon_started = false,
    };

    const stdin_handle = std.fs.File.stdin().handle;
    var stdout_buf: [16 * 1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const out = &stdout_writer.interface;

    var line_buf = std.ArrayList(u8){};
    defer line_buf.deinit(gpa);

    while (true) {
        line_buf.clearRetainingCapacity();
        const got = readLine(gpa, stdin_handle, &line_buf) catch return;
        if (!got) return;
        const line = std.mem.trim(u8, line_buf.items, " \t\r\n");
        if (line.len == 0) continue;

        handleMessage(&ctx, out, line) catch |err| {
            // We can't easily route protocol errors back without an id;
            // log to stderr and continue.
            std.debug.print("mcp handler error: {s}\n", .{@errorName(err)});
        };
        try out.flush();
    }
}

const Ctx = struct {
    gpa: std.mem.Allocator,
    args: Args,
    daemon_started: bool,
};

fn handleMessage(ctx: *Ctx, out: *std.io.Writer, line: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    const al = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, al, line, .{}) catch |err| {
        std.debug.print("mcp parse error: {s}: {s}\n", .{ @errorName(err), line });
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return;
    const obj = root.object;

    const id_val: ?std.json.Value = if (obj.get("id")) |v| v else null;
    const method = (obj.get("method") orelse return).string;

    if (std.mem.eql(u8, method, "initialize")) {
        try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
        try writeIdJson(out, id_val);
        try out.writeAll(",\"result\":{\"protocolVersion\":\"" ++ PROTOCOL_VERSION ++
            "\",\"capabilities\":" ++ CAPABILITIES_JSON ++
            ",\"serverInfo\":" ++ SERVER_INFO_JSON ++ ",\"instructions\":");
        try writeJsonString(out, INSTRUCTIONS);
        try out.writeAll("}}\n");
        return;
    }
    if (std.mem.eql(u8, method, "notifications/initialized")) {
        // No response for notifications.
        return;
    }
    if (std.mem.eql(u8, method, "ping")) {
        try writeResultRaw(out, id_val, "{}");
        return;
    }
    if (std.mem.eql(u8, method, "shutdown")) {
        try writeResultRaw(out, id_val, "{}");
        return;
    }
    if (std.mem.eql(u8, method, "tools/list")) {
        try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
        try writeIdJson(out, id_val);
        try out.writeAll(",\"result\":{\"tools\":");
        try out.writeAll(TOOLS_JSON_FLAT);
        try out.writeAll("}}\n");
        return;
    }
    if (std.mem.eql(u8, method, "tools/call")) {
        try handleToolCall(ctx, al, out, id_val, obj.get("params"));
        return;
    }

    // Unknown method.
    try writeError(out, id_val, -32601, "method not found");
}

fn handleToolCall(
    ctx: *Ctx,
    al: std.mem.Allocator,
    out: *std.io.Writer,
    id_val: ?std.json.Value,
    params_opt: ?std.json.Value,
) !void {
    const params = params_opt orelse return writeError(out, id_val, -32602, "missing params");
    if (params != .object) return writeError(out, id_val, -32602, "params must be object");
    const name_v = params.object.get("name") orelse return writeError(out, id_val, -32602, "missing tool name");
    if (name_v != .string) return writeError(out, id_val, -32602, "name must be string");
    const tool = name_v.string;
    const tool_args = if (params.object.get("arguments")) |v| v else std.json.Value{ .null = {} };

    try ensureDaemon(ctx);

    var url = std.ArrayList(u8){};
    defer url.deinit(al);
    try buildUrl(al, &url, ctx.args.daemon_port, tool, tool_args);
    if (url.items.len == 0) {
        return writeError(out, id_val, -32601, "unknown tool");
    }

    const body = httpGet(al, url.items) catch |err| {
        // The daemon may have died since we last cached daemon_started.
        // Clear the flag so the next tool call re-runs ensureDaemon and
        // respawns it instead of immediately failing with the same error.
        switch (err) {
            error.ConnectionRefused, error.ConnectionResetByPeer, error.NetworkUnreachable => {
                ctx.daemon_started = false;
            },
            else => {},
        }
        const msg = try std.fmt.allocPrint(al, "daemon request failed: {s}", .{@errorName(err)});
        return writeError(out, id_val, -32000, msg);
    };
    defer al.free(body);

    try writeToolText(out, id_val, body);
}

fn buildUrl(
    al: std.mem.Allocator,
    out: *std.ArrayList(u8),
    port: u16,
    tool: []const u8,
    args: std.json.Value,
) !void {
    const base = try std.fmt.allocPrint(al, "http://127.0.0.1:{d}", .{port});
    try out.appendSlice(al, base);

    if (std.mem.eql(u8, tool, "callgraph_arches")) {
        try out.appendSlice(al, "/api/arches");
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_commits")) {
        // MCP shim always requests text; the daemon defaults /api/commits
        // to JSON for the web UI.
        try out.appendSlice(al, "/api/commits?format=text");
        if (jsonInt(args, "limit")) |n| try out.writer(al).print("&limit={d}", .{n});
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_entries")) {
        try out.appendSlice(al, "/api/entries");
        var first = true;
        if (jsonString(args, "arch")) |a| {
            try out.writer(al).print("{s}arch={s}", .{ if (first) "?" else "&", a });
            first = false;
        }
        if (jsonString(args, "kind")) |k| {
            try out.writer(al).print("{s}kind={s}", .{ if (first) "?" else "&", percentEncode(al, k) catch k });
            first = false;
        }
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_find")) {
        try out.appendSlice(al, "/api/find?");
        const q_opt = jsonString(args, "query") orelse return error.MissingQuery;
        try out.writer(al).print("q={s}", .{percentEncode(al, q_opt) catch q_opt});
        if (jsonString(args, "arch")) |a| try out.writer(al).print("&arch={s}", .{a});
        if (jsonInt(args, "limit")) |n| try out.writer(al).print("&limit={d}", .{n});
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_trace")) {
        try out.appendSlice(al, "/api/trace?");
        const e_opt = jsonString(args, "entry") orelse return error.MissingEntry;
        try out.writer(al).print("entry={s}", .{percentEncode(al, e_opt) catch e_opt});
        if (jsonString(args, "arch")) |a| try out.writer(al).print("&arch={s}", .{a});
        if (jsonInt(args, "depth")) |n| try out.writer(al).print("&depth={d}", .{n});
        if (jsonBoolOpt(args, "hide_debug")) |b| {
            try out.writer(al).print("&hide_debug={d}", .{@intFromBool(b)});
        }
        if (jsonBoolOpt(args, "hide_library")) |b| {
            try out.writer(al).print("&hide_library={d}", .{@intFromBool(b)});
        }
        if (jsonBoolOpt(args, "hide_assertions")) |b| {
            try out.writer(al).print("&hide_assertions={d}", .{@intFromBool(b)});
        }
        if (jsonBoolOpt(args, "hide_ref_captures")) |b| {
            try out.writer(al).print("&hide_ref_captures={d}", .{@intFromBool(b)});
        }
        if (jsonString(args, "exclude")) |e| {
            try out.writer(al).print("&exclude={s}", .{percentEncode(al, e) catch e});
        }
        // MCP defaults to the compact format (token-optimized for LLMs).
        // The HTTP `/api/trace` endpoint still defaults to `text` so manual
        // curl users get a readable tree.
        const fmt = jsonString(args, "format") orelse "compact";
        try out.writer(al).print("&format={s}", .{fmt});
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_loc")) {
        try out.appendSlice(al, "/api/loc?");
        const n_opt = jsonString(args, "name") orelse return error.MissingName;
        try out.writer(al).print("name={s}", .{percentEncode(al, n_opt) catch n_opt});
        if (jsonString(args, "arch")) |a| try out.writer(al).print("&arch={s}", .{a});
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_type")) {
        try out.appendSlice(al, "/api/type?");
        const n_opt = jsonString(args, "name") orelse return error.MissingName;
        try out.writer(al).print("name={s}", .{percentEncode(al, n_opt) catch n_opt});
        if (jsonString(args, "arch")) |a| try out.writer(al).print("&arch={s}", .{a});
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_reaches")) {
        try out.appendSlice(al, "/api/reaches?");
        const f_opt = jsonString(args, "from") orelse return error.MissingFrom;
        const t_opt = jsonString(args, "to") orelse return error.MissingTo;
        try out.writer(al).print("from={s}", .{percentEncode(al, f_opt) catch f_opt});
        try out.writer(al).print("&to={s}", .{percentEncode(al, t_opt) catch t_opt});
        if (jsonString(args, "arch")) |a| try out.writer(al).print("&arch={s}", .{a});
        if (jsonInt(args, "max")) |n| try out.writer(al).print("&max={d}", .{n});
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_src")) {
        try out.appendSlice(al, "/api/fn_source?");
        const n_opt = jsonString(args, "name") orelse return error.MissingName;
        try out.writer(al).print("name={s}", .{percentEncode(al, n_opt) catch n_opt});
        if (jsonString(args, "arch")) |a| try out.writer(al).print("&arch={s}", .{a});
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_callers")) {
        try out.appendSlice(al, "/api/callers?");
        const n_opt = jsonString(args, "name") orelse return error.MissingName;
        try out.writer(al).print("name={s}", .{percentEncode(al, n_opt) catch n_opt});
        if (jsonString(args, "arch")) |a| try out.writer(al).print("&arch={s}", .{a});
        return;
    }
    if (std.mem.eql(u8, tool, "callgraph_modules")) {
        try out.appendSlice(al, "/api/modules");
        var first = true;
        if (jsonString(args, "arch")) |a| {
            try out.writer(al).print("{s}arch={s}", .{ if (first) "?" else "&", a });
            first = false;
        }
        if (jsonInt(args, "level")) |n| {
            try out.writer(al).print("{s}level={d}", .{ if (first) "?" else "&", n });
            first = false;
        }
        if (jsonBool(args, "intra")) {
            try out.writer(al).print("{s}intra=1", .{if (first) "?" else "&"});
            first = false;
        }
        if (jsonInt(args, "min_edges")) |n| {
            try out.writer(al).print("{s}min_edges={d}", .{ if (first) "?" else "&", n });
            first = false;
        }
        if (jsonBool(args, "exclude_external")) {
            try out.writer(al).print("{s}exclude_external=1", .{if (first) "?" else "&"});
            first = false;
        }
        if (jsonString(args, "direction")) |d| {
            try out.writer(al).print("{s}direction={s}", .{ if (first) "?" else "&", d });
            first = false;
        }
        return;
    }
    out.clearRetainingCapacity();
}

fn jsonString(v: std.json.Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const got = v.object.get(key) orelse return null;
    if (got != .string) return null;
    return got.string;
}

fn jsonInt(v: std.json.Value, key: []const u8) ?i64 {
    if (v != .object) return null;
    const got = v.object.get(key) orelse return null;
    return switch (got) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => null,
    };
}

fn jsonBool(v: std.json.Value, key: []const u8) bool {
    if (v != .object) return false;
    const got = v.object.get(key) orelse return false;
    return switch (got) {
        .bool => |b| b,
        else => false,
    };
}

/// Tri-state read: `null` if the key is absent (let server default win),
/// otherwise the explicit boolean. Use this for any flag whose server-side
/// default is `true` so callers can still opt out by passing `false`.
fn jsonBoolOpt(v: std.json.Value, key: []const u8) ?bool {
    if (v != .object) return null;
    const got = v.object.get(key) orelse return null;
    return switch (got) {
        .bool => |b| b,
        else => null,
    };
}

// ----------------------------------------------------------- daemon spawn

fn ensureDaemon(ctx: *Ctx) !void {
    if (ctx.daemon_started) return;
    if (try pingDaemon(ctx.gpa, ctx.args.daemon_port)) {
        ctx.daemon_started = true;
        return;
    }
    try spawnDaemon(ctx);
    // Poll until /api/arches answers OK, or timeout.
    const deadline = std.time.milliTimestamp() + ctx.args.spawn_timeout_ms;
    while (std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(500 * std.time.ns_per_ms);
        if (try pingDaemon(ctx.gpa, ctx.args.daemon_port)) {
            ctx.daemon_started = true;
            return;
        }
    }
    return error.DaemonStartTimeout;
}

fn pingDaemon(gpa: std.mem.Allocator, port: u16) !bool {
    const url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/api/arches", .{port});
    defer gpa.free(url);
    const body = httpGet(gpa, url) catch return false;
    gpa.free(body);
    return true;
}

fn spawnDaemon(ctx: *Ctx) !void {
    const self_path = ctx.args.self_path orelse blk: {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const link = try std.posix.readlink("/proc/self/exe", &buf);
        break :blk try ctx.gpa.dupe(u8, link);
    };
    defer if (ctx.args.self_path == null) ctx.gpa.free(self_path);

    const port_arg = try std.fmt.allocPrint(ctx.gpa, "{d}", .{ctx.args.daemon_port});
    defer ctx.gpa.free(port_arg);

    // Spawn the daemon WITHOUT --no-build. Cold start now triggers a kernel
    // rebuild + IR regeneration so the index reflects the working tree at
    // spawn time. The daemon is long-lived; subsequent MCP sessions reuse
    // it and pay no startup cost. Without this, deleted-or-renamed modules
    // continued to surface in tool output indefinitely (the recurring
    // "ghost symbol" problem). The freshness footer in the daemon flags
    // long-running stale indexes after FRESHNESS_FOOTER_AFTER_SECS.
    const argv = [_][]const u8{
        self_path,
        "--port",                 port_arg,
        "--build-root",           ctx.args.build_root,
        "--kernel-root",          ctx.args.kernel_root,
    };

    // Fork + setsid so the daemon outlives this MCP process. Redirect
    // stdio to /dev/null so we don't compete for the MCP transport.
    const pid = try std.posix.fork();
    if (pid == 0) {
        // Child.
        _ = std.os.linux.setsid();
        const devnull = std.posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0) catch std.process.exit(1);
        _ = std.posix.dup2(devnull, 0) catch {};
        _ = std.posix.dup2(devnull, 1) catch {};
        _ = std.posix.dup2(devnull, 2) catch {};
        if (devnull > 2) std.posix.close(devnull);

        // Second fork so the grandchild is reparented to PID 1 and we
        // don't leave a zombie when the first child exits.
        const pid2 = std.posix.fork() catch std.process.exit(1);
        if (pid2 != 0) std.process.exit(0);

        const env = std.process.getEnvMap(ctx.gpa) catch std.process.exit(1);
        const err = std.process.execve(ctx.gpa, &argv, &env);
        std.debug.print("execve failed: {}\n", .{err});
        std.process.exit(1);
    }
    // Parent: reap the immediate child so it doesn't linger as a zombie.
    _ = std.posix.waitpid(pid, 0);
}

// --------------------------------------------------------------- HTTP GET

fn httpGet(gpa: std.mem.Allocator, url: []const u8) ![]u8 {
    var client: std.http.Client = .{ .allocator = gpa };
    defer client.deinit();

    var aw = std.io.Writer.Allocating.init(gpa);
    defer aw.deinit();

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .response_writer = &aw.writer,
    });
    if (result.status != .ok and result.status != .not_found and result.status != .bad_request) {
        std.debug.print("http {d} from {s}\n", .{ @intFromEnum(result.status), url });
    }
    return aw.toOwnedSlice();
}

// ---------------------------------------------------------- JSON-RPC out

fn writeResultRaw(out: *std.io.Writer, id_val: ?std.json.Value, raw_result: []const u8) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeIdJson(out, id_val);
    try out.writeAll(",\"result\":");
    try out.writeAll(raw_result);
    try out.writeAll("}\n");
}

fn writeError(out: *std.io.Writer, id_val: ?std.json.Value, code: i32, message: []const u8) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeIdJson(out, id_val);
    try out.print(",\"error\":{{\"code\":{d},\"message\":", .{code});
    try writeJsonString(out, message);
    try out.writeAll("}}\n");
}

fn writeToolText(out: *std.io.Writer, id_val: ?std.json.Value, body: []const u8) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try writeIdJson(out, id_val);
    try out.writeAll(",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    try writeJsonString(out, body);
    try out.writeAll("}]}}\n");
}

fn writeIdJson(out: *std.io.Writer, id_val: ?std.json.Value) !void {
    const v = id_val orelse {
        try out.writeAll("null");
        return;
    };
    switch (v) {
        .integer => |i| try out.print("{d}", .{i}),
        .string => |s| try writeJsonString(out, s),
        .null => try out.writeAll("null"),
        else => try out.writeAll("null"),
    }
}

fn writeJsonString(out: *std.io.Writer, s: []const u8) !void {
    try out.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            0...0x07, 0x0b, 0x0e...0x1f => try out.print("\\u{x:0>4}", .{c}),
            else => try out.writeAll(&[_]u8{c}),
        }
    }
    try out.writeAll("\"");
}

// ---------------------------------------------------------------- helpers

fn percentEncode(al: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(al);
    for (s) |c| {
        const safe = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~';
        if (safe) {
            try out.append(al, c);
        } else {
            try out.writer(al).print("%{X:0>2}", .{c});
        }
    }
    return out.toOwnedSlice(al);
}

fn readLine(
    gpa: std.mem.Allocator,
    fd: std.posix.fd_t,
    buf: *std.ArrayList(u8),
) !bool {
    var byte: [1]u8 = undefined;
    while (true) {
        const n = try std.posix.read(fd, &byte);
        if (n == 0) return buf.items.len > 0;
        if (byte[0] == '\n') return true;
        try buf.append(gpa, byte[0]);
    }
}
