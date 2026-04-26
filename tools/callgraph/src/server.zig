//! HTTP server for the kernel call-graph explorer.
//!
//! Endpoints:
//!   - `GET /` and `GET /static/{app.js,trace.js,cytoscape.min.js}` —
//!     embedded frontend assets.
//!   - `GET /api/arches` — JSON listing of loaded arches and the default.
//!     Optional `?sha=` switches to a loaded commit's arches.
//!   - `GET /api/graph?arch=<tag>&sha=<sha>` — JSON dump of the immutable
//!     Graph. With no `sha=`, serves the live working-tree build.
//!   - `GET /api/source?path=...&start=N&end=M` — JSON {lines, tokens}
//!     for the named source file.
//!   - `GET /api/commits?limit=N` — recent git log entries.
//!   - `GET /api/load_commit?sha=X` — kicks off a worktree+build for X
//!     on a worker thread; returns initial status. Idempotent: a second
//!     call with X already-ready returns the cached state.
//!   - `GET /api/load_commit/status?sha=X` — current load state for X.
//!   - `GET /api/diff?sha_a=&sha_b=&path=` — unified diff (text/plain)
//!     between two refs for one file.
//!   - `GET /api/diff_files?sha=X` — `git diff --name-only X` (vs
//!     working tree).
//!   - `GET /api/diff_hunks?sha=X` — parsed hunk ranges per file.
//!     Each hunk emits {old_start,old_count,start,count} so both sides
//!     of the diff can be tinted.
//!
//! Synchronous accept loop on 127.0.0.1. Per-arch graph blobs are
//! pre-serialized once at startup since the live graphs never change
//! during the server's life.

const std = @import("std");

const commits = @import("commits.zig");
const render = @import("render.zig");
const types = @import("types.zig");

const Function = types.Function;
const Graph = types.Graph;

const index_html = @embedFile("assets/index.html");
const app_js = @embedFile("assets/app.js");
const trace_js = @embedFile("assets/trace.js");
const cytoscape_js = @embedFile("assets/cytoscape.min.js");

const SOURCE_MAX_BYTES: usize = 1 * 1024 * 1024;

pub const GraphMap = std.StringHashMap(Graph);

const ServerState = struct {
    /// Pre-serialized JSON blobs per arch tag.
    blobs: std.StringHashMap([]u8),
    /// Pre-serialized `/api/arches` payload.
    arches_blob: []u8,
    /// Default arch tag (must be a key in `blobs`).
    default_arch: []const u8,
    /// Path to the kernel repo root — used as cwd for git invocations.
    git_root: []const u8,
    /// Per-commit graph registry. Lookups by sha; missing/empty sha
    /// means "live" (use `blobs`).
    registry: *commits.Registry,
    /// In-memory live graphs (HEAD). Used by /api/trace and /api/fn_source
    /// to walk the call tree without re-parsing JSON. Key matches the keys
    /// in `blobs`.
    graphs: *const GraphMap,
    /// Per-arch render lookup tables (by_id + by_name). Built once at
    /// startup; reused across requests. Key matches the arch tag.
    lookups: std.StringHashMap(render.Maps),
};

pub fn serve(
    allocator: std.mem.Allocator,
    graphs: *const GraphMap,
    default_arch: []const u8,
    git_root: []const u8,
    registry: *commits.Registry,
    port: u16,
) !void {
    var state = try buildState(allocator, graphs, default_arch, git_root, registry);
    defer freeState(allocator, &state);

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var net_server = try addr.listen(.{ .reuse_address = true });
    defer net_server.deinit();

    std.debug.print("Listening on http://127.0.0.1:{d}\n", .{port});

    var recv_buffer: [16 * 1024]u8 = undefined;
    var send_buffer: [16 * 1024]u8 = undefined;
    while (true) {
        const conn = net_server.accept() catch |err| {
            std.debug.print("accept failed: {s}\n", .{@errorName(err)});
            continue;
        };
        defer conn.stream.close();

        var conn_reader = conn.stream.reader(&recv_buffer);
        var conn_writer = conn.stream.writer(&send_buffer);
        var http_server = std.http.Server.init(conn_reader.interface(), &conn_writer.interface);

        var request = http_server.receiveHead() catch |err| {
            std.debug.print("receiveHead failed: {s}\n", .{@errorName(err)});
            continue;
        };
        handleRequest(allocator, &request, &state) catch |err| {
            std.debug.print("handler error: {s}\n", .{@errorName(err)});
        };
    }
}

fn buildState(
    allocator: std.mem.Allocator,
    graphs: *const GraphMap,
    default_arch: []const u8,
    git_root: []const u8,
    registry: *commits.Registry,
) !ServerState {
    var blobs = std.StringHashMap([]u8).init(allocator);
    errdefer {
        var it = blobs.iterator();
        while (it.next()) |e| allocator.free(e.value_ptr.*);
        blobs.deinit();
    }

    var it = graphs.iterator();
    while (it.next()) |entry| {
        const blob = try std.json.Stringify.valueAlloc(allocator, entry.value_ptr.*, .{});
        try blobs.put(entry.key_ptr.*, blob);
    }

    var arches_buf = std.ArrayList(u8){};
    defer arches_buf.deinit(allocator);
    try arches_buf.appendSlice(allocator, "{\"arches\":[");
    var first = true;
    var kit = graphs.keyIterator();
    while (kit.next()) |k| {
        if (!first) try arches_buf.appendSlice(allocator, ",");
        first = false;
        try arches_buf.append(allocator, '"');
        try arches_buf.appendSlice(allocator, k.*);
        try arches_buf.append(allocator, '"');
    }
    try arches_buf.appendSlice(allocator, "],\"default\":\"");
    try arches_buf.appendSlice(allocator, default_arch);
    try arches_buf.appendSlice(allocator, "\"}");

    var lookups = std.StringHashMap(render.Maps).init(allocator);
    errdefer {
        var lit = lookups.valueIterator();
        while (lit.next()) |m| m.deinit();
        lookups.deinit();
    }
    var git2 = graphs.iterator();
    while (git2.next()) |entry| {
        const m = try render.buildLookups(allocator, entry.value_ptr);
        try lookups.put(entry.key_ptr.*, m);
    }

    return .{
        .blobs = blobs,
        .arches_blob = try arches_buf.toOwnedSlice(allocator),
        .default_arch = default_arch,
        .git_root = git_root,
        .registry = registry,
        .graphs = graphs,
        .lookups = lookups,
    };
}

fn freeState(allocator: std.mem.Allocator, state: *ServerState) void {
    var it = state.blobs.iterator();
    while (it.next()) |e| allocator.free(e.value_ptr.*);
    state.blobs.deinit();
    allocator.free(state.arches_blob);
    var lit = state.lookups.valueIterator();
    while (lit.next()) |m| m.deinit();
    state.lookups.deinit();
}

fn handleRequest(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    state: *const ServerState,
) !void {
    const target = request.head.target;
    const path_end = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
    const path = target[0..path_end];
    const query = if (path_end < target.len) target[path_end + 1 ..] else "";

    if (std.mem.eql(u8, path, "/")) {
        return respondBytes(request, .ok, "text/html; charset=utf-8", index_html);
    }
    if (std.mem.eql(u8, path, "/static/app.js")) {
        return respondBytes(request, .ok, "application/javascript; charset=utf-8", app_js);
    }
    if (std.mem.eql(u8, path, "/static/trace.js")) {
        return respondBytes(request, .ok, "application/javascript; charset=utf-8", trace_js);
    }
    if (std.mem.eql(u8, path, "/static/cytoscape.min.js")) {
        return respondBytes(request, .ok, "application/javascript; charset=utf-8", cytoscape_js);
    }
    if (std.mem.eql(u8, path, "/api/arches")) {
        return handleArches(request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/graph")) {
        return handleGraph(request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/source")) {
        return handleSource(allocator, request, query);
    }
    if (std.mem.eql(u8, path, "/api/trace")) {
        return handleTrace(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/fn_source")) {
        return handleFnSource(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/find")) {
        return handleFind(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/entries")) {
        return handleEntries(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/callers")) {
        return handleCallers(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/modules")) {
        return handleModules(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/loc")) {
        return handleLoc(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/reaches")) {
        return handleReaches(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/type")) {
        return handleType(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/commits")) {
        return handleCommits(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/load_commit")) {
        return handleLoadCommit(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/load_commit/status")) {
        return handleLoadCommitStatus(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/diff")) {
        return handleDiff(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/diff_files")) {
        return handleDiffFiles(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/diff_hunks")) {
        return handleDiffHunks(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/review_state")) {
        return handleReviewState(allocator, request, query, state);
    }

    return respondBytes(request, .not_found, "text/plain; charset=utf-8", "not found\n");
}

// ---- Arches / graph ------------------------------------------------------

fn handleArches(
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var sha: []const u8 = "";
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha")) sha = val;
    }
    if (sha.len == 0) {
        return respondBytes(request, .ok, "application/json; charset=utf-8", state.arches_blob);
    }
    const reg = state.registry;
    reg.lockShared();
    defer reg.unlockShared();
    const entry = reg.entries.get(sha) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "commit not loaded\n",
    );
    if (entry.status != .ready) return respondBytes(
        request,
        .conflict,
        "text/plain; charset=utf-8",
        "commit not ready\n",
    );
    return respondBytes(request, .ok, "application/json; charset=utf-8", entry.arches_blob);
}

fn handleGraph(
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var arch: []const u8 = "";
    var sha: []const u8 = "";

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "arch")) arch = val;
        if (std.mem.eql(u8, key, "sha")) sha = val;
    }

    if (sha.len == 0) {
        const a = if (arch.len == 0) state.default_arch else arch;
        const blob = state.blobs.get(a) orelse {
            return respondBytes(
                request,
                .not_found,
                "text/plain; charset=utf-8",
                "arch not loaded\n",
            );
        };
        return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
    }

    const reg = state.registry;
    reg.lockShared();
    defer reg.unlockShared();
    const entry = reg.entries.get(sha) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "commit not loaded\n",
    );
    if (entry.status != .ready) return respondBytes(
        request,
        .conflict,
        "text/plain; charset=utf-8",
        "commit not ready\n",
    );
    const a = if (arch.len == 0) entry.default_arch else arch;
    const blob = entry.arch_blobs.get(a) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "arch not loaded for this commit\n",
    );
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
}

fn respondBytes(
    request: *std.http.Server.Request,
    status: std.http.Status,
    content_type: []const u8,
    body: []const u8,
) !void {
    try request.respond(body, .{
        .status = status,
        .keep_alive = false,
        .extra_headers = &.{
            .{ .name = "content-type", .value = content_type },
            .{ .name = "cache-control", .value = "no-store" },
        },
    });
}

// ---- Source (JSON with tokenized highlights) -----------------------------

const SourceToken = struct {
    /// 1-indexed absolute line number in the source file.
    line: u32,
    /// 1-indexed byte column within the line.
    col: u32,
    /// Length in bytes. Multi-line tokens are split server-side so each
    /// emitted token stays on a single line.
    len: u32,
    /// Coarse highlight category (keyword, builtin, string, number,
    /// comment, doc_comment). Frontend maps this to a CSS class.
    kind: []const u8,
};

const SourceJson = struct {
    lines: []const []const u8,
    tokens: []const SourceToken,
};

const RangeBounds = struct { begin: usize, end: usize };

fn handleSource(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
) !void {
    var path_param: ?[]const u8 = null;
    var start_line: ?u32 = null;
    var end_line: ?u32 = null;

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "path")) {
            path_param = val;
        } else if (std.mem.eql(u8, key, "start")) {
            start_line = std.fmt.parseInt(u32, val, 10) catch null;
        } else if (std.mem.eql(u8, key, "end")) {
            end_line = std.fmt.parseInt(u32, val, 10) catch null;
        }
    }

    const file_path = path_param orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?path=\n",
    );
    const start = start_line orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?start=\n",
    );
    const end = end_line orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?end=\n",
    );
    if (end < start) return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "end < start\n",
    );

    const decoded_path = try percentDecodeAlloc(allocator, file_path);
    defer allocator.free(decoded_path);

    const file = std.fs.cwd().openFile(decoded_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return respondBytes(
            request,
            .not_found,
            "text/plain; charset=utf-8",
            "source file not found\n",
        ),
        else => return err,
    };
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, SOURCE_MAX_BYTES);
    defer allocator.free(contents);

    const range = computeLineRange(contents, start, end);

    var lines = std.ArrayList([]const u8){};
    defer lines.deinit(allocator);
    {
        var line_start: usize = range.begin;
        var i: usize = range.begin;
        while (i < range.end) : (i += 1) {
            if (contents[i] == '\n') {
                var line_end = i;
                if (line_end > line_start and contents[line_end - 1] == '\r') line_end -= 1;
                try lines.append(allocator, contents[line_start..line_end]);
                line_start = i + 1;
            }
        }
        if (line_start < range.end) {
            var tail_end = range.end;
            if (tail_end > line_start and contents[tail_end - 1] == '\r') tail_end -= 1;
            try lines.append(allocator, contents[line_start..tail_end]);
        }
    }

    var tokens = std.ArrayList(SourceToken){};
    defer tokens.deinit(allocator);

    if (std.mem.endsWith(u8, decoded_path, ".zig")) {
        try collectTokens(allocator, contents, range, &tokens);
    }

    const payload = SourceJson{ .lines = lines.items, .tokens = tokens.items };
    const blob = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(blob);
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
}

// ---- Agent / MCP endpoints (trace, fn_source, find, entries) -------------

const TraceQuery = struct {
    arch: ?[]const u8 = null,
    sha: ?[]const u8 = null,
    entry: ?[]const u8 = null,
    depth: u32 = 6,
    // Default-on: most exploratory traces want debug/stdlib leaves folded.
    // Pass `hide_debug=0` / `hide_library=0` to opt back into full fidelity.
    hide_debug: bool = true,
    hide_library: bool = true,
    /// Output format: "text" (default, indented tree) or "json" (compact
    /// machine-readable tree with stats wrapper).
    format: []const u8 = "text",
    /// Comma-separated list of patterns to exclude from the trace as
    /// folded `-` leaves. Empty by default. Supports `module.*` prefix
    /// globs and bare substrings.
    excludes: []const u8 = "",
};

fn parseTraceQuery(query: []const u8) TraceQuery {
    var q: TraceQuery = .{};
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const k = pair[0..eq];
        const v = pair[eq + 1 ..];
        if (std.mem.eql(u8, k, "arch")) q.arch = v;
        if (std.mem.eql(u8, k, "sha")) q.sha = v;
        if (std.mem.eql(u8, k, "entry") or std.mem.eql(u8, k, "name") or std.mem.eql(u8, k, "fn")) q.entry = v;
        if (std.mem.eql(u8, k, "depth")) q.depth = std.fmt.parseInt(u32, v, 10) catch q.depth;
        if (std.mem.eql(u8, k, "hide_debug")) q.hide_debug = isTruthy(v);
        if (std.mem.eql(u8, k, "hide_library")) q.hide_library = isTruthy(v);
        if (std.mem.eql(u8, k, "format")) q.format = v;
        if (std.mem.eql(u8, k, "exclude") or std.mem.eql(u8, k, "excludes")) q.excludes = v;
    }
    return q;
}

fn isTruthy(v: []const u8) bool {
    return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "on");
}

/// Resolve a `(sha, arch)` pair to an in-memory live graph + lookup maps.
/// `sha` is treated as HEAD when null/empty/"HEAD"; non-HEAD lookups are
/// rejected since the registry only stores serialized blobs for those.
fn resolveLiveGraph(
    state: *const ServerState,
    sha_opt: ?[]const u8,
    arch_opt: ?[]const u8,
) !struct { graph: *const Graph, maps: render.Maps, arch: []const u8 } {
    if (sha_opt) |s| {
        if (s.len > 0 and !std.mem.eql(u8, s, "HEAD")) return error.NonHeadNotSupported;
    }
    const arch = arch_opt orelse state.default_arch;
    const arch_eff = if (arch.len == 0) state.default_arch else arch;
    const g = state.graphs.getPtr(arch_eff) orelse return error.UnknownArch;
    const m = state.lookups.get(arch_eff) orelse return error.UnknownArch;
    return .{ .graph = g, .maps = m, .arch = arch_eff };
}

fn handleTrace(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    const q = parseTraceQuery(query);
    const entry_name_raw = q.entry orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?entry=<fn name>\n",
    );

    const entry_name = try percentDecodeAlloc(allocator, entry_name_raw);
    defer allocator.free(entry_name);

    const live = resolveLiveGraph(state, q.sha, q.arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported by /api/trace yet (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch (try /api/arches)\n",
        ),
        else => return err,
    };

    const fp: *const Function = live.maps.by_name.get(entry_name) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "function not found\n",
    );

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();

    // Parse exclude patterns (comma-separated, percent-decoded as a whole
    // string). Empty list when none requested. Owned by the per-request
    // arena so the slices stay valid for the renderer.
    const excludes_raw = try percentDecodeAlloc(allocator, q.excludes);
    defer allocator.free(excludes_raw);
    var excludes_list = std.ArrayList([]const u8){};
    defer excludes_list.deinit(allocator);
    if (excludes_raw.len > 0) {
        var eit = std.mem.splitScalar(u8, excludes_raw, ',');
        while (eit.next()) |pat| {
            const trimmed = std.mem.trim(u8, pat, " \t");
            if (trimmed.len > 0) try excludes_list.append(allocator, trimmed);
        }
    }

    const ctx: render.Ctx = .{
        .by_id = &live.maps.by_id,
        .by_name = &live.maps.by_name,
        .hide_debug = q.hide_debug,
        .hide_library = q.hide_library,
        .excludes = excludes_list.items,
    };
    // Stats walk feeds either the JSON wrapper or the text header.
    const stats = render.statsTrace(arena.allocator(), ctx, fp, q.depth) catch render.TraceStats{};

    if (std.mem.eql(u8, q.format, "json")) {
        render.renderTraceJson(arena.allocator(), &aw.writer, ctx, fp, q.depth, stats) catch |err| {
            return respondBytes(
                request,
                .internal_server_error,
                "text/plain; charset=utf-8",
                @errorName(err),
            );
        };
        return respondBytes(request, .ok, "application/json; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
    }
    if (std.mem.eql(u8, q.format, "compact")) {
        render.renderTraceCompact(arena.allocator(), &aw.writer, ctx, fp, q.depth, stats) catch |err| {
            return respondBytes(
                request,
                .internal_server_error,
                "text/plain; charset=utf-8",
                @errorName(err),
            );
        };
        return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
    }

    if (stats.top_fanout > 0) {
        try aw.writer.print(
            "trace: {d} fns, {d} at depth cap (depth={d}), top fanout {s} ({d} calls)\n\n",
            .{ stats.fns_visited, stats.at_cap, q.depth, stats.top_name, stats.top_fanout },
        );
    } else {
        try aw.writer.print(
            "trace: {d} fns, {d} at depth cap (depth={d})\n\n",
            .{ stats.fns_visited, stats.at_cap, q.depth },
        );
    }
    render.renderTrace(arena.allocator(), &aw.writer, ctx, fp, q.depth) catch |err| {
        return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            @errorName(err),
        );
    };
    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

fn handleFnSource(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    const q = parseTraceQuery(query);
    const name_raw = q.entry orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?name=<fn name>\n",
    );
    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);

    const live = resolveLiveGraph(state, q.sha, q.arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch\n",
        ),
        else => return err,
    };

    const fp: *const Function = live.maps.by_name.get(name) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "function not found\n",
    );

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    render.printFnSource(allocator, &aw.writer, fp) catch |err| return respondBytes(
        request,
        .internal_server_error,
        "text/plain; charset=utf-8",
        @errorName(err),
    );
    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

fn handleFind(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var q_arch: ?[]const u8 = null;
    var q_sha: ?[]const u8 = null;
    var q_query: ?[]const u8 = null;
    var q_limit: u32 = 200;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const k = pair[0..eq];
        const v = pair[eq + 1 ..];
        if (std.mem.eql(u8, k, "arch")) q_arch = v;
        if (std.mem.eql(u8, k, "sha")) q_sha = v;
        if (std.mem.eql(u8, k, "q") or std.mem.eql(u8, k, "query")) q_query = v;
        if (std.mem.eql(u8, k, "limit")) q_limit = std.fmt.parseInt(u32, v, 10) catch q_limit;
    }
    const needle_raw = q_query orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?q=<substr>\n",
    );
    const needle = try percentDecodeAlloc(allocator, needle_raw);
    defer allocator.free(needle);

    const live = resolveLiveGraph(state, q_sha, q_arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch\n",
        ),
        else => return err,
    };

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    var matches: u32 = 0;
    var aux_buf: [128]u8 = undefined;
    for (live.graph.functions) |f| {
        if (std.mem.indexOf(u8, f.name, needle) == null) continue;
        // Concatenate entry tag + reach count into the aux column.
        // `(reached by N)` makes hub functions visually distinct from
        // local helpers — same name lookup, very different blast radius.
        const tag = render.entryTag(f);
        const aux: []const u8 = if (f.entry_reach > 0 and tag.len > 0)
            (std.fmt.bufPrint(&aux_buf, "{s} (reached by {d})", .{ tag, f.entry_reach }) catch tag)
        else if (f.entry_reach > 0)
            (std.fmt.bufPrint(&aux_buf, "(reached by {d})", .{f.entry_reach}) catch "")
        else
            tag;
        try render.writePaddedName(&aw.writer, "", f.name, aux);
        try render.writeLoc(&aw.writer, f.def_loc, "");
        try aw.writer.writeAll("\n");
        matches += 1;
        if (matches >= q_limit) {
            try aw.writer.writeAll("(truncated)\n");
            break;
        }
    }
    if (matches == 0) try aw.writer.writeAll("(no matches)\n");
    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

fn handleType(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    const q = parseTraceQuery(query);
    const name_raw = q.entry orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?name=<type qname>\n",
    );
    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);

    const live = resolveLiveGraph(state, q.sha, q.arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch\n",
        ),
        else => return err,
    };

    // Look up the Definition by qualified name. Linear scan over the
    // per-arch definitions list — small enough (~hundreds) that an
    // index isn't worth the maintenance cost yet.
    var def_opt: ?*const types.Definition = null;
    for (live.graph.definitions) |*d| {
        if (std.mem.eql(u8, d.qualified_name, name) or std.mem.eql(u8, d.name, name)) {
            def_opt = d;
            break;
        }
    }
    const def = def_opt orelse {
        // Fallback: maybe the user passed a function name instead — give
        // a hint so they don't waste a second tool call.
        if (live.maps.by_name.get(name)) |fp| {
            var aw = std.io.Writer.Allocating.init(allocator);
            defer aw.deinit();
            try aw.writer.print("{s} is a function, not a type — use callgraph_src or callgraph_loc.\nat {s}:{d}\n", .{ fp.name, render.shortFile(fp.def_loc.file), fp.def_loc.line });
            return respondBytes(request, .not_found, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
        }
        return respondBytes(
            request,
            .not_found,
            "text/plain; charset=utf-8",
            "type not found\n",
        );
    };

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    const visibility: []const u8 = if (def.is_pub) "pub " else "";
    try aw.writer.print(
        "{s}{s} ({s}) — {s}:{d}-{d}\n---\n",
        .{ visibility, def.qualified_name, @tagName(def.kind), render.shortFile(def.file), def.line_start, def.line_end },
    );

    // Read just the line range out of the source file. Definitions can be
    // sizeable (full struct bodies), so cap at 64KB to avoid pathological
    // payload growth.
    const file = std.fs.openFileAbsolute(def.file, .{}) catch |err| {
        try aw.writer.print("(open {s}: {s})\n", .{ def.file, @errorName(err) });
        return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
    };
    defer file.close();
    const contents = try file.readToEndAlloc(allocator, 8 * 1024 * 1024);
    defer allocator.free(contents);

    // Compute byte offsets for [line_start, line_end].
    var line: u32 = 1;
    var off: usize = 0;
    var start_off: usize = 0;
    var end_off: usize = contents.len;
    while (off < contents.len) : (off += 1) {
        if (line == def.line_start and start_off == 0) start_off = off;
        if (contents[off] == '\n') {
            line += 1;
            if (line > def.line_end) {
                end_off = off + 1;
                break;
            }
        }
    }
    if (start_off == 0 and def.line_start > 1) start_off = contents.len; // line not found
    const slice = contents[start_off..@min(end_off, contents.len)];
    const cap: usize = 64 * 1024;
    if (slice.len > cap) {
        try aw.writer.writeAll(slice[0..cap]);
        try aw.writer.print("\n... (truncated; full body is {d} bytes)\n", .{slice.len});
    } else {
        try aw.writer.writeAll(slice);
    }
    if (slice.len == 0 or slice[slice.len - 1] != '\n') try aw.writer.writeAll("\n");
    try aw.writer.writeAll("---\n");

    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

fn handleReaches(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var q_arch: ?[]const u8 = null;
    var q_sha: ?[]const u8 = null;
    var q_from: ?[]const u8 = null;
    var q_to: ?[]const u8 = null;
    var q_max: u32 = 24;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const k = pair[0..eq];
        const v = pair[eq + 1 ..];
        if (std.mem.eql(u8, k, "arch")) q_arch = v;
        if (std.mem.eql(u8, k, "sha")) q_sha = v;
        if (std.mem.eql(u8, k, "from")) q_from = v;
        if (std.mem.eql(u8, k, "to")) q_to = v;
        if (std.mem.eql(u8, k, "max")) q_max = std.fmt.parseInt(u32, v, 10) catch q_max;
    }
    const from_raw = q_from orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?from=<fn name>\n",
    );
    const to_raw = q_to orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?to=<fn name>\n",
    );
    const from = try percentDecodeAlloc(allocator, from_raw);
    defer allocator.free(from);
    const to = try percentDecodeAlloc(allocator, to_raw);
    defer allocator.free(to);

    const live = resolveLiveGraph(state, q_sha, q_arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch\n",
        ),
        else => return err,
    };

    const from_fp: *const Function = live.maps.by_name.get(from) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "from function not found\n",
    );
    const to_fp: *const Function = live.maps.by_name.get(to) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "to function not found\n",
    );

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();

    const path = findShortestPath(allocator, live.graph, &live.maps, from_fp.id, to_fp.id, q_max) catch |err| switch (err) {
        error.OutOfMemory => return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            "out of memory\n",
        ),
    };
    defer if (path) |p| allocator.free(p);

    if (path == null) {
        try aw.writer.print("no path from {s} to {s} within {d} hops (try increasing max)\n", .{ from_fp.name, to_fp.name, q_max });
        return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
    }

    try aw.writer.print("path ({d} hops):\n", .{path.?.len - 1});
    for (path.?, 0..) |id, i| {
        const fp = live.maps.by_id.get(id) orelse continue;
        try aw.writer.print("{d} {s}\n", .{ i, fp.name });
    }
    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

/// BFS forward from `from` looking for `to`, walking the same intra-atom
/// edges as `computeEntryReach`. Returns the shortest path as an owned
/// slice of FnIds (caller frees), or null if no path within `max_hops`.
fn findShortestPath(
    allocator: std.mem.Allocator,
    graph: *const Graph,
    maps: *const render.Maps,
    from: types.FnId,
    to: types.FnId,
    max_hops: u32,
) std.mem.Allocator.Error!?[]types.FnId {
    if (from == to) {
        const buf = try allocator.alloc(types.FnId, 1);
        buf[0] = from;
        return buf;
    }
    const fns = graph.functions;
    if (from >= fns.len or to >= fns.len) return null;

    // BFS with parent pointers. parent[id] = predecessor on shortest path,
    // or sentinel `null_id` for unvisited (we use fns.len as the sentinel).
    const null_id: u32 = @intCast(fns.len);
    var parent = try allocator.alloc(u32, fns.len);
    defer allocator.free(parent);
    @memset(parent, null_id);
    const depth = try allocator.alloc(u32, fns.len);
    defer allocator.free(depth);
    @memset(depth, 0);

    var queue = std.ArrayList(types.FnId){};
    defer queue.deinit(allocator);
    try queue.append(allocator, from);
    parent[from] = from; // mark visited (self-parent for the source)

    var head: usize = 0;
    while (head < queue.items.len) {
        const cur = queue.items[head];
        head += 1;
        if (depth[cur] >= max_hops) continue;
        try walkIntraReachable(allocator, fns, &maps.by_name, cur, fns[cur].intra, &queue, parent, depth);
        if (parent[to] != null_id) break;
    }

    if (parent[to] == null_id) return null;

    // Reconstruct path: walk parent chain from `to` back to `from`.
    var rev = std.ArrayList(types.FnId){};
    defer rev.deinit(allocator);
    var cur: types.FnId = to;
    while (true) {
        try rev.append(allocator, cur);
        if (cur == from) break;
        cur = parent[cur];
    }
    const out = try allocator.alloc(types.FnId, rev.items.len);
    var i: usize = 0;
    while (i < rev.items.len) : (i += 1) out[i] = rev.items[rev.items.len - 1 - i];
    return out;
}

fn walkIntraReachable(
    allocator: std.mem.Allocator,
    fns: []types.Function,
    by_name: *const std.StringHashMap(*const types.Function),
    parent_id: types.FnId,
    atoms: []const types.Atom,
    queue: *std.ArrayList(types.FnId),
    parent: []u32,
    depth: []u32,
) std.mem.Allocator.Error!void {
    for (atoms) |atom| {
        switch (atom) {
            .call => |c| {
                if (c.kind == .indirect or c.kind == .vtable or c.kind == .leaf_userspace) continue;
                var to_id: ?types.FnId = c.to;
                if (to_id == null) {
                    if (by_name.get(c.name)) |fp| to_id = fp.id;
                }
                const id = to_id orelse continue;
                if (id >= fns.len) continue;
                if (parent[id] != @as(u32, @intCast(fns.len))) continue; // already visited
                parent[id] = parent_id;
                depth[id] = depth[parent_id] + 1;
                try queue.append(allocator, id);
            },
            .branch => |b| for (b.arms) |arm| try walkIntraReachable(allocator, fns, by_name, parent_id, arm.seq, queue, parent, depth),
            .loop => |l| try walkIntraReachable(allocator, fns, by_name, parent_id, l.body, queue, parent, depth),
        }
    }
}

fn handleLoc(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    const q = parseTraceQuery(query);
    const name_raw = q.entry orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?name=<fn name>\n",
    );
    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);

    const live = resolveLiveGraph(state, q.sha, q.arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch\n",
        ),
        else => return err,
    };

    const fp: *const Function = live.maps.by_name.get(name) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "function not found\n",
    );

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    try aw.writer.print("{s}  {s}:{d}", .{ fp.name, render.shortFile(fp.def_loc.file), fp.def_loc.line });
    if (fp.is_entry) {
        if (fp.entry_kind) |k| try aw.writer.print("  {s}", .{render.kindLabel(k)});
    }
    if (fp.is_ast_only) try aw.writer.writeAll("  inlined");
    try aw.writer.writeAll("\n");
    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

fn handleModules(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var q_arch: ?[]const u8 = null;
    var q_sha: ?[]const u8 = null;
    var q_level: u32 = 1;
    var q_intra: bool = false;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const k = pair[0..eq];
        const v = pair[eq + 1 ..];
        if (std.mem.eql(u8, k, "arch")) q_arch = v;
        if (std.mem.eql(u8, k, "sha")) q_sha = v;
        if (std.mem.eql(u8, k, "level")) q_level = std.fmt.parseInt(u32, v, 10) catch q_level;
        if (std.mem.eql(u8, k, "intra")) q_intra = isTruthy(v);
    }

    const live = resolveLiveGraph(state, q_sha, q_arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch\n",
        ),
        else => return err,
    };

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    render.renderModuleGraph(allocator, &aw.writer, live.graph, live.maps, q_level, q_intra) catch |err| {
        return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            @errorName(err),
        );
    };
    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

fn handleCallers(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    const q = parseTraceQuery(query);
    const name_raw = q.entry orelse return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing ?name=<fn name>\n",
    );
    const name = try percentDecodeAlloc(allocator, name_raw);
    defer allocator.free(name);

    const live = resolveLiveGraph(state, q.sha, q.arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch\n",
        ),
        else => return err,
    };

    const fp: *const Function = live.maps.by_name.get(name) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "function not found\n",
    );

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    const sites_opt = live.maps.callers.get(fp.id);
    const sites: []const render.CallerSite = if (sites_opt) |list| list.items else &.{};
    if (sites.len == 0) {
        try aw.writer.writeAll("(no callers found in graph — may be unreachable, indirect-only, or an entry point)\n");
        return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
    }

    // Sort by caller name then site line so output is deterministic and
    // groupable by caller.
    const sorted = try allocator.dupe(render.CallerSite, sites);
    defer allocator.free(sorted);
    std.mem.sort(render.CallerSite, sorted, {}, callerSiteLessThan);

    try aw.writer.print("{d} call sites for {s}:\n", .{ sorted.len, fp.name });
    var kind_buf: [64]u8 = undefined;
    var prev_from_id: ?types.FnId = null;
    for (sorted) |cs| {
        const tag = try std.fmt.bufPrint(&kind_buf, "({s})", .{@tagName(cs.kind)});
        // Repeat-caller sites get a continuation marker so the eye groups
        // them under one caller name without the caller line being noise.
        const display: []const u8 = if (prev_from_id != null and prev_from_id.? == cs.from.id)
            "  ↳"
        else
            cs.from.name;
        try render.writePaddedName(&aw.writer, "  ", display, tag);
        try render.writeLoc(&aw.writer, cs.site, "@ ");
        try aw.writer.writeAll("\n");
        prev_from_id = cs.from.id;
    }
    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

fn callerSiteLessThan(_: void, a: render.CallerSite, b: render.CallerSite) bool {
    const cmp = std.mem.order(u8, a.from.name, b.from.name);
    if (cmp != .eq) return cmp == .lt;
    if (a.site.line != b.site.line) return a.site.line < b.site.line;
    return std.mem.order(u8, a.site.file, b.site.file) == .lt;
}

fn handleEntries(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    const q = parseTraceQuery(query);
    const live = resolveLiveGraph(state, q.sha, q.arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown arch\n",
        ),
        else => return err,
    };
    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    var name_buf: [512]u8 = undefined;
    for (live.graph.entry_points) |ep| {
        const fp_opt = live.maps.by_id.get(ep.fn_id);
        const loc: ?types.SourceLoc = if (fp_opt) |fp| fp.def_loc else null;
        // Append `-> <qualified_name>` after the label so callers know
        // the exact identifier to feed to callgraph_trace / callgraph_src
        // (the entry label is the userspace ABI name, often snake_case).
        const display: []const u8 = if (fp_opt) |fp| blk: {
            const slice = std.fmt.bufPrint(&name_buf, "{s} -> {s}", .{ ep.label, fp.name }) catch break :blk ep.label;
            break :blk slice;
        } else ep.label;
        try render.writePaddedName(&aw.writer, "", display, render.kindLabel(ep.kind));
        if (loc) |l| try render.writeLoc(&aw.writer, l, "");
        try aw.writer.writeAll("\n");
    }
    return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
}

fn computeLineRange(contents: []const u8, start: u32, end: u32) RangeBounds {
    if (start == 0) return .{ .begin = 0, .end = 0 };
    var line: u32 = 1;
    var i: usize = 0;
    var range_begin: ?usize = null;
    var range_end: usize = contents.len;
    while (i <= contents.len) {
        if (line == start and range_begin == null) range_begin = i;
        if (line == end + 1) {
            range_end = i;
            break;
        }
        if (i == contents.len) break;
        if (contents[i] == '\n') line += 1;
        i += 1;
    }
    if (range_begin) |begin| return .{ .begin = begin, .end = range_end };
    return .{ .begin = 0, .end = 0 };
}

fn classifyTokenTag(tag: std.zig.Token.Tag) ?[]const u8 {
    if (tag == .eof or tag == .invalid) return null;
    const tag_name = @tagName(tag);
    if (std.mem.startsWith(u8, tag_name, "keyword_")) return "keyword";
    return switch (tag) {
        .builtin => "builtin",
        .number_literal => "number",
        .string_literal,
        .multiline_string_literal_line,
        .char_literal,
        => "string",
        .doc_comment, .container_doc_comment => "doc_comment",
        else => null,
    };
}

fn collectTokens(
    allocator: std.mem.Allocator,
    contents: []const u8,
    range: RangeBounds,
    out: *std.ArrayList(SourceToken),
) !void {
    const contents_z = try allocator.dupeZ(u8, contents);
    defer allocator.free(contents_z);

    var line_starts = std.ArrayList(usize){};
    defer line_starts.deinit(allocator);
    try line_starts.append(allocator, 0);
    for (contents, 0..) |c, i| {
        if (c == '\n') try line_starts.append(allocator, i + 1);
    }

    var tokenizer = std.zig.Tokenizer.init(contents_z);
    var prev_end: usize = 0;
    while (true) {
        const tok = tokenizer.next();
        try scanCommentsInGap(allocator, contents, prev_end, tok.loc.start, range, line_starts.items, out);
        if (tok.tag == .eof) break;
        prev_end = tok.loc.end;
        if (tok.loc.end <= range.begin) continue;
        if (tok.loc.start >= range.end) break;
        const kind = classifyTokenTag(tok.tag) orelse continue;
        try emitClipped(allocator, contents, tok.loc.start, tok.loc.end, kind, range, line_starts.items, out);
    }
}

fn scanCommentsInGap(
    allocator: std.mem.Allocator,
    contents: []const u8,
    gap_begin: usize,
    gap_end: usize,
    range: RangeBounds,
    line_starts: []const usize,
    out: *std.ArrayList(SourceToken),
) !void {
    if (gap_begin >= gap_end) return;
    var i = gap_begin;
    while (i + 1 < gap_end) {
        if (contents[i] == '/' and contents[i + 1] == '/') {
            const c_start = i;
            while (i < gap_end and contents[i] != '\n') : (i += 1) {}
            try emitClipped(allocator, contents, c_start, i, "comment", range, line_starts, out);
        } else {
            i += 1;
        }
    }
}

fn emitClipped(
    allocator: std.mem.Allocator,
    contents: []const u8,
    start: usize,
    end: usize,
    kind: []const u8,
    range: RangeBounds,
    line_starts: []const usize,
    out: *std.ArrayList(SourceToken),
) !void {
    const s = @max(start, range.begin);
    const e = @min(end, range.end);
    if (s >= e) return;

    var pos: usize = s;
    while (pos < e) {
        const line_idx = byteToLineIdx(line_starts, pos);
        const line_end_byte: usize = if (line_idx + 1 < line_starts.len)
            line_starts[line_idx + 1] - 1
        else
            contents.len;

        const seg_end = @min(e, line_end_byte);
        if (seg_end > pos) {
            const col = pos - line_starts[line_idx] + 1;
            try out.append(allocator, .{
                .line = @intCast(line_idx + 1),
                .col = @intCast(col),
                .len = @intCast(seg_end - pos),
                .kind = kind,
            });
        }
        pos = seg_end + 1;
        if (pos > e) pos = e;
    }
}

fn byteToLineIdx(line_starts: []const usize, offset: usize) usize {
    var lo: usize = 0;
    var hi: usize = line_starts.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (line_starts[mid] <= offset) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo - 1;
}

// ---- Commits + load_commit -----------------------------------------------

const Commit = struct {
    sha: []const u8,
    short: []const u8,
    author: []const u8,
    date: []const u8,
    subject: []const u8,
    /// True iff this commit's `build.zig` supports `-Demit_ir`. Commits
    /// older than the callgraph scaffold lack the option, can't produce
    /// IR, and so can't be reviewed via this tool. The dropdown uses
    /// this to fade incompatible commits instead of letting the user
    /// pick one and watch it fail with a generic build error.
    cg_compatible: bool,
};

const CommitList = struct {
    commits: []const Commit,
};

const GIT_FIELD_SEP = "\x1f";

fn handleCommits(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var limit: u32 = 50;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "limit")) {
            limit = std.fmt.parseInt(u32, val, 10) catch limit;
        }
    }
    if (limit == 0) limit = 50;
    if (limit > 500) limit = 500;

    const limit_arg = try std.fmt.allocPrint(allocator, "-{d}", .{limit});
    defer allocator.free(limit_arg);

    const fmt_arg = "--pretty=format:%H" ++ GIT_FIELD_SEP ++ "%h" ++ GIT_FIELD_SEP ++ "%an" ++ GIT_FIELD_SEP ++ "%aI" ++ GIT_FIELD_SEP ++ "%s";
    const argv = [_][]const u8{ "git", "log", limit_arg, fmt_arg };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
        .cwd = state.git_root,
        .max_output_bytes = 4 * 1024 * 1024,
    }) catch |err| {
        std.debug.print("git log failed: {s}\n", .{@errorName(err)});
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", "git log failed\n");
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| if (code != 0) return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            "git log nonzero exit\n",
        ),
        else => return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            "git log abnormal termination\n",
        ),
    }

    // Compute the set of commits that contain the `-Demit_ir` build
    // option in their ancestry. Anything not in this set predates the
    // callgraph tool's scaffold and would fail with `invalid option:
    // -Demit_ir` if the user tried to load it.
    var compat_set = try buildEmitIrCompatSet(allocator, state.git_root);
    defer {
        var it_keys = compat_set.keyIterator();
        while (it_keys.next()) |k| allocator.free(k.*);
        compat_set.deinit();
    }

    var commit_list = std.ArrayList(Commit){};
    defer commit_list.deinit(allocator);
    var line_it = std.mem.splitScalar(u8, result.stdout, '\n');
    while (line_it.next()) |line| {
        if (line.len == 0) continue;
        var fields_it = std.mem.splitSequence(u8, line, GIT_FIELD_SEP);
        const sha = fields_it.next() orelse continue;
        const short = fields_it.next() orelse continue;
        const author = fields_it.next() orelse continue;
        const date = fields_it.next() orelse continue;
        const subject = fields_it.next() orelse continue;
        try commit_list.append(allocator, .{
            .sha = sha,
            .short = short,
            .author = author,
            .date = date,
            .subject = subject,
            .cg_compatible = compat_set.contains(sha),
        });
    }

    const payload = CommitList{ .commits = commit_list.items };
    const blob = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(blob);
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
}

/// Build a set of full SHAs whose tree contains the `-Demit_ir` option.
/// Strategy: find the commit that introduced "emit_ir" in build.zig, then
/// `git rev-list <introducing>~..HEAD` enumerates the introducing commit
/// plus all descendants reachable from HEAD — exactly the commits whose
/// trees carry the option. On any error returns an empty set; callers
/// then mark every commit incompatible, which is wrong but safe (the user
/// can still try to load and get the real error).
fn buildEmitIrCompatSet(
    allocator: std.mem.Allocator,
    git_root: []const u8,
) !std.StringHashMap(void) {
    var set = std.StringHashMap(void).init(allocator);
    errdefer {
        var it = set.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        set.deinit();
    }

    // 1. Find the introducing commit. `-G"emit_ir"` matches commits whose
    //    diff added/removed any line containing "emit_ir". The oldest
    //    such commit (last line of default reverse-chronological output)
    //    is the one that introduced the option.
    const find_argv = [_][]const u8{
        "git",          "log",      "-G",
        "emit_ir",      "--format=%H", "--",
        "build.zig",
    };
    const find_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &find_argv,
        .cwd = git_root,
        .max_output_bytes = 1024 * 1024,
    }) catch return set;
    defer allocator.free(find_result.stdout);
    defer allocator.free(find_result.stderr);

    var oldest: []const u8 = "";
    var line_it = std.mem.splitScalar(u8, find_result.stdout, '\n');
    while (line_it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) oldest = trimmed;
    }
    if (oldest.len == 0) return set;

    // 2. Enumerate `<introducing>~..HEAD`. Includes the introducing
    //    commit and all descendants reachable from HEAD.
    const range = try std.fmt.allocPrint(allocator, "{s}~..HEAD", .{oldest});
    defer allocator.free(range);
    const list_argv = [_][]const u8{ "git", "rev-list", range };
    const list_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &list_argv,
        .cwd = git_root,
        .max_output_bytes = 16 * 1024 * 1024,
    }) catch return set;
    defer allocator.free(list_result.stdout);
    defer allocator.free(list_result.stderr);

    var sha_it = std.mem.splitScalar(u8, list_result.stdout, '\n');
    while (sha_it.next()) |raw| {
        const sha = std.mem.trim(u8, raw, " \t\r");
        if (sha.len == 0) continue;
        const owned = try allocator.dupe(u8, sha);
        try set.put(owned, {});
    }
    return set;
}

const LoadStatusJson = struct {
    sha: []const u8,
    short: []const u8,
    status: commits.Status,
    arches: []const []const u8,
    default_arch: []const u8,
    @"error": ?[]const u8,
};

fn handleLoadCommit(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var sha: []const u8 = "";
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha")) sha = val;
    }
    if (!isValidSha(sha)) return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing or invalid ?sha=\n",
    );

    const entry = state.registry.requestLoad(sha) catch |err| {
        std.debug.print("requestLoad failed: {s}\n", .{@errorName(err)});
        return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            "load request failed\n",
        );
    };
    return writeStatusJson(allocator, request, state.registry, entry);
}

fn handleLoadCommitStatus(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var sha: []const u8 = "";
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha")) sha = val;
    }
    if (!isValidSha(sha)) return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing or invalid ?sha=\n",
    );

    const reg = state.registry;
    reg.lockShared();
    const entry_opt = reg.entries.get(sha);
    reg.unlockShared();

    if (entry_opt) |entry| return writeStatusJson(allocator, request, reg, entry);

    const payload = LoadStatusJson{
        .sha = sha,
        .short = sha[0..@min(sha.len, 12)],
        .status = .not_loaded,
        .arches = &.{},
        .default_arch = "",
        .@"error" = null,
    };
    const blob = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(blob);
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
}

fn writeStatusJson(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    reg: *commits.Registry,
    entry: *commits.Entry,
) !void {
    reg.lockShared();
    const payload = LoadStatusJson{
        .sha = entry.sha,
        .short = entry.short_sha,
        .status = entry.status,
        .arches = entry.arches.items,
        .default_arch = entry.default_arch,
        .@"error" = entry.error_msg,
    };
    const blob = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    reg.unlockShared();
    defer allocator.free(blob);
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
}

// ---- Diff endpoints -----------------------------------------------------

fn handleDiff(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var sha_a: []const u8 = "";
    var sha_b: []const u8 = "";
    var path_param: []const u8 = "";

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha_a")) sha_a = val;
        if (std.mem.eql(u8, key, "sha_b")) sha_b = val;
        if (std.mem.eql(u8, key, "path")) path_param = val;
    }
    if (!isValidShaOrRef(sha_a) or !isValidShaOrRef(sha_b) or path_param.len == 0) {
        return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "need sha_a, sha_b, path\n");
    }

    const decoded_path = try percentDecodeAlloc(allocator, path_param);
    defer allocator.free(decoded_path);
    const repo_rel = try makeRepoRelative(allocator, state.git_root, decoded_path);
    defer allocator.free(repo_rel);

    const argv = [_][]const u8{ "git", "diff", "--no-color", "-U3", sha_a, sha_b, "--", repo_rel };
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
        .cwd = state.git_root,
        .max_output_bytes = 8 * 1024 * 1024,
    }) catch |err| {
        std.debug.print("git diff failed: {s}\n", .{@errorName(err)});
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", "git diff failed\n");
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return respondBytes(request, .ok, "text/plain; charset=utf-8", result.stdout);
}

const DiffFilesJson = struct {
    files: []const []const u8,
};

fn handleDiffFiles(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    // Same dual shape as handleDiffHunks. Parent mode passes
    // sha_a (older) + sha_b (newer); head mode passes a single sha.
    var sha: []const u8 = "";
    var sha_a: []const u8 = "";
    var sha_b: []const u8 = "";
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha")) sha = val;
        if (std.mem.eql(u8, key, "sha_a")) sha_a = val;
        if (std.mem.eql(u8, key, "sha_b")) sha_b = val;
    }
    const have_pair = sha_a.len > 0 and sha_b.len > 0;
    if (!have_pair and !isValidShaOrRef(sha)) return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing or invalid ?sha= (or sha_a + sha_b)\n",
    );
    if (have_pair and (!isValidShaOrRef(sha_a) or !isValidShaOrRef(sha_b))) {
        return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "invalid sha_a or sha_b\n",
        );
    }

    var argv_buf: [5][]const u8 = undefined;
    const argv: []const []const u8 = if (have_pair) blk: {
        argv_buf[0] = "git";
        argv_buf[1] = "diff";
        argv_buf[2] = "--name-only";
        argv_buf[3] = sha_a;
        argv_buf[4] = sha_b;
        break :blk argv_buf[0..5];
    } else blk: {
        argv_buf[0] = "git";
        argv_buf[1] = "diff";
        argv_buf[2] = "--name-only";
        argv_buf[3] = sha;
        break :blk argv_buf[0..4];
    };
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = state.git_root,
        .max_output_bytes = 4 * 1024 * 1024,
    }) catch |err| {
        std.debug.print("git diff --name-only failed: {s}\n", .{@errorName(err)});
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", "git diff failed\n");
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var files = std.ArrayList([]const u8){};
    defer files.deinit(allocator);
    var line_it = std.mem.splitScalar(u8, result.stdout, '\n');
    while (line_it.next()) |line| {
        if (line.len == 0) continue;
        try files.append(allocator, line);
    }
    const payload = DiffFilesJson{ .files = files.items };
    const blob = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(blob);
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
}

const HunkRange = struct {
    /// Start line on the OLD (secondary commit) side, 1-indexed.
    old_start: u32,
    /// Number of lines on the old side. 0 = pure insertion.
    old_count: u32,
    /// Start line on the NEW (working tree) side, 1-indexed.
    start: u32,
    /// Number of lines on the new side. 0 = pure deletion.
    count: u32,
};

const FileHunks = struct {
    path: []const u8,
    hunks: []const HunkRange,
};

const DiffHunksJson = struct {
    files: []const FileHunks,
};

fn handleDiffHunks(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    // Two call shapes are supported:
    //   ?sha=X            — head mode: diff between working tree and X
    //   ?sha_a=X^&sha_b=X — parent mode: diff between two specific commits
    // Parent mode is the right shape for the review tracker because the
    // reviewable hunks should match the *commits the user is comparing*,
    // not whatever transient state the working tree happens to have.
    var sha: []const u8 = "";
    var sha_a: []const u8 = "";
    var sha_b: []const u8 = "";
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha")) sha = val;
        if (std.mem.eql(u8, key, "sha_a")) sha_a = val;
        if (std.mem.eql(u8, key, "sha_b")) sha_b = val;
    }
    const have_pair = sha_a.len > 0 and sha_b.len > 0;
    if (!have_pair and !isValidShaOrRef(sha)) return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing or invalid ?sha= (or sha_a + sha_b)\n",
    );
    if (have_pair and (!isValidShaOrRef(sha_a) or !isValidShaOrRef(sha_b))) {
        return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "invalid sha_a or sha_b\n",
        );
    }

    var argv_buf: [6][]const u8 = undefined;
    const argv: []const []const u8 = if (have_pair) blk: {
        argv_buf[0] = "git";
        argv_buf[1] = "diff";
        argv_buf[2] = "--unified=0";
        argv_buf[3] = "--no-color";
        argv_buf[4] = sha_a;
        argv_buf[5] = sha_b;
        break :blk argv_buf[0..6];
    } else blk: {
        argv_buf[0] = "git";
        argv_buf[1] = "diff";
        argv_buf[2] = "--unified=0";
        argv_buf[3] = "--no-color";
        argv_buf[4] = sha;
        break :blk argv_buf[0..5];
    };
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = state.git_root,
        .max_output_bytes = 64 * 1024 * 1024,
    }) catch |err| {
        std.debug.print("git diff --unified=0 failed: {s}\n", .{@errorName(err)});
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", "git diff failed\n");
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    var files = std.ArrayList(FileHunks){};
    defer files.deinit(allocator);

    var current_path: ?[]const u8 = null;
    var current_hunks = std.ArrayList(HunkRange){};
    defer current_hunks.deinit(allocator);

    const flushFile = struct {
        fn run(
            gpa: std.mem.Allocator,
            ar: std.mem.Allocator,
            files_out: *std.ArrayList(FileHunks),
            path_opt: *?[]const u8,
            hunks_buf: *std.ArrayList(HunkRange),
        ) !void {
            if (path_opt.*) |p| {
                if (hunks_buf.items.len > 0) {
                    const owned = try ar.dupe(HunkRange, hunks_buf.items);
                    try files_out.append(gpa, .{ .path = p, .hunks = owned });
                }
            }
            path_opt.* = null;
            hunks_buf.clearRetainingCapacity();
        }
    }.run;

    var line_it = std.mem.splitScalar(u8, result.stdout, '\n');
    while (line_it.next()) |line| {
        if (std.mem.startsWith(u8, line, "+++ b/")) {
            try flushFile(allocator, aalloc, &files, &current_path, &current_hunks);
            current_path = try aalloc.dupe(u8, line["+++ b/".len..]);
        } else if (std.mem.startsWith(u8, line, "+++ /dev/null")) {
            try flushFile(allocator, aalloc, &files, &current_path, &current_hunks);
        } else if (std.mem.startsWith(u8, line, "@@")) {
            // @@ -a[,b] +c[,d] @@ ...
            const minus_idx = std.mem.indexOfScalar(u8, line, '-') orelse continue;
            const after_minus = line[minus_idx + 1 ..];
            const old_space = std.mem.indexOfScalar(u8, after_minus, ' ') orelse continue;
            const old_range = after_minus[0..old_space];
            const old_comma = std.mem.indexOfScalar(u8, old_range, ',');
            const old_start_str = if (old_comma) |i| old_range[0..i] else old_range;
            const old_count_str: []const u8 = if (old_comma) |i| old_range[i + 1 ..] else "1";
            const old_start = std.fmt.parseInt(u32, old_start_str, 10) catch continue;
            const old_count = std.fmt.parseInt(u32, old_count_str, 10) catch 1;
            const plus_rest = after_minus[old_space + 1 ..];
            if (plus_rest.len == 0 or plus_rest[0] != '+') continue;
            const after_plus = plus_rest[1..];
            const new_space = std.mem.indexOfScalar(u8, after_plus, ' ') orelse continue;
            const new_range = after_plus[0..new_space];
            const new_comma = std.mem.indexOfScalar(u8, new_range, ',');
            const new_start_str = if (new_comma) |i| new_range[0..i] else new_range;
            const new_count_str: []const u8 = if (new_comma) |i| new_range[i + 1 ..] else "1";
            const new_start = std.fmt.parseInt(u32, new_start_str, 10) catch continue;
            const new_count = std.fmt.parseInt(u32, new_count_str, 10) catch 1;
            try current_hunks.append(allocator, .{
                .old_start = old_start,
                .old_count = old_count,
                .start = new_start,
                .count = new_count,
            });
        }
    }
    try flushFile(allocator, aalloc, &files, &current_path, &current_hunks);

    const payload = DiffHunksJson{ .files = files.items };
    const blob = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(blob);
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
}

// ---- Review state persistence --------------------------------------------

/// On-disk schema for `<git_root>/.callgraph/review/<sha_a>..<sha_b>.json`.
/// Each unit is keyed by a stable id: `<repo-rel-path>:<new_start>:<kind>`
/// where kind is "a" for added or "r" for removed. Parent mode (X^ vs X)
/// is the only mode that persists — both endpoints are immutable so unit
/// ids never shift. Head mode skips the file entirely.
const ReviewStateFile = struct {
    schema: u32 = 1,
    sha_a: []const u8,
    sha_b: []const u8,
    units: std.json.ArrayHashMap(ReviewUnit) = .{},
};

const ReviewUnit = struct {
    reviewed: bool,
    at: []const u8 = "",
    by: []const u8 = "",
};

/// Body of a POST /api/review_state request: toggle one unit.
const ReviewToggle = struct {
    unit_id: []const u8,
    reviewed: bool,
    by: []const u8 = "",
};

fn handleReviewState(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var sha_a: []const u8 = "";
    var sha_b: []const u8 = "";
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha_a")) sha_a = val;
        if (std.mem.eql(u8, key, "sha_b")) sha_b = val;
    }
    if (!isValidSha(sha_a) or !isValidSha(sha_b)) {
        return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "need sha_a and sha_b (parent mode only — full hex shas)\n",
        );
    }

    const file_path = try reviewStateFilePath(allocator, state.git_root, sha_a, sha_b);
    defer allocator.free(file_path);

    if (request.head.method == .GET) {
        return readReviewState(allocator, request, file_path, sha_a, sha_b);
    }
    if (request.head.method == .POST) {
        return mergeReviewState(allocator, request, file_path, sha_a, sha_b);
    }
    return respondBytes(
        request,
        .method_not_allowed,
        "text/plain; charset=utf-8",
        "GET or POST only\n",
    );
}

fn readReviewState(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    file_path: []const u8,
    sha_a: []const u8,
    sha_b: []const u8,
) !void {
    const contents = std.fs.cwd().readFileAlloc(allocator, file_path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => {
            // No state on disk yet — return an empty payload so the
            // frontend can still render checkboxes (all unchecked).
            const empty = ReviewStateFile{
                .sha_a = sha_a,
                .sha_b = sha_b,
            };
            const blob = try std.json.Stringify.valueAlloc(allocator, empty, .{});
            defer allocator.free(blob);
            return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
        },
        else => return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            "failed to read review state\n",
        ),
    };
    defer allocator.free(contents);
    return respondBytes(request, .ok, "application/json; charset=utf-8", contents);
}

fn mergeReviewState(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    file_path: []const u8,
    sha_a: []const u8,
    sha_b: []const u8,
) !void {
    var read_buf: [16 * 1024]u8 = undefined;
    var hdr_buf: [4 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&hdr_buf) catch
        return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "missing body\n");
    const body_len = reader.readSliceShort(&read_buf) catch
        return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "failed to read body\n");
    if (body_len == 0) return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "empty body\n");

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const parsed = std.json.parseFromSliceLeaky(ReviewToggle, aalloc, read_buf[0..body_len], .{
        .ignore_unknown_fields = true,
    }) catch
        return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "invalid JSON body\n");

    if (parsed.unit_id.len == 0) {
        return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "missing unit_id\n");
    }

    // Load existing file (if any), merge the toggle, write atomically.
    var existing = ReviewStateFile{ .sha_a = sha_a, .sha_b = sha_b };
    const existing_bytes = std.fs.cwd().readFileAlloc(aalloc, file_path, 16 * 1024 * 1024) catch null;
    if (existing_bytes) |bytes| {
        existing = std.json.parseFromSliceLeaky(ReviewStateFile, aalloc, bytes, .{
            .ignore_unknown_fields = true,
        }) catch existing;
    }

    // Stamp current time + reviewer.
    var ts_buf: [32]u8 = undefined;
    const now = std.time.timestamp();
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{now}) catch "";

    const id_owned = try aalloc.dupe(u8, parsed.unit_id);
    const at_owned = try aalloc.dupe(u8, ts_str);
    const by_owned = try aalloc.dupe(u8, parsed.by);
    try existing.units.map.put(aalloc, id_owned, .{
        .reviewed = parsed.reviewed,
        .at = at_owned,
        .by = by_owned,
    });

    // Ensure parent dir exists, write atomically (write tmp + rename).
    if (std.fs.path.dirname(file_path)) |dir| {
        std.fs.cwd().makePath(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => {
                std.debug.print("mkdir {s} failed: {s}\n", .{ dir, @errorName(err) });
                return respondBytes(
                    request,
                    .internal_server_error,
                    "text/plain; charset=utf-8",
                    "failed to create review dir\n",
                );
            },
        };
    }

    const new_blob = try std.json.Stringify.valueAlloc(aalloc, existing, .{ .whitespace = .indent_2 });
    const tmp_path = try std.fmt.allocPrint(aalloc, "{s}.tmp", .{file_path});
    {
        const f = std.fs.cwd().createFile(tmp_path, .{ .truncate = true }) catch |err| {
            std.debug.print("create tmp {s} failed: {s}\n", .{ tmp_path, @errorName(err) });
            return respondBytes(
                request,
                .internal_server_error,
                "text/plain; charset=utf-8",
                "failed to write review state\n",
            );
        };
        defer f.close();
        f.writeAll(new_blob) catch |err| {
            std.debug.print("write tmp failed: {s}\n", .{@errorName(err)});
            return respondBytes(
                request,
                .internal_server_error,
                "text/plain; charset=utf-8",
                "failed to write review state\n",
            );
        };
    }
    std.fs.cwd().rename(tmp_path, file_path) catch |err| {
        std.debug.print("rename {s} → {s} failed: {s}\n", .{ tmp_path, file_path, @errorName(err) });
        return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            "failed to install review state\n",
        );
    };

    return respondBytes(request, .ok, "application/json; charset=utf-8", new_blob);
}

fn reviewStateFilePath(
    allocator: std.mem.Allocator,
    git_root: []const u8,
    sha_a: []const u8,
    sha_b: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/.callgraph/review/{s}..{s}.json", .{
        git_root, sha_a, sha_b,
    });
}

// ---- Helpers --------------------------------------------------------------

fn makeRepoRelative(
    allocator: std.mem.Allocator,
    git_root: []const u8,
    path: []const u8,
) ![]u8 {
    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_root = std.fs.realpath(git_root, &rp_buf) catch
        return allocator.dupe(u8, path);

    if (std.fs.path.isAbsolute(path)) {
        if (std.mem.startsWith(u8, path, real_root)) {
            const after = path[real_root.len..];
            const trimmed = if (after.len > 0 and after[0] == '/') after[1..] else after;
            return allocator.dupe(u8, trimmed);
        }
        if (std.mem.indexOf(u8, path, "/cg-worktrees/")) |idx| {
            const after = path[idx + "/cg-worktrees/".len ..];
            if (std.mem.indexOfScalar(u8, after, '/')) |slash| {
                return allocator.dupe(u8, after[slash + 1 ..]);
            }
        }
        return allocator.dupe(u8, path);
    }
    return allocator.dupe(u8, path);
}

fn isValidSha(sha: []const u8) bool {
    if (sha.len < 4 or sha.len > 64) return false;
    for (sha) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!ok) return false;
    }
    return true;
}

fn isValidShaOrRef(s: []const u8) bool {
    if (isValidSha(s)) return true;
    if (s.len == 0 or s.len > 64) return false;
    for (s) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '~' or c == '^' or c == '/' or c == '-' or c == '_' or c == '.';
        if (!ok) return false;
    }
    return true;
}

fn percentDecodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, input.len);
    var w: usize = 0;
    var r: usize = 0;
    while (r < input.len) {
        const c = input[r];
        if (c == '%' and r + 2 < input.len) {
            const hi = std.fmt.charToDigit(input[r + 1], 16) catch {
                out[w] = c;
                w += 1;
                r += 1;
                continue;
            };
            const lo = std.fmt.charToDigit(input[r + 2], 16) catch {
                out[w] = c;
                w += 1;
                r += 1;
                continue;
            };
            out[w] = (@as(u8, hi) << 4) | @as(u8, lo);
            w += 1;
            r += 3;
        } else if (c == '+') {
            out[w] = ' ';
            w += 1;
            r += 1;
        } else {
            out[w] = c;
            w += 1;
            r += 1;
        }
    }
    return allocator.realloc(out, w);
}
