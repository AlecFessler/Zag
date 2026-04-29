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
const review_classifier = @import("review_classifier.zig");
const review_deps_mod = @import("review_deps.zig");
const review_diff = @import("review_diff.zig");
const review_store = @import("review_store.zig");
const review_witness = @import("review_witness.zig");
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
    /// Wall-clock unix seconds when the IR was loaded into this daemon.
    /// Used to compute an "index age" footer on MCP-targeted responses so
    /// agents notice when the daemon is serving stale graphs (e.g. a
    /// long-running daemon spawned before a refactor renamed several
    /// modules). Zero disables the footer entirely.
    index_built_unix: i64,
};

pub fn serve(
    allocator: std.mem.Allocator,
    graphs: *const GraphMap,
    default_arch: []const u8,
    git_root: []const u8,
    registry: *commits.Registry,
    port: u16,
    index_built_unix: i64,
) !void {
    var state = try buildState(allocator, graphs, default_arch, git_root, registry, index_built_unix);
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
    index_built_unix: i64,
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
        .index_built_unix = index_built_unix,
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
        return handleSource(allocator, request, query, state);
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
    if (std.mem.eql(u8, path, "/api/review/open")) {
        return handleReviewOpen(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/review/deps")) {
        return handleReviewDeps(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/review/checkoff")) {
        return handleReviewCheckoff(allocator, request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/review/complete")) {
        return handleReviewComplete(allocator, request, query, state);
    }

    return respondBytes(request, .not_found, "text/plain; charset=utf-8", "not found\n");
}

// ---- Review witnessing seam ----------------------------------------------

/// Record a successful symbol fetch against any open mcp-channel review's
/// deps_required. Called by handleFnSource and handleType *after* their
/// response is built — earlier and a panicking handler (e.g., the
/// synthetic `__zig_*` openFileAbsolute crash) would leave the gate
/// thinking the agent viewed something they actually didn't.
///
/// Witnessable handlers:
///   - `callgraph_src`  (function bodies)
///   - `callgraph_type` (type definitions)
/// `callgraph_trace` is intentionally NOT witnessed: a trace shows the
/// call hierarchy, not the actual code. `loc` and `find` are too cheap
/// to count for similar reasons.
///
/// No-op when the request didn't carry `X-Cg-Channel: mcp` (web GUI
/// requests skip witnessing entirely).
fn recordReviewWitness(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    state: *const ServerState,
    qualified_name: []const u8,
) void {
    const channel = getHeaderValue(request, "x-cg-channel") orelse return;
    if (!std.mem.eql(u8, channel, "mcp")) return;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const store = review_store.Store.init(state.git_root);
    review_witness.recordView(arena.allocator(), &store, qualified_name) catch |err| {
        std.debug.print("review witness failed (non-fatal): {s}\n", .{@errorName(err)});
    };
}

/// Case-insensitive header lookup. Returns the first matching value or
/// null if absent. Standard header lookup pattern for the daemon.
fn getHeaderValue(request: *std.http.Server.Request, name: []const u8) ?[]const u8 {
    var it = request.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

/// Pull a single value from a query string. Returns null when the key
/// isn't present. Does NOT URL-decode — caller does that if needed.
fn getQueryValue(query: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// Minimal URL decoder for query values: `%XX` hex pairs and `+` → space.
/// Anything malformed passes through unchanged so we never refuse to
/// witness on a crafted-but-harmless url.
fn urlDecode(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = std.ArrayList(u8){};
    errdefer out.deinit(alloc);
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '+') {
            try out.append(alloc, ' ');
            i += 1;
        } else if (c == '%' and i + 2 < s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch {
                try out.append(alloc, c);
                i += 1;
                continue;
            };
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch {
                try out.append(alloc, c);
                i += 1;
                continue;
            };
            try out.append(alloc, (hi << 4) | lo);
            i += 3;
        } else {
            try out.append(alloc, c);
            i += 1;
        }
    }
    return out.toOwnedSlice(alloc);
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

/// Index-age threshold (seconds) at which we start adding a freshness footer
/// to MCP-targeted responses. The kernel changes constantly during dev — a
/// graph older than this is increasingly likely to disagree with the
/// working tree (deleted modules, renamed fns, etc.).
const FRESHNESS_FOOTER_AFTER_SECS: i64 = 60 * 60;

/// Build the freshness footer string for MCP-targeted text responses, or
/// return null when the index is fresh enough to skip it. Caller owns the
/// returned slice when non-null.
fn buildFreshnessFooter(allocator: std.mem.Allocator, state: *const ServerState) !?[]u8 {
    if (state.index_built_unix == 0) return null;
    const now = std.time.timestamp();
    const age_s = now - state.index_built_unix;
    if (age_s < FRESHNESS_FOOTER_AFTER_SECS) return null;
    const hours = @divTrunc(age_s, 3600);
    const minutes = @divTrunc(@mod(age_s, 3600), 60);
    return try std.fmt.allocPrint(
        allocator,
        "\n# index age: {d}h{d:0>2}m — restart the daemon if names look stale\n",
        .{ hours, minutes },
    );
}

/// 400-response body for `unknown arch` errors. Always includes the list
/// of arches the daemon actually has loaded, so the agent doesn't need a
/// follow-up `callgraph_arches` round-trip just to recover from a typo or
/// to discover the alternative tag.
fn respondUnknownArch(
    allocator: std.mem.Allocator,
    state: *const ServerState,
    request: *std.http.Server.Request,
) !void {
    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    try buf.appendSlice(allocator, "unknown arch (available: ");
    var first = true;
    var kit = state.graphs.keyIterator();
    while (kit.next()) |k| {
        if (!first) try buf.appendSlice(allocator, ", ");
        first = false;
        try buf.appendSlice(allocator, k.*);
    }
    try buf.appendSlice(allocator, ")\n");
    return respondBytes(request, .bad_request, "text/plain; charset=utf-8", buf.items);
}

/// Like `respondBytes` but for MCP-targeted `text/plain` payloads: appends
/// the freshness footer when the index has aged past the threshold so an
/// agent reading the output notices when it might be looking at deleted /
/// renamed symbols.
fn respondTextWithFreshness(
    allocator: std.mem.Allocator,
    state: *const ServerState,
    request: *std.http.Server.Request,
    status: std.http.Status,
    body: []const u8,
) !void {
    const footer_opt = buildFreshnessFooter(allocator, state) catch null;
    if (footer_opt) |footer| {
        defer allocator.free(footer);
        const combined = try allocator.alloc(u8, body.len + footer.len);
        defer allocator.free(combined);
        @memcpy(combined[0..body.len], body);
        @memcpy(combined[body.len..], footer);
        return respondBytes(request, status, "text/plain; charset=utf-8", combined);
    }
    return respondBytes(request, status, "text/plain; charset=utf-8", body);
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
    state: *const ServerState,
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

    // Resolve repo-relative paths (e.g. `kernel/sched/scheduler.zig` from
    // the review tracker's hunk rows) against the configured git_root so
    // behavior doesn't depend on the daemon's CWD. Absolute paths pass
    // through unchanged — those come from def_loc.file (own checkout) and
    // worktree-mounted secondary commits.
    const resolved_path = if (std.fs.path.isAbsolute(decoded_path))
        try allocator.dupe(u8, decoded_path)
    else
        try std.fs.path.join(allocator, &.{ state.git_root, decoded_path });
    defer allocator.free(resolved_path);

    const file = std.fs.openFileAbsolute(resolved_path, .{}) catch |err| switch (err) {
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
    /// Default-on: drop `debug.assert`, `debug.FullPanic.*`, and
    /// `builtin.returnError` calls entirely (no fold leaf either) — these
    /// are 0-signal in most control-flow investigations and can dominate
    /// 10–25% of trace lines. Pass `hide_assertions=0` when explicitly
    /// investigating panic / failure sites.
    hide_assertions: bool = true,
    /// Default-on: drop `&<bare_ident>` lines (e.g. `&self`, `&buckets`)
    /// that are usually argument captures the IR analyzer flagged as
    /// indirect calls. Pass `hide_ref_captures=0` to keep them.
    hide_ref_captures: bool = true,
    /// Output format: "text" (default for HTTP, indented tree) or "compact"
    /// (the agent-optimized line format; see render.renderTraceCompact).
    format: []const u8 = "text",
    /// Comma-separated list of patterns to exclude from the trace as
    /// folded `-` leaves. Empty by default. Supports `module.*` prefix
    /// globs and bare substrings.
    excludes: []const u8 = "",
    /// Comma-separated list of entry kinds to keep when listing entries.
    /// Empty = no filter (return all). Recognised kinds match
    /// `EntryKind`: `syscall`, `irq`, `trap`, `boot`, `manual`. Used by
    /// `/api/entries` so an agent investigating one subsystem doesn't
    /// have to post-filter ~70 entries on every orientation call.
    kind: []const u8 = "",
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
        if (std.mem.eql(u8, k, "hide_assertions")) q.hide_assertions = isTruthy(v);
        if (std.mem.eql(u8, k, "hide_ref_captures")) q.hide_ref_captures = isTruthy(v);
        if (std.mem.eql(u8, k, "format")) q.format = v;
        if (std.mem.eql(u8, k, "exclude") or std.mem.eql(u8, k, "excludes")) q.excludes = v;
        if (std.mem.eql(u8, k, "kind") or std.mem.eql(u8, k, "kinds")) q.kind = v;
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
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
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
        .hide_assertions = q.hide_assertions,
        .hide_ref_captures = q.hide_ref_captures,
        .excludes = excludes_list.items,
    };
    // Stats walk feeds either the JSON wrapper or the text header.
    const stats = render.statsTrace(arena.allocator(), ctx, fp, q.depth) catch render.TraceStats{};

    if (std.mem.eql(u8, q.format, "compact")) {
        render.renderTraceCompact(arena.allocator(), &aw.writer, ctx, fp, q.depth, stats) catch |err| {
            return respondBytes(
                request,
                .internal_server_error,
                "text/plain; charset=utf-8",
                @errorName(err),
            );
        };
        return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
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
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
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
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
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
    // Witness now — we successfully assembled a response. Earlier
    // (in handleRequest) would mean the gate counts viewing a symbol
    // that ultimately panicked the daemon (the `__zig_*` synthetic
    // case before render.printFnSource grew its non-absolute guard).
    recordReviewWitness(allocator, request, state, fp.name);
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
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
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
        else => return err,
    };

    // Pre-collect matches so we can decide between flat and grouped output
    // and bound the cost of optional signature extraction. We keep counting
    // past the limit so the footer can say HOW MANY matches were dropped —
    // the caller needs that to decide whether to raise `limit` or refine
    // the query.
    var matches_buf = std.ArrayList(*const types.Function){};
    defer matches_buf.deinit(allocator);
    var total_matches: usize = 0;
    for (live.graph.functions) |*f| {
        if (std.mem.indexOf(u8, f.name, needle) == null) continue;
        total_matches += 1;
        if (matches_buf.items.len < q_limit) {
            try matches_buf.append(allocator, f);
        }
    }
    const truncated = total_matches > matches_buf.items.len;
    const dropped = total_matches - matches_buf.items.len;

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    if (matches_buf.items.len == 0) {
        try aw.writer.writeAll("(no matches)\n");
        return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
    }

    // Cheap signature extraction — only for small result sets. Bounded by
    // GROUPED_THRESHOLD so wildcard searches across hundreds of fns don't
    // open every source file. We cache file contents per-handler so multiple
    // matches in the same file pay one read.
    const SIG_BUDGET: usize = 50;
    var file_cache = std.StringHashMap([]u8).init(allocator);
    defer {
        var ci = file_cache.iterator();
        while (ci.next()) |e| allocator.free(e.value_ptr.*);
        file_cache.deinit();
    }
    const want_sigs = matches_buf.items.len <= SIG_BUDGET;

    // Group when the result set is large: scanning 30+ flat lines for the
    // right name is much slower than scanning by file. Threshold deliberately
    // higher than SIG_BUDGET so we never group AND skip signatures.
    const GROUP_THRESHOLD: usize = 30;
    const want_group = matches_buf.items.len > GROUP_THRESHOLD;

    if (want_group) {
        // Sort by (file, name). One header per file, then matches under it.
        std.mem.sort(*const types.Function, matches_buf.items, {}, struct {
            fn lt(_: void, a: *const types.Function, b: *const types.Function) bool {
                const c = std.mem.order(u8, a.def_loc.file, b.def_loc.file);
                if (c != .eq) return c == .lt;
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lt);
    }

    var aux_buf: [128]u8 = undefined;
    var sig_buf: [256]u8 = undefined;
    var prev_file: []const u8 = "";
    for (matches_buf.items) |f| {
        if (want_group) {
            if (!std.mem.eql(u8, f.def_loc.file, prev_file)) {
                if (prev_file.len > 0) try aw.writer.writeAll("\n");
                try aw.writer.print("# {s}\n", .{render.shortFile(f.def_loc.file)});
                prev_file = f.def_loc.file;
            }
        }

        const tag = render.entryTag(f.*);
        const aux: []const u8 = if (f.entry_reach > 0 and tag.len > 0)
            (std.fmt.bufPrint(&aux_buf, "{s} (reached by {d})", .{ tag, f.entry_reach }) catch tag)
        else if (f.entry_reach > 0)
            (std.fmt.bufPrint(&aux_buf, "(reached by {d})", .{f.entry_reach}) catch "")
        else
            tag;
        try render.writePaddedName(&aw.writer, "", f.name, aux);
        if (want_group) {
            try aw.writer.print("  :{d}", .{f.def_loc.line});
        } else {
            try render.writeLoc(&aw.writer, f.def_loc, "");
        }
        if (want_sigs) {
            if (extractSignature(allocator, &file_cache, f, &sig_buf)) |sig| {
                try aw.writer.print("\n  {s}", .{sig});
            }
        }
        try aw.writer.writeAll("\n");
    }
    if (truncated) try aw.writer.print(
        "(truncated; showing {d} of {d}; {d} more — raise `limit` or refine query)\n",
        .{ matches_buf.items.len, total_matches, dropped },
    );
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
}

/// Read just the signature header (`fn foo(...) RetType` up to `{`) of a
/// function and write a single-line summary into `scratch`. Returns null
/// when the source is unreadable or the signature spans more than `scratch`.
/// File contents are cached in `cache` so multiple matches in one file pay
/// one disk read.
fn extractSignature(
    allocator: std.mem.Allocator,
    cache: *std.StringHashMap([]u8),
    f: *const types.Function,
    scratch: []u8,
) ?[]const u8 {
    // Guard against synthetic / IR-only symbols (e.g. `__zig_*` helpers
    // emitted by the compiler) that have no file location, or non-absolute
    // paths that would crash openFileAbsolute's assertion. Same guard
    // pattern as printFnSource — extractSignature was an overlooked
    // second instance that took down the daemon when handleFind walked a
    // result set containing one of these symbols.
    if (f.def_loc.file.len == 0) return null;
    if (!std.fs.path.isAbsolute(f.def_loc.file)) return null;

    const contents = blk: {
        if (cache.get(f.def_loc.file)) |c| break :blk c;
        const file = std.fs.openFileAbsolute(f.def_loc.file, .{}) catch return null;
        defer file.close();
        const c = file.readToEndAlloc(allocator, 8 * 1024 * 1024) catch return null;
        cache.put(f.def_loc.file, c) catch {
            allocator.free(c);
            return null;
        };
        break :blk c;
    };

    // Find the byte offset for line def_loc.line.
    var line: u32 = 1;
    var i: usize = 0;
    var line_off: usize = 0;
    while (i < contents.len) : (i += 1) {
        if (line == f.def_loc.line) {
            line_off = i;
            break;
        }
        if (contents[i] == '\n') line += 1;
    }
    if (line != f.def_loc.line) return null;

    // Scan from line_off to the first '{' on the same logical fn header,
    // tracking paren depth so we don't stop at a default-value `{` inside
    // params (rare but possible).
    var paren_depth: i32 = 0;
    var end: usize = line_off;
    while (end < contents.len) : (end += 1) {
        const c = contents[end];
        if (c == '(') paren_depth += 1;
        if (c == ')') paren_depth -= 1;
        if (c == '{' and paren_depth == 0) break;
    }
    if (end >= contents.len) return null;
    const raw = contents[line_off..end];

    // Collapse whitespace so the one-line summary fits in scratch.
    var out_len: usize = 0;
    var prev_ws = true;
    for (raw) |c| {
        const is_ws = c == ' ' or c == '\t' or c == '\r' or c == '\n';
        if (is_ws) {
            if (!prev_ws and out_len < scratch.len) {
                scratch[out_len] = ' ';
                out_len += 1;
            }
            prev_ws = true;
        } else {
            if (out_len >= scratch.len) return null;
            scratch[out_len] = c;
            out_len += 1;
            prev_ws = false;
        }
    }
    while (out_len > 0 and scratch[out_len - 1] == ' ') out_len -= 1;
    if (out_len == 0) return null;
    return scratch[0..out_len];
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
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
        else => return err,
    };

    // Look up the Definition by qualified name. Linear scan over the
    // per-arch definitions list — small enough (~hundreds) that an
    // index isn't worth the maintenance cost yet.
    const initial = findDefinitionByName(live.graph.definitions, name) orelse {
        // Fallback: maybe the user passed a function name instead — give
        // a hint so they don't waste a second tool call.
        if (live.maps.by_name.get(name)) |fp| {
            var aw_fn = std.io.Writer.Allocating.init(allocator);
            defer aw_fn.deinit();
            try aw_fn.writer.print("{s} is a function, not a type — use callgraph_src or callgraph_loc.\nat {s}:{d}\n", .{ fp.name, render.shortFile(fp.def_loc.file), fp.def_loc.line });
            return respondBytes(request, .not_found, "text/plain; charset=utf-8", aw_fn.writer.buffer[0..aw_fn.writer.end]);
        }
        return respondBytes(
            request,
            .not_found,
            "text/plain; charset=utf-8",
            "type not found\n",
        );
    };

    // Follow trivial alias chains (`pub const X = some.dotted.Y;`) up to
    // a small depth so a single tool call lands on the underlying type
    // instead of a one-line redirect that forces a second lookup.
    const max_follow = 4;
    var chain_buf: [max_follow]*const types.Definition = undefined;
    chain_buf[0] = initial;
    var chain_len: usize = 1;
    var alias_payload_buf: [256]u8 = undefined;
    while (chain_len < max_follow) {
        const cur = chain_buf[chain_len - 1];
        if (cur.kind != .constant) break;
        const rhs_opt = readConstantAliasRhs(allocator, cur, &alias_payload_buf) catch null;
        const rhs = rhs_opt orelse break;
        const target = resolveAliasTarget(live.graph.definitions, rhs, cur) orelse break;
        if (target == cur) break;
        // Loop / repeat guard.
        var seen = false;
        for (chain_buf[0..chain_len]) |c| if (c == target) {
            seen = true;
            break;
        };
        if (seen) break;
        chain_buf[chain_len] = target;
        chain_len += 1;
        // Stop as soon as we land on a real type body — further hops would
        // walk past the answer the caller asked for.
        if (target.kind != .constant) break;
    }
    const def = chain_buf[chain_len - 1];

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    const visibility: []const u8 = if (def.is_pub) "pub " else "";
    if (chain_len > 1) {
        try aw.writer.writeAll("(followed alias: ");
        for (chain_buf[0..chain_len], 0..) |c, i| {
            if (i > 0) try aw.writer.writeAll(" → ");
            try aw.writer.writeAll(c.qualified_name);
        }
        try aw.writer.writeAll(")\n");
    }
    try aw.writer.print(
        "{s}{s} ({s}) — {s}:{d}-{d}\n---\n",
        .{ visibility, def.qualified_name, @tagName(def.kind), render.shortFile(def.file), def.line_start, def.line_end },
    );

    // Read just the line range out of the source file. Definitions can be
    // sizeable (full struct bodies), so cap at 64KB to avoid pathological
    // payload growth. Synthetic / IR-only definitions (no path or
    // non-absolute path) crash openFileAbsolute's assertion; treat them
    // as unreadable instead.
    if (def.file.len == 0 or !std.fs.path.isAbsolute(def.file)) {
        try aw.writer.print("(no source path for synthetic / IR-only def {s})\n", .{def.qualified_name});
        return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
    }
    const file = std.fs.openFileAbsolute(def.file, .{}) catch |err| {
        try aw.writer.print("(open {s}: {s})\n", .{ def.file, @errorName(err) });
        return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
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

    // Witness for the review-deps gate: agent successfully fetched the
    // type body (or its alias terminus). Use the *original* requested
    // name so callers that look up by either alias-or-target match.
    recordReviewWitness(allocator, request, state, name);
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
}

fn findDefinitionByName(defs: []const types.Definition, name: []const u8) ?*const types.Definition {
    for (defs) |*d| {
        if (std.mem.eql(u8, d.qualified_name, name) or std.mem.eql(u8, d.name, name)) return d;
    }
    return null;
}

/// Resolve `rhs` (a dotted identifier chain like `port.Port` from an
/// alias's RHS) to a concrete Definition, excluding `from` so an alias
/// never resolves to itself.
///
/// The RHS is in the alias author's import-table namespace, not in the
/// global qname namespace, so a literal `qname == rhs` lookup almost
/// never hits — we don't have the import table here. Two heuristics
/// instead, in priority order:
///   1. Exact qualified_name match.
///   2. Suffix match: any qname ending in `.<rhs>` (covers re-exports
///      via short module aliases — e.g. RHS `port.Port` matches
///      `sched.port.Port`).
///   3. Bare-name fallback: a single non-`from` Definition whose
///      simple `name` equals the last segment of RHS.
fn resolveAliasTarget(
    defs: []const types.Definition,
    rhs: []const u8,
    from: *const types.Definition,
) ?*const types.Definition {
    // 1) Exact qualified_name match.
    for (defs) |*d| {
        if (d == from) continue;
        if (std.mem.eql(u8, d.qualified_name, rhs)) return d;
    }
    // 2) Suffix match — `<anything>.rhs`. Reject the bare-prefix case
    //    (just `rhs`) since 1) already handled it.
    var suffix_unique: ?*const types.Definition = null;
    var suffix_count: usize = 0;
    for (defs) |*d| {
        if (d == from) continue;
        const q = d.qualified_name;
        if (q.len <= rhs.len + 1) continue;
        if (q[q.len - rhs.len - 1] != '.') continue;
        if (!std.mem.eql(u8, q[q.len - rhs.len ..], rhs)) continue;
        suffix_count += 1;
        suffix_unique = d;
        if (suffix_count > 1) break;
    }
    if (suffix_count == 1) return suffix_unique;
    // 3) Bare-name fallback — pick when exactly one non-`from` def has
    //    `name` == rhs's last segment. Multiple matches mean ambiguous;
    //    bail rather than guess.
    const dot = std.mem.lastIndexOfScalar(u8, rhs, '.');
    const tail = if (dot) |d| rhs[d + 1 ..] else rhs;
    var bare_unique: ?*const types.Definition = null;
    var bare_count: usize = 0;
    for (defs) |*d| {
        if (d == from) continue;
        if (!std.mem.eql(u8, d.name, tail)) continue;
        bare_count += 1;
        bare_unique = d;
        if (bare_count > 1) break;
    }
    if (bare_count == 1) return bare_unique;
    return null;
}

/// Read just the source slice for a single-line `const X = ...;` definition
/// and return the dotted-identifier RHS if it's a trivial alias.
/// The returned slice points into `scratch`; caller must not free it.
/// Returns null when the body isn't a trivial alias (multi-line, has braces,
/// numeric literal, function call, etc.).
fn readConstantAliasRhs(
    allocator: std.mem.Allocator,
    def: *const types.Definition,
    scratch: []u8,
) !?[]const u8 {
    if (def.line_end != def.line_start) return null;
    if (def.file.len == 0 or !std.fs.path.isAbsolute(def.file)) return null;
    const file = std.fs.openFileAbsolute(def.file, .{}) catch return null;
    defer file.close();
    const contents = try file.readToEndAlloc(allocator, 8 * 1024 * 1024);
    defer allocator.free(contents);

    // Locate the single source line for this def.
    var line: u32 = 1;
    var off: usize = 0;
    var line_start: usize = 0;
    while (off < contents.len) : (off += 1) {
        if (line == def.line_start) {
            line_start = off;
            break;
        }
        if (contents[off] == '\n') line += 1;
    }
    if (line != def.line_start) return null;
    const line_end = std.mem.indexOfScalarPos(u8, contents, line_start, '\n') orelse contents.len;
    const src = std.mem.trim(u8, contents[line_start..line_end], " \t\r");

    // Match: `(pub )?const NAME = <rhs>;`. Anything fancier (calls, braces,
    // operators, slices) means it's not a trivial alias and we bail.
    var rest = src;
    if (std.mem.startsWith(u8, rest, "pub ")) rest = rest[4..];
    if (!std.mem.startsWith(u8, rest, "const ")) return null;
    rest = rest[6..];
    const eq = std.mem.indexOfScalar(u8, rest, '=') orelse return null;
    rest = std.mem.trim(u8, rest[eq + 1 ..], " \t");
    if (!std.mem.endsWith(u8, rest, ";")) return null;
    var rhs = rest[0 .. rest.len - 1];
    rhs = std.mem.trim(u8, rhs, " \t");
    if (rhs.len == 0) return null;
    // Reject anything with non-identifier characters between dots.
    for (rhs) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '_' or c == '.';
        if (!ok) return null;
    }
    // Must lead with an alphabetic / underscore (otherwise it's a number).
    if (!((rhs[0] >= 'a' and rhs[0] <= 'z') or (rhs[0] >= 'A' and rhs[0] <= 'Z') or rhs[0] == '_')) return null;

    if (rhs.len > scratch.len) return null;
    @memcpy(scratch[0..rhs.len], rhs);
    return scratch[0..rhs.len];
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
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
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

    var search_stats: ReachesStats = .{ .visited = 0, .cap_hit = false };
    const path = findShortestPath(allocator, live.graph, &live.maps, from_fp.id, to_fp.id, q_max, &search_stats) catch |err| switch (err) {
        error.OutOfMemory => return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            "out of memory\n",
        ),
    };
    defer if (path) |p| allocator.free(p);

    if (path == null) {
        if (search_stats.cap_hit) {
            try aw.writer.print(
                "no path from {s} to {s} within {d} hops (depth limit hit; reached {d} fns; try increasing max)\n",
                .{ from_fp.name, to_fp.name, q_max, search_stats.visited },
            );
        } else {
            try aw.writer.print(
                "no path from {s} to {s} (search exhausted; {s} transitively reaches {d} fns, {s} not among them)\n",
                .{ from_fp.name, to_fp.name, from_fp.name, search_stats.visited, to_fp.name },
            );
            // Heuristic: if the source is an entry point whose direct-call
            // closure is tiny (≤ 4 fns), it's almost certainly a trampoline
            // that dispatches to its real targets through a runtime table
            // (the syscall vector, the IDT, vtables, ...). Tell the agent
            // which other tools to reach for instead of letting them stare
            // at a confusing dead-end.
            if (from_fp.is_entry and search_stats.visited <= 4) {
                const kind_tag: []const u8 = if (from_fp.entry_kind) |k| @tagName(k) else "unknown";
                const article: []const u8 = if (kind_tag.len > 0 and (kind_tag[0] == 'a' or kind_tag[0] == 'i' or kind_tag[0] == 'u')) "an" else "a";
                try aw.writer.print(
                    "  hint: {s} is {s} {s} entry that reaches only {d} fn(s) by direct calls — its real targets are likely reached through a runtime dispatch table (e.g. the syscall/IDT vector) which BFS does not follow. To investigate {s}, try `callgraph_callers {s}` (who calls it directly) or `callgraph_entries` to enumerate the dispatch handlers.\n",
                    .{
                        from_fp.name,
                        article,
                        kind_tag,
                        search_stats.visited,
                        to_fp.name,
                        to_fp.name,
                    },
                );
            }
        }
        return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
    }

    try aw.writer.print("path ({d} hops):\n", .{path.?.len - 1});
    for (path.?, 0..) |id, i| {
        const fp = live.maps.by_id.get(id) orelse continue;
        try aw.writer.print("{d} {s}\n", .{ i, fp.name });
    }
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
}

/// Outcome statistics for a `findShortestPath` run. `visited` is how many
/// distinct functions BFS reached (including `from`). `cap_hit` flips to
/// true the first time BFS would have descended past `max_hops` — i.e.,
/// the search was depth-limited rather than fully exhausted.
const ReachesStats = struct {
    visited: u32,
    cap_hit: bool,
};

/// BFS forward from `from` looking for `to`, walking the same intra-atom
/// edges as `computeEntryReach`. Returns the shortest path as an owned
/// slice of FnIds (caller frees), or null if no path within `max_hops`.
/// Fills `stats` so callers can distinguish depth-limited from exhausted.
fn findShortestPath(
    allocator: std.mem.Allocator,
    graph: *const Graph,
    maps: *const render.Maps,
    from: types.FnId,
    to: types.FnId,
    max_hops: u32,
    stats: *ReachesStats,
) std.mem.Allocator.Error!?[]types.FnId {
    if (from == to) {
        const buf = try allocator.alloc(types.FnId, 1);
        buf[0] = from;
        stats.visited = 1;
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
        if (depth[cur] >= max_hops) {
            stats.cap_hit = true;
            continue;
        }
        try walkIntraReachable(allocator, fns, &maps.by_name, cur, fns[cur].intra, &queue, parent, depth);
        if (parent[to] != null_id) break;
    }

    stats.visited = @intCast(queue.items.len);
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
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
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
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
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
    var q_min_edges: u32 = 1;
    var q_exclude_external: bool = false;
    var q_direction: render.ModuleDirection = .out;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const k = pair[0..eq];
        const v = pair[eq + 1 ..];
        if (std.mem.eql(u8, k, "arch")) q_arch = v;
        if (std.mem.eql(u8, k, "sha")) q_sha = v;
        if (std.mem.eql(u8, k, "level")) q_level = std.fmt.parseInt(u32, v, 10) catch q_level;
        if (std.mem.eql(u8, k, "intra")) q_intra = isTruthy(v);
        if (std.mem.eql(u8, k, "min_edges")) q_min_edges = std.fmt.parseInt(u32, v, 10) catch q_min_edges;
        if (std.mem.eql(u8, k, "exclude_external")) q_exclude_external = isTruthy(v);
        if (std.mem.eql(u8, k, "direction")) {
            if (std.mem.eql(u8, v, "in")) q_direction = .in;
            if (std.mem.eql(u8, v, "out")) q_direction = .out;
            if (std.mem.eql(u8, v, "both")) q_direction = .both;
        }
    }
    if (q_min_edges == 0) q_min_edges = 1;

    const live = resolveLiveGraph(state, q_sha, q_arch) catch |err| switch (err) {
        error.NonHeadNotSupported => return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "non-HEAD sha not supported (HEAD only)\n",
        ),
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
        else => return err,
    };

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    render.renderModuleGraph(allocator, &aw.writer, live.graph, live.maps, q_level, q_intra, q_min_edges, q_exclude_external, q_direction) catch |err| {
        return respondBytes(
            request,
            .internal_server_error,
            "text/plain; charset=utf-8",
            @errorName(err),
        );
    };
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
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
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
        else => return err,
    };

    const fp: *const Function = live.maps.by_name.get(name) orelse return respondBytes(
        request,
        .not_found,
        "text/plain; charset=utf-8",
        "function not found\n",
    );

    // Aggregate across every Function sharing this name. For generic
    // methods Zig emits one IR fn per `(T,)` instantiation, all with
    // the same `name` — listing only `by_name`'s last-wins entry would
    // under-report callers for the most common shape (`SlabRef.lock`,
    // etc.). `by_name_multi` keeps every instantiation; we walk all of
    // them and merge their reverse-edge lists.
    const inst_list_opt = live.maps.by_name_multi.get(fp.name);
    const inst_count: usize = if (inst_list_opt) |l| l.items.len else 1;
    var merged = std.ArrayList(render.CallerSite){};
    defer merged.deinit(allocator);
    if (inst_list_opt) |list| {
        for (list.items) |inst| {
            if (live.maps.callers.get(inst.id)) |sites_list| {
                try merged.appendSlice(allocator, sites_list.items);
            }
        }
    } else if (live.maps.callers.get(fp.id)) |sites_list| {
        try merged.appendSlice(allocator, sites_list.items);
    }

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    if (merged.items.len == 0) {
        try aw.writer.writeAll("(no callers found in graph — may be unreachable, indirect-only, or an entry point)\n");
        return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
    }

    // Sort by caller name then site line so output is deterministic and
    // groupable by caller.
    const sorted = try allocator.dupe(render.CallerSite, merged.items);
    defer allocator.free(sorted);
    std.mem.sort(render.CallerSite, sorted, {}, callerSiteLessThan);

    if (inst_count > 1) {
        try aw.writer.print("({d} instantiations share this name; counts aggregated)\n", .{inst_count});
    }
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
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
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
        error.UnknownArch => return respondUnknownArch(allocator, state, request),
        else => return err,
    };
    // Parse the optional `kind=` filter. Empty list means "keep everything".
    // We bit-pack the allowed kinds — fewer than 8 variants, so a u8 mask is
    // plenty and avoids allocator churn on a hot read endpoint. Unknown kind
    // strings 400 so the agent gets a clear error rather than silent
    // empty-result behaviour.
    //
    // Decode percent-escapes first — the MCP shim percent-encodes commas
    // (`,` → `%2C`) when forwarding multi-kind filters, and `parseKindMask`
    // splits on a literal `,`. Without decoding, `kind=trap,irq` arrives as
    // `trap%2Cirq` and trips the unknown-kind branch.
    const kind_decoded = try percentDecodeAlloc(allocator, q.kind);
    defer allocator.free(kind_decoded);
    const kind_mask = parseKindMask(kind_decoded) catch {
        return respondBytes(
            request,
            .bad_request,
            "text/plain; charset=utf-8",
            "unknown kind — accepted: syscall,irq,trap,boot,manual\n",
        );
    };

    // Sort entries by (kind, label) so the output groups orientation by
    // subsystem instead of dumping in graph-walk order. Within a kind, the
    // alphabetic order keeps the syscall list scannable.
    var sorted = try std.ArrayList(types.EntryPoint).initCapacity(allocator, live.graph.entry_points.len);
    defer sorted.deinit(allocator);
    for (live.graph.entry_points) |ep| {
        if (kind_mask != 0 and (kind_mask & kindBit(ep.kind)) == 0) continue;
        sorted.appendAssumeCapacity(ep);
    }
    std.mem.sort(types.EntryPoint, sorted.items, {}, entryPointLessThan);

    var aw = std.io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    var name_buf: [512]u8 = undefined;
    var prev_kind: ?types.EntryKind = null;
    for (sorted.items) |ep| {
        // Blank line between kind groups so visual scanning is fast.
        if (prev_kind) |pk| {
            if (pk != ep.kind) try aw.writer.writeAll("\n");
        }
        prev_kind = ep.kind;

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
    return respondTextWithFreshness(allocator, state, request, .ok, aw.writer.buffer[0..aw.writer.end]);
}

/// Sort order: boot → trap → irq → syscall → manual, then alphabetic by label.
fn entryKindOrder(k: types.EntryKind) u8 {
    return switch (k) {
        .boot => 0,
        .trap => 1,
        .irq => 2,
        .syscall => 3,
        .manual => 4,
    };
}

fn entryPointLessThan(_: void, a: types.EntryPoint, b: types.EntryPoint) bool {
    const oa = entryKindOrder(a.kind);
    const ob = entryKindOrder(b.kind);
    if (oa != ob) return oa < ob;
    return std.mem.lessThan(u8, a.label, b.label);
}

fn kindBit(k: types.EntryKind) u8 {
    return @as(u8, 1) << @intFromEnum(k);
}

/// Parse a comma-separated list of entry kinds into a bitmask. Empty input
/// returns 0 (the caller treats 0 as "no filter"). Unknown tokens trigger
/// an error so callers get a 400 — silently dropping them would yield an
/// empty result and look like the entry list itself was empty.
fn parseKindMask(s: []const u8) !u8 {
    if (s.len == 0) return 0;
    var mask: u8 = 0;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |raw| {
        const tok = std.mem.trim(u8, raw, " \t");
        if (tok.len == 0) continue;
        const k = std.meta.stringToEnum(types.EntryKind, tok) orelse return error.UnknownKind;
        mask |= kindBit(k);
    }
    return mask;
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
    /// Channels with a completion `.md` artifact on disk. Each entry is
    /// "mcp" (agent review) or "http" (human review); both can be
    /// present, neither, or just one. The web UI renders a small badge
    /// per channel so the user can see review coverage at a glance
    /// without opening the commit. Computed via two stat-only checks
    /// per commit (cheap; ~50 commits = ~100 stats per /api/commits).
    reviewed_by: []const []const u8,
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
    // Default format is JSON for the web UI; the MCP shim asks for text
    // so the callgraph tool surface is uniformly plain text.
    var fmt: enum { json, text } = .json;
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "limit")) {
            limit = std.fmt.parseInt(u32, val, 10) catch limit;
        }
        if (std.mem.eql(u8, key, "format")) {
            if (std.mem.eql(u8, val, "text")) fmt = .text;
            if (std.mem.eql(u8, val, "json")) fmt = .json;
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

    if (fmt == .text) {
        // One commit per line: `<short>  <date>  <subject>` with a trailing
        // `  [stale]` marker on commits whose tree predates the `-Demit_ir`
        // build option (those can't be loaded by /api/load_commit because
        // the build would fail with `invalid option: -Demit_ir`). Every
        // other MCP tool returns text/plain; the format=text branch keeps
        // the MCP surface uniform without breaking the JSON-consuming
        // web UI.
        var aw = std.io.Writer.Allocating.init(allocator);
        defer aw.deinit();
        var line_it = std.mem.splitScalar(u8, result.stdout, '\n');
        while (line_it.next()) |line| {
            if (line.len == 0) continue;
            var fields_it = std.mem.splitSequence(u8, line, GIT_FIELD_SEP);
            const sha = fields_it.next() orelse continue;
            const short = fields_it.next() orelse continue;
            _ = fields_it.next() orelse continue; // author — not in the line format
            const date = fields_it.next() orelse continue;
            const subject = fields_it.next() orelse continue;
            try aw.writer.print("{s}  {s}  {s}", .{ short, date, subject });
            if (!compat_set.contains(sha)) try aw.writer.writeAll("  [stale]");
            try aw.writer.writeAll("\n");
        }
        return respondBytes(request, .ok, "text/plain; charset=utf-8", aw.writer.buffer[0..aw.writer.end]);
    }

    // Arena scoped to this handler for the per-commit `reviewed_by`
    // slices. Strings inside Commit (sha/short/author/...) point into
    // result.stdout which is freed at handler exit, so the arena's
    // lifetime is fine.
    var rb_arena = std.heap.ArenaAllocator.init(allocator);
    defer rb_arena.deinit();
    const rb_alloc = rb_arena.allocator();
    const review_store_inst = review_store.Store.init(state.git_root);

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

        // Reviews may be stored under either the full sha or the short
        // 8-char prefix (agents commonly pass the short form, which is
        // what we then store). Check both — newer reviews could still
        // be added under either form depending on what the caller passes.
        var rb_buf: [2][]const u8 = undefined;
        var rb_len: usize = 0;
        const presence_full = review_store_inst.summariesPresent(rb_alloc, sha) catch
            review_store.SummaryPresence{ .mcp = false, .http = false };
        const sha_short = if (sha.len > 8) sha[0..8] else sha;
        const presence_short = if (sha.len > 8)
            (review_store_inst.summariesPresent(rb_alloc, sha_short) catch
                review_store.SummaryPresence{ .mcp = false, .http = false })
        else
            presence_full;
        const has_mcp = presence_full.mcp or presence_short.mcp;
        const has_http = presence_full.http or presence_short.http;
        if (has_mcp) {
            rb_buf[rb_len] = "mcp";
            rb_len += 1;
        }
        if (has_http) {
            rb_buf[rb_len] = "http";
            rb_len += 1;
        }
        const rb_slice = try rb_alloc.dupe([]const u8, rb_buf[0..rb_len]);

        try commit_list.append(allocator, .{
            .sha = sha,
            .short = short,
            .author = author,
            .date = date,
            .subject = subject,
            .cg_compatible = compat_set.contains(sha),
            .reviewed_by = rb_slice,
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

// ---- Per-commit channeled review (mcp + http unified) --------------------

const ReviewListEntry = struct {
    sha: []const u8,
    subject: []const u8,
    reviewed_by: []const []const u8,
};

const ReviewListPayload = struct {
    reviews: []const ReviewListEntry,
};

fn handleReviewOpen(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = getQueryValue(query, "sha") orelse "";
    const channel = parseReviewChannel(query);
    const agent_model = getQueryValue(query, "agent_model");
    const fmt = parseReviewFormat(query);
    const store = review_store.Store.init(state.git_root);

    if (sha.len == 0) {
        return respondReviewList(a, request, &store, fmt);
    }
    if (!isValidSha(sha)) {
        return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "invalid sha\n");
    }

    // Always ensure the commit graph is loaded — even when persisted
    // review state already exists. Agents call review_open as the
    // resume point; if the daemon restarted (e.g., after a crash or
    // to pick up new code) the in-memory registry is empty even
    // though the .json state survived. Without this, subsequent
    // review_deps calls would fail with "commit graph not loaded"
    // and the agent would have no way out from inside MCP.
    //
    // Build can take 1-5 minutes; the daemon's HTTP I/O has no
    // timeout, and the MCP shim's std.http.Client doesn't either.
    ensureCommitLoaded(state, sha) catch |err| {
        const msg = try std.fmt.allocPrint(a, "auto-load failed: {s}\n", .{@errorName(err)});
        return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", msg);
    };

    var review = (try store.load(a, sha)) orelse review_store.ReviewState{
        .sha = try a.dupe(u8, sha),
        .subject = getCommitSubject(a, state.git_root, sha) catch try a.dupe(u8, ""),
        .channels = .{},
    };

    // Open the requested channel if it doesn't exist yet. Existing
    // channels (in_progress or complete) are returned as-is — both
    // channels are independent attestations on the same commit.
    if (getChannelState(review.channels, channel) == null) {
        const graph = loadCommitGraphForReview(a, state, sha) catch |err| {
            const msg = try std.fmt.allocPrint(a, "commit graph load reported success but lookup failed ({s})\n", .{@errorName(err)});
            return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", msg);
        };
        const files = review_diff.fetchHunksForCommit(a, state.git_root, sha) catch |err| {
            const msg = try std.fmt.allocPrint(a, "git diff failed: {s}\n", .{@errorName(err)});
            return respondBytes(request, .internal_server_error, "text/plain; charset=utf-8", msg);
        };
        const items = try review_classifier.classify(a, files, graph);
        // Pre-resolve dep counts so the open response shows planning
        // info (`callers/12` vs `callers/1`) without forcing the
        // caller to invoke review_deps on every item just to scope
        // effort. We don't store the names — that would skip the
        // "must call review_deps" gate.
        for (items) |*it| {
            if (it.trivial or it.deps_kind == .none) continue;
            const deps = review_deps_mod.computeDeps(a, it, graph) catch continue;
            it.deps_count = @intCast(deps.len);
        }
        const ch_state = review_store.ChannelState{
            .status = .in_progress,
            .started_at = std.time.timestamp(),
            // agent_model is meaningful only for the mcp channel; the
            // http channel is human-driven and identifies the reviewer
            // by the .http.md content, not a model id.
            .agent_model = if (channel == .mcp and agent_model != null)
                try a.dupe(u8, agent_model.?)
            else
                null,
            .items = items,
        };
        setChannelState(&review.channels, channel, ch_state);
        try store.save(a, &review);
    }

    return respondReviewState(a, request, &review, channel, fmt);
}

fn handleReviewDeps(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = getQueryValue(query, "sha") orelse return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "missing sha\n");
    const item_id_raw = getQueryValue(query, "item_id") orelse return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "missing item_id\n");
    const item_id = try urlDecode(a, item_id_raw);
    if (!isValidSha(sha)) return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "invalid sha\n");
    const channel = parseReviewChannel(query);
    const fmt = parseReviewFormat(query);

    const store = review_store.Store.init(state.git_root);
    var review = (try store.load(a, sha)) orelse return respondBytes(request, .not_found, "text/plain; charset=utf-8", "no review open for this commit; call review_open first\n");
    var ch = getChannelState(review.channels, channel) orelse return respondBytes(request, .conflict, "text/plain; charset=utf-8", "channel not open; call review_open\n");
    if (ch.status != .in_progress) return respondBytes(request, .conflict, "text/plain; charset=utf-8", "channel already complete; nothing to compute\n");

    var item_idx: ?usize = null;
    for (ch.items, 0..) |it, i| {
        if (std.mem.eql(u8, it.id, item_id)) {
            item_idx = i;
            break;
        }
    }
    const idx = item_idx orelse return respondBytes(request, .not_found, "text/plain; charset=utf-8", "unknown item_id\n");
    const item_ptr = &ch.items[idx];

    if (item_ptr.deps_kind == .none or item_ptr.trivial) {
        return respondBytes(request, .conflict, "text/plain; charset=utf-8", "no deps required for this item; you can call checkoff directly\n");
    }

    const graph = loadCommitGraphForReview(a, state, sha) catch |err| {
        const msg = try std.fmt.allocPrint(a, "commit graph not loaded ({s})\n", .{@errorName(err)});
        return respondBytes(request, .conflict, "text/plain; charset=utf-8", msg);
    };

    const deps = try review_deps_mod.computeDeps(a, item_ptr, graph);

    // Sticky merge: extend existing deps_required, never shrink.
    const merged = try mergeStickyNames(a, item_ptr.deps_required, deps);
    item_ptr.deps_required = merged;

    // Retro-fill deps_viewed from the channel session log. If the
    // agent already viewed any of these deps under a previously-opened
    // item, that view counts here too — eliminates the "had to re-call
    // callgraph_src enqueue 30 seconds later" friction agents reported
    // when a shared dep gets pulled into a second item's deps_required.
    if (channel == .mcp and ch.deps_viewed_session.len > 0) {
        var retro = std.ArrayList([]const u8){};
        // Seed with whatever was already in deps_viewed (preserve prior).
        for (item_ptr.deps_viewed) |v| try retro.append(a, v);
        for (merged) |req| {
            // Skip if already in retro (i.e. already in deps_viewed).
            var seen = false;
            for (retro.items) |r| {
                if (std.mem.eql(u8, r, req)) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;
            // Counts as viewed iff the channel session log has it.
            for (ch.deps_viewed_session) |sv| {
                if (std.mem.eql(u8, sv, req)) {
                    try retro.append(a, req);
                    break;
                }
            }
        }
        item_ptr.deps_viewed = try retro.toOwnedSlice(a);
    }

    setChannelState(&review.channels, channel, ch);
    try store.save(a, &review);

    return respondReviewDeps(a, request, item_id, deps, merged, fmt);
}

fn handleReviewCheckoff(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = getQueryValue(query, "sha") orelse return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "missing sha\n");
    const item_id_raw = getQueryValue(query, "item_id") orelse return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "missing item_id\n");
    const item_id = try urlDecode(a, item_id_raw);
    if (!isValidSha(sha)) return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "invalid sha\n");
    const notes_raw = getQueryValue(query, "notes");
    const notes: ?[]const u8 = if (notes_raw) |n| try urlDecode(a, n) else null;
    const channel = parseReviewChannel(query);
    // Optional `state=on|off`. Default `on` preserves the shipped MCP
    // shim's contract (it only ever checks items off, never unchecks).
    // The web GUI sends `off` when the user clicks a checked checkbox
    // back to unchecked.
    const state_q = getQueryValue(query, "state") orelse "on";
    const want_checked = !std.mem.eql(u8, state_q, "off");
    const fmt = parseReviewFormat(query);

    const store = review_store.Store.init(state.git_root);
    var review = (try store.load(a, sha)) orelse return respondBytes(request, .not_found, "text/plain; charset=utf-8", "no review open\n");
    var ch = getChannelState(review.channels, channel) orelse return respondBytes(request, .conflict, "text/plain; charset=utf-8", "channel not open\n");
    if (ch.status != .in_progress) return respondBytes(request, .conflict, "text/plain; charset=utf-8", "channel already complete\n");

    var item_idx: ?usize = null;
    for (ch.items, 0..) |it, i| {
        if (std.mem.eql(u8, it.id, item_id)) {
            item_idx = i;
            break;
        }
    }
    const idx = item_idx orelse return respondBytes(request, .not_found, "text/plain; charset=utf-8", "unknown item_id\n");
    const item_ptr = &ch.items[idx];

    // Gate: only the mcp (agent) channel enforces deps-viewing on
    // check. The http (human) channel is intentionally ungated — humans
    // know what they're doing and shouldn't have to call review_deps to
    // satisfy a paperwork requirement. Unchecking (state=off) skips
    // the gate either way.
    if (want_checked and channel == .mcp and !item_ptr.trivial and item_ptr.deps_kind != .none) {
        const required = item_ptr.deps_required orelse {
            return respondBytes(request, .conflict, "text/plain; charset=utf-8", "must call review_deps for this item before check-off\n");
        };
        var missing = std.ArrayList([]const u8){};
        outer: for (required) |r| {
            for (item_ptr.deps_viewed) |v| {
                if (std.mem.eql(u8, v, r)) continue :outer;
            }
            try missing.append(a, r);
        }
        if (missing.items.len > 0) {
            var buf = std.ArrayList(u8){};
            try buf.appendSlice(a, "must view these deps before check-off (call callgraph_src on each function dep, or callgraph_type on each type dep):");
            for (missing.items) |m| {
                try buf.append(a, '\n');
                try buf.appendSlice(a, "  - ");
                try buf.appendSlice(a, m);
            }
            try buf.append(a, '\n');
            return respondBytes(request, .conflict, "text/plain; charset=utf-8", buf.items);
        }
    }

    item_ptr.checked_off = want_checked;
    if (notes) |n| item_ptr.notes = n;
    setChannelState(&review.channels, channel, ch);
    try store.save(a, &review);

    return respondReviewState(a, request, &review, channel, fmt);
}

fn handleReviewComplete(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = getQueryValue(query, "sha") orelse return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "missing sha\n");
    const summary_raw = getQueryValue(query, "summary") orelse return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "missing summary\n");
    if (!isValidSha(sha)) return respondBytes(request, .bad_request, "text/plain; charset=utf-8", "invalid sha\n");
    const summary = try urlDecode(a, summary_raw);
    const channel = parseReviewChannel(query);

    const store = review_store.Store.init(state.git_root);
    var review = (try store.load(a, sha)) orelse return respondBytes(request, .not_found, "text/plain; charset=utf-8", "no review open\n");
    var ch = getChannelState(review.channels, channel) orelse return respondBytes(request, .conflict, "text/plain; charset=utf-8", "channel not open\n");
    if (ch.status != .in_progress) return respondBytes(request, .conflict, "text/plain; charset=utf-8", "channel already complete\n");

    var unchecked = std.ArrayList([]const u8){};
    for (ch.items) |it| {
        if (!it.checked_off) try unchecked.append(a, it.id);
    }
    if (unchecked.items.len > 0) {
        var buf = std.ArrayList(u8){};
        try buf.appendSlice(a, "cannot complete: items remain unchecked:");
        for (unchecked.items) |id| {
            try buf.append(a, '\n');
            try buf.appendSlice(a, "  - ");
            try buf.appendSlice(a, id);
        }
        try buf.append(a, '\n');
        return respondBytes(request, .conflict, "text/plain; charset=utf-8", buf.items);
    }

    const now = std.time.timestamp();
    ch.status = .complete;
    ch.completed_at = now;
    ch.summary = summary;
    setChannelState(&review.channels, channel, ch);

    const artifact = try renderReviewArtifact(a, &review, channel, summary);
    // Write the .md FIRST: presence is the source of truth for
    // completion. Save the JSON second. If we crash between, next
    // load sees status=in_progress with a stray .md (harmless — load
    // ignores it when status != complete). Conversely, if save
    // happens but writeSummary fails, the channel-reset-on-md-deletion
    // path in store.load resets the channel and the next _open will
    // re-classify cleanly. Both crash windows are safe.
    try store.writeSummary(a, sha, channel, artifact);
    try store.save(a, &review);

    return respondBytes(request, .ok, "text/markdown; charset=utf-8", artifact);
}

// ---- Review handler helpers ---------------------------------------------

/// Output format for /api/review/* responses. `compact` is a dense
/// human-readable text format mirroring the trace tool's compact mode;
/// `json` is the verbose default for the web GUI. The MCP shim defaults
/// to compact so agents pay fewer tokens.
const ReviewFormat = enum { compact, json };

fn parseReviewFormat(query: []const u8) ReviewFormat {
    const v = getQueryValue(query, "format") orelse return .json;
    if (std.mem.eql(u8, v, "compact")) return .compact;
    return .json;
}

/// Channel selector for /api/review/* endpoints. Defaults to `mcp` so
/// the shipped MCP shim (which builds URLs without a channel param)
/// keeps working without a re-ship. The web GUI passes `channel=http`
/// explicitly.
fn parseReviewChannel(query: []const u8) review_store.Channel {
    const v = getQueryValue(query, "channel") orelse return .mcp;
    if (std.mem.eql(u8, v, "http")) return .http;
    return .mcp;
}

fn getChannelState(channels: review_store.Channels, ch: review_store.Channel) ?review_store.ChannelState {
    return switch (ch) {
        .mcp => channels.mcp,
        .http => channels.http,
    };
}

fn setChannelState(channels: *review_store.Channels, ch: review_store.Channel, st: ?review_store.ChannelState) void {
    switch (ch) {
        .mcp => channels.mcp = st,
        .http => channels.http = st,
    }
}

fn respondReviewList(
    a: std.mem.Allocator,
    request: *std.http.Server.Request,
    store: *const review_store.Store,
    fmt: ReviewFormat,
) !void {
    const shas = try store.listShas(a);
    var entries = std.ArrayList(ReviewListEntry){};
    for (shas) |sha| {
        const review = (store.load(a, sha) catch null) orelse continue;
        var rb = std.ArrayList([]const u8){};
        if (review.channels.mcp) |ch| if (ch.status == .complete) try rb.append(a, "mcp");
        if (review.channels.http) |ch| if (ch.status == .complete) try rb.append(a, "http");
        try entries.append(a, .{
            .sha = review.sha,
            .subject = review.subject,
            .reviewed_by = try rb.toOwnedSlice(a),
        });
    }

    if (fmt == .json) {
        const payload = ReviewListPayload{ .reviews = entries.items };
        return respondJsonAlloc(a, request, &payload);
    }

    var buf = std.ArrayList(u8){};
    try buf.writer(a).print("L reviews={d}\n", .{entries.items.len});
    for (entries.items) |e| {
        var marks = [_]u8{ '-', '-' }; // [mcp][http]
        for (e.reviewed_by) |r| {
            if (std.mem.eql(u8, r, "mcp")) marks[0] = 'm';
            if (std.mem.eql(u8, r, "http")) marks[1] = 'h';
        }
        try buf.writer(a).print("{s}{s} {s} {s}\n", .{
            marks[0..1], marks[1..2], shortSha(e.sha), e.subject,
        });
    }
    return respondBytes(request, .ok, "text/plain; charset=utf-8", buf.items);
}

fn respondReviewState(
    a: std.mem.Allocator,
    request: *std.http.Server.Request,
    review: *const review_store.ReviewState,
    channel: review_store.Channel,
    fmt: ReviewFormat,
) !void {
    if (fmt == .json) return respondJsonAlloc(a, request, review);

    var buf = std.ArrayList(u8){};
    const ch_opt = getChannelState(review.channels, channel);
    const ch = ch_opt orelse {
        try buf.writer(a).print("R {s} {s}=<none> subject={s}\n", .{
            shortSha(review.sha), channel.tag(), review.subject,
        });
        return respondBytes(request, .ok, "text/plain; charset=utf-8", buf.items);
    };

    var done: usize = 0;
    for (ch.items) |it| if (it.checked_off) {
        done += 1;
    };
    try buf.writer(a).print(
        "R {s} {s}={s} items={d} done={d} subject={s}\n",
        .{ shortSha(review.sha), channel.tag(), @tagName(ch.status), ch.items.len, done, review.subject },
    );

    for (ch.items) |it| {
        const marker: u8 = if (it.checked_off) '+' else if (it.trivial) '.' else '!';
        try buf.writer(a).print("{c} {s}", .{ marker, it.id });
        if (it.trivial) {
            try buf.writer(a).print(" trivial", .{});
        } else if (it.deps_kind != .none) {
            try buf.writer(a).print(" {s} deps={d}", .{ @tagName(it.deps_kind), it.deps_count });
            if (it.deps_required) |required| {
                try buf.writer(a).print(" viewed={d}/{d}", .{ it.deps_viewed.len, required.len });
            }
        }
        try buf.writer(a).print(" {s}:{s}\n", .{ it.file, it.loc });
        if (it.notes) |n| if (n.len > 0) {
            try buf.writer(a).print("    -- {s}\n", .{n});
        };
    }
    return respondBytes(request, .ok, "text/plain; charset=utf-8", buf.items);
}

fn respondReviewDeps(
    a: std.mem.Allocator,
    request: *std.http.Server.Request,
    item_id: []const u8,
    deps: []const review_deps_mod.DepEntry,
    required: []const []const u8,
    fmt: ReviewFormat,
) !void {
    if (fmt == .json) {
        const payload = struct {
            item_id: []const u8,
            deps: []const review_deps_mod.DepEntry,
            required: []const []const u8,
        }{ .item_id = item_id, .deps = deps, .required = required };
        return respondJsonAlloc(a, request, &payload);
    }

    var buf = std.ArrayList(u8){};
    try buf.writer(a).print("D {s} required={d}\n", .{ item_id, required.len });
    for (deps, 1..) |d, i| {
        try buf.writer(a).print(
            "  [{d}] {s}\n      @ {s}:{d}\n      -- {s}\n",
            .{ i, d.qualified_name, d.file, d.line, d.summary },
        );
    }
    return respondBytes(request, .ok, "text/plain; charset=utf-8", buf.items);
}

fn shortSha(sha: []const u8) []const u8 {
    return sha[0..@min(sha.len, 12)];
}

fn respondJsonAlloc(
    a: std.mem.Allocator,
    request: *std.http.Server.Request,
    value: anytype,
) !void {
    const blob = try std.json.Stringify.valueAlloc(a, value.*, .{ .whitespace = .indent_2 });
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
}

/// Trigger a registry load for `sha` if not already in flight, then
/// block (with a poll loop) until the entry transitions to `ready` or
/// `errored`. No timeout — the MCP transport doesn't impose one and
/// kernel builds legitimately take 1-5 minutes. Errors propagate the
/// registry's recorded error_msg if present.
fn ensureCommitLoaded(state: *const ServerState, sha: []const u8) !void {
    const reg = state.registry;
    const entry = try reg.requestLoad(sha);

    // Snapshot status under the mutex each tick. We don't subscribe
    // (no condition variable in the registry today); polling at 200ms
    // keeps per-call overhead negligible while still completing within
    // a fraction of a second of the worker finishing.
    while (true) {
        reg.lockShared();
        const status = entry.status;
        reg.unlockShared();
        switch (status) {
            .ready => return,
            .errored => return error.CommitBuildFailed,
            .building, .not_loaded => std.Thread.sleep(200 * std.time.ns_per_ms),
        }
    }
}

/// Pull the per-commit Graph out of the registry and JSON-decode it
/// back into a `types.Graph` so the classifier and deps computer can
/// walk it. The registry stores a serialized blob per arch; we pick
/// the entry's default arch and parse on demand.
fn loadCommitGraphForReview(
    a: std.mem.Allocator,
    state: *const ServerState,
    sha: []const u8,
) !*const types.Graph {
    const reg = state.registry;
    reg.lockShared();
    defer reg.unlockShared();
    const entry = reg.entries.get(sha) orelse return error.CommitNotLoaded;
    if (entry.status != .ready) return error.CommitNotReady;
    const blob = entry.arch_blobs.get(entry.default_arch) orelse return error.NoArchBlob;

    const parsed = try std.json.parseFromSliceLeaky(types.Graph, a, blob, .{
        .ignore_unknown_fields = true,
    });
    const out = try a.create(types.Graph);
    out.* = parsed;
    return out;
}

fn getCommitSubject(
    a: std.mem.Allocator,
    git_root: []const u8,
    sha: []const u8,
) ![]const u8 {
    const argv = [_][]const u8{ "git", "log", "-1", "--format=%s", sha };
    const result = try std.process.Child.run(.{
        .allocator = a,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 16 * 1024,
    });
    if (result.term != .Exited or result.term.Exited != 0) return error.GitLogFailed;
    return std.mem.trim(u8, result.stdout, "\n\r \t");
}

/// Sticky merge: result = dedup(prior ∪ fresh.qname). Order = prior
/// first (preserved), then any new entries in fresh's order.
fn mergeStickyNames(
    a: std.mem.Allocator,
    prior_opt: ?[]const []const u8,
    fresh: []const review_deps_mod.DepEntry,
) ![]const []const u8 {
    var out = std.ArrayList([]const u8){};
    var seen = std.StringHashMap(void).init(a);
    if (prior_opt) |prior| {
        for (prior) |p| {
            if (seen.contains(p)) continue;
            try seen.put(p, {});
            try out.append(a, p);
        }
    }
    for (fresh) |f| {
        if (seen.contains(f.qualified_name)) continue;
        try seen.put(f.qualified_name, {});
        try out.append(a, f.qualified_name);
    }
    return out.toOwnedSlice(a);
}

/// Build a channel's `.md` artifact. Sections: header (sha, subject,
/// timestamps; agent_model only for mcp), free-text summary supplied
/// by the caller, then per-item bullet list with notes. Title varies
/// by channel ("Agent" for mcp, "Human" for http) so a glance at the
/// file tells you which attestation it is.
fn renderReviewArtifact(
    a: std.mem.Allocator,
    review: *const review_store.ReviewState,
    channel: review_store.Channel,
    summary: []const u8,
) ![]u8 {
    var buf = std.ArrayList(u8){};
    const ch = getChannelState(review.channels, channel).?;

    const heading = switch (channel) {
        .mcp => "Agent",
        .http => "Human",
    };
    try buf.writer(a).print("# {s} review of {s}\n\n", .{ heading, review.sha });
    try buf.writer(a).print("**Subject:** {s}\n", .{review.subject});
    if (ch.agent_model) |m| try buf.writer(a).print("**Agent:** {s}\n", .{m});
    try buf.writer(a).print("**Started:** {d}\n", .{ch.started_at});
    if (ch.completed_at) |c| try buf.writer(a).print("**Completed:** {d}\n", .{c});

    try buf.appendSlice(a, "\n## Summary\n\n");
    try buf.appendSlice(a, summary);
    if (summary.len == 0 or summary[summary.len - 1] != '\n') try buf.append(a, '\n');

    try buf.appendSlice(a, "\n## Items reviewed\n\n");
    for (ch.items) |it| {
        try buf.writer(a).print("- `{s}` — {s} @ {s}:{s}", .{
            it.id, @tagName(it.kind), it.file, it.loc,
        });
        if (it.trivial) try buf.appendSlice(a, " (trivial)");
        try buf.append(a, '\n');
        if (it.notes) |n| if (n.len > 0) try buf.writer(a).print("  - {s}\n", .{n});
    }

    return buf.toOwnedSlice(a);
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
