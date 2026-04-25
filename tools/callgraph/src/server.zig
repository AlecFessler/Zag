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
const types = @import("types.zig");

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

    return .{
        .blobs = blobs,
        .arches_blob = try arches_buf.toOwnedSlice(allocator),
        .default_arch = default_arch,
        .git_root = git_root,
        .registry = registry,
    };
}

fn freeState(allocator: std.mem.Allocator, state: *ServerState) void {
    var it = state.blobs.iterator();
    while (it.next()) |e| allocator.free(e.value_ptr.*);
    state.blobs.deinit();
    allocator.free(state.arches_blob);
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
        });
    }

    const payload = CommitList{ .commits = commit_list.items };
    const blob = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(blob);
    return respondBytes(request, .ok, "application/json; charset=utf-8", blob);
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
    var sha: []const u8 = "";
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha")) sha = val;
    }
    if (!isValidShaOrRef(sha)) return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing or invalid ?sha=\n",
    );

    const argv = [_][]const u8{ "git", "diff", "--name-only", sha };
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
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
    var sha: []const u8 = "";
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "sha")) sha = val;
    }
    if (!isValidShaOrRef(sha)) return respondBytes(
        request,
        .bad_request,
        "text/plain; charset=utf-8",
        "missing or invalid ?sha=\n",
    );

    const argv = [_][]const u8{ "git", "diff", "--unified=0", "--no-color", sha };
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &argv,
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
