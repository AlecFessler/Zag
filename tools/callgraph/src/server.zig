//! HTTP server for the kernel call-graph explorer.
//!
//! Serves four things:
//!   - `GET /` and `GET /static/{app.js,trace.js,cytoscape.min.js}` — embedded
//!     frontend assets.
//!   - `GET /api/arches` — JSON listing of loaded arches and the default.
//!   - `GET /api/graph?arch=<tag>` — JSON dump of the immutable Graph for the
//!     requested arch (or default if no `arch=` query). 404 if not loaded.
//!   - `GET /api/source?path=...&start=N&end=M` — inclusive line range from
//!     the named source file, read fresh each request.
//!
//! Synchronous accept loop on 127.0.0.1. Per-arch graph blobs are
//! pre-serialized once at startup since the graphs never change during the
//! server's life.

const std = @import("std");

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
};

pub fn serve(
    allocator: std.mem.Allocator,
    graphs: *const GraphMap,
    default_arch: []const u8,
    port: u16,
) !void {
    var state = try buildState(allocator, graphs, default_arch);
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

        // One request per connection — keep-alive bookkeeping for the
        // explorer is not worth the complexity right now.
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

    // Build the /api/arches blob.
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
        return respondBytes(request, .ok, "application/json; charset=utf-8", state.arches_blob);
    }
    if (std.mem.eql(u8, path, "/api/graph")) {
        return handleGraph(request, query, state);
    }
    if (std.mem.eql(u8, path, "/api/source")) {
        return handleSource(allocator, request, query);
    }

    return respondBytes(request, .not_found, "text/plain; charset=utf-8", "not found\n");
}

fn handleGraph(
    request: *std.http.Server.Request,
    query: []const u8,
    state: *const ServerState,
) !void {
    var arch: []const u8 = state.default_arch;

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "arch")) {
            arch = val;
        }
    }

    const blob = state.blobs.get(arch) orelse {
        return respondBytes(
            request,
            .not_found,
            "text/plain; charset=utf-8",
            "arch not loaded\n",
        );
    };
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

    const slice = extractLineRange(contents, start, end);
    return respondBytes(request, .ok, "text/plain; charset=utf-8", slice);
}

/// Returns the inclusive byte range covering source lines [start, end].
/// Lines are 1-indexed. If `start` is past EOF, returns an empty slice.
fn extractLineRange(contents: []const u8, start: u32, end: u32) []const u8 {
    if (start == 0) return contents[0..0];

    var line: u32 = 1;
    var i: usize = 0;
    var range_begin: ?usize = null;
    var range_end: usize = contents.len;

    while (i <= contents.len) {
        if (line == start and range_begin == null) {
            range_begin = i;
        }
        if (line == end + 1) {
            range_end = i;
            break;
        }
        if (i == contents.len) break;
        if (contents[i] == '\n') {
            line += 1;
        }
        i += 1;
    }

    const begin = range_begin orelse return contents[0..0];
    return contents[begin..range_end];
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
