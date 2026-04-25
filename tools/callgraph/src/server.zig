//! HTTP server for the kernel call-graph explorer.
//!
//! Serves three things:
//!   - `GET /` and `GET /static/{app.js,cytoscape.min.js}` — embedded
//!     frontend assets. The asset files in `src/assets/` are one-line stubs
//!     that the frontend agent overwrites at integration time. The server
//!     code is the integration boundary and stays unchanged.
//!   - `GET /api/graph` — JSON dump of the immutable Graph, pre-serialized
//!     once at startup (the graph never changes during the server's life).
//!   - `GET /api/source?path=...&start=N&end=M` — inclusive line range from
//!     the named source file, read fresh each request.
//!
//! Synchronous accept loop on 127.0.0.1. Graph is shared read-only across
//! requests via `*const Graph`.

const std = @import("std");

const types = @import("types.zig");

const Graph = types.Graph;

const index_html = @embedFile("assets/index.html");
const app_js = @embedFile("assets/app.js");
const trace_js = @embedFile("assets/trace.js");
const cytoscape_js = @embedFile("assets/cytoscape.min.js");

const SOURCE_MAX_BYTES: usize = 1 * 1024 * 1024;

pub fn serve(allocator: std.mem.Allocator, graph: *const Graph, port: u16) !void {
    const json_blob = try serializeGraph(allocator, graph);
    defer allocator.free(json_blob);

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
        handleRequest(allocator, &request, json_blob) catch |err| {
            std.debug.print("handler error: {s}\n", .{@errorName(err)});
        };
    }
}

fn serializeGraph(allocator: std.mem.Allocator, graph: *const Graph) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, graph.*, .{});
}

fn handleRequest(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    json_blob: []const u8,
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
    if (std.mem.eql(u8, path, "/api/graph")) {
        return respondBytes(request, .ok, "application/json; charset=utf-8", json_blob);
    }
    if (std.mem.eql(u8, path, "/api/source")) {
        return handleSource(allocator, request, query);
    }

    return respondBytes(request, .not_found, "text/plain; charset=utf-8", "not found\n");
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
