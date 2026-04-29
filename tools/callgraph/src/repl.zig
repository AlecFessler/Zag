//! Interactive REPL for exploring loaded call graphs.
//!
//! Runs against the same in-memory graphs the HTTP server uses. Lets the
//! caller switch arch, list entry points, render textual call traces, fuzzy-
//! find function names, and cat function source — all without opening a
//! browser. Aimed primarily at AI agents that want a high-level view of the
//! kernel's execution flow.
//!
//! Currently REPL state is pinned to HEAD (the graphs built at startup).
//! `commits` lists recent shas via git log; `use commit <sha>` accepts only
//! "HEAD" until we extend the registry to keep per-commit graphs in memory.

const std = @import("std");

const commits = @import("commits.zig");
const render = @import("render.zig");
const server = @import("server.zig");
const types = @import("types.zig");

const FnId = types.FnId;
const Function = types.Function;
const Graph = types.Graph;
const GraphMap = server.GraphMap;

/// Default trace depth when the user runs `trace <name>` without an
/// explicit cap. Mirrors the web UI's default.
const DEFAULT_DEPTH: u32 = 6;

const State = struct {
    gpa: std.mem.Allocator,
    graphs: *GraphMap,
    git_root: []const u8,
    kernel_root: []const u8,
    registry: *commits.Registry,
    /// Currently selected arch tag (key into `graphs`).
    current_arch: []const u8,
    hide_debug: bool = false,
    hide_library: bool = false,

    /// Per-arch lookup caches. Rebuilt lazily on first use after an arch
    /// switch.
    cache_arch: ?[]const u8 = null,
    maps: render.Maps,

    fn currentGraph(self: *State) ?*const Graph {
        return self.graphs.getPtr(self.current_arch);
    }

    fn ensureLookups(self: *State) !void {
        if (self.cache_arch) |a| if (std.mem.eql(u8, a, self.current_arch)) return;
        self.maps.deinit();
        const g = self.currentGraph() orelse {
            self.maps = render.emptyMaps(self.gpa);
            self.cache_arch = self.current_arch;
            return;
        };
        self.maps = try render.buildLookups(self.gpa, g);
        self.cache_arch = self.current_arch;
    }

    fn lookup(self: *State, name: []const u8) ?*const Function {
        return self.maps.by_name.get(name);
    }

    fn ctx(self: *State) render.Ctx {
        return .{
            .by_id = &self.maps.by_id,
            .by_name = &self.maps.by_name,
            .hide_debug = self.hide_debug,
            .hide_library = self.hide_library,
        };
    }
};

pub fn run(
    gpa: std.mem.Allocator,
    graphs: *GraphMap,
    default_arch: []const u8,
    git_root: []const u8,
    kernel_root: []const u8,
    registry: *commits.Registry,
) !void {
    var state = State{
        .gpa = gpa,
        .graphs = graphs,
        .git_root = git_root,
        .kernel_root = kernel_root,
        .registry = registry,
        .current_arch = default_arch,
        .maps = render.emptyMaps(gpa),
    };
    defer state.maps.deinit();
    try state.ensureLookups();

    const stdin_handle = std.fs.File.stdin().handle;
    var stdout_buf: [64 * 1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const out = &stdout_writer.interface;

    var line_buf = std.ArrayList(u8){};
    defer line_buf.deinit(gpa);

    try out.print(
        \\callgraph repl — type 'help' for commands, 'quit' to exit
        \\arch: {s}   commit: HEAD   filters: hide_debug={s} hide_library={s}
        \\
    , .{
        state.current_arch,
        if (state.hide_debug) "on" else "off",
        if (state.hide_library) "on" else "off",
    });
    try out.flush();

    var line_arena = std.heap.ArenaAllocator.init(gpa);
    defer line_arena.deinit();

    while (true) {
        try out.print("\ncg [{s}]> ", .{state.current_arch});
        try out.flush();

        line_buf.clearRetainingCapacity();
        const got = readLine(gpa, stdin_handle, &line_buf) catch |err| {
            try out.print("read error: {s}\n", .{@errorName(err)});
            try out.flush();
            return;
        };
        if (!got) {
            try out.writeAll("\n");
            try out.flush();
            return;
        }

        const line = std.mem.trim(u8, line_buf.items, " \t\r\n");
        if (line.len == 0) continue;

        _ = line_arena.reset(.retain_capacity);
        dispatch(&state, line_arena.allocator(), out, line) catch |err| {
            try out.print("error: {s}\n", .{@errorName(err)});
        };
        try out.flush();
    }
}

fn dispatch(
    state: *State,
    arena: std.mem.Allocator,
    out: *std.io.Writer,
    line: []const u8,
) !void {
    const cmd, const rest = splitFirst(line);

    if (eqi(cmd, "help") or eqi(cmd, "?")) return cmdHelp(out);
    if (eqi(cmd, "quit") or eqi(cmd, "exit")) std.process.exit(0);
    if (eqi(cmd, "arches") or eqi(cmd, "arch")) return cmdArches(state, out);
    if (eqi(cmd, "entries")) return cmdEntries(state, out);
    if (eqi(cmd, "commits")) return cmdCommits(state, arena, out, rest);
    if (eqi(cmd, "trace")) return cmdTrace(state, arena, out, rest);
    if (eqi(cmd, "src") or eqi(cmd, "source")) return cmdSrc(state, out, rest);
    if (eqi(cmd, "find") or eqi(cmd, "search")) return cmdFind(state, out, rest);
    if (eqi(cmd, "callers")) return cmdCallers(state, arena, out, rest);
    if (eqi(cmd, "use")) return cmdUse(state, out, rest);
    if (eqi(cmd, "set")) return cmdSet(state, out, rest);
    if (eqi(cmd, "info") or eqi(cmd, "status")) return cmdInfo(state, out);

    try out.print("unknown command: '{s}' (try 'help')\n", .{cmd});
}

fn cmdHelp(out: *std.io.Writer) !void {
    try out.writeAll(
        \\commands:
        \\  help                       — show this help
        \\  info                       — current arch / commit / filters
        \\  arches                     — list loaded arches
        \\  entries                    — list entry points for the current arch
        \\  commits [N]                — list the last N commits (default 30)
        \\  use arch <tag>             — switch to arch <tag> (e.g. x86_64, aarch64)
        \\  use commit <sha|HEAD>      — switch commit (HEAD only for now)
        \\  trace <name> [depth]       — print indented call trace from <name>
        \\  src <name>                 — print the source body of <name>
        \\  find <substr>              — fuzzy-find functions by name substring
        \\  callers <name>             — list call sites that invoke <name>
        \\  set hide_debug on|off      — toggle debug.* leaf folding
        \\  set hide_library on|off    — toggle stdlib leaf folding
        \\  quit                       — exit
        \\
    );
}

fn cmdInfo(state: *State, out: *std.io.Writer) !void {
    const g = state.currentGraph();
    try out.print(
        "arch={s}  commit=HEAD  hide_debug={s}  hide_library={s}  fns={d}\n",
        .{
            state.current_arch,
            if (state.hide_debug) "on" else "off",
            if (state.hide_library) "on" else "off",
            if (g) |gp| gp.functions.len else 0,
        },
    );
}

fn cmdArches(state: *State, out: *std.io.Writer) !void {
    var it = state.graphs.iterator();
    while (it.next()) |entry| {
        const tag = entry.key_ptr.*;
        const marker: []const u8 = if (std.mem.eql(u8, tag, state.current_arch)) "*" else " ";
        try out.print("  {s} {s}  ({d} fns)\n", .{ marker, tag, entry.value_ptr.functions.len });
    }
}

fn cmdEntries(state: *State, out: *std.io.Writer) !void {
    const g = state.currentGraph() orelse {
        try out.writeAll("no graph loaded for current arch\n");
        return;
    };
    try out.print("{d} entry points in {s}:\n", .{ g.entry_points.len, state.current_arch });
    var name_buf: [512]u8 = undefined;
    for (g.entry_points) |ep| {
        const fp_opt = state.maps.by_id.get(ep.fn_id);
        const loc: ?types.SourceLoc = if (fp_opt) |fp| fp.def_loc else null;
        const display: []const u8 = if (fp_opt) |fp| blk: {
            const slice = std.fmt.bufPrint(&name_buf, "{s} -> {s}", .{ ep.label, fp.name }) catch break :blk ep.label;
            break :blk slice;
        } else ep.label;
        try render.writePaddedName(out, "  ", display, render.kindLabel(ep.kind));
        if (loc) |l| try render.writeLoc(out, l, "");
        try out.writeAll("\n");
    }
}

fn cmdCommits(
    state: *State,
    arena: std.mem.Allocator,
    out: *std.io.Writer,
    rest: []const u8,
) !void {
    var limit: u32 = 30;
    if (rest.len > 0) {
        limit = std.fmt.parseInt(u32, std.mem.trim(u8, rest, " \t"), 10) catch limit;
    }
    const limit_arg = try std.fmt.allocPrint(arena, "-{d}", .{limit});
    const fmt = "--pretty=format:%h\t%aI\t%s";
    const argv = [_][]const u8{ "git", "log", limit_arg, fmt };
    const r = std.process.Child.run(.{
        .allocator = arena,
        .argv = &argv,
        .cwd = state.git_root,
        .max_output_bytes = 4 * 1024 * 1024,
    }) catch |err| {
        try out.print("git log failed: {s}\n", .{@errorName(err)});
        return;
    };
    switch (r.term) {
        .Exited => |code| if (code != 0) {
            try out.print("git log exited {d}\n", .{code});
            return;
        },
        else => {
            try out.writeAll("git log abnormal\n");
            return;
        },
    }
    var it = std.mem.splitScalar(u8, r.stdout, '\n');
    while (it.next()) |raw| {
        if (raw.len == 0) continue;
        try out.print("  {s}\n", .{raw});
    }
}

fn cmdUse(state: *State, out: *std.io.Writer, rest: []const u8) !void {
    const sub, const val = splitFirst(rest);
    if (eqi(sub, "arch")) {
        const tag = std.mem.trim(u8, val, " \t");
        if (tag.len == 0) {
            try out.writeAll("usage: use arch <tag>\n");
            return;
        }
        if (state.graphs.getKey(tag)) |key| {
            state.current_arch = key;
            try state.ensureLookups();
            try out.print("arch -> {s}\n", .{key});
        } else {
            try out.print("unknown arch: '{s}' (try `arches`)\n", .{tag});
        }
        return;
    }
    if (eqi(sub, "commit")) {
        const sha = std.mem.trim(u8, val, " \t");
        if (sha.len == 0) {
            try out.writeAll("usage: use commit <sha|HEAD>\n");
            return;
        }
        if (eqi(sha, "head") or std.mem.eql(u8, sha, "HEAD")) {
            try out.writeAll("commit -> HEAD\n");
            return;
        }
        try out.writeAll("note: non-HEAD commits not yet usable from REPL; loaded commits are visible in the web UI\n");
        return;
    }
    try out.writeAll("usage: use arch <tag> | use commit <sha>\n");
}

fn cmdSet(state: *State, out: *std.io.Writer, rest: []const u8) !void {
    const key, const val = splitFirst(rest);
    const v = std.mem.trim(u8, val, " \t");
    const on = eqi(v, "on") or eqi(v, "true") or eqi(v, "1");
    const off = eqi(v, "off") or eqi(v, "false") or eqi(v, "0");
    if (!on and !off) {
        try out.writeAll("usage: set hide_debug|hide_library on|off\n");
        return;
    }
    if (eqi(key, "hide_debug")) {
        state.hide_debug = on;
        try out.print("hide_debug = {s}\n", .{if (on) "on" else "off"});
        return;
    }
    if (eqi(key, "hide_library")) {
        state.hide_library = on;
        try out.print("hide_library = {s}\n", .{if (on) "on" else "off"});
        return;
    }
    try out.writeAll("unknown setting (hide_debug | hide_library)\n");
}

fn cmdFind(state: *State, out: *std.io.Writer, rest: []const u8) !void {
    const needle = std.mem.trim(u8, rest, " \t");
    if (needle.len == 0) {
        try out.writeAll("usage: find <substr>\n");
        return;
    }
    const g = state.currentGraph() orelse return;
    var matches: u32 = 0;
    for (g.functions) |f| {
        if (std.mem.indexOf(u8, f.name, needle) == null) continue;
        try render.writePaddedName(out, "  ", f.name, render.entryTag(f));
        try render.writeLoc(out, f.def_loc, "");
        try out.writeAll("\n");
        matches += 1;
        if (matches >= 200) {
            try out.writeAll("  ... (truncated at 200 matches)\n");
            return;
        }
    }
    if (matches == 0) try out.writeAll("(no matches)\n");
}

fn cmdCallers(
    state: *State,
    arena: std.mem.Allocator,
    out: *std.io.Writer,
    rest: []const u8,
) !void {
    const name = std.mem.trim(u8, rest, " \t");
    if (name.len == 0) {
        try out.writeAll("usage: callers <name>\n");
        return;
    }
    const fp = state.lookup(name) orelse {
        try out.print("function not found: {s}\n", .{name});
        return;
    };
    const sites_opt = state.maps.callers.get(fp.id);
    const sites: []const render.CallerSite = if (sites_opt) |list| list.items else &.{};
    if (sites.len == 0) {
        try out.writeAll("(no callers found)\n");
        return;
    }
    const sorted = try arena.dupe(render.CallerSite, sites);
    std.mem.sort(render.CallerSite, sorted, {}, callerLessThan);
    try out.print("{d} call sites for {s}:\n", .{ sorted.len, fp.name });
    var kind_buf: [64]u8 = undefined;
    var prev_id: ?types.FnId = null;
    for (sorted) |cs| {
        const tag = try std.fmt.bufPrint(&kind_buf, "({s})", .{@tagName(cs.kind)});
        const display: []const u8 = if (prev_id != null and prev_id.? == cs.from.id) "  ↳" else cs.from.name;
        try render.writePaddedName(out, "  ", display, tag);
        try render.writeLoc(out, cs.site, "@ ");
        try out.writeAll("\n");
        prev_id = cs.from.id;
    }
}

fn callerLessThan(_: void, a: render.CallerSite, b: render.CallerSite) bool {
    const cmp = std.mem.order(u8, a.from.name, b.from.name);
    if (cmp != .eq) return cmp == .lt;
    if (a.site.line != b.site.line) return a.site.line < b.site.line;
    return std.mem.order(u8, a.site.file, b.site.file) == .lt;
}

fn cmdSrc(state: *State, out: *std.io.Writer, rest: []const u8) !void {
    const name = std.mem.trim(u8, rest, " \t");
    if (name.len == 0) {
        try out.writeAll("usage: src <name>\n");
        return;
    }
    const fp = state.lookup(name) orelse {
        try out.print("function not found: {s}\n", .{name});
        return;
    };
    try render.printFnSource(state.gpa, out, fp);
}

fn cmdTrace(
    state: *State,
    arena: std.mem.Allocator,
    out: *std.io.Writer,
    rest: []const u8,
) !void {
    const name_part, const depth_part = splitLast(rest);
    var depth: u32 = DEFAULT_DEPTH;
    var name: []const u8 = std.mem.trim(u8, rest, " \t");
    if (depth_part.len > 0) {
        if (std.fmt.parseInt(u32, std.mem.trim(u8, depth_part, " \t"), 10)) |n| {
            depth = n;
            name = std.mem.trim(u8, name_part, " \t");
        } else |_| {}
    }
    if (name.len == 0) {
        try out.writeAll("usage: trace <name> [depth]\n");
        return;
    }
    const fp = state.lookup(name) orelse {
        try out.print("function not found: {s}\n", .{name});
        return;
    };

    const stats = render.statsTrace(arena, state.ctx(), fp, depth) catch render.TraceStats{};
    if (stats.top_fanout > 0) {
        try out.print(
            "trace: {d} fns, {d} at depth cap (depth={d}), top fanout {s} ({d} calls)\n\n",
            .{ stats.fns_visited, stats.at_cap, depth, stats.top_name, stats.top_fanout },
        );
    } else {
        try out.print(
            "trace: {d} fns, {d} at depth cap (depth={d})\n\n",
            .{ stats.fns_visited, stats.at_cap, depth },
        );
    }
    try render.renderTrace(arena, out, state.ctx(), fp, depth);
}

/// Read one '\n'-terminated line from `fd` into `buf`. Returns true if a
/// line was produced, false if the stream ended with no bytes read.
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

fn eqi(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        const ca = a[i];
        const cb = b[i];
        const lo_a = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lo_b = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (lo_a != lo_b) return false;
    }
    return true;
}

fn splitFirst(s: []const u8) struct { []const u8, []const u8 } {
    const t = std.mem.trim(u8, s, " \t");
    const sp = std.mem.indexOfAny(u8, t, " \t") orelse return .{ t, "" };
    const head = t[0..sp];
    const tail = std.mem.trim(u8, t[sp..], " \t");
    return .{ head, tail };
}

fn splitLast(s: []const u8) struct { []const u8, []const u8 } {
    const t = std.mem.trim(u8, s, " \t");
    const sp = std.mem.lastIndexOfAny(u8, t, " \t") orelse return .{ t, "" };
    const head = std.mem.trim(u8, t[0..sp], " \t");
    const tail = std.mem.trim(u8, t[sp..], " \t");
    return .{ head, tail };
}
