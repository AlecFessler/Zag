const std = @import("std");

const ast = @import("ast/index.zig");
const entry = @import("entry.zig");
const ir = @import("ir/parse.zig");
const join = @import("join.zig");
const reachability = @import("reachability.zig");
const server = @import("server.zig");
const types = @import("types.zig");
const verify = @import("verify.zig");

const Args = struct {
    ir_path: []const u8 = "zig-out/kernel.ll",
    kernel_root: []const u8 = "kernel",
    port: u16 = 8080,
    arch: []const u8 = "x64",
    verify: bool = false,
    demo_graph: bool = false,
};

fn parseArgs(allocator: std.mem.Allocator) !Args {
    var args = Args{};
    var it = try std.process.argsWithAllocator(allocator);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--ir")) {
            args.ir_path = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--kernel-root")) {
            args.kernel_root = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--port")) {
            const v = it.next() orelse return error.MissingValue;
            args.port = try std.fmt.parseInt(u16, v, 10);
        } else if (std.mem.eql(u8, arg, "--arch")) {
            args.arch = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--verify")) {
            args.verify = true;
        } else if (std.mem.eql(u8, arg, "--demo-graph")) {
            args.demo_graph = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp();
            std.process.exit(0);
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            try printHelp();
            std.process.exit(1);
        }
    }
    return args;
}

fn printHelp() !void {
    std.debug.print(
        \\callgraph — kernel call graph explorer
        \\
        \\Usage: callgraph [options]
        \\
        \\  --ir PATH           Path to kernel LLVM IR (.ll). Default: zig-out/kernel.ll
        \\  --kernel-root PATH  Kernel source root. Default: kernel
        \\  --port PORT         HTTP port. Default: 8080
        \\  --arch x64|aarch64  Target arch (must match the IR). Default: x64
        \\  --verify            Run AST/IR diff and print discrepancies, then exit
        \\  --demo-graph        Skip IR parsing; serve a synthetic 3-function graph
        \\  --help              Show this help
        \\
    , .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try parseArgs(allocator);
    std.debug.print("callgraph: ir={s} kernel-root={s} arch={s} port={d}\n", .{
        args.ir_path, args.kernel_root, args.arch, args.port,
    });

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    if (args.demo_graph) {
        const graph = try buildDemoGraph(arena_allocator);
        try server.serve(allocator, &graph, args.port);
        return;
    }

    const ir_graph = try ir.parse(&arena, args.ir_path);

    const walk = try ast.walkKernelFull(arena_allocator, args.kernel_root);
    const ast_fns = walk.fns;
    const file_count = countDistinctFiles(arena_allocator, ast_fns) catch ast_fns.len;
    std.debug.print("ast: {d} functions across {d} files\n", .{ ast_fns.len, file_count });

    if (args.verify) {
        // Verify mode short-circuits before the join + entry discovery so
        // the diff sees the raw AST/IR sets without any reconciliation
        // smoothing the numbers.
        var stdout_buf: [16 * 1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        try verify.run(allocator, &stdout_writer.interface, ir_graph, ast_fns, walk.asts);
        return;
    }

    const discovered = try entry.discover(
        arena_allocator,
        args.kernel_root,
        args.arch,
        ast_fns,
        walk.asts,
    );
    printEntryStats(discovered);

    var stats: join.JoinStats = undefined;
    var graph = try join.buildGraphWithStats(
        arena_allocator,
        ir_graph,
        ast_fns,
        walk.asts,
        discovered,
        &stats,
    );
    const pct: f64 = if (stats.ir_total == 0)
        0.0
    else
        100.0 * @as(f64, @floatFromInt(stats.matched)) / @as(f64, @floatFromInt(stats.ir_total));
    std.debug.print("join: {d} / {d} IR functions matched to AST ({d:.1} %)\n", .{
        stats.matched, stats.ir_total, pct,
    });
    std.debug.print("entry: {d} of {d} discovered entries matched IR functions\n", .{
        graph.entry_points.len, discovered.len,
    });

    const reach_stats = try reachability.compute(allocator, &graph);
    const reach_pct: f64 = if (reach_stats.total == 0)
        0.0
    else
        100.0 * @as(f64, @floatFromInt(reach_stats.reachable)) / @as(f64, @floatFromInt(reach_stats.total));
    std.debug.print("reachability: {d} of {d} functions reachable from any entry point ({d:.1} %)\n", .{
        reach_stats.reachable, reach_stats.total, reach_pct,
    });

    try server.serve(allocator, &graph, args.port);
}

fn countDistinctFiles(arena: std.mem.Allocator, fns: []const ast.AstFunction) !usize {
    var set = std.StringHashMap(void).init(arena);
    for (fns) |f| try set.put(f.file, {});
    return set.count();
}

fn printEntryStats(discovered: []const entry.Discovered) void {
    var s: usize = 0;
    var t: usize = 0;
    var i: usize = 0;
    var b: usize = 0;
    var m: usize = 0;
    for (discovered) |d| switch (d.kind) {
        .syscall => s += 1,
        .trap => t += 1,
        .irq => i += 1,
        .boot => b += 1,
        .manual => m += 1,
    };
    std.debug.print("entry: discovered {d} syscalls, {d} traps, {d} IRQs, {d} boot, total {d}\n", .{
        s, t, i, b, discovered.len,
    });
}

/// Synthesizes a tiny graph with three functions and a couple of edges so the
/// server can be exercised in isolation while the real IR parser is built on
/// a parallel branch.
fn buildDemoGraph(arena: std.mem.Allocator) !types.Graph {
    const loc_dispatch = types.SourceLoc{
        .file = "kernel/syscall/dispatch.zig",
        .line = 120,
        .col = 0,
    };
    const loc_vmm = types.SourceLoc{
        .file = "kernel/memory/vmm.zig",
        .line = 42,
        .col = 0,
    };
    const loc_pmm = types.SourceLoc{
        .file = "kernel/memory/pmm.zig",
        .line = 17,
        .col = 0,
    };

    const fn0_callees = try arena.dupe(types.EnrichedEdge, &.{
        .{
            .to = 1,
            .target_name = "vmm.alloc",
            .kind = .direct,
            .site = .{ .file = "kernel/syscall/dispatch.zig", .line = 130, .col = 12 },
        },
        .{
            .to = null,
            .target_name = null,
            .kind = .indirect,
            .site = .{ .file = "kernel/syscall/dispatch.zig", .line = 145, .col = 4 },
        },
    });
    const fn1_callees = try arena.dupe(types.EnrichedEdge, &.{
        .{
            .to = 2,
            .target_name = "pmm.allocPage",
            .kind = .direct,
            .site = .{ .file = "kernel/memory/vmm.zig", .line = 55, .col = 8 },
        },
    });
    const fn2_callees = try arena.dupe(types.EnrichedEdge, &.{});

    const functions = try arena.dupe(types.Function, &.{
        .{
            .id = 0,
            .name = "syscall.dispatch.open",
            .mangled = "syscall.dispatch.open",
            .def_loc = loc_dispatch,
            .is_entry = true,
            .entry_kind = .syscall,
            .callees = fn0_callees,
        },
        .{
            .id = 1,
            .name = "vmm.alloc",
            .mangled = "vmm.alloc",
            .def_loc = loc_vmm,
            .is_entry = false,
            .entry_kind = null,
            .callees = fn1_callees,
        },
        .{
            .id = 2,
            .name = "pmm.allocPage",
            .mangled = "pmm.allocPage",
            .def_loc = loc_pmm,
            .is_entry = false,
            .entry_kind = null,
            .callees = fn2_callees,
        },
    });

    const entry_points = try arena.dupe(types.EntryPoint, &.{
        .{ .fn_id = 0, .kind = .syscall, .label = "syscall.dispatch.open" },
    });

    return .{
        .functions = functions,
        .entry_points = entry_points,
    };
}
