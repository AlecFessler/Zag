const std = @import("std");

const ir = @import("ir/parse.zig");
const server = @import("server.zig");
const types = @import("types.zig");

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

    const graph = if (args.demo_graph)
        try buildDemoGraph(arena_allocator)
    else blk: {
        const ir_graph = try ir.parse(&arena, args.ir_path);
        break :blk try buildPhase1Graph(arena_allocator, ir_graph);
    };

    try server.serve(allocator, &graph, args.port);
}

/// Phase-1 transform: each IR function becomes a Function with mangled name as
/// display name (demangling lands in phase 2). Outgoing edges from the IR
/// graph are bucketed per `from` and converted to EnrichedEdges.
fn buildPhase1Graph(
    arena: std.mem.Allocator,
    ir_graph: types.IrGraph,
) !types.Graph {
    // Bucket edges by `from` in a single pass.
    var edges_by_fn = std.AutoHashMap(types.FnId, std.ArrayList(types.EnrichedEdge)).init(arena);
    for (ir_graph.edges) |edge| {
        const kind: types.EdgeKind = if (edge.indirect or edge.to == null)
            .indirect
        else
            .direct;
        const enriched = types.EnrichedEdge{
            .to = edge.to,
            .target_name = null,
            .kind = kind,
            .site = edge.site,
        };
        const gop = try edges_by_fn.getOrPut(edge.from);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.append(arena, enriched);
    }

    var functions = try arena.alloc(types.Function, ir_graph.functions.len);
    for (ir_graph.functions, 0..) |ir_fn, i| {
        const callees: []types.EnrichedEdge = if (edges_by_fn.get(ir_fn.id)) |list|
            try arena.dupe(types.EnrichedEdge, list.items)
        else
            &.{};
        functions[i] = .{
            .id = ir_fn.id,
            .name = ir_fn.mangled,
            .mangled = ir_fn.mangled,
            .def_loc = ir_fn.def_loc orelse .{ .file = "<unknown>", .line = 0, .col = 0 },
            .is_entry = false,
            .entry_kind = null,
            .callees = callees,
        };
    }

    try applyEntryHeuristic(arena, functions);

    var entry_points = std.ArrayList(types.EntryPoint){};
    for (functions) |f| {
        if (f.is_entry) {
            try entry_points.append(arena, .{
                .fn_id = f.id,
                .kind = f.entry_kind orelse .manual,
                .label = f.name,
            });
        }
    }

    return .{
        .functions = functions,
        .entry_points = try entry_points.toOwnedSlice(arena),
    };
}

/// Heuristic entry-point detection. Real auto-discovery is phase 4; this is
/// just enough to give the frontend something to render. Mark every function
/// whose def_loc.file ends with one of a small set of dispatch/exception
/// files; if that yields nothing, fall back to a name-substring scan.
fn applyEntryHeuristic(arena: std.mem.Allocator, functions: []types.Function) !void {
    _ = arena;
    const path_suffixes = [_][]const u8{
        "kernel/syscall/dispatch.zig",
        "kernel/arch/x64/exceptions.zig",
        "kernel/arch/x64/idt.zig",
    };

    var marked: usize = 0;
    for (functions) |*f| {
        for (path_suffixes) |suffix| {
            if (std.mem.endsWith(u8, f.def_loc.file, suffix)) {
                f.is_entry = true;
                f.entry_kind = entryKindForFile(f.def_loc.file);
                marked += 1;
                break;
            }
        }
    }
    if (marked > 0) return;

    // Fallback — pick up to 5 by name substring.
    const name_substrs = [_][]const u8{ "entry", "syscall", "handler" };
    var picked: usize = 0;
    for (functions) |*f| {
        if (picked >= 5) break;
        for (name_substrs) |needle| {
            if (std.mem.indexOf(u8, f.mangled, needle) != null) {
                f.is_entry = true;
                f.entry_kind = .manual;
                picked += 1;
                break;
            }
        }
    }
}

fn entryKindForFile(file: []const u8) types.EntryKind {
    if (std.mem.endsWith(u8, file, "kernel/syscall/dispatch.zig")) return .syscall;
    if (std.mem.endsWith(u8, file, "kernel/arch/x64/exceptions.zig")) return .trap;
    if (std.mem.endsWith(u8, file, "kernel/arch/x64/idt.zig")) return .irq;
    return .manual;
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
