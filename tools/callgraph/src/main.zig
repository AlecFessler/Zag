const std = @import("std");

const ast = @import("ast/index.zig");
const commits = @import("commits.zig");
const def_deps = @import("def_deps.zig");
const entry = @import("entry.zig");
const ir = @import("ir/parse.zig");
const join = @import("join.zig");
const mcp = @import("mcp.zig");
const reachability = @import("reachability.zig");
const repl_mod = @import("repl.zig");
const server = @import("server.zig");
const types = @import("types.zig");
const verify = @import("verify.zig");

const Args = struct {
    /// Single-IR path (legacy, only used in --verify mode).
    ir_path: []const u8 = "zig-out/kernel.ll",
    /// Directory containing kernel.<arch>.ll files. Defaults to
    /// `<build-root>/zig-out`.
    ir_dir: ?[]const u8 = null,
    /// Path to the kernel repo root (for running `zig build`).
    /// Defaults to "../.." relative to the callgraph tool dir.
    build_root: []const u8 = "../..",
    kernel_root: []const u8 = "kernel",
    port: u16 = 8080,
    arch: []const u8 = "x64",
    verify: bool = false,
    no_build: bool = false,
    demo_graph: bool = false,
    repl: bool = false,
    mcp: bool = false,
};

fn parseArgs(allocator: std.mem.Allocator) !Args {
    var args = Args{};
    var it = try std.process.argsWithAllocator(allocator);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--ir")) {
            args.ir_path = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--ir-dir")) {
            args.ir_dir = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--build-root")) {
            args.build_root = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--kernel-root")) {
            args.kernel_root = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--port")) {
            const v = it.next() orelse return error.MissingValue;
            args.port = try std.fmt.parseInt(u16, v, 10);
        } else if (std.mem.eql(u8, arg, "--arch")) {
            args.arch = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--verify")) {
            args.verify = true;
        } else if (std.mem.eql(u8, arg, "--no-build")) {
            args.no_build = true;
        } else if (std.mem.eql(u8, arg, "--demo-graph")) {
            args.demo_graph = true;
        } else if (std.mem.eql(u8, arg, "--repl")) {
            args.repl = true;
        } else if (std.mem.eql(u8, arg, "--mcp")) {
            args.mcp = true;
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
        \\  --build-root PATH   Kernel repo root (defaults to ../..)
        \\  --ir-dir PATH       Directory with kernel.<arch>.ll (defaults to <build-root>/zig-out)
        \\  --ir PATH           Single-IR path used by --verify mode (default: zig-out/kernel.ll)
        \\  --kernel-root PATH  Kernel source root. Default: kernel
        \\  --port PORT         HTTP port. Default: 8080
        \\  --arch x64|aarch64  Target arch for --verify (default: x64)
        \\  --no-build          Skip auto-build; reuse existing kernel.*.ll files
        \\  --verify            Run AST/IR diff and print discrepancies, then exit
        \\  --demo-graph        Skip IR parsing; serve a synthetic 3-function graph
        \\  --repl              Drop into an interactive REPL instead of starting the HTTP server
        \\  --mcp               Run as an MCP server over stdio (auto-spawns the daemon)
        \\  --help              Show this help
        \\
    , .{});
}

const ArchSpec = commits.ArchSpec;

const arch_specs = [_]ArchSpec{
    .{ .build_tag = "x64", .file_tag = "x86_64", .api_tag = "x86_64", .target_arch = .x86_64 },
    .{ .build_tag = "arm", .file_tag = "aarch64", .api_tag = "aarch64", .target_arch = .aarch64 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try parseArgs(allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    if (args.demo_graph) {
        const graph = try buildDemoGraph(arena_allocator);
        var graphs = server.GraphMap.init(allocator);
        defer graphs.deinit();
        try graphs.put("x86_64", graph);
        var registry = commits.Registry.init(
            allocator,
            args.build_root,
            "/var/tmp/cg-worktrees",
            &arch_specs,
        );
        try server.serve(allocator, &graphs, "x86_64", args.build_root, &registry, args.port, std.time.timestamp());
        return;
    }

    if (args.mcp) {
        // MCP shim: never load graphs in-process. The daemon does that.
        try mcp.run(allocator, .{
            .daemon_port = if (args.port == 8080) 18845 else args.port,
            .build_root = try arena_allocator.dupe(u8, args.build_root),
            .kernel_root = try arena_allocator.dupe(u8, args.kernel_root),
        });
        return;
    }

    if (args.verify) {
        std.debug.print("callgraph: ir={s} kernel-root={s} arch={s} (verify)\n", .{
            args.ir_path, args.kernel_root, args.arch,
        });
        const ir_graph = try ir.parse(&arena, args.ir_path);

        const walk = try ast.walkKernelFull(arena_allocator, args.kernel_root);
        const ast_fns = walk.fns;
        const file_count = countDistinctFiles(arena_allocator, ast_fns) catch ast_fns.len;
        std.debug.print("ast: {d} functions across {d} files\n", .{ ast_fns.len, file_count });

        var stdout_buf: [16 * 1024]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
        try verify.run(allocator, &stdout_writer.interface, ir_graph, ast_fns, walk.asts);
        return;
    }

    std.debug.print("callgraph: build-root={s} kernel-root={s} port={d}\n", .{
        args.build_root, args.kernel_root, args.port,
    });

    const ir_dir = args.ir_dir orelse blk: {
        break :blk try std.fs.path.join(arena_allocator, &.{ args.build_root, "zig-out" });
    };

    // Run the kernel build for each arch unless --no-build.
    if (!args.no_build) {
        for (arch_specs) |spec| {
            buildKernel(allocator, args.build_root, spec) catch |err| {
                std.debug.print(
                    "[build {s}] FAILED ({s}); continuing without this arch\n",
                    .{ spec.api_tag, @errorName(err) },
                );
            };
        }
    }

    // Walk AST once.
    const walk = try ast.walkKernelFull(arena_allocator, args.kernel_root);
    const ast_fns = walk.fns;
    const file_count = countDistinctFiles(arena_allocator, ast_fns) catch ast_fns.len;
    std.debug.print("ast: {d} functions across {d} files\n", .{ ast_fns.len, file_count });

    // For each arch with an IR file present, build a Graph.
    var graphs = server.GraphMap.init(allocator);
    defer graphs.deinit();

    var loaded_arches = std.ArrayList([]const u8){};
    defer loaded_arches.deinit(allocator);

    for (arch_specs) |spec| {
        const ir_path = try std.fs.path.join(
            arena_allocator,
            &.{ ir_dir, try std.fmt.allocPrint(arena_allocator, "kernel.{s}.ll", .{spec.file_tag}) },
        );
        // Probe that the file exists before parsing.
        std.fs.cwd().access(ir_path, .{}) catch {
            std.debug.print("[arch {s}] no IR at {s}; skipping\n", .{ spec.api_tag, ir_path });
            continue;
        };

        std.debug.print("[arch {s}] parsing {s}\n", .{ spec.api_tag, ir_path });
        const ir_graph = ir.parse(&arena, ir_path) catch |err| {
            std.debug.print(
                "[arch {s}] IR parse failed: {s}; skipping\n",
                .{ spec.api_tag, @errorName(err) },
            );
            continue;
        };

        const discovered = try entry.discover(
            arena_allocator,
            args.kernel_root,
            spec.build_tag,
            ast_fns,
            walk.asts,
        );

        var stats: join.JoinStats = undefined;
        var graph = try join.buildGraphWithStats(
            arena_allocator,
            ir_graph,
            ast_fns,
            walk.asts,
            walk.struct_types,
            walk.aliases,
            discovered,
            spec.target_arch,
            &stats,
        );

        // Install the Definition catalog for this arch's graph. Phase 1
        // of the diff/review feature: every top-level non-fn declaration
        // becomes a reviewable Definition with an assigned id.
        graph.definitions = try ast.buildDefinitionList(arena_allocator, walk.definitions);

        // Phase 2: walk each fn's tokens, resolve references against the
        // def-qname index, and install Function.def_deps. Best-effort —
        // unresolved refs are dropped silently.
        var dep_cache = try def_deps.Cache.init(
            arena_allocator, graph.definitions, walk.asts, walk.aliases,
        );
        defer dep_cache.deinit();
        def_deps.compute(arena_allocator, &graph, &dep_cache) catch |err| {
            std.debug.print("[arch {s}] def_deps failed: {s}\n", .{ spec.api_tag, @errorName(err) });
        };

        const pct: f64 = if (stats.ir_total == 0)
            0.0
        else
            100.0 * @as(f64, @floatFromInt(stats.matched)) / @as(f64, @floatFromInt(stats.ir_total));
        std.debug.print(
            "[arch {s}] join: {d}/{d} matched ({d:.1}%); entries: {d}/{d}\n",
            .{ spec.api_tag, stats.matched, stats.ir_total, pct, graph.entry_points.len, discovered.len },
        );
        std.debug.print(
            "[arch {s}] ast-only fns: {d} (no IR record; bodies served from AST walk)\n",
            .{ spec.api_tag, stats.ast_only },
        );

        try reachability.computeEntryReach(allocator, &graph);
        const reach_stats = try reachability.compute(allocator, &graph);
        const reach_pct: f64 = if (reach_stats.total == 0)
            0.0
        else
            100.0 * @as(f64, @floatFromInt(reach_stats.reachable)) / @as(f64, @floatFromInt(reach_stats.total));
        std.debug.print(
            "[arch {s}] reachability: {d}/{d} ({d:.1}%)\n",
            .{ spec.api_tag, reach_stats.reachable, reach_stats.total, reach_pct },
        );

        try graphs.put(spec.api_tag, graph);
        try loaded_arches.append(allocator, spec.api_tag);
    }

    if (graphs.count() == 0) {
        std.debug.print("error: no IR files loaded; nothing to serve\n", .{});
        std.process.exit(1);
    }

    // Default to x86_64 if loaded, else first available.
    const default_arch: []const u8 = blk: {
        if (graphs.contains("x86_64")) break :blk "x86_64";
        break :blk loaded_arches.items[0];
    };

    std.debug.print("startup: {d} arches loaded (", .{loaded_arches.items.len});
    for (loaded_arches.items, 0..) |a, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{s}", .{a});
    }
    std.debug.print("); default={s}\n", .{default_arch});

    var registry = commits.Registry.init(
        allocator,
        args.build_root,
        "/var/tmp/cg-worktrees",
        &arch_specs,
    );

    if (args.repl) {
        try repl_mod.run(
            allocator,
            &graphs,
            default_arch,
            args.build_root,
            args.kernel_root,
            &registry,
        );
        return;
    }

    try server.serve(allocator, &graphs, default_arch, args.build_root, &registry, args.port, std.time.timestamp());
}

fn buildKernel(
    allocator: std.mem.Allocator,
    build_root: []const u8,
    spec: ArchSpec,
) !void {
    const argv = [_][]const u8{
        "zig",
        "build",
        "-Dprofile=test",
        "-Demit_ir=true",
    };
    const arch_arg = try std.fmt.allocPrint(allocator, "-Darch={s}", .{spec.build_tag});
    defer allocator.free(arch_arg);

    var argv_full = std.ArrayList([]const u8){};
    defer argv_full.deinit(allocator);
    try argv_full.appendSlice(allocator, &argv);
    try argv_full.append(allocator, arch_arg);

    std.debug.print("[build {s}] running: zig build -Dprofile=test -Demit_ir=true {s} (cwd={s})\n", .{
        spec.api_tag, arch_arg, build_root,
    });

    var child = std.process.Child.init(argv_full.items, allocator);
    child.cwd = build_root;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    // Stream stdout/stderr lines to our stderr with a prefix. Use a thread
    // for stderr so we don't deadlock on pipe-full.
    const PrefixCtx = struct {
        prefix: []const u8,
        reader: std.fs.File,
        fn run(self: *@This()) void {
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = self.reader.read(&buf) catch return;
                if (n == 0) return;
                std.debug.print("[{s}] {s}", .{ self.prefix, buf[0..n] });
            }
        }
    };

    var stdout_ctx = PrefixCtx{
        .prefix = try std.fmt.allocPrint(allocator, "build {s}", .{spec.api_tag}),
        .reader = child.stdout.?,
    };
    defer allocator.free(stdout_ctx.prefix);
    var stderr_ctx = PrefixCtx{
        .prefix = try std.fmt.allocPrint(allocator, "build {s}", .{spec.api_tag}),
        .reader = child.stderr.?,
    };
    defer allocator.free(stderr_ctx.prefix);

    const stderr_thread = try std.Thread.spawn(.{}, PrefixCtx.run, .{&stderr_ctx});
    stdout_ctx.run();
    stderr_thread.join();

    const term = try child.wait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) return error.BuildFailed;
        },
        else => return error.BuildFailed,
    }
}

fn countDistinctFiles(arena: std.mem.Allocator, fns: []const ast.AstFunction) !usize {
    var set = std.StringHashMap(void).init(arena);
    for (fns) |f| try set.put(f.file, {});
    return set.count();
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
