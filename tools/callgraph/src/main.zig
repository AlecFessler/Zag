const std = @import("std");

const types = @import("types.zig");

const Args = struct {
    ir_path: []const u8 = "zig-out/kernel.ll",
    kernel_root: []const u8 = "kernel",
    port: u16 = 8080,
    arch: []const u8 = "x64",
    verify: bool = false,
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

    // Phase 1 wiring lands here:
    //   const ir_graph = try ir.parse(allocator, args.ir_path);
    //   const graph = try buildPhase1Graph(allocator, ir_graph);
    //   try server.serve(allocator, graph, args.port);
    return error.NotImplemented;
}
