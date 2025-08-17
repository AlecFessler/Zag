const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .Debug,
    });

    const memory_mod = b.addModule("memory", .{
        .root_source_file = b.path("../../kernel/memory/memory.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "buddy_fuzzer",
        .root_source_file = b.path("buddy_fuzzer.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("memory", memory_mod);

    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    const run_step = b.step("run", "Run buddy fuzzer");
    run_step.dependOn(&run.step);
}
