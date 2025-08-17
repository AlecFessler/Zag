const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const memory_mod = b.addModule("memory", .{
        .root_source_file = b.path("../../kernel/memory/memory.zig"),
        .target = target,
        .optimize = optimize,
    });

    const containers_mod = b.addModule("containers", .{
        .root_source_file = b.path("../../kernel/containers/containers.zig"),
        .target = target,
        .optimize = optimize,
    });

    memory_mod.addImport("containers", containers_mod);

    const exe = b.addExecutable(.{
        .name = "heap_fuzzer",
        .root_source_file = b.path("heap_fuzzer.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("memory", memory_mod);

    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);
    const run_step = b.step("run", "Run heap fuzzer");
    run_step.dependOn(&run.step);
}
