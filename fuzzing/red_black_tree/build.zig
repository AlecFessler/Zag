const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });

    const rbt_mod = b.addModule("red_black_tree", .{
        .root_source_file = b.path("../../kernel/utils/containers/red_black_tree.zig"),
        .target = target,
        .optimize = optimize,
    });

    const shared_mod = b.addModule("shared", .{
        .root_source_file = b.path("../lib/shared/shared.zig"),
        .target = target,
        .optimize = optimize,
    });

    const fuzz_mod = b.addModule("fuzz", .{
        .root_source_file = b.path("../lib/fuzz/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "shared", .module = shared_mod }},
    });

    const prof_mod = b.addModule("prof", .{
        .root_source_file = b.path("../lib/prof/prof.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "shared", .module = shared_mod }},
    });

    // Fuzzer
    const fuzz_exe = b.addExecutable(.{
        .name = "rbt_fuzzer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzzer.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "red_black_tree", .module = rbt_mod },
                .{ .name = "fuzz", .module = fuzz_mod },
                .{ .name = "shared", .module = shared_mod },
            },
        }),
    });
    b.installArtifact(fuzz_exe);

    const fuzz_run = b.addRunArtifact(fuzz_exe);
    if (b.args) |args| fuzz_run.addArgs(args);
    const fuzz_step = b.step("fuzz", "Run red-black tree fuzzer");
    fuzz_step.dependOn(&fuzz_run.step);

    // Profiler
    const prof_exe = b.addExecutable(.{
        .name = "rbt_profiler",
        .root_module = b.createModule(.{
            .root_source_file = b.path("profiler.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "red_black_tree", .module = rbt_mod },
                .{ .name = "prof", .module = prof_mod },
                .{ .name = "shared", .module = shared_mod },
            },
        }),
    });
    prof_exe.root_module.linkSystemLibrary("c", .{});
    b.installArtifact(prof_exe);

    const prof_run = b.addRunArtifact(prof_exe);
    if (b.args) |args| prof_run.addArgs(args);
    const prof_step = b.step("prof", "Run red-black tree profiler");
    prof_step.dependOn(&prof_run.step);
}
