const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .Debug,
    });

    // Kernel source modules (pure, std-only)
    const bitmap_freelist_mod = b.addModule("bitmap_freelist", .{
        .root_source_file = b.path("../../kernel/memory/bitmap_freelist.zig"),
        .target = target,
        .optimize = optimize,
    });

    const intrusive_freelist_mod = b.addModule("intrusive_freelist", .{
        .root_source_file = b.path("../../kernel/memory/intrusive_freelist.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Memory shim (re-exports bitmap_freelist + intrusive_freelist)
    const memory_shim_mod = b.addModule("memory", .{
        .root_source_file = b.path("../shims/memory.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bitmap_freelist", .module = bitmap_freelist_mod },
            .{ .name = "intrusive_freelist", .module = intrusive_freelist_mod },
        },
    });

    // Containers shim (not needed for buddy but zag shim expects it)
    const rbt_mod = b.addModule("red_black_tree", .{
        .root_source_file = b.path("../../kernel/containers/red_black_tree.zig"),
        .target = target,
        .optimize = optimize,
    });

    const containers_shim_mod = b.addModule("containers", .{
        .root_source_file = b.path("../shims/containers.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "red_black_tree", .module = rbt_mod },
        },
    });

    // Zag shim (provides zag.memory.* and zag.containers.*)
    const zag_mod = b.addModule("zag", .{
        .root_source_file = b.path("../shims/zag.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "memory", .module = memory_shim_mod },
            .{ .name = "containers", .module = containers_shim_mod },
        },
    });

    // The buddy_allocator module from the kernel
    const buddy_mod = b.addModule("buddy_allocator", .{
        .root_source_file = b.path("../../kernel/memory/buddy_allocator.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zag", .module = zag_mod },
        },
    });

    // DSLab framework modules
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

    // Fuzzer executable
    const fuzz_exe = b.addExecutable(.{
        .name = "buddy_fuzzer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzzer.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "buddy_allocator", .module = buddy_mod },
                .{ .name = "fuzz", .module = fuzz_mod },
                .{ .name = "shared", .module = shared_mod },
            },
        }),
    });
    b.installArtifact(fuzz_exe);

    const fuzz_run = b.addRunArtifact(fuzz_exe);
    if (b.args) |args| fuzz_run.addArgs(args);
    const fuzz_step = b.step("fuzz", "Run buddy allocator fuzzer");
    fuzz_step.dependOn(&fuzz_run.step);

    // Profiler executable
    const prof_exe = b.addExecutable(.{
        .name = "buddy_profiler",
        .root_module = b.createModule(.{
            .root_source_file = b.path("profiler.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "buddy_allocator", .module = buddy_mod },
                .{ .name = "prof", .module = prof_mod },
                .{ .name = "shared", .module = shared_mod },
            },
        }),
    });
    prof_exe.root_module.linkSystemLibrary("c", .{});
    b.installArtifact(prof_exe);

    const prof_run = b.addRunArtifact(prof_exe);
    if (b.args) |args| prof_run.addArgs(args);
    const prof_step = b.step("prof", "Run buddy allocator profiler");
    prof_step.dependOn(&prof_run.step);
}
