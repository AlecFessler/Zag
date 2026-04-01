const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .Debug,
    });

    // Pure kernel source modules
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

    const rbt_mod = b.addModule("red_black_tree", .{
        .root_source_file = b.path("../../kernel/containers/red_black_tree.zig"),
        .target = target,
        .optimize = optimize,
    });

    const range_mod = b.addModule("range", .{
        .root_source_file = b.path("../../kernel/utils/range.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Shim modules
    const containers_shim_mod = b.addModule("containers", .{
        .root_source_file = b.path("../shims/containers.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "red_black_tree", .module = rbt_mod },
        },
    });

    const utils_shim_mod = b.addModule("utils", .{
        .root_source_file = b.path("../shims/utils.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "range", .module = range_mod },
        },
    });

    // Address module needs zag for Range
    // Forward-declare zag module and wire it up
    const sync_shim_mod = b.addModule("sync", .{
        .root_source_file = b.path("../shims/sync.zig"),
        .target = target,
        .optimize = optimize,
    });

    const sched_shim_mod = b.addModule("sched", .{
        .root_source_file = b.path("../shims/sched.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "sync", .module = sync_shim_mod },
        },
    });

    const zag_mod = b.addModule("zag", .{
        .root_source_file = b.path("../shims/zag.zig"),
        .target = target,
        .optimize = optimize,
    });

    const address_mod = b.addModule("address", .{
        .root_source_file = b.path("../../kernel/memory/address.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zag", .module = zag_mod },
        },
    });

    const slab_allocator_mod = b.addModule("slab_allocator", .{
        .root_source_file = b.path("../../kernel/memory/slab_allocator.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zag", .module = zag_mod },
        },
    });

    const memory_shim_mod = b.addModule("memory", .{
        .root_source_file = b.path("../shims/memory.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "address", .module = address_mod },
            .{ .name = "bitmap_freelist", .module = bitmap_freelist_mod },
            .{ .name = "intrusive_freelist", .module = intrusive_freelist_mod },
            .{ .name = "slab_allocator", .module = slab_allocator_mod },
        },
    });

    // Wire up zag's imports
    zag_mod.addImport("memory", memory_shim_mod);
    zag_mod.addImport("containers", containers_shim_mod);
    zag_mod.addImport("sched", sched_shim_mod);
    zag_mod.addImport("utils", utils_shim_mod);

    // The heap_allocator module from the kernel
    const heap_mod = b.addModule("heap_allocator", .{
        .root_source_file = b.path("../../kernel/memory/heap_allocator.zig"),
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
        .name = "heap_fuzzer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzzer.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "heap_allocator", .module = heap_mod },
                .{ .name = "fuzz", .module = fuzz_mod },
                .{ .name = "shared", .module = shared_mod },
            },
        }),
    });
    b.installArtifact(fuzz_exe);

    const fuzz_run = b.addRunArtifact(fuzz_exe);
    if (b.args) |args| fuzz_run.addArgs(args);
    const fuzz_step = b.step("fuzz", "Run heap allocator fuzzer");
    fuzz_step.dependOn(&fuzz_run.step);

    // Profiler executable
    const prof_exe = b.addExecutable(.{
        .name = "heap_profiler",
        .root_module = b.createModule(.{
            .root_source_file = b.path("profiler.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "heap_allocator", .module = heap_mod },
                .{ .name = "prof", .module = prof_mod },
                .{ .name = "shared", .module = shared_mod },
            },
        }),
    });
    prof_exe.root_module.linkSystemLibrary("c", .{});
    b.installArtifact(prof_exe);

    const prof_run = b.addRunArtifact(prof_exe);
    if (b.args) |args| prof_run.addArgs(args);
    const prof_step = b.step("prof", "Run heap allocator profiler");
    prof_step.dependOn(&prof_run.step);
}
