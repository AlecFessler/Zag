const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });

    // Pure kernel source modules
    const bitmap_freelist_mod = b.addModule("bitmap_freelist", .{
        .root_source_file = b.path("../../kernel/memory/allocators/bitmap_freelist.zig"),
        .target = target,
        .optimize = optimize,
    });

    const intrusive_freelist_mod = b.addModule("intrusive_freelist", .{
        .root_source_file = b.path("../../kernel/memory/allocators/intrusive_freelist.zig"),
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

    const paging_mod = b.addModule("paging", .{
        .root_source_file = b.path("../../kernel/memory/paging.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Shim modules
    const containers_shim = b.addModule("containers", .{
        .root_source_file = b.path("../shims/containers.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "red_black_tree", .module = rbt_mod }},
    });

    const sync_shim = b.addModule("sync", .{
        .root_source_file = b.path("../shims/sync.zig"),
        .target = target,
        .optimize = optimize,
    });

    const utils_shim = b.addModule("utils", .{
        .root_source_file = b.path("../shims/utils.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "range", .module = range_mod },
            .{ .name = "sync", .module = sync_shim },
        },
    });

    // sync_shim already declared above for utils

    const sched_shim = b.addModule("sched", .{
        .root_source_file = b.path("../shims/sched.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sync", .module = sync_shim }},
    });

    const perms_privilege_mod = b.addModule("perms_privilege", .{
        .root_source_file = b.path("../shims/perms_privilege.zig"),
        .target = target,
        .optimize = optimize,
    });

    const perms_memory_mod = b.addModule("perms_memory", .{
        .root_source_file = b.path("../shims/perms_memory.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "perms_privilege", .module = perms_privilege_mod }},
    });

    const perms_permissions_mod = b.addModule("perms_permissions", .{
        .root_source_file = b.path("../shims/perms_permissions.zig"),
        .target = target,
        .optimize = optimize,
    });

    const perms_shim = b.addModule("perms", .{
        .root_source_file = b.path("../shims/perms.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "perms_memory", .module = perms_memory_mod },
            .{ .name = "perms_permissions", .module = perms_permissions_mod },
            .{ .name = "perms_privilege", .module = perms_privilege_mod },
        },
    });

    // Forward-declared zag module
    const zag_mod = b.addModule("zag", .{
        .root_source_file = b.path("../shims/zag.zig"),
        .target = target,
        .optimize = optimize,
    });

    const address_mod = b.addModule("address", .{
        .root_source_file = b.path("../../kernel/memory/address.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zag", .module = zag_mod }},
    });

    const slab_allocator_mod = b.addModule("slab_allocator", .{
        .root_source_file = b.path("../../kernel/memory/allocators/slab.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zag", .module = zag_mod }},
    });

    // Shims that depend on memory (circular: memory <-> device_region/shared)
    const memory_shim = b.addModule("memory", .{
        .root_source_file = b.path("../shims/memory.zig"),
        .target = target,
        .optimize = optimize,
    });

    const device_region_mod = b.addModule("device_region", .{
        .root_source_file = b.path("../shims/device_region.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "memory", .module = memory_shim }},
    });

    const shared_mod = b.addModule("shared_memory", .{
        .root_source_file = b.path("../shims/shared.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "memory", .module = memory_shim }},
    });

    const pmm_mod = b.addModule("pmm", .{
        .root_source_file = b.path("../shims/pmm.zig"),
        .target = target,
        .optimize = optimize,
    });

    const arch_shim = b.addModule("arch", .{
        .root_source_file = b.path("../shims/arch.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "memory", .module = memory_shim },
            .{ .name = "perms", .module = perms_shim },
        },
    });

    // Allocators shim
    const allocators_shim = b.addModule("allocators", .{
        .root_source_file = b.path("../shims/allocators.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "bitmap_freelist", .module = bitmap_freelist_mod },
            .{ .name = "intrusive_freelist", .module = intrusive_freelist_mod },
            .{ .name = "slab_allocator", .module = slab_allocator_mod },
        },
    });

    // Wire up memory shim imports
    memory_shim.addImport("address", address_mod);
    memory_shim.addImport("allocators", allocators_shim);
    memory_shim.addImport("bitmap_freelist", bitmap_freelist_mod);
    memory_shim.addImport("device_region", device_region_mod);
    memory_shim.addImport("intrusive_freelist", intrusive_freelist_mod);
    memory_shim.addImport("paging", paging_mod);
    memory_shim.addImport("pmm", pmm_mod);
    memory_shim.addImport("shared", shared_mod);
    memory_shim.addImport("slab_allocator", slab_allocator_mod);

    // Wire up zag's imports
    zag_mod.addImport("arch", arch_shim);
    zag_mod.addImport("containers", containers_shim);
    zag_mod.addImport("memory", memory_shim);
    zag_mod.addImport("perms", perms_shim);
    zag_mod.addImport("sched", sched_shim);
    zag_mod.addImport("utils", utils_shim);

    // The real vmm module from the kernel
    const vmm_mod = b.addModule("vmm", .{
        .root_source_file = b.path("../../kernel/memory/vmm.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zag", .module = zag_mod }},
    });

    // DSLab framework modules
    const dslab_shared_mod = b.addModule("dslab_shared", .{
        .root_source_file = b.path("../lib/shared/shared.zig"),
        .target = target,
        .optimize = optimize,
    });

    const fuzz_mod = b.addModule("fuzz", .{
        .root_source_file = b.path("../lib/fuzz/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "shared", .module = dslab_shared_mod }},
    });

    const prof_mod = b.addModule("prof", .{
        .root_source_file = b.path("../lib/prof/prof.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "shared", .module = dslab_shared_mod }},
    });

    // Fuzzer executable
    const fuzz_exe = b.addExecutable(.{
        .name = "vmm_fuzzer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzzer.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vmm", .module = vmm_mod },
                .{ .name = "address", .module = address_mod },
                .{ .name = "perms_permissions", .module = perms_permissions_mod },
                .{ .name = "fuzz", .module = fuzz_mod },
                .{ .name = "dslab_shared", .module = dslab_shared_mod },
            },
        }),
    });
    b.installArtifact(fuzz_exe);

    const fuzz_run = b.addRunArtifact(fuzz_exe);
    if (b.args) |args| fuzz_run.addArgs(args);
    const fuzz_step = b.step("fuzz", "Run VMM fuzzer");
    fuzz_step.dependOn(&fuzz_run.step);

    // Profiler executable
    const prof_exe = b.addExecutable(.{
        .name = "vmm_profiler",
        .root_module = b.createModule(.{
            .root_source_file = b.path("profiler.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vmm", .module = vmm_mod },
                .{ .name = "address", .module = address_mod },
                .{ .name = "perms_permissions", .module = perms_permissions_mod },
                .{ .name = "prof", .module = prof_mod },
                .{ .name = "dslab_shared", .module = dslab_shared_mod },
            },
        }),
    });
    prof_exe.root_module.linkSystemLibrary("c", .{});
    b.installArtifact(prof_exe);

    const prof_run = b.addRunArtifact(prof_exe);
    if (b.args) |args| prof_run.addArgs(args);
    const prof_step = b.step("prof", "Run VMM profiler");
    prof_step.dependOn(&prof_run.step);
}
