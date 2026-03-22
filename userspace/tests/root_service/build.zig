const std = @import("std");

fn buildChild(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    comptime name: []const u8,
    comptime src: []const u8,
) std.Build.LazyPath {
    const child_app_mod = b.createModule(.{
        .root_source_file = b.path(src),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });
    child_app_mod.addImport("lib", lib_mod);
    const child_start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../lib/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });
    child_start_mod.addImport("lib", lib_mod);
    child_start_mod.addImport("app", child_app_mod);
    const child_exe = b.addExecutable(.{
        .name = name,
        .root_module = child_start_mod,
        .linkage = .static,
    });
    child_exe.pie = true;
    child_exe.entry = .{ .symbol_name = "_start" };
    child_exe.setLinkerScript(.{ .cwd_relative = "linker.ld" });
    return child_exe.getEmittedBin();
}

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
    });
    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../lib/lib.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });

    const child_exit_bin = buildChild(b, target, lib_mod, "child_exit", "child_exit.zig");
    const child_shm_counter_bin = buildChild(b, target, lib_mod, "child_shm_counter", "child_shm_counter.zig");
    const child_stack_overflow_bin = buildChild(b, target, lib_mod, "child_stack_overflow", "child_stack_overflow.zig");
    const child_restart_counter_bin = buildChild(b, target, lib_mod, "child_restart_counter", "child_restart_counter.zig");
    const child_multithread_bin = buildChild(b, target, lib_mod, "child_multithread", "child_multithread.zig");
    const child_spawner_bin = buildChild(b, target, lib_mod, "child_spawner", "child_spawner.zig");
    const child_restart_verify_bin = buildChild(b, target, lib_mod, "child_restart_verify", "child_restart_verify.zig");
    const child_shm_writer_bin = buildChild(b, target, lib_mod, "child_shm_writer", "child_shm_writer.zig");

    const embedded_wf = b.addWriteFiles();
    _ = embedded_wf.addCopyFile(child_exit_bin, "child_exit.elf");
    _ = embedded_wf.addCopyFile(child_shm_counter_bin, "child_shm_counter.elf");
    _ = embedded_wf.addCopyFile(child_stack_overflow_bin, "child_stack_overflow.elf");
    _ = embedded_wf.addCopyFile(child_restart_counter_bin, "child_restart_counter.elf");
    _ = embedded_wf.addCopyFile(child_multithread_bin, "child_multithread.elf");
    _ = embedded_wf.addCopyFile(child_spawner_bin, "child_spawner.elf");
    _ = embedded_wf.addCopyFile(child_restart_verify_bin, "child_restart_verify.elf");
    _ = embedded_wf.addCopyFile(child_shm_writer_bin, "child_shm_writer.elf");
    const embed_src = embedded_wf.add("embedded_children.zig",
        \\pub const child_exit = @embedFile("child_exit.elf");
        \\pub const child_shm_counter = @embedFile("child_shm_counter.elf");
        \\pub const child_stack_overflow = @embedFile("child_stack_overflow.elf");
        \\pub const child_restart_counter = @embedFile("child_restart_counter.elf");
        \\pub const child_multithread = @embedFile("child_multithread.elf");
        \\pub const child_spawner = @embedFile("child_spawner.elf");
        \\pub const child_restart_verify = @embedFile("child_restart_verify.elf");
        \\pub const child_shm_writer = @embedFile("child_shm_writer.elf");
        \\
    );

    const embedded_children_mod = b.createModule(.{
        .root_source_file = embed_src,
        .target = target,
        .optimize = .ReleaseSmall,
    });

    const app_mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("embedded_children", embedded_children_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../lib/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);
    const exe = b.addExecutable(.{
        .name = "root_service",
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(.{ .cwd_relative = "linker.ld" });
    const install = b.addInstallFile(exe.getEmittedBin(), "../../../bin/root_service.elf");
    b.getInstallStep().dependOn(&install.step);
}
