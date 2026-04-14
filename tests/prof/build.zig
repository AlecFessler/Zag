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
        .optimize = .Debug,
        .pic = true,
    });
    child_app_mod.addImport("lib", lib_mod);
    const child_start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../tests/libz/start.zig" },
        .target = target,
        .optimize = .Debug,
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
    child_exe.setLinkerScript(.{ .cwd_relative = "../tests/linker.ld" });
    return child_exe.getEmittedBin();
}

pub fn build(b: *std.Build) void {
    const target_arch_str = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";
    const workload = b.option([]const u8, "workload", "kprof workload: yield, ipc, fault, spawn (default: yield)") orelse "yield";

    const workload_src = blk: {
        if (std.mem.eql(u8, workload, "yield")) break :blk "src/yield.zig";
        if (std.mem.eql(u8, workload, "ipc")) break :blk "src/ipc.zig";
        if (std.mem.eql(u8, workload, "fault")) break :blk "src/fault.zig";
        if (std.mem.eql(u8, workload, "spawn")) break :blk "src/spawn.zig";
        @panic("-Dworkload must be one of: yield, ipc, fault, spawn");
    };

    const cpu_arch: std.Target.Cpu.Arch = blk: {
        break :blk if (std.mem.eql(u8, target_arch_str, "x64"))
            .x86_64
        else if (std.mem.eql(u8, target_arch_str, "arm"))
            .aarch64
        else
            @panic("Unsupported target architecture");
    };
    const cpu_model: std.Target.Query.CpuModel = if (cpu_arch == .aarch64)
        .{ .explicit = &std.Target.aarch64.cpu.cortex_a72 }
    else
        .determined_by_arch_os;
    const target = b.resolveTargetQuery(.{
        .cpu_arch = cpu_arch,
        .os_tag = .freestanding,
        .cpu_model = cpu_model,
    });

    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../tests/libz/lib.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });

    // Build the tiny inline children used by the ipc and spawn workloads and
    // stitch them into an embedded_children module (mirrors tests/tests).
    const child_ipc_echo_bin = buildChild(b, target, lib_mod, "child_ipc_echo", "src/children/child_ipc_echo.zig");
    const child_exit_bin = buildChild(b, target, lib_mod, "child_exit", "src/children/child_exit.zig");

    const embedded_wf = b.addWriteFiles();
    _ = embedded_wf.addCopyFile(child_ipc_echo_bin, "child_ipc_echo.elf");
    _ = embedded_wf.addCopyFile(child_exit_bin, "child_exit.elf");
    const embed_src = embedded_wf.add("embedded_children.zig",
        \\pub const child_ipc_echo = @embedFile("child_ipc_echo.elf");
        \\pub const child_exit = @embedFile("child_exit.elf");
        \\
    );
    const embedded_children_mod = b.createModule(.{
        .root_source_file = embed_src,
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });

    const app_mod = b.createModule(.{
        .root_source_file = b.path(workload_src),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("embedded_children", embedded_children_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../tests/libz/start.zig" },
        .target = target,
        .optimize = .Debug,
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
    exe.setLinkerScript(.{ .cwd_relative = "../tests/linker.ld" });

    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/root_service.elf");
    b.getInstallStep().dependOn(&install.step);
}
