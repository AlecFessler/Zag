const std = @import("std");

fn buildChild(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    prof_lib_mod: ?*std.Build.Module,
    extra_imports: []const struct { name: []const u8, mod: *std.Build.Module },
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
    if (prof_lib_mod) |pl| child_app_mod.addImport("prof_lib", pl);
    for (extra_imports) |imp| child_app_mod.addImport(imp.name, imp.mod);

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
    const workload = b.option([]const u8, "workload", "kprof workload: yield, ipc, fault, spawn, shm_cycle, debugger, composed, fpu_mix (default: yield)") orelse "yield";

    const workload_src = blk: {
        if (std.mem.eql(u8, workload, "yield")) break :blk "src/yield.zig";
        if (std.mem.eql(u8, workload, "ipc")) break :blk "src/ipc.zig";
        if (std.mem.eql(u8, workload, "fault")) break :blk "src/fault.zig";
        if (std.mem.eql(u8, workload, "spawn")) break :blk "src/spawn.zig";
        if (std.mem.eql(u8, workload, "shm_cycle")) break :blk "src/shm_cycle.zig";
        if (std.mem.eql(u8, workload, "debugger")) break :blk "src/debugger.zig";
        if (std.mem.eql(u8, workload, "composed")) break :blk "src/composed.zig";
        if (std.mem.eql(u8, workload, "fpu_mix")) break :blk "src/fpu_mix.zig";
        @panic("-Dworkload must be one of: yield, ipc, fault, spawn, shm_cycle, debugger, composed, fpu_mix");
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

    // Prof-local libz: shared protocol / types between root and children.
    const prof_lib_mod = b.createModule(.{
        .root_source_file = b.path("libz/lib.zig"),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    prof_lib_mod.addImport("lib", lib_mod);

    // Children used by existing workloads.
    const child_ipc_echo_bin = buildChild(b, target, lib_mod, null, &.{}, "child_ipc_echo", "src/children/child_ipc_echo.zig");
    const child_exit_bin = buildChild(b, target, lib_mod, null, &.{}, "child_exit", "src/children/child_exit.zig");
    const child_shm_cycle_bin = buildChild(b, target, lib_mod, null, &.{}, "child_shm_cycle", "src/children/child_shm_cycle.zig");

    // Debugger scenario children. child_debuggee is a normal child with
    // prof_lib access for protocol constants. child_debugger is the same
    // but additionally carries an embedded copy of the debuggee ELF so
    // it can (later) symbolize fault_addr via DWARF and so the build
    // pipeline pulls the debuggee ELF into a single artifact.
    const child_debuggee_bin = buildChild(b, target, lib_mod, prof_lib_mod, &.{}, "child_debuggee", "src/children/child_debuggee.zig");

    const debuggee_embed_wf = b.addWriteFiles();
    _ = debuggee_embed_wf.addCopyFile(child_debuggee_bin, "debuggee.elf");
    const debuggee_embed_src = debuggee_embed_wf.add(
        "debuggee_elf.zig",
        "pub const bytes = @embedFile(\"debuggee.elf\");\n",
    );
    const debuggee_embed_mod = b.createModule(.{
        .root_source_file = debuggee_embed_src,
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });

    const child_debugger_bin = buildChild(
        b,
        target,
        lib_mod,
        prof_lib_mod,
        &.{.{ .name = "debuggee_elf", .mod = debuggee_embed_mod }},
        "child_debugger",
        "src/children/child_debugger.zig",
    );

    const embedded_wf = b.addWriteFiles();
    _ = embedded_wf.addCopyFile(child_ipc_echo_bin, "child_ipc_echo.elf");
    _ = embedded_wf.addCopyFile(child_exit_bin, "child_exit.elf");
    _ = embedded_wf.addCopyFile(child_shm_cycle_bin, "child_shm_cycle.elf");
    _ = embedded_wf.addCopyFile(child_debuggee_bin, "child_debuggee.elf");
    _ = embedded_wf.addCopyFile(child_debugger_bin, "child_debugger.elf");
    const embed_src = embedded_wf.add("embedded_children.zig",
        \\pub const child_ipc_echo = @embedFile("child_ipc_echo.elf");
        \\pub const child_exit = @embedFile("child_exit.elf");
        \\pub const child_shm_cycle = @embedFile("child_shm_cycle.elf");
        \\pub const child_debuggee = @embedFile("child_debuggee.elf");
        \\pub const child_debugger = @embedFile("child_debugger.elf");
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
    app_mod.addImport("prof_lib", prof_lib_mod);
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
