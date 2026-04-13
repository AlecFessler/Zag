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
        .optimize = .ReleaseSafe,
        .pic = true,
    });
    child_app_mod.addImport("lib", lib_mod);
    const child_start_mod = b.createModule(.{
        .root_source_file = b.path("start.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
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
    child_exe.setLinkerScript(b.path("linker.ld"));
    return child_exe.getEmittedBin();
}

pub fn build(b: *std.Build) void {
    const single_test = b.option([]const u8, "test", "Build only this test (e.g. perf_ipc). Omit to build all.");

    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
    });
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("lib.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .pic = true,
    });

    // --- Children ---
    const child_perf_ipc_echo_bin = buildChild(b, target, lib_mod, "child_perf_ipc_echo", "children/child_perf_ipc_echo.zig");
    const child_perf_ipc_client_bin = buildChild(b, target, lib_mod, "child_perf_ipc_client", "children/child_perf_ipc_client.zig");
    const child_perf_futex_waiter_bin = buildChild(b, target, lib_mod, "child_perf_futex_waiter", "children/child_perf_futex_waiter.zig");
    const child_perf_workload_bin = buildChild(b, target, lib_mod, "child_perf_workload", "children/child_perf_workload.zig");
    const child_perf_fault_int3_bin = buildChild(b, target, lib_mod, "child_perf_fault_int3", "children/child_perf_fault_int3.zig");
    const child_perf_debug_target_bin = buildChild(b, target, lib_mod, "child_perf_debug_target", "children/child_perf_debug_target.zig");

    // --- Embedded children module ---
    const embedded_wf = b.addWriteFiles();
    _ = embedded_wf.addCopyFile(child_perf_ipc_echo_bin, "child_perf_ipc_echo.elf");
    _ = embedded_wf.addCopyFile(child_perf_ipc_client_bin, "child_perf_ipc_client.elf");
    _ = embedded_wf.addCopyFile(child_perf_futex_waiter_bin, "child_perf_futex_waiter.elf");
    _ = embedded_wf.addCopyFile(child_perf_workload_bin, "child_perf_workload.elf");
    _ = embedded_wf.addCopyFile(child_perf_fault_int3_bin, "child_perf_fault_int3.elf");
    _ = embedded_wf.addCopyFile(child_perf_debug_target_bin, "child_perf_debug_target.elf");

    const embed_src = embedded_wf.addCopyFile(b.addWriteFiles().add("embedded_children.zig",
        \\pub const child_perf_ipc_echo = @embedFile("child_perf_ipc_echo.elf");
        \\pub const child_perf_ipc_client = @embedFile("child_perf_ipc_client.elf");
        \\pub const child_perf_futex_waiter = @embedFile("child_perf_futex_waiter.elf");
        \\pub const child_perf_workload = @embedFile("child_perf_workload.elf");
        \\pub const child_perf_fault_int3 = @embedFile("child_perf_fault_int3.elf");
        \\pub const child_perf_debug_target = @embedFile("child_perf_debug_target.elf");
        \\
    ), "embedded_children.zig");

    const embedded_children_mod = b.createModule(.{
        .root_source_file = embed_src,
        .target = target,
        .optimize = .ReleaseSafe,
    });

    // --- Iterate tests/ directory, build one ELF per .zig file ---
    var tests_dir = std.fs.cwd().openDir("tests", .{ .iterate = true }) catch
        @panic("Cannot open tests/ directory");
    defer tests_dir.close();

    var it = tests_dir.iterate();
    while (it.next() catch @panic("Failed to iterate tests/")) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
        if (!std.mem.startsWith(u8, entry.name, "perf_")) continue;

        const stem = entry.name[0 .. entry.name.len - 4];

        if (single_test) |wanted| {
            if (!std.mem.eql(u8, stem, wanted)) continue;
        }

        const app_mod = b.createModule(.{
            .root_source_file = b.path(b.fmt("tests/{s}", .{entry.name})),
            .target = target,
            .optimize = .ReleaseSafe,
            .pic = true,
        });
        app_mod.addImport("lib", lib_mod);
        app_mod.addImport("embedded_children", embedded_children_mod);

        const start_mod = b.createModule(.{
            .root_source_file = b.path("start.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .pic = true,
        });
        start_mod.addImport("lib", lib_mod);
        start_mod.addImport("app", app_mod);

        const exe = b.addExecutable(.{
            .name = @ptrCast(stem),
            .root_module = start_mod,
            .linkage = .static,
        });
        exe.pie = true;
        exe.entry = .{ .symbol_name = "_start" };
        exe.setLinkerScript(b.path("linker.ld"));

        const install = b.addInstallFile(exe.getEmittedBin(), b.fmt("../bin/{s}.elf", .{stem}));
        b.getInstallStep().dependOn(&install.step);
    }
}
