const std = @import("std");

fn buildTestElf(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    comptime name: []const u8,
    result_code: u64,
    assertion_id: u64,
) std.Build.LazyPath {
    const cfg = b.addOptions();
    cfg.addOption(u64, "result_code", result_code);
    cfg.addOption(u64, "assertion_id", assertion_id);

    const app_mod = b.createModule(.{
        .root_source_file = b.path("runner/mock_test.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("test_config", cfg.createModule());

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(b.path("linker.ld"));

    return exe.getEmittedBin();
}

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
    });

    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/lib.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    // self-reference so libz files can `@import("lib")`
    lib_mod.addImport("lib", lib_mod);

    // Two mock test flavors: one passes (result_code=1), one fails
    // (result_code=0); each carries a distinct assertion id so the
    // primary's recv branch sees both shapes.
    const mock_pass_bin = buildTestElf(b, target, lib_mod, "mock_pass", 1, 1);
    const mock_fail_bin = buildTestElf(b, target, lib_mod, "mock_fail", 0, 7);

    const embedded_wf = b.addWriteFiles();
    _ = embedded_wf.addCopyFile(mock_pass_bin, "mock_pass.elf");
    _ = embedded_wf.addCopyFile(mock_fail_bin, "mock_fail.elf");

    // Manifest module surfaces the embedded ELFs as a slice the
    // primary can iterate. The manifest order is the spawn/recv
    // order for the v0 sequential runner.
    const manifest_src = embedded_wf.add("embedded_tests.zig",
        \\pub const Entry = struct {
        \\    name: []const u8,
        \\    bytes: []const u8,
        \\};
        \\
        \\pub const manifest = [_]Entry{
        \\    .{ .name = "mock_pass:01", .bytes = @embedFile("mock_pass.elf") },
        \\    .{ .name = "mock_fail:01", .bytes = @embedFile("mock_fail.elf") },
        \\};
        \\
    );

    const embedded_tests_mod = b.createModule(.{
        .root_source_file = manifest_src,
        .target = target,
        .optimize = .ReleaseSmall,
    });

    const app_mod = b.createModule(.{
        .root_source_file = b.path("runner/primary.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("embedded_tests", embedded_tests_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
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
    exe.setLinkerScript(b.path("linker.ld"));

    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/root_service.elf");
    b.getInstallStep().dependOn(&install.step);

    // Install the individual mock ELFs alongside for inspection.
    const install_pass = b.addInstallFile(mock_pass_bin, "../bin/mock_pass.elf");
    const install_fail = b.addInstallFile(mock_fail_bin, "../bin/mock_fail.elf");
    b.getInstallStep().dependOn(&install_pass.step);
    b.getInstallStep().dependOn(&install_fail.step);
}
