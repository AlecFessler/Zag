const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
    });

    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../libz/lib.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    lib_mod.addImport("lib", lib_mod);

    const app_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "main.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    app_mod.addImport("lib", lib_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../libz/start.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);

    const exe = b.addExecutable(.{
        .name = "root_service",
        .root_module = start_mod,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    const install = b.addInstallFile(exe.getEmittedBin(), "../../bin/root_service.elf");
    b.getInstallStep().dependOn(&install.step);
}
