const std = @import("std");
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
    const app_mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });
    app_mod.addImport("lib", lib_mod);
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
