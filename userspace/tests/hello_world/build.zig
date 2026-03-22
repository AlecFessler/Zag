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
    });
    const app_mod = b.createModule(.{
        .root_source_file = b.path("hello_world.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
    });
    app_mod.addImport("lib", lib_mod);
    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../lib/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);
    const exe = b.addExecutable(.{
        .name = "hello_world",
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(.{ .cwd_relative = "linker.ld" });
    const objcopy = b.addObjCopy(exe.getEmittedBin(), .{ .format = .bin });
    const install = b.addInstallFile(objcopy.getOutput(), "../../../bin/hello_world.bin");
    b.getInstallStep().dependOn(&install.step);
}
