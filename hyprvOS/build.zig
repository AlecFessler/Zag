const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
    });

    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/lib.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    lib_mod.addImport("lib", lib_mod);

    const app_mod = b.createModule(.{
        .root_source_file = b.path("vmm/main.zig"),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    app_mod.addImport("lib", lib_mod);

    // Assets module disabled — using NVMe disk loading instead
    // const embedded_wf = b.addWriteFiles();
    // ...
    // app_mod.addImport("assets", assets_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);

    const exe = b.addExecutable(.{
        .name = "hyprvOS",
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(b.path("linker.ld"));

    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/hyprvOS.elf");
    b.getInstallStep().dependOn(&install.step);
}
