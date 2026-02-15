const std = @import("std");

pub fn build(b: *std.Build) void {
    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../lib/lib.zig" },
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .x86_64,
            .os_tag = .freestanding,
        }),
        .optimize = .ReleaseSmall,
    });

    const exe = b.addExecutable(.{
        .name = "mem_reserve",
        .root_module = b.createModule(.{
            .root_source_file = b.path("mem_reserve.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .freestanding,
            }),
            .optimize = .ReleaseSmall,
        }),
        .linkage = .static,
    });
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(.{ .cwd_relative = "linker.ld" });
    exe.root_module.addImport("lib", lib_mod);

    const objcopy = b.addObjCopy(exe.getEmittedBin(), .{ .format = .bin });
    const install = b.addInstallFile(objcopy.getOutput(), "../../../bin/mem_reserve.bin");
    b.getInstallStep().dependOn(&install.step);
}
