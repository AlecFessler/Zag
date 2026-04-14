const std = @import("std");

pub fn build(b: *std.Build) void {
    const arch_opt = b.option([]const u8, "arch", "Target architecture: x64 (default) or arm") orelse "x64";
    const is_arm = std.mem.eql(u8, arch_opt, "arm");

    const target = if (is_arm)
        b.resolveTargetQuery(.{
            .cpu_arch = .aarch64,
            .os_tag = .freestanding,
        })
    else
        b.resolveTargetQuery(.{
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

    const app_root = if (is_arm) "vmm/aarch64/main.zig" else "vmm/main.zig";

    const app_mod = b.createModule(.{
        .root_source_file = b.path(app_root),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    app_mod.addImport("lib", lib_mod);

    // Embedded assets for QEMU fallback (NVMe may not work in emulation).
    // Only the x64 path consumes this today; the aarch64 path does not yet
    // embed a Linux arm64 Image + initramfs (see vmm/aarch64/initramfs.zig).
    if (!is_arm) {
        const assets_mod = b.createModule(.{
            .root_source_file = b.path("assets/assets.zig"),
            .target = target,
            .optimize = .Debug,
            .pic = true,
        });
        app_mod.addImport("assets", assets_mod);
    }

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);

    const exe_name = if (is_arm) "hyprvOS-arm" else "hyprvOS";
    const exe = b.addExecutable(.{
        .name = exe_name,
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(b.path("linker.ld"));

    const install_name = if (is_arm) "../bin/hyprvOS-arm.elf" else "../bin/hyprvOS.elf";
    const install = b.addInstallFile(exe.getEmittedBin(), install_name);
    b.getInstallStep().dependOn(&install.step);
}
