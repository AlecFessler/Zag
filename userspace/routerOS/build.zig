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
        .optimize = .ReleaseSmall,
        .pic = true,
    });
    child_app_mod.addImport("lib", lib_mod);
    const child_start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../lib/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
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
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
    });
    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../lib/lib.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });

    const serial_driver_bin = buildChild(b, target, lib_mod, "serial_driver", "serial_driver/main.zig");
    const router_bin = buildChild(b, target, lib_mod, "router", "router/main.zig");
    const console_bin = buildChild(b, target, lib_mod, "console", "console/main.zig");
    const nfs_client_bin = buildChild(b, target, lib_mod, "nfs_client", "nfs_client/main.zig");
    const ntp_client_bin = buildChild(b, target, lib_mod, "ntp_client", "ntp_client/main.zig");

    const embedded_wf = b.addWriteFiles();
    _ = embedded_wf.addCopyFile(serial_driver_bin, "serial_driver.elf");
    _ = embedded_wf.addCopyFile(router_bin, "router.elf");
    _ = embedded_wf.addCopyFile(console_bin, "console.elf");
    _ = embedded_wf.addCopyFile(nfs_client_bin, "nfs_client.elf");
    _ = embedded_wf.addCopyFile(ntp_client_bin, "ntp_client.elf");
    const embed_src = embedded_wf.add("embedded_children.zig",
        \\pub const serial_driver = @embedFile("serial_driver.elf");
        \\pub const router = @embedFile("router.elf");
        \\pub const console = @embedFile("console.elf");
        \\pub const nfs_client = @embedFile("nfs_client.elf");
        \\pub const ntp_client = @embedFile("ntp_client.elf");
        \\
    );

    const embedded_children_mod = b.createModule(.{
        .root_source_file = embed_src,
        .target = target,
        .optimize = .ReleaseSmall,
    });

    const app_mod = b.createModule(.{
        .root_source_file = b.path("root_service/main.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("embedded_children", embedded_children_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../lib/start.zig" },
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
    exe.setLinkerScript(b.path("linker.ld"));
    const install = b.addInstallFile(exe.getEmittedBin(), "../../bin/routerOS.elf");
    b.getInstallStep().dependOn(&install.step);
}
