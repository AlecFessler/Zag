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
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
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

fn buildManagerChild(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    embedded_mod: *std.Build.Module,
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
    child_app_mod.addImport("embedded_children", embedded_mod);
    const child_start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
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
        .root_source_file = .{ .cwd_relative = "libz/lib.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
    });

    // Step 1: Build leaf processes
    const serial_driver_bin = buildChild(b, target, lib_mod, "serial_driver", "serial_driver/main.zig");
    const usb_driver_bin = buildChild(b, target, lib_mod, "usb_driver", "usb_driver/main.zig");
    const hello_app_bin = buildChild(b, target, lib_mod, "hello_app", "hello_app/main.zig");

    // Step 2a: Build device_manager with serial_driver + usb_driver embedded
    const dm_embedded_wf = b.addWriteFiles();
    _ = dm_embedded_wf.addCopyFile(serial_driver_bin, "serial_driver.elf");
    _ = dm_embedded_wf.addCopyFile(usb_driver_bin, "usb_driver.elf");
    const dm_embed_src = dm_embedded_wf.add("embedded_children.zig",
        \\pub const serial_driver = @embedFile("serial_driver.elf");
        \\pub const usb_driver = @embedFile("usb_driver.elf");
        \\
    );
    const dm_embedded_mod = b.createModule(.{
        .root_source_file = dm_embed_src,
        .target = target,
        .optimize = .ReleaseSmall,
    });
    const device_manager_bin = buildManagerChild(
        b,
        target,
        lib_mod,
        dm_embedded_mod,
        "device_manager",
        "device_manager/main.zig",
    );

    // Step 2b: Build app_manager with hello_app embedded
    const am_embedded_wf = b.addWriteFiles();
    _ = am_embedded_wf.addCopyFile(hello_app_bin, "hello_app.elf");
    const am_embed_src = am_embedded_wf.add("embedded_children.zig",
        \\pub const hello_app = @embedFile("hello_app.elf");
        \\
    );
    const am_embedded_mod = b.createModule(.{
        .root_source_file = am_embed_src,
        .target = target,
        .optimize = .ReleaseSmall,
    });
    const app_manager_bin = buildManagerChild(
        b,
        target,
        lib_mod,
        am_embedded_mod,
        "app_manager",
        "app_manager/main.zig",
    );

    // Step 3: Build root_service with device_manager + app_manager embedded
    const root_embedded_wf = b.addWriteFiles();
    _ = root_embedded_wf.addCopyFile(device_manager_bin, "device_manager.elf");
    _ = root_embedded_wf.addCopyFile(app_manager_bin, "app_manager.elf");
    const root_embed_src = root_embedded_wf.add("embedded_children.zig",
        \\pub const device_manager = @embedFile("device_manager.elf");
        \\pub const app_manager = @embedFile("app_manager.elf");
        \\
    );
    const root_embedded_mod = b.createModule(.{
        .root_source_file = root_embed_src,
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
    app_mod.addImport("embedded_children", root_embedded_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
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
    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/desktopOS.elf");
    b.getInstallStep().dependOn(&install.step);
}
