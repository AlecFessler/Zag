const std = @import("std");

fn buildProcess(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    comptime name: []const u8,
    comptime src: []const u8,
    embedded_mod: ?*std.Build.Module,
) std.Build.LazyPath {
    const child_app_mod = b.createModule(.{
        .root_source_file = b.path(src),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    child_app_mod.addImport("lib", lib_mod);
    if (embedded_mod) |em| {
        child_app_mod.addImport("embedded_children", em);
    }
    const child_start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .Debug,
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
    child_exe.use_llvm = true;
    child_exe.use_lld = true;
    child_exe.entry = .{ .symbol_name = "_start" };
    child_exe.setLinkerScript(b.path("linker.ld"));
    child_exe.root_module.strip = true;
    return child_exe.getEmittedBin();
}

fn buildUtil(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    comptime name: []const u8,
    comptime src: []const u8,
) std.Build.LazyPath {
    const child_app_mod = b.createModule(.{
        .root_source_file = b.path(src),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    child_app_mod.addImport("lib", lib_mod);
    const child_start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/simple_start.zig" },
        .target = target,
        .optimize = .Debug,
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
    child_exe.use_llvm = true;
    child_exe.use_lld = true;
    child_exe.entry = .{ .symbol_name = "_start" };
    child_exe.setLinkerScript(b.path("linker.ld"));
    child_exe.root_module.strip = true;
    return child_exe.getEmittedBin();
}

fn makeEmbeddedModule1(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    comptime name: []const u8,
    path: std.Build.LazyPath,
) *std.Build.Module {
    const wf = b.addWriteFiles();
    _ = wf.addCopyFile(path, name);
    const id = comptime name[0 .. name.len - 4];
    return b.createModule(.{
        .root_source_file = wf.add("embedded_children.zig",
            "pub const " ++ id ++ " = @embedFile(\"" ++ name ++ "\");\n"),
        .target = target,
        .optimize = .Debug,
    });
}

fn makeEmbeddedModule2(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    comptime name1: []const u8,
    path1: std.Build.LazyPath,
    comptime name2: []const u8,
    path2: std.Build.LazyPath,
) *std.Build.Module {
    const wf = b.addWriteFiles();
    _ = wf.addCopyFile(path1, name1);
    _ = wf.addCopyFile(path2, name2);
    const id1 = comptime name1[0 .. name1.len - 4];
    const id2 = comptime name2[0 .. name2.len - 4];
    return b.createModule(.{
        .root_source_file = wf.add("embedded_children.zig",
            "pub const " ++ id1 ++ " = @embedFile(\"" ++ name1 ++ "\");\n" ++
                "pub const " ++ id2 ++ " = @embedFile(\"" ++ name2 ++ "\");\n"),
        .target = target,
        .optimize = .Debug,
    });
}

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
    lib_mod.addImport("lib", lib_mod); // self-reference so libz files can @import("lib")

    // ── Level 0: Leaf processes and utilities ─────────────────────
    const compositor = buildProcess(b, target, lib_mod, "compositor", "compositor/main.zig", null);
    const usb_driver = buildProcess(b, target, lib_mod, "usb_driver", "usb_driver/main.zig", null);
    const echo = buildUtil(b, target, lib_mod, "echo", "zutils/echo/main.zig");

    // Terminal embeds echo, so it's built as a manager
    const echo_embed = makeEmbeddedModule1(b, target, "echo.elf", echo);
    const terminal = buildProcess(b, target, lib_mod, "terminal", "terminal/main.zig", echo_embed);

    // ── Level 1: Managers ──────────────────────────────────────────
    const svc_embed = makeEmbeddedModule2(b, target, "compositor.elf", compositor, "usb_driver.elf", usb_driver);
    const app_embed = makeEmbeddedModule1(b, target, "terminal.elf", terminal);

    const service_manager = buildProcess(b, target, lib_mod, "service_manager", "service_manager/main.zig", svc_embed);
    const app_manager = buildProcess(b, target, lib_mod, "app_manager", "app_manager/main.zig", app_embed);

    // ── Level 2: Root service ──────────────────────────────────────
    const root_embed = makeEmbeddedModule2(b, target, "service_manager.elf", service_manager, "app_manager.elf", app_manager);

    const app_mod = b.createModule(.{
        .root_source_file = b.path("root_service/main.zig"),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("embedded_children", root_embed);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .Debug,
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
    exe.use_llvm = true;
    exe.use_lld = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(b.path("linker.ld"));
    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/desktopOS.elf");
    b.getInstallStep().dependOn(&install.step);
}
