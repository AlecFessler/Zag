const std = @import("std");

fn buildLeaf(
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

fn buildManager(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    comptime name: []const u8,
    comptime src: []const u8,
    embedded_mod: *std.Build.Module,
) std.Build.LazyPath {
    const child_app_mod = b.createModule(.{
        .root_source_file = b.path(src),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    child_app_mod.addImport("lib", lib_mod);
    child_app_mod.addImport("embedded_children", embedded_mod);
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

    // ── Level 4: Leaf processes ─────────────────────────────────────
    const leaf_a1 = buildLeaf(b, target, lib_mod, "leaf_a1", "leaf_a1/main.zig");
    const leaf_a2 = buildLeaf(b, target, lib_mod, "leaf_a2", "leaf_a2/main.zig");
    const leaf_a3 = buildLeaf(b, target, lib_mod, "leaf_a3", "leaf_a3/main.zig");
    const leaf_a4 = buildLeaf(b, target, lib_mod, "leaf_a4", "leaf_a4/main.zig");
    const leaf_b1 = buildLeaf(b, target, lib_mod, "leaf_b1", "leaf_b1/main.zig");
    const leaf_b2 = buildLeaf(b, target, lib_mod, "leaf_b2", "leaf_b2/main.zig");
    const leaf_b3 = buildLeaf(b, target, lib_mod, "leaf_b3", "leaf_b3/main.zig");
    const leaf_b4 = buildLeaf(b, target, lib_mod, "leaf_b4", "leaf_b4/main.zig");

    // ── Level 3: Sub-managers (each embeds 2 leaves) ────────────────
    const sub_a1_embed = makeEmbeddedModule2(b, target, "leaf_1.elf", leaf_a1, "leaf_2.elf", leaf_a2);
    const sub_a2_embed = makeEmbeddedModule2(b, target, "leaf_1.elf", leaf_a3, "leaf_2.elf", leaf_a4);
    const sub_b1_embed = makeEmbeddedModule2(b, target, "leaf_1.elf", leaf_b1, "leaf_2.elf", leaf_b2);
    const sub_b2_embed = makeEmbeddedModule2(b, target, "leaf_1.elf", leaf_b3, "leaf_2.elf", leaf_b4);

    const sub_a1 = buildManager(b, target, lib_mod, "sub_a1", "sub_manager/main.zig", sub_a1_embed);
    const sub_a2 = buildManager(b, target, lib_mod, "sub_a2", "sub_manager/main.zig", sub_a2_embed);
    const sub_b1 = buildManager(b, target, lib_mod, "sub_b1", "sub_manager/main.zig", sub_b1_embed);
    const sub_b2 = buildManager(b, target, lib_mod, "sub_b2", "sub_manager/main.zig", sub_b2_embed);

    // ── Level 2: Managers (each embeds 2 sub-managers) ──────────────
    const mgr_a_embed = makeEmbeddedModule2(b, target, "sub_1.elf", sub_a1, "sub_2.elf", sub_a2);
    const mgr_b_embed = makeEmbeddedModule2(b, target, "sub_1.elf", sub_b1, "sub_2.elf", sub_b2);

    const manager_a = buildManager(b, target, lib_mod, "manager_a", "manager/main.zig", mgr_a_embed);
    const manager_b = buildManager(b, target, lib_mod, "manager_b", "manager/main.zig", mgr_b_embed);

    // ── Level 1: Root service (embeds 2 managers) ───────────────────
    const root_embed = makeEmbeddedModule2(b, target, "manager_a.elf", manager_a, "manager_b.elf", manager_b);

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
    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/channel_rework.elf");
    b.getInstallStep().dependOn(&install.step);
}
