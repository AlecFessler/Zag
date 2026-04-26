const std = @import("std");

const TestEntry = struct {
    name: []const u8,
    path: []const u8,
};

// Authoritative list of spec test ELFs the runner will spawn. Each
// entry corresponds to a `[test NN]` tag in docs/kernel/specv3.md.
// Manifest order is also spawn order; tests that conflict on global
// resources should be ordered serially here. New tests: add a file
// under tests/ then add an entry below.
const test_entries = [_]TestEntry{
    .{ .name = "delete_01", .path = "tests/delete_01.zig" },
    .{ .name = "restrict_01", .path = "tests/restrict_01.zig" },
    .{ .name = "restrict_02", .path = "tests/restrict_02.zig" },
    .{ .name = "restrict_03", .path = "tests/restrict_03.zig" },
    .{ .name = "restrict_04", .path = "tests/restrict_04.zig" },
    .{ .name = "restrict_05", .path = "tests/restrict_05.zig" },
    .{ .name = "restrict_06", .path = "tests/restrict_06.zig" },
    .{ .name = "restrict_07", .path = "tests/restrict_07.zig" },
};

fn buildTestElf(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    name: []const u8,
    src_path: []const u8,
) std.Build.LazyPath {
    const app_mod = b.createModule(.{
        .root_source_file = b.path(src_path),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    app_mod.addImport("lib", lib_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.setLinkerScript(b.path("linker.ld"));

    return exe.getEmittedBin();
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
        .omit_frame_pointer = true,
    });
    // self-reference so libz files can `@import("lib")`
    lib_mod.addImport("lib", lib_mod);

    const embedded_wf = b.addWriteFiles();
    var test_elfs: [test_entries.len]std.Build.LazyPath = undefined;
    for (test_entries, 0..) |t, i| {
        test_elfs[i] = buildTestElf(b, target, lib_mod, t.name, t.path);
        _ = embedded_wf.addCopyFile(test_elfs[i], b.fmt("{s}.elf", .{t.name}));
    }

    // Generate a manifest module surfacing the embedded ELFs as a
    // slice the primary iterates. Manifest order = spawn order.
    var manifest = std.array_list.Managed(u8).init(b.allocator);
    defer manifest.deinit();
    manifest.appendSlice(
        \\pub const Entry = struct {
        \\    name: []const u8,
        \\    bytes: []const u8,
        \\};
        \\
        \\pub const manifest = [_]Entry{
        \\
    ) catch unreachable;
    for (test_entries) |t| {
        manifest.writer().print(
            "    .{{ .name = \"{s}\", .bytes = @embedFile(\"{s}.elf\") }},\n",
            .{ t.name, t.name },
        ) catch unreachable;
    }
    manifest.appendSlice("};\n") catch unreachable;
    const manifest_src = embedded_wf.add("embedded_tests.zig", manifest.items);

    const embedded_tests_mod = b.createModule(.{
        .root_source_file = manifest_src,
        .target = target,
        .optimize = .ReleaseSmall,
    });

    const app_mod = b.createModule(.{
        .root_source_file = b.path("runner/primary.zig"),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("embedded_tests", embedded_tests_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
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

    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/root_service.elf");
    b.getInstallStep().dependOn(&install.step);

    // Install the individual test ELFs alongside for inspection.
    for (test_entries, 0..) |t, i| {
        const path = b.fmt("../bin/{s}.elf", .{t.name});
        const inst = b.addInstallFile(test_elfs[i], path);
        b.getInstallStep().dependOn(&inst.step);
    }
}
