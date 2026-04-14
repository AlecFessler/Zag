const std = @import("std");

// Builds one PoC main source file, and optionally a child ELF. Usage:
//   zig build -Dsrc=poc.zig
//   zig build -Dsrc=poc.zig -Dchild=child.zig
pub fn build(b: *std.Build) void {
    const src = b.option([]const u8, "src", "PoC main source file") orelse
        @panic("pass -Dsrc=<file>.zig");
    const child_src = b.option([]const u8, "child", "Optional child ELF source");

    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
    });

    const buildElf = struct {
        fn run(bb: *std.Build, tgt: std.Build.ResolvedTarget, src_path: []const u8, name: []const u8) *std.Build.Step.Compile {
            const lib_mod = bb.createModule(.{
                .root_source_file = .{ .cwd_relative = "../tests/libz/lib.zig" },
                .target = tgt,
                .optimize = .Debug,
                .pic = true,
            });
            const app_mod = bb.createModule(.{
                .root_source_file = .{ .cwd_relative = src_path },
                .target = tgt,
                .optimize = .Debug,
                .pic = true,
            });
            app_mod.addImport("lib", lib_mod);
            const start_mod = bb.createModule(.{
                .root_source_file = .{ .cwd_relative = "../tests/libz/start.zig" },
                .target = tgt,
                .optimize = .Debug,
                .pic = true,
            });
            start_mod.addImport("lib", lib_mod);
            start_mod.addImport("app", app_mod);
            const exe = bb.addExecutable(.{
                .name = name,
                .root_module = start_mod,
                .linkage = .static,
            });
            exe.pie = true;
            exe.entry = .{ .symbol_name = "_start" };
            exe.setLinkerScript(.{ .cwd_relative = "../tests/linker.ld" });
            return exe;
        }
    }.run;

    const poc = buildElf(b, target, src, "poc");

    if (child_src) |cs| {
        const child = buildElf(b, target, cs, "child");
        const child_install = b.addInstallArtifact(child, .{});
        b.getInstallStep().dependOn(&child_install.step);
        poc.step.dependOn(&child_install.step);
    }

    b.installArtifact(poc);
}
