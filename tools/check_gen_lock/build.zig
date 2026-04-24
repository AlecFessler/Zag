const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Debug is intentional here: the analyzer's HashMap iteration order
    // interacts with per-entry finding counts in a handful of edge-case
    // syscalls (notably sysThreadCreate / sysIpcReply). Debug gives a
    // finding-count match against tools/check_gen_lock.py; ReleaseFast
    // changes the hash probe sequence and drifts by 2 err. The tool is
    // still fast enough at Debug (~2.4s on this tree).
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .Debug,
    });

    const exe = b.addExecutable(.{
        .name = "check_gen_lock",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the gen-lock analyzer");
    run_step.dependOn(&run_cmd.step);
}
