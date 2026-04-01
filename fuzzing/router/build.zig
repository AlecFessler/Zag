const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });

    const router_path = "../../routerOS/router/";
    const shims_path = "shims/";

    // Shim module replaces the real `lib` with fuzzer-controlled stubs
    const lib_mod = b.addModule("lib", .{
        .root_source_file = b.path(shims_path ++ "lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Build options: fuzzer always uses e1000
    const options = b.addOptions();
    options.addOption(bool, "use_x550", false);

    // Router module with lib dependency remapped to shim
    const router_mod = b.addModule("router", .{
        .root_source_file = b.path(router_path ++ "router.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "lib", .module = lib_mod },
        },
    });
    router_mod.addImport("router", router_mod);
    router_mod.addOptions("build_options", options);

    const exe = b.addExecutable(.{
        .name = "router_fuzzer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzzer.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "router", .module = router_mod },
                .{ .name = "lib", .module = lib_mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the router fuzzer");
    run_step.dependOn(&run_cmd.step);
}
