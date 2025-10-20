const std = @import("std");

pub fn build(b: *std.Build) void {
    const s_log_level = b.option(
        []const u8,
        "log_level",
        "log_level",
    ) orelse "info";
    const log_level: std.log.Level = b: {
        break :b if (std.mem.eql(u8, s_log_level, "debug"))
            .debug
        else if (std.mem.eql(u8, s_log_level, "info"))
            .info
        else if (std.mem.eql(u8, s_log_level, "warn"))
            .warn
        else if (std.mem.eql(u8, s_log_level, "error"))
            .err
        else
            @panic("Invalid log level");
    };

    const options = b.addOptions();
    options.addOption(std.log.Level, "log_level", log_level);

    const optimize = b.standardOptimizeOption(.{});
    const out_dir_name = "img";

    const loader = b.addExecutable(.{
        .name = "BOOTX64.EFI",
        .root_module = b.createModule(.{
            .root_source_file = b.path("uefi/main.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .uefi,
            }),
            .optimize = optimize,
        }),
        .linkage = .static,
    });
    b.installArtifact(loader);

    loader.root_module.addOptions("option", options);

    const install_loader = b.addInstallFile(
        loader.getEmittedBin(),
        b.fmt("{s}/efi/boot/{s}", .{
            out_dir_name,
            loader.name,
        }),
    );
    install_loader.step.dependOn(&loader.step);
    b.getInstallStep().dependOn(&install_loader.step);

    const use_llvm = b.option(bool, "use-llvm", "Force LLVM+LLD backend") orelse false;
    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("kernel/main.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .freestanding,
                .ofmt = .elf,
            }),
            .optimize = optimize,
            .code_model = .kernel,
        }),
        .linkage = .static,
    });
    if (use_llvm) {
        kernel.use_llvm = true;
        kernel.use_lld = true;
    }
    kernel.entry = .{ .symbol_name = "kEntry" };
    kernel.root_module.omit_frame_pointer = false;
    kernel.root_module.red_zone = false;
    kernel.setLinkerScript(b.path("kernel/linker.ld"));
    b.installArtifact(kernel);

    const install_kernel = b.addInstallFile(
        kernel.getEmittedBin(),
        b.fmt("{s}/{s}", .{
            out_dir_name,
            kernel.name,
        }),
    );
    install_kernel.step.dependOn(&kernel.step);
    b.getInstallStep().dependOn(&install_kernel.step);

    const nm_out = "zig-out/kernel.map";
    const gen_map = b.addSystemCommand(&[_][]const u8{
        "sh", "-lc",
        \\set -o pipefail
        \\llvm-nm -P -n --defined-only zig-out/bin/kernel.elf \
        \\| awk '$2 ~ /^[Tt]$/ { printf "%s %s\\n", $3, $1 }' \
        \\> zig-out/kernel.map
    });
    gen_map.step.dependOn(&kernel.step);
    const install_map = b.addInstallFile(
        b.path(nm_out),
        b.fmt("{s}/kernel.map", .{out_dir_name}),
    );
    install_map.step.dependOn(&gen_map.step);
    b.getInstallStep().dependOn(&install_map.step);

    // All module's root files (named after the containing dir)
    // should be imported into kernel/main.zig, and then all
    // modules root files can be imported under @import("zag")
    const zag_mod = b.addModule("zag", .{
        .root_source_file = b.path("kernel/main.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = .x86_64,
            .os_tag = .freestanding,
        }),
        .optimize = optimize,
    });
    zag_mod.omit_frame_pointer = false;
    zag_mod.red_zone = false;

    const x86_mod = b.addModule("x86", .{
        .root_source_file = b.path("kernel/arch/x86/x86.zig"),
    });

    const defs_mod = b.addModule("boot_defs", .{
        .root_source_file = b.path("uefi/defs.zig"),
    });

    loader.root_module.addImport("x86", x86_mod);
    zag_mod.addImport("boot_defs", defs_mod);
    kernel.root_module.addImport("zag", zag_mod);
    kernel.root_module.addImport("boot_defs", defs_mod);

    const qemu_args = [_][]const u8{
        "qemu-system-x86_64",
        "-m",
        "512M",
        "-bios",
        "/usr/share/ovmf/x64/OVMF.4m.fd",
        "-drive",
        b.fmt("file=fat:rw:{s}/{s},format=raw", .{
            b.install_path,
            out_dir_name,
        }),
        "-nographic",
        "-serial",
        "mon:stdio",
        "-no-reboot",
        "-enable-kvm",
        "-cpu",
        "host",
        "-s",
    };
    const qemu_cmd = b.addSystemCommand(&qemu_args);
    qemu_cmd.step.dependOn(b.getInstallStep());

    const run_qemu_cmd = b.step("run", "Run QEMU");
    run_qemu_cmd.dependOn(&qemu_cmd.step);
}
