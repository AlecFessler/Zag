const std = @import("std");

pub fn build(b: *std.Build) void {
    const kvm = b.option(bool, "kvm", "Enable KVM acceleration (default: on)") orelse true;
    const use_llvm = b.option(bool, "use-llvm", "Force LLVM+LLD backend") orelse false;
    const target_arch = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";

    const arch: std.Target.Cpu.Arch = blk: {
        break :blk if (std.mem.eql(u8, target_arch, "x64"))
            .x86_64
        else if (std.mem.eql(u8, target_arch, "arm"))
            .aarch64
        else
            @panic("Unsupported target architecture");
    };

    const optimize = b.standardOptimizeOption(.{});

    const zag_mod = b.addModule("zag", .{
        .root_source_file = b.path("kernel/zag.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = arch,
            .os_tag = .freestanding,
        }),
        .optimize = optimize,
    });
    zag_mod.omit_frame_pointer = false;
    zag_mod.red_zone = false;
    zag_mod.addImport("zag", zag_mod);

    const loader = b.addExecutable(.{
        .name = "BOOTX64.EFI",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bootloader/main.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = arch,
                .os_tag = .uefi,
            }),
            .optimize = optimize,
        }),
        .linkage = .static,
    });
    b.installArtifact(loader);

    const out_dir = "img";
    const install_loader = b.addInstallFile(
        loader.getEmittedBin(),
        b.fmt("{s}/efi/boot/{s}", .{
            out_dir,
            loader.name,
        }),
    );
    loader.root_module.addImport("zag", zag_mod);
    install_loader.step.dependOn(&loader.step);
    b.getInstallStep().dependOn(&install_loader.step);

    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("kernel/main.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = arch,
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
    kernel.root_module.addImport("zag", zag_mod);
    kernel.setLinkerScript(b.path("kernel/linker.ld"));
    b.installArtifact(kernel);

    const install_kernel = b.addInstallFile(
        kernel.getEmittedBin(),
        b.fmt("{s}/{s}", .{
            out_dir,
            kernel.name,
        }),
    );
    install_kernel.step.dependOn(&kernel.step);
    b.getInstallStep().dependOn(&install_kernel.step);

    const qemu_accel_args: []const u8 = if (kvm)
        \\-enable-kvm \
        \\-cpu host,+invtsc
    else
        \\-machine accel=tcg \
        \\-cpu qemu64,+invtsc \
        \\-d in_asm,int,guest_errors \
        \\-D qemu.log
    ;

    const qemu_cmdline = b.fmt(
        \\exec qemu-system-x86_64 \
        \\ -m 512M \
        \\ -bios /usr/share/ovmf/x64/OVMF.4m.fd \
        \\ -drive file=fat:rw:{s}/{s},format=raw \
        \\ -serial mon:stdio \
        \\ -no-reboot \
        \\ {s} \
        \\ -smp cores="$(
        \\   lscpu -p=Core,Socket | grep -v '^#' | sort -u | wc -l
        \\ )",threads=1,sockets=1 \
        \\ -s
    , .{ b.install_path, out_dir, qemu_accel_args });

    const qemu_cmd = b.addSystemCommand(&[_][]const u8{
        "sh", "-lc", qemu_cmdline,
    });
    qemu_cmd.step.dependOn(b.getInstallStep());

    const run_qemu_cmd = b.step("run", "Run QEMU");
    run_qemu_cmd.dependOn(&qemu_cmd.step);
}
