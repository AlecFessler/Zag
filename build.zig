const std = @import("std");

pub fn build(b: *std.Build) void {
    const kvm = b.option(bool, "kvm", "Enable KVM acceleration (default: on)") orelse true;
    const use_llvm = b.option(bool, "use-llvm", "Force LLVM+LLD backend") orelse false;
    const target_arch = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";
    const root_service_path = b.option([]const u8, "root-service", "Path to root service ELF (default: userspace/bin/root_service.elf)");
    const iommu_type = b.option([]const u8, "iommu", "IOMMU type: intel, amd, or none (default: none)") orelse "none";
    const net_type = b.option([]const u8, "net", "Network: tap, user, or none (default: user)") orelse "user";
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

    // ── Root service binary ─────────────────────────────────────────────
    const embedded_wf = b.addWriteFiles();
    var embed_src: std.ArrayListUnmanaged(u8) = .{};

    const root_elf_path = root_service_path orelse "userspace/bin/root_service.elf";
    _ = embedded_wf.addCopyFile(.{ .cwd_relative = root_elf_path }, "root_service.elf");
    embed_src.writer(b.allocator).print(
        "pub const root_service = @embedFile(\"root_service.elf\");\n",
        .{},
    ) catch @panic("OOM");

    // ── SMP trampoline ──────────────────────────────────────────────────
    const nasm_step = b.addSystemCommand(&.{
        "nasm",                    "-f", "bin",
        "kernel/arch/x64/smp.asm", "-o",
    });
    const trampoline_output = nasm_step.addOutputFileArg("trampoline.bin");
    _ = embedded_wf.addCopyFile(trampoline_output, "trampoline.bin");
    embed_src.writer(b.allocator).print(
        "pub const trampoline = @embedFile(\"trampoline.bin\");\n",
        .{},
    ) catch @panic("OOM");

    const embedded_bins_mod = b.createModule(.{
        .root_source_file = embedded_wf.add("embedded_bins.zig", embed_src.items),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = arch,
            .os_tag = .freestanding,
        }),
        .optimize = optimize,
    });
    zag_mod.addImport("embedded_bins", embedded_bins_mod);

    // ── Bootloader ──────────────────────────────────────────────────────
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

    // ── Kernel ──────────────────────────────────────────────────────────
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

    // ── QEMU ────────────────────────────────────────────────────────────
    const qemu_accel_args: []const u8 = if (kvm)
        \\-enable-kvm \
        \\-cpu host,+invtsc
    else
        \\-machine accel=tcg \
        \\-cpu qemu64,+invtsc \
        \\-d int,cpu_reset \
        \\-no-shutdown \
        \\-D qemu.log
    ;
    const has_iommu = !std.mem.eql(u8, iommu_type, "none");
    const qemu_machine_args: []const u8 = if (has_iommu)
        \\-machine q35
    else
        \\
    ;
    const qemu_iommu_args: []const u8 = if (std.mem.eql(u8, iommu_type, "intel"))
        \\-device intel-iommu,intremap=off
    else if (std.mem.eql(u8, iommu_type, "amd"))
        \\-device amd-iommu
    else
        \\
    ;
    const qemu_net_args: []const u8 = if (std.mem.eql(u8, net_type, "tap"))
        \\-netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
        \\-device e1000,netdev=net0,mac=52:54:00:12:34:56 \
        \\-netdev tap,id=net1,ifname=tap1,script=no,downscript=no \
        \\-device e1000,netdev=net1,mac=52:54:00:12:34:57
    else if (std.mem.eql(u8, net_type, "user"))
        \\
    else
        \\-net none
    ;
    const qemu_cmdline = b.fmt(
        \\exec qemu-system-x86_64 \
        \\ -m 512M \
        \\ -bios /usr/share/ovmf/x64/OVMF.4m.fd \
        \\ -drive file=fat:rw:{s}/{s},format=raw \
        \\ -serial mon:stdio \
        \\ -display none \
        \\ -no-reboot \
        \\ {s} \
        \\ {s} \
        \\ {s} \
        \\ {s} \
        \\ -smp cores=4
    , .{ b.install_path, out_dir, qemu_accel_args, qemu_machine_args, qemu_iommu_args, qemu_net_args });
    const qemu_cmd = b.addSystemCommand(&[_][]const u8{
        "sh", "-lc", qemu_cmdline,
    });
    qemu_cmd.step.dependOn(b.getInstallStep());
    const run_qemu_cmd = b.step("run", "Run QEMU");
    run_qemu_cmd.dependOn(&qemu_cmd.step);
}
