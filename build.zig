const std = @import("std");

const Profile = struct {
    root_service: []const u8,
    net: []const u8,
    kvm: bool,
    use_llvm: bool,
    iommu: []const u8,
    display: []const u8 = "none",
};

const profiles = struct {
    const router = Profile{
        .root_service = "routerOS/bin/routerOS.elf",
        .net = "tap",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    const test_ = Profile{
        .root_service = "kernel/tests/bin/root_service.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    const bench = Profile{
        .root_service = "kernel/tests/bin/bench.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    const desktop = Profile{
        .root_service = "desktopOS/bin/desktopOS.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
        .display = "gtk",
    };
    const hyprvos = Profile{
        .root_service = "hyprvOS/bin/hyprvOS.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };

};

fn getProfile(name: []const u8) ?Profile {
    if (std.mem.eql(u8, name, "router")) return profiles.router;
    if (std.mem.eql(u8, name, "test")) return profiles.test_;
    if (std.mem.eql(u8, name, "bench")) return profiles.bench;
    if (std.mem.eql(u8, name, "desktop")) return profiles.desktop;
    if (std.mem.eql(u8, name, "hyprvos")) return profiles.hyprvos;

    return null;
}

pub fn build(b: *std.Build) void {
    const profile_name = b.option([]const u8, "profile", "Build profile: router, test, bench (sets defaults for other flags)");
    const profile = if (profile_name) |name| getProfile(name) else null;

    const kvm = b.option(bool, "kvm", "Enable KVM acceleration (default: on)") orelse
        if (profile) |p| p.kvm else true;
    const use_llvm = b.option(bool, "use-llvm", "Force LLVM+LLD backend") orelse
        if (profile) |p| p.use_llvm else false;
    const target_arch = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";
    const root_service_path = b.option([]const u8, "root-service", "Path to root service ELF") orelse
        if (profile) |p| p.root_service else "kernel/tests/bin/root_service.elf";
    const iommu_type = b.option([]const u8, "iommu", "IOMMU type: intel or amd (default: intel)") orelse
        if (profile) |p| p.iommu else "intel";
    const display_type = b.option([]const u8, "display", "QEMU display: none, gtk, sdl (default: none)") orelse
        if (profile) |p| p.display else "none";
    const net_type = b.option([]const u8, "net", "Network: tap, user, or none (default: user)") orelse
        if (profile) |p| p.net else "user";

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

    // ── SMP trampoline (only remaining embedded binary) ─────────────────
    const embedded_wf = b.addWriteFiles();
    const nasm_step = b.addSystemCommand(&.{
        "nasm",                    "-f", "bin",
        "kernel/arch/x64/smp.asm", "-o",
    });
    const trampoline_output = nasm_step.addOutputFileArg("trampoline.bin");
    _ = embedded_wf.addCopyFile(trampoline_output, "trampoline.bin");
    const embedded_bins_mod = b.createModule(.{
        .root_source_file = embedded_wf.add("embedded_bins.zig",
            \\pub const trampoline = @embedFile("trampoline.bin");
            \\
        ),
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

    // ── Root service (copied into FAT image, loaded by bootloader) ─────
    const install_root_service = b.addInstallFile(
        .{ .cwd_relative = root_service_path },
        b.fmt("{s}/root_service.elf", .{out_dir}),
    );
    b.getInstallStep().dependOn(&install_root_service.step);

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
    const qemu_machine_args: []const u8 = 
        \\-machine q35
    ;
    const qemu_iommu_args: []const u8 = if (std.mem.eql(u8, iommu_type, "intel"))
        "-device intel-iommu,intremap=off"
    else
        "-device amd-iommu"
    ;
    const qemu_usb_args: []const u8 = if (profile_name != null and std.mem.eql(u8, profile_name.?, "desktop"))
        \\-device qemu-xhci,id=xhci \
        \\-device usb-kbd,bus=xhci.0 \
        \\-device usb-mouse,bus=xhci.0
    else
        ""
    ;
    const qemu_nvme_args: []const u8 = if (profile_name != null and
        (std.mem.eql(u8, profile_name.?, "desktop") or std.mem.eql(u8, profile_name.?, "hyprvos")))
        \\-drive file=nvme.img,format=raw,if=none,id=nvme0 \
        \\-device nvme,drive=nvme0,serial=zagdisk0
    else
        ""
    ;
    const qemu_net_args: []const u8 = if (std.mem.eql(u8, net_type, "tap"))
        \\-netdev tap,id=net0,ifname=tap0,script=no,downscript=no,vhost=off \
        \\-device e1000e,netdev=net0,mac=52:54:00:12:34:56 \
        \\-netdev tap,id=net1,ifname=tap1,script=no,downscript=no,vhost=off \
        \\-device e1000e,netdev=net1,mac=52:54:00:12:34:57
    else if (std.mem.eql(u8, net_type, "passthrough"))
        \\-net none \
        \\-device pcie-root-port,id=rp1,slot=1 \
        \\-device pcie-pci-bridge,id=br1,bus=rp1 \
        \\-device vfio-pci,host=05:00.0,bus=br1,addr=1.0 \
        \\-device vfio-pci,host=05:00.1,bus=br1,addr=2.0
    else if (std.mem.eql(u8, net_type, "user"))
        \\-netdev user,id=net0 \
        \\-device e1000e,netdev=net0,mac=52:54:00:12:34:56 \
        \\-netdev user,id=net1 \
        \\-device e1000e,netdev=net1,mac=52:54:00:12:34:57
    else
        \\-net none
    ;
    const qemu_cmdline = b.fmt(
        \\exec qemu-system-x86_64 \
        \\ -m 1G \
        \\ -bios /usr/share/ovmf/x64/OVMF.4m.fd \
        \\ -drive file=fat:rw:{s}/{s},format=raw \
        \\ -serial mon:stdio \
        \\ -display {s} \
        \\ -no-reboot \
        \\ {s} \
        \\ {s} \
        \\ {s} \
        \\ {s} \
        \\ {s} \
        \\ {s} \
        \\ -smp cores=4
    , .{ b.install_path, out_dir, display_type, qemu_accel_args, qemu_machine_args, qemu_iommu_args, qemu_net_args, qemu_usb_args, qemu_nvme_args });
    // Create NVMe disk image if it doesn't exist
    const create_nvme_img = b.addSystemCommand(&[_][]const u8{
        "sh", "-c", "test -f nvme.img || dd if=/dev/zero of=nvme.img bs=1M count=64 2>/dev/null",
    });

    const qemu_cmd = b.addSystemCommand(&[_][]const u8{
        "sh", "-lc", qemu_cmdline,
    });
    qemu_cmd.step.dependOn(b.getInstallStep());
    qemu_cmd.step.dependOn(&create_nvme_img.step);
    const run_qemu_cmd = b.step("run", "Run QEMU");
    run_qemu_cmd.dependOn(&qemu_cmd.step);
}
