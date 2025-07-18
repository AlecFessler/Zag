const std = @import("std");

pub fn build(b: *std.Build) void {
    const bootstrap_obj = b.addSystemCommand(&[_][]const u8{
        "nasm", "-f", "elf64",
        "src/arch/x86_64/bootstrap.asm",
        "-o", "zig-out/bootstrap.o",
    });
    bootstrap_obj.addFileArg(b.path("src/arch/x86_64/bootstrap.asm"));

    const target = b.resolveTargetQuery(.{
        .cpu_arch = std.Target.Cpu.Arch.x86,
        .os_tag = std.Target.Os.Tag.freestanding,
        .abi = std.Target.Abi.none,
    });
    const optimize = b.standardOptimizeOption(.{});

    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .kernel,
    });
    kernel.setLinkerScript(b.path("linker.ld"));
    kernel.addObjectFile(b.path("zig-out/bootstrap.o"));

    const build_step = b.step("kernel", "Build the kernel");
    build_step.dependOn(&kernel.step);
    build_step.dependOn(&bootstrap_obj.step);

    const write_file = b.addWriteFiles();
    _ = write_file.addCopyFile(
        kernel.getEmittedBin(),
        "iso/boot/kernel.elf",
    );

    const iso_cmd = b.addSystemCommand(&[_][]const u8{
        "grub-mkrescue", "-o",
        "KosmOS.iso", "iso/",
    });

    const iso_step = b.step("iso", "Create bootable ISO");
    iso_step.dependOn(&write_file.step);
    iso_step.dependOn(&iso_cmd.step);

    const vm_cmd = b.addSystemCommand(&[_][]const u8{
        "qemu-system-x86_64",
        "-cdrom", "iso/KosmOS.iso",
    });

    const vm_step = b.step("boot", "Run in QEMU");
    vm_step.dependOn(iso_step);
    vm_step.dependOn(&vm_cmd.step);
}
