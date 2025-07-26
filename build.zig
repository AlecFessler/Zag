const std = @import("std");

pub fn build(b: *std.Build) void {
    const obj_dir_path = b.pathJoin(&.{ b.install_prefix, "obj" });
    const mkdir_obj = b.addSystemCommand(&[_][]const u8{
        "mkdir", "-p", obj_dir_path,
    });

    const obj_file_path = b.pathJoin(&.{ obj_dir_path, "bootstrap.o" });
    const bootstrap_obj = b.addSystemCommand(&[_][]const u8{
        "nasm",        "-f", "elf64", "-o",
        obj_file_path, "",
    });
    bootstrap_obj.addFileArg(b.path("kernel/arch/x86_64/bootstrap.asm"));
    bootstrap_obj.step.dependOn(&mkdir_obj.step);

    var disabled_features = std.Target.Cpu.Feature.Set.empty;
    var enabled_features = std.Target.Cpu.Feature.Set.empty;

    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.mmx));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.sse));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.sse2));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.avx));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.avx2));
    enabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.soft_float));

    const target = b.resolveTargetQuery(.{
        .cpu_arch = std.Target.Cpu.Arch.x86_64,
        .os_tag = std.Target.Os.Tag.freestanding,
        .abi = std.Target.Abi.none,
        .cpu_features_sub = disabled_features,
        .cpu_features_add = enabled_features,
    });
    const optimize = b.standardOptimizeOption(.{});

    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_source_file = b.path("kernel/main.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .kernel,
    });
    kernel.setLinkerScript(b.path("linker.ld"));
    kernel.addObjectFile(b.path("zig-out/obj/bootstrap.o"));
    kernel.step.dependOn(&bootstrap_obj.step);

    b.installArtifact(kernel);

    const copy_elf = b.addSystemCommand(&[_][]const u8{
        "cp", "zig-out/bin/kernel.elf", "iso/boot/kernel.elf",
    });
    copy_elf.step.dependOn(b.getInstallStep());

    const iso = b.addSystemCommand(&[_][]const u8{
        "grub-mkrescue", "-o",
        "Zog.iso",       "iso/",
    });

    const iso_step = b.step("iso", "Create bootable ISO");
    iso_step.dependOn(&copy_elf.step);
    iso_step.dependOn(&iso.step);

    const vm_cmd = b.addSystemCommand(&[_][]const u8{
        "qemu-system-x86_64",
        "-cdrom",
        "Zog.iso",
    });

    const vm_step = b.step("boot", "Run in QEMU");
    vm_step.dependOn(iso_step);
    vm_step.dependOn(&vm_cmd.step);
}
