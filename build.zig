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
    bootstrap_obj.addFileArg(b.path("kernel/arch/x86/bootstrap.asm"));
    bootstrap_obj.step.dependOn(&mkdir_obj.step);

    const disabled_features = std.Target.Cpu.Feature.Set.empty;
    const enabled_features = std.Target.Cpu.Feature.Set.empty;

    const target = b.resolveTargetQuery(.{
        .cpu_arch = std.Target.Cpu.Arch.x86_64,
        .os_tag = std.Target.Os.Tag.freestanding,
        .abi = std.Target.Abi.none,
        .cpu_features_sub = disabled_features,
        .cpu_features_add = enabled_features,
    });
    const optimize = b.standardOptimizeOption(.{});

    const memory_mod = b.addModule("memory", .{
        .root_source_file = b.path("kernel/memory/memory.zig"),
        .target = target,
        .optimize = optimize,
    });

    const containers_mod = b.addModule("containers", .{
        .root_source_file = b.path("kernel/containers/containers.zig"),
        .target = target,
        .optimize = optimize,
    });

    // NOTE: Use llvm flag is temporary until 0.15.2 fixes the unrecognized symbols in linker script bug https://github.com/ziglang/zig/issues/25069
    const use_llvm = b.option(bool, "use-llvm", "Force LLVM+LLD backend") orelse false;
    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("kernel/main.zig"),
            .target = target,
            .optimize = optimize,
            .code_model = .kernel,
        }),
    });

    if (use_llvm) {
        kernel.use_llvm = true;
        kernel.use_lld = true;
    }

    kernel.root_module.addImport("memory", memory_mod);
    kernel.root_module.addImport("containers", containers_mod);

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
        "Zag.iso",       "iso/",
    });

    const iso_step = b.step("iso", "Create bootable ISO");
    iso_step.dependOn(&copy_elf.step);
    iso_step.dependOn(&iso.step);

    const vm_cmd = b.addSystemCommand(&[_][]const u8{
        "qemu-system-x86_64",
        "-cdrom",
        "Zag.iso",
    });

    const vm_step = b.step("boot", "Run in QEMU");
    vm_step.dependOn(iso_step);
    vm_step.dependOn(&vm_cmd.step);
}
