//! aarch64 direct-kernel Zig entry point.
//!
//! Called from `start.S` (phase3_el1_trampoline → `br directKernelEntry`)
//! immediately after the EL2→EL1 ERET with TTBR0/TTBR1 live and the
//! kernel image mapped at its high VA. SP already points at the low-VA
//! boot stack. x0 carries the DTB physical address QEMU handed us.
//!
//! Responsibility: synthesise a `BootInfo` that matches what the UEFI
//! bootloader hands to `kEntry` in the normal path, then tail-call
//! `kEntry`. After this function the kernel boots indistinguishably
//! from the UEFI flow (memory.init / sched.init / root service spawn).
//!
//! Simplifications vs. the UEFI path, documented so they don't get
//! silently copied into production code:
//!
//!   - The DTB is ignored. We hardcode QEMU `virt -m 1G` memory: RAM at
//!     0x40000000..0x80000000, with the first 18 MiB (boot stub + 16 MiB
//!     kernel image window) marked reserved and the rest free. When we
//!     want variable `-m`, add a tiny DTB parser here and walk /memory.
//!
//!   - No framebuffer, no ACPI XSDP, no KASLR slide, no kernel ELF blob
//!     for symbolication. The kernel already tolerates all of these
//!     being zeroed because the UEFI path sometimes omits them too.
//!
//!   - The root service ELF is pulled from the `embedded_bins` module
//!     (populated by build.zig when `-Ddirect_kernel=true`). The pointer
//!     handed to kMain is a high-VA symbol in kernel .rodata; kMain
//!     reads it via its usual physmap conversion, which works because
//!     memory.init's physmap covers all of RAM.

const std = @import("std");
const builtin = @import("builtin");
const embedded_bins = @import("embedded_bins");
const zag = @import("zag");

const boot_protocol = zag.boot.protocol;
const BootInfo = boot_protocol.BootInfo;
const Blob = boot_protocol.Blob;
const Framebuffer = boot_protocol.Framebuffer;
const MMap = boot_protocol.MMap;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const uefi = std.os.uefi;
const MemoryDescriptor = uefi.tables.MemoryDescriptor;
const MemoryMapKey = uefi.tables.MemoryMapKey;

/// Synthesised memory map. Two descriptors:
///   [0] acpi_reclaim — boot stub + .data.boot page tables + kernel
///       image, 0x40000000..0x41200000. Marked `acpi` rather than
///       `reserved` so `memory.init`'s physmap loop still covers the
///       range (it skips only !free && !acpi entries) while the
///       buddy/bump allocators leave it alone. Critical for direct-
///       kernel on several fronts:
///         - The TTBR1 root and intermediate tables physically live
///           in .data.boot; physmap access lets `mapPage` walk them
///           when kernel demand-page faults on slab-init writes.
///         - The `root_service.elf` blob is `@embedFile`'d into the
///           kernel's .rodata, and kMain dereferences its pointer as
///           a physmap VA, so the kernel image's PA range has to be
///           physmap-covered too.
///   [1] conventional — everything above, 0x41200000..0x80000000.
///       Used by the bump/buddy allocators.
var mmap_descs: [2]MemoryDescriptor = undefined;
var synth_boot_info: BootInfo = undefined;

// Hardcoded QEMU virt -m 1G RAM layout.
const RAM_START: u64 = 0x4000_0000;
const KERNEL_IMAGE_END: u64 = 0x4120_0000;
const RAM_END: u64 = 0x8000_0000;
const PAGE_SIZE: u64 = 4096;

// Kernel image VA base (matches linker-aarch64-direct.ld
// KERNEL_VADDR_BASE) and LMA base (the 2 MiB-aligned boundary
// `_boot_end_lma` resolves to with a 0x180000-byte boot stub +
// 2 MiB alignment). Keep these in sync with the linker script.
const KERNEL_VMA_BASE: u64 = 0xFFFF_0000_0000_0000;
const KERNEL_LMA_BASE: u64 = 0x4020_0000;

fn kernelVaToPa(va: u64) u64 {
    return va - KERNEL_VMA_BASE + KERNEL_LMA_BASE;
}

extern fn kEntry(boot_info: *BootInfo) callconv(.{ .aarch64_aapcs = .{} }) noreturn;

/// Direct-kernel entry point. Called from `start.S` at EL1, MMU on,
/// kernel image mapped at its high VA. x0 = DTB phys (currently
/// unused — we hardcode the memory layout instead of parsing).
pub export fn directKernelEntry(dtb_phys: u64) callconv(.{ .aarch64_aapcs = .{} }) noreturn {
    _ = dtb_phys;

    // [0] acpi_reclaim — boot stub + .data.boot + kernel image.
    mmap_descs[0] = .{
        .type = .acpi_reclaim_memory,
        .physical_start = RAM_START,
        .virtual_start = 0,
        .number_of_pages = (KERNEL_IMAGE_END - RAM_START) / PAGE_SIZE,
        .attribute = std.mem.zeroes(uefi.tables.MemoryDescriptorAttribute),
    };
    // [1] conventional — bump/buddy arena.
    mmap_descs[1] = .{
        .type = .conventional_memory,
        .physical_start = KERNEL_IMAGE_END,
        .virtual_start = 0,
        .number_of_pages = (RAM_END - KERNEL_IMAGE_END) / PAGE_SIZE,
        .attribute = std.mem.zeroes(uefi.tables.MemoryDescriptorAttribute),
    };

    const descriptor_size: u64 = @sizeOf(MemoryDescriptor);
    const num: u64 = mmap_descs.len;

    synth_boot_info = .{
        .elf_blob = .{
            .ptr = @constCast(@as([*]const u8, @ptrCast(""))),
            .len = 0,
        },
        .root_service = .{
            // kMain treats `root_service.ptr` as a *physical* address
            // (`PAddr.fromInt(@intFromPtr(ptr))`) and then converts it
            // to a physmap VA for the read. The embedded_bins blob is
            // linked into kernel .rodata at a high VA, so hand kMain
            // the corresponding PA instead of the VA.
            .ptr = @ptrFromInt(kernelVaToPa(@intFromPtr(embedded_bins.root_service.ptr))),
            .len = embedded_bins.root_service.len,
        },
        .stack_top = VAddr.fromInt(0),
        .xsdp_phys = PAddr.fromInt(0),
        .kaslr_slide = 0,
        .mmap = .{
            .key = @as(MemoryMapKey, @enumFromInt(0)),
            .mmap = &mmap_descs,
            .mmap_size = descriptor_size * num,
            .descriptor_size = descriptor_size,
            .num_descriptors = num,
        },
        .framebuffer = .{
            .base = PAddr.fromInt(0),
            .size = 0,
            .width = 0,
            .height = 0,
            .stride = 0,
            .pixel_format = .none,
        },
    };

    kEntry(&synth_boot_info);
}
