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
const zag = @import("zag");

const vm_hw = zag.arch.aarch64.vm;

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

/// Synthesised memory map. Four descriptors carve out three regions:
///   [0] acpi_reclaim — 0x40000000..0x41200000 — boot stub + .data.boot
///       page tables + kernel image. Marked `acpi` (not `reserved`) so
///       `memory.init`'s physmap loop covers the range (it skips only
///       !free && !acpi entries) while the buddy/bump allocators leave
///       it alone. The TTBR1 root and intermediate tables live here.
///   [1] conventional — 0x41200000..0x44000000 — bump/buddy arena (low).
///   [2] acpi_reclaim — 0x44000000..0x45000000 — root_service.elf blob
///       loader window (16 MiB). The aarch64 test runner injects the
///       per-test ELF here via QEMU `-device loader,addr=0x44000000`.
///       Layout: u64 little-endian length, then ELF bytes. Marked acpi
///       so kMain can read it via physmap VA but the allocators don't
///       trample it.
///   [3] conventional — 0x45000000..0x80000000 — bump/buddy arena (high).
var mmap_descs: [4]MemoryDescriptor = undefined;
var synth_boot_info: BootInfo = undefined;

// Hardcoded QEMU virt -m 1G RAM layout.
const RAM_START: u64 = 0x4000_0000;
const KERNEL_IMAGE_END: u64 = 0x4120_0000;
const BLOB_REGION_START: u64 = 0x4400_0000;
const BLOB_REGION_END: u64 = 0x4500_0000;
const RAM_END: u64 = 0x8000_0000;
const PAGE_SIZE: u64 = 4096;

// Layout of the blob loaded at BLOB_REGION_START:
//   offset 0x00: u64 little-endian ELF length
//   offset 0x08: <length> bytes of root_service.elf
const BLOB_ELF_OFFSET: u64 = 8;

/// Early marker print via PL011. Works both MMU-off (PA 0x0900_0000
/// mapped identity) and MMU-on (the low-VA 0x0900_0000 identity map
/// from start.S still covers it until the kernel's own physmap takes
/// over). Used by the EL2 smoke tests so we can localise failures
/// before any kernel logging subsystem exists.
fn smokePutc(c: u8) void {
    const pl011: *volatile u8 = @ptrFromInt(0x0900_0000);
    pl011.* = c;
}

fn smokePuts(s: []const u8) void {
    for (s) |c| smokePutc(c);
}

fn smokePutHex(v: u64) void {
    var i: u6 = 60;
    while (true) : (i -= 4) {
        const nib: u8 = @intCast((v >> i) & 0xF);
        smokePutc(if (nib < 10) '0' + nib else 'A' + nib - 10);
        if (i == 0) break;
    }
}

/// Phase A smoke test: verify the EL2 hyp stub round-trip works by
/// issuing a HVC_NOOP with a known argument and checking that the
/// dispatcher toggled the low bit. Prints `[hypA:XXXX->YYYY]` on
/// the PL011. A failure here usually means the hyp vectors are not
/// installed, SP_EL2 is bad, or HCR_EL2 is routing wrong.
fn runHypSmokeA() void {
    smokePuts("[hypA:");
    const arg: u64 = 0x1234;
    smokePutHex(arg);
    smokePuts("->");
    const ret = vm_hw.hypCall(.noop, arg);
    smokePutHex(ret);
    smokePuts("]\r\n");
}

extern fn kEntry(boot_info: *BootInfo) callconv(.{ .aarch64_aapcs = .{} }) noreturn;

/// Direct-kernel entry point. Called from `start.S` at EL1, MMU on,
/// kernel image mapped at its high VA. x0 = DTB phys (currently
/// unused — we hardcode the memory layout instead of parsing).
pub export fn directKernelEntry(dtb_phys: u64) callconv(.{ .aarch64_aapcs = .{} }) noreturn {
    _ = dtb_phys;

    // start.S installed VBAR_EL2 with __hyp_vectors before the EL2→EL1
    // ERET that landed us here. Record that fact so vmSupported() can
    // distinguish "EL2 advertised in ID reg" from "EL2 actually reachable
    // via HVC from this kernel".
    zag.arch.aarch64.vm.hyp_stub_installed = true;

    // Read the QEMU-loader-injected blob length. The low-VA identity map
    // installed by start.S (TTBR0 L1[1] = 1 GiB block at 0x40000000) makes
    // PA 0x44000000 directly addressable as VA 0x44000000 from EL1, so a
    // raw u64 load works without any physmap setup.
    const blob_len_ptr: *const volatile u64 = @ptrFromInt(BLOB_REGION_START);
    const rs_len = blob_len_ptr.*;
    const rs_ptr_pa = BLOB_REGION_START + BLOB_ELF_OFFSET;

    // [0] acpi_reclaim — boot stub + .data.boot + kernel image.
    mmap_descs[0] = .{
        .type = .acpi_reclaim_memory,
        .physical_start = RAM_START,
        .virtual_start = 0,
        .number_of_pages = (KERNEL_IMAGE_END - RAM_START) / PAGE_SIZE,
        .attribute = std.mem.zeroes(uefi.tables.MemoryDescriptorAttribute),
    };
    // [1] conventional — bump/buddy arena (low half).
    mmap_descs[1] = .{
        .type = .conventional_memory,
        .physical_start = KERNEL_IMAGE_END,
        .virtual_start = 0,
        .number_of_pages = (BLOB_REGION_START - KERNEL_IMAGE_END) / PAGE_SIZE,
        .attribute = std.mem.zeroes(uefi.tables.MemoryDescriptorAttribute),
    };
    // [2] acpi_reclaim — root_service blob loader window.
    mmap_descs[2] = .{
        .type = .acpi_reclaim_memory,
        .physical_start = BLOB_REGION_START,
        .virtual_start = 0,
        .number_of_pages = (BLOB_REGION_END - BLOB_REGION_START) / PAGE_SIZE,
        .attribute = std.mem.zeroes(uefi.tables.MemoryDescriptorAttribute),
    };
    // [3] conventional — bump/buddy arena (high half).
    mmap_descs[3] = .{
        .type = .conventional_memory,
        .physical_start = BLOB_REGION_END,
        .virtual_start = 0,
        .number_of_pages = (RAM_END - BLOB_REGION_END) / PAGE_SIZE,
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
            // kMain treats root_service.ptr as a *physical* address
            // (`PAddr.fromInt(@intFromPtr(ptr))`) and then converts it
            // to a physmap VA for the read. The blob already lives at a
            // physical address (loaded by QEMU `-device loader,addr=...`),
            // so hand kMain that PA directly.
            .ptr = @ptrFromInt(rs_ptr_pa),
            .len = rs_len,
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

    runHypSmokeA();

    kEntry(&synth_boot_info);
}
