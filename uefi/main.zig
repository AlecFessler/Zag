const alloc_mod = @import("boot_allocator.zig");
const defs_mod = @import("defs.zig");
const file_mod = @import("file.zig");
const mmap_mod = @import("mmap.zig");
const exec = @import("exec");
const std = @import("std");
const x86 = @import("x86");

const cpu = x86.Cpu;
const paging = x86.Paging;
const uefi = std.os.uefi;

pub const KEntryType = fn (defs_mod.BootInfo) callconv(.{ .x86_64_sysv = .{} }) noreturn;

pub fn main() uefi.Status {
    const boot_services: *uefi.tables.BootServices = uefi.system_table.boot_services.?;
    uefi.system_table.con_out.?.clearScreen() catch {};

    var page_allocator = alloc_mod.PageAllocator.init(
        boot_services,
        .acpi_reclaim_memory,
    );
    const page_alloc_iface = page_allocator.allocator();

    const new_pml4_page = page_alloc_iface.alignedAlloc(u8, paging.PAGE_ALIGN, paging.PAGE4K) catch return .aborted;
    const pml4_paddr = paging.read_cr3();
    const pml4_ptr = pml4_paddr.getPtr([*]u8);
    const pml4_slice = pml4_ptr[0..paging.PAGE4K];
    @memcpy(new_pml4_page, pml4_slice);
    const new_pml4_phys = paging.PAddr.fromInt(@intFromPtr(new_pml4_page.ptr));
    paging.write_cr3(new_pml4_phys);

    const loaded_image = boot_services.handleProtocol(
        uefi.protocol.LoadedImage,
        uefi.handle,
    ) catch {
        return .aborted;
    } orelse {
        return .aborted;
    };

    const fs: *uefi.protocol.SimpleFileSystem = boot_services.handleProtocol(
        uefi.protocol.SimpleFileSystem,
        loaded_image.device_handle.?,
    ) catch {
        return .aborted;
    } orelse {
        return .aborted;
    };

    const root_dir: *uefi.protocol.File = fs.openVolume() catch return .aborted;

    const kernel_file = file_mod.openFile(root_dir, "kernel.elf") catch return .aborted;
    const file_bytes = file_mod.readFile(kernel_file, boot_services) catch return .aborted;
    const parsed_elf = exec.elf.parseElf(file_bytes) catch return .aborted;

    var current_virt: u64 = undefined;
    var file_bytes_offset: u64 = undefined;

    const text_start = parsed_elf.text.vaddr;
    const text_end = text_start + parsed_elf.text.len;
    current_virt = text_start;
    file_bytes_offset = parsed_elf.text.offset;
    while (current_virt < text_end) {
        const page = page_alloc_iface.alignedAlloc(u8, paging.PAGE_ALIGN, paging.PAGE4K) catch return .aborted;
        const text_bytes = file_bytes[file_bytes_offset .. file_bytes_offset + paging.PAGE4K];
        @memcpy(page, text_bytes);

        const page_phys = paging.PAddr.fromInt(@intFromPtr(page.ptr));
        const page_virt = paging.VAddr.fromInt(current_virt);

        paging.mapPage(
            @ptrFromInt(new_pml4_phys.addr),
            page_phys,
            page_virt,
            .ro,
            .x,
            .cache,
            .su,
            .Page4K,
            .identity,
            page_alloc_iface,
        );

        current_virt += paging.PAGE4K;
        file_bytes_offset += paging.PAGE4K;
    }

    const rodata_start = parsed_elf.rodata.vaddr;
    const rodata_end = rodata_start + parsed_elf.rodata.len;
    current_virt = rodata_start;
    file_bytes_offset = parsed_elf.rodata.offset;
    while (current_virt < rodata_end) {
        const page = page_alloc_iface.alignedAlloc(u8, paging.PAGE_ALIGN, paging.PAGE4K) catch return .aborted;
        const rodata_bytes = file_bytes[file_bytes_offset .. file_bytes_offset + paging.PAGE4K];
        @memcpy(page, rodata_bytes);

        const page_phys = paging.PAddr.fromInt(@intFromPtr(page.ptr));
        const page_virt = paging.VAddr.fromInt(current_virt);

        paging.mapPage(
            @ptrFromInt(new_pml4_phys.addr),
            page_phys,
            page_virt,
            .ro,
            .nx,
            .cache,
            .su,
            .Page4K,
            .identity,
            page_alloc_iface,
        );

        current_virt += paging.PAGE4K;
        file_bytes_offset += paging.PAGE4K;
    }

    const data_start = parsed_elf.data.vaddr;
    const data_end = data_start + parsed_elf.data.len;
    current_virt = data_start;
    file_bytes_offset = parsed_elf.data.offset;
    while (current_virt < data_end) {
        const page = page_alloc_iface.alignedAlloc(u8, paging.PAGE_ALIGN, paging.PAGE4K) catch return .aborted;
        const data_bytes = file_bytes[file_bytes_offset .. file_bytes_offset + paging.PAGE4K];
        @memcpy(page, data_bytes);

        const page_phys = paging.PAddr.fromInt(@intFromPtr(page.ptr));
        const page_virt = paging.VAddr.fromInt(current_virt);

        paging.mapPage(
            @ptrFromInt(new_pml4_phys.addr),
            page_phys,
            page_virt,
            .rw,
            .nx,
            .cache,
            .su,
            .Page4K,
            .identity,
            page_alloc_iface,
        );

        current_virt += paging.PAGE4K;
        file_bytes_offset += paging.PAGE4K;
    }

    const bss_start = parsed_elf.bss.vaddr;
    const bss_end = bss_start + parsed_elf.bss.len;
    current_virt = bss_start;
    while (current_virt < bss_end) {
        const page = page_alloc_iface.alignedAlloc(u8, paging.PAGE_ALIGN, paging.PAGE4K) catch return .aborted;
        @memset(page, 0);
        const page_phys = paging.PAddr.fromInt(@intFromPtr(page.ptr));
        const page_virt = paging.VAddr.fromInt(current_virt);

        paging.mapPage(
            @ptrFromInt(new_pml4_phys.addr),
            page_phys,
            page_virt,
            .rw,
            .nx,
            .cache,
            .su,
            .Page4K,
            .identity,
            page_alloc_iface,
        );

        current_virt += paging.PAGE4K;
    }

    const stack_start = parsed_elf.stack.vaddr;
    const stack_end = stack_start + parsed_elf.stack.len;
    current_virt = stack_start;
    while (current_virt < stack_end) {
        const page = page_alloc_iface.alignedAlloc(u8, paging.PAGE_ALIGN, paging.PAGE4K) catch return .aborted;
        @memset(page, 0);
        const page_phys = paging.PAddr.fromInt(@intFromPtr(page.ptr));
        const page_virt = paging.VAddr.fromInt(current_virt);

        paging.mapPage(
            @ptrFromInt(new_pml4_phys.addr),
            page_phys,
            page_virt,
            .rw,
            .nx,
            .cache,
            .su,
            .Page4K,
            .identity,
            page_alloc_iface,
        );

        current_virt += paging.PAGE4K;
    }

    const xsdp_paddr = defs_mod.findXSDP() catch return .aborted;

    var mmap = mmap_mod.getMmap(boot_services) orelse return .aborted;
    boot_services.exitBootServices(
        uefi.handle,
        mmap.key,
    ) catch {
        mmap = mmap_mod.getMmap(boot_services) orelse return .aborted;
        boot_services.exitBootServices(
            uefi.handle,
            mmap.key,
        ) catch return .aborted;
    };

    const boot_info = defs_mod.BootInfo{
        .xsdp_paddr = xsdp_paddr,
        .mmap = mmap,
        .elf = .{
            .ptr = @ptrCast(file_bytes.ptr),
            .len = file_bytes.len,
        },
    };

    const kEntry: *KEntryType = @ptrFromInt(parsed_elf.entry);
    kEntry(boot_info);
    unreachable;
}
