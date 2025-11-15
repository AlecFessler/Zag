const fs_mod = @import("fs.zig");
const page_allocator = @import("page_allocator.zig");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const elf = zag.utils.elf;
const paging = zag.memory.paging;
const uefi = std.os.uefi;

const BootInfo = zag.boot.protocol.BootInfo;
const ElfSection = elf.ElfSection;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageAllocator = page_allocator.PageAllocator;
const ParsedElf = zag.utils.elf.ParsedElf;
const VAddr = zag.memory.address.VAddr;

pub fn main() uefi.Status {
    const boot_services: *uefi.tables.BootServices = uefi.system_table.boot_services orelse return .aborted;
    uefi.system_table.con_out.?.clearScreen() catch return .aborted;

    // by using acpi reclaim memory, we ensure that the kernel will physmap these addresses,
    // but it will not give them to the buddy allocator as available memory
    var page_alloc = PageAllocator.init(boot_services, .acpi_reclaim_memory);
    const page_alloc_iface = page_alloc.allocator();

    const addr_space_root_phys = arch.getAddrSpaceRoot();
    const addr_space_root_bytes_ptr = addr_space_root_phys.getPtr([*]u8);
    const addr_space_root_bytes_slice = addr_space_root_bytes_ptr[0..paging.PAGE4K];
    const new_addr_space_root = page_alloc_iface.alignedAlloc(
        u8,
        paging.PAGE_ALIGN,
        paging.PAGE4K,
    ) catch return .aborted;
    @memcpy(new_addr_space_root, addr_space_root_bytes_slice);
    const new_addr_space_root_phys = PAddr.fromInt(@intFromPtr(new_addr_space_root.ptr));
    arch.swapAddrSpace(new_addr_space_root_phys);

    const loaded_image = boot_services.handleProtocol(
        uefi.protocol.LoadedImage,
        uefi.handle,
    ) catch {
        return .aborted;
    } orelse return .aborted;

    const fs: *uefi.protocol.SimpleFileSystem = boot_services.handleProtocol(
        uefi.protocol.SimpleFileSystem,
        loaded_image.device_handle.?,
    ) catch {
        return .aborted;
    } orelse return .aborted;

    const root_dir: *uefi.protocol.File = fs.openVolume() catch return .aborted;
    const kernel_file = fs_mod.openFile(root_dir, "kernel.elf") catch return .aborted;
    const file_bytes = fs_mod.readFile(kernel_file, boot_services) catch return .aborted;

    const parsed_elf_mem = boot_services.allocatePool(.loader_data, @sizeOf(ParsedElf)) catch return .aborted;
    const parsed_elf: *ParsedElf = @ptrCast(parsed_elf_mem.ptr);
    elf.parseElf(parsed_elf, file_bytes) catch return .aborted;

    const num_sections = @intFromEnum(ElfSection.num_sections);
    for (0..num_sections) |i| {
        const section_idx: ElfSection = @enumFromInt(i);
        const perms: MemoryPerms = switch (section_idx) {
            .text => .{
                .write_perm = .no_write,
                .execute_perm = .execute,
                .cache_perm = .write_back,
                .global_perm = .global,
                .privilege_perm = .kernel,
            },
            .rodata => .{
                .write_perm = .no_write,
                .execute_perm = .no_execute,
                .cache_perm = .write_back,
                .global_perm = .global,
                .privilege_perm = .kernel,
            },
            .data, .bss => .{
                .write_perm = .write,
                .execute_perm = .no_execute,
                .cache_perm = .write_back,
                .global_perm = .global,
                .privilege_perm = .kernel,
            },
        };

        const section = parsed_elf.sections[i];
        const start_vaddr = section.vaddr;
        const end_vaddr = section.vaddr + section.size;
        var current_vaddr = start_vaddr;
        var file_offset = section.offset;
        while (current_vaddr < end_vaddr) {
            const page = page_alloc_iface.alignedAlloc(
                u8,
                paging.PAGE_ALIGN,
                paging.PAGE4K,
            ) catch return .aborted;
            const bytes = file_bytes[file_offset .. file_offset + paging.PAGE4K];
            @memcpy(page, bytes);

            const page_phys = PAddr.fromInt(@intFromPtr(page.ptr));
            const page_virt = VAddr.fromInt(current_vaddr);

            arch.mapPage(
                new_addr_space_root_phys,
                page_phys,
                page_virt,
                .page4k,
                perms,
                page_alloc_iface,
            ) catch return .aborted;

            current_vaddr += paging.PAGE4K;
            file_offset += paging.PAGE4K;
        }
    }

    arch.halt();
}
