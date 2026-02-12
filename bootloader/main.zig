const fs_mod = @import("fs.zig");
const page_allocator = @import("page_allocator.zig");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const address = zag.memory.address;
const boot_protocol = zag.boot.protocol;
const elf = zag.utils.elf;
const paging = zag.memory.paging;
const uefi = std.os.uefi;

const BootInfo = boot_protocol.BootInfo;
const ElfSection = elf.ElfSection;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageAllocator = page_allocator.PageAllocator;
const ParsedElf = zag.utils.elf.ParsedElf;
const VAddr = zag.memory.address.VAddr;

const KEntryType = fn (*BootInfo) callconv(.{ .x86_64_sysv = .{} }) noreturn;

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
        paging.pageAlign(.page4k),
        paging.PAGE4K,
    ) catch return .aborted;
    @memcpy(new_addr_space_root, addr_space_root_bytes_slice);
    const new_addr_space_root_phys = PAddr.fromInt(@intFromPtr(new_addr_space_root.ptr));
    arch.swapAddrSpace(new_addr_space_root_phys);

    const identity_mapping = 0;
    const new_addr_space_root_virt = VAddr.fromPAddr(new_addr_space_root_phys, identity_mapping);

    // physmap the address space root for the kernel, won't be used in the bootloader
    const new_addr_space_root_virt_physmapped = VAddr.fromPAddr(new_addr_space_root_phys, null);
    const addr_space_root_perms: MemoryPerms = .{
        .write_perm = .write,
        .execute_perm = .no_execute,
        .cache_perm = .write_back,
        .global_perm = .global,
        .privilege_perm = .kernel,
    };
    arch.mapPage(
        new_addr_space_root_virt,
        new_addr_space_root_phys,
        new_addr_space_root_virt_physmapped,
        .page4k,
        addr_space_root_perms,
        page_alloc_iface,
    ) catch return .aborted;

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
            else => unreachable,
        };

        const section = parsed_elf.sections[i];
        const start_vaddr = section.vaddr;
        const end_vaddr = section.vaddr + section.size;
        var current_vaddr = start_vaddr;
        var file_offset = section.offset;
        while (current_vaddr < end_vaddr) {
            const page = page_alloc_iface.alignedAlloc(
                u8,
                paging.pageAlign(.page4k),
                paging.PAGE4K,
            ) catch return .aborted;
            if (section_idx == .bss) {
                @memset(page, 0);
            } else {
                const bytes = file_bytes[file_offset .. file_offset + paging.PAGE4K];
                @memcpy(page, bytes);
                file_offset += paging.PAGE4K;
            }

            const page_phys = PAddr.fromInt(@intFromPtr(page.ptr));
            const page_virt = VAddr.fromInt(current_vaddr);

            arch.mapPage(
                new_addr_space_root_virt,
                page_phys,
                page_virt,
                .page4k,
                perms,
                page_alloc_iface,
            ) catch return .aborted;

            current_vaddr += paging.PAGE4K;
        }
    }

    const xsdp_addr = boot_protocol.findXSDP() catch return .aborted;
    const xsdp_phys = PAddr.fromInt(xsdp_addr);

    const stack_pages = page_alloc_iface.alignedAlloc(
        u8,
        paging.pageAlign(.page4k),
        boot_protocol.STACK_SIZE,
    ) catch return .aborted;

    const num_pages = boot_protocol.STACK_SIZE / paging.PAGE4K;
    var current_page_phys = PAddr.fromInt(@intFromPtr(stack_pages.ptr));
    for (0..num_pages) |_| {
        const current_page_virt = VAddr.fromPAddr(current_page_phys, null);
        const perms: MemoryPerms = .{
            .write_perm = .write,
            .execute_perm = .no_execute,
            .cache_perm = .write_back,
            .global_perm = .global,
            .privilege_perm = .kernel,
        };

        arch.mapPage(
            new_addr_space_root_virt,
            current_page_phys,
            current_page_virt,
            .page4k,
            perms,
            page_alloc_iface,
        ) catch return .aborted;

        current_page_phys = PAddr.fromInt(current_page_phys.addr + paging.PAGE4K);
    }

    const stack_top_virt = VAddr.fromPAddr(current_page_phys, null);
    const boot_info_virt = VAddr.fromInt(stack_top_virt.addr - @sizeOf(BootInfo));
    const aligned_stack_top_virt = address.alignStack(boot_info_virt);
    const boot_info: *BootInfo = @ptrFromInt(boot_info_virt.addr);

    boot_info.elf_blob.ptr = parsed_elf.bytes.ptr;
    boot_info.elf_blob.len = parsed_elf.bytes.len;
    boot_info.xsdp_phys = xsdp_phys;
    boot_info.stack_top = aligned_stack_top_virt;
    boot_info.mmap = boot_protocol.getMmap(boot_services) orelse return .aborted;
    boot_services.exitBootServices(
        uefi.handle,
        boot_info.mmap.key,
    ) catch {
        boot_info.mmap = boot_protocol.getMmap(boot_services) orelse return .aborted;
        boot_services.exitBootServices(
            uefi.handle,
            boot_info.mmap.key,
        ) catch return .aborted;
    };

    const kEntry: *KEntryType = @ptrFromInt(parsed_elf.entry);
    kEntry(boot_info);
    unreachable;
}
