const fs_mod = @import("fs.zig");
const page_allocator = @import("page_allocator.zig");
const std = @import("std");
const zag = @import("zag");

const BootInfo = zag.boot.protocol.BootInfo;
const PageAllocator = page_allocator.PageAllocator;
const ParsedElf = zag.utils.elf.ParsedElf;

const arch = zag.arch.dispatch;
const elf = zag.utils.elf;
const paging = zag.memory.paging;
const uefi = std.os.uefi;

const PAddr = zag.memory.address.PAddr;

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

    // implement map page and then map in the program headers then call kEntry;

    arch.halt();
}
