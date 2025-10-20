const std = @import("std");
const defs = @import("defs.zig");
const file_mod = @import("file.zig");
const log_mod = @import("log.zig");
const alloc_mod = @import("boot_allocator.zig");
const x86 = @import("x86");

const elf = std.elf;
const paging = x86.Paging;
const cpu = x86.Cpu;
const uefi = std.os.uefi;

pub const std_options = log_mod.default_log_options;

const Addr = elf.Elf64_Addr;

pub fn main() uefi.Status {
    log_mod.init(uefi.system_table.con_out.?) catch return .aborted;
    const log = std.log.scoped(.loader);

    const boot_services: *uefi.tables.BootServices = uefi.system_table.boot_services orelse {
        log.err("Failed to get boot services!", .{});
        return .aborted;
    };
    log.info("Got boot services.", .{});

    const pages_slice = boot_services.allocatePages(
        .any,
        .boot_services_data,
        1,
    ) catch {
        log.err("Failed to allocate page for new pml4", .{});
        return .aborted;
    };
    const page = &pages_slice[0];
    log.info("Allocated page for new pml4.", .{});

    const page4K = @intFromEnum(paging.PageSize.Page4K);

    const pml4_paddr = paging.read_cr3();
    const pml4_ptr = pml4_paddr.getPtr([*]u8);
    const pml4_slice = pml4_ptr[0..page4K];
    @memcpy(page, pml4_slice);
    const new_pml4_paddr = paging.PAddr.fromInt(@intFromPtr(page));
    paging.write_cr3(new_pml4_paddr);
    log.info("Made pml4 writeable.", .{});

    const loaded_image = boot_services.handleProtocol(
        uefi.protocol.LoadedImage,
        uefi.handle,
    ) catch |err| {
        log.err("Failed to get loaded image protocol: {}", .{err});
        return .aborted;
    } orelse {
        log.err("Failed to get loaded image protocol", .{});
        return .aborted;
    };
    log.info("Got load image protocol", .{});

    if (loaded_image.device_handle == null) {
        log.err("Loaded image doesn't contain device handle", .{});
        return .aborted;
    }

    const fs: *uefi.protocol.SimpleFileSystem = boot_services.handleProtocol(
        uefi.protocol.SimpleFileSystem,
        loaded_image.device_handle.?,
    ) catch |err| {
        log.err("Failed to locate simple file system protocol: {}", .{err});
        return .aborted;
    } orelse {
        log.err("Failed to get simple file system protocol", .{});
        return .aborted;
    };
    log.info("Got file system protocol", .{});

    const root_dir: *uefi.protocol.File = fs.openVolume() catch |err| {
        log.err("Failed to open volume: {}", .{err});
        return .aborted;
    };
    log.info("Opened root volume", .{});

    const kernel_file = file_mod.openFile(
        root_dir,
        "kernel.elf",
    ) catch return .aborted;
    log.info("Opened kernel elf file", .{});

    var header_size: u64 = @sizeOf(elf.Elf64_Ehdr);
    var header_buffer = boot_services.allocatePool(
        .loader_data,
        header_size,
    ) catch |err| {
        log.err("Failed to allocate ELF header buffer: {}", .{err});
        return .aborted;
    };
    log.info("Allocated buffer for kernel elf header", .{});

    header_size = kernel_file.read(header_buffer) catch |err| {
        log.err("Failed to read kernel ELF header: {}", .{err});
        return .aborted;
    };
    log.info("Read kernel elf header", .{});

    var reader = std.Io.Reader.fixed(header_buffer[0..header_size]);
    const elf_header = elf.Header.read(&reader) catch |err| {
        log.err("Failed to parse kernel ELF header: {}", .{err});
        return .aborted;
    };
    log.info("Parsed kernel elf header", .{});

    const phdr_size = elf_header.phentsize * elf_header.phnum;
    const file_prefix_size = elf_header.phoff + phdr_size;
    const prefix_buffer = boot_services.allocatePool(
        .loader_data,
        file_prefix_size,
    ) catch {
        log.err("Failed to allocate ELF prefix buffer", .{});
        return .aborted;
    };

    kernel_file.setPosition(0) catch {
        log.err("Failed to seek to 0", .{});
        return .aborted;
    };
    const got_prefix = kernel_file.read(prefix_buffer) catch {
        log.err("Failed to read ELF prefix", .{});
        return .aborted;
    };
    if (got_prefix != file_prefix_size) {
        log.err("Short read of ELF prefix: got {} expected {}", .{ got_prefix, file_prefix_size });
        return .aborted;
    }

    var iter = elf_header.iterateProgramHeadersBuffer(prefix_buffer);
    log.info("Parsing kernel elf program headers", .{});

    var page_allocator = alloc_mod.PageAllocator.init(
        boot_services,
        .loader_data,
    );
    const page_alloc_iface = page_allocator.allocator();

    while (true) {
        const phdr = iter.next() catch |err| {
            if (err == error.EndOfStream) break;
            log.err("PHDR iter error: {}", .{err});
            return .aborted;
        } orelse break;
        if (phdr.p_type != elf.PT_LOAD) continue;

        const writeable = (phdr.p_flags & elf.PF_W) != 0;
        const not_executeable = (phdr.p_flags & elf.PF_X) == 0;

        const start_vaddr = phdr.p_vaddr;
        const end_vaddr = start_vaddr + phdr.p_memsz;
        const start_paddr = phdr.p_paddr;

        var vaddr = start_vaddr;
        var paddr = start_paddr;

        while (vaddr < end_vaddr) {
            paging.mapPage(
                @ptrFromInt(new_pml4_paddr.addr),
                paging.PAddr.fromInt(paddr),
                paging.VAddr.fromInt(vaddr),
                if (writeable) .ReadWrite else .Readonly,
                not_executeable,
                .Supervisor,
                .Page4K,
                .identity,
                page_alloc_iface,
            );

            vaddr += page4K;
            paddr += page4K;
        }

        kernel_file.setPosition(phdr.p_offset) catch |err| {
            log.err("Failed to read kernel segment into memory: {}", .{err});
            return .aborted;
        };

        // disable and then reenable the write protect bit when copying
        // data from file into memory to temporarily bypass the text and rodata
        // sections being mapped with the correct readonly permissions
        cpu.setWriteProtect(false);
        defer cpu.setWriteProtect(true);

        const segment: [*]u8 = @ptrFromInt(phdr.p_vaddr);
        var copied: u64 = 0;
        while (copied < phdr.p_filesz) {
            const segment_slice = segment[copied..phdr.p_filesz];
            const chunk = kernel_file.read(segment_slice) catch |err| {
                log.err("Failed to read kernel segment into memory: {}", .{err});
                return .aborted;
            };
            if (chunk == 0) {
                log.err("Short read while loading segment: copied {} of {}", .{
                    copied,
                    phdr.p_filesz,
                });
                return .aborted;
            }
            copied += chunk;
        }

        // zero the bss section tail
        if (phdr.p_memsz > phdr.p_filesz) {
            const segment_slice = segment[phdr.p_filesz..phdr.p_memsz];
            @memset(segment_slice, 0);
        }
    }
    log.info("Mapped Zag kernel sections into memory", .{});

    const map_file = file_mod.openFile(
        root_dir,
        "kernel.map",
    ) catch |err| {
        log.err("Failed to open kernel.map: {}", .{err});
        return .aborted;
    };

    const info_size = map_file.getInfoSize(.file) catch |err| {
        log.err("Failed to stat size of kernel.map: {}", .{err});
        return .aborted;
    };

    const info_bytes = boot_services.allocatePool(.loader_data, info_size) catch |err| {
        log.err("Failed to alloc File.Info buffer: {}", .{err});
        return .aborted;
    };

    const map_file_info = map_file.getInfo(.file, info_bytes[0..info_size]) catch |err| {
        log.err("Failed to get file info for kernel.map: {}", .{err});
        return .aborted;
    };

    const map_buf = boot_services.allocatePool(.loader_data, map_file_info.file_size) catch |err| {
        log.err("Failed to alloc buffer for kernel.map: {}", .{err});
        return .aborted;
    };

    var read_total: usize = 0;
    while (read_total < map_file_info.file_size) {
        const chunk = map_file.read(map_buf[read_total..map_file_info.file_size]) catch |err| {
            log.err("Failed to read kernel.map: {}", .{err});
            return .aborted;
        };
        if (chunk == 0) {
            log.err("Short read on kernel.map: got {}", .{read_total});
            return .aborted;
        }
        read_total += chunk;
    }

    map_file.close() catch |err| {
        log.err("Failed to close kernel.map: {}", .{err});
        return .aborted;
    };

    boot_services.freePool(@ptrCast(header_buffer.ptr)) catch |err| {
        log.err("Failed to free memory for kernel ELF header: {}", .{err});
        return .aborted;
    };

    kernel_file.close() catch |err| {
        log.err("Failed to close kernel ELF file: {}", .{err});
        return .aborted;
    };

    root_dir.close() catch |err| {
        log.err("Failed to close root volume: {}", .{err});
        return .aborted;
    };

    const mmap_pages_slice = boot_services.allocatePages(
        .any,
        .boot_services_data,
        4,
    ) catch {
        log.err("Failed to allocate pages for memory map", .{});
        return .aborted;
    };
    log.info("Allocated pages for memory map.", .{});

    const mmap_pages_bytes = (@as([*]u8, @ptrCast(mmap_pages_slice.ptr)))[0 .. page4K * 4];
    const mmap_buf: []align(@alignOf(uefi.tables.MemoryDescriptor)) u8 = @alignCast(mmap_pages_bytes);

    var map = boot_services.getMemoryMap(mmap_buf) catch |err| {
        log.err("Failed to get memory map: {}", .{err});
        return .aborted;
    };

    log.info("Exiting boot services.", .{});
    boot_services.exitBootServices(
        uefi.handle,
        map.info.key,
    ) catch {
        map = boot_services.getMemoryMap(mmap_buf) catch |err| {
            log.err("Failed to get memory map: {}", .{err});
            return .aborted;
        };
        boot_services.exitBootServices(
            uefi.handle,
            map.info.key,
        ) catch |err| {
            log.err("Failed to exit boot services: {}", .{err});
            return .aborted;
        };
    };

    const boot_info = defs.BootInfo{
        .mmap = .{
            .buffer_size = mmap_buf.len,
            .descriptors = @alignCast(@ptrCast(mmap_buf.ptr)),
            .map_key = map.info.key,
            .map_size = map.info.len,
            .descriptor_size = map.info.descriptor_size,
            .descriptor_version = map.info.descriptor_version,
        },
        .ksyms = .{
            .ptr = map_buf.ptr,
            .len = map_file_info.file_size,
        },
    };

    const KEntryType = fn (defs.BootInfo) noreturn;
    const kentry: *KEntryType = @ptrFromInt(elf_header.entry);

    kentry(boot_info);
    unreachable;
}
