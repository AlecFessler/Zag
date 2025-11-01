//! UEFI bootloader entry and kernel handoff.
//!
//! Responsibilities:
//! - Initialize logging and access UEFI Boot Services.
//! - Duplicate the current PML4 into a writeable page and reload CR3.
//! - Open the boot volume via Simple File System and load `kernel.elf`.
//! - Map PT_LOAD segments with appropriate permissions (RO/RW, NX).
//! - Load `kernel.map` into a reserved pool for later symbolization.
//! - Discover ACPI XSDP and capture the final memory map.
//! - Exit Boot Services, build `BootInfo`, and jump to the kernel entry.

const alloc_mod = @import("boot_allocator.zig");
const defs_mod = @import("defs.zig");
const file_mod = @import("file.zig");
const log_mod = @import("log.zig");
const mmap_mod = @import("mmap.zig");
const std = @import("std");
const x86 = @import("x86");

const cpu = x86.Cpu;
const elf = std.elf;
const paging = x86.Paging;
const uefi = std.os.uefi;

pub const KEntryType = fn (defs_mod.BootInfo) callconv(.{ .x86_64_sysv = .{} }) noreturn;

pub const std_options = log_mod.default_log_options;

/// UEFI application entry point.
///
/// Performs loader setup, copies the current PML4 into a fresh page,
/// opens the boot volume, loads and maps `kernel.elf`, loads `kernel.map`,
/// locates ACPI XSDP, acquires the final memory map, exits Boot Services,
/// constructs `BootInfo`, and tail-calls the kernel entry point.
///
/// Returns:
/// - `.aborted` on failure (errors are logged here).
/// - Does not return on success (transfers control to the kernel).
pub fn main() uefi.Status {
    log_mod.init(uefi.system_table.con_out.?) catch return .aborted;
    const log = std.log.scoped(.loader);

    const boot_services: *uefi.tables.BootServices = uefi.system_table.boot_services orelse {
        log.err("Failed to get boot services!", .{});
        return .aborted;
    };

    const pages_slice = boot_services.allocatePages(
        .any,
        .reserved_memory_type,
        1,
    ) catch {
        log.err("Failed to allocate page for new pml4", .{});
        return .aborted;
    };
    const page = &pages_slice[0];

    const page4K = @intFromEnum(paging.PageSize.Page4K);

    const pml4_paddr = paging.read_cr3();
    const pml4_ptr = pml4_paddr.getPtr([*]u8);
    const pml4_slice = pml4_ptr[0..page4K];
    @memcpy(page, pml4_slice);
    const new_pml4_paddr = paging.PAddr.fromInt(@intFromPtr(page));
    paging.write_cr3(new_pml4_paddr);

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

    const root_dir: *uefi.protocol.File = fs.openVolume() catch |err| {
        log.err("Failed to open volume: {}", .{err});
        return .aborted;
    };

    const kentry_addr = loadKernel(
        boot_services,
        root_dir,
        new_pml4_paddr,
    ) orelse return .aborted;

    const ksyms_bytes = loadKsymsMap(
        boot_services,
        root_dir,
    ) orelse return .aborted;

    root_dir.close() catch |err| {
        log.err("Failed to close root volume: {}", .{err});
        return .aborted;
    };

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
        ) catch |err| {
            log.err("Failed to exit boot services: {}", .{err});
            return .aborted;
        };
    };

    const boot_info = defs_mod.BootInfo{
        .xsdp_paddr = xsdp_paddr,
        .mmap = mmap,
        .ksyms = .{
            .ptr = ksyms_bytes.ptr,
            .len = ksyms_bytes.len,
        },
    };

    const kEntry: *KEntryType = @ptrFromInt(kentry_addr);

    kEntry(boot_info);
    unreachable;
}

/// Load and map `kernel.elf` into the provided page tables, returning the entry address.
///
/// Behavior:
/// - Opens `kernel.elf`, parses ELF header and program headers.
/// - Allocates backing pages for each `PT_LOAD` segment and identity maps them
///   into `new_pml4_paddr` with permissions derived from `p_flags` (read-only
///   vs read-write, and NX for non-executable segments).
/// - Copies file bytes into mapped memory and zero-fills BSS (`p_memsz > p_filesz`).
///
/// Params:
/// - `boot_services`: UEFI boot services pointer.
/// - `root_dir`: root volume already opened.
/// - `new_pml4_paddr`: physical address of the active PML4 to receive mappings.
///
/// Returns:
/// - `elf.Elf64_Addr` entry point on success.
/// - `null` on failure (errors are logged here).
fn loadKernel(
    boot_services: *uefi.tables.BootServices,
    root_dir: *uefi.protocol.File,
    new_pml4_paddr: paging.PAddr,
) ?elf.Elf64_Addr {
    const log = std.log.scoped(.kernel_loader);

    const kernel_file = file_mod.openFile(root_dir, "kernel.elf") catch {
        return null;
    };
    defer {
        kernel_file.close() catch |err| {
            log.err("Failed to close kernel ELF file: {}", .{err});
        };
    }

    var header_size: usize = @sizeOf(elf.Elf64_Ehdr);
    var header_buffer = boot_services.allocatePool(.loader_data, header_size) catch |err| {
        log.err("Failed to allocate ELF header buffer: {}", .{err});
        return null;
    };
    defer {
        boot_services.freePool(@ptrCast(header_buffer.ptr)) catch |ferr| {
            log.err("Failed to free memory for kernel ELF header: {}", .{ferr});
        };
    }

    header_size = kernel_file.read(header_buffer) catch |err| {
        log.err("Failed to read kernel ELF header: {}", .{err});
        return null;
    };

    var reader = std.Io.Reader.fixed(header_buffer[0..header_size]);
    const elf_header = elf.Header.read(&reader) catch |err| {
        log.err("Failed to parse kernel ELF header: {}", .{err});
        return null;
    };

    const phdr_size: usize = elf_header.phentsize * elf_header.phnum;
    const file_prefix_size: usize = @intCast(elf_header.phoff + phdr_size);

    const prefix_buffer = boot_services.allocatePool(.loader_data, file_prefix_size) catch {
        log.err("Failed to allocate ELF prefix buffer", .{});
        return null;
    };
    defer {
        boot_services.freePool(@ptrCast(prefix_buffer.ptr)) catch |ferr| {
            log.err("Failed to free ELF prefix buffer: {}", .{ferr});
        };
    }

    kernel_file.setPosition(0) catch {
        log.err("Failed to seek to 0", .{});
        return null;
    };
    const got_prefix = kernel_file.read(prefix_buffer) catch {
        log.err("Failed to read ELF prefix", .{});
        return null;
    };
    if (got_prefix != file_prefix_size) {
        log.err("Short read of ELF prefix: got {} expected {}", .{ got_prefix, file_prefix_size });
        return null;
    }

    var iter = elf_header.iterateProgramHeadersBuffer(prefix_buffer);

    var page_allocator = alloc_mod.PageAllocator.init(
        boot_services,
        .reserved_memory_type,
    );
    const page_alloc_iface = page_allocator.allocator();

    const page4K: u64 = @intFromEnum(paging.PageSize.Page4K);

    while (true) {
        const phdr = iter.next() catch |err| {
            if (err == error.EndOfStream) break;
            log.err("PHDR iter error: {}", .{err});
            return null;
        } orelse break;
        if (phdr.p_type != elf.PT_LOAD) continue;

        const writeable = (phdr.p_flags & elf.PF_W) != 0;
        const not_executeable = (phdr.p_flags & elf.PF_X) == 0;

        const start_vaddr: u64 = phdr.p_vaddr;
        const end_vaddr: u64 = start_vaddr + phdr.p_memsz;

        var vaddr = start_vaddr;
        while (vaddr < end_vaddr) {
            const backing_page_slice = boot_services.allocatePages(
                .any,
                .reserved_memory_type,
                1,
            ) catch {
                log.err("Failed to allocate backing page for segment", .{});
                return null;
            };

            const backing_page_paddr = @intFromPtr(&backing_page_slice[0]);

            paging.mapPage(
                @ptrFromInt(new_pml4_paddr.addr),
                paging.PAddr.fromInt(backing_page_paddr),
                paging.VAddr.fromInt(vaddr),
                if (writeable) .ReadWrite else .Readonly,
                not_executeable,
                .Supervisor,
                .Page4K,
                .identity,
                page_alloc_iface,
            );

            vaddr += page4K;
        }

        kernel_file.setPosition(phdr.p_offset) catch |err| {
            log.err("Failed to position for kernel segment: {}", .{err});
            return null;
        };

        cpu.setWriteProtect(false);
        defer cpu.setWriteProtect(true);

        const segment: [*]u8 = @ptrFromInt(phdr.p_vaddr);
        var copied: u64 = 0;
        while (copied < phdr.p_filesz) {
            const segment_slice = segment[copied..phdr.p_filesz];
            const chunk = kernel_file.read(segment_slice) catch |err| {
                log.err("Failed to read kernel segment into memory: {}", .{err});
                return null;
            };
            if (chunk == 0) {
                log.err("Short read while loading segment: copied {} of {}", .{
                    copied,
                    phdr.p_filesz,
                });
                return null;
            }
            copied += chunk;
        }

        if (phdr.p_memsz > phdr.p_filesz) {
            const segment_slice = segment[phdr.p_filesz..phdr.p_memsz];
            @memset(segment_slice, 0);
        }
    }

    return elf_header.entry;
}

/// Load `kernel.map` into a reserved UEFI pool and return its bytes.
///
/// Params:
/// - `boot_services`: UEFI boot services pointer
/// - `root_dir`: already-opened root volume
///
/// Returns:
/// - `[]u8` slice of the file contents on success
/// - `null` on failure (errors are logged here)
fn loadKsymsMap(
    boot_services: *uefi.tables.BootServices,
    root_dir: *uefi.protocol.File,
) ?[]u8 {
    const log = std.log.scoped(.ksyms_loader);

    const ksyms_file = file_mod.openFile(root_dir, "kernel.map") catch |err| {
        log.err("Failed to open kernel.map: {}", .{err});
        return null;
    };
    defer {
        ksyms_file.close() catch |cerr| {
            log.err("Failed to close kernel.map: {}", .{cerr});
        };
    }

    const info_size = ksyms_file.getInfoSize(.file) catch |err| {
        log.err("Failed to stat size of kernel.map: {}", .{err});
        return null;
    };

    const info_bytes = boot_services.allocatePool(.loader_data, info_size) catch |err| {
        log.err("Failed to alloc File.Info buffer: {}", .{err});
        return null;
    };
    defer {
        boot_services.freePool(@ptrCast(info_bytes.ptr)) catch |ferr| {
            log.err("Failed to free File.Info buffer: {}", .{ferr});
        };
    }

    const info = ksyms_file.getInfo(.file, info_bytes[0..info_size]) catch |err| {
        log.err("Failed to get file info for kernel.map: {}", .{err});
        return null;
    };

    const map_size: usize = @intCast(info.file_size);

    const map_buf = boot_services.allocatePool(.reserved_memory_type, map_size) catch |err| {
        log.err("Failed to alloc buffer for kernel.map: {}", .{err});
        return null;
    };

    var read_total: usize = 0;
    while (read_total < map_size) {
        const chunk = ksyms_file.read(map_buf[read_total..map_size]) catch |err| {
            log.err("Failed to read kernel.map: {}", .{err});
            return null;
        };
        if (chunk == 0) {
            log.err("Short read on kernel.map: got {}", .{read_total});
            return null;
        }
        read_total += chunk;
    }

    return map_buf[0..map_size];
}
