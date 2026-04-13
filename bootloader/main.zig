const fs_mod = @import("fs.zig");
const page_allocator = @import("page_allocator.zig");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const address = zag.memory.address;
const boot_protocol = zag.boot.protocol;
const elf = zag.utils.elf;
const paging = zag.memory.paging;
const std_elf = std.elf;
const uefi = std.os.uefi;

const BootInfo = boot_protocol.BootInfo;
const ElfSection = elf.ElfSection;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageAllocator = page_allocator.PageAllocator;
const ParsedElf = zag.utils.elf.ParsedElf;
const VAddr = zag.memory.address.VAddr;

const KEntryType = fn (*BootInfo) callconv(zag.arch.dispatch.cc()) noreturn;

fn computeKaslrSlide(parsed_elf: *const ParsedElf) u64 {
    const link_base = address.AddrSpacePartition.kernel_code.start;
    const kaslr_end = address.AddrSpacePartition.kernel_code.end;

    var image_end: u64 = 0;
    const num_sections = @intFromEnum(ElfSection.num_sections);
    for (0..num_sections) |i| {
        const section = parsed_elf.sections[i];
        const section_end = section.vaddr + section.size;
        if (section_end > image_end) image_end = section_end;
    }
    const image_size = std.mem.alignForward(u64, image_end - link_base, paging.PAGE4K);
    const max_slide = kaslr_end - link_base - image_size;
    const slide_pages = max_slide / paging.PAGE4K;

    const entropy = arch.readTimestamp();
    const offset_pages = entropy % slide_pages;
    return offset_pages * paging.PAGE4K;
}

fn applyKaslrRelocations(file_bytes: []u8, slide: u64) !void {
    if (slide == 0) return;
    if (file_bytes.len < @sizeOf(std_elf.Elf64_Ehdr)) return error.InvalidElf;

    const ehdr = std.mem.bytesAsValue(
        std_elf.Elf64_Ehdr,
        file_bytes[0..@sizeOf(std_elf.Elf64_Ehdr)],
    );
    const shdr_size: u64 = ehdr.e_shentsize;
    const shdr_count: u64 = ehdr.e_shnum;

    if (ehdr.e_shoff == 0 or shdr_count == 0) return;
    if (shdr_size < @sizeOf(std_elf.Elf64_Shdr)) return;

    var s: u64 = 0;
    while (s < shdr_count) : (s += 1) {
        const off = ehdr.e_shoff + s * shdr_size;
        const shdr = std.mem.bytesAsValue(
            std_elf.Elf64_Shdr,
            file_bytes[off..][0..@sizeOf(std_elf.Elf64_Shdr)],
        );
        if (shdr.sh_type != std_elf.SHT_RELA) continue;

        const target_idx: u64 = shdr.sh_info;
        if (target_idx == 0 or target_idx >= shdr_count) continue;

        const target_off = ehdr.e_shoff + target_idx * shdr_size;
        const target_shdr = std.mem.bytesAsValue(
            std_elf.Elf64_Shdr,
            file_bytes[target_off..][0..@sizeOf(std_elf.Elf64_Shdr)],
        );

        if ((target_shdr.sh_flags & std_elf.SHF_ALLOC) == 0) continue;

        const target_base_addr = target_shdr.sh_addr;
        const target_base_file_offset = target_shdr.sh_offset;

        const entry_size: u64 = @sizeOf(std_elf.Elf64_Rela);
        const num_entries = shdr.sh_size / entry_size;

        var r: u64 = 0;
        while (r < num_entries) : (r += 1) {
            const rela_off = shdr.sh_offset + r * entry_size;
            const rela = std.mem.bytesAsValue(
                std_elf.Elf64_Rela,
                file_bytes[rela_off..][0..entry_size],
            );
            const rtype: u32 = @truncate(rela.r_info);

            if (rela.r_offset < target_base_addr) return error.InvalidElf;
            const file_off = target_base_file_offset + (rela.r_offset - target_base_addr);

            switch (arch.classifyRelocation(rtype)) {
                .skip => continue,
                .abs64 => {
                    if (file_off + 8 > file_bytes.len) return error.InvalidElf;
                    const slot: *align(1) u64 = @ptrCast(file_bytes.ptr + file_off);
                    slot.* +%= slide;
                },
                .abs32 => {
                    if (file_off + 4 > file_bytes.len) return error.InvalidElf;
                    const slot: *align(1) i32 = @ptrCast(file_bytes.ptr + file_off);
                    const new_val: i64 = @as(i64, slot.*) +% @as(i64, @bitCast(slide));
                    slot.* = @truncate(new_val);
                },
                .unsupported => return error.InvalidElf,
            }
        }
    }
}

fn puts(msg: [*:0]const u16) void {
    if (uefi.system_table.con_out) |out| {
        _ = out.outputString(msg) catch {};
    }
}


const dbg = struct {
    const boot_start = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] boot start\r\n");
    const page_tables = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] page tables\r\n");
    const physmap = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] physmap\r\n");
    const loading = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] loading files\r\n");
    const kernel_elf = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] kernel.elf\r\n");
    const rs_elf = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] root_service\r\n");
    const elf_parsed = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] ELF parsed\r\n");
    const kaslr1 = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] KASLR slide\r\n");
    const kaslr2 = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] KASLR reloc\r\n");
    const sections = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] sections\r\n");
    const sections_done = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] mapped\r\n");
    const stack = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] stack\r\n");
    const exit_bs = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] exit BS\r\n");
    const jump = std.unicode.utf8ToUtf16LeStringLiteral("[ZAG] jump\r\n");
};

pub fn main() uefi.Status {
    const boot_services: *uefi.tables.BootServices = uefi.system_table.boot_services orelse return .aborted;
    uefi.system_table.con_out.?.clearScreen() catch return .aborted;
    puts(dbg.boot_start);

    var page_alloc = PageAllocator.init(boot_services, .acpi_reclaim_memory);
    const page_alloc_iface = page_alloc.allocator();

    puts(dbg.page_tables);

    // Set up the kernel page table root. enableKernelTranslation() is a no-op
    // on x86-64 (CR3 covers both halves) and configures TCR_EL1 TTBR1 on
    // aarch64. getKernelAddrSpaceRoot() returns CR3 on x86 / TTBR1 on aarch64.
    arch.enableKernelTranslation();

    // Copy or allocate the kernel page table root. On x86-64, the UEFI
    // identity-mapped CR3 covers both halves so we copy it and keep using it.
    // On aarch64 TTBR1 may be uninitialized, but getKernelAddrSpaceRoot still
    // returns whatever is there — allocate a fresh table regardless, set it as
    // the kernel root, then use it for all kernel-range mappings.
    const kernel_table_root_phys: PAddr = blk: {
        const fresh = page_alloc_iface.alignedAlloc(
            u8,
            paging.pageAlign(.page4k),
            paging.PAGE4K,
        ) catch return .aborted;

        // On x86-64 (shared CR3): copy UEFI's identity-mapped table so the
        // bootloader keeps running from the same mappings.
        // On aarch64 (split TTBR0/TTBR1): start with a clean kernel table.
        if (arch.kernel_shares_user_table) {
            const current = arch.getKernelAddrSpaceRoot();
            const src = current.getPtr([*]u8);
            @memcpy(fresh, src[0..paging.PAGE4K]);
        } else {
            @memset(fresh, 0);
        }

        const phys = PAddr.fromInt(@intFromPtr(fresh.ptr));
        arch.setKernelAddrSpace(phys);
        break :blk phys;
    };

    puts(dbg.physmap);
    const identity_mapping = 0;
    const new_addr_space_root_virt = VAddr.fromPAddr(kernel_table_root_phys, identity_mapping);

    const new_addr_space_root_virt_physmapped = VAddr.fromPAddr(kernel_table_root_phys, null);
    const addr_space_root_perms: MemoryPerms = .{
        .write_perm = .write,
        .execute_perm = .no_execute,
        .cache_perm = .write_back,
        .global_perm = .global,
        .privilege_perm = .kernel,
    };
    arch.mapPageBoot(
        new_addr_space_root_virt,
        kernel_table_root_phys,
        new_addr_space_root_virt_physmapped,
        .page4k,
        addr_space_root_perms,
        page_alloc_iface,
    ) catch return .aborted;

    puts(dbg.loading);
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
    puts(dbg.kernel_elf);

    const rs_file = fs_mod.openFile(root_dir, "root_service.elf") catch return .aborted;
    const rs_bytes = fs_mod.readFile(rs_file, boot_services) catch return .aborted;
    puts(dbg.rs_elf);

    const parsed_elf_mem = boot_services.allocatePool(.loader_data, @sizeOf(ParsedElf)) catch return .aborted;
    const parsed_elf: *ParsedElf = @ptrCast(parsed_elf_mem.ptr);
    elf.parseElf(parsed_elf, file_bytes) catch return .aborted;
    puts(dbg.elf_parsed);

    const kaslr_slide = computeKaslrSlide(parsed_elf);
    puts(dbg.kaslr1);
    applyKaslrRelocations(file_bytes, kaslr_slide) catch return .aborted;
    puts(dbg.kaslr2);
    puts(dbg.sections);

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
        const start_vaddr = section.vaddr + kaslr_slide;
        const end_vaddr = section.vaddr + section.size + kaslr_slide;
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

            arch.mapPageBoot(
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

    puts(dbg.sections_done);
    const xsdp_addr = boot_protocol.findXSDP() catch return .aborted;
    const xsdp_phys = PAddr.fromInt(xsdp_addr);

    const gop = boot_services.locateProtocol(uefi.protocol.GraphicsOutput, null) catch null;
    const framebuffer: boot_protocol.Framebuffer = if (gop) |g| .{
        .base = PAddr.fromInt(g.mode.frame_buffer_base),
        .size = g.mode.frame_buffer_size,
        .width = g.mode.info.horizontal_resolution,
        .height = g.mode.info.vertical_resolution,
        .stride = g.mode.info.pixels_per_scan_line,
        .pixel_format = switch (g.mode.info.pixel_format) {
            .red_green_blue_reserved_8_bit_per_color => .rgb8,
            .blue_green_red_reserved_8_bit_per_color => .bgr8,
            .bit_mask => .bitmask,
            .blt_only => .blt_only,
        },
    } else .{
        .base = PAddr.fromInt(0),
        .size = 0,
        .width = 0,
        .height = 0,
        .stride = 0,
        .pixel_format = .none,
    };

    puts(dbg.stack);
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

        arch.mapPageBoot(
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
    boot_info.root_service.ptr = rs_bytes.ptr;
    boot_info.root_service.len = rs_bytes.len;
    boot_info.xsdp_phys = xsdp_phys;
    boot_info.stack_top = aligned_stack_top_virt;
    boot_info.framebuffer = framebuffer;
    boot_info.kaslr_slide = kaslr_slide;
    puts(dbg.exit_bs);
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

    // Final TLB flush after exitBootServices ensures all TTBR1 page table
    // entries are visible to the hardware walker before jumping to the kernel.
    arch.setKernelAddrSpace(kernel_table_root_phys);
    // Switch SP to kernel stack before calling kEntry. After exitBootServices,
    // the UEFI stack (loader_data) may be reclaimed — writing to it would
    // fault on KVM where memory is real hardware.
    arch.switchStackAndCall(
        boot_info.stack_top,
        @intFromPtr(boot_info),
        parsed_elf.entry.addr + kaslr_slide,
    );
}
