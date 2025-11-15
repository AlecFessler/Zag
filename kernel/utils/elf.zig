const std = @import("std");

const elf = std.elf;
const Dwarf = std.debug.Dwarf;

pub const Text = struct {
    vaddr: u64,
    size: u64,
    offset: u64,
};

pub const Rodata = struct {
    vaddr: u64,
    size: u64,
    offset: u64,
};

pub const Data = struct {
    vaddr: u64,
    size: u64,
    offset: u64,
};

pub const Bss = struct {
    vaddr: u64,
    size: u64,
};

pub const ParsedElf = struct {
    bytes: []u8,
    entry: u64,
    text: Text,
    rodata: Rodata,
    data: Data,
    bss: Bss,
    dwarf: Dwarf,
};

pub fn parseElf(result: *ParsedElf, bytes: []u8) !void {
    result.bytes = bytes;

    const hdr_sz = @sizeOf(elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(bytes[0..hdr_sz]);
    const elf_hdr = try elf.Header.read(&rd);

    result.entry = elf_hdr.entry;
    result.dwarf = .{
        .endian = elf_hdr.endian,
        .is_macho = false,
    };

    var phdr_itr = elf_hdr.iterateProgramHeadersBuffer(bytes);

    while (try phdr_itr.next()) |phdr| {
        if (phdr.p_type != elf.PT_LOAD) continue;
        const writable = (phdr.p_flags & elf.PF_W) != 0;
        const executable = (phdr.p_flags & elf.PF_X) != 0;
        if (!writable and executable) {
            result.text = .{
                .vaddr = phdr.p_vaddr,
                .size = phdr.p_filesz,
                .offset = phdr.p_offset,
            };
        } else if (!writable and !executable) {
            result.rodata = .{
                .vaddr = phdr.p_vaddr,
                .size = phdr.p_filesz,
                .offset = phdr.p_offset,
            };
        } else if (writable and !executable) {
            result.data = .{
                .vaddr = phdr.p_vaddr,
                .size = phdr.p_filesz,
                .offset = phdr.p_offset,
            };
            result.bss = .{
                .vaddr = phdr.p_vaddr + phdr.p_filesz,
                .size = phdr.p_memsz - phdr.p_filesz,
            };
        }
    }

    var shdr_itr = elf_hdr.iterateSectionHeadersBuffer(bytes);

    const shdrs = std.mem.bytesAsSlice(
        elf.Elf64_Shdr,
        bytes[elf_hdr.shoff .. elf_hdr.shoff + elf_hdr.shentsize * elf_hdr.shnum],
    );

    const shstr_shdr = shdrs[elf_hdr.shstrndx];
    const shstr_end = shstr_shdr.sh_offset + shstr_shdr.sh_size;
    const shstr = bytes[shstr_shdr.sh_offset..shstr_end];

    while (try shdr_itr.next()) |shdr| {
        const name = getCStrAt(shstr, @intCast(shdr.sh_name)) orelse "<bad name>";

        const dwarf_idx = blk: {
            if (std.mem.eql(u8, name, ".debug_info")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_info);
            } else if (std.mem.eql(u8, name, ".debug_abbrev")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_abbrev);
            } else if (std.mem.eql(u8, name, ".debug_str")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_str);
            } else if (std.mem.eql(u8, name, ".debug_str_offsets")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_str_offsets);
            } else if (std.mem.eql(u8, name, ".debug_line")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_line);
            } else if (std.mem.eql(u8, name, ".debug_line_str")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_line_str);
            } else if (std.mem.eql(u8, name, ".debug_ranges")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_ranges);
            } else if (std.mem.eql(u8, name, ".debug_loclists")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_loclists);
            } else if (std.mem.eql(u8, name, ".debug_rnglists")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_rnglists);
            } else if (std.mem.eql(u8, name, ".debug_addr")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_addr);
            } else if (std.mem.eql(u8, name, ".debug_names")) {
                break :blk @intFromEnum(Dwarf.Section.Id.debug_names);
            } else if (std.mem.eql(u8, name, ".eh_frame")) {
                break :blk @intFromEnum(Dwarf.Section.Id.eh_frame);
            } else if (std.mem.eql(u8, name, ".eh_frame_hdr")) {
                break :blk @intFromEnum(Dwarf.Section.Id.eh_frame_hdr);
            } else {
                break :blk null;
            }
        };
        if (dwarf_idx) |i| {
            result.dwarf.sections[i] = .{
                .data = bytes[shdr.sh_offset .. shdr.sh_offset + shdr.sh_size],
                .owned = false,
            };
        }
    }
}

fn getCStrAt(bytes: []const u8, offset: u64) ?[]const u8 {
    if (offset >= bytes.len) return null;
    const tail = bytes[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
    return tail[0..end];
}
