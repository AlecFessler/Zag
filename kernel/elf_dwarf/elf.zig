const std = @import("std");
const elf = std.elf;

pub const Section = struct {
    vaddr: u64,
    len: u64,
    offset: u64,
};

pub const ParsedElf = struct {
    bytes: []u8,
    entry: u64,
    endian: std.builtin.Endian,
    text: Section,
    rodata: Section,
    data: Section,
    bss: Section,
    dbg_info: ?Section,
    dbg_abbrev: ?Section,
    dbg_str: ?Section,
    dbg_str_offsets: ?Section,
    dbg_line: ?Section,
    dbg_line_str: ?Section,
    dbg_ranges: ?Section,
    dbg_loclists: ?Section,
    dbg_rnglists: ?Section,
    dbg_addr: ?Section,
    dbg_names: ?Section,
    dbg_eh_frame: ?Section,
    dbg_eh_frame_hdr: ?Section,
};

fn parseElf(bytes: []u8) !ParsedElf {
    var result: ParsedElf = undefined;
    result.bytes = bytes;

    const hdr_sz = @sizeOf(elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(bytes[0..hdr_sz]);
    const elf_hdr = try elf.Header.read(&rd);

    result.entry = elf_hdr.entry;
    result.endian = elf_hdr.endian;

    const shdrs = std.mem.bytesAsSlice(
        elf.Elf64_Shdr,
        bytes[elf_hdr.shoff .. elf_hdr.shoff + elf_hdr.shentsize * elf_hdr.shnum],
    );

    const shstr_shdr = shdrs[elf_hdr.shstrndx];
    const shstr_end = shstr_shdr.sh_offset + shstr_shdr.sh_size;
    const shstr = bytes[shstr_shdr.sh_offset..shstr_end];

    var shdr_itr = elf_hdr.iterateSectionHeadersBuffer(bytes);
    while (true) {
        const shdr = shdr_itr.next() catch break orelse break;
        const name = getCStrAt(shstr, @intCast(shdr.sh_name)) orelse "<bad name>";

        if (std.mem.eql(u8, name, ".text")) {
            result.text = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".rodata")) {
            result.rodata = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".data")) {
            result.data = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".bss")) {
            result.bss = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_info")) {
            result.dbg_info = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_abbrev")) {
            result.dbg_abbrev = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_str")) {
            result.dbg_str = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_str_offsets")) {
            result.dbg_str_offsets = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_line")) {
            result.dbg_line = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_line_str")) {
            result.dbg_line_str = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_ranges")) {
            result.dbg_ranges = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_loclists")) {
            result.dbg_loclists = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_rnglists")) {
            result.dbg_rnglists = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_addr")) {
            result.dbg_addr = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".debug_names")) {
            result.dbg_names = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".eh_frame")) {
            result.dbg_eh_frame = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        } else if (std.mem.eql(u8, name, ".eh_frame_hdr")) {
            result.dbg_eh_frame_hdr = .{
                .vaddr = shdr.sh_addr,
                .len = shdr.sh_size,
                .offset = shdr.sh_offset,
            };
        }
    }

    return result;
}

fn getCStrAt(bytes: []const u8, offset: u64) ?[]const u8 {
    if (offset >= bytes.len) return null;
    const tail = bytes[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
    return tail[0..end];
}
