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
    text: Section,
    rodata: Section,
    data: Section,
    bss: Section,
    stack: Section,
};

pub fn parseElf(bytes: []u8) !ParsedElf {
    var result: ParsedElf = undefined;
    result.bytes = bytes;

    const hdr_sz = @sizeOf(elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(bytes[0..hdr_sz]);
    const elf_hdr = try elf.Header.read(&rd);

    result.entry = elf_hdr.entry;

    var shdr_itr = elf_hdr.iterateSectionHeadersBuffer(bytes);

    const shdrs = std.mem.bytesAsSlice(
        elf.Elf64_Shdr,
        bytes[elf_hdr.shoff .. elf_hdr.shoff + elf_hdr.shentsize * elf_hdr.shnum],
    );

    const shstr_shdr = shdrs[elf_hdr.shstrndx];
    const shstr_end = shstr_shdr.sh_offset + shstr_shdr.sh_size;
    const shstr = bytes[shstr_shdr.sh_offset..shstr_end];

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
        } else if (std.mem.eql(u8, name, "__stack")) {
            result.stack = .{
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
