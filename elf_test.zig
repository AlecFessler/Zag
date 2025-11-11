const std = @import("std");
const elf = std.elf;
const Dwarf = std.debug.Dwarf;

const Section = struct {
    vaddr: u64,
    len: u64,
    offset: u64,
};

const ParsedElf = struct {
    bytes: []u8,
    entry: u64,
    text: Section,
    rodata: Section,
    data: Section,
    bss: Section,
    dwarf: Dwarf,
};

/// This function expects the WHOLE FILE
fn parseElf(bytes: []u8) !ParsedElf {
    var result: ParsedElf = undefined;
    result.bytes = bytes;

    const hdr_sz = @sizeOf(elf.Elf64_Ehdr);
    var rd = std.Io.Reader.fixed(bytes[0..hdr_sz]);
    const elf_hdr = try elf.Header.read(&rd);

    result.entry = elf_hdr.entry;
    result.dwarf = .{
        .endian = elf_hdr.endian,
        .is_macho = false,
    };

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
        }

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

    return result;
}

fn getCStrAt(bytes: []const u8, offset: u64) ?[]const u8 {
    if (offset >= bytes.len) return null;
    const tail = bytes[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
    return tail[0..end];
}

/// This function simply needs to read the WHOLE FILE into a single buffer
fn readElf(allocator: std.mem.Allocator) ![]u8 {
    const f = try std.fs.cwd().openFile("kernel.elf", .{});
    defer f.close();

    return try f.readToEndAlloc(allocator, std.math.maxInt(u64));
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const bytes = try readElf(allocator);
    var result = try parseElf(bytes);

    try result.dwarf.open(allocator);

    const sym = try result.dwarf.getSymbol(allocator, 0xffffffff8002f588);
    if (sym.source_location) |sl| {
        std.debug.print("{s}:{} {}\n", .{ sl.file_name, sl.line, sl.column });
    }
}
