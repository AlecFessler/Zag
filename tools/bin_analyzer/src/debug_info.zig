const std = @import("std");

const Allocator = std.mem.Allocator;
const Dwarf = std.debug.Dwarf;
const elf = std.elf;

pub const SourceKey = struct {
    file_idx: u32,
    line: u32,
};

pub const DisasmIdxList = std.ArrayList(usize);

pub fn loadDwarf(gpa: Allocator, path: []const u8) !Dwarf {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const bytes = try file.readToEndAlloc(gpa, std.math.maxInt(u32));

    const hdr_sz = @sizeOf(elf.Elf64_Ehdr);
    if (bytes.len < hdr_sz) return error.InvalidElfFile;

    var rd = std.Io.Reader.fixed(bytes[0..hdr_sz]);
    const elf_hdr = try elf.Header.read(&rd);

    var dwarf: Dwarf = .{
        .endian = elf_hdr.endian,
        .is_macho = false,
    };

    const shdrs = std.mem.bytesAsSlice(
        elf.Elf64_Shdr,
        bytes[elf_hdr.shoff .. elf_hdr.shoff + elf_hdr.shentsize * elf_hdr.shnum],
    );
    const shstr_shdr = shdrs[elf_hdr.shstrndx];
    const shstr = bytes[shstr_shdr.sh_offset .. shstr_shdr.sh_offset + shstr_shdr.sh_size];

    var shdr_itr = elf_hdr.iterateSectionHeadersBuffer(bytes);
    while (try shdr_itr.next()) |shdr| {
        const name = getCStrAt(shstr, @intCast(shdr.sh_name)) orelse continue;
        const dwarf_idx: ?usize = if (std.mem.eql(u8, name, ".debug_info"))
            @intFromEnum(Dwarf.Section.Id.debug_info)
        else if (std.mem.eql(u8, name, ".debug_abbrev"))
            @intFromEnum(Dwarf.Section.Id.debug_abbrev)
        else if (std.mem.eql(u8, name, ".debug_str"))
            @intFromEnum(Dwarf.Section.Id.debug_str)
        else if (std.mem.eql(u8, name, ".debug_str_offsets"))
            @intFromEnum(Dwarf.Section.Id.debug_str_offsets)
        else if (std.mem.eql(u8, name, ".debug_line"))
            @intFromEnum(Dwarf.Section.Id.debug_line)
        else if (std.mem.eql(u8, name, ".debug_line_str"))
            @intFromEnum(Dwarf.Section.Id.debug_line_str)
        else if (std.mem.eql(u8, name, ".debug_ranges"))
            @intFromEnum(Dwarf.Section.Id.debug_ranges)
        else if (std.mem.eql(u8, name, ".debug_loclists"))
            @intFromEnum(Dwarf.Section.Id.debug_loclists)
        else if (std.mem.eql(u8, name, ".debug_rnglists"))
            @intFromEnum(Dwarf.Section.Id.debug_rnglists)
        else if (std.mem.eql(u8, name, ".debug_addr"))
            @intFromEnum(Dwarf.Section.Id.debug_addr)
        else if (std.mem.eql(u8, name, ".debug_names"))
            @intFromEnum(Dwarf.Section.Id.debug_names)
        else if (std.mem.eql(u8, name, ".eh_frame"))
            @intFromEnum(Dwarf.Section.Id.eh_frame)
        else if (std.mem.eql(u8, name, ".eh_frame_hdr"))
            @intFromEnum(Dwarf.Section.Id.eh_frame_hdr)
        else
            null;

        if (dwarf_idx) |i| {
            dwarf.sections[i] = .{
                .data = bytes[shdr.sh_offset .. shdr.sh_offset + shdr.sh_size],
                .owned = false,
            };
        }
    }

    try dwarf.open(gpa);
    return dwarf;
}

pub fn buildReverseMap(
    gpa: Allocator,
    dwarf: *Dwarf,
    addr_to_disasm: *std.AutoHashMap(u64, usize),
    file_paths: *std.ArrayList([]const u8),
    reverse_map: *std.AutoHashMap(SourceKey, DisasmIdxList),
) !void {
    for (dwarf.compile_unit_list.items) |*cu| {
        dwarf.populateSrcLocCache(gpa, cu) catch continue;
        const slc = &(cu.src_loc_cache orelse continue);

        const keys = slc.line_table.keys();
        const values = slc.line_table.values();

        for (keys, values) |pc, entry| {
            if (entry.isInvalid()) continue;

            const file_index = entry.file -| @intFromBool(slc.version < 5);
            if (file_index >= slc.files.len) continue;
            const file_entry = &slc.files[file_index];
            if (file_entry.dir_index >= slc.directories.len) continue;
            const dir_name = slc.directories[file_entry.dir_index].path;
            const full_path = std.fs.path.join(gpa, &.{ dir_name, file_entry.path }) catch continue;

            const file_idx = findOrAddPath(gpa, file_paths, full_path);

            const disasm_idx = addr_to_disasm.get(pc) orelse continue;

            const key = SourceKey{ .file_idx = file_idx, .line = entry.line };
            const gop = reverse_map.getOrPut(key) catch continue;
            if (!gop.found_existing) {
                gop.value_ptr.* = .empty;
            }
            gop.value_ptr.append(gpa, disasm_idx) catch {};
        }
    }
}

pub fn loadSourceFile(gpa: Allocator, path: []const u8) ?[][]const u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    const content = file.readToEndAlloc(gpa, std.math.maxInt(u32)) catch return null;

    var lines_list: std.ArrayList([]const u8) = .empty;
    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |line| {
        lines_list.append(gpa, line) catch return null;
    }
    return lines_list.toOwnedSlice(gpa) catch null;
}

pub fn resolveFileIdx(
    file_paths: *std.ArrayList([]const u8),
    file: []const u8,
) ?u32 {
    for (file_paths.items, 0..) |path, i| {
        if (std.mem.eql(u8, path, file)) return @intCast(i);
    }
    const basename = std.fs.path.basename(file);
    for (file_paths.items, 0..) |path, i| {
        if (std.mem.endsWith(u8, path, basename)) return @intCast(i);
    }
    return null;
}

fn findOrAddPath(gpa: Allocator, file_paths: *std.ArrayList([]const u8), full_path: []const u8) u32 {
    for (file_paths.items, 0..) |existing, i| {
        if (std.mem.eql(u8, existing, full_path)) return @intCast(i);
    }
    const idx: u32 = @intCast(file_paths.items.len);
    file_paths.append(gpa, full_path) catch return idx;
    return idx;
}

fn getCStrAt(bytes: []const u8, offset: u64) ?[]const u8 {
    if (offset >= bytes.len) return null;
    const tail = bytes[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
    return tail[0..end];
}
