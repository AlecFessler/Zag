const elf = @import("elf.zig");
const std = @import("std");

const Abbrev = struct {
    code: u64,
    tag_id: u64,
    has_children: bool,
    attrs: []Attr,

    const Attr = struct {
        id: u64,
        form_id: u64,
        payload: i64,
    };

    fn deinit(abbrev: *Abbrev, allocator: std.mem.Allocator) void {
        allocator.free(abbrev.attrs);
    }

    const Table = struct {
        offset: u64,
        abbrevs: []Abbrev,

        fn deinit(table: *Table, allocator: std.mem.Allocator) void {
            for (table.abbrevs) |*abbrev| {
                abbrev.deinit(allocator);
            }
            allocator.free(table.abbrevs);
        }

        fn get(table: *const Table, abbrev_code: u64) ?*const Abbrev {
            return for (table.abbrevs) |*abbrev| {
                if (abbrev.code == abbrev_code) break abbrev;
            } else null;
        }
    };
};

pub const CompileUnit = struct {
    version: u16,
    format: std.dwarf.Format,
    addr_size_bytes: u8,
    die: Die,
    pc_range: ?PcRange,

    str_offsets_base: u64,
    addr_base: u64,
    rnglists_base: u64,
    loclists_base: u64,
    frame_base: ?*const FormValue,

    src_loc_cache: ?SrcLocCache,

    pub const SrcLocCache = struct {
        line_table: LineTable,
        directories: []const FileEntry,
        files: []FileEntry,
        version: u16,

        pub const LineTable = std.AutoArrayHashMapUnmanaged(u64, LineEntry);

        pub const LineEntry = struct {
            line: u32,
            column: u32,
            file: u32,

            pub const invalid: LineEntry = .{
                .line = undefined,
                .column = undefined,
                .file = std.math.maxInt(u32),
            };

            pub fn isInvalid(le: LineEntry) bool {
                return le.file == invalid.file;
            }
        };

        pub fn findSource(slc: *const SrcLocCache, address: u64) !LineEntry {
            const index = std.sort.upperBound(u64, slc.line_table.keys(), address, struct {
                fn order(context: u64, item: u64) std.math.Order {
                    return std.math.order(context, item);
                }
            }.order);
            if (index == 0) return error.MissingDebugInfo;
            return slc.line_table.values()[index - 1];
        }
    };
};

const Die = struct {
    tag_id: u64,
    has_children: bool,
    attrs: []Attr,

    const Attr = struct {
        id: u64,
        value: FormValue,
    };

    fn deinit(self: *Die, allocator: std.mem.Allocator) void {
        allocator.free(self.attrs);
    }

    fn getAttr(self: *const Die, id: u64) ?*const FormValue {
        for (self.attrs) |*attr| {
            if (attr.id == id) return &attr.value;
        }
        return null;
    }

    fn getAttrAddr(
        self: *const Die,
        parsed_elf: elf.ParsedElf,
        id: u64,
        compile_unit: *const CompileUnit,
    ) !u64 {
        const form_value = self.getAttr(id) orelse return error.MissingDebugInfo;
        return switch (form_value.*) {
            .addr => |value| value,
            .addrx => |index| readDebugAddr(parsed_elf, compile_unit, index),
            else => error.MissingDebugInfo,
        };
    }
};

const FileEntry = struct {
    path: []const u8,
    dir_index: u32 = 0,
    mtime: u64 = 0,
    size: u64 = 0,
    md5: [16]u8 = [1]u8{0} ** 16,
};

const FormValue = union(enum) {
    addr: u64,
    addrx: u64,
    block: []const u8,
    udata: u64,
    data16: *const [16]u8,
    sdata: i64,
    exprloc: []const u8,
    flag: bool,
    sec_offset: u64,
    ref: u64,
    ref_addr: u64,
    string: [:0]const u8,
    strp: u64,
    strx: u64,
    line_strp: u64,
    loclistx: u64,
    rnglistx: u64,

    fn getString(parsed_elf: elf.ParsedElf, fv: FormValue) ?[:0]const u8 {
        switch (fv) {
            .string => |str| return str,
            .strp => |offset| return getSectionString(parsed_elf, parsed_elf.dbg_str.?, offset),
            .line_strp => |offset| return getSectionString(parsed_elf, parsed_elf.dbg_line_str.?, offset),
            else => return null,
        }
    }

    fn getUInt(fv: FormValue, comptime U: type) ?U {
        return switch (fv) {
            inline .udata,
            .sdata,
            .sec_offset,
            => |c| std.math.cast(U, c),
            else => return null,
        };
    }
};

const PcRange = struct {
    start: u64,
    end: u64,
};

const UnitHeader = struct {
    format: std.dwarf.Format,
    header_len: u4,
    unit_len: u64,
};

var abbrev_table_list: std.ArrayList(Abbrev.Table) = .empty;
var compile_unit_list: std.ArrayList(CompileUnit) = .empty;

fn readDebugAddr(
    parsed_elf: elf.ParsedElf,
    compile_unit: *const CompileUnit,
    index: u64,
) !u64 {
    const debug_addr_start = parsed_elf.dbg_addr.?.offset;
    const debug_addr_end = debug_addr_start + parsed_elf.dbg_addr.?.len;
    const debug_addr = parsed_elf.bytes[debug_addr_start..debug_addr_end];

    if (compile_unit.addr_base < 8) return error.ParseFailure;

    const version = std.mem.readInt(u16, debug_addr[compile_unit.addr_base - 4 ..][0..2], parsed_elf.endian);
    if (version != 5) return error.ParseFailure;

    const addr_size = debug_addr[compile_unit.addr_base - 2];
    const seg_size = debug_addr[compile_unit.addr_base - 1];

    const byte_offset = compile_unit.addr_base + (addr_size + seg_size) * index;
    if (byte_offset + addr_size > debug_addr.len) return error.ParseFailure;
    return switch (addr_size) {
        1 => debug_addr[@intCast(byte_offset)],
        2 => std.mem.readInt(u16, debug_addr[@intCast(byte_offset)..][0..2], parsed_elf.endian),
        4 => std.mem.readInt(u32, debug_addr[@intCast(byte_offset)..][0..4], parsed_elf.endian),
        8 => std.mem.readInt(u64, debug_addr[@intCast(byte_offset)..][0..8], parsed_elf.endian),
        else => error.ParseFailure,
    };
}

fn parseCompileUnits(parsed_elf: elf.ParsedElf, allocator: std.mem.Allocator) !void {
    const dbg_info_start = parsed_elf.dbg_info.?.offset;
    const dbg_info_end = dbg_info_start + parsed_elf.dbg_info.?.len;
    const dbg_info = parsed_elf.bytes[dbg_info_start..dbg_info_end];
    var r: std.Io.Reader = .fixed(dbg_info);

    var attrs_buf = std.array_list.Managed(Die.Attr).init(allocator);
    defer attrs_buf.deinit();

    var current_offset: u64 = 0;
    while (current_offset < r.buffer.len) {
        r.seek = @intCast(current_offset);
        const unit_len = try r.takeInt(u32, parsed_elf.endian);
        const unit_header: UnitHeader = switch (unit_len) {
            0...0xfffffff0 - 1 => .{
                .format = .@"32",
                .header_len = 4,
                .unit_len = unit_len,
            },
            0xfffffff0...0xffffffff - 1 => return error.ParseFailure,
            0xffffffff => .{
                .format = .@"64",
                .header_len = 12,
                .unit_len = try r.takeInt(u64, parsed_elf.endian),
            },
        };

        std.debug.print("Format {s} header len {} unit len {}\n", .{
            @tagName(unit_header.format),
            unit_header.header_len,
            unit_header.unit_len,
        });

        const version = try r.takeInt(u16, parsed_elf.endian);
        if (2 > version or 5 < version) return error.ParseFailure;

        var address_size: u8 = undefined;
        var debug_abbrev_offset: u64 = undefined;
        if (version >= 5) {
            const unit_type = try r.takeByte();
            if (unit_type != std.dwarf.UT.compile) return error.ParseFailure;
            address_size = try r.takeByte();
            debug_abbrev_offset = switch (unit_header.format) {
                .@"32" => try r.takeInt(u32, parsed_elf.endian),
                .@"64" => try r.takeInt(u64, parsed_elf.endian),
            };
        } else {
            debug_abbrev_offset = switch (unit_header.format) {
                .@"32" => try r.takeInt(u32, parsed_elf.endian),
                .@"64" => try r.takeInt(u64, parsed_elf.endian),
            };
            address_size = try r.takeByte();
        }

        const abbrev_table = try getAbbrevTable(parsed_elf, debug_abbrev_offset, allocator);

        var max_attrs: u64 = 0;
        for (abbrev_table.abbrevs) |abbrev| {
            max_attrs = @max(max_attrs, abbrev.attrs.len);
        }
        try attrs_buf.resize(max_attrs);

        var compile_unit_die = (try parseDie(
            parsed_elf,
            &r,
            attrs_buf.items,
            abbrev_table,
            unit_header.format,
            address_size,
        )) orelse return error.ParseFailure;

        if (compile_unit_die.tag_id != std.dwarf.TAG.compile_unit) return error.ParseFailure;

        compile_unit_die.attrs = try allocator.dupe(Die.Attr, compile_unit_die.attrs);

        var compile_unit: CompileUnit = .{
            .version = version,
            .format = unit_header.format,
            .addr_size_bytes = address_size,
            .pc_range = null,
            .die = compile_unit_die,
            .str_offsets_base = if (compile_unit_die.getAttr(std.dwarf.AT.str_offsets_base)) |fv| fv.getUInt(u64) orelse 0 else 0,
            .addr_base = if (compile_unit_die.getAttr(std.dwarf.AT.addr_base)) |fv| fv.getUInt(u64) orelse 0 else 0,
            .rnglists_base = if (compile_unit_die.getAttr(std.dwarf.AT.rnglists_base)) |fv| fv.getUInt(u64) orelse 0 else 0,
            .loclists_base = if (compile_unit_die.getAttr(std.dwarf.AT.loclists_base)) |fv| fv.getUInt(u64) orelse 0 else 0,
            .frame_base = compile_unit_die.getAttr(std.dwarf.AT.frame_base),
            .src_loc_cache = null,
        };

        compile_unit.pc_range = blk: {
            if (compile_unit_die.getAttrAddr(parsed_elf, std.dwarf.AT.low_pc, &compile_unit)) |low_pc| {
                if (compile_unit_die.getAttr(std.dwarf.AT.high_pc)) |high_pc_value| {
                    const pc_end = switch (high_pc_value.*) {
                        .addr => |value| value,
                        .udata => |offset| low_pc + offset,
                        else => return error.ParseFailure,
                    };
                    break :blk PcRange{
                        .start = low_pc,
                        .end = pc_end,
                    };
                } else {
                    break :blk null;
                }
            } else |err| {
                if (err != error.MissingDebugInfo) return err;
                break :blk null;
            }
        };

        try compile_unit_list.append(allocator, compile_unit);

        current_offset += unit_header.header_len + unit_header.unit_len;
    }
}

fn parseDie(
    parsed_elf: elf.ParsedElf,
    r: *std.Io.Reader,
    attrs_buf: []Die.Attr,
    abbrev_table: *const Abbrev.Table,
    format: std.dwarf.Format,
    addr_size_bytes: u8,
) !?Die {
    const abbrev_code = try r.takeLeb128(u64);
    if (abbrev_code == 0) return null;
    const table_entry = abbrev_table.get(abbrev_code) orelse return error.ParseFailure;

    const attrs = attrs_buf[0..table_entry.attrs.len];
    for (attrs, table_entry.attrs) |*result_attr, attr| result_attr.* = .{
        .id = attr.id,
        .value = try parseFormValue(
            r,
            attr.form_id,
            format,
            parsed_elf.endian,
            addr_size_bytes,
            attr.payload,
        ),
    };

    return .{
        .tag_id = table_entry.tag_id,
        .has_children = table_entry.has_children,
        .attrs = attrs,
    };
}

fn parseFormValue(
    r: *std.Io.Reader,
    form_id: u64,
    format: std.dwarf.Format,
    endian: std.builtin.Endian,
    addr_size_bytes: u8,
    implicit_const: ?i64,
) !FormValue {
    return switch (form_id) {
        std.dwarf.FORM.addr => .{ .addr = try readAddress(r, endian, addr_size_bytes) },
        std.dwarf.FORM.addrx1 => .{ .addrx = try r.takeByte() },
        std.dwarf.FORM.addrx2 => .{ .addrx = try r.takeInt(u16, endian) },
        std.dwarf.FORM.addrx3 => .{ .addrx = try r.takeInt(u24, endian) },
        std.dwarf.FORM.addrx4 => .{ .addrx = try r.takeInt(u32, endian) },
        std.dwarf.FORM.addrx => .{ .addrx = try r.takeLeb128(u64) },

        std.dwarf.FORM.block1 => .{ .block = try r.take(try r.takeByte()) },
        std.dwarf.FORM.block2 => .{ .block = try r.take(try r.takeInt(u16, endian)) },
        std.dwarf.FORM.block4 => .{ .block = try r.take(try r.takeInt(u32, endian)) },
        std.dwarf.FORM.block => .{ .block = try r.take(try r.takeLeb128(u64)) },

        std.dwarf.FORM.data1 => .{ .udata = try r.takeByte() },
        std.dwarf.FORM.data2 => .{ .udata = try r.takeInt(u16, endian) },
        std.dwarf.FORM.data4 => .{ .udata = try r.takeInt(u32, endian) },
        std.dwarf.FORM.data8 => .{ .udata = try r.takeInt(u64, endian) },
        std.dwarf.FORM.data16 => .{ .data16 = try r.takeArray(16) },
        std.dwarf.FORM.udata => .{ .udata = try r.takeLeb128(u64) },
        std.dwarf.FORM.sdata => .{ .sdata = try r.takeLeb128(i64) },
        std.dwarf.FORM.exprloc => .{ .exprloc = try r.take(try r.takeLeb128(u64)) },
        std.dwarf.FORM.flag => .{ .flag = (try r.takeByte()) != 0 },
        std.dwarf.FORM.flag_present => .{ .flag = true },
        std.dwarf.FORM.sec_offset => .{ .sec_offset = try readFormatSizedInt(r, format, endian) },

        std.dwarf.FORM.ref1 => .{ .ref = try r.takeByte() },
        std.dwarf.FORM.ref2 => .{ .ref = try r.takeInt(u16, endian) },
        std.dwarf.FORM.ref4 => .{ .ref = try r.takeInt(u32, endian) },
        std.dwarf.FORM.ref8 => .{ .ref = try r.takeInt(u64, endian) },
        std.dwarf.FORM.ref_udata => .{ .ref = try r.takeLeb128(u64) },

        std.dwarf.FORM.ref_addr => .{ .ref_addr = try readFormatSizedInt(r, format, endian) },
        std.dwarf.FORM.ref_sig8 => .{ .ref = try r.takeInt(u64, endian) },

        std.dwarf.FORM.string => .{ .string = try r.takeSentinel(0) },
        std.dwarf.FORM.strp => .{ .strp = try readFormatSizedInt(r, format, endian) },
        std.dwarf.FORM.strx1 => .{ .strx = try r.takeByte() },
        std.dwarf.FORM.strx2 => .{ .strx = try r.takeInt(u16, endian) },
        std.dwarf.FORM.strx3 => .{ .strx = try r.takeInt(u24, endian) },
        std.dwarf.FORM.strx4 => .{ .strx = try r.takeInt(u32, endian) },
        std.dwarf.FORM.strx => .{ .strx = try r.takeLeb128(u64) },
        std.dwarf.FORM.line_strp => .{ .line_strp = try readFormatSizedInt(r, format, endian) },
        std.dwarf.FORM.indirect => parseFormValue(
            r,
            try r.takeLeb128(u64),
            format,
            endian,
            addr_size_bytes,
            implicit_const,
        ),
        std.dwarf.FORM.implicit_const => .{ .sdata = implicit_const orelse return error.ParseFailure },
        std.dwarf.FORM.loclistx => .{ .loclistx = try r.takeLeb128(u64) },
        std.dwarf.FORM.rnglistx => .{ .rnglistx = try r.takeLeb128(u64) },
        else => {
            return error.ParseFailure;
        },
    };
}

fn readFormatSizedInt(
    r: *std.Io.Reader,
    format: std.dwarf.Format,
    endian: std.builtin.Endian,
) !u64 {
    return switch (format) {
        .@"32" => try r.takeInt(u32, endian),
        .@"64" => try r.takeInt(u64, endian),
    };
}

fn readAddress(
    r: *std.Io.Reader,
    endian: std.builtin.Endian,
    addr_size_bytes: u8,
) !u64 {
    return switch (addr_size_bytes) {
        2 => try r.takeInt(u16, endian),
        4 => try r.takeInt(u32, endian),
        8 => try r.takeInt(u64, endian),
        else => return error.ParseFailure,
    };
}

fn getAbbrevTable(parsed_elf: elf.ParsedElf, offset: u64, allocator: std.mem.Allocator) !*const Abbrev.Table {
    for (abbrev_table_list.items) |*table| {
        if (table.offset == offset) return table;
    }
    const table = try parseAbbrevTable(parsed_elf, offset, allocator);
    try abbrev_table_list.append(allocator, table);
    return &abbrev_table_list.items[abbrev_table_list.items.len - 1];
}

fn parseAbbrevTable(parsed_elf: elf.ParsedElf, offset: u64, allocator: std.mem.Allocator) !Abbrev.Table {
    const dbg_abbrev_start = parsed_elf.dbg_abbrev.?.offset;
    const dbg_abbrev_end = dbg_abbrev_start + parsed_elf.dbg_abbrev.?.len;
    const dbg_abbrev = parsed_elf.bytes[dbg_abbrev_start..dbg_abbrev_end];
    var r: std.Io.Reader = .fixed(dbg_abbrev);

    r.seek = @intCast(offset);

    var abbrevs = std.array_list.Managed(Abbrev).init(allocator);
    defer {
        for (abbrevs.items) |*abbrev| {
            abbrev.deinit(allocator);
        }
        abbrevs.deinit();
    }

    var attrs = std.array_list.Managed(Abbrev.Attr).init(allocator);
    defer attrs.deinit();

    while (true) {
        const code = try r.takeLeb128(u64);
        if (code == 0) break;
        const tag_id = try r.takeLeb128(u64);
        const has_children = (try r.takeByte()) == std.dwarf.CHILDREN.yes;

        while (true) {
            const attr_id = try r.takeLeb128(u64);
            const form_id = try r.takeLeb128(u64);
            if (attr_id == 0 and form_id == 0) break;
            try attrs.append(.{
                .id = attr_id,
                .form_id = form_id,
                .payload = switch (form_id) {
                    std.dwarf.FORM.implicit_const => try r.takeLeb128(i64),
                    else => undefined,
                },
            });
        }

        try abbrevs.append(.{
            .code = code,
            .tag_id = tag_id,
            .has_children = has_children,
            .attrs = try attrs.toOwnedSlice(),
        });
    }

    return .{
        .offset = offset,
        .abbrevs = try abbrevs.toOwnedSlice(),
    };
}

fn getSectionString(parsed_elf: elf.ParsedElf, section: elf.Section, offset: u64) ?[:0]const u8 {
    const strs: []u8 = parsed_elf.bytes[section.offset .. section.offset + section.len];
    if (offset > strs.len) return null;
    const tail = strs[offset..];
    const last = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
    return strs[offset..last :0];
}

pub fn parseDwarf(parsed_elf: elf.ParsedElf, allocator: std.mem.Allocator) !void {
    if (parsed_elf.dbg_info == null) return error.NoDbgInfo;
    if (parsed_elf.dbg_abbrev == null) return error.NoDbgAbbrev;
    if (parsed_elf.dbg_str == null) return error.NoDbgStr;
    if (parsed_elf.dbg_str_offsets == null) return error.NoDbgStrOffsets;
    if (parsed_elf.dbg_line == null) return error.NoDbgLine;
    if (parsed_elf.dbg_line_str == null) return error.NoDbgLineStr;
    if (parsed_elf.dbg_ranges == null) return error.NoDbgRanges;
    if (parsed_elf.dbg_loclists == null) return error.NoDbgLoclists;
    if (parsed_elf.dbg_rnglists == null) return error.NoDbgRnglists;
    if (parsed_elf.dbg_addr == null) return error.NoDbgAddr;
    if (parsed_elf.dbg_names == null) return error.NoDbgNames;
    if (parsed_elf.dbg_eh_frame == null) return error.NoDbgEhFrame;
    if (parsed_elf.dbg_eh_frame_hdr == null) return error.NoDbgEhFrameHdr;

    try parseCompileUnits(parsed_elf, allocator);

    for (compile_unit_list.items) |*cu| {
        std.debug.print(
            "addr_base=0x{X}\naddr_size={}\nformat={s}\nloclists=0x{X}\nrnglists=0x{X}\nstr_offsets=0x{X}\nversion={}\n",
            .{
                cu.addr_base,
                cu.addr_size_bytes,
                @tagName(cu.format),
                cu.loclists_base,
                cu.rnglists_base,
                cu.str_offsets_base,
                cu.version,
            },
        );
    }
}
