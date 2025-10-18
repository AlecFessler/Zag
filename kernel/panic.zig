const std = @import("std");
const x86 = @import("x86");

const builtin = std.builtin;
const cpu = x86.Cpu;
const vga = x86.Vga;

pub const PanicError = error{
    InvalidSymbolFile,
};

const MapEntry = struct {
    addr: u64,
    name: []const u8,
};

const SymbolMap = struct {
    alloc: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(MapEntry),

    pub fn init(alloc: std.mem.Allocator) SymbolMap {
        return .{
            .alloc = alloc,
            .entries = .{},
        };
    }

    pub fn deinit(self: *SymbolMap) void {
        self.entries.deinit(self.alloc);
    }

    pub fn add(
        self: *SymbolMap,
        addr: u64,
        name: []const u8,
    ) !void {
        const name_copy = try self.alloc.dupe(u8, name);
        try self.entries.append(
            self.alloc,
            .{
                .addr = addr,
                .name = name_copy,
            },
        );
    }

    fn find(
        self: *const SymbolMap,
        pc: u64,
    ) ?struct {
        name: []const u8,
        base: u64,
    } {
        const items = self.entries.items;
        if (items.len == 0) return null;

        var lo: u64 = 0;
        var hi: u64 = items.len;
        while (lo < hi) {
            const mid = (lo + hi) >> 1;
            if (items[mid].addr <= pc) lo = mid + 1 else hi = mid;
        }
        if (lo == 0) return null;
        const idx = lo - 1;
        return .{
            .name = items[idx].name,
            .base = items[idx].addr,
        };
    }
};

pub var g_symmap: ?SymbolMap = null;

pub fn initSymbolsFromSlice(
    map_bytes: []const u8,
    alloc: std.mem.Allocator,
) (std.mem.Allocator.Error || PanicError || std.fmt.ParseIntError)!void {
    var sm = SymbolMap.init(alloc);
    errdefer sm.deinit();

    var count: u64 = 0;
    var j: u64 = 0;
    while (j < map_bytes.len) : (j += 1) {
        if (map_bytes[j] == '\\' and j + 1 < map_bytes.len and map_bytes[j + 1] == 'n') {
            count += 1;
            j += 1;
        }
    }
    if (count == 0) return PanicError.InvalidSymbolFile;
    const buf = try alloc.alloc(MapEntry, count);
    sm.entries.items = buf[0..0];
    sm.entries.capacity = buf.len;

    const State = enum(u1) { addr, name };

    var state: State = .addr;
    var addr_buf: [32]u8 = undefined;
    var addr_len: u64 = 0;
    var name_start: u64 = 0;

    var i: u64 = 0;
    while (i < map_bytes.len) {
        const c = map_bytes[i];

        if (c == '\\' and i + 1 < map_bytes.len and map_bytes[i + 1] == 'n') {
            if (addr_len != 0 and state == .name and name_start < i) {
                const parsed_addr = try std.fmt.parseInt(u64, addr_buf[0..addr_len], 16);
                try sm.add(parsed_addr, map_bytes[name_start..i]);
            }
            addr_len = 0;
            name_start = 0;
            state = .addr;
            i += 2;
            continue;
        }

        if (c == ' ') {
            if (state == .addr and addr_len != 0) {
                state = .name;
                name_start = i + 1;
            }
            i += 1;
            continue;
        }

        if (state == .addr) {
            const lower = c | 0x20;
            const is_hex = (c >= '0' and c <= '9') or (lower >= 'a' and lower <= 'f');
            if (is_hex and addr_len < addr_buf.len) {
                addr_buf[addr_len] = c;
                addr_len += 1;
            }
        }

        i += 1;
    }

    if (addr_len != 0 and state == .name and name_start < map_bytes.len) {
        const parsed_addr = try std.fmt.parseInt(u64, addr_buf[0..addr_len], 16);
        try sm.add(parsed_addr, map_bytes[name_start..map_bytes.len]);
    }

    g_symmap = sm;
}

pub fn panic(
    msg: []const u8,
    trace: ?*builtin.StackTrace,
    ret_addr: ?u64,
) noreturn {
    @branchHint(.cold);
    _ = trace;
    vga.setColor(.White, .Blue);

    if (ret_addr) |ra| {
        vga.print("KERNEL PANIC: {s} (ret_addr {X})\n", .{ msg, ra });
        logAddr(ra);
    } else {
        vga.print("KERNEL PANIC: {s}\n", .{msg});
    }

    const first = @returnAddress();
    var last: u64 = 0;
    var it = std.debug.StackIterator.init(first, null);
    while (it.next()) |pc| {
        if (pc == 0 or pc == last) continue;
        logAddr(pc);
        last = pc;
    }

    cpu.halt();
}

fn logAddr(pc: u64) void {
    if (g_symmap) |sm| {
        if (sm.find(pc)) |hit| {
            const off = pc - hit.base;
            vga.print("{X}: {s}+0x{X}\n", .{ pc, hit.name, off });
            return;
        }
        vga.print("{X}: ?????\n", .{pc});
        return;
    }
    vga.print("{X}: (no symbols)\n", .{pc});
}
