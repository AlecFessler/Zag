//! Symbol map and kernel panic utilities.
//!
//! Provides a compact symbol table for address-to-name lookups during panics
//! and a minimal panic routine that prints a backtrace via serial.

const std = @import("std");
const zag = @import("zag.zig");

const builtin = std.builtin;
const cpu = zag.x86.Cpu;
const serial = zag.x86.Serial;

/// Errors emitted by the symbol utilities.
pub const PanicError = error{
    /// The provided symbol file/slice is malformed or empty.
    InvalidSymbolFile,
};

/// A single symbol map entry (address base and name).
const MapEntry = struct {
    /// Base program counter of the symbol.
    addr: u64,
    /// Symbol name bytes (duped into the map’s allocator).
    name: []const u8,
};

/// Compact symbol map supporting binary search by program counter.
///
/// Invariants:
/// - `entries.items` are kept sorted by `addr` ascending.
/// - Names are allocator-owned copies and freed in `deinit`.
const SymbolMap = struct {
    /// Allocator owning `entries` and name copies.
    alloc: std.mem.Allocator,
    /// Sorted storage of `(addr,name)` pairs.
    entries: std.ArrayListUnmanaged(MapEntry),

    /// Creates an empty symbol map using `alloc`.
    ///
    /// Arguments:
    /// - `alloc`: allocator that will own the entries array and name copies.
    ///
    /// Returns:
    /// - New empty `SymbolMap`.
    pub fn init(alloc: std.mem.Allocator) SymbolMap {
        return .{
            .alloc = alloc,
            .entries = .{},
        };
    }

    /// Releases backing storage and name copies.
    ///
    /// Arguments:
    /// - `self`: map to deinitialize.
    pub fn deinit(self: *SymbolMap) void {
        self.entries.deinit(self.alloc);
    }

    /// Inserts a `(addr, name)` pair; duplicates `name` into `alloc`.
    ///
    /// Arguments:
    /// - `self`: target symbol map.
    /// - `addr`: base program counter of the symbol.
    /// - `name`: UTF-8 symbol name to copy into the map.
    ///
    /// Errors:
    /// - `std.mem.Allocator.Error` on allocation/dupe/append failure.
    ///
    /// Notes:
    /// - For best performance, insert in non-decreasing `addr` order;
    ///   otherwise bulk-load then sort once before queries.
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

    /// Finds the symbol whose base address is the rightmost `<= pc`.
    ///
    /// Arguments:
    /// - `self`: map to query (read-only).
    /// - `pc`: program counter to resolve.
    ///
    /// Returns:
    /// - `{ name, base }` on success; `null` if no symbol base is `<= pc`.
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

/// Global symbol map used by `panic`/`logAddr` for backtraces.
pub var g_symmap: ?SymbolMap = null;

/// Parses a simple `addr<space>name\n` symbol list and installs `g_symmap`.
///
/// Arguments:
/// - `map_bytes`: symbol list where each entry is `<hex-addr><space><name>\n`,
///   with newline encoded as the two-byte sequence `\`n`.
/// - `alloc`: allocator used for `SymbolMap` entries and name copies.
///
/// Errors:
/// - `PanicError.InvalidSymbolFile` if the slice has zero entries or a malformed line.
/// - `std.mem.Allocator.Error` on allocation failure.
/// - `std.fmt.ParseIntError` if any address fails to parse as hex.
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

    const State = enum(u1) {
        addr,
        name,
    };

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

/// Prints a kernel panic message and a best-effort backtrace, then halts.
///
/// Arguments:
/// - `msg`: description of the failure.
/// - `trace`: optional Zig stack trace (unused in this variant).
/// - `ret_addr`: optional return address to highlight in the log.
///
/// Returns:
/// - Never returns (`noreturn`).
pub fn panic(
    msg: []const u8,
    trace: ?*builtin.StackTrace,
    ret_addr: ?u64,
) noreturn {
    @branchHint(.cold);
    _ = trace;

    if (ret_addr) |ra| {
        serial.print("KERNEL PANIC: {s} (ret_addr {X})\n", .{ msg, ra });
        logAddr(ra);
    } else {
        serial.print("KERNEL PANIC: {s}\n", .{msg});
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

/// Logs `pc` with symbol+offset if available; otherwise prints a placeholder.
///
/// Arguments:
/// - `pc`: program counter to resolve and print.
fn logAddr(pc: u64) void {
    if (g_symmap) |sm| {
        if (sm.find(pc)) |hit| {
            const off = pc - hit.base;
            serial.print("{X}: {s}+0x{X}\n", .{ pc, hit.name, off });
            return;
        }
        serial.print("{X}: ?????\n", .{pc});
        return;
    }
    serial.print("{X}: (no symbols)\n", .{pc});
}
