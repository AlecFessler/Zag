//! Symbol map and kernel panic utilities.
//!
//! Provides a compact, binary-searchable symbol table for address→name lookups
//! during faults/panics, and a minimal panic routine that prints a backtrace
//! over serial before halting the CPU.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `PanicError` — error set for symbol-map loading failures.
//! - `MapEntry` — one `(addr, name)` pair used by the symbol map.
//! - `SymbolMap` — compact symbol table with binary search and append API.
//!
//! ## Constants
//! - `VAddr` — typed virtual-address alias exposed by paging.
//!
//! ## Variables
//! - `g_symmap` — optional process-wide symbol map used by panic/log helpers.
//!
//! ## Functions
//! - `SymbolMap.init` — construct an empty map with a specified allocator.
//! - `SymbolMap.deinit` — free entry storage and name copies.
//! - `SymbolMap.add` — append `(addr, name)`; duplicates name into the map.
//! - `SymbolMap.find` — binary-search for rightmost base `<= pc` (private).
//! - `initSymbolsFromSlice` — parse serialized map bytes into `g_symmap`.
//! - `panic` — print message and backtrace; halt (noreturn).
//! - `logAddr` — print a single PC with symbolization if available (private).

const std = @import("std");
const zag = @import("zag.zig");

const builtin = std.builtin;
const cpu = zag.x86.Cpu;
const serial = zag.x86.Serial;

/// Error set for symbol-map loading/validation.
pub const PanicError = error{
    InvalidSymbolFile,
};

/// One `(addr, name)` pair within the symbol map.
const MapEntry = struct {
    addr: u64,
    name: []const u8,
};

/// Compact symbol table supporting binary search by program counter.
const SymbolMap = struct {
    alloc: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(MapEntry),

    /// Summary:
    /// Construct an empty `SymbolMap` that uses `alloc`.
    ///
    /// Arguments:
    /// - `alloc`: allocator that will own entry storage and name copies.
    ///
    /// Returns:
    /// - New empty `SymbolMap`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn init(alloc: std.mem.Allocator) SymbolMap {
        return .{
            .alloc = alloc,
            .entries = .{},
        };
    }

    /// Summary:
    /// Release backing storage and all duplicated names.
    ///
    /// Arguments:
    /// - `self`: map to deinitialize.
    ///
    /// Returns:
    /// - `void`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn deinit(self: *SymbolMap) void {
        self.entries.deinit(self.alloc);
    }

    /// Summary:
    /// Insert a `(addr, name)` pair; duplicates `name` into `self.alloc`.
    ///
    /// Arguments:
    /// - `self`: target symbol map.
    /// - `addr`: base program counter of the symbol.
    /// - `name`: UTF-8 symbol name to copy into the map.
    ///
    /// Returns:
    /// - `void`.
    ///
    /// Errors:
    /// - `std.mem.Allocator.Error` on allocation/dupe/append failure.
    ///
    /// Panics:
    /// - None.
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

    /// Summary:
    /// Find the symbol whose base address is the rightmost value `<= pc`.
    ///
    /// Arguments:
    /// - `self`: map to query (read-only).
    /// - `pc`: program counter to resolve.
    ///
    /// Returns:
    /// - `?{ name: []const u8, base: u64 }` — `null` if no base `<= pc`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
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

/// Typed virtual-address alias from the paging module.
const VAddr = zag.x86.Paging.VAddr;

/// Optional global symbol map used for backtrace symbolization.
pub var g_symmap: ?SymbolMap = null;

/// Summary:
/// Initialize the global symbol map from a serialized byte slice.
///
/// Arguments:
/// - `map_bytes`: UTF-8 bytes of the serialized symbol map; each line encoded
///   as `HEX_ADDR SP NAME \ n` (backslash + `n` two-byte sequence).
/// - `alloc`: allocator used to store entries and duplicated names.
///
/// Returns:
/// - `void` (on success `g_symmap` is populated).
///
/// Errors:
/// - `PanicError.InvalidSymbolFile` if no entries are found.
/// - `std.mem.Allocator.Error` on allocation failures.
/// - `std.fmt.ParseIntError` if an address field is not valid hex.
///
/// Panics:
/// - None.
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

/// Summary:
/// Kernel panic handler: print message and backtrace, then halt the CPU.
///
/// Arguments:
/// - `msg`: panic message to display.
/// - `trace`: optional Zig return-trace (unused; backtrace gathered manually).
/// - `ret_addr`: optional return address for additional context.
///
/// Returns:
/// - Never returns (`noreturn`).
///
/// Errors:
/// - None.
///
/// Panics:
/// - None (function halts the CPU).
pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    @branchHint(.cold);
    _ = trace;

    if (ret_addr) |ra| {
        serial.print("KERNEL PANIC: {s} (ret_addr {X})\n", .{ msg, ra });
        logAddr(ra);
    } else {
        serial.print("KERNEL PANIC: {s}\n", .{msg});
    }

    const first = @returnAddress();
    var it = std.debug.StackIterator.init(first, null);
    var last_pc: u64 = 0;
    var frames: u64 = 0;

    while (frames < 64) : (frames += 1) {
        const pc = it.next() orelse break;
        if (pc == 0) break;
        logAddr(pc);
        last_pc = pc;
    }

    cpu.halt();
}

/// Summary:
/// Log a single program counter with symbolization if available.
///
/// Arguments:
/// - `pc`: program counter to log.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn logAddr(pc: u64) void {
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
