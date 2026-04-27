//! On-disk cache for the parsed call graph + indexes.
//!
//! Layer 2 of the daemon's incremental story:
//!   - Layer 1: Zig's own build cache; only re-emits `kernel.<arch>.ll`
//!     when kernel sources change. Owned by `zig build`.
//!   - Layer 2 (this module): when the IR file is byte-for-byte
//!     identical to what produced a previous Graph, skip re-parsing the
//!     IR + walking the AST + running the join/reach passes; instead
//!     rehydrate the previously-serialized Graph from disk.
//!
//! Format: a small custom binary, one file per arch under
//! `$XDG_CACHE_HOME/callgraph/<arch>.<ir_hash>.cgcache`.
//!
//!   header
//!     magic[8]        = "CGCACHE\0"
//!     version         u32  (bump when the layout changes)
//!     ir_hash         u64  (xxhash3 of the IR file bytes)
//!     ast_hash        u64  (combined hash of relevant AST inputs)
//!     arch_tag        length-prefixed UTF-8
//!
//!   body
//!     graph payload — see writeGraph / readGraph below for the
//!     exact field-by-field layout. Strings are length-prefixed
//!     bytes copied into a single arena on load; we don't bother
//!     deduplicating because the file size is small enough that
//!     the simpler layout pays for itself.
//!
//!   footer
//!     body_checksum   u64  (fnv1a-64 over the body region)
//!     trailing magic  "CGCACHEEND"
//!
//! Any read error (truncation, magic mismatch, version mismatch,
//! checksum mismatch) returns null so the daemon can fall back to a
//! full build.

const std = @import("std");

const types = @import("types.zig");

const Atom = types.Atom;
const ArmSeq = types.ArmSeq;
const BranchAtom = types.BranchAtom;
const BranchKind = types.BranchKind;
const Callee = types.Callee;
const Definition = types.Definition;
const DefId = types.DefId;
const DefKind = types.DefKind;
const EdgeKind = types.EdgeKind;
const EnrichedEdge = types.EnrichedEdge;
const EntryKind = types.EntryKind;
const EntryPoint = types.EntryPoint;
const FnId = types.FnId;
const Function = types.Function;
const Graph = types.Graph;
const LoopAtom = types.LoopAtom;
const SourceLoc = types.SourceLoc;

pub const MAGIC: [8]u8 = .{ 'C', 'G', 'C', 'A', 'C', 'H', 'E', 0 };
pub const TRAILER: [10]u8 = .{ 'C', 'G', 'C', 'A', 'C', 'H', 'E', 'E', 'N', 'D' };
pub const FORMAT_VERSION: u32 = 2;

/// Path inputs the cache key is computed from.
pub const KeyInputs = struct {
    /// Hash of the IR file's contents. Primary cache key.
    ir_hash: u64,
    /// Combined hash of secondary inputs (kernel source mtimes + sizes).
    /// Used to invalidate when the AST walker would see different
    /// source files even if the IR was somehow unchanged.
    ast_hash: u64,
};

/// Compute xxhash3-64 of the IR file at `path`. Returns 0 if unreadable.
pub fn hashFile(path: []const u8) u64 {
    var file = std.fs.cwd().openFile(path, .{}) catch return 0;
    defer file.close();
    var hasher = std.hash.XxHash3.init(0);
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = file.read(&buf) catch return 0;
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }
    return hasher.final();
}

/// Compute a stable hash of every `.zig` file's path + size + mtime under
/// `kernel_root`. This is faster than re-reading every source byte and is
/// sufficient as a secondary cache invalidator: any edit to any kernel
/// source bumps mtime and busts the cache.
///
/// Errors during walking degrade to the partial hash already accumulated.
/// On total failure (root unreadable) returns 0 — the cache key still has
/// the IR hash to fall back on so this only weakens secondary detection.
pub fn hashAstInputs(allocator: std.mem.Allocator, kernel_root: []const u8) u64 {
    var hasher = std.hash.XxHash3.init(0);

    var dir = std.fs.cwd().openDir(kernel_root, .{ .iterate = true }) catch return 0;
    defer dir.close();
    var walker = dir.walk(allocator) catch return 0;
    defer walker.deinit();

    // Collect entries first so the hash is order-stable (filesystem walk
    // order is platform-defined). Sort by path before hashing.
    const Entry = struct { path: []u8, size: u64, mtime_ns: i128 };
    var entries = std.ArrayList(Entry){};
    defer {
        for (entries.items) |e| allocator.free(e.path);
        entries.deinit(allocator);
    }

    while (walker.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        const stat = entry.dir.statFile(entry.basename) catch continue;
        const path_copy = allocator.dupe(u8, entry.path) catch continue;
        entries.append(allocator, .{
            .path = path_copy,
            .size = stat.size,
            .mtime_ns = stat.mtime,
        }) catch {
            allocator.free(path_copy);
            continue;
        };
    }

    std.mem.sort(Entry, entries.items, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lt);

    for (entries.items) |e| {
        hasher.update(e.path);
        var scratch: [24]u8 = undefined;
        std.mem.writeInt(u64, scratch[0..8], e.size, .little);
        std.mem.writeInt(i128, scratch[8..24], e.mtime_ns, .little);
        hasher.update(&scratch);
    }
    return hasher.final();
}

/// Resolve the cache directory: `$XDG_CACHE_HOME/callgraph` if set, else
/// `$HOME/.cache/callgraph`. Returns an arena-owned absolute path or an
/// error if neither env var is usable.
pub fn cacheDir(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "XDG_CACHE_HOME")) |xdg| {
        defer allocator.free(xdg);
        return std.fs.path.join(allocator, &.{ xdg, "callgraph" });
    } else |_| {}
    if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
        defer allocator.free(home);
        return std.fs.path.join(allocator, &.{ home, ".cache", "callgraph" });
    } else |_| {}
    return error.NoCacheDir;
}

/// Build the per-arch cache filename for `(arch, ir_hash)`. Caller owns.
pub fn cachePath(
    allocator: std.mem.Allocator,
    dir: []const u8,
    arch_tag: []const u8,
    ir_hash: u64,
) ![]u8 {
    const base = try std.fmt.allocPrint(allocator, "{s}.{x:0>16}.cgcache", .{ arch_tag, ir_hash });
    defer allocator.free(base);
    return std.fs.path.join(allocator, &.{ dir, base });
}

/// Delete every `<arch>.*.cgcache` file in `dir` that doesn't match
/// `keep_path`. Best-effort; logs but never fails the caller.
pub fn purgeStaleForArch(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    arch_tag: []const u8,
    keep_path: []const u8,
) void {
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();

    const prefix = std.fmt.allocPrint(allocator, "{s}.", .{arch_tag}) catch return;
    defer allocator.free(prefix);

    const keep_basename = std.fs.path.basename(keep_path);

    var it = dir.iterate();
    while (it.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, prefix)) continue;
        if (!std.mem.endsWith(u8, entry.name, ".cgcache")) continue;
        if (std.mem.eql(u8, entry.name, keep_basename)) continue;
        dir.deleteFile(entry.name) catch {};
    }
}

// ------------------------------------------------------------------------
// Writer
// ------------------------------------------------------------------------

const BodyHasher = struct {
    inner: std.hash.Fnv1a_64,
    fn init() BodyHasher {
        return .{ .inner = std.hash.Fnv1a_64.init() };
    }
    fn update(self: *BodyHasher, bytes: []const u8) void {
        self.inner.update(bytes);
    }
    fn final(self: *BodyHasher) u64 {
        return self.inner.final();
    }
};

const Writer = struct {
    buf: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    fn writeBytes(self: *Writer, bytes: []const u8) !void {
        try self.buf.appendSlice(self.allocator, bytes);
    }
    fn writeU8(self: *Writer, v: u8) !void {
        try self.buf.append(self.allocator, v);
    }
    fn writeU32(self: *Writer, v: u32) !void {
        var scratch: [4]u8 = undefined;
        std.mem.writeInt(u32, &scratch, v, .little);
        try self.writeBytes(&scratch);
    }
    fn writeU64(self: *Writer, v: u64) !void {
        var scratch: [8]u8 = undefined;
        std.mem.writeInt(u64, &scratch, v, .little);
        try self.writeBytes(&scratch);
    }
    fn writeStr(self: *Writer, s: []const u8) !void {
        try self.writeU32(@intCast(s.len));
        try self.writeBytes(s);
    }
    fn writeOptU32(self: *Writer, v: ?u32) !void {
        if (v) |x| {
            try self.writeU8(1);
            try self.writeU32(x);
        } else {
            try self.writeU8(0);
        }
    }
    fn writeOptStr(self: *Writer, s: ?[]const u8) !void {
        if (s) |x| {
            try self.writeU8(1);
            try self.writeStr(x);
        } else {
            try self.writeU8(0);
        }
    }
    fn writeLoc(self: *Writer, loc: SourceLoc) !void {
        try self.writeStr(loc.file);
        try self.writeU32(loc.line);
        try self.writeU32(loc.col);
    }
    fn writeOptLoc(self: *Writer, loc: ?SourceLoc) !void {
        if (loc) |x| {
            try self.writeU8(1);
            try self.writeLoc(x);
        } else {
            try self.writeU8(0);
        }
    }
};

fn writeEnrichedEdge(w: *Writer, e: EnrichedEdge) !void {
    try w.writeOptU32(e.to);
    try w.writeOptStr(e.target_name);
    try w.writeU8(@intFromEnum(e.kind));
    try w.writeLoc(e.site);
}

fn writeCallee(w: *Writer, c: Callee) !void {
    try w.writeOptU32(c.to);
    try w.writeStr(c.name);
    try w.writeU8(@intFromEnum(c.kind));
    try w.writeLoc(c.site);
}

const WriteError = std.mem.Allocator.Error;

fn writeAtoms(w: *Writer, atoms: []const Atom) WriteError!void {
    try w.writeU32(@intCast(atoms.len));
    for (atoms) |atom| try writeAtom(w, atom);
}

fn writeAtom(w: *Writer, atom: Atom) WriteError!void {
    switch (atom) {
        .call => |c| {
            try w.writeU8(0);
            try writeCallee(w, c);
        },
        .branch => |b| {
            try w.writeU8(1);
            try w.writeU8(@intFromEnum(b.kind));
            try w.writeLoc(b.loc);
            try w.writeU32(@intCast(b.arms.len));
            for (b.arms) |arm| {
                try w.writeStr(arm.label);
                try writeAtoms(w, arm.seq);
            }
        },
        .loop => |l| {
            try w.writeU8(2);
            try w.writeLoc(l.loc);
            try writeAtoms(w, l.body);
        },
    }
}

fn writeFunction(w: *Writer, f: Function) !void {
    try w.writeU32(f.id);
    try w.writeStr(f.name);
    try w.writeStr(f.mangled);
    try w.writeLoc(f.def_loc);
    try w.writeU32(f.body_line_end);
    try w.writeU8(if (f.is_entry) 1 else 0);
    if (f.entry_kind) |k| {
        try w.writeU8(1);
        try w.writeU8(@intFromEnum(k));
    } else {
        try w.writeU8(0);
    }
    try w.writeU32(@intCast(f.callees.len));
    for (f.callees) |e| try writeEnrichedEdge(w, e);
    try writeAtoms(w, f.intra);
    try w.writeU8(if (f.reachable) 1 else 0);
    try w.writeU8(if (f.is_ast_only) 1 else 0);
    try w.writeU32(@intCast(f.def_deps.len));
    for (f.def_deps) |d| try w.writeU32(d);
    try w.writeU32(f.entry_reach);
}

fn writeEntryPoint(w: *Writer, ep: EntryPoint) !void {
    try w.writeU32(ep.fn_id);
    try w.writeU8(@intFromEnum(ep.kind));
    try w.writeStr(ep.label);
}

fn writeDefinition(w: *Writer, d: Definition) !void {
    try w.writeU32(d.id);
    try w.writeStr(d.name);
    try w.writeStr(d.qualified_name);
    try w.writeStr(d.file);
    try w.writeU32(d.line_start);
    try w.writeU32(d.line_end);
    try w.writeU8(@intFromEnum(d.kind));
    try w.writeU8(if (d.is_pub) 1 else 0);
}

/// Serialize `graph` to a temp file under `cache_dir` then atomic-rename
/// it to the per-arch cache filename. Caller owns nothing — the temp
/// file's name is internal. Returns the elapsed nanoseconds on success
/// or null on any failure (caller logs).
pub fn save(
    allocator: std.mem.Allocator,
    cache_dir_path: []const u8,
    arch_tag: []const u8,
    key: KeyInputs,
    graph: *const Graph,
) ?u64 {
    const t0 = std.time.nanoTimestamp();
    saveInner(allocator, cache_dir_path, arch_tag, key, graph) catch |err| {
        std.debug.print("[cache {s}] save failed: {s}\n", .{ arch_tag, @errorName(err) });
        return null;
    };
    const t1 = std.time.nanoTimestamp();
    return @intCast(t1 - t0);
}

fn saveInner(
    allocator: std.mem.Allocator,
    cache_dir_path: []const u8,
    arch_tag: []const u8,
    key: KeyInputs,
    graph: *const Graph,
) !void {
    std.fs.cwd().makePath(cache_dir_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const final_path = try cachePath(allocator, cache_dir_path, arch_tag, key.ir_hash);
    defer allocator.free(final_path);
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp.{d}", .{ final_path, std.time.milliTimestamp() });
    defer allocator.free(tmp_path);

    // Build the entire serialized blob in memory first. Easier than
    // streaming to disk while also tracking the body checksum, and the
    // total size (~ a few MB) easily fits in RAM.
    var buf = std.ArrayList(u8){};
    defer buf.deinit(allocator);
    var w = Writer{ .buf = &buf, .allocator = allocator };

    // Header
    try w.writeBytes(&MAGIC);
    try w.writeU32(FORMAT_VERSION);
    try w.writeU64(key.ir_hash);
    try w.writeU64(key.ast_hash);
    try w.writeStr(arch_tag);

    const body_start = buf.items.len;

    // Graph body
    try w.writeU32(@intCast(graph.functions.len));
    for (graph.functions) |f| try writeFunction(&w, f);

    try w.writeU32(@intCast(graph.entry_points.len));
    for (graph.entry_points) |ep| try writeEntryPoint(&w, ep);

    try w.writeU32(@intCast(graph.definitions.len));
    for (graph.definitions) |d| try writeDefinition(&w, d);

    const body_end = buf.items.len;

    // Footer: body checksum + trailing magic.
    var hasher = BodyHasher.init();
    hasher.update(buf.items[body_start..body_end]);
    try w.writeU64(hasher.final());
    try w.writeBytes(&TRAILER);

    // Atomic write: write to temp, then rename.
    const file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(buf.items);
    try std.fs.cwd().rename(tmp_path, final_path);

    // Best-effort: prune older cgcache files for this arch.
    purgeStaleForArch(allocator, cache_dir_path, arch_tag, final_path);
}

// ------------------------------------------------------------------------
// Reader
// ------------------------------------------------------------------------

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    arena: std.mem.Allocator,

    fn need(self: *Reader, n: usize) ![]const u8 {
        if (self.pos + n > self.bytes.len) return error.Truncated;
        const slice = self.bytes[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }
    fn readU8(self: *Reader) !u8 {
        const s = try self.need(1);
        return s[0];
    }
    fn readU32(self: *Reader) !u32 {
        const s = try self.need(4);
        return std.mem.readInt(u32, s[0..4], .little);
    }
    fn readU64(self: *Reader) !u64 {
        const s = try self.need(8);
        return std.mem.readInt(u64, s[0..8], .little);
    }
    fn readStr(self: *Reader) ![]const u8 {
        const len = try self.readU32();
        const raw = try self.need(len);
        return self.arena.dupe(u8, raw);
    }
    fn readOptU32(self: *Reader) !?u32 {
        const tag = try self.readU8();
        if (tag == 0) return null;
        return try self.readU32();
    }
    fn readOptStr(self: *Reader) !?[]const u8 {
        const tag = try self.readU8();
        if (tag == 0) return null;
        return try self.readStr();
    }
    fn readLoc(self: *Reader) !SourceLoc {
        const file = try self.readStr();
        const line = try self.readU32();
        const col = try self.readU32();
        return .{ .file = file, .line = line, .col = col };
    }
    fn readEnumU8(self: *Reader, comptime E: type) !E {
        const v = try self.readU8();
        const max = @typeInfo(E).@"enum".fields.len;
        if (v >= max) return error.BadEnum;
        return @enumFromInt(v);
    }
};

fn readEnrichedEdge(r: *Reader) !EnrichedEdge {
    const to = try r.readOptU32();
    const target_name = try r.readOptStr();
    const kind = try r.readEnumU8(EdgeKind);
    const site = try r.readLoc();
    return .{
        .to = to,
        .target_name = target_name,
        .kind = kind,
        .site = site,
    };
}

fn readCallee(r: *Reader) !Callee {
    const to = try r.readOptU32();
    const name = try r.readStr();
    const kind = try r.readEnumU8(EdgeKind);
    const site = try r.readLoc();
    return .{ .to = to, .name = name, .kind = kind, .site = site };
}

fn readAtoms(r: *Reader) ![]Atom {
    const n = try r.readU32();
    const atoms = try r.arena.alloc(Atom, n);
    var i: u32 = 0;
    while (i < n) {
        atoms[i] = try readAtom(r);
        i += 1;
    }
    return atoms;
}

fn readAtom(r: *Reader) error{ Truncated, BadEnum, BadAtomTag, OutOfMemory }!Atom {
    const tag = try r.readU8();
    switch (tag) {
        0 => {
            const c = try readCallee(r);
            return .{ .call = c };
        },
        1 => {
            const kind = try r.readEnumU8(BranchKind);
            const loc = try r.readLoc();
            const arm_count = try r.readU32();
            const arms = try r.arena.alloc(ArmSeq, arm_count);
            var i: u32 = 0;
            while (i < arm_count) {
                const label = try r.readStr();
                const seq = try readAtoms(r);
                arms[i] = .{ .label = label, .seq = seq };
                i += 1;
            }
            return .{ .branch = .{ .kind = kind, .loc = loc, .arms = arms } };
        },
        2 => {
            const loc = try r.readLoc();
            const body = try readAtoms(r);
            return .{ .loop = .{ .loc = loc, .body = body } };
        },
        else => return error.BadAtomTag,
    }
}

fn readFunction(r: *Reader) !Function {
    const id = try r.readU32();
    const name = try r.readStr();
    const mangled = try r.readStr();
    const def_loc = try r.readLoc();
    const body_line_end = try r.readU32();
    const is_entry = (try r.readU8()) != 0;
    const has_entry_kind = (try r.readU8()) != 0;
    const entry_kind: ?EntryKind = if (has_entry_kind) try r.readEnumU8(EntryKind) else null;
    const callee_count = try r.readU32();
    const callees = try r.arena.alloc(EnrichedEdge, callee_count);
    var i: u32 = 0;
    while (i < callee_count) {
        callees[i] = try readEnrichedEdge(r);
        i += 1;
    }
    const intra = try readAtoms(r);
    const reachable = (try r.readU8()) != 0;
    const is_ast_only = (try r.readU8()) != 0;
    const dep_count = try r.readU32();
    const def_deps = try r.arena.alloc(DefId, dep_count);
    var j: u32 = 0;
    while (j < dep_count) {
        def_deps[j] = try r.readU32();
        j += 1;
    }
    const entry_reach = try r.readU32();
    return .{
        .id = id,
        .name = name,
        .mangled = mangled,
        .def_loc = def_loc,
        .body_line_end = body_line_end,
        .is_entry = is_entry,
        .entry_kind = entry_kind,
        .callees = callees,
        .intra = intra,
        .reachable = reachable,
        .is_ast_only = is_ast_only,
        .def_deps = def_deps,
        .entry_reach = entry_reach,
    };
}

fn readEntryPoint(r: *Reader) !EntryPoint {
    const fn_id = try r.readU32();
    const kind = try r.readEnumU8(EntryKind);
    const label = try r.readStr();
    return .{ .fn_id = fn_id, .kind = kind, .label = label };
}

fn readDefinition(r: *Reader) !Definition {
    const id = try r.readU32();
    const name = try r.readStr();
    const qualified_name = try r.readStr();
    const file = try r.readStr();
    const line_start = try r.readU32();
    const line_end = try r.readU32();
    const kind = try r.readEnumU8(DefKind);
    const is_pub = (try r.readU8()) != 0;
    return .{
        .id = id,
        .name = name,
        .qualified_name = qualified_name,
        .file = file,
        .line_start = line_start,
        .line_end = line_end,
        .kind = kind,
        .is_pub = is_pub,
    };
}

pub const LoadResult = struct {
    graph: Graph,
    elapsed_ns: u64,
};

/// Try to load the cache file at `path` and rehydrate a Graph using
/// `arena` for all owned slices. Returns null on any error / mismatch:
/// the daemon falls back to a full build in that case.
pub fn load(
    arena: std.mem.Allocator,
    path: []const u8,
    expected_key: KeyInputs,
    expected_arch: []const u8,
) ?LoadResult {
    const t0 = std.time.nanoTimestamp();
    const result = loadInner(arena, path, expected_key, expected_arch) catch |err| {
        // FileNotFound is the normal cold-start case (no cache yet for
        // this IR hash); don't pollute the log. Anything else is worth
        // surfacing — bad checksum, version skew, partial write, etc.
        if (err != error.FileNotFound) {
            std.debug.print("[cache] load {s} failed: {s}\n", .{ path, @errorName(err) });
        }
        return null;
    };
    const t1 = std.time.nanoTimestamp();
    return .{ .graph = result, .elapsed_ns = @intCast(t1 - t0) };
}

fn loadInner(
    arena: std.mem.Allocator,
    path: []const u8,
    expected_key: KeyInputs,
    expected_arch: []const u8,
) !Graph {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.size < MAGIC.len + 4 + 8 + 8 + 4 + 8 + TRAILER.len) return error.Truncated;
    const bytes = try arena.alloc(u8, stat.size);
    const n = try file.readAll(bytes);
    if (n != stat.size) return error.Truncated;

    if (!std.mem.eql(u8, bytes[0..MAGIC.len], &MAGIC)) return error.BadMagic;
    if (!std.mem.eql(u8, bytes[bytes.len - TRAILER.len ..], &TRAILER)) return error.BadTrailer;

    var r = Reader{ .bytes = bytes[0 .. bytes.len - TRAILER.len], .arena = arena };
    r.pos = MAGIC.len;
    const version = try r.readU32();
    if (version != FORMAT_VERSION) return error.BadVersion;
    const ir_hash = try r.readU64();
    if (ir_hash != expected_key.ir_hash) return error.IrHashMismatch;
    const ast_hash = try r.readU64();
    if (ast_hash != expected_key.ast_hash) return error.AstHashMismatch;
    const arch_tag = try r.readStr();
    if (!std.mem.eql(u8, arch_tag, expected_arch)) return error.ArchMismatch;

    const body_start = r.pos;
    const body_end = bytes.len - TRAILER.len - 8; // sub trailing checksum u64
    if (body_end < body_start) return error.Truncated;

    // Verify body checksum first so we don't decode a corrupted blob.
    const stored_checksum = std.mem.readInt(u64, bytes[body_end..][0..8], .little);
    var hasher = BodyHasher.init();
    hasher.update(bytes[body_start..body_end]);
    if (hasher.final() != stored_checksum) return error.BadChecksum;

    // Body
    const fn_count = try r.readU32();
    const fns = try arena.alloc(Function, fn_count);
    var i: u32 = 0;
    while (i < fn_count) {
        fns[i] = try readFunction(&r);
        i += 1;
    }

    const ep_count = try r.readU32();
    const eps = try arena.alloc(EntryPoint, ep_count);
    var j: u32 = 0;
    while (j < ep_count) {
        eps[j] = try readEntryPoint(&r);
        j += 1;
    }

    const def_count = try r.readU32();
    const defs = try arena.alloc(Definition, def_count);
    var k: u32 = 0;
    while (k < def_count) {
        defs[k] = try readDefinition(&r);
        k += 1;
    }

    if (r.pos != body_end) return error.TrailingBytes;

    return .{
        .functions = fns,
        .entry_points = eps,
        .definitions = defs,
    };
}
