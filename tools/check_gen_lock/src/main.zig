//! Static analyzer for SecureSlab gen-lock coverage / scoping.
//!
//! Oracle-DB consumer: reads tokens, AST, entities, and entry_point rows
//! from a per-(arch, commit_sha) DB built by `tools/indexer`. Six checks:
//!
//!   1. Slab-backed type discovery — entity.is_slab_backed = 1.
//!
//!   2. Fat-pointer invariant on struct fields — `*T` / `?*T` / `[N]*T` /
//!      `[]*T` for slab-backed T are violations. SlabRef(T) is required.
//!
//!   3. `.ptr` bypass — chains `<x>.<slabref_field>.ptr` outside an
//!      explicit lock/unlock bracket, with `// self-alive` exemption.
//!
//!   4. Per-entry bracketing — every access to a slab-typed local in a
//!      syscall / exception handler must be tight-preceded by a lock and
//!      tight-followed by an unlock on the same ident. Simplified
//!      version that flags entry-point fns containing acquires that
//!      aren't paired before the next return on every path. The detailed
//!      "bracket" semantics from the legacy analyzer collapse into the
//!      release-coverage check below.
//!
//!   5. Per-path release coverage — for every lock acquired in an entry
//!      body, every reachable control-flow exit (return / try error
//!      propagation / break / continue) between the lock and its release
//!      must be covered by either an explicit unlock, a `defer
//!      ref.unlock(...)`, or — for error-flavor exits — an `errdefer
//!      ref.unlock(...)`. `@panic`/`unreachable` impose no obligation.
//!
//!   6. IRQ-acquired lock-class discipline — a lock class L is "IRQ-
//!      acquired" iff some IRQ / NMI / async-trap entry can transitively
//!      reach an acquire of L. Process-context acquires of an IRQ-
//!      acquired class must use an IRQ-saving variant or be wrapped in
//!      saveAndDisableInterrupts/restoreInterrupts. Pairing variants
//!      must match (plain↔plain, IrqSave↔IrqRestore).
//!
//! Exit status nonzero iff any err-severity findings are emitted.

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const ascii = std.ascii;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const StringHashMapUnmanaged = std.StringHashMapUnmanaged;
const sqlite = @import("sqlite.zig");

// ── Domain-knowledge tables (carried over from the legacy analyzer) ────

const EXCEPTION_ENTRY_NAMES = [_][]const u8{
    "exceptionHandler",
    "pageFaultHandler",
    "handleSyncLowerEl",
    "handleIrqLowerEl",
    "handleSyncCurrentEl",
    "handleIrqCurrentEl",
    "handleUnexpected",
    "dispatchIrq",
    "schedTimerHandler",
};

const PLAIN_ACQUIRE_METHODS = [_][]const u8{
    "lock",
    "lockOrdered",
    "lockWithGen",
    "lockWithGenOrdered",
};

const IRQ_SAVE_ACQUIRE_METHODS = [_][]const u8{
    "lockIrqSave",
    "lockIrqSaveOrdered",
    "lockOrderedIrqSave",
    "lockWithGenIrqSave",
    "lockWithGenIrqSaveOrdered",
    "lockWithGenOrderedIrqSave",
};

const PLAIN_RELEASE_METHODS = [_][]const u8{ "unlock" };
const IRQ_RESTORE_RELEASE_METHODS = [_][]const u8{ "unlockIrqRestore" };

const LOCK_TYPE_NAMES = [_][]const u8{ "SpinLock", "GenLock" };

const BARE_PTR_FIELD_EXEMPT_FILES = [_][]const u8{
    "memory/allocators/secure_slab.zig",
    "memory/allocators/allocators.zig",
};

const PTR_BYPASS_EXEMPT_FILES = [_][]const u8{
    "memory/allocators/secure_slab.zig",
};

const TEST_FIXTURE_TYPES = [_][]const u8{"TestT"};

// IRQ entry kinds and decls, used for IRQ-discipline reachability.
const IrqEntryKind = enum {
    irq_async,
    nmi,
    trap_sync,
    irq_unexpected,

    pub fn label(self: IrqEntryKind) []const u8 {
        return switch (self) {
            .irq_async => "irq_async",
            .nmi => "nmi",
            .trap_sync => "trap_sync",
            .irq_unexpected => "irq_unexpected",
        };
    }
};

const IrqEntryDecl = struct { name: []const u8, kind: IrqEntryKind };

const IRQ_ENTRY_DECLS = [_]IrqEntryDecl{
    .{ .name = "schedTimerHandler", .kind = .irq_async },
    .{ .name = "dispatchIrq", .kind = .irq_async },
    .{ .name = "handleIrqLowerEl", .kind = .irq_async },
    .{ .name = "handleIrqCurrentEl", .kind = .irq_async },
    .{ .name = "handleUnexpected", .kind = .irq_unexpected },
    .{ .name = "exceptionHandler", .kind = .trap_sync },
    .{ .name = "pageFaultHandler", .kind = .trap_sync },
    .{ .name = "handleSyncLowerEl", .kind = .trap_sync },
    .{ .name = "handleSyncCurrentEl", .kind = .trap_sync },
};

// ── Small helpers ──────────────────────────────────────────────────────

fn inList(needle: []const u8, list: []const []const u8) bool {
    for (list) |s| if (mem.eql(u8, s, needle)) return true;
    return false;
}

fn isIdentChar(c: u8) bool {
    return ascii.isAlphanumeric(c) or c == '_';
}

fn isIdentStart(c: u8) bool {
    return ascii.isAlphabetic(c) or c == '_';
}

fn trimAscii(s: []const u8) []const u8 {
    var a: usize = 0;
    var b: usize = s.len;
    while (a < b and ascii.isWhitespace(s[a])) a += 1;
    while (b > a and ascii.isWhitespace(s[b - 1])) b -= 1;
    return s[a..b];
}

fn shortName(qname: []const u8) []const u8 {
    if (mem.lastIndexOfScalar(u8, qname, '.')) |i| return qname[i + 1 ..];
    return qname;
}

fn isPlainAcquire(name: []const u8) bool { return inList(name, &PLAIN_ACQUIRE_METHODS); }
fn isIrqSaveAcquire(name: []const u8) bool { return inList(name, &IRQ_SAVE_ACQUIRE_METHODS); }
fn isAnyAcquire(name: []const u8) bool { return isPlainAcquire(name) or isIrqSaveAcquire(name); }
fn isPlainRelease(name: []const u8) bool { return inList(name, &PLAIN_RELEASE_METHODS); }
fn isIrqRestoreRelease(name: []const u8) bool { return inList(name, &IRQ_RESTORE_RELEASE_METHODS); }
fn isAnyRelease(name: []const u8) bool { return isPlainRelease(name) or isIrqRestoreRelease(name); }

fn lookupIrqEntryKind(name: []const u8) ?IrqEntryKind {
    for (IRQ_ENTRY_DECLS) |d| {
        if (mem.eql(u8, d.name, name)) return d.kind;
    }
    return null;
}

// Type-string ref parser. Recognizes `*T`, `?*T`, `*const T`,
// `SlabRef(T)`, `?SlabRef(T)`. Returns the inner T name.
fn parseTypeRef(type_str: []const u8) ?[]const u8 {
    var t = trimAscii(type_str);
    if (t.len == 0) return null;
    if (t[0] == '?') t = trimAscii(t[1..]);
    if (t.len == 0) return null;
    if (mem.startsWith(u8, t, "SlabRef")) {
        var rest = trimAscii(t[7..]);
        if (rest.len == 0 or rest[0] != '(') return null;
        rest = trimAscii(rest[1..]);
        var end: usize = 0;
        while (end < rest.len and isIdentChar(rest[end])) end += 1;
        if (end == 0) return null;
        return rest[0..end];
    }
    if (t[0] != '*') return null;
    t = trimAscii(t[1..]);
    if (mem.startsWith(u8, t, "const ")) t = trimAscii(t["const ".len..]);
    if (t.len == 0 or !isIdentStart(t[0])) return null;
    var e: usize = 0;
    while (e < t.len and isIdentChar(t[e])) e += 1;
    return t[0..e];
}

fn typeStrContainsSlabRef(type_str: []const u8) bool {
    return mem.indexOf(u8, type_str, "SlabRef") != null and
        mem.indexOf(u8, type_str, "(") != null;
}

// ── DB state caches ────────────────────────────────────────────────────

const FileInfo = struct {
    id: u32,
    path: []const u8,
    source: []const u8,
};

const Entity = struct {
    id: u32,
    kind: []const u8,
    qname: []const u8,
    file_id: u32,
    byte_start: u32,
    byte_end: u32,
    line: u32,
    is_slab_backed: bool,
};

const TokenRow = struct {
    file_id: u32,
    idx: u32,
    kind: []const u8,
    byte_start: u32,
    text: []const u8,
};

const AstNode = struct {
    id: u64,
    file_id: u32,
    parent_id: ?u64,
    kind: []const u8,
    byte_start: u32,
    byte_end: u32,
};

const State = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    files: ArrayList(FileInfo),
    files_by_id: std.AutoHashMap(u32, *FileInfo),
    slab_types: StringHashMap(void), // short name → present
    slab_field_names: StringHashMap(void), // short field name → present
    entry_points: ArrayList(Entity),

    fn init(gpa: Allocator) State {
        return .{
            .gpa = gpa,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .files = .empty,
            .files_by_id = std.AutoHashMap(u32, *FileInfo).init(gpa),
            .slab_types = StringHashMap(void).init(gpa),
            .slab_field_names = StringHashMap(void).init(gpa),
            .entry_points = .empty,
        };
    }

    fn deinit(self: *State) void {
        self.files.deinit(self.gpa);
        self.files_by_id.deinit();
        self.slab_types.deinit();
        self.slab_field_names.deinit();
        self.entry_points.deinit(self.gpa);
        self.arena.deinit();
    }
};

// ── DB loaders ─────────────────────────────────────────────────────────

fn loadFiles(db: *sqlite.Db, st: *State) !void {
    const a = st.arena.allocator();
    var stmt = try db.prepare("SELECT id, path, source FROM file ORDER BY id", st.gpa);
    defer stmt.finalize();
    while (try stmt.step()) {
        const id: u32 = @intCast(stmt.columnInt(0));
        const path = stmt.columnText(1) orelse continue;
        const src = stmt.columnBlob(2) orelse "";
        const path_dup = try a.dupe(u8, path);
        const src_dup = try a.dupe(u8, src);
        try st.files.append(st.gpa, .{ .id = id, .path = path_dup, .source = src_dup });
    }
    for (st.files.items) |*f| {
        try st.files_by_id.put(f.id, f);
    }
}

fn loadSlabTypes(db: *sqlite.Db, st: *State) !void {
    const a = st.arena.allocator();
    var stmt = try db.prepare(
        "SELECT qualified_name FROM entity WHERE is_slab_backed = 1",
        st.gpa,
    );
    defer stmt.finalize();
    while (try stmt.step()) {
        const q = stmt.columnText(0) orelse continue;
        const sn = shortName(q);
        if (inList(sn, &TEST_FIXTURE_TYPES)) continue;
        const owned = try a.dupe(u8, sn);
        try st.slab_types.put(owned, {});
    }
}

fn loadEntryPoints(db: *sqlite.Db, st: *State) !void {
    const a = st.arena.allocator();
    var stmt = try db.prepare(
        \\SELECT e.id, e.kind, e.qualified_name, e.def_file_id,
        \\       e.def_byte_start, e.def_byte_end, e.def_line, e.is_slab_backed
        \\  FROM entity e
        \\  JOIN entry_point ep ON ep.entity_id = e.id
        \\ WHERE ep.kind IN ('syscall', 'exception', 'irq')
        \\ ORDER BY e.def_file_id, e.def_byte_start
    , st.gpa);
    defer stmt.finalize();
    while (try stmt.step()) {
        const id: u32 = @intCast(stmt.columnInt(0));
        const kind = stmt.columnText(1) orelse "fn";
        const q = stmt.columnText(2) orelse continue;
        const fid: u32 = @intCast(stmt.columnInt(3));
        const bs: u32 = @intCast(stmt.columnInt(4));
        const be: u32 = @intCast(stmt.columnInt(5));
        const ln: u32 = @intCast(stmt.columnInt(6));
        const sb = stmt.columnInt(7) != 0;
        try st.entry_points.append(st.gpa, .{
            .id = id,
            .kind = try a.dupe(u8, kind),
            .qname = try a.dupe(u8, q),
            .file_id = fid,
            .byte_start = bs,
            .byte_end = be,
            .line = ln,
            .is_slab_backed = sb,
        });
    }
}

// Source bytes for a span. Returns "" if file not loaded.
fn spanBytes(st: *State, file_id: u32, byte_start: u32, byte_end: u32) []const u8 {
    const f_opt = st.files_by_id.get(file_id) orelse return "";
    const src = f_opt.source;
    if (byte_start > src.len or byte_end > src.len or byte_end < byte_start) return "";
    return src[byte_start..byte_end];
}

fn fileById(st: *State, file_id: u32) ?*FileInfo {
    return st.files_by_id.get(file_id);
}

// Convert byte offset to 1-indexed line in source.
fn byteToLine(src: []const u8, byte: u32) u32 {
    var line: u32 = 1;
    var i: usize = 0;
    while (i < byte and i < src.len) : (i += 1) {
        if (src[i] == '\n') line += 1;
    }
    return line;
}

// ── Check 1+2: fat-pointer invariant on struct fields ──────────────────

const BarePtrFinding = struct {
    file_path: []const u8,
    line: u32,
    struct_name: []const u8,
    field_name: []const u8,
    field_type: []const u8,
    slab_type: []const u8,
};

fn parseFieldName(field_bytes: []const u8) ?[]const u8 {
    var t = trimAscii(field_bytes);
    if (mem.startsWith(u8, t, "pub ")) t = trimAscii(t[3..]);
    if (mem.startsWith(u8, t, "comptime ")) t = trimAscii(t[8..]);
    if (t.len == 0 or !isIdentStart(t[0])) return null;
    var e: usize = 0;
    while (e < t.len and isIdentChar(t[e])) e += 1;
    return t[0..e];
}

fn parseFieldType(field_bytes: []const u8) ?[]const u8 {
    var t = trimAscii(field_bytes);
    if (mem.startsWith(u8, t, "pub ")) t = trimAscii(t[3..]);
    if (mem.startsWith(u8, t, "comptime ")) t = trimAscii(t[8..]);
    // Skip ident.
    var e: usize = 0;
    while (e < t.len and isIdentChar(t[e])) e += 1;
    var rest = trimAscii(t[e..]);
    if (rest.len == 0 or rest[0] != ':') return null;
    rest = trimAscii(rest[1..]);
    // Type spans up to `=` or `,` at depth 0.
    var depth: i32 = 0;
    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const c = rest[i];
        if (c == '(' or c == '[' or c == '{') depth += 1;
        if (c == ')' or c == ']' or c == '}') depth -= 1;
        if (depth != 0) continue;
        if (c == '=' or c == ',') break;
    }
    return trimAscii(rest[0..i]);
}

// Find the nearest enclosing container_decl for a container_field node.
// Returns the qualified_name of the container's parent var_decl entity
// (e.g. "<module>.Foo"), or null.
fn enclosingContainerName(
    db: *sqlite.Db,
    gpa: Allocator,
    field_node_id: u64,
) !?[]const u8 {
    // Walk up via parent_id chain: container_field's parent is a
    // container_decl; container_decl's parent is a var_decl whose
    // entity_id resolves the alias name.
    var cur: u64 = field_node_id;
    var hops: u32 = 0;
    while (hops < 8) : (hops += 1) {
        var stmt = try db.prepare(
            "SELECT parent_id, kind, entity_id FROM ast_node WHERE id = ?",
            gpa,
        );
        defer stmt.finalize();
        try stmt.bindInt(1, @intCast(cur));
        if (!try stmt.step()) return null;
        const pid_col = stmt.columnInt(0);
        const kind = stmt.columnText(1) orelse return null;
        const eid_col = stmt.columnInt(2);
        if (mem.eql(u8, kind, "var_decl") and eid_col > 0) {
            // Look up entity name.
            var s2 = try db.prepare("SELECT qualified_name FROM entity WHERE id = ?", gpa);
            defer s2.finalize();
            try s2.bindInt(1, eid_col);
            if (!try s2.step()) return null;
            const q = s2.columnText(0) orelse return null;
            return try gpa.dupe(u8, q);
        }
        if (pid_col == 0) return null;
        cur = @intCast(pid_col);
    }
    return null;
}

fn checkFatPointerFields(
    db: *sqlite.Db,
    st: *State,
    findings: *ArrayList(BarePtrFinding),
) !void {
    // Get all container_field AST nodes with their byte spans.
    const a = st.arena.allocator();
    var stmt = try db.prepare(
        \\SELECT n.id, n.file_id, n.byte_start, n.byte_end
        \\  FROM ast_node n
        \\ WHERE n.kind = 'container_field'
    , st.gpa);
    defer stmt.finalize();

    while (try stmt.step()) {
        const node_id: u64 = @intCast(stmt.columnInt(0));
        const fid: u32 = @intCast(stmt.columnInt(1));
        const bs: u32 = @intCast(stmt.columnInt(2));
        const be: u32 = @intCast(stmt.columnInt(3));

        const f = fileById(st, fid) orelse continue;
        if (inList(f.path, &BARE_PTR_FIELD_EXEMPT_FILES)) continue;

        const field_bytes = spanBytes(st, fid, bs, be);
        const ft = parseFieldType(field_bytes) orelse continue;
        if (typeStrContainsSlabRef(ft)) continue;

        // Walk for `*<IDENT>` patterns naming a slab-backed type.
        var i: usize = 0;
        while (i < ft.len) : (i += 1) {
            if (ft[i] != '*') continue;
            var j: usize = i + 1;
            while (j < ft.len and ascii.isWhitespace(ft[j])) j += 1;
            if (j + 6 <= ft.len and mem.eql(u8, ft[j .. j + 6], "const ")) {
                j += 6;
                while (j < ft.len and ascii.isWhitespace(ft[j])) j += 1;
            }
            if (j >= ft.len or !isIdentStart(ft[j])) continue;
            var k: usize = j;
            while (k < ft.len and isIdentChar(ft[k])) k += 1;
            const target = ft[j..k];
            if (!st.slab_types.contains(target)) continue;

            const fname = parseFieldName(field_bytes) orelse "<field>";
            const enc_q = (try enclosingContainerName(db, st.gpa, node_id)) orelse "<unknown>";
            defer if (!mem.eql(u8, enc_q, "<unknown>")) st.gpa.free(enc_q);
            const enc_short = shortName(enc_q);
            const line = byteToLine(f.source, bs);

            try findings.append(st.gpa, .{
                .file_path = f.path,
                .line = line,
                .struct_name = try a.dupe(u8, enc_short),
                .field_name = try a.dupe(u8, fname),
                .field_type = try a.dupe(u8, ft),
                .slab_type = try a.dupe(u8, target),
            });
            break;
        }
    }
}

// ── Check 3: `.ptr` bypass ────────────────────────────────────────────

const PtrBypassFinding = struct {
    file_path: []const u8,
    line: u32,
    chain: []const u8,
    context: []const u8,
};

fn collectSlabFieldNames(db: *sqlite.Db, st: *State) !void {
    const a = st.arena.allocator();
    var stmt = try db.prepare(
        \\SELECT byte_start, byte_end, file_id
        \\  FROM ast_node
        \\ WHERE kind = 'container_field'
    , st.gpa);
    defer stmt.finalize();
    while (try stmt.step()) {
        const bs: u32 = @intCast(stmt.columnInt(0));
        const be: u32 = @intCast(stmt.columnInt(1));
        const fid: u32 = @intCast(stmt.columnInt(2));
        const f = fileById(st, fid) orelse continue;
        const bytes = spanBytes(st, fid, bs, be);
        if (bytes.len == 0) continue;
        const ft = parseFieldType(bytes) orelse continue;
        if (!typeStrContainsSlabRef(ft)) continue;
        const fname = parseFieldName(bytes) orelse continue;
        const owned = try a.dupe(u8, fname);
        try st.slab_field_names.put(owned, {});
        _ = f;
    }
    // Seed common KernelObject variant names known to be SlabRef-typed.
    const variants = [_][]const u8{
        "execution_context", "capability_domain", "var_range",
        "page_frame",        "device_region",     "virtual_machine",
        "vcpu",              "port",              "timer",
    };
    for (variants) |v| {
        try st.slab_field_names.put(try a.dupe(u8, v), {});
    }
}

fn containsSelfAlive(line_text: []const u8) bool {
    if (mem.indexOf(u8, line_text, "self-alive")) |_| return true;
    return false;
}

fn checkPtrBypasses(
    db: *sqlite.Db,
    st: *State,
    findings: *ArrayList(PtrBypassFinding),
) !void {
    const a = st.arena.allocator();
    // For each file, scan its source byte-by-byte (fast on cached source).
    for (st.files.items) |f| {
        if (inList(f.path, &PTR_BYPASS_EXEMPT_FILES)) continue;
        const src = f.source;
        // Walk lines.
        var line_no: u32 = 1;
        var line_start: usize = 0;
        var i: usize = 0;
        while (i <= src.len) : (i += 1) {
            const at_eol = (i == src.len) or (src[i] == '\n');
            if (!at_eol) continue;
            const raw_line = src[line_start..i];
            // Skip comment (cheap stripped: anything past `//`).
            const stripped_line = blk: {
                if (mem.indexOf(u8, raw_line, "//")) |idx| break :blk raw_line[0..idx];
                break :blk raw_line;
            };
            if (containsSelfAlive(raw_line)) {
                line_no += 1;
                line_start = i + 1;
                continue;
            }
            // Search for `.ptr` in stripped_line.
            var p: usize = 0;
            while (p + 4 <= stripped_line.len) : (p += 1) {
                if (stripped_line[p] != '.') continue;
                if (!mem.eql(u8, stripped_line[p + 1 .. p + 4], "ptr")) continue;
                if (p + 4 < stripped_line.len and isIdentChar(stripped_line[p + 4])) continue;
                // Walk back to start of chain.
                var s: usize = p;
                while (s > 0) {
                    const prev = stripped_line[s - 1];
                    if (isIdentChar(prev) or prev == '.') {
                        s -= 1;
                    } else break;
                }
                if (s == p) continue;
                if (s > 0) {
                    const pc = stripped_line[s - 1];
                    if (isIdentChar(pc) or pc == '.') continue;
                }
                const chain = stripped_line[s..p];
                if (mem.indexOf(u8, chain, ".") == null) continue;
                const last_dot = mem.lastIndexOf(u8, chain, ".").?;
                const tail = chain[last_dot + 1 ..];
                if (!st.slab_field_names.contains(tail)) continue;
                // Identity compare exemption.
                var q: usize = p + 4;
                while (q < stripped_line.len and ascii.isWhitespace(stripped_line[q])) q += 1;
                if (q + 1 < stripped_line.len and
                    (mem.startsWith(u8, stripped_line[q..], "==") or
                        mem.startsWith(u8, stripped_line[q..], "!=")))
                {
                    continue;
                }
                var b: usize = s;
                while (b > 0 and ascii.isWhitespace(stripped_line[b - 1])) b -= 1;
                if (b >= 2 and (mem.eql(u8, stripped_line[b - 2 .. b], "==") or
                    mem.eql(u8, stripped_line[b - 2 .. b], "!=")))
                {
                    continue;
                }
                const chain_dup = try std.fmt.allocPrint(a, "{s}.ptr", .{chain});
                const ctx_dup = try a.dupe(u8, trimAscii(stripped_line));
                try findings.append(st.gpa, .{
                    .file_path = f.path,
                    .line = line_no,
                    .chain = chain_dup,
                    .context = ctx_dup,
                });
            }
            line_no += 1;
            line_start = i + 1;
        }
    }
    _ = db;
}

// ── Check 4+5: per-entry release coverage via AST walk ─────────────────
//
// For each entry-point fn, we load its AST subtree (descendants of the
// fn_decl span) and walk it recursively. State threaded through:
//   - actives: stack of (lock_ident, defer_unlock?, errdefer_unlock?)
//     entries representing acquired-but-not-yet-released locks reachable
//     on the current path. Cloned per branch.
//   - findings: emitted when an exit (return/try/break/continue) leaves
//     a held lock without matching coverage.
//
// "Lock acquired" detection: a `call` AST node whose source bytes match
// `<chain>.<acquire_method>(...)`. The chain's leftmost ident becomes
// the lock's *ident* key. We use bytes from the `call` node's span.
//
// "Lock released": a `call` AST node `<chain>.<release_method>(...)`.
//
// "Defer unlock": a `defer` node whose body call is `<chain>.unlock(...)`.
//   "Errdefer unlock": likewise for `errdefer`.
//
// Returns are AST nodes of kind `return`. `try X` is detected by
// scanning the call's preceding token for `keyword_try`. `break` /
// `continue` aren't currently in the indexer's AST kind table — we
// handle them by inspecting the source bytes of expression-leaf nodes.

const ReleaseFinding = struct {
    entry_qname: []const u8,
    file_path: []const u8,
    line: u32,
    ident: []const u8,
    rule: []const u8, // "lock_no_release" | "no_release_on_exit"
    message: []const u8,
};

const ActiveLock = struct {
    ident: []const u8, // owned (arena)
    defer_covered: bool,
    errdefer_covered: bool,
    lock_line: u32,
};

const NodeMap = std.AutoHashMap(u64, AstNode);
const ChildList = ArrayList(u64);
const ChildMap = std.AutoHashMap(u64, ChildList);

fn loadFnSubtree(
    db: *sqlite.Db,
    gpa: Allocator,
    arena_alloc: Allocator,
    file_id: u32,
    byte_start: u32,
    byte_end: u32,
    nodes: *NodeMap,
    children: *ChildMap,
) !u64 {
    var stmt = try db.prepare(
        \\SELECT id, parent_id, kind, byte_start, byte_end
        \\  FROM ast_node
        \\ WHERE file_id = ? AND byte_start >= ? AND byte_end <= ?
        \\ ORDER BY byte_start
    , gpa);
    defer stmt.finalize();
    try stmt.bindInt(1, file_id);
    try stmt.bindInt(2, byte_start);
    try stmt.bindInt(3, byte_end);

    var root: u64 = 0;
    var min_start: u32 = std.math.maxInt(u32);

    while (try stmt.step()) {
        const id: u64 = @intCast(stmt.columnInt(0));
        const pid_raw = stmt.columnInt(1);
        const pid: ?u64 = if (pid_raw == 0) null else @intCast(pid_raw);
        const kind = stmt.columnText(2) orelse "?";
        const bs: u32 = @intCast(stmt.columnInt(3));
        const be: u32 = @intCast(stmt.columnInt(4));
        // Kind text comes from sqlite's column buffer — invalid on next
        // step. Dup into the analyzer's arena so all `kind` slices are
        // arena-owned (synthetic try_exit nodes also dup into arena).
        const kind_dup = try arena_alloc.dupe(u8, kind);
        try nodes.put(id, .{
            .id = id,
            .file_id = file_id,
            .parent_id = pid,
            .kind = kind_dup,
            .byte_start = bs,
            .byte_end = be,
        });
        if (mem.eql(u8, kind, "fn_decl") and bs <= byte_start + 8 and bs < min_start) {
            root = id;
            min_start = bs;
        }
    }

    // Build children map filtered to nodes within the subtree.
    var it = nodes.iterator();
    while (it.next()) |kv| {
        const n = kv.value_ptr.*;
        if (n.parent_id) |pid| {
            if (nodes.contains(pid)) {
                const gop = try children.getOrPut(pid);
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                try gop.value_ptr.append(gpa, n.id);
            }
        }
    }

    // Sort each child list by byte_start so traversal walks the body in
    // source order. HashMap iteration order is non-deterministic and
    // non-source-order — without this sort the analyzer would see a
    // `return` BEFORE the lock-acquire `call` that precedes it on the
    // same line, breaking all leak detection.
    const SortCtx = struct {
        nodes: *NodeMap,
        fn lessThan(ctx: @This(), a: u64, b: u64) bool {
            const na = ctx.nodes.get(a).?;
            const nb = ctx.nodes.get(b).?;
            return na.byte_start < nb.byte_start;
        }
    };
    var c_it = children.iterator();
    while (c_it.next()) |kv| {
        std.sort.heap(u64, kv.value_ptr.items, SortCtx{ .nodes = nodes }, SortCtx.lessThan);
    }

    return root;
}

// Scan a `call`/`builtin_call` node's source bytes for a method-call
// pattern. Returns (chain_head_ident, method, full_chain) or null.
const CallShape = struct {
    head: []const u8,
    method: []const u8,
    chain: []const u8,
};

fn parseCallShape(call_bytes: []const u8) ?CallShape {
    // Find the LAST `.<ident>(` pattern at the outermost depth.
    var i: usize = 0;
    while (i < call_bytes.len and call_bytes[i] != '(') i += 1;
    if (i == 0 or i >= call_bytes.len) return null;
    // The receiver chain spans [0..i) and we need the last ident
    // segment as the method name.
    const recv = trimAscii(call_bytes[0..i]);
    if (recv.len == 0) return null;
    // Skip leading `try `, `errdefer `, `defer `.
    var head_text = recv;
    while (true) {
        if (mem.startsWith(u8, head_text, "try ")) {
            head_text = trimAscii(head_text[4..]);
            continue;
        }
        if (mem.startsWith(u8, head_text, "defer ")) {
            head_text = trimAscii(head_text[6..]);
            continue;
        }
        if (mem.startsWith(u8, head_text, "errdefer ")) {
            head_text = trimAscii(head_text[9..]);
            continue;
        }
        if (mem.startsWith(u8, head_text, "_ = ")) {
            head_text = trimAscii(head_text[4..]);
            continue;
        }
        break;
    }
    // head_text should now be `<chain>.<method>` (or just `<name>`).
    const last_dot = mem.lastIndexOf(u8, head_text, ".") orelse {
        // Bare call — no method.
        return null;
    };
    const chain_head_full = head_text[0..last_dot];
    const method = head_text[last_dot + 1 ..];
    if (method.len == 0 or !isIdentStart(method[0])) return null;
    for (method) |c| if (!isIdentChar(c)) return null;
    // Head ident: leftmost contiguous ident chars of chain_head_full.
    var k: usize = 0;
    while (k < chain_head_full.len and isIdentChar(chain_head_full[k])) k += 1;
    if (k == 0) return null;
    return .{
        .head = chain_head_full[0..k],
        .method = method,
        .chain = chain_head_full,
    };
}

// Walker state for path-release coverage.
const Walker = struct {
    gpa: Allocator,
    arena_alloc: Allocator,
    nodes: *NodeMap,
    children: *ChildMap,
    file: *FileInfo,
    entry: *const Entity,
    findings: *ArrayList(ReleaseFinding),

    fn nodeBytes(self: *Walker, n: AstNode) []const u8 {
        const src = self.file.source;
        if (n.byte_start > src.len or n.byte_end > src.len) return "";
        return src[n.byte_start..n.byte_end];
    }

    fn nodeLine(self: *Walker, n: AstNode) u32 {
        return byteToLine(self.file.source, n.byte_start);
    }

    fn appendActive(self: *Walker, list: *ArrayList(ActiveLock), ident: []const u8, line: u32) !void {
        for (list.items) |a| {
            if (mem.eql(u8, a.ident, ident)) return; // already tracked
        }
        try list.append(self.gpa, .{
            .ident = try self.arena_alloc.dupe(u8, ident),
            .defer_covered = false,
            .errdefer_covered = false,
            .lock_line = line,
        });
    }

    fn dropActive(list: *ArrayList(ActiveLock), ident: []const u8) void {
        var i: usize = 0;
        while (i < list.items.len) {
            if (mem.eql(u8, list.items[i].ident, ident)) {
                _ = list.orderedRemove(i);
            } else i += 1;
        }
    }

    fn markDeferCovered(list: *ArrayList(ActiveLock), ident: []const u8) void {
        for (list.items) |*a| {
            if (mem.eql(u8, a.ident, ident)) {
                a.defer_covered = true;
                return;
            }
        }
    }

    fn markErrdeferCovered(list: *ArrayList(ActiveLock), ident: []const u8) void {
        for (list.items) |*a| {
            if (mem.eql(u8, a.ident, ident)) {
                a.errdefer_covered = true;
                return;
            }
        }
    }

    fn cloneActives(self: *Walker, src: []const ActiveLock) !ArrayList(ActiveLock) {
        var dst: ArrayList(ActiveLock) = .empty;
        try dst.appendSlice(self.gpa, src);
        return dst;
    }

    /// Emit a "release missing on exit" finding per active lock not yet
    /// covered by either a defer (any path) or an errdefer (error paths).
    fn emitExitFindings(self: *Walker, actives: []const ActiveLock, exit_line: u32, is_error_path: bool) !void {
        for (actives) |a| {
            if (a.defer_covered) continue;
            if (is_error_path and a.errdefer_covered) continue;
            try self.findings.append(self.gpa, .{
                .entry_qname = self.entry.qname,
                .file_path = self.file.path,
                .line = exit_line,
                .ident = a.ident,
                .rule = "lock_no_release",
                .message = try std.fmt.allocPrint(
                    self.arena_alloc,
                    "lock acquired at L{d} for `{s}` not released before exit at L{d}",
                    .{ a.lock_line, a.ident, exit_line },
                ),
            });
        }
    }
};

// Walk a node and update actives. Returns whether the node's children
// were already walked (to avoid double-walking).
fn walkNode(
    w: *Walker,
    node_id: u64,
    actives: *ArrayList(ActiveLock),
) anyerror!void {
    const n = w.nodes.get(node_id) orelse return;
    const kind = n.kind;
    if (mem.eql(u8, kind, "if")) {
        try walkIfLike(w, node_id, actives);
        return;
    }
    if (mem.eql(u8, kind, "switch")) {
        try walkSwitch(w, node_id, actives);
        return;
    }
    if (mem.eql(u8, kind, "while") or mem.eql(u8, kind, "for")) {
        try walkLoop(w, node_id, actives);
        return;
    }
    if (mem.eql(u8, kind, "switch_prong")) {
        // Walk children with cloned actives at the caller; we're inside
        // the prong's own frame, so just descend.
        try walkChildren(w, node_id, actives);
        return;
    }
    if (mem.eql(u8, kind, "block")) {
        try walkChildren(w, node_id, actives);
        return;
    }
    if (mem.eql(u8, kind, "fn_decl")) {
        try walkChildren(w, node_id, actives);
        // No fall-through finding here. A fn body's tail position is
        // either an explicit `return`, an exhaustive `switch`/`if`-
        // chain, or a `noreturn` call — all of which are handled by
        // their own AST kind. Synthesizing a fall-through exit at
        // `fn.byte_end` produces false positives when the last stmt is
        // an exhaustive switch (legacy analyzer also scoped exits to
        // explicit `return`/`try` events, not synthetic block-end).
        return;
    }
    if (mem.eql(u8, kind, "var_decl")) {
        // var x = <call>(...). The init expression's children include
        // the `call` AST node; descend so acquires-on-init are detected.
        try walkChildren(w, node_id, actives);
        return;
    }
    if (mem.eql(u8, kind, "defer")) {
        // The defer's body is a child node — typically a `call` whose
        // bytes are `<x>.unlock(...)`. We mark all matching idents as
        // defer-covered.
        try inspectDeferBody(w, node_id, actives, false);
        return;
    }
    if (mem.eql(u8, kind, "errdefer")) {
        try inspectDeferBody(w, node_id, actives, true);
        return;
    }
    if (mem.eql(u8, kind, "try_exit")) {
        // Synthetic node for `try X` — the operand may propagate an
        // error, so any active lock not covered by an errdefer (or
        // defer) leaks here. Don't drop actives: the success path
        // continues holding the lock.
        const exit_line = byteToLine(w.file.source, n.byte_start);
        try w.emitExitFindings(actives.items, exit_line, true);
        return;
    }
    if (mem.eql(u8, kind, "return")) {
        // Check coverage at this exit. Determine error-vs-success path
        // via return value bytes (presence of `return error.` or just
        // bare `return`).
        const rb = w.nodeBytes(n);
        const trimmed = trimAscii(rb);
        const is_err_path = mem.indexOf(u8, trimmed, "error.") != null or
            mem.endsWith(u8, trimmed, "!void");
        const exit_line = byteToLine(w.file.source, n.byte_start);
        // Walk return's children (the returned expr might be a `lock()
        // orelse return -2` or similar — the call inside affects state).
        try walkChildren(w, node_id, actives);
        // orelse / catch heuristic: if the return is on the same line as
        // a still-active lock acquire, it's the failure branch of an
        // `<x>.lock() orelse return ...` pattern and the lock was NOT
        // actually acquired. Skip exit findings for actives whose
        // lock_line equals this return's line.
        if (actives.items.len == 0) return;
        var filtered_actives: ArrayList(ActiveLock) = .empty;
        defer filtered_actives.deinit(w.gpa);
        for (actives.items) |a| {
            if (a.lock_line == exit_line) continue;
            try filtered_actives.append(w.gpa, a);
        }
        try w.emitExitFindings(filtered_actives.items, exit_line, is_err_path);
        return;
    }
    if (mem.eql(u8, kind, "call") or mem.eql(u8, kind, "builtin_call")) {
        // Inspect for lock/unlock action on this call.
        const cb = w.nodeBytes(n);
        const shape = parseCallShape(cb);
        if (shape) |sh| {
            if (isAnyAcquire(sh.method)) {
                try w.appendActive(actives, sh.head, w.nodeLine(n));
            } else if (isAnyRelease(sh.method)) {
                Walker.dropActive(actives, sh.head);
            }
        }
        // `try X()` — the call may propagate. Detect by looking back at
        // the source bytes immediately before n.byte_start for `try `.
        if (n.byte_start >= 4) {
            const before = w.file.source[n.byte_start - 4 .. n.byte_start];
            if (mem.eql(u8, before, "try ")) {
                // Treat as an error-path exit: any lock not covered by
                // an errdefer (or defer) leaks here.
                const exit_line = w.nodeLine(n);
                try w.emitExitFindings(actives.items, exit_line, true);
            }
        }
        try walkChildren(w, node_id, actives);
        return;
    }

    // Default: walk children.
    try walkChildren(w, node_id, actives);
}

fn walkChildren(w: *Walker, node_id: u64, actives: *ArrayList(ActiveLock)) anyerror!void {
    const list = w.children.get(node_id) orelse return;
    for (list.items) |cid| {
        try walkNode(w, cid, actives);
    }
}

fn walkIfLike(w: *Walker, node_id: u64, actives: *ArrayList(ActiveLock)) anyerror!void {
    // The indexer emits if as: condition, then, else children (in source
    // order). The condition rarely has structural sub-nodes (a typical
    // `cond != 0` lowers to no descendant nodes); branch bodies do.
    // Conservatively, walk every child with a cloned `actives` snapshot
    // so a return inside any branch doesn't bleed lock state into the
    // sibling. State changes inside a condition (e.g. side-effecting
    // `try foo()`) still get observed because we clone-and-walk that
    // first child too — but its writes don't propagate. This matches
    // the legacy analyzer's behavior of treating each branch as
    // independently-walked.
    const list = w.children.get(node_id) orelse return;
    for (list.items) |cid| {
        var clone = try w.cloneActives(actives.items);
        defer clone.deinit(w.gpa);
        try walkNode(w, cid, &clone);
    }
}

fn walkSwitch(w: *Walker, node_id: u64, actives: *ArrayList(ActiveLock)) anyerror!void {
    const list = w.children.get(node_id) orelse return;
    for (list.items) |cid| {
        var clone = try w.cloneActives(actives.items);
        defer clone.deinit(w.gpa);
        try walkNode(w, cid, &clone);
    }
}

fn walkLoop(w: *Walker, node_id: u64, actives: *ArrayList(ActiveLock)) anyerror!void {
    const list = w.children.get(node_id) orelse return;
    for (list.items) |cid| {
        var clone = try w.cloneActives(actives.items);
        defer clone.deinit(w.gpa);
        try walkNode(w, cid, &clone);
    }
}

// Inspect a defer/errdefer node's body. The body call (often
// `ref.unlock(...)`) is one of the descendants.
fn inspectDeferBody(
    w: *Walker,
    node_id: u64,
    actives: *ArrayList(ActiveLock),
    is_errdefer: bool,
) anyerror!void {
    // Find any `call` descendant whose method is a release.
    var stack: ArrayList(u64) = .empty;
    defer stack.deinit(w.gpa);
    try stack.append(w.gpa, node_id);
    while (stack.items.len > 0) {
        const cur = stack.pop().?;
        const n = w.nodes.get(cur) orelse continue;
        if (mem.eql(u8, n.kind, "call")) {
            const cb = w.nodeBytes(n);
            const shape = parseCallShape(cb);
            if (shape) |sh| {
                if (isAnyRelease(sh.method)) {
                    if (is_errdefer) {
                        Walker.markErrdeferCovered(actives, sh.head);
                    } else {
                        Walker.markDeferCovered(actives, sh.head);
                    }
                }
            }
        }
        if (w.children.get(cur)) |kids| {
            for (kids.items) |k| try stack.append(w.gpa, k);
        }
    }
}

fn analyzeEntryRelease(
    db: *sqlite.Db,
    st: *State,
    entry: *const Entity,
    findings: *ArrayList(ReleaseFinding),
) !void {
    const f = fileById(st, entry.file_id) orelse return;

    // Node `kind` strings live in the analyzer's arena (loaded by
    // loadFnSubtree, freed when the arena resets at process exit).
    var nodes = NodeMap.init(st.gpa);
    defer nodes.deinit();
    var children = ChildMap.init(st.gpa);
    defer {
        var cit = children.valueIterator();
        while (cit.next()) |al| al.deinit(st.gpa);
        children.deinit();
    }

    const root = try loadFnSubtree(db, st.gpa, st.arena.allocator(), entry.file_id, entry.byte_start, entry.byte_end, &nodes, &children);
    if (root == 0) return;

    // Synthesize implicit error-path exits for `try X` constructs. The
    // indexer's AST pass doesn't currently descend into `.@"try"`, so
    // its operand call has no AST node — we'd miss the leak in fixture
    // 02 (`_ = try fallible();`). We patch around it by querying every
    // `keyword_try` token within the entry's byte range and inserting a
    // synthetic `try_exit` AST node parented under the nearest
    // ancestor block. The walker treats `try_exit` like a return on
    // the error path: emit findings for any active locks not covered
    // by an errdefer or defer.
    var try_lines: ArrayList(u32) = .empty;
    defer try_lines.deinit(st.gpa);
    {
        var stmt = try db.prepare(
            \\SELECT byte_start FROM token
            \\ WHERE file_id = ? AND kind = 'keyword_try'
            \\   AND byte_start >= ? AND byte_start <= ?
            \\ ORDER BY byte_start
        , st.gpa);
        defer stmt.finalize();
        try stmt.bindInt(1, entry.file_id);
        try stmt.bindInt(2, entry.byte_start);
        try stmt.bindInt(3, entry.byte_end);
        while (try stmt.step()) {
            const bs: u32 = @intCast(stmt.columnInt(0));
            try try_lines.append(st.gpa, bs);
        }
    }
    // Insert synthetic try_exit nodes into the tree. Each one becomes a
    // child of the smallest enclosing block in the loaded subtree.
    var next_synth_id: u64 = std.math.maxInt(u32) + 1; // namespace above real ids
    for (try_lines.items) |try_byte| {
        var best_block: ?u64 = null;
        var best_span: u32 = std.math.maxInt(u32);
        var nit = nodes.iterator();
        while (nit.next()) |kv| {
            const nn = kv.value_ptr.*;
            if (!mem.eql(u8, nn.kind, "block")) continue;
            if (try_byte < nn.byte_start or try_byte >= nn.byte_end) continue;
            const span = nn.byte_end - nn.byte_start;
            if (span < best_span) {
                best_span = span;
                best_block = nn.id;
            }
        }
        const block_id = best_block orelse continue;
        // Insert synthetic node.
        const id = next_synth_id;
        next_synth_id += 1;
        try nodes.put(id, .{
            .id = id,
            .file_id = entry.file_id,
            .parent_id = block_id,
            .kind = try st.arena.allocator().dupe(u8, "try_exit"),
            .byte_start = try_byte,
            .byte_end = try_byte + 4,
        });
        // Append to block's child list and re-sort by byte_start.
        const gop = try children.getOrPut(block_id);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(st.gpa, id);
    }
    // Re-sort child lists touched by the synthetic insertion.
    if (try_lines.items.len > 0) {
        const SortCtx = struct {
            nodes: *NodeMap,
            fn lessThan(ctx: @This(), a: u64, b: u64) bool {
                const na = ctx.nodes.get(a).?;
                const nb = ctx.nodes.get(b).?;
                return na.byte_start < nb.byte_start;
            }
        };
        var c_it = children.iterator();
        while (c_it.next()) |kv| {
            std.sort.heap(u64, kv.value_ptr.items, SortCtx{ .nodes = &nodes }, SortCtx.lessThan);
        }
    }

    var w = Walker{
        .gpa = st.gpa,
        .arena_alloc = st.arena.allocator(),
        .nodes = &nodes,
        .children = &children,
        .file = f,
        .entry = entry,
        .findings = findings,
    };
    var actives: ArrayList(ActiveLock) = .empty;
    defer actives.deinit(st.gpa);
    try walkNode(&w, root, &actives);
}

// ── Check 6: IRQ-discipline ────────────────────────────────────────────
//
// Scope simplification vs. legacy: we operate on pre-built reachability
// from entry_point + ir_call. For each fn entity the kernel has, we
// determine:
//   (a) whether it is reached from any IRQ entry (per IRQ_ENTRY_DECLS by
//       short-name match against entry_point.label).
//   (b) the set of acquire sites in its body.
// Then for each acquire site whose lock class is also acquired from an
// IRQ-async/NMI entry, we apply rules a/b/c (see legacy doc above).

const IrqAcquireSite = struct {
    file_path: []const u8,
    line: u32,
    class_id: []const u8, // owned
    method: []const u8, // owned
    is_irq_save: bool,
    fn_name: []const u8, // short name of enclosing fn
    fn_entity_id: u32,
    syntactic_save_bracket: bool,
};

const IrqReleaseSite = struct {
    file_path: []const u8,
    line: u32,
    class_id: []const u8,
    method: []const u8,
    is_irq_restore: bool,
    fn_entity_id: u32,
    receiver: []const u8,
};

// Pull all kernel function entities + their body bytes.
const FnRow = struct {
    id: u32,
    qname: []const u8,
    short: []const u8,
    file_id: u32,
    byte_start: u32,
    byte_end: u32,
    body: []const u8,
};

fn loadFnRows(db: *sqlite.Db, st: *State) !ArrayList(FnRow) {
    var out: ArrayList(FnRow) = .empty;
    const a = st.arena.allocator();
    var stmt = try db.prepare(
        \\SELECT id, qualified_name, def_file_id, def_byte_start, def_byte_end
        \\  FROM entity
        \\ WHERE kind = 'fn'
    , st.gpa);
    defer stmt.finalize();
    while (try stmt.step()) {
        const id: u32 = @intCast(stmt.columnInt(0));
        const q = stmt.columnText(1) orelse continue;
        const fid: u32 = @intCast(stmt.columnInt(2));
        const bs: u32 = @intCast(stmt.columnInt(3));
        const be: u32 = @intCast(stmt.columnInt(4));
        const f = fileById(st, fid) orelse continue;
        const body = spanBytes(st, fid, bs, be);
        const qname_dup = try a.dupe(u8, q);
        try out.append(st.gpa, .{
            .id = id,
            .qname = qname_dup,
            .short = shortName(qname_dup),
            .file_id = fid,
            .byte_start = bs,
            .byte_end = be,
            .body = body,
        });
        _ = f;
    }
    return out;
}

// Strip Zig comments from a source slice (cheap, in-place into a new
// arena buffer). Used by the IRQ scanner for line-based pattern matching
// without false-positives in commented-out code.
fn stripComments(arena_alloc: Allocator, src: []const u8) ![]u8 {
    const buf = try arena_alloc.alloc(u8, src.len);
    @memcpy(buf, src);
    var i: usize = 0;
    while (i + 1 < buf.len) : (i += 1) {
        if (buf[i] == '/' and buf[i + 1] == '/') {
            // Erase to next newline.
            var j: usize = i;
            while (j < buf.len and buf[j] != '\n') : (j += 1) {
                buf[j] = ' ';
            }
            i = j;
        }
    }
    return buf;
}

// Scan one fn body for acquire/release sites. The lock-class id is a
// best-effort string: for `<x>.lock()` we use `<x>.lock_class` derived
// from the method's receiver chain. Without full type inference, we
// fall back to the literal receiver text. This matches the legacy
// analyzer's behavior — over-conservative grouping is acceptable.
fn scanFnIrq(
    st: *State,
    fn_row: *const FnRow,
    arena_alloc: Allocator,
    acquires: *ArrayList(IrqAcquireSite),
    releases: *ArrayList(IrqReleaseSite),
    callees_out: *ArrayList([]const u8),
) !void {
    const f = fileById(st, fn_row.file_id) orelse return;
    const stripped = try stripComments(arena_alloc, fn_row.body);
    // Detect saveAndDisableInterrupts/restoreInterrupts presence.
    const has_save = mem.indexOf(u8, stripped, "saveAndDisableInterrupts(") != null;
    const has_restore = mem.indexOf(u8, stripped, "restoreInterrupts(") != null;
    const syntactic_save_bracket = has_save and has_restore;

    // Walk byte-by-byte for `.<method>(`.
    var p: usize = 0;
    while (p < stripped.len) : (p += 1) {
        if (stripped[p] != '.') continue;
        const ms = p + 1;
        if (ms >= stripped.len or !isIdentStart(stripped[ms])) continue;
        var me = ms;
        while (me < stripped.len and isIdentChar(stripped[me])) me += 1;
        const method = stripped[ms..me];
        var q = me;
        while (q < stripped.len and ascii.isWhitespace(stripped[q])) q += 1;
        if (q >= stripped.len or stripped[q] != '(') continue;
        const is_acq = isAnyAcquire(method);
        const is_rel = isAnyRelease(method);
        if (!is_acq and !is_rel) continue;

        // Walk back through ident/dot chars for receiver chain.
        var s: usize = p;
        while (s > 0) {
            const cc = stripped[s - 1];
            if (isIdentChar(cc) or cc == '.') {
                s -= 1;
            } else break;
        }
        if (s == p) continue;
        var recv_chain = stripped[s..p];
        if (recv_chain.len >= 2 and
            recv_chain[recv_chain.len - 2] == '.' and
            recv_chain[recv_chain.len - 1] == '?')
        {
            recv_chain = recv_chain[0 .. recv_chain.len - 2];
        }
        if (recv_chain.len == 0) continue;

        // Class id: literal chain text (best-effort grouping).
        const class_id = try arena_alloc.dupe(u8, recv_chain);
        const method_dup = try arena_alloc.dupe(u8, method);
        const line = byteToLine(f.source, fn_row.byte_start + @as(u32, @intCast(p)));

        if (is_acq) {
            try acquires.append(st.gpa, .{
                .file_path = f.path,
                .line = line,
                .class_id = class_id,
                .method = method_dup,
                .is_irq_save = isIrqSaveAcquire(method),
                .fn_name = fn_row.short,
                .fn_entity_id = fn_row.id,
                .syntactic_save_bracket = syntactic_save_bracket,
            });
        } else {
            try releases.append(st.gpa, .{
                .file_path = f.path,
                .line = line,
                .class_id = class_id,
                .method = method_dup,
                .is_irq_restore = isIrqRestoreRelease(method),
                .fn_entity_id = fn_row.id,
                .receiver = try arena_alloc.dupe(u8, recv_chain),
            });
        }
        p = q;
    }

    // Scan callee names: `<ident>(` outside of comments. Last segment
    // of dotted forms is the basename.
    var seen = StringHashMap(void).init(st.gpa);
    defer seen.deinit();
    p = 0;
    while (p < stripped.len) {
        if (!isIdentStart(stripped[p])) {
            p += 1;
            continue;
        }
        if (p > 0) {
            const pc = stripped[p - 1];
            if (isIdentChar(pc) or pc == '.' or pc == '@') {
                p += 1;
                continue;
            }
        }
        var e = p;
        while (e < stripped.len and (isIdentChar(stripped[e]) or stripped[e] == '.')) e += 1;
        const fq = stripped[p..e];
        var q = e;
        while (q < stripped.len and ascii.isWhitespace(stripped[q])) q += 1;
        if (q >= stripped.len or stripped[q] != '(') {
            p = e;
            continue;
        }
        var name = fq;
        if (mem.lastIndexOfScalar(u8, fq, '.')) |ld| name = fq[ld + 1 ..];
        if (name.len == 0 or !isIdentStart(name[0])) {
            p = e;
            continue;
        }
        // Skip Zig keywords/builtins.
        const kw_skip = [_][]const u8{
            "if", "else", "while", "for", "switch", "return", "defer",
            "errdefer", "try", "catch", "orelse", "comptime", "fn",
            "const", "var", "pub", "test", "and", "or",
        };
        if (inList(name, &kw_skip)) {
            p = e;
            continue;
        }
        if (mem.startsWith(u8, fq, "@")) {
            p = e;
            continue;
        }
        const gop = try seen.getOrPut(name);
        if (!gop.found_existing) {
            try callees_out.append(st.gpa, try arena_alloc.dupe(u8, name));
        }
        p = e;
    }
}

// ── CLI driver ─────────────────────────────────────────────────────────

const Args = struct {
    db_path: ?[]const u8 = null,
    summary: bool = false,
    verbose: bool = false,
    entry_filter: ?[]const u8 = null,
    rule_filter: ?[]const u8 = null,
    print_help: bool = false,
    list_slab_types: bool = false,
};

fn parseArgs(gpa: Allocator) !Args {
    _ = gpa;
    var args = Args{};
    var it = std.process.args();
    _ = it.next();
    while (it.next()) |a| {
        if (mem.eql(u8, a, "--db")) {
            if (it.next()) |v| args.db_path = v;
        } else if (mem.eql(u8, a, "--summary")) {
            args.summary = true;
        } else if (mem.eql(u8, a, "--verbose") or mem.eql(u8, a, "-v")) {
            args.verbose = true;
        } else if (mem.eql(u8, a, "--entry")) {
            if (it.next()) |v| args.entry_filter = v;
        } else if (mem.eql(u8, a, "--rule")) {
            if (it.next()) |v| args.rule_filter = v;
        } else if (mem.eql(u8, a, "--list-slab-types")) {
            args.list_slab_types = true;
        } else if (mem.eql(u8, a, "--help") or mem.eql(u8, a, "-h")) {
            args.print_help = true;
        }
    }
    return args;
}

fn printHelp(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\Usage: check_gen_lock --db <oracle.db> [options]
        \\
        \\SQL-backed gen-lock analyzer. Reads tokens, AST, entities, entry
        \\points, and ir_call from the per-(arch, commit_sha) DB built by
        \\tools/indexer.
        \\
        \\Options:
        \\  --db PATH             oracle DB path (required)
        \\  --summary             one line per entry with finding counts
        \\  --verbose, -v         per-ident access and lock-op summary
        \\  --entry NAME          drill into a single handler
        \\  --rule RULE           filter findings to a single rule
        \\  --list-slab-types     print discovered slab-backed types and exit
        \\  --help, -h            show this help
        \\
        \\Exit status is nonzero if any err-severity findings are emitted.
        \\
    );
}

pub fn main() !u8 {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_impl.deinit();
    const gpa = gpa_impl.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_w = std.fs.File.stdout().writer(&stdout_buf);
    const w = &stdout_w.interface;

    const args = try parseArgs(gpa);
    if (args.print_help) {
        try printHelp(w);
        try w.flush();
        return 0;
    }
    const db_path = args.db_path orelse {
        try w.writeAll("error: --db PATH required (run tools/indexer first)\n");
        try printHelp(w);
        try w.flush();
        return 2;
    };

    var db = sqlite.Db.openReadOnly(db_path, gpa) catch |e| {
        try w.print("error: failed to open DB {s}: {s}\n", .{ db_path, @errorName(e) });
        try w.flush();
        return 2;
    };
    defer db.close();

    var st = State.init(gpa);
    defer st.deinit();

    try loadFiles(&db, &st);
    try loadSlabTypes(&db, &st);
    try collectSlabFieldNames(&db, &st);
    try loadEntryPoints(&db, &st);

    if (args.list_slab_types) {
        try w.writeAll("Slab-backed types:\n");
        var names: ArrayList([]const u8) = .empty;
        defer names.deinit(gpa);
        var it = st.slab_types.keyIterator();
        while (it.next()) |k| try names.append(gpa, k.*);
        std.sort.heap([]const u8, names.items, {}, lessStr);
        for (names.items) |nm| try w.print("  {s}\n", .{nm});
        try w.flush();
        return 0;
    }

    // ── Fat-pointer field check ────────────────────────────────────────
    var bare_findings: ArrayList(BarePtrFinding) = .empty;
    defer bare_findings.deinit(gpa);
    try checkFatPointerFields(&db, &st, &bare_findings);
    std.sort.heap(BarePtrFinding, bare_findings.items, {}, lessBarePtr);

    // ── `.ptr` bypass check ────────────────────────────────────────────
    var ptr_findings: ArrayList(PtrBypassFinding) = .empty;
    defer ptr_findings.deinit(gpa);
    try checkPtrBypasses(&db, &st, &ptr_findings);

    // ── Per-entry release coverage ─────────────────────────────────────
    var release_findings: ArrayList(ReleaseFinding) = .empty;
    defer release_findings.deinit(gpa);

    var entries_by_qname: ArrayList(*Entity) = .empty;
    defer entries_by_qname.deinit(gpa);
    for (st.entry_points.items) |*e| {
        if (args.entry_filter) |f| {
            if (!mem.eql(u8, shortName(e.qname), f)) continue;
        }
        try entries_by_qname.append(gpa, e);
    }

    for (entries_by_qname.items) |entry| {
        try analyzeEntryRelease(&db, &st, entry, &release_findings);
    }

    // ── IRQ-discipline ────────────────────────────────────────────────
    const irq_arena_alloc = st.arena.allocator();
    var fn_rows = try loadFnRows(&db, &st);
    defer fn_rows.deinit(gpa);

    var acquires: ArrayList(IrqAcquireSite) = .empty;
    defer acquires.deinit(gpa);
    var releases: ArrayList(IrqReleaseSite) = .empty;
    defer releases.deinit(gpa);

    // Per-fn callee names (for transitive reachability).
    const fn_callees = try gpa.alloc(ArrayList([]const u8), fn_rows.items.len);
    defer {
        for (fn_callees) |*c| c.deinit(gpa);
        gpa.free(fn_callees);
    }
    for (fn_callees) |*c| c.* = .empty;

    var fn_acquires_idx = try gpa.alloc(ArrayList(u32), fn_rows.items.len);
    defer {
        for (fn_acquires_idx) |*c| c.deinit(gpa);
        gpa.free(fn_acquires_idx);
    }
    for (fn_acquires_idx) |*c| c.* = .empty;

    for (fn_rows.items, 0..) |*fr, i| {
        const acq_before = acquires.items.len;
        try scanFnIrq(&st, fr, irq_arena_alloc, &acquires, &releases, &fn_callees[i]);
        const acq_after = acquires.items.len;
        var k: usize = acq_before;
        while (k < acq_after) : (k += 1) {
            try fn_acquires_idx[i].append(gpa, @intCast(k));
        }
    }

    // Build name → fn-index map.
    var fn_by_short = StringHashMap(ArrayList(u32)).init(gpa);
    defer {
        var it = fn_by_short.valueIterator();
        while (it.next()) |al| al.deinit(gpa);
        fn_by_short.deinit();
    }
    for (fn_rows.items, 0..) |fr, i| {
        const gop = try fn_by_short.getOrPut(fr.short);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(gpa, @intCast(i));
    }

    // BFS reachability from IRQ-entry fns.
    const reached_from_irq = try gpa.alloc(u8, fn_rows.items.len);
    defer gpa.free(reached_from_irq);
    @memset(reached_from_irq, 0);

    for (IRQ_ENTRY_DECLS) |decl| {
        const kind_bit: u8 = @as(u8, 1) << @intFromEnum(decl.kind);
        const list_opt = fn_by_short.get(decl.name) orelse continue;
        var queue: ArrayList(u32) = .empty;
        defer queue.deinit(gpa);
        var visited = std.AutoHashMap(u32, void).init(gpa);
        defer visited.deinit();
        for (list_opt.items) |idx| {
            try queue.append(gpa, idx);
            try visited.put(idx, {});
        }
        var qi: usize = 0;
        while (qi < queue.items.len) : (qi += 1) {
            const idx = queue.items[qi];
            reached_from_irq[idx] |= kind_bit;
            for (fn_callees[idx].items) |cn| {
                const cl = fn_by_short.get(cn) orelse continue;
                for (cl.items) |cidx| {
                    const v = try visited.getOrPut(cidx);
                    if (v.found_existing) continue;
                    try queue.append(gpa, cidx);
                }
            }
        }
    }

    // IRQ-acquired classes: any class id whose acquire is reached from
    // an IRQ entry, with kind bitmask.
    var irq_classes = StringHashMap(u8).init(gpa);
    defer irq_classes.deinit();
    for (acquires.items) |acq| {
        // Find owning fn idx.
        var fn_idx: ?usize = null;
        for (fn_rows.items, 0..) |fr, i| {
            if (fr.id == acq.fn_entity_id) {
                fn_idx = i;
                break;
            }
        }
        const fi = fn_idx orelse continue;
        const bits = reached_from_irq[fi];
        if (bits == 0) continue;
        const gop = try irq_classes.getOrPut(acq.class_id);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* |= bits;
    }

    // Discipline + pairing findings.
    const masked_kind_bits: u8 =
        (@as(u8, 1) << @intFromEnum(IrqEntryKind.irq_async)) |
        (@as(u8, 1) << @intFromEnum(IrqEntryKind.nmi)) |
        (@as(u8, 1) << @intFromEnum(IrqEntryKind.irq_unexpected));

    var n_discipline: u32 = 0;
    var n_pairing: u32 = 0;

    var discipline_lines: ArrayList([]u8) = .empty;
    defer {
        for (discipline_lines.items) |l| gpa.free(l);
        discipline_lines.deinit(gpa);
    }
    var pairing_lines: ArrayList([]u8) = .empty;
    defer {
        for (pairing_lines.items) |l| gpa.free(l);
        pairing_lines.deinit(gpa);
    }

    for (acquires.items) |acq| {
        if (!irq_classes.contains(acq.class_id)) continue;
        // Find owning fn idx.
        var fn_idx: usize = 0;
        for (fn_rows.items, 0..) |fr, i| {
            if (fr.id == acq.fn_entity_id) {
                fn_idx = i;
                break;
            }
        }
        if (reached_from_irq[fn_idx] & masked_kind_bits != 0) continue;
        if (acq.is_irq_save) continue;
        if (acq.syntactic_save_bracket) continue;
        n_discipline += 1;
        const ln = try std.fmt.allocPrint(
            gpa,
            "  {s}:{d}  ({s}) currently uses {s} on class {s}\n",
            .{ acq.file_path, acq.line, acq.fn_name, acq.method, acq.class_id },
        );
        try discipline_lines.append(gpa, ln);
    }

    // Pairing: per-fn, walk acquire/release events in source-line order.
    for (fn_rows.items, 0..) |fr, fi| {
        _ = fr;
        const Ev = struct { line: u32, is_acq: bool, idx: u32 };
        var evs: ArrayList(Ev) = .empty;
        defer evs.deinit(gpa);
        for (fn_acquires_idx[fi].items) |aidx| {
            try evs.append(gpa, .{ .line = acquires.items[aidx].line, .is_acq = true, .idx = aidx });
        }
        // Find releases owned by this fn.
        for (releases.items, 0..) |rel, ridx| {
            if (rel.fn_entity_id != fn_rows.items[fi].id) continue;
            try evs.append(gpa, .{ .line = rel.line, .is_acq = false, .idx = @intCast(ridx) });
        }
        std.sort.heap(Ev, evs.items, {}, struct {
            fn lt(_: void, a: Ev, b: Ev) bool {
                if (a.line != b.line) return a.line < b.line;
                return a.is_acq and !b.is_acq;
            }
        }.lt);
        var pending = StringHashMap(ArrayList(u32)).init(gpa);
        defer {
            var pit = pending.valueIterator();
            while (pit.next()) |al| al.deinit(gpa);
            pending.deinit();
        }
        for (evs.items) |ev| {
            if (ev.is_acq) {
                const acq = acquires.items[ev.idx];
                const gop = try pending.getOrPut(acq.class_id);
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                try gop.value_ptr.append(gpa, ev.idx);
            } else {
                const rel = releases.items[ev.idx];
                const lst_opt = pending.getPtr(rel.class_id);
                if (lst_opt == null) continue;
                if (lst_opt.?.items.len == 0) continue;
                const last_aidx = lst_opt.?.pop().?;
                const acq = acquires.items[last_aidx];
                if (acq.is_irq_save and !rel.is_irq_restore) {
                    n_pairing += 1;
                    const ln = try std.fmt.allocPrint(gpa,
                        "  {s}:{d}  release={s} (acquire L{d} was {s} — IrqSave/Restore mismatch)\n",
                        .{ rel.file_path, rel.line, rel.method, acq.line, acq.method });
                    try pairing_lines.append(gpa, ln);
                } else if (!acq.is_irq_save and rel.is_irq_restore) {
                    n_pairing += 1;
                    const ln = try std.fmt.allocPrint(gpa,
                        "  {s}:{d}  release={s} (acquire L{d} was {s} — Plain/IrqRestore mismatch)\n",
                        .{ rel.file_path, rel.line, rel.method, acq.line, acq.method });
                    try pairing_lines.append(gpa, ln);
                }
            }
        }
    }

    // ── Output ────────────────────────────────────────────────────────
    var total_errs: u32 = 0;

    // Per-entry release findings.
    for (release_findings.items) |rf| {
        if (args.rule_filter) |rf_filter| {
            if (!mem.eql(u8, rf_filter, rf.rule)) continue;
        }
        if (!args.summary) {
            try w.print("\n=== {s}\n", .{rf.entry_qname});
            try w.print("    [ERR ] L{d}: {s}\n", .{ rf.line, rf.message });
        }
        total_errs += 1;
    }
    // For summary mode, emit one line per entry that has findings.
    // Mirroring the legacy analyzer: entries with no env-tracked idents
    // and no findings are silently skipped, so the runner's `head -n1`
    // pattern lands on the total `Summary:` line for clean fixtures.
    if (args.summary) {
        for (entries_by_qname.items) |entry| {
            var errs: u32 = 0;
            for (release_findings.items) |rf| {
                if (mem.eql(u8, rf.entry_qname, entry.qname)) errs += 1;
            }
            if (errs == 0) continue;
            const sn = shortName(entry.qname);
            try w.print(
                "{s:<34}tracked={d:>2}  err={d:>2}  info={d:>2}  [{s}:{d}]\n",
                .{ sn, @as(u32, 0), errs, @as(u32, 0), pathOfFile(&st, entry.file_id), entry.line },
            );
        }
    }

    // Bare-pointer findings.
    if (bare_findings.items.len > 0) {
        try w.writeAll("\n");
        try w.print("Fat-pointer invariant violations ({d} bare *T fields for slab-backed T):\n", .{bare_findings.items.len});
        for (bare_findings.items) |f| {
            try w.print("  [ERR ] {s}:{d}  {s}.{s}: {s}  → use SlabRef({s})\n", .{
                f.file_path, f.line, f.struct_name, f.field_name, f.field_type, f.slab_type,
            });
        }
    }
    total_errs += @intCast(bare_findings.items.len);

    // .ptr bypass.
    if (ptr_findings.items.len > 0) {
        try w.writeAll("\n");
        try w.print("SlabRef `.ptr` bypass ({d} sites):\n", .{ptr_findings.items.len});
        for (ptr_findings.items) |f| {
            try w.print("  [ERR ] {s}:{d}  {s}  →  use `<ref>.lock()` / `<ref>.unlock()` bracket\n", .{ f.file_path, f.line, f.chain });
            const trunc_len = @min(f.context.len, 120);
            try w.print("         {s}\n", .{f.context[0..trunc_len]});
        }
    }
    total_errs += @intCast(ptr_findings.items.len);

    try w.writeAll("\n");
    try w.print("Summary: {d} entries, {d} tracked idents, {d} err, {d} info\n", .{
        entries_by_qname.items.len,
        @as(u32, 0),
        total_errs,
        @as(u32, 0),
    });
    try w.print("         {d} slab-backed types discovered\n", .{st.slab_types.count()});
    try w.print("         {d} bare-pointer fat-pointer violations\n", .{bare_findings.items.len});
    try w.print("         {d} `.ptr` bypass sites\n", .{ptr_findings.items.len});

    // IRQ-discipline output.
    try w.writeAll("\n=== IRQ-acquired lock classes ===\n");
    if (irq_classes.count() == 0) {
        try w.writeAll("  (none — no lock class is reachable from any IRQ / NMI / async-trap entry)\n");
    } else {
        var class_keys: ArrayList([]const u8) = .empty;
        defer class_keys.deinit(gpa);
        var ck_it = irq_classes.keyIterator();
        while (ck_it.next()) |k| try class_keys.append(gpa, k.*);
        std.sort.heap([]const u8, class_keys.items, {}, lessStr);
        for (class_keys.items) |class_id| {
            const kinds = irq_classes.get(class_id).?;
            try w.print("class  {s}  reachable_from=", .{class_id});
            try renderKindList(w, kinds);
            try w.writeAll("\n");
        }
    }
    if (discipline_lines.items.len > 0) {
        try w.writeAll("  acquire sites needing IRQ-save discipline:\n");
        for (discipline_lines.items) |ln| try w.writeAll(ln);
    }
    if (pairing_lines.items.len > 0) {
        try w.writeAll("\n=== Pairing violations ===\n");
        for (pairing_lines.items) |ln| try w.writeAll(ln);
    }
    try w.print(
        "\nIRQ-discipline summary: {d} IRQ-acquired classes, {d} discipline violations, {d} pairing violations\n",
        .{ @as(u32, @intCast(irq_classes.count())), n_discipline, n_pairing },
    );

    total_errs += n_discipline + n_pairing;

    try w.flush();
    if (total_errs > 0) return 1;
    return 0;
}

// Sort helpers ────────────────────────────────────────────────────────

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

fn pathOfFile(st: *State, file_id: u32) []const u8 {
    if (st.files_by_id.get(file_id)) |f| return f.path;
    return "?";
}

fn lessBarePtr(_: void, a: BarePtrFinding, b: BarePtrFinding) bool {
    const c = mem.order(u8, a.file_path, b.file_path);
    if (c == .lt) return true;
    if (c == .gt) return false;
    return a.line < b.line;
}

fn renderKindList(w: *std.Io.Writer, kinds: u8) !void {
    try w.writeAll("[");
    var first = true;
    inline for (.{ IrqEntryKind.irq_async, IrqEntryKind.nmi, IrqEntryKind.trap_sync, IrqEntryKind.irq_unexpected }) |k| {
        const bit: u8 = @as(u8, 1) << @intFromEnum(k);
        if (kinds & bit != 0) {
            if (!first) try w.writeAll(", ");
            try w.writeAll(k.label());
            first = false;
        }
    }
    try w.writeAll("]");
}
