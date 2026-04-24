//! Static analyzer for SecureSlab gen-lock coverage / scoping.
//!
//! Uses std.zig.Tokenizer so the analyzer sees real tokens instead of
//! raw source text — comment stripping, string-literal awareness,
//! paren/brace depth, and decl boundaries all come from the tokenizer
//! instead of hand-rolled regex.
//!
//! Design:
//!
//!   1. Discover slab-backed types — `pub const X = SecureSlab(T, N)`
//!      exposes T. Struct defs containing `_gen_lock: GenLock` (the
//!      allocator stamp) are also marked slab-backed for coverage.
//!
//!   2. Fat-pointer invariant — struct fields with type `*T` / `?*T` /
//!      `[N]*T` / `[]*T` for slab-backed T are violations (must be
//!      `SlabRef(T)`).
//!
//!   3. `.ptr` bypass — `<chain>.<slabref_field>.ptr` where <field> is
//!      a known SlabRef-typed field. Exempted by `// self-alive`
//!      comment on the line or in the contiguous `//` block above;
//!      identity compares are also exempt.
//!
//!   4. Per-entry gen-lock bracketing — every access to a slab-typed
//!      local in a syscall / exception handler must be tight-preceded
//!      by a lock and tight-followed by an unlock on the same ident.
//!      Each function body walks ONCE with its own fresh ident env; at
//!      call sites the callee's memoized per-param summary is folded
//!      into the caller's event timeline at the real call-site source
//!      line. Callee-internal locals stay internal to the callee — no
//!      inline expansion, no synthetic line counter.
//!
//! Exit status nonzero iff any err-severity findings are emitted.

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const ascii = std.ascii;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const Tokenizer = std.zig.Tokenizer;
const TokenTag = std.zig.Token.Tag;

// -----------------------------------------------------------------
// Known table of hand-written slab-related metadata — mirrors the
// constants at the top of check_gen_lock.py. Kept here so the rest
// of the tool is pure scanning logic.
// -----------------------------------------------------------------

const LOCK_OPS = [_][]const u8{
    "lock",
    "unlock",
    "lockWithGen",
    "currentGen",
    "setGenRelease",
};

const SELF_ALIVE_HELPERS = [_][]const u8{
    "currentThread",
    "currentProc",
};

// KernelObject union-variant field names, keyed to their slab type.
const UnionVariantEntry = struct { variant: []const u8, ty: []const u8 };
const UNION_VARIANTS = [_]UnionVariantEntry{
    .{ .variant = "thread", .ty = "Thread" },
    .{ .variant = "process", .ty = "Process" },
    .{ .variant = "dead_process", .ty = "Process" },
    .{ .variant = "shared_memory", .ty = "SharedMemory" },
    .{ .variant = "device_region", .ty = "DeviceRegion" },
    .{ .variant = "vm", .ty = "Vm" },
};

const DefaultFieldChainEntry = struct { owner: []const u8, field: []const u8, ty: []const u8 };
const DEFAULT_FIELD_CHAINS = [_]DefaultFieldChainEntry{
    .{ .owner = "Thread", .field = "process", .ty = "Process" },
    .{ .owner = "Thread", .field = "pmu_state", .ty = "PmuState" },
    .{ .owner = "VCpu", .field = "process", .ty = "Process" },
    .{ .owner = "VCpu", .field = "vm", .ty = "Vm" },
    .{ .owner = "Vm", .field = "proc", .ty = "Process" },
};

const FatFieldEntry = struct { owner: []const u8, field: []const u8 };
const FAT_YIELDING_FIELDS = [_]FatFieldEntry{
    .{ .owner = "Thread", .field = "process" },
    .{ .owner = "Thread", .field = "next" },
    .{ .owner = "Thread", .field = "ipc_server" },
    .{ .owner = "Thread", .field = "pmu_state" },
    .{ .owner = "VCpu", .field = "process" },
    .{ .owner = "VCpu", .field = "vm" },
    .{ .owner = "VCpu", .field = "thread" },
    .{ .owner = "Process", .field = "vm" },
};

const EXCEPTION_ENTRY_NAMES = [_][]const u8{
    "exceptionHandler",
    "pageFaultHandler",
    "handleSyncLowerEl",
    "handleIrqLowerEl",
    "handleSyncCurrentEl",
    "handleIrqCurrentEl",
    "handleUnexpected",
    "dispatchIrq",
    "faultOrKillUser",
    "schedTimerHandler",
};

const ExtraRoot = struct { rel_path: []const u8, fn_name: []const u8 };
const EXTRA_ROOTS = [_]ExtraRoot{
    .{ .rel_path = "kernel/sched/scheduler.zig", .fn_name = "schedTimerHandler" },
};

const SlabReturnHelperEntry = struct { name: []const u8, ty: []const u8 };
const SLAB_RETURN_HELPERS = [_]SlabReturnHelperEntry{
    .{ .name = "lookupThread", .ty = "Thread" },
};

const SLAB_RETURN_METHODS = [_]SlabReturnHelperEntry{
    .{ .name = "findNode", .ty = "VmNode" },
};

const FAT_SLAB_RETURN_NAMES = [_][]const u8{
    "lookupThread",
    "findNode",
};

const BARE_PTR_FIELD_EXEMPT_FILES = [_][]const u8{
    "kernel/memory/allocators/secure_slab.zig",
    "kernel/memory/allocators/allocators.zig",
};

const PTR_BYPASS_EXEMPT_FILES = [_][]const u8{
    "kernel/memory/allocators/secure_slab.zig",
};

const TEST_FIXTURE_TYPES = [_][]const u8{"TestT"};

// Field types recognized as locks. A field `foo: SpinLock` or
// `foo: GenLock` on any struct is treated as a lock-class field whose
// class identity is `"<StructName>.<field_name>"`. Additional lock
// abstractions can be added here; the analyzer treats the class as
// opaque beyond the struct-field → class mapping.
const LOCK_TYPE_NAMES = [_][]const u8{
    "SpinLock",
    "GenLock",
};

// Blessed helpers for ordered same-type lock acquisition. A call like
// `lockPair(a, b)` internally acquires `a` and `b` in a deterministic
// address-ordered sequence, so the same-type nesting within that single
// call is safe-by-construction — equivalent to Linux's
// mutex_lock_nested / spin_lock_nested "subclass" annotation but
// expressed as a helper name instead of a magic comment. The lock-order
// cycle detector skips same-type pairs whose events share an
// ordered_group id emitted by one of these helpers.
const ORDERED_PAIR_LOCK_HELPERS = [_][]const u8{
    "lockPair",
};
const ORDERED_PAIR_UNLOCK_HELPERS = [_][]const u8{
    "unlockPair",
};

// -----------------------------------------------------------------
// Small helper types
// -----------------------------------------------------------------

const SliceSet = struct {
    set: StringHashMap(void),

    fn init(gpa: Allocator) SliceSet {
        return .{ .set = StringHashMap(void).init(gpa) };
    }

    fn deinit(self: *SliceSet) void {
        self.set.deinit();
    }

    fn add(self: *SliceSet, s: []const u8) !void {
        _ = try self.set.getOrPut(s);
    }

    fn contains(self: *const SliceSet, s: []const u8) bool {
        return self.set.contains(s);
    }
};

const StringStringMap = StringHashMap([]const u8);

fn inList(needle: []const u8, list: []const []const u8) bool {
    for (list) |s| if (mem.eql(u8, s, needle)) return true;
    return false;
}

fn lookupUnionVariant(name: []const u8) ?[]const u8 {
    for (UNION_VARIANTS) |e| {
        if (mem.eql(u8, e.variant, name)) return e.ty;
    }
    return null;
}

fn lookupDefaultFieldChain(owner: []const u8, field: []const u8) ?[]const u8 {
    for (DEFAULT_FIELD_CHAINS) |e| {
        if (mem.eql(u8, e.owner, owner) and mem.eql(u8, e.field, field)) return e.ty;
    }
    return null;
}

fn isFatYieldingField(owner: []const u8, field: []const u8) bool {
    for (FAT_YIELDING_FIELDS) |e| {
        if (mem.eql(u8, e.owner, owner) and mem.eql(u8, e.field, field)) return true;
    }
    return false;
}

fn lookupSlabReturnHelper(name: []const u8) ?[]const u8 {
    for (SLAB_RETURN_HELPERS) |e| {
        if (mem.eql(u8, e.name, name)) return e.ty;
    }
    return null;
}

fn lookupSlabReturnMethod(name: []const u8) ?[]const u8 {
    for (SLAB_RETURN_METHODS) |e| {
        if (mem.eql(u8, e.name, name)) return e.ty;
    }
    return null;
}

// -----------------------------------------------------------------
// Source file wrapping + comment-stripped line view
// -----------------------------------------------------------------

const SourceFile = struct {
    path: []const u8, // absolute
    rel_path: []const u8, // relative to repo root, '/' separated
    source: [:0]const u8,
    // For every byte in source, line_of[i] is the 1-based line number.
    // line_starts[l-1] is the byte index of the start of line l.
    line_starts: []usize,
    // Comment-stripped view of each line. A line is:
    //   the raw source of the line (no trailing \n), with every //-comment
    //   byte replaced by ' '. Columns in `stripped` align with columns in
    //   the raw source so col offsets match.
    // String-aware: tokenizer-produced.
    stripped_lines: [][]u8,
    // Raw (original) line text.
    raw_lines: [][]const u8,

    fn deinit(self: *SourceFile, gpa: Allocator) void {
        for (self.stripped_lines) |ln| gpa.free(ln);
        gpa.free(self.stripped_lines);
        gpa.free(self.raw_lines);
        gpa.free(self.line_starts);
        gpa.free(self.source);
        gpa.free(self.path);
        gpa.free(self.rel_path);
    }

    fn lineCount(self: *const SourceFile) usize {
        return self.raw_lines.len;
    }
};

fn loadSourceFile(
    gpa: Allocator,
    path_abs: []const u8,
    rel_path: []const u8,
) !SourceFile {
    const file = try fs.cwd().openFile(path_abs, .{});
    defer file.close();
    const stat = try file.stat();
    const bytes = try gpa.allocSentinel(u8, @intCast(stat.size), 0);
    errdefer gpa.free(bytes);
    _ = try file.readAll(bytes);

    // Compute line starts + raw line slices.
    var line_starts = ArrayList(usize).empty;
    defer line_starts.deinit(gpa);
    try line_starts.append(gpa, 0);
    for (bytes, 0..) |ch, i| {
        if (ch == '\n') {
            try line_starts.append(gpa, i + 1);
        }
    }
    const n_lines = if (bytes.len == 0 or bytes[bytes.len - 1] == '\n')
        line_starts.items.len - 1
    else
        line_starts.items.len;

    const raw_lines = try gpa.alloc([]const u8, n_lines);
    for (0..n_lines) |l| {
        const start = line_starts.items[l];
        var end: usize = if (l + 1 < line_starts.items.len)
            line_starts.items[l + 1] - 1
        else
            bytes.len;
        // Trim any trailing \r for \r\n line endings.
        if (end > start and bytes[end - 1] == '\r') end -= 1;
        raw_lines[l] = bytes[start..end];
    }

    // Comment-stripped per-line buffer. Start by copying raw lines, then
    // blank out the comment ranges reported by the tokenizer.
    const stripped = try gpa.alloc([]u8, n_lines);
    for (0..n_lines) |l| {
        stripped[l] = try gpa.alloc(u8, raw_lines[l].len);
        @memcpy(stripped[l], raw_lines[l]);
    }

    // The stock Tokenizer skips line comments entirely (no token for
    // them). To discover comment ranges we rescan each line by hand —
    // string-aware so a `//` inside "...".
    for (0..n_lines) |l| {
        const s = stripped[l];
        var i: usize = 0;
        var in_str = false;
        var in_char = false;
        while (i < s.len) : (i += 1) {
            const c = s[i];
            if (in_str) {
                if (c == '\\' and i + 1 < s.len) {
                    i += 1;
                    continue;
                }
                if (c == '"') in_str = false;
                continue;
            }
            if (in_char) {
                if (c == '\\' and i + 1 < s.len) {
                    i += 1;
                    continue;
                }
                if (c == '\'') in_char = false;
                continue;
            }
            if (c == '"') {
                in_str = true;
                continue;
            }
            if (c == '\'') {
                in_char = true;
                continue;
            }
            if (c == '/' and i + 1 < s.len and s[i + 1] == '/') {
                // Blank out the rest of the line.
                while (i < s.len) : (i += 1) s[i] = ' ';
                break;
            }
        }
    }

    return .{
        .path = path_abs,
        .rel_path = rel_path,
        .source = bytes,
        .line_starts = try line_starts.toOwnedSlice(gpa),
        .stripped_lines = stripped,
        .raw_lines = raw_lines,
    };
}

// -----------------------------------------------------------------
// File walking
// -----------------------------------------------------------------

fn walkZigFiles(
    gpa: Allocator,
    root_abs: []const u8,
    repo_root_abs: []const u8,
    out: *ArrayList([]const u8), // absolute paths
    out_rel: *ArrayList([]const u8), // relative paths ('/'-separated)
) !void {
    var stack = ArrayList([]const u8).empty;
    defer {
        for (stack.items) |p| gpa.free(p);
        stack.deinit(gpa);
    }
    try stack.append(gpa, try gpa.dupe(u8, root_abs));
    while (stack.items.len > 0) {
        const dir_path = stack.pop().?;
        defer gpa.free(dir_path);
        var dir = fs.cwd().openDir(dir_path, .{ .iterate = true }) catch continue;
        defer dir.close();
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (mem.eql(u8, entry.name, ".zig-cache")) continue;
            const child = try fs.path.join(gpa, &.{ dir_path, entry.name });
            switch (entry.kind) {
                .directory => try stack.append(gpa, child),
                .file => {
                    if (mem.endsWith(u8, entry.name, ".zig")) {
                        const rel = try fs.path.relative(gpa, repo_root_abs, child);
                        // Normalize to forward slashes for comparisons.
                        for (rel) |*b| if (b.* == '\\') {
                            b.* = '/';
                        };
                        try out.append(gpa, child);
                        try out_rel.append(gpa, rel);
                    } else {
                        gpa.free(child);
                    }
                },
                else => gpa.free(child),
            }
        }
    }
}

// -----------------------------------------------------------------
// Tokens per file (produced once via std.zig.Tokenizer)
// -----------------------------------------------------------------

const Tok = struct {
    tag: TokenTag,
    start: u32,
    end: u32,
    line: u32, // 1-based
    col: u32, // 0-based byte column in the raw line
};

fn tokenizeFile(gpa: Allocator, sf: *const SourceFile) ![]Tok {
    var list = ArrayList(Tok).empty;
    defer list.deinit(gpa);
    var tz = Tokenizer.init(sf.source);
    while (true) {
        const t = tz.next();
        if (t.tag == .eof) break;
        // Line/col of start.
        var lo: usize = 0;
        var hi: usize = sf.line_starts.len;
        while (lo + 1 < hi) {
            const mid = (lo + hi) / 2;
            if (sf.line_starts[mid] <= t.loc.start) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        const line_no: u32 = @intCast(lo + 1);
        const col: u32 = @intCast(t.loc.start - sf.line_starts[lo]);
        try list.append(gpa, .{
            .tag = t.tag,
            .start = @intCast(t.loc.start),
            .end = @intCast(t.loc.end),
            .line = line_no,
            .col = col,
        });
    }
    return list.toOwnedSlice(gpa);
}

fn tokSlice(sf: *const SourceFile, t: Tok) []const u8 {
    return sf.source[t.start..t.end];
}

// -----------------------------------------------------------------
// Data model
// -----------------------------------------------------------------

const SlabType = struct {
    name: []const u8, // owned
    file_rel: []const u8, // owned
    line: u32,
};

const SlabTypeMap = struct {
    // Keyed by name (borrowed from the SlabType.name); value is the SlabType.
    inner: StringHashMap(SlabType),

    fn init(gpa: Allocator) SlabTypeMap {
        return .{ .inner = StringHashMap(SlabType).init(gpa) };
    }

    fn deinit(self: *SlabTypeMap, gpa: Allocator) void {
        var it = self.inner.valueIterator();
        while (it.next()) |st| {
            gpa.free(st.name);
            gpa.free(st.file_rel);
        }
        self.inner.deinit();
    }

    fn contains(self: *const SlabTypeMap, name: []const u8) bool {
        return self.inner.contains(name);
    }
};

const EntryPoint = struct {
    name: []const u8, // borrowed from source buffer or dup
    file_path: []const u8, // absolute, borrowed
    file_rel: []const u8, // relative, borrowed
    line: u32, // 1-based line of header
    body_start_line: u32, // 1-based, first body line
    body_end_line: u32, // 1-based, last body line inclusive
};

// A function we may inline during call-graph tracing.
const FnInfo = struct {
    file_path: []const u8, // absolute, borrowed
    file_rel: []const u8, // relative, borrowed
    line: u32,
    first_param: []const u8, // borrowed
    other_params: []ParamSpec, // owned
    body_start_line: u32,
    body_end_line: u32,
    receiver_type: []const u8, // slab type name, borrowed
    return_type: ?[]const u8, // slab type name, borrowed or null
};

const ParamSpec = struct {
    name: []const u8, // borrowed from file source
    type_str: []const u8, // borrowed from file source
};

// (receiver_type, fn_name) → FnInfo (pointer, owned)
const FnIndex = std.HashMap(
    FnKey,
    *FnInfo,
    FnKeyContext,
    std.hash_map.default_max_load_percentage,
);
const FnKey = struct {
    recv: []const u8,
    name: []const u8,
};
const FnKeyContext = struct {
    pub fn hash(_: @This(), k: FnKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(k.recv);
        h.update("|");
        h.update(k.name);
        return h.final();
    }
    pub fn eql(_: @This(), a: FnKey, b: FnKey) bool {
        return mem.eql(u8, a.recv, b.recv) and mem.eql(u8, a.name, b.name);
    }
};

const BarePtrFinding = struct {
    file_rel: []const u8, // borrowed
    line: u32,
    struct_name: []const u8, // owned
    field_name: []const u8, // owned
    field_type: []const u8, // owned
    slab_type: []const u8, // borrowed (points at slab_types entry)
};

const PtrBypassFinding = struct {
    file_rel: []const u8, // borrowed
    line: u32,
    chain: []const u8, // owned — full `<prefix>.ptr` text
    context: []const u8, // owned — stripped code of the line
};

const Severity = enum { err, warn, info };

const Finding = struct {
    severity: Severity,
    entry_name: []const u8, // borrowed
    message: []const u8, // owned
    line_no: u32,
};

// One event in an ident's per-entry event timeline. Events come from the
// entry body directly OR from folded callee summaries applied at the call
// site; either way the src_line is the real caller-source line where the
// event observably happened. seq is a per-entry monotonically-increasing
// insertion counter so callee events folded at a single call site retain
// their internal order for tight-bracket checking.
const EventKind = enum {
    access,
    lock,
    unlock,
    defer_unlock,
    lock_with_gen,
};

const Event = struct {
    kind: EventKind,
    src_line: u32, // 1-based real line in the caller's source file
    seq: u32, // per-entry insertion order
    tail: []const u8 = "", // method / field name for access events
    slab_type: []const u8 = "",
    // Non-zero when this lock/unlock event was emitted by an ordered-pair
    // helper call (`lockPair`, `unlockPair`). Two lock events sharing the
    // same non-zero group_id are treated as a single atomic ordered
    // acquisition when the cycle detector considers same-type pairs —
    // their mutual self-loop is suppressed because the helper enforces a
    // deterministic address-order internally. Cross-type pairs from
    // ordered groups still contribute normal edges; only the same-type
    // self-loop between the group's members is elided.
    group_id: u32 = 0,
    // Pre-resolved lock class (interned). When non-empty, the pair
    // extractor uses this verbatim instead of synthesizing a class from
    // slab_type. Populated for plain SpinLock / struct-field locks
    // where the class is `<OwnerStruct>.<field_name>`.
    lock_class: []const u8 = "",
};

// -----------------------------------------------------------------
// Lock-ordering graph: pairs + cycles.
// -----------------------------------------------------------------
//
// A LockClass is an interned string identifying a lock *type* — e.g.
// "Process._gen_lock", "Thread._gen_lock". Instances of the same class
// are interchangeable for graph purposes (two Process objects' gen-locks
// share a class, same as Linux lockdep's lock_class).
//
// A LockPair (outer_class → inner_class) records that some function was
// observed to hold `outer` when acquiring `inner`. A cycle in the
// directed graph of pairs indicates a potential deadlock: thread A
// holding outer→inner and thread B holding inner→outer can deadlock
// regardless of which specific instances each thread acquires.

const LockPair = struct {
    outer: []const u8, // interned class
    inner: []const u8, // interned class
    file_rel: []const u8, // borrowed
    line: u32, // call-site line where `inner` was acquired
    entry_name: []const u8, // borrowed
    outer_ident: []const u8, // borrowed
    inner_ident: []const u8, // borrowed
};

// -----------------------------------------------------------------
// Helpers: typed string predicates
// -----------------------------------------------------------------

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

fn rstrip(s: []const u8) []const u8 {
    var b: usize = s.len;
    while (b > 0 and ascii.isWhitespace(s[b - 1])) b -= 1;
    return s[0..b];
}

// Remove trailing `orelse ...`, `.?`, `catch ...`, parenthesized casts.
fn stripPostfix(s: []const u8) []const u8 {
    var out = trimAscii(s);
    if (mem.indexOf(u8, out, " orelse ")) |i| out = trimAscii(out[0..i]);
    if (mem.indexOf(u8, out, " catch ")) |i| out = trimAscii(out[0..i]);
    while (mem.endsWith(u8, out, ".?")) out = trimAscii(out[0 .. out.len - 2]);
    while (out.len >= 2 and out[0] == '(' and out[out.len - 1] == ')') {
        out = trimAscii(out[1 .. out.len - 1]);
    }
    return out;
}

// Matches `A.b.c...` (no trailing / surrounding operators). Returns the
// chain split on `.` or null if it's not a pure chain.
fn leadingChain(gpa: Allocator, s_in: []const u8) !?[][]const u8 {
    var s = trimAscii(s_in);
    if (s.len > 0 and s[s.len - 1] == ';') s = trimAscii(s[0 .. s.len - 1]);
    if (s.len == 0) return null;
    if (!isIdentStart(s[0])) return null;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (isIdentChar(c) or c == '.') continue;
        return null;
    }
    // Must not end with `.` or have `..`.
    if (s[s.len - 1] == '.') return null;
    var parts = ArrayList([]const u8).empty;
    errdefer parts.deinit(gpa);
    var start: usize = 0;
    var j: usize = 0;
    while (j < s.len) : (j += 1) {
        if (s[j] == '.') {
            if (j == start) return null;
            try parts.append(gpa, s[start..j]);
            start = j + 1;
        }
    }
    if (start == s.len) return null;
    try parts.append(gpa, s[start..s.len]);
    return try parts.toOwnedSlice(gpa);
}

// -----------------------------------------------------------------
// Type-string parsing (mirrors parse_type_ref)
// -----------------------------------------------------------------

// Given a type string, extract trailing slab-type name. Recognizes:
//   `*T`, `?*T`, `*const T`, `SlabRef(T)`, `?SlabRef(T)`
// Returns the name slice (borrowed from input) or null.
fn parseTypeRef(type_str: []const u8) ?[]const u8 {
    var t = trimAscii(type_str);
    if (t.len == 0) return null;
    if (t[0] == '?') t = trimAscii(t[1..]);
    if (t.len == 0) return null;
    // SlabRef(T)
    if (mem.startsWith(u8, t, "SlabRef")) {
        var rest = trimAscii(t[7..]);
        if (rest.len == 0 or rest[0] != '(') return null;
        rest = trimAscii(rest[1..]);
        // Trailing `)`.
        var end: usize = 0;
        while (end < rest.len and (isIdentChar(rest[end]))) end += 1;
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

// -----------------------------------------------------------------
// Pass 1: discover slab-backed types.
// -----------------------------------------------------------------
//
// Two signals — a struct whose body contains `_gen_lock: GenLock = .{}`
// (the allocator stamp) OR a decl of the form
// `pub const Foo = SecureSlab(T, N)` that exposes T. The Python tool
// uses the first signal; we cross-check with the second to keep parity.

fn findSlabTypes(
    gpa: Allocator,
    files: []const *SourceFile,
    tokens_per_file: []const []const Tok,
    out: *SlabTypeMap,
) !void {
    // Signal A: `_gen_lock:` fields inside a struct. We locate the
    // enclosing struct header by scanning tokens back from the field to
    // the opening `{` of its struct body, then back up to `const <Name> =`.
    const BraceMeta = struct { name: []const u8, header_line: u32 };
    for (files, tokens_per_file) |sf, toks| {
        var brace_to_name = std.AutoHashMap(u32, BraceMeta).init(gpa);
        defer brace_to_name.deinit();
        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            // Find `const <name> =`.
            if (toks[i].tag != .keyword_const) continue;
            if (i + 3 >= toks.len) continue;
            if (toks[i + 1].tag != .identifier) continue;
            if (toks[i + 2].tag != .equal) continue;
            var j: usize = i + 3;
            if (j < toks.len and (toks[j].tag == .keyword_extern or toks[j].tag == .keyword_packed)) j += 1;
            if (j >= toks.len) continue;
            if (toks[j].tag != .keyword_struct and toks[j].tag != .keyword_union) continue;
            j += 1;
            if (j < toks.len and toks[j].tag == .l_paren) {
                var depth: i32 = 1;
                j += 1;
                while (j < toks.len and depth > 0) : (j += 1) {
                    if (toks[j].tag == .l_paren) depth += 1;
                    if (toks[j].tag == .r_paren) depth -= 1;
                }
            }
            if (j >= toks.len) continue;
            if (toks[j].tag != .l_brace) continue;
            const name = tokSlice(sf, toks[i + 1]);
            const header_line = toks[i].line; // line of `const` keyword
            try brace_to_name.put(toks[j].start, .{ .name = name, .header_line = header_line });
        }

        // Walk tokens; whenever we see an identifier `_gen_lock` followed
        // by `:`, find its enclosing struct brace.
        i = 0;
        while (i + 1 < toks.len) : (i += 1) {
            if (toks[i].tag != .identifier) continue;
            if (!mem.eql(u8, tokSlice(sf, toks[i]), "_gen_lock")) continue;
            if (toks[i + 1].tag != .colon) continue;
            // Find the most recent unmatched `{` before index i.
            var depth: i32 = 0;
            var k: isize = @as(isize, @intCast(i)) - 1;
            var enclosing: u32 = 0;
            while (k >= 0) : (k -= 1) {
                const tt = toks[@intCast(k)].tag;
                if (tt == .r_brace) depth += 1;
                if (tt == .l_brace) {
                    if (depth == 0) {
                        enclosing = toks[@intCast(k)].start;
                        break;
                    }
                    depth -= 1;
                }
            }
            if (k < 0) continue;
            if (brace_to_name.get(enclosing)) |meta| {
                if (inList(meta.name, &TEST_FIXTURE_TYPES)) continue;
                if (out.inner.contains(meta.name)) continue;
                const owned_name = try gpa.dupe(u8, meta.name);
                const owned_rel = try gpa.dupe(u8, sf.rel_path);
                try out.inner.put(owned_name, .{
                    .name = owned_name,
                    .file_rel = owned_rel,
                    .line = meta.header_line,
                });
            }
        }
    }
}

// -----------------------------------------------------------------
// Pass 1b: discover struct field declarations (used by bare-ptr and
// .ptr-bypass passes).
// -----------------------------------------------------------------

const StructField = struct {
    file_rel: []const u8,
    line: u32, // 1-based
    struct_name: []const u8, // borrowed
    field_name: []const u8, // borrowed
    field_type: []const u8, // borrowed (stripped code slice of the type)
};

// Module-level `var/const <name>: <type> = ...` declarations. Used by
// the lock-ordering analyzer to resolve locals like
// `const state = &core_states[core_id];` — without this, the receiver
// `state` is untyped and subsequent `state.rq_lock.lockIrqSave()` calls
// can't classify.
//
// Scope for v3: keyed by bare name (not file-qualified). If two files
// declare same-named globals the map takes last-wins. Internal to
// each file's walks, this is almost always unique — cross-file access
// goes through `module.name` which we don't normalize here.
const ModuleGlobal = struct {
    name: []const u8, // interned
    bare_type: []const u8, // interned — e.g. "PerCoreState", "Vmm", "SpinLock"
    is_array: bool, // true when the declared type is `[N]T`
};

fn scanModuleGlobals(
    gpa: Allocator,
    pool: *Pool,
    sf: *const SourceFile,
    toks: []const Tok,
    out: *StringStringMap,
) !void {
    _ = gpa;
    // Walk tokens at the file's top-level (brace_depth 0, paren_depth 0)
    // looking for `pub? (var|const) <ident>: <type> ...`. The `: type`
    // distinguishes typed globals from `const X = 42` style value decls
    // (no type annotation) where inferring the type needs real
    // type-checking — out of scope for v3. Missing an un-annotated
    // global is fine; the lock-ordering analyzer just skips receivers
    // it can't resolve.
    var brace_depth: i32 = 0;
    var paren_depth: i32 = 0;
    var i: usize = 0;
    while (i < toks.len) : (i += 1) {
        const t = toks[i];
        switch (t.tag) {
            .l_brace => brace_depth += 1,
            .r_brace => brace_depth -= 1,
            .l_paren => paren_depth += 1,
            .r_paren => paren_depth -= 1,
            else => {},
        }
        if (brace_depth != 0 or paren_depth != 0) continue;
        if (t.tag != .keyword_var and t.tag != .keyword_const) continue;
        if (i + 3 >= toks.len) continue;
        if (toks[i + 1].tag != .identifier) continue;
        if (toks[i + 2].tag != .colon) continue;
        const name = tokSlice(sf, toks[i + 1]);
        // Collect the type expression from after `:` until the next
        // top-level `=` or `;`.
        const type_start_idx = i + 3;
        var j: usize = type_start_idx;
        var inner_paren: i32 = 0;
        var inner_bracket: i32 = 0;
        while (j < toks.len) : (j += 1) {
            switch (toks[j].tag) {
                .l_paren => inner_paren += 1,
                .r_paren => inner_paren -= 1,
                .l_bracket => inner_bracket += 1,
                .r_bracket => inner_bracket -= 1,
                else => {},
            }
            if (inner_paren == 0 and inner_bracket == 0) {
                if (toks[j].tag == .equal or toks[j].tag == .semicolon) break;
            }
        }
        if (j <= type_start_idx) continue;
        const type_start_byte = toks[type_start_idx].start;
        const type_end_byte = toks[j].start;
        const type_text = trimAscii(sf.source[type_start_byte..type_end_byte]);
        if (type_text.len == 0) continue;
        // Strip leading `[N]` / `[_]` for array globals — element type
        // is what matters when callers do `&global[idx]`.
        var te = type_text;
        if (te.len > 0 and te[0] == '[') {
            if (mem.indexOfScalar(u8, te, ']')) |close| {
                te = trimAscii(te[close + 1 ..]);
            }
        }
        const bare = typeNameFromFieldType(te);
        if (bare.len == 0) continue;
        // Skip primitive / stdlib types — they don't own lock fields.
        if (mem.eql(u8, bare, "bool") or
            mem.eql(u8, bare, "u8") or mem.eql(u8, bare, "u16") or
            mem.eql(u8, bare, "u32") or mem.eql(u8, bare, "u64") or
            mem.eql(u8, bare, "usize") or
            mem.eql(u8, bare, "i8") or mem.eql(u8, bare, "i16") or
            mem.eql(u8, bare, "i32") or mem.eql(u8, bare, "i64") or
            mem.eql(u8, bare, "isize") or
            mem.startsWith(u8, bare, "std")) continue;
        const name_i = try pool.intern(name);
        const bare_i = try pool.intern(bare);
        try out.put(name_i, bare_i);
        i = j;
    }
}

// Walks a file's tokens finding lines where a struct field appears at
// brace-depth >= 1 and paren-depth == 0. For each such line, we emit
// StructField. The field-recognition pattern is identifier + `:` +
// type-expression terminated by `,` or end-of-line or `=`.
fn scanStructFields(
    gpa: Allocator,
    sf: *const SourceFile,
    toks: []const Tok,
    out: *ArrayList(StructField),
) !void {
    // Build brace depth + paren depth at the start of each line.
    const n_lines = sf.lineCount();
    const brace_depth_at_line = try gpa.alloc(i32, n_lines + 1);
    defer gpa.free(brace_depth_at_line);
    const paren_depth_at_line = try gpa.alloc(i32, n_lines + 1);
    defer gpa.free(paren_depth_at_line);
    // Map: struct-opening `{` to struct name (same as before).
    var brace_to_name = std.AutoHashMap(u32, []const u8).init(gpa);
    defer brace_to_name.deinit();
    {
        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            if (toks[i].tag != .keyword_const and toks[i].tag != .keyword_var) continue;
            if (i + 3 >= toks.len) continue;
            if (toks[i + 1].tag != .identifier) continue;
            if (toks[i + 2].tag != .equal) continue;
            var j: usize = i + 3;
            if (j < toks.len and (toks[j].tag == .keyword_extern or toks[j].tag == .keyword_packed)) j += 1;
            if (j >= toks.len) continue;
            if (toks[j].tag != .keyword_struct and toks[j].tag != .keyword_union) continue;
            j += 1;
            if (j < toks.len and toks[j].tag == .l_paren) {
                var depth: i32 = 1;
                j += 1;
                while (j < toks.len and depth > 0) : (j += 1) {
                    if (toks[j].tag == .l_paren) depth += 1;
                    if (toks[j].tag == .r_paren) depth -= 1;
                }
            }
            if (j >= toks.len) continue;
            if (toks[j].tag != .l_brace) continue;
            try brace_to_name.put(toks[j].start, tokSlice(sf, toks[i + 1]));
        }
    }

    // Simulate per-line brace/paren depth.
    var brace_depth: i32 = 0;
    var paren_depth: i32 = 0;
    var tok_idx: usize = 0;
    for (0..n_lines) |l| {
        brace_depth_at_line[l] = brace_depth;
        paren_depth_at_line[l] = paren_depth;
        const line_no: u32 = @intCast(l + 1);
        while (tok_idx < toks.len and toks[tok_idx].line == line_no) : (tok_idx += 1) {
            switch (toks[tok_idx].tag) {
                .l_brace => brace_depth += 1,
                .r_brace => brace_depth -= 1,
                .l_paren => paren_depth += 1,
                .r_paren => paren_depth -= 1,
                .l_bracket => {},
                .r_bracket => {},
                else => {},
            }
        }
    }
    brace_depth_at_line[n_lines] = brace_depth;
    paren_depth_at_line[n_lines] = paren_depth;

    // For each line at brace>=1 and paren==0, try matching the field
    // pattern on the stripped line. Pattern: `^<ws>(pub<ws>+)?<IDENT><ws>*:<ws>*<TYPE>(<ws>*=<stuff>)?<ws>*,?<ws>*$`
    for (0..n_lines) |l| {
        if (brace_depth_at_line[l] < 1) continue;
        if (paren_depth_at_line[l] > 0) continue;
        const line = sf.stripped_lines[l];
        const trimmed = trimAscii(line);
        if (trimmed.len == 0) continue;

        // Walk past optional `pub `.
        var t = trimmed;
        if (mem.startsWith(u8, t, "pub ") or mem.startsWith(u8, t, "pub\t")) {
            t = trimAscii(t[3..]);
        }
        if (t.len == 0 or !isIdentStart(t[0])) continue;

        // Extract ident.
        var p: usize = 0;
        while (p < t.len and isIdentChar(t[p])) p += 1;
        const field_name = t[0..p];
        if (field_name.len == 0) continue;
        if (mem.eql(u8, field_name, "const") or mem.eql(u8, field_name, "var") or
            mem.eql(u8, field_name, "fn") or mem.eql(u8, field_name, "pub") or
            mem.eql(u8, field_name, "return")) continue;
        var rest = t[p..];
        rest = trimAscii(rest);
        if (rest.len == 0 or rest[0] != ':') continue;
        rest = trimAscii(rest[1..]);
        // Type spans up to `=` or `,` or end. We respect paren depth so a
        // comma inside generic type args doesn't cut the type early.
        var depth: i32 = 0;
        var e: usize = 0;
        while (e < rest.len) : (e += 1) {
            const c = rest[e];
            if (c == '(' or c == '[' or c == '{') depth += 1;
            if (c == ')' or c == ']' or c == '}') depth -= 1;
            if (depth != 0) continue;
            if (c == '=' or c == ',') break;
        }
        const field_type = trimAscii(rest[0..e]);
        if (field_type.len == 0) continue;
        // Reject anything that looks like a statement rather than a field.
        if (mem.indexOfScalar(u8, field_type, ';') != null) continue;

        // Walk back to find enclosing struct name via brace pos.
        const enclosing_name = findEnclosingStructName(toks, sf, @intCast(l + 1), brace_to_name) orelse "<unknown>";

        try out.append(gpa, .{
            .file_rel = sf.rel_path,
            .line = @intCast(l + 1),
            .struct_name = enclosing_name,
            .field_name = field_name,
            .field_type = field_type,
        });
    }
}

fn findEnclosingStructName(
    toks: []const Tok,
    sf: *const SourceFile,
    line_no: u32,
    brace_to_name: std.AutoHashMap(u32, []const u8),
) ?[]const u8 {
    _ = sf;
    // Walk tokens until we pass `line_no`; record the open brace index
    // of the innermost open struct. We track a stack of `{` positions
    // that are struct-headed.
    var stack = std.ArrayList(u32).empty;
    defer stack.deinit(std.heap.page_allocator);
    // Parallel stack of all `{`s with a flag for struct-ness.
    const Braces = struct { pos: u32, is_struct: bool };
    var all_stack = std.ArrayList(Braces).empty;
    defer all_stack.deinit(std.heap.page_allocator);
    var last_struct_name: ?[]const u8 = null;
    for (toks) |t| {
        if (t.line >= line_no) break;
        switch (t.tag) {
            .l_brace => {
                const is_s = brace_to_name.contains(t.start);
                all_stack.append(std.heap.page_allocator, .{ .pos = t.start, .is_struct = is_s }) catch return null;
                if (is_s) last_struct_name = brace_to_name.get(t.start);
            },
            .r_brace => {
                _ = all_stack.pop();
                // Recompute last_struct_name from what's on stack.
                last_struct_name = null;
                for (all_stack.items) |b| {
                    if (b.is_struct) last_struct_name = brace_to_name.get(b.pos);
                }
            },
            else => {},
        }
    }
    return last_struct_name;
}

// Bare-pointer invariant: scan every struct field; flag where the type
// string contains a bare `*<SlabName>` (or `?*`, `[N]*`, `[]*`) that
// isn't wrapped in SlabRef(...).
fn findBareSlabPointerFields(
    gpa: Allocator,
    struct_fields: []const StructField,
    slab_types: *const SlabTypeMap,
    out: *ArrayList(BarePtrFinding),
) !void {
    for (struct_fields) |f| {
        if (inList(f.file_rel, &BARE_PTR_FIELD_EXEMPT_FILES)) continue;
        if (typeStrContainsSlabRef(f.field_type)) continue;
        // Look for a bare pointer form pointing at a slab type name.
        // Walk the type string for `*<IDENT>` occurrences.
        const ft = f.field_type;
        var i: usize = 0;
        while (i < ft.len) : (i += 1) {
            if (ft[i] != '*') continue;
            // Advance past *, optional `const `.
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
            if (slab_types.contains(target)) {
                // Found one.
                const sn = try gpa.dupe(u8, f.struct_name);
                const fn_dup = try gpa.dupe(u8, f.field_name);
                const ft_dup = try gpa.dupe(u8, f.field_type);
                try out.append(gpa, .{
                    .file_rel = f.file_rel,
                    .line = f.line,
                    .struct_name = sn,
                    .field_name = fn_dup,
                    .field_type = ft_dup,
                    .slab_type = target,
                });
                break;
            }
        }
    }
}

// -----------------------------------------------------------------
// Pass 1c: `.ptr` bypass
// -----------------------------------------------------------------
//
// Same logic as Python: scan each line for `<chain>.ptr` where the tail
// segment is a known SlabRef-typed field name. Exempt identity compares
// (`x.ptr == ...`) and `// self-alive` marked sites.

fn collectSlabFieldNames(
    struct_fields: []const StructField,
    out: *SliceSet,
) !void {
    for (struct_fields) |f| {
        if (typeStrContainsSlabRef(f.field_type)) {
            try out.add(f.field_name);
        }
    }
    // Seed KernelObject variant names.
    for (UNION_VARIANTS) |v| try out.add(v.variant);
}

fn containsSelfAliveComment(line_raw: []const u8) bool {
    // Looking for "//" followed by whitespace + "self-alive".
    var i: usize = 0;
    while (i + 1 < line_raw.len) : (i += 1) {
        if (line_raw[i] == '/' and line_raw[i + 1] == '/') {
            const rest = line_raw[i + 2 ..];
            var j: usize = 0;
            while (j < rest.len and ascii.isWhitespace(rest[j])) j += 1;
            if (j + "self-alive".len <= rest.len and
                mem.eql(u8, rest[j .. j + "self-alive".len], "self-alive")) return true;
            return false;
        }
    }
    return false;
}

fn findPtrBypasses(
    gpa: Allocator,
    files: []const *SourceFile,
    slab_field_names: *const SliceSet,
    out: *ArrayList(PtrBypassFinding),
) !void {
    for (files) |sf| {
        if (inList(sf.rel_path, &PTR_BYPASS_EXEMPT_FILES)) continue;
        const n = sf.lineCount();
        for (0..n) |l| {
            const line = sf.stripped_lines[l];
            const raw = sf.raw_lines[l];
            // self-alive on this line.
            if (containsSelfAliveComment(raw)) continue;
            // or in the contiguous // comment block immediately above.
            var above_self_alive = false;
            var k: isize = @as(isize, @intCast(l)) - 1;
            while (k >= 0) : (k -= 1) {
                const lk = sf.raw_lines[@intCast(k)];
                const tlk = trimAscii(lk);
                if (!mem.startsWith(u8, tlk, "//")) break;
                if (containsSelfAliveComment(lk)) {
                    above_self_alive = true;
                    break;
                }
            }
            if (above_self_alive) continue;

            // Walk the stripped line and find `.ptr` occurrences whose
            // preceding segment forms a chain `<ident>(.<ident>)*.<field>`
            // where <field> is in slab_field_names.
            var i: usize = 0;
            while (i + 4 <= line.len) : (i += 1) {
                if (line[i] != '.') continue;
                if (!mem.eql(u8, line[i + 1 .. i + 4], "ptr")) continue;
                if (i + 4 < line.len and isIdentChar(line[i + 4])) continue;
                // Walk back to the start of the ident chain.
                var start: usize = i;
                while (start > 0) {
                    const prev = line[start - 1];
                    if (isIdentChar(prev) or prev == '.') {
                        start -= 1;
                    } else break;
                }
                if (start == i) continue;
                // Ensure the char before start is NOT ident or '.'.
                if (start > 0) {
                    const pc = line[start - 1];
                    if (isIdentChar(pc) or pc == '.') continue;
                }
                const chain = line[start..i]; // without the `.ptr`
                if (mem.indexOf(u8, chain, ".") == null) continue;
                // tail after last `.`
                const last_dot = mem.lastIndexOf(u8, chain, ".").?;
                const tail = chain[last_dot + 1 ..];
                if (!slab_field_names.contains(tail)) continue;
                // Identity compare?
                var q: usize = i + 4;
                while (q < line.len and ascii.isWhitespace(line[q])) q += 1;
                if (q + 1 < line.len and (mem.startsWith(u8, line[q..], "==") or mem.startsWith(u8, line[q..], "!="))) continue;
                var b: usize = start;
                while (b > 0 and ascii.isWhitespace(line[b - 1])) b -= 1;
                if (b >= 2 and (mem.eql(u8, line[b - 2 .. b], "==") or mem.eql(u8, line[b - 2 .. b], "!="))) continue;

                // Emit. Chain text = chain+`.ptr`.
                const chain_dup = try std.fmt.allocPrint(gpa, "{s}.ptr", .{chain});
                const ctx_dup = try gpa.dupe(u8, trimAscii(line));
                try out.append(gpa, .{
                    .file_rel = sf.rel_path,
                    .line = @intCast(l + 1),
                    .chain = chain_dup,
                    .context = ctx_dup,
                });
            }
        }
    }
}

// -----------------------------------------------------------------
// Pass 2: entry points + fn index
// -----------------------------------------------------------------

// Find `fn <name>(` on a given line in tokens. Returns token index of
// the fn keyword or null.
const FnHeader = struct {
    fn_tok_idx: usize,
    name_tok_idx: usize,
    l_paren_idx: usize,
    r_paren_idx: usize,
    l_brace_idx: usize,
    r_brace_idx: usize,
};

fn parseFnHeaderAt(toks: []const Tok, start_idx: usize) ?FnHeader {
    // Look for fn keyword token.
    if (start_idx >= toks.len) return null;
    var i = start_idx;
    if (toks[i].tag == .keyword_pub) i += 1;
    if (i >= toks.len or toks[i].tag != .keyword_fn) return null;
    const fn_tok = i;
    i += 1;
    if (i >= toks.len or toks[i].tag != .identifier) return null;
    const name_tok = i;
    i += 1;
    if (i >= toks.len or toks[i].tag != .l_paren) return null;
    const lp = i;
    // find matching `)`.
    var depth: i32 = 1;
    i += 1;
    while (i < toks.len and depth > 0) : (i += 1) {
        if (toks[i].tag == .l_paren) depth += 1;
        if (toks[i].tag == .r_paren) depth -= 1;
        if (depth == 0) break;
    }
    if (i >= toks.len) return null;
    const rp = i;
    i += 1;
    // Walk until `{`.
    while (i < toks.len and toks[i].tag != .l_brace) : (i += 1) {}
    if (i >= toks.len) return null;
    const lb = i;
    // find matching `}`.
    depth = 1;
    i += 1;
    while (i < toks.len and depth > 0) : (i += 1) {
        if (toks[i].tag == .l_brace) depth += 1;
        if (toks[i].tag == .r_brace) depth -= 1;
        if (depth == 0) break;
    }
    if (i >= toks.len) return null;
    return .{
        .fn_tok_idx = fn_tok,
        .name_tok_idx = name_tok,
        .l_paren_idx = lp,
        .r_paren_idx = rp,
        .l_brace_idx = lb,
        .r_brace_idx = i,
    };
}

// Parses the param list between l_paren..r_paren (exclusive of both).
// Returns a list of (name, type_str). Commas at depth 0 split.
fn parseParamList(
    gpa: Allocator,
    sf: *const SourceFile,
    toks: []const Tok,
    lp: usize,
    rp: usize,
) ![]ParamSpec {
    var list = ArrayList(ParamSpec).empty;
    errdefer list.deinit(gpa);
    if (lp + 1 >= rp) return list.toOwnedSlice(gpa);
    // Reconstruct the raw text from source[tok(lp+1).start .. tok(rp).start - 0],
    // but careful: the raw slice contains comments. Instead work on tokens.
    // For each param we find "name : type_tokens".
    var i: usize = lp + 1;
    while (i < rp) {
        // Skip leading `comptime`.
        if (toks[i].tag == .keyword_comptime) i += 1;
        // Name token (identifier) followed by `:` starts a typed param.
        if (i >= rp) break;
        if (toks[i].tag != .identifier) {
            // Advance to next comma at depth 0.
            while (i < rp and toks[i].tag != .comma) i += 1;
            if (i < rp) i += 1;
            continue;
        }
        const name_tok = i;
        i += 1;
        if (i >= rp or toks[i].tag != .colon) {
            // Not a typed param; skip.
            while (i < rp and toks[i].tag != .comma) i += 1;
            if (i < rp) i += 1;
            continue;
        }
        i += 1; // past `:`
        const type_start_byte: u32 = if (i < rp) toks[i].start else toks[rp].start;
        var depth: i32 = 0;
        while (i < rp) : (i += 1) {
            if (toks[i].tag == .l_paren or toks[i].tag == .l_bracket or toks[i].tag == .l_brace) depth += 1;
            if (toks[i].tag == .r_paren or toks[i].tag == .r_bracket or toks[i].tag == .r_brace) depth -= 1;
            if (depth == 0 and toks[i].tag == .comma) break;
        }
        const type_end_byte: u32 = if (i < rp) toks[i].start else toks[rp].start;
        const type_slice = trimAscii(sf.source[type_start_byte..type_end_byte]);
        try list.append(gpa, .{
            .name = tokSlice(sf, toks[name_tok]),
            .type_str = type_slice,
        });
        if (i < rp) i += 1; // skip comma
    }
    return list.toOwnedSlice(gpa);
}

// Extract the return-type token slice between r_paren+1 .. l_brace-1
// (in source bytes). This includes possible `error{…}!` / `!` prefix.
fn returnTypeSlice(sf: *const SourceFile, toks: []const Tok, rp: usize, lb: usize) []const u8 {
    if (rp + 1 >= toks.len) return "";
    const sb = toks[rp + 1].start;
    const eb = toks[lb].start;
    if (eb <= sb) return "";
    return trimAscii(sf.source[sb..eb]);
}

// Strips `error{…}!` and leading `!` and returns parseTypeRef on the result.
fn parseReturnType(rt_str: []const u8) ?[]const u8 {
    var s = trimAscii(rt_str);
    if (mem.startsWith(u8, s, "error")) {
        // find `}` then `!`.
        if (mem.indexOfScalar(u8, s, '}')) |rb| {
            var rest = trimAscii(s[rb + 1 ..]);
            if (rest.len > 0 and rest[0] == '!') rest = trimAscii(rest[1..]);
            s = rest;
        }
    }
    if (s.len > 0 and s[0] == '!') s = trimAscii(s[1..]);
    return parseTypeRef(s);
}

fn findEntryPoints(
    gpa: Allocator,
    files: []const *SourceFile,
    tokens_per_file: []const []const Tok,
    out: *ArrayList(EntryPoint),
) !void {
    for (files, tokens_per_file) |sf, toks| {
        const rel = sf.rel_path;
        const is_syscall_dir = mem.startsWith(u8, rel, "kernel/syscall/");
        const is_x64_except = mem.eql(u8, rel, "kernel/arch/x64/exceptions.zig");
        const is_arm_except = mem.eql(u8, rel, "kernel/arch/aarch64/exceptions.zig");
        const is_extra_root = blk: {
            for (EXTRA_ROOTS) |r| if (mem.eql(u8, r.rel_path, rel)) break :blk true;
            break :blk false;
        };
        if (!(is_syscall_dir or is_x64_except or is_arm_except or is_extra_root)) continue;

        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            if (toks[i].tag != .keyword_fn) continue;
            var start_i_mut: usize = i;
            if (i > 0 and toks[i - 1].tag == .keyword_pub) start_i_mut = i - 1;
            const start_i = start_i_mut;
            // Only pub fn for sys*; any fn for exception list.
            const is_pub = start_i != i;
            const header = parseFnHeaderAt(toks, start_i) orelse continue;
            const name = tokSlice(sf, toks[header.name_tok_idx]);

            // Must start on column 0 (top-level) to mirror Python's
            // anchored regexes. We test: the raw line at this token
            // should start with either `pub ` or `fn `.
            const line = sf.raw_lines[toks[start_i].line - 1];
            const lt = if (mem.startsWith(u8, line, "pub fn ") or
                mem.startsWith(u8, line, "fn ")) true else false;
            if (!lt) {
                i = header.r_brace_idx;
                continue;
            }

            var accept = false;
            if (is_syscall_dir and is_pub and mem.startsWith(u8, name, "sys")) accept = true;
            if ((is_x64_except or is_arm_except) and inList(name, &EXCEPTION_ENTRY_NAMES)) accept = true;
            if (is_extra_root) {
                for (EXTRA_ROOTS) |r| if (mem.eql(u8, r.rel_path, rel) and mem.eql(u8, r.fn_name, name)) {
                    accept = true;
                };
            }
            if (!accept) {
                i = header.r_brace_idx;
                continue;
            }

            const body_start_line = computeFirstBodyLine(sf, toks, header);
            const body_end_line = toks[header.r_brace_idx].line;
            try out.append(gpa, .{
                .name = name,
                .file_path = sf.path,
                .file_rel = sf.rel_path,
                .line = toks[start_i].line,
                .body_start_line = body_start_line,
                .body_end_line = body_end_line,
            });
            i = header.r_brace_idx;
        }
    }
}

// First body line = first non-blank line strictly after the `{` line.
// (Mirrors Python's extract_function_body: it returns the 1-based line
// of the first non-blank body line.)
fn computeFirstBodyLine(sf: *const SourceFile, toks: []const Tok, hdr: FnHeader) u32 {
    const open_line = toks[hdr.l_brace_idx].line;
    const close_line = toks[hdr.r_brace_idx].line;
    // Same-line body: brace and close on same line.
    if (open_line == close_line) return open_line;
    // Check the rest of the open brace's line for non-blank content
    // after the `{`.
    const l = open_line - 1;
    const line = sf.stripped_lines[l];
    const lb_col = toks[hdr.l_brace_idx].col;
    const after = trimAscii(line[lb_col + 1 ..]);
    if (after.len > 0) return open_line;
    // Else first non-blank line after.
    var ln: u32 = open_line + 1;
    while (ln <= close_line) : (ln += 1) {
        const s = trimAscii(sf.stripped_lines[ln - 1]);
        if (s.len > 0) return ln;
    }
    return open_line + 1;
}

// -----------------------------------------------------------------
// Build function index for inlining (receiver-type, name).
// -----------------------------------------------------------------

fn buildFnIndex(
    gpa: Allocator,
    files: []const *SourceFile,
    tokens_per_file: []const []const Tok,
    slab_types: *const SlabTypeMap,
    idx: *FnIndex,
) !void {
    for (files, tokens_per_file) |sf, toks| {
        // Skip arch/dispatch/ trampolines.
        if (mem.startsWith(u8, sf.rel_path, "kernel/arch/dispatch/")) continue;
        var i: usize = 0;
        while (i < toks.len) : (i += 1) {
            if (toks[i].tag != .keyword_fn) continue;
            var start_i = i;
            if (i > 0 and toks[i - 1].tag == .keyword_pub) start_i = i - 1;
            // Mirror Python: its regex anchors to `^\s*(?:pub\s+)?fn` and
            // so skips `inline fn`, `export fn`, `extern fn`, etc. We do
            // the same by inspecting the stripped header line.
            {
                const hdr_line_raw = sf.raw_lines[toks[start_i].line - 1];
                const hdr_line = trimAscii(hdr_line_raw);
                if (!(mem.startsWith(u8, hdr_line, "fn ") or
                    mem.startsWith(u8, hdr_line, "pub fn ")))
                {
                    continue;
                }
            }
            const header = parseFnHeaderAt(toks, start_i) orelse continue;
            // First param must resolve to slab type.
            const params = parseParamList(gpa, sf, toks, header.l_paren_idx, header.r_paren_idx) catch {
                i = header.r_brace_idx;
                continue;
            };
            if (params.len == 0) {
                gpa.free(params);
                i = header.r_brace_idx;
                continue;
            }
            const recv = parseTypeRef(params[0].type_str) orelse {
                gpa.free(params);
                i = header.r_brace_idx;
                continue;
            };
            if (!slab_types.contains(recv)) {
                gpa.free(params);
                i = header.r_brace_idx;
                continue;
            }
            const name = tokSlice(sf, toks[header.name_tok_idx]);
            const key = FnKey{ .recv = recv, .name = name };
            if (idx.contains(key)) {
                gpa.free(params);
                i = header.r_brace_idx;
                continue;
            }
            const rt_str = returnTypeSlice(sf, toks, header.r_paren_idx, header.l_brace_idx);
            var rt: ?[]const u8 = parseReturnType(rt_str);
            if (rt != null and !slab_types.contains(rt.?)) rt = null;

            // Body line range.
            const body_start = computeFirstBodyLine(sf, toks, header);
            const body_end = toks[header.r_brace_idx].line;

            const info = try gpa.create(FnInfo);
            info.* = .{
                .file_path = sf.path,
                .file_rel = sf.rel_path,
                .line = toks[start_i].line,
                .first_param = params[0].name,
                .other_params = if (params.len > 1) blk: {
                    const others = try gpa.alloc(ParamSpec, params.len - 1);
                    @memcpy(others, params[1..]);
                    break :blk others;
                } else &[_]ParamSpec{},
                .body_start_line = body_start,
                .body_end_line = body_end,
                .receiver_type = recv,
                .return_type = rt,
            };
            gpa.free(params);
            try idx.put(key, info);
            i = header.r_brace_idx;
        }
    }
}

// -----------------------------------------------------------------
// Gen-lock bracket analysis per entry point.
// -----------------------------------------------------------------
//
// Each entry walks its own body once with a fresh ident env. Call
// sites look up the callee's memoized summary (see Summary below) and
// fold its effects into the caller's per-ident event timeline at the
// real source line of the call. Callee-internal locals never enter
// the caller env — that was the old inline-expansion mode, whose
// ident-scoping collisions caused ghost bracket failures on unrelated
// function locals like `prev` or `restored_caller_ref`.

const SlabEnv = struct {
    map: StringStringMap,
    fat: SliceSet,
    self_alive: SliceSet,
    // Broader type-of ident registry — covers NON-slab locals too.
    // Used by the lock-ordering analyzer to resolve `<ident>.<lock_field>.lock()`
    // into a `<StructType>.<lock_field>` class when the ident isn't
    // slab-typed but does have a known struct type (method receiver,
    // non-slab fn param, etc.). Entries are interned.
    all_types: StringStringMap,

    fn init(gpa: Allocator) SlabEnv {
        return .{
            .map = StringStringMap.init(gpa),
            .fat = SliceSet.init(gpa),
            .self_alive = SliceSet.init(gpa),
            .all_types = StringStringMap.init(gpa),
        };
    }
    fn deinit(self: *SlabEnv) void {
        self.map.deinit();
        self.fat.deinit();
        self.self_alive.deinit();
        self.all_types.deinit();
    }
};

// Find the source file object whose path matches.
fn fileByPath(files: []const *SourceFile, path: []const u8) ?*const SourceFile {
    for (files) |sf| if (mem.eql(u8, sf.path, path)) return sf;
    return null;
}

// -----------------------------------------------------------------
// Per-body walk
// -----------------------------------------------------------------

// Interned string pool — every ident/string that gets stored in env /
// self_alive / fat / accesses / lock_ops goes through here. Backed by a
// hash set keyed on the bytes, so the same text always maps to the same
// slice. Lifetime: same as the arena.
const Pool = struct {
    gpa: Allocator,
    set: StringHashMap(void),

    fn init(gpa: Allocator) Pool {
        return .{ .gpa = gpa, .set = StringHashMap(void).init(gpa) };
    }
    fn deinit(self: *Pool) void {
        var it = self.set.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        self.set.deinit();
    }
    fn intern(self: *Pool, s: []const u8) ![]const u8 {
        if (self.set.getKey(s)) |existing| return existing;
        const owned = try self.gpa.dupe(u8, s);
        try self.set.put(owned, {});
        return owned;
    }
};

// -----------------------------------------------------------------
// Function summary = what a function does with each of its slab-typed
// params. Events from internal non-param locals are NOT part of the
// summary — they only exist for the function's own internal bracket
// check and never leak to callers. This is the key fix that kills the
// previous inline-expansion ident-scoping false-positives.
// -----------------------------------------------------------------

// A callee event describes one effect on a specific param (or a locally-
// created slab object returned to the caller). The caller remaps the
// param index to its passed-in ident and folds the event into its own
// timeline at the call-site's source line.
const ParamEventKind = enum {
    access,
    lock,
    unlock,
    defer_unlock,
    lock_with_gen,
};

const ParamEvent = struct {
    kind: ParamEventKind,
    param_idx: usize,
    order: u32, // relative order within the callee body
    tail: []const u8 = "",
    // Mirrors Event.group_id — preserved through summary/fold so an
    // ordered-pair helper call inside a helper function still
    // suppresses the same-type self-loop when its caller replays the
    // summary. group_id values are unique within one walk (callee's
    // walk produces them), so folding into a caller where the caller
    // has its own ordered_group_counter can't collide — we remap by
    // adding a caller-side offset at fold time. For v1 we just preserve
    // the callee's value; collisions across callees are rare enough
    // that they'd appear as an accidental suppression, not a cycle
    // false-positive — and the SCC still fires if any other site also
    // establishes the same edge.
    group_id: u32 = 0,
    // Mirrors Event.lock_class. Required for plain SpinLock / non-
    // gen-lock classifications to survive summary → fold: the callee
    // resolves `<recv>.<field>.lock()` to a class like "Vmm.lock" and
    // stamps that on the lock event; without preserving it through the
    // summary the caller would fall back to `<slab_type>._gen_lock`
    // synthesis and mis-classify the edge.
    lock_class: []const u8 = "",
};

const Summary = struct {
    // Does the function acquire-then-release each param in a balanced way?
    // (Unused for now — kept as a future optimization; the caller folds
    // all events and bracket_check judges tightness.)
    events: []ParamEvent, // owned
    // Slab type per param position (empty string if that position isn't
    // slab-typed). Indexed by param position.
    param_types: [][]const u8, // owned
    // Param names for debugging / callee sig alignment.
    param_names: [][]const u8, // borrowed from source
};

const SummaryMap = std.HashMap(FnKey, *Summary, FnKeyContext, std.hash_map.default_max_load_percentage);

const Ctx = struct {
    gpa: Allocator,
    pool: *Pool,
    files: []const *SourceFile,
    tokens_per_file: []const []const Tok,
    slab_types: *const SlabTypeMap,
    fn_index: *FnIndex,
    summaries: *SummaryMap,
    lock_fields: *const LockFieldMap,
    module_globals: *const StringStringMap,
    field_types: *const StructFieldTypeMap,

    fn fileTokens(self: *const Ctx, sf: *const SourceFile) []const Tok {
        for (self.files, self.tokens_per_file) |f, toks| {
            if (f == sf) return toks;
        }
        return &.{};
    }
};

// Scan a line for atomic builtin call spans `@atomic*(` and `@cmpxchg*(` / `@fence(`,
// returning [start, end) byte ranges (end past matching `)`).
fn atomicCallSpans(gpa: Allocator, line: []const u8) ![]const [2]usize {
    var out = ArrayList([2]usize).empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        if (line[i] != '@') continue;
        // Match builtin name.
        var end = i + 1;
        while (end < line.len and isIdentChar(line[end])) end += 1;
        const name = line[i + 1 .. end];
        const is_atomic_builtin = mem.eql(u8, name, "atomicLoad") or
            mem.eql(u8, name, "atomicStore") or
            mem.eql(u8, name, "atomicRmw") or
            mem.eql(u8, name, "cmpxchgWeak") or
            mem.eql(u8, name, "cmpxchgStrong") or
            mem.eql(u8, name, "fence");
        if (!is_atomic_builtin) continue;
        // Expect `(`.
        var p = end;
        while (p < line.len and ascii.isWhitespace(line[p])) p += 1;
        if (p >= line.len or line[p] != '(') continue;
        // Balanced `)`.
        var depth: i32 = 1;
        p += 1;
        while (p < line.len and depth > 0) : (p += 1) {
            if (line[p] == '(') depth += 1;
            if (line[p] == ')') depth -= 1;
        }
        try out.append(gpa, .{ i, p });
        i = p;
    }
    return out.toOwnedSlice(gpa);
}

fn isAtomicMethodAt(line: []const u8, start: usize) bool {
    // start points at `.` preceding the method. We test whether it
    // matches `.<name>(` where <name> ∈ the atomic-method list.
    if (start >= line.len or line[start] != '.') return false;
    var p = start + 1;
    while (p < line.len and ascii.isWhitespace(line[p])) p += 1;
    var e = p;
    while (e < line.len and isIdentChar(line[e])) e += 1;
    const nm = line[p..e];
    var q = e;
    while (q < line.len and ascii.isWhitespace(line[q])) q += 1;
    if (q >= line.len or line[q] != '(') return false;
    const names = [_][]const u8{
        "load", "store", "cmpxchgWeak", "cmpxchgStrong", "swap", "exchange",
        "fetchAdd", "fetchSub", "fetchOr", "fetchAnd", "fetchXor", "fetchMin", "fetchMax",
        "bitSet", "bitReset", "bitToggle", "raw",
    };
    for (names) |n| if (mem.eql(u8, n, nm)) return true;
    return false;
}

// Does `line` contain `<name>\s*\(` — a call to `<name>`? Pure syntactic.
fn containsCall(line: []const u8, name: []const u8) bool {
    var pos: usize = 0;
    while (pos + name.len <= line.len) : (pos += 1) {
        if (!mem.eql(u8, line[pos .. pos + name.len], name)) continue;
        if (pos > 0 and isIdentChar(line[pos - 1])) continue;
        var p = pos + name.len;
        while (p < line.len and ascii.isWhitespace(line[p])) p += 1;
        if (p < line.len and line[p] == '(') return true;
    }
    return false;
}

// Search `line` for pattern `<leader>.<name>\s*\(`, where `<leader>` is an
// ident. Returns (leader_slice) on first match, or null.
fn findCallOnIdent(line: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos + 1 < line.len) : (pos += 1) {
        if (line[pos] != '.') continue;
        var p = pos + 1;
        while (p < line.len and ascii.isWhitespace(line[p])) p += 1;
        if (p + name.len > line.len) continue;
        if (!mem.eql(u8, line[p .. p + name.len], name)) continue;
        const after = p + name.len;
        if (after < line.len and isIdentChar(line[after])) continue;
        // Must be followed by `(`.
        var q = after;
        while (q < line.len and ascii.isWhitespace(line[q])) q += 1;
        if (q >= line.len or line[q] != '(') continue;
        // Walk back for leader ident.
        var s = pos;
        while (s > 0 and isIdentChar(line[s - 1])) s -= 1;
        if (s == pos) continue;
        return line[s..pos];
    }
    return null;
}

// Parse a decl line in the stripped form. Returns name, ann (may be ""),
// rhs (without trailing `;`) or null.
const DeclParts = struct {
    name: []const u8,
    ann: []const u8,
    rhs: []const u8,
};

fn parseDeclLine(line: []const u8) ?DeclParts {
    var s = trimAscii(line);
    var has_const = false;
    if (mem.startsWith(u8, s, "const ")) {
        s = s[6..];
        has_const = true;
    } else if (mem.startsWith(u8, s, "var ")) {
        s = s[4..];
        has_const = true;
    }
    if (!has_const) return null;
    s = trimAscii(s);
    if (s.len == 0 or !isIdentStart(s[0])) return null;
    var p: usize = 0;
    while (p < s.len and isIdentChar(s[p])) p += 1;
    const name = s[0..p];
    var rest = trimAscii(s[p..]);
    var ann: []const u8 = "";
    if (rest.len > 0 and rest[0] == ':') {
        rest = trimAscii(rest[1..]);
        // Type until `=` at depth 0.
        var depth: i32 = 0;
        var e: usize = 0;
        while (e < rest.len) : (e += 1) {
            const c = rest[e];
            if (c == '(' or c == '[' or c == '{') depth += 1;
            if (c == ')' or c == ']' or c == '}') depth -= 1;
            if (depth == 0 and c == '=') break;
        }
        if (e >= rest.len) return null;
        ann = trimAscii(rest[0..e]);
        rest = rest[e..];
    }
    if (rest.len == 0 or rest[0] != '=') return null;
    rest = trimAscii(rest[1..]);
    if (rest.len == 0) return null;
    // Strip trailing `;`.
    if (rest[rest.len - 1] != ';') return null;
    rest = rstrip(rest[0 .. rest.len - 1]);
    return .{ .name = name, .ann = ann, .rhs = trimAscii(rest) };
}

// Join a decl across multiple lines when it doesn't end in `;`.
fn joinMultilineDecl(
    gpa: Allocator,
    stripped: []const []const u8,
    rel: usize,
) ![]u8 {
    var buf = ArrayList(u8).empty;
    errdefer buf.deinit(gpa);
    try buf.appendSlice(gpa, stripped[rel]);
    const first = trimAscii(stripped[rel]);
    // Only need to join if we look like a decl that doesn't terminate.
    const looks_like_decl = mem.startsWith(u8, first, "const ") or mem.startsWith(u8, first, "var ");
    if (!looks_like_decl) return buf.toOwnedSlice(gpa);
    const first_rs = rstrip(buf.items);
    if (first_rs.len > 0 and first_rs[first_rs.len - 1] == ';') return buf.toOwnedSlice(gpa);
    var look = rel + 1;
    while (look < stripped.len) : (look += 1) {
        try buf.append(gpa, ' ');
        try buf.appendSlice(gpa, trimAscii(stripped[look]));
        const rs = rstrip(buf.items);
        if (rs.len > 0 and rs[rs.len - 1] == ';') return buf.toOwnedSlice(gpa);
    }
    return buf.toOwnedSlice(gpa);
}

// Heuristic: does a leader ident look like a slab-allocator module?
// Matches `<x>_slab`, `<x>Slab`, `<x>Allocator`, or exact `slab_instance`.
// The destroy-after-unlock pattern (`<slab_module>.destroy(ident, gen)`)
// reacquires the gen-lock internally, so the ident access at the call
// site shouldn't require a tight-following unlock in the caller.
fn leaderIsSlabModule(leader: []const u8) bool {
    if (leader.len == 0) return false;
    if (mem.eql(u8, leader, "slab_instance")) return true;
    if (mem.endsWith(u8, leader, "_slab")) return true;
    if (mem.endsWith(u8, leader, "Slab")) return true;
    if (mem.endsWith(u8, leader, "Allocator")) return true;
    return false;
}

// Heuristic: does the RHS indicate a fresh alloc?
// - `<ident>_slab.create(`, `<ident>Slab.create(`, `<ident>Allocator.create(`,
//   `slab_instance.create(`
// - `<SlabType>.create(`
fn isFreshAlloc(rhs: []const u8, slab_types: *const SlabTypeMap) bool {
    if (containsCall(rhs, "create")) {
        // Must be called on a likely-slab name. Look for `.create(`.
        if (findCallOnIdent(rhs, "create")) |leader| {
            if (mem.endsWith(u8, leader, "_slab") or
                mem.endsWith(u8, leader, "Slab") or
                mem.endsWith(u8, leader, "Allocator") or
                mem.eql(u8, leader, "slab_instance")) return true;
            if (slab_types.contains(leader)) return true;
        }
    }
    return false;
}

// Heuristic: is RHS a bare chain `<ident>.ptr` with head in self_alive?
fn isPtrOfFresh(rhs: []const u8, self_alive: *const SliceSet) !bool {
    const chain = trimAscii(rhs);
    if (!mem.endsWith(u8, chain, ".ptr")) return false;
    const prefix = chain[0 .. chain.len - 4];
    // Must be single ident (no further `.` means we need just one ident).
    // Actually Python's test: rhs_chain[-1] == "ptr" and rhs_chain[0] in self_alive.
    // i.e., head is the first element. We parse chain parts.
    var i: usize = 0;
    while (i < prefix.len and isIdentChar(prefix[i])) i += 1;
    if (i == 0) return false;
    const head = prefix[0..i];
    return self_alive.contains(head);
}

// Self-alive comment check: same line OR contiguous `//` block directly
// above.
fn declHasSelfAlive(raw_lines: []const []const u8, rel: usize) bool {
    if (rel < raw_lines.len and containsSelfAliveComment(raw_lines[rel])) return true;
    var k: isize = @as(isize, @intCast(rel)) - 1;
    while (k >= 0) : (k -= 1) {
        const lk = raw_lines[@intCast(k)];
        const t = trimAscii(lk);
        if (!mem.startsWith(u8, t, "//")) break;
        if (containsSelfAliveComment(lk)) return true;
    }
    return false;
}

fn inferRhsType(
    gpa: Allocator,
    rhs: []const u8,
    env: *const SlabEnv,
    slab_types: *const SlabTypeMap,
) !?[]const u8 {
    var s = trimAscii(rhs);
    if (s.len > 0 and s[s.len - 1] == ';') s = trimAscii(s[0 .. s.len - 1]);
    if (s.len == 0) return null;

    // Comparison => bool.
    // Detect `==`, `!=`, `<=`, `>=`, `<`, `>` not adjacent to `-`/`=`.
    const cmp_pats = [_][]const u8{ "==", "!=", "<=", ">=" };
    for (cmp_pats) |p| if (mem.indexOf(u8, s, p) != null) return null;
    // loose < / > detection — needs care about `<-`, `<=`; `<=` already handled.
    var idx: usize = 0;
    while (idx < s.len) : (idx += 1) {
        const c = s[idx];
        if (c == '<' or c == '>') {
            const next: u8 = if (idx + 1 < s.len) s[idx + 1] else 0;
            if (next == '=' or next == '-') continue;
            // likely comparison
            return null;
        }
    }

    s = stripPostfix(s);

    // scheduler.currentThread() / scheduler.currentProc(), exact match.
    const sched_thread = [_][]const u8{
        "scheduler.currentThread()", "sched.currentThread()",
    };
    const sched_proc = [_][]const u8{
        "scheduler.currentProc()", "sched.currentProc()",
    };
    for (sched_thread) |p| if (mem.eql(u8, s, p)) return "Thread";
    for (sched_proc) |p| if (mem.eql(u8, s, p)) return "Process";

    // `<helper>(...)` — call. Extract the name.
    if (s.len > 0 and isIdentStart(s[0])) {
        var e: usize = 0;
        while (e < s.len and isIdentChar(s[e])) e += 1;
        if (e < s.len and s[e] == '(' and mem.endsWith(u8, s, ")")) {
            const nm = s[0..e];
            if (lookupSlabReturnHelper(nm)) |ty| return ty;
        }
    }

    // `<prefix>.<method>(...)` — check known slab-returning methods.
    // Find LAST `.` before `(` in the chain, match pattern.
    if (mem.indexOfScalar(u8, s, '(')) |lp| {
        const before = s[0..lp];
        // Should be ident chain.
        if (before.len > 0) {
            // Find last `.`.
            if (mem.lastIndexOfScalar(u8, before, '.')) |ld| {
                const method = before[ld + 1 ..];
                // Validate method is all ident chars.
                var all_ident = method.len > 0;
                for (method) |c| if (!isIdentChar(c)) {
                    all_ident = false;
                    break;
                };
                const prefix_ok = blk: {
                    for (before[0..ld]) |c| if (!isIdentChar(c) and c != '.') break :blk false;
                    break :blk true;
                };
                if (all_ident and prefix_ok and mem.endsWith(u8, s, ")")) {
                    if (lookupSlabReturnMethod(method)) |ty| return ty;
                }
            }
        }
    }

    // `<entry>.object.<variant>` — exact.
    {
        // match: identifier "." "object" "." variant
        var parts: [3][]const u8 = .{ "", "", "" };
        var pi: usize = 0;
        var seg_start: usize = 0;
        var ok = true;
        var ix: usize = 0;
        while (ix <= s.len) : (ix += 1) {
            if (ix == s.len or s[ix] == '.') {
                if (pi >= 3) {
                    ok = false;
                    break;
                }
                parts[pi] = s[seg_start..ix];
                pi += 1;
                seg_start = ix + 1;
            } else if (!isIdentChar(s[ix])) {
                ok = false;
                break;
            }
        }
        if (ok and pi == 3 and mem.eql(u8, parts[1], "object")) {
            if (lookupUnionVariant(parts[2])) |ty| return ty;
        }
    }

    // `<ident>.<variant>` — exact, where ident is not itself slab-typed.
    {
        var parts: [2][]const u8 = .{ "", "" };
        var pi: usize = 0;
        var seg_start: usize = 0;
        var ok = true;
        var ix: usize = 0;
        while (ix <= s.len) : (ix += 1) {
            if (ix == s.len or s[ix] == '.') {
                if (pi >= 2) {
                    ok = false;
                    break;
                }
                parts[pi] = s[seg_start..ix];
                pi += 1;
                seg_start = ix + 1;
            } else if (!isIdentChar(s[ix])) {
                ok = false;
                break;
            }
        }
        if (ok and pi == 2) {
            const head = parts[0];
            const variant = parts[1];
            const known = [_][]const u8{ "thread", "process", "vm", "shared_memory", "device_region", "dead_process" };
            if (inList(variant, &known)) {
                if (env.map.get(head)) |ht| {
                    if (!slab_types.contains(ht)) return lookupUnionVariant(variant);
                } else {
                    return lookupUnionVariant(variant);
                }
            }
        }
    }

    // Bare chain `A.b.c` — chase DEFAULT_FIELD_CHAINS.
    const chain_opt = try leadingChain(gpa, s);
    if (chain_opt) |chain| {
        defer gpa.free(chain);
        if (chain.len >= 1) {
            if (env.map.get(chain[0])) |head_ty_initial| {
                var ty_opt: ?[]const u8 = head_ty_initial;
                var ok = true;
                for (chain[1..]) |fld| {
                    if (ty_opt) |tt| {
                        if (lookupDefaultFieldChain(tt, fld)) |nxt| {
                            ty_opt = nxt;
                        } else {
                            ok = false;
                            break;
                        }
                    } else {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    if (ty_opt) |tt| {
                        if (slab_types.contains(tt)) return tt;
                    }
                }
            }
        }
    }

    // Bare ident → inherit.
    var all_ident = s.len > 0;
    for (s) |c| if (!isIdentChar(c)) {
        all_ident = false;
        break;
    };
    if (all_ident) {
        if (env.map.get(s)) |ty| return ty;
    }

    return null;
}

// -----------------------------------------------------------------
// Walk one body
// -----------------------------------------------------------------

const WalkError = error{ OutOfMemory };

// Per-ident event list. Each entry captures a real source line, so
// error messages bottom out at the actual kernel line where the access
// happened rather than at a synthetic counter.
const EventList = ArrayList(Event);
const EventMap = StringHashMap(EventList);

// A shared scratch bag the line-walker threads through:
//   * emit_map — the ident→events map we populate (owned by caller)
//   * param_set — idents that are params of the function currently being
//     walked. For summary builds, the walker only considers these idents
//     observable. For entry walks, this is empty (all entry locals are
//     observable).
//   * emit_param_only — when true, non-param ident events are silently
//     dropped (summary mode).
const EmitCtx = struct {
    events: *EventMap,
    seq: *u32,
    param_set: *const SliceSet,
    emit_param_only: bool,
};

fn emitEvent(
    gpa: Allocator,
    ec: *EmitCtx,
    ident: []const u8,
    kind: EventKind,
    src_line: u32,
    tail: []const u8,
    slab_type: []const u8,
) !void {
    return emitEventG(gpa, ec, ident, kind, src_line, tail, slab_type, 0);
}

fn emitEventG(
    gpa: Allocator,
    ec: *EmitCtx,
    ident: []const u8,
    kind: EventKind,
    src_line: u32,
    tail: []const u8,
    slab_type: []const u8,
    group_id: u32,
) !void {
    return emitEventGC(gpa, ec, ident, kind, src_line, tail, slab_type, group_id, "");
}

fn emitEventGC(
    gpa: Allocator,
    ec: *EmitCtx,
    ident: []const u8,
    kind: EventKind,
    src_line: u32,
    tail: []const u8,
    slab_type: []const u8,
    group_id: u32,
    lock_class: []const u8,
) !void {
    if (ec.emit_param_only and !ec.param_set.contains(ident)) return;
    const gop = try ec.events.getOrPut(ident);
    if (!gop.found_existing) gop.value_ptr.* = EventList.empty;
    ec.seq.* += 1;
    try gop.value_ptr.append(gpa, .{
        .kind = kind,
        .src_line = src_line,
        .seq = ec.seq.*,
        .tail = tail,
        .slab_type = slab_type,
        .group_id = group_id,
        .lock_class = lock_class,
    });
}

// Summary build is memoized in ctx.summaries. Cycles return an empty
// summary placeholder — any slab-typed param still gets listed so the
// caller's summary lookup finds an entry and doesn't fall through to
// the "treat call as a raw access" fallback.
fn getOrBuildSummary(
    ctx: *Ctx,
    recv: []const u8,
    name: []const u8,
) WalkError!?*Summary {
    const key = FnKey{ .recv = recv, .name = name };
    if (ctx.summaries.get(key)) |s| return s;
    const fi = ctx.fn_index.get(key) orelse return null;
    // Install an empty placeholder first to break cycles cleanly.
    const placeholder = try ctx.gpa.create(Summary);
    placeholder.* = .{
        .events = &[_]ParamEvent{},
        .param_types = &[_][]const u8{},
        .param_names = &[_][]const u8{},
    };
    try ctx.summaries.put(key, placeholder);

    // Gather all params of the callee (including non-slab ones; we need
    // positional alignment so caller arg[i] maps to callee param[i]).
    const sf = fileByPath(ctx.files, fi.file_path) orelse return placeholder;
    const toks = ctx.fileTokens(sf);
    // Re-find the fn header by scanning tokens at fi.line.
    var hdr: ?FnHeader = null;
    for (toks, 0..) |t, ti| {
        if (t.tag != .keyword_fn) continue;
        var si = ti;
        if (ti > 0 and toks[ti - 1].tag == .keyword_pub) si = ti - 1;
        if (toks[si].line != fi.line) continue;
        if (ti + 1 >= toks.len) continue;
        if (!mem.eql(u8, tokSlice(sf, toks[ti + 1]), name)) continue;
        hdr = parseFnHeaderAt(toks, si) orelse continue;
        break;
    }
    if (hdr == null) return placeholder;
    const params = try parseParamList(ctx.gpa, sf, toks, hdr.?.l_paren_idx, hdr.?.r_paren_idx);
    defer ctx.gpa.free(params);

    const param_types = try ctx.gpa.alloc([]const u8, params.len);
    const param_names = try ctx.gpa.alloc([]const u8, params.len);

    var param_set = SliceSet.init(ctx.gpa);
    defer param_set.deinit();

    var env = SlabEnv.init(ctx.gpa);
    defer env.deinit();

    for (params, 0..) |pp, pi| {
        const interned = try ctx.pool.intern(pp.name);
        param_names[pi] = interned;
        const ty_opt = parseTypeRef(pp.type_str);
        if (ty_opt) |ty| if (ctx.slab_types.contains(ty)) {
            const ty_i = try ctx.pool.intern(ty);
            param_types[pi] = ty_i;
            try env.map.put(interned, ty_i);
            try env.all_types.put(interned, ty_i);
            if (mem.indexOf(u8, pp.type_str, "SlabRef") != null) try env.fat.add(interned);
            try param_set.add(interned);
            continue;
        };
        param_types[pi] = "";
        // Non-slab param: track bare type name so receiver chains
        // through this ident can classify plain SpinLock/GenLock
        // fields (e.g. `self.perm_lock.lock()` with `self: *Process`).
        const bare = typeNameFromFieldType(pp.type_str);
        if (bare.len > 0) {
            const bare_i = try ctx.pool.intern(bare);
            try env.all_types.put(interned, bare_i);
        }
    }

    var events_map = EventMap.init(ctx.gpa);
    defer {
        var it = events_map.valueIterator();
        while (it.next()) |al| al.deinit(ctx.gpa);
        events_map.deinit();
    }
    var seq: u32 = 0;
    var ec = EmitCtx{
        .events = &events_map,
        .seq = &seq,
        .param_set = &param_set,
        .emit_param_only = true,
    };

    try walkBody(ctx, sf, fi.body_start_line, fi.body_end_line, &env, &ec);

    // Materialize into ParamEvent list.
    var events = ArrayList(ParamEvent).empty;
    errdefer events.deinit(ctx.gpa);
    // Flatten: iterate per-param so callers can match by position cheaply.
    for (params, 0..) |pp, pi| {
        if (param_types[pi].len == 0) continue;
        const interned = try ctx.pool.intern(pp.name);
        const lst_opt = events_map.getPtr(interned);
        if (lst_opt == null) continue;
        for (lst_opt.?.items) |ev| {
            const tail_i = if (ev.tail.len > 0) try ctx.pool.intern(ev.tail) else "";
            try events.append(ctx.gpa, .{
                .kind = switch (ev.kind) {
                    .access => .access,
                    .lock => .lock,
                    .unlock => .unlock,
                    .defer_unlock => .defer_unlock,
                    .lock_with_gen => .lock_with_gen,
                },
                .param_idx = pi,
                .order = ev.seq,
                .tail = tail_i,
                .group_id = ev.group_id,
                .lock_class = ev.lock_class,
            });
        }
    }
    // Sort by seq so caller folds events in the callee's source order.
    std.sort.heap(ParamEvent, events.items, {}, lessParamEvent);

    placeholder.events = try events.toOwnedSlice(ctx.gpa);
    placeholder.param_types = param_types;
    placeholder.param_names = param_names;
    return placeholder;
}

fn lessParamEvent(_: void, a: ParamEvent, b: ParamEvent) bool {
    return a.order < b.order;
}

// Fold a callee summary into the caller's events at call-site src_line.
// `caller_args[i]` is the caller's arg at position i (null when the arg
// isn't a plain ident). For each param-event on position i, if the
// caller passed a tracked ident there, emit a matching caller-side
// event. Non-tracked args cause the callee events on that param to be
// silently dropped — the caller literally doesn't have a local of that
// name to bracket-check.
fn foldSummary(
    ctx: *Ctx,
    summary: *const Summary,
    caller_args: []const ?[]const u8,
    env: *const SlabEnv,
    ec: *EmitCtx,
    src_line: u32,
) !void {
    for (summary.events) |pe| {
        if (pe.param_idx >= caller_args.len) continue;
        const arg_opt = caller_args[pe.param_idx];
        if (arg_opt == null) continue;
        const arg = arg_opt.?;
        const arg_ty = env.map.get(arg) orelse continue;
        _ = arg_ty;
        const kind: EventKind = switch (pe.kind) {
            .access => .access,
            .lock => .lock,
            .unlock => .unlock,
            .defer_unlock => .defer_unlock,
            .lock_with_gen => .lock_with_gen,
        };
        const slab_ty = env.map.get(arg) orelse "";
        try emitEventGC(ctx.gpa, ec, arg, kind, src_line, pe.tail, slab_ty, pe.group_id, pe.lock_class);
    }
}

// -----------------------------------------------------------------
// walkBody: drive the line-by-line scanner over a function body.
//
// Emits events through the EmitCtx. Responsibilities:
//   * maintain env (decl-introduced locals and their slab types)
//   * emit lock/unlock/defer-unlock events when it sees a lock op
//   * emit access events for `.field` / `.method` references
//   * at each call site, look up the callee summary and fold its
//     effects into the caller's event timeline at the call-site line
//
// It does NOT recurse into callee bodies with the caller's env (that
// was the inline-expansion mode; gone). Each function body walks once
// with its OWN env; cross-function effects flow through summaries.
// -----------------------------------------------------------------

fn walkBody(
    ctx: *Ctx,
    sf: *const SourceFile,
    body_start_line: u32, // 1-based
    body_end_line: u32, // 1-based, inclusive of closing brace line
    env: *SlabEnv,
    ec: *EmitCtx,
) WalkError!void {
    const gpa = ctx.gpa;
    if (body_start_line > body_end_line) return;
    if (body_end_line > sf.stripped_lines.len) return;
    const start_i: usize = body_start_line - 1;
    const end_i: usize = body_end_line - 1;
    if (start_i >= end_i) return;
    const body_lines = sf.stripped_lines[start_i..end_i];
    const raw_lines = sf.raw_lines[start_i..end_i];

    // Tracker for brace-depth-aware defers.
    const Pending = struct { ident: []const u8, fire_at_depth: i32 };
    var pending_defers = ArrayList(Pending).empty;
    defer pending_defers.deinit(gpa);
    var brace_depth: i32 = 0;

    // Monotonic group counter for ordered-pair helper calls within this
    // body walk. Each call to `lockPair(a, b)` gets a unique non-zero
    // group_id that's stamped into every lock event it emits; the cycle
    // detector uses matching group_ids to suppress the same-type pair
    // between the helper's argument locks.
    var ordered_group_counter: u32 = 0;

    for (body_lines, 0..) |line, rel| {
        const src_line: u32 = body_start_line + @as(u32, @intCast(rel));
        const code = line;

        // for-loop captures: Process.threads is [MAX_THREADS]*Thread.
        if (mem.startsWith(u8, trimAscii(code), "for ") or mem.startsWith(u8, trimAscii(code), "for(")) {
            if (mem.indexOf(u8, code, ") |")) |bp| {
                const after = code[bp + 3 ..];
                var e: usize = 0;
                while (e < after.len and isIdentChar(after[e])) e += 1;
                if (e > 0) {
                    const cap = after[0..e];
                    if (mem.indexOfScalar(u8, code, '(')) |lp| {
                        if (bp > lp) {
                            const inner = trimAscii(code[lp + 1 .. bp]);
                            var p2: usize = 0;
                            while (p2 < inner.len and isIdentChar(inner[p2])) p2 += 1;
                            const head = inner[0..p2];
                            if (head.len > 0 and env.map.contains(head)) {
                                var segments = ArrayList([]const u8).empty;
                                defer segments.deinit(gpa);
                                var seg_start: usize = 0;
                                var j: usize = 0;
                                while (j < inner.len) : (j += 1) {
                                    if (inner[j] == '.') {
                                        try segments.append(gpa, inner[seg_start..j]);
                                        seg_start = j + 1;
                                    }
                                }
                                if (seg_start <= inner.len) try segments.append(gpa, inner[seg_start..inner.len]);
                                var tail_last: ?[]const u8 = null;
                                if (segments.items.len > 1) {
                                    const last_seg = segments.items[segments.items.len - 1];
                                    var tt: []const u8 = last_seg;
                                    if (mem.indexOfScalar(u8, last_seg, '[')) |b| tt = last_seg[0..b];
                                    tail_last = tt;
                                }
                                if (tail_last) |tl| {
                                    if (mem.eql(u8, tl, "threads")) {
                                        try env.map.put(try ctx.pool.intern(cap), "Thread");
                                    } else if (mem.eql(u8, tl, "children")) {
                                        try env.map.put(try ctx.pool.intern(cap), "Process");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Decl parsing (multi-line aware).
        const joined = try joinMultilineDecl(gpa, body_lines, rel);
        defer gpa.free(joined);
        if (parseDeclLine(joined)) |dp_raw| {
            const dp = DeclParts{
                .name = try ctx.pool.intern(dp_raw.name),
                .ann = dp_raw.ann,
                .rhs = dp_raw.rhs,
            };
            var is_fat = mem.indexOf(u8, dp.ann, "SlabRef") != null or mem.indexOf(u8, dp.rhs, "SlabRef") != null;
            if (!is_fat) {
                for (FAT_SLAB_RETURN_NAMES) |fn_name| {
                    if (containsCall(dp.rhs, fn_name)) {
                        is_fat = true;
                        break;
                    }
                }
            }
            if (!is_fat) {
                const rhs_plain = stripPostfix(dp.rhs);
                if (mem.indexOfScalar(u8, rhs_plain, '.')) |dotp| {
                    const head = rhs_plain[0..dotp];
                    const tail = rhs_plain[dotp + 1 ..];
                    var all_ident_h = head.len > 0;
                    for (head) |c| if (!isIdentChar(c)) { all_ident_h = false; break; };
                    var all_ident_t = tail.len > 0;
                    for (tail) |c| if (!isIdentChar(c)) { all_ident_t = false; break; };
                    if (all_ident_h and all_ident_t) {
                        if (env.map.get(head)) |head_ty| {
                            if (isFatYieldingField(head_ty, tail)) is_fat = true;
                        }
                        // Even when <head> isn't in env.map — e.g.
                        // `target_proc_ref = target.process` where `target`
                        // came out of a chained `.lock()` whose return type
                        // the analyzer didn't resolve — the tail segment
                        // alone can identify a SlabRef-yielding field: every
                        // KernelObject union variant is SlabRef(T), and
                        // every FAT_YIELDING_FIELDS entry is too. Match the
                        // tail lexically so chained assignments through
                        // un-tracked intermediaries still land `is_fat=true`.
                        if (!is_fat and lookupUnionVariant(tail) != null) is_fat = true;
                        if (!is_fat) {
                            for (FAT_YIELDING_FIELDS) |e| {
                                if (mem.eql(u8, e.field, tail)) { is_fat = true; break; }
                            }
                        }
                    }
                }
            }

            var lock_alias_ref: ?[]const u8 = null;
            {
                const rhs_plain = stripPostfix(dp.rhs);
                if (mem.indexOfScalar(u8, rhs_plain, '.')) |dotp| {
                    const head = rhs_plain[0..dotp];
                    const tail = rhs_plain[dotp + 1 ..];
                    if (mem.eql(u8, tail, "lock()")) {
                        var all_ident_h = head.len > 0;
                        for (head) |c| if (!isIdentChar(c)) { all_ident_h = false; break; };
                        if (all_ident_h and env.fat.contains(head)) {
                            lock_alias_ref = head;
                        }
                    }
                }
            }

            var resolved: ?[]const u8 = null;
            if (lock_alias_ref) |lr| {
                if (env.map.get(lr)) |lrty| {
                    if (ctx.slab_types.contains(lrty)) resolved = lrty;
                }
            }
            if (resolved == null and dp.ann.len > 0) {
                if (parseTypeRef(dp.ann)) |ty| {
                    if (ctx.slab_types.contains(ty)) resolved = ty;
                }
            }
            if (resolved == null) {
                if (try inferRhsType(gpa, dp.rhs, env, ctx.slab_types)) |ty| {
                    if (ctx.slab_types.contains(ty)) resolved = ty;
                }
            }
            if (resolved == null) {
                const rhs_plain = stripPostfix(dp.rhs);
                if (rhs_plain.len > 0 and isIdentStart(rhs_plain[0])) {
                    var pp: usize = 0;
                    while (pp < rhs_plain.len and (isIdentChar(rhs_plain[pp]) or rhs_plain[pp] == '.')) pp += 1;
                    if (pp < rhs_plain.len and rhs_plain[pp] == '(') {
                        const fq = rhs_plain[0..pp];
                        var fn_nm: []const u8 = fq;
                        if (mem.lastIndexOfScalar(u8, fq, '.')) |lastd| fn_nm = fq[lastd + 1 ..];
                        var p2 = pp + 1;
                        while (p2 < rhs_plain.len and ascii.isWhitespace(rhs_plain[p2])) p2 += 1;
                        var e2 = p2;
                        while (e2 < rhs_plain.len and isIdentChar(rhs_plain[e2])) e2 += 1;
                        if (e2 > p2) {
                            const first_arg = rhs_plain[p2..e2];
                            if (env.map.get(first_arg)) |at| {
                                if (ctx.fn_index.get(.{ .recv = at, .name = fn_nm })) |fi| {
                                    if (fi.return_type) |rt| {
                                        if (ctx.slab_types.contains(rt)) resolved = rt;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            var became_self_alive = false;
            for (SELF_ALIVE_HELPERS) |helper| {
                if (containsCall(dp.rhs, helper)) {
                    try env.self_alive.add(dp.name);
                    became_self_alive = true;
                    break;
                }
            }
            if (!became_self_alive) {
                const chain_opt = try leadingChain(gpa, dp.rhs);
                if (chain_opt) |chain| {
                    defer gpa.free(chain);
                    if (chain.len == 1 and env.self_alive.contains(chain[0])) {
                        try env.self_alive.add(dp.name);
                        became_self_alive = true;
                    }
                }
            }
            if (!became_self_alive) {
                const fresh = isFreshAlloc(dp.rhs, ctx.slab_types);
                const ptr_fresh = try isPtrOfFresh(dp.rhs, &env.self_alive);
                if (fresh or ptr_fresh) {
                    try env.self_alive.add(dp.name);
                    became_self_alive = true;
                }
            }

            if (resolved) |rt| {
                const rt_i = try ctx.pool.intern(rt);
                try env.map.put(dp.name, rt_i);
                try env.all_types.put(dp.name, rt_i);
                if (is_fat) try env.fat.add(dp.name);
                if (lock_alias_ref != null) try env.self_alive.add(dp.name);
            } else if (dp.ann.len > 0) {
                // Non-slab annotation — record bare type in all_types so
                // plain SpinLock/GenLock field accesses through this local
                // can classify. `*PerCoreState`, `Vmm`, `*const Foo`, etc.
                const bare = typeNameFromFieldType(dp.ann);
                if (bare.len > 0) {
                    const bare_i = try ctx.pool.intern(bare);
                    try env.all_types.put(dp.name, bare_i);
                }
            } else {
                // No annotation — try to resolve via module-global lookup
                // of the RHS. Patterns we handle:
                //   `&<name>`, `&<name>[...]`, `<name>`, `<name>[...]`
                // each produces a local of (element) type <name>'s
                // declared bare type. Covers scheduler-style per-core
                // state slots and similar module-backed data.
                const rhs_plain = stripPostfix(dp.rhs);
                var start: usize = 0;
                if (rhs_plain.len > 0 and rhs_plain[0] == '&') start = 1;
                while (start < rhs_plain.len and ascii.isWhitespace(rhs_plain[start])) start += 1;
                var end: usize = start;
                while (end < rhs_plain.len and isIdentChar(rhs_plain[end])) end += 1;
                if (end > start) {
                    const lead = rhs_plain[start..end];
                    // Accept if the only trailing content is `[...]` or
                    // the string ends immediately — anything else (like
                    // `.field`, `(`, `+`) means the RHS isn't a plain
                    // global reference.
                    const after = trimAscii(rhs_plain[end..]);
                    const plain_ok = after.len == 0 or after[0] == '[';
                    if (plain_ok) {
                        if (ctx.module_globals.get(lead)) |mty| {
                            try env.all_types.put(dp.name, mty);
                        }
                    }
                }
            }

            if (!became_self_alive) {
                if (declHasSelfAlive(raw_lines, rel)) try env.self_alive.add(dp.name);
            }
        }

        // Refcount-pin detector.
        {
            const t = trimAscii(code);
            if (mem.startsWith(u8, t, "defer ")) {
                const rest = trimAscii(t[6..]);
                if (rest.len > 0 and isIdentStart(rest[0])) {
                    var p: usize = 0;
                    while (p < rest.len and isIdentChar(rest[p])) p += 1;
                    const nm = rest[0..p];
                    const tail = trimAscii(rest[p..]);
                    if (mem.startsWith(u8, tail, ".releaseRef(") or mem.startsWith(u8, tail, ".decRef(")) {
                        try env.self_alive.add(try ctx.pool.intern(nm));
                    }
                }
            }
        }

        // Lock-op detection: `ident._gen_lock.<op>`.
        {
            const lg = "._gen_lock.";
            var pos: usize = 0;
            while (pos < code.len) {
                const idx_opt = mem.indexOf(u8, code[pos..], lg);
                if (idx_opt == null) break;
                const idx = pos + idx_opt.?;
                var sidx: usize = idx;
                while (sidx > 0 and isIdentChar(code[sidx - 1])) sidx -= 1;
                if (sidx == idx) { pos = idx + lg.len; continue; }
                const ident = code[sidx..idx];
                const op_start = idx + lg.len;
                var op_end = op_start;
                while (op_end < code.len and isIdentChar(code[op_end])) op_end += 1;
                const op_name = code[op_start..op_end];
                const is_lock = mem.eql(u8, op_name, "lock");
                const is_unlock = mem.eql(u8, op_name, "unlock");
                const is_lwg = mem.eql(u8, op_name, "lockWithGen");
                if ((is_lock or is_unlock or is_lwg) and env.map.contains(ident)) {
                    const is_defer = isDeferFor(code, ident);
                    const kind: EventKind = if (is_defer and is_unlock)
                        .defer_unlock
                    else if (is_lock) .lock
                    else if (is_unlock) .unlock
                    else .lock_with_gen;
                    const ident_i = try ctx.pool.intern(ident);
                    try emitEvent(gpa, ec, ident_i, kind, src_line, "", env.map.get(ident) orelse "");
                    if (is_defer and is_unlock) {
                        try pending_defers.append(gpa, .{ .ident = ident_i, .fire_at_depth = brace_depth });
                    }
                }
                pos = op_end;
            }
        }

        // SlabRef form: `ident.lock()` / `ident.unlock()`.
        {
            var pos: usize = 0;
            while (pos < code.len) {
                const lock_p = mem.indexOf(u8, code[pos..], ".lock(");
                const unlock_p = mem.indexOf(u8, code[pos..], ".unlock(");
                var hit: ?usize = null;
                var op_name: []const u8 = "";
                var skip: usize = 0;
                if (lock_p != null and (unlock_p == null or lock_p.? < unlock_p.?)) {
                    hit = pos + lock_p.?;
                    op_name = "lock";
                    skip = ".lock(".len;
                } else if (unlock_p != null) {
                    hit = pos + unlock_p.?;
                    op_name = "unlock";
                    skip = ".unlock(".len;
                }
                if (hit == null) break;
                const at = hit.?;
                var leader_end: usize = at;
                if (at >= 2 and code[at - 2] == '.' and code[at - 1] == '?') {
                    leader_end = at - 2;
                }
                // Walk back through idents AND dots to capture full
                // receiver chain. Plain-ident case still works (chain
                // with no dots); chain case picks up patterns like
                // `entry.object.thread.lock()` where the final segment
                // is a known fat-yielding field.
                var sidx: usize = leader_end;
                while (sidx > 0) {
                    const c = code[sidx - 1];
                    if (isIdentChar(c) or c == '.') {
                        sidx -= 1;
                    } else break;
                }
                if (sidx == leader_end) { pos = at + skip; continue; }
                const full = code[sidx..leader_end];
                // Plain-ident fast path.
                if (mem.indexOfScalar(u8, full, '.') == null) {
                    const ident = full;
                    if (env.map.contains(ident) and env.fat.contains(ident)) {
                        const is_defer = isDeferForFat(code, ident);
                        const kind: EventKind = if (is_defer and mem.eql(u8, op_name, "unlock"))
                            .defer_unlock
                        else if (mem.eql(u8, op_name, "lock")) .lock
                        else .unlock;
                        const ident_i = try ctx.pool.intern(ident);
                        try emitEvent(gpa, ec, ident_i, kind, src_line, "", env.map.get(ident) orelse "");
                        if (is_defer and mem.eql(u8, op_name, "unlock")) {
                            try pending_defers.append(gpa, .{ .ident = ident_i, .fire_at_depth = brace_depth });
                        }
                    }
                    pos = at + skip;
                    continue;
                }
                // Chain case: last segment must be a known fat-yielding
                // field (UNION_VARIANTS covers KernelObject slots like
                // `.object.thread`, `.object.process`; FAT_YIELDING_FIELDS
                // covers direct struct-field fat refs like `thread.process`,
                // `vcpu.thread`). The slab type carried by the event comes
                // from whichever table matched.
                const last_seg_start = (mem.lastIndexOfScalar(u8, full, '.') orelse 0) + 1;
                const last_seg = full[last_seg_start..];
                var chain_slab_ty: []const u8 = "";
                if (lookupUnionVariant(last_seg)) |ty| chain_slab_ty = ty;
                if (chain_slab_ty.len == 0) {
                    for (FAT_YIELDING_FIELDS) |e| {
                        if (mem.eql(u8, e.field, last_seg)) {
                            // Field can belong to multiple owners but all
                            // our current entries yield the same slab type
                            // per tail name (e.g. "process" always yields
                            // Process). Resolve via DEFAULT_FIELD_CHAINS.
                            for (DEFAULT_FIELD_CHAINS) |d| {
                                if (mem.eql(u8, d.field, last_seg)) {
                                    chain_slab_ty = d.ty;
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
                if (chain_slab_ty.len == 0) {
                    pos = at + skip;
                    continue;
                }
                // Chain as synthetic ident; different sites on different
                // chains get distinct idents, but all carry the same
                // slab_type so the pair extractor treats them as the
                // same lock class. This is precisely what catches
                // same-type-two-instance deadlocks (two `.lock()` calls
                // on different chain expressions that both resolve to
                // Thread — the classic two-lock self-deadlock).
                const chain_i = try ctx.pool.intern(full);
                const ty_i = try ctx.pool.intern(chain_slab_ty);
                // `defer <chain>.unlock()` — detect by scanning for
                // `defer ` before the chain start on the same line. This
                // matters for the lock-order simulator: popping on the
                // defer statement rather than at scope exit would make
                // the chain's lock look released at the defer line,
                // hiding any nested same-type acquire downstream.
                const is_defer_chain = mem.indexOf(u8, code[0..sidx], "defer ") != null;
                const kind: EventKind = if (mem.eql(u8, op_name, "lock"))
                    .lock
                else if (is_defer_chain)
                    .defer_unlock
                else
                    .unlock;
                try emitEvent(gpa, ec, chain_i, kind, src_line, "", ty_i);
                if (is_defer_chain and mem.eql(u8, op_name, "unlock")) {
                    try pending_defers.append(gpa, .{ .ident = chain_i, .fire_at_depth = brace_depth });
                }
                pos = at + skip;
            }
        }

        // Generic lock-field scan: `<chain>.lock()` / `.unlock()` on a
        // plain SpinLock (or any LOCK_TYPE_NAMES member) field. The
        // receiver's owner type must resolve via env.all_types for the
        // call to classify — unclassifiable calls are left alone (they
        // won't contribute to the lock-order graph). Classification
        // produces a class name like `"Vmm.lock"`, `"Process.perm_lock"`.
        //
        // This block explicitly SKIPS any call that's already handled by
        // the earlier SlabRef / _gen_lock blocks — those emit events
        // with the slab_type alone and the pair extractor synthesizes
        // `"<Slab>._gen_lock"` from it. Double-emitting would produce
        // ghost pairs.
        //
        // Both `.lock(` and `.lockIrqSave(` acquire; `.unlock(` and
        // `.unlockIrqRestore(` release. The IRQ variants live on
        // SpinLock and are the usual form in scheduler / IRQ paths.
        {
            const LockForm = struct {
                tag: []const u8,
                is_lock: bool,
            };
            const forms = [_]LockForm{
                .{ .tag = ".lock(", .is_lock = true },
                .{ .tag = ".lockIrqSave(", .is_lock = true },
                .{ .tag = ".unlock(", .is_lock = false },
                .{ .tag = ".unlockIrqRestore(", .is_lock = false },
            };
            var pos: usize = 0;
            while (pos < code.len) {
                var hit: ?usize = null;
                var op_is_lock = false;
                var skip: usize = 0;
                for (forms) |f| {
                    const fp = mem.indexOf(u8, code[pos..], f.tag) orelse continue;
                    const abs = pos + fp;
                    if (hit == null or abs < hit.?) {
                        hit = abs;
                        op_is_lock = f.is_lock;
                        skip = f.tag.len;
                    }
                }
                if (hit == null) break;
                const at = hit.?;
                // Walk back to extract the receiver chain (`a.b.c`).
                // Stop at the first non-chain char (whitespace, paren,
                // comma, operator, etc.).
                var sidx: usize = at;
                while (sidx > 0) {
                    const c = code[sidx - 1];
                    if (isIdentChar(c) or c == '.') {
                        sidx -= 1;
                    } else break;
                }
                if (sidx == at) {
                    pos = at + skip;
                    continue;
                }
                const full_chain = code[sidx..at]; // e.g. "self.lock"
                // Split into (receiver, lock_field) at the LAST `.`.
                const last_dot = mem.lastIndexOfScalar(u8, full_chain, '.') orelse {
                    // Bare `foo.lock()` with no chain — can't classify
                    // without knowing foo's type. Skip.
                    pos = at + skip;
                    continue;
                };
                const recv_chain = full_chain[0..last_dot];
                const field_name = full_chain[last_dot + 1 ..];
                // _gen_lock is handled by the slab block above; skip.
                if (mem.eql(u8, field_name, "_gen_lock")) {
                    pos = at + skip;
                    continue;
                }
                // Resolve receiver's type. Walk segments left-to-right:
                //   first segment: env.all_types (locals/params) or
                //                  module_globals (file-scope vars);
                //   each subsequent segment: field_types lookup on the
                //                  current type.
                // Segments may include `[...]` suffixes which we strip.
                var recv_type: []const u8 = "";
                {
                    // Split recv_chain on '.' ignoring content inside `[]`.
                    const SegParser = struct {
                        fn next(s: []const u8, start: *usize) ?[]const u8 {
                            if (start.* >= s.len) return null;
                            var i: usize = start.*;
                            var depth: i32 = 0;
                            while (i < s.len) : (i += 1) {
                                switch (s[i]) {
                                    '[' => depth += 1,
                                    ']' => depth -= 1,
                                    '.' => if (depth == 0) {
                                        const seg = s[start.*..i];
                                        start.* = i + 1;
                                        return seg;
                                    },
                                    else => {},
                                }
                            }
                            const seg = s[start.*..];
                            start.* = s.len;
                            return seg;
                        }
                        fn stripSubscript(s: []const u8) []const u8 {
                            if (mem.indexOfScalar(u8, s, '[')) |b| return s[0..b];
                            return s;
                        }
                    };
                    var scur: usize = 0;
                    const first_raw = SegParser.next(recv_chain, &scur) orelse "";
                    const first = SegParser.stripSubscript(first_raw);
                    if (first.len > 0) {
                        if (env.all_types.get(first)) |ty| {
                            recv_type = ty;
                        } else if (ctx.module_globals.get(first)) |ty| {
                            recv_type = ty;
                        }
                    }
                    while (recv_type.len > 0) {
                        const seg_raw = SegParser.next(recv_chain, &scur) orelse break;
                        const seg = SegParser.stripSubscript(seg_raw);
                        if (seg.len == 0) {
                            recv_type = "";
                            break;
                        }
                        if (ctx.field_types.get(.{ .owner = recv_type, .field = seg })) |nt| {
                            recv_type = nt;
                        } else {
                            recv_type = "";
                            break;
                        }
                    }
                }
                if (recv_type.len == 0) {
                    pos = at + skip;
                    continue;
                }
                // Lookup (recv_type, field_name) in LockFieldMap.
                const class_opt = ctx.lock_fields.get(.{ .owner = recv_type, .field = field_name });
                if (class_opt == null) {
                    pos = at + skip;
                    continue;
                }
                // Skip if this ident is already being tracked via the
                // slab block (its events are emitted above with a
                // slab_type; the pair extractor will synthesize a class).
                // In practice, slab-tracked idents use `_gen_lock` (already
                // filtered) or SlabRef `.lock()` (which resolves on a fat
                // ident where env.fat.contains). We can't easily detect
                // overlap from here; rely on the `_gen_lock` skip + the
                // fact that plain lock-field names (e.g. "rq_lock",
                // "perm_lock", "lock") won't collide with the SlabRef form
                // because SlabRef.lock() is a *method* call with an empty
                // last segment, not a `<x>.lock` field access followed by
                // `.lock()`.
                const class = class_opt.?;
                const recv_ident_i = try ctx.pool.intern(recv_chain);
                const is_defer_plain = blk: {
                    // `defer <chain>.lock()` / `defer <chain>.unlock()`:
                    // detect a `defer ` token appearing before the
                    // callsite on this line.
                    if (mem.indexOf(u8, code[0..at], "defer ")) |_| break :blk !op_is_lock;
                    break :blk false;
                };
                const kind: EventKind = if (op_is_lock)
                    .lock
                else if (is_defer_plain)
                    .defer_unlock
                else
                    .unlock;
                try emitEventGC(
                    gpa,
                    ec,
                    recv_ident_i,
                    kind,
                    src_line,
                    "",
                    recv_type,
                    0,
                    class,
                );
                if (is_defer_plain) {
                    try pending_defers.append(gpa, .{
                        .ident = recv_ident_i,
                        .fire_at_depth = brace_depth,
                    });
                }
                pos = at + skip;
            }
        }

        // Ordered-pair helper scan: `lockPair(a, b, ...)` /
        // `unlockPair(a, b, ...)`. Each match emits a lock/unlock event
        // for every fat-ref arg that's tracked in env, all sharing a
        // fresh group_id so the cycle detector can tell they came from
        // one atomic ordered acquisition.
        {
            const Scan = struct {
                names: []const []const u8,
                kind_lock: bool,
            };
            const scans = [_]Scan{
                .{ .names = &ORDERED_PAIR_LOCK_HELPERS, .kind_lock = true },
                .{ .names = &ORDERED_PAIR_UNLOCK_HELPERS, .kind_lock = false },
            };
            for (scans) |scan| {
                for (scan.names) |helper| {
                    var sp: usize = 0;
                    while (sp < code.len) {
                        const idx_opt = mem.indexOf(u8, code[sp..], helper);
                        if (idx_opt == null) break;
                        const idx = sp + idx_opt.?;
                        // Start-of-ident boundary.
                        if (idx > 0 and isIdentChar(code[idx - 1])) {
                            sp = idx + helper.len;
                            continue;
                        }
                        const after = idx + helper.len;
                        if (after >= code.len or code[after] != '(') {
                            sp = after;
                            continue;
                        }
                        var caller_args = ArrayList(?[]const u8).empty;
                        defer caller_args.deinit(gpa);
                        try parseCallArgs(gpa, ctx.pool, code, after, &caller_args);
                        ordered_group_counter += 1;
                        const gid = ordered_group_counter;
                        const is_defer = scan.kind_lock == false and isOrderedDefer(code, idx);
                        for (caller_args.items) |ai_opt| {
                            const ai = ai_opt orelse continue;
                            if (!env.map.contains(ai)) continue;
                            if (!env.fat.contains(ai)) continue;
                            const ident_i = try ctx.pool.intern(ai);
                            const kind: EventKind = if (scan.kind_lock)
                                .lock
                            else if (is_defer)
                                .defer_unlock
                            else
                                .unlock;
                            try emitEventG(
                                gpa,
                                ec,
                                ident_i,
                                kind,
                                src_line,
                                "",
                                env.map.get(ident_i) orelse "",
                                gid,
                            );
                            if (is_defer) {
                                try pending_defers.append(gpa, .{
                                    .ident = ident_i,
                                    .fire_at_depth = brace_depth,
                                });
                            }
                        }
                        sp = after;
                    }
                }
            }
        }

        // Access + call-site scanning.
        const atomic_spans = try atomicCallSpans(gpa, code);
        defer gpa.free(atomic_spans);

        const AS = struct { start: usize, end: usize, ident: []const u8, tail: []const u8 };
        var access_spans = ArrayList(AS).empty;
        defer access_spans.deinit(gpa);
        var call_spans = ArrayList(AS).empty;
        defer call_spans.deinit(gpa);

        {
            var p: usize = 0;
            while (p < code.len) {
                if (!isIdentStart(code[p])) { p += 1; continue; }
                if (p > 0 and (isIdentChar(code[p - 1]) or code[p - 1] == '.')) { p += 1; continue; }
                var e = p;
                while (e < code.len and isIdentChar(code[e])) e += 1;
                const ident = code[p..e];
                var cursor = e;
                if (cursor + 2 <= code.len and code[cursor] == '.' and code[cursor + 1] == '?') cursor += 2;
                if (cursor < code.len and code[cursor] == '.') {
                    var te = cursor + 1;
                    while (te < code.len and isIdentChar(code[te])) te += 1;
                    if (te > cursor + 1) {
                        const tail = code[cursor + 1 .. te];
                        if (env.map.contains(ident) and !mem.eql(u8, tail, "_gen_lock")) {
                            var in_atomic = false;
                            for (atomic_spans) |sp| {
                                if (p >= sp[0] and p < sp[1]) { in_atomic = true; break; }
                            }
                            if (!in_atomic) {
                                if (!isAtomicMethodAt(code, cursor)) {
                                    const skip_as_lock =
                                        env.fat.contains(ident) and
                                        (mem.eql(u8, tail, "lock") or mem.eql(u8, tail, "unlock")) and
                                        te < code.len and code[te] == '(';
                                    if (!skip_as_lock) {
                                        if (te < code.len and code[te] == '(') {
                                            try call_spans.append(gpa, .{ .start = p, .end = te, .ident = ident, .tail = tail });
                                        } else {
                                            try access_spans.append(gpa, .{ .start = p, .end = te, .ident = ident, .tail = tail });
                                        }
                                    }
                                }
                            }
                        }
                        p = te;
                        continue;
                    }
                }
                p = e;
            }
        }

        // Free-fn calls passing slab ident as first arg.
        const Free = struct {
            fn_name: []const u8,
            leader: []const u8, // prefix before the last `.` in fq, or ""
            first_arg: []const u8,
            open_p: usize,
        };
        var free_call_spans = ArrayList(Free).empty;
        defer free_call_spans.deinit(gpa);
        {
            var p: usize = 0;
            while (p < code.len) {
                if (!isIdentStart(code[p])) { p += 1; continue; }
                if (p > 0 and (isIdentChar(code[p - 1]) or code[p - 1] == '.')) { p += 1; continue; }
                // Builtin calls `@intCast(...)` etc. — when the scanner
                // skipped past '@' it lands on the bare builtin name;
                // reject it here so we don't misread the first parenthesized
                // expr as a "call on the builtin."
                if (p > 0 and code[p - 1] == '@') { p += 1; continue; }
                var e = p;
                while (e < code.len and (isIdentChar(code[e]) or code[e] == '.')) e += 1;
                const fq = code[p..e];
                if (fq.len == 0 or !isIdentStart(fq[0])) { p = e + 1; continue; }
                if (fq[0] == '@' or mem.startsWith(u8, fq, "std.") or isKeywordOrNotCall(fq)) {
                    p = e;
                    continue;
                }
                var q = e;
                while (q < code.len and ascii.isWhitespace(code[q])) q += 1;
                if (q >= code.len or code[q] != '(') { p = e; continue; }
                var dot_count: usize = 0;
                for (fq) |c| {
                    if (c == '.') dot_count += 1;
                }
                const head = blk: {
                    if (mem.indexOfScalar(u8, fq, '.')) |d| break :blk fq[0..d];
                    break :blk fq;
                };
                if (env.map.contains(head) and dot_count == 1) { p = e; continue; }
                var ap = q + 1;
                while (ap < code.len and ascii.isWhitespace(code[ap])) ap += 1;
                var ae = ap;
                while (ae < code.len and isIdentChar(code[ae])) ae += 1;
                if (ae == ap) { p = e; continue; }
                const fa = code[ap..ae];
                if (!env.map.contains(fa)) { p = e; continue; }
                var fn_name = fq;
                var leader: []const u8 = "";
                if (mem.lastIndexOfScalar(u8, fq, '.')) |ld| {
                    fn_name = fq[ld + 1 ..];
                    leader = fq[0..ld];
                }
                try free_call_spans.append(gpa, .{
                    .fn_name = fn_name,
                    .leader = leader,
                    .first_arg = fa,
                    .open_p = q,
                });
                p = e;
            }
        }

        // Emit direct accesses (no known callee summary involvement).
        for (access_spans.items) |as| {
            const ident_i = try ctx.pool.intern(as.ident);
            const tail_i = try ctx.pool.intern(as.tail);
            try emitEvent(gpa, ec, ident_i, .access, src_line, tail_i, env.map.get(ident_i) orelse "");
        }

        // Method call sites: .<name>(. Resolve via (recv_type, name).
        for (call_spans.items) |cs| {
            const recv_ty = env.map.get(cs.ident) orelse continue;
            const summary_opt = try getOrBuildSummary(ctx, recv_ty, cs.tail);
            if (summary_opt == null) {
                // Unknown callee — treat as raw access on the ident.
                const ident_i = try ctx.pool.intern(cs.ident);
                const tail_i = try ctx.pool.intern(cs.tail);
                try emitEvent(gpa, ec, ident_i, .access, src_line, tail_i, recv_ty);
                continue;
            }
            const summary = summary_opt.?;
            // Parse args at cs.end.
            var caller_args = ArrayList(?[]const u8).empty;
            defer caller_args.deinit(gpa);
            if (cs.end < code.len and code[cs.end] == '(') {
                try parseCallArgs(gpa, ctx.pool, code, cs.end, &caller_args);
            }
            // Pos 0 = receiver (cs.ident), interned so it survives past
            // the scratch buffers parseCallArgs writes into; then args.
            var all_args = ArrayList(?[]const u8).empty;
            defer all_args.deinit(gpa);
            try all_args.append(gpa, try ctx.pool.intern(cs.ident));
            for (caller_args.items) |ca| try all_args.append(gpa, ca);
            try foldSummary(ctx, summary, all_args.items, env, ec, src_line);
        }

        // Free-fn call sites.
        for (free_call_spans.items) |fc| {
            const recv_ty = env.map.get(fc.first_arg) orelse continue;
            // `<slab_module>.destroy(<ident>, <gen>)` is the SecureSlab
            // sink operation: the allocator re-acquires the gen-lock
            // internally, and the caller is done with <ident>. Treat this
            // as terminal — don't emit an access event, otherwise the
            // bracket check will demand an unlock AFTER the destroy call
            // (legitimately impossible, since the slot is freed). The
            // lock/unlock surrounding the real mutation (before destroy)
            // already stand on their own merits.
            if (mem.eql(u8, fc.fn_name, "destroy") and leaderIsSlabModule(fc.leader)) {
                continue;
            }
            // `<slab_module>.destroyLocked(<ident>, <gen>)` is the caller-
            // holds-gen-lock sink: the allocator releases the lock bit as
            // part of the gen bump, so there is no (and must be no) trailing
            // `unlock()`. Skip emitting an access event on the first arg,
            // and synthesize an unlock event for any fat ident used in the
            // args (typically `<ref>.gen`) so bracketCheck sees the lock
            // released right after the last access, rather than flagging a
            // missing tight-following unlock.
            if (mem.eql(u8, fc.fn_name, "destroyLocked") and leaderIsSlabModule(fc.leader)) {
                const args_start = fc.open_p + 1;
                var rp = args_start;
                var depth: i32 = 1;
                while (rp < code.len and depth > 0) : (rp += 1) {
                    if (code[rp] == '(') depth += 1;
                    if (code[rp] == ')') depth -= 1;
                    if (depth == 0) break;
                }
                const args_end = rp;
                if (args_end <= code.len and args_start <= args_end) {
                    var sp: usize = args_start;
                    while (sp < args_end) {
                        if (!isIdentStart(code[sp])) { sp += 1; continue; }
                        if (sp > 0 and (isIdentChar(code[sp - 1]) or code[sp - 1] == '.')) { sp += 1; continue; }
                        var se = sp;
                        while (se < args_end and isIdentChar(code[se])) se += 1;
                        const aid = code[sp..se];
                        if (se + 4 <= args_end and code[se] == '.' and
                            mem.eql(u8, code[se + 1 .. se + 4], "gen") and
                            (se + 4 == args_end or !isIdentChar(code[se + 4])))
                        {
                            if (env.fat.contains(aid)) {
                                const aid_i = try ctx.pool.intern(aid);
                                try emitEvent(gpa, ec, aid_i, .unlock, src_line, "", env.map.get(aid) orelse "");
                            }
                        }
                        sp = se;
                    }
                }
                continue;
            }
            const summary_opt = try getOrBuildSummary(ctx, recv_ty, fc.fn_name);
            if (summary_opt == null) {
                const ident_i = try ctx.pool.intern(fc.first_arg);
                const tail_i = try ctx.pool.intern(fc.fn_name);
                try emitEvent(gpa, ec, ident_i, .access, src_line, tail_i, recv_ty);
                continue;
            }
            const summary = summary_opt.?;
            var caller_args = ArrayList(?[]const u8).empty;
            defer caller_args.deinit(gpa);
            try parseCallArgs(gpa, ctx.pool, code, fc.open_p, &caller_args);
            try foldSummary(ctx, summary, caller_args.items, env, ec, src_line);
        }

        // End-of-line brace tracking + defer fires.
        var in_str = false;
        var esc = false;
        for (code) |c| {
            if (esc) { esc = false; continue; }
            if (c == '\\' and in_str) { esc = true; continue; }
            if (c == '"') { in_str = !in_str; continue; }
            if (in_str) continue;
            if (c == '{') brace_depth += 1;
            if (c == '}') brace_depth -= 1;
        }
        var i: isize = @as(isize, @intCast(pending_defers.items.len)) - 1;
        while (i >= 0) : (i -= 1) {
            const pd = pending_defers.items[@intCast(i)];
            if (brace_depth < pd.fire_at_depth) {
                try emitEvent(gpa, ec, pd.ident, .unlock, src_line, "", env.map.get(pd.ident) orelse "");
                _ = pending_defers.orderedRemove(@intCast(i));
            }
        }
    }

    // End-of-body fire: any remaining pending defers release at the last
    // body line — this matches the Python tool's behavior where an implicit
    // scope exit at the closing brace releases the defer.
    while (pending_defers.items.len > 0) {
        const pd = pending_defers.pop().?;
        try emitEvent(gpa, ec, pd.ident, .unlock, body_end_line, "", env.map.get(pd.ident) orelse "");
    }
}

// Zig keywords / pseudo-keywords that look like `name(` but aren't
// function calls we can summarize. Filtering these out stops the
// free-fn detector from treating `if (caller_ref)` as a call to a
// helper named `if` — the old analyzer leaked this as a ghost access
// event before inlining was turned off.
fn isKeywordOrNotCall(fq: []const u8) bool {
    const kws = [_][]const u8{
        "return",  "if",      "while",    "for",   "switch",
        "defer",   "errdefer","try",      "catch", "orelse",
        "break",   "continue","comptime", "nosuspend",
        "suspend", "resume",  "async",    "await", "inline",
        "unreachable","and", "or",        "not",
    };
    for (kws) |k| if (mem.eql(u8, fq, k)) return true;
    return false;
}

// Helper: detect `defer <ident>._gen_lock.` earlier on this line.
fn isDeferFor(code: []const u8, ident: []const u8) bool {
    var search_pos: usize = 0;
    while (search_pos < code.len) {
        const p = mem.indexOf(u8, code[search_pos..], "defer ") orelse break;
        const abs = search_pos + p;
        const rest = trimAscii(code[abs + 6 ..]);
        if (rest.len >= ident.len and
            mem.eql(u8, rest[0..ident.len], ident) and
            rest.len > ident.len and rest[ident.len] == '.')
        {
            return true;
        }
        search_pos = abs + 6;
    }
    return false;
}

// Helper: detect `defer ` preceding a specific byte-offset callsite
// (e.g. for `defer unlockPair(a, b)` — ordered-pair helpers live at
// top-level, not as a `.method()` call, so the existing isDeferFor*
// helpers don't match them).
fn isOrderedDefer(code: []const u8, callsite_idx: usize) bool {
    var sp: usize = 0;
    while (sp < callsite_idx) {
        const p = mem.indexOf(u8, code[sp..callsite_idx], "defer ") orelse break;
        const abs = sp + p;
        // There's a `defer ` before us; verify only whitespace between
        // `defer ` and callsite_idx (ignoring `try ` / `errdefer` noise
        // is beyond v1's appetite — if needed, callers can nest).
        const between = trimAscii(code[abs + 6 .. callsite_idx]);
        if (between.len == 0) return true;
        sp = abs + 6;
    }
    return false;
}

// Helper: detect `defer <ident>(\.\?)?\.`.
fn isDeferForFat(code: []const u8, ident: []const u8) bool {
    var sp: usize = 0;
    while (sp < code.len) {
        const p = mem.indexOf(u8, code[sp..], "defer ") orelse break;
        const abs = sp + p;
        const rest = trimAscii(code[abs + 6 ..]);
        if (rest.len >= ident.len and mem.eql(u8, rest[0..ident.len], ident)) {
            var k = ident.len;
            if (k + 2 <= rest.len and rest[k] == '.' and rest[k + 1] == '?') k += 2;
            if (k < rest.len and rest[k] == '.') return true;
        }
        sp = abs + 6;
    }
    return false;
}

// Parse the arg list starting at `open_paren_pos` (a '(' in `code`).
// For each arg, extract the bare-ident form via argToIdent and push an
// interned (pool-owned) slice or null into `out`. Interning matters
// because the scratch buffer we accumulate each arg into is reused
// across commas, and nothing in the caller chain keeps cur alive —
// without the pool copy, slices would dangle the instant parseCallArgs
// returns.
fn parseCallArgs(
    gpa: Allocator,
    pool: *Pool,
    code: []const u8,
    open_paren_pos: usize,
    out: *ArrayList(?[]const u8),
) !void {
    if (open_paren_pos >= code.len or code[open_paren_pos] != '(') return;
    var depth: i32 = 0;
    var i: usize = open_paren_pos;
    var cur = ArrayList(u8).empty;
    defer cur.deinit(gpa);
    while (i < code.len) : (i += 1) {
        const c = code[i];
        if (c == '(' or c == '[' or c == '{') {
            depth += 1;
            if (depth > 1) try cur.append(gpa, c);
        } else if (c == ')' or c == ']' or c == '}') {
            depth -= 1;
            if (depth == 0) {
                if (trimAscii(cur.items).len > 0) {
                    try out.append(gpa, try internArgIdent(pool, cur.items));
                }
                return;
            }
            try cur.append(gpa, c);
        } else if (c == ',' and depth == 1) {
            try out.append(gpa, try internArgIdent(pool, cur.items));
            cur.clearRetainingCapacity();
        } else {
            if (depth >= 1) try cur.append(gpa, c);
        }
    }
}

fn internArgIdent(pool: *Pool, bytes: []const u8) !?[]const u8 {
    const id = argToIdent(bytes) orelse return null;
    return try pool.intern(id);
}

fn argToIdent(s: []const u8) ?[]const u8 {
    const t = trimAscii(s);
    if (t.len == 0) return null;
    if (!isIdentStart(t[0])) return null;
    for (t) |c| if (!isIdentChar(c)) return null;
    return t;
}


// -----------------------------------------------------------------
// Bracket check & reporting
// -----------------------------------------------------------------

fn analyzeEntry(
    gpa: Allocator,
    pool: *Pool,
    ctx_files: []const *SourceFile,
    ctx_tokens: []const []const Tok,
    slab_types: *const SlabTypeMap,
    fn_index: *FnIndex,
    summaries: *SummaryMap,
    lock_fields: *const LockFieldMap,
    module_globals: *const StringStringMap,
    field_types: *const StructFieldTypeMap,
    entry: *const EntryPoint,
    out_env: *SlabEnv,
    out_events: *EventMap,
) !void {
    const sf = fileByPath(ctx_files, entry.file_path) orelse return;
    const toks = blk: {
        for (ctx_files, ctx_tokens) |f, t| if (f == sf) break :blk t;
        break :blk @as([]const Tok, &.{});
    };

    // Find the function header.
    var hdr: ?FnHeader = null;
    for (toks, 0..) |t, ti| {
        if (t.tag != .keyword_fn) continue;
        var start_i = ti;
        if (ti > 0 and toks[ti - 1].tag == .keyword_pub) start_i = ti - 1;
        if (ti + 1 >= toks.len) continue;
        const name = tokSlice(sf, toks[ti + 1]);
        if (!mem.eql(u8, name, entry.name)) continue;
        if (toks[start_i].line != entry.line) continue;
        hdr = parseFnHeaderAt(toks, start_i) orelse continue;
        break;
    }
    if (hdr == null) return;

    const is_syscall_entry = mem.startsWith(u8, entry.name, "sys");

    // Seed env from the fn header params.
    const params = try parseParamList(gpa, sf, toks, hdr.?.l_paren_idx, hdr.?.r_paren_idx);
    defer gpa.free(params);
    for (params) |pp| {
        const nm = try pool.intern(pp.name);
        if (parseTypeRef(pp.type_str)) |ty| {
            if (slab_types.contains(ty)) {
                const ty_i = try pool.intern(ty);
                try out_env.map.put(nm, ty_i);
                try out_env.all_types.put(nm, ty_i);
                if (mem.indexOf(u8, pp.type_str, "SlabRef") != null) try out_env.fat.add(nm);
                if (is_syscall_entry and (mem.eql(u8, ty, "Process") or mem.eql(u8, ty, "Thread"))) {
                    try out_env.self_alive.add(nm);
                }
                continue;
            }
        }
        // Non-slab param: still record its bare type name (if any) so
        // `self.lock.lock()` style calls on non-slab receivers can be
        // classified via LockFieldMap. parseTypeRef is slab-specific;
        // fall through to the bare-name extractor for plain types.
        const bare = typeNameFromFieldType(pp.type_str);
        if (bare.len > 0) {
            const bare_i = try pool.intern(bare);
            try out_env.all_types.put(nm, bare_i);
        }
    }

    var ctx = Ctx{
        .gpa = gpa,
        .pool = pool,
        .files = ctx_files,
        .tokens_per_file = ctx_tokens,
        .slab_types = slab_types,
        .fn_index = fn_index,
        .summaries = summaries,
        .lock_fields = lock_fields,
        .module_globals = module_globals,
        .field_types = field_types,
    };

    var seq: u32 = 0;
    var empty_set = SliceSet.init(gpa);
    defer empty_set.deinit();
    var ec = EmitCtx{
        .events = out_events,
        .seq = &seq,
        .param_set = &empty_set,
        .emit_param_only = false,
    };

    try walkBody(&ctx, sf, entry.body_start_line, entry.body_end_line, out_env, &ec);
}

const CheckResult = struct {
    entry: *const EntryPoint,
    env: SlabEnv,
    events: EventMap,
    findings: ArrayList(Finding),

    fn deinit(self: *CheckResult, gpa: Allocator) void {
        var it = self.events.valueIterator();
        while (it.next()) |al| al.deinit(gpa);
        self.events.deinit();
        for (self.findings.items) |f| gpa.free(f.message);
        self.findings.deinit(gpa);
        self.env.deinit();
    }
};

// Bracket check is event-based: for each ident with any access events,
// locate the first access and verify the immediately-preceding event (by
// insertion order within the entry's walk) is a lock/lock_with_gen or a
// defer_unlock whose predecessor is a lock. Likewise verify the
// immediately-following event is an unlock (or that a defer-unlock
// covers).
//
// Line numbers reported back to the developer are REAL source lines
// from the caller file — the new walker never generates synthetic ones.
fn bracketCheck(gpa: Allocator, res: *CheckResult) !void {
    var it = res.events.iterator();
    while (it.next()) |kv| {
        const ident = kv.key_ptr.*;
        const events = kv.value_ptr.items;
        if (events.len == 0) continue;
        if (res.env.self_alive.contains(ident)) continue;

        // Find access event indices and line set.
        var access_idxs = ArrayList(usize).empty;
        defer access_idxs.deinit(gpa);
        var access_lines = ArrayList(u32).empty;
        defer access_lines.deinit(gpa);
        var slab_ty: []const u8 = res.env.map.get(ident) orelse "?";
        for (events, 0..) |ev, ei| {
            if (ev.kind == .access) {
                try access_idxs.append(gpa, ei);
                try access_lines.append(gpa, ev.src_line);
                if (ev.slab_type.len > 0) slab_ty = ev.slab_type;
            }
        }
        if (access_idxs.items.len == 0) continue;

        // Sort & dedup lines for display.
        std.sort.heap(u32, access_lines.items, {}, std.sort.asc(u32));
        var uniq_lines = ArrayList(u32).empty;
        defer uniq_lines.deinit(gpa);
        {
            var last: u32 = 0;
            for (access_lines.items) |l| {
                if (uniq_lines.items.len == 0 or last != l) {
                    try uniq_lines.append(gpa, l);
                    last = l;
                }
            }
        }

        const first_idx = access_idxs.items[0];
        const last_idx = access_idxs.items[access_idxs.items.len - 1];
        const first_line = events[first_idx].src_line;
        const last_line = events[last_idx].src_line;

        // Are there any lock/unlock/defer_unlock events on this ident?
        var has_any_op = false;
        for (events) |ev| if (ev.kind != .access) {
            has_any_op = true;
            break;
        };

        if (!has_any_op) {
            var lines_buf = ArrayList(u8).empty;
            defer lines_buf.deinit(gpa);
            try lines_buf.append(gpa, '[');
            for (uniq_lines.items, 0..) |l, li| {
                if (li > 0) try lines_buf.appendSlice(gpa, ", ");
                try lines_buf.writer(gpa).print("{d}", .{l});
            }
            try lines_buf.append(gpa, ']');
            const msg = try std.fmt.allocPrint(gpa,
                "{s} ({s}): {d} access(es) on lines {s} but no gen-lock op on this ident at all",
                .{ ident, slab_ty, access_idxs.items.len, lines_buf.items });
            try res.findings.append(gpa, .{
                .severity = .err,
                .entry_name = res.entry.name,
                .message = msg,
                .line_no = first_line,
            });
            continue;
        }

        // Tight-preceding: the event immediately before first_idx (by
        // insertion order) must be a lock/lock_with_gen. A defer_unlock
        // in that slot is OK if the one before IT is a lock.
        var acq_ok = false;
        if (first_idx >= 1) {
            const prev = events[first_idx - 1];
            if (prev.kind == .lock or prev.kind == .lock_with_gen) acq_ok = true;
            if (!acq_ok and prev.kind == .defer_unlock and first_idx >= 2) {
                const pp = events[first_idx - 2];
                if (pp.kind == .lock or pp.kind == .lock_with_gen) acq_ok = true;
            }
        }
        if (!acq_ok) {
            // Nearest lock before first access (by src_line).
            var nearest: ?u32 = null;
            for (events) |ev| {
                if ((ev.kind == .lock or ev.kind == .lock_with_gen) and ev.src_line < first_line) {
                    if (nearest == null or ev.src_line > nearest.?) nearest = ev.src_line;
                }
            }
            const severity: Severity = if (nearest == null) .err else .info;
            const msg = if (nearest) |n| try std.fmt.allocPrint(gpa,
                "{s} ({s}): first access at L{d} not tight-preceded by lock (nearest acquire L{d}, gap={d})",
                .{ ident, slab_ty, first_line, n, first_line - n })
            else try std.fmt.allocPrint(gpa,
                "{s} ({s}): first access at L{d} not tight-preceded by lock (nearest acquire LNone, gap=None)",
                .{ ident, slab_ty, first_line });
            try res.findings.append(gpa, .{
                .severity = severity,
                .entry_name = res.entry.name,
                .message = msg,
                .line_no = first_line,
            });
        }

        // Tight-following: event immediately after last_idx must be
        // unlock.
        var rel_ok = false;
        if (last_idx + 1 < events.len) {
            const next = events[last_idx + 1];
            if (next.kind == .unlock) rel_ok = true;
        }
        if (!rel_ok) {
            // Any defer_unlock anywhere before last_line covers.
            var has_defer = false;
            for (events) |ev| {
                if (ev.kind == .defer_unlock and ev.src_line <= last_line) {
                    has_defer = true;
                    break;
                }
            }
            if (has_defer) {
                const msg = try std.fmt.allocPrint(gpa,
                    "{s} ({s}): last access L{d} relies on defer-unlock (no explicit unlock on L{d})",
                    .{ ident, slab_ty, last_line, last_line + 1 });
                try res.findings.append(gpa, .{
                    .severity = .info,
                    .entry_name = res.entry.name,
                    .message = msg,
                    .line_no = last_line,
                });
            } else {
                var nearest: ?u32 = null;
                for (events) |ev| {
                    if (ev.kind == .unlock and ev.src_line > last_line) {
                        if (nearest == null or ev.src_line < nearest.?) nearest = ev.src_line;
                    }
                }
                const severity: Severity = if (nearest == null) .err else .info;
                const msg = if (nearest) |n| try std.fmt.allocPrint(gpa,
                    "{s} ({s}): last access at L{d} not tight-followed by unlock (nearest release L{d}, gap={d})",
                    .{ ident, slab_ty, last_line, n, n - last_line })
                else try std.fmt.allocPrint(gpa,
                    "{s} ({s}): last access at L{d} not tight-followed by unlock (nearest release LNone, gap=None)",
                    .{ ident, slab_ty, last_line });
                try res.findings.append(gpa, .{
                    .severity = severity,
                    .entry_name = res.entry.name,
                    .message = msg,
                    .line_no = last_line,
                });
            }
        }
    }
}

// -----------------------------------------------------------------
// Lock-field registry — maps (struct_name, field_name) → lock class
// for every field whose declared type is one of LOCK_TYPE_NAMES.
// -----------------------------------------------------------------

const LockFieldKey = struct { owner: []const u8, field: []const u8 };
const LockFieldCtx = struct {
    pub fn hash(_: @This(), k: LockFieldKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(k.owner);
        h.update("|");
        h.update(k.field);
        return h.final();
    }
    pub fn eql(_: @This(), a: LockFieldKey, b: LockFieldKey) bool {
        return mem.eql(u8, a.owner, b.owner) and mem.eql(u8, a.field, b.field);
    }
};
// Value is the lock CLASS name (interned): e.g. "Vmm.lock",
// "Process.perm_lock". Stable across a run.
const LockFieldMap = std.HashMap(
    LockFieldKey,
    []const u8,
    LockFieldCtx,
    std.hash_map.default_max_load_percentage,
);

fn typeNameFromFieldType(ft: []const u8) []const u8 {
    // Strip trailing `= .{...}`, `,`, surrounding whitespace, pointer
    // prefixes (`*`, `?`, `*const`) to bottom out at the bare type
    // name. We only care about matching against LOCK_TYPE_NAMES.
    var t = trimAscii(ft);
    if (t.len == 0) return t;
    if (t[0] == '?') t = trimAscii(t[1..]);
    if (t.len == 0) return t;
    if (t[0] == '*') t = trimAscii(t[1..]);
    if (mem.startsWith(u8, t, "const ")) t = trimAscii(t["const ".len..]);
    // Take leading identifier.
    var e: usize = 0;
    while (e < t.len and isIdentChar(t[e])) e += 1;
    return t[0..e];
}

// Generic struct-field-type map: (owner, field) → bare type name. Used
// by the lock-ordering analyzer to walk multi-segment receiver chains
// like `a.b.c.lock()` segment-by-segment: start from `a`'s type,
// look up `b` in that type's fields to get `b`'s type, repeat. Covers
// every struct field — not just lock-typed ones — so the chain walk
// can traverse through intermediate non-lock fields.
const StructFieldTypeMap = std.HashMap(
    LockFieldKey,
    []const u8,
    LockFieldCtx,
    std.hash_map.default_max_load_percentage,
);

fn buildStructFieldTypeMap(
    pool: *Pool,
    struct_fields: []const StructField,
    out: *StructFieldTypeMap,
) !void {
    for (struct_fields) |f| {
        const bare = typeNameFromFieldType(f.field_type);
        if (bare.len == 0) continue;
        const owner_i = try pool.intern(f.struct_name);
        const field_i = try pool.intern(f.field_name);
        const ty_i = try pool.intern(bare);
        // Last-wins for same (owner, field) — struct fields don't
        // typically duplicate in practice.
        try out.put(.{ .owner = owner_i, .field = field_i }, ty_i);
    }
}

fn buildLockFieldMap(
    gpa: Allocator,
    pool: *Pool,
    struct_fields: []const StructField,
    out: *LockFieldMap,
) !void {
    _ = gpa;
    for (struct_fields) |f| {
        const bare = typeNameFromFieldType(f.field_type);
        if (bare.len == 0) continue;
        var is_lock = false;
        for (LOCK_TYPE_NAMES) |lt| {
            if (mem.eql(u8, bare, lt)) {
                is_lock = true;
                break;
            }
        }
        if (!is_lock) continue;
        const owner_i = try pool.intern(f.struct_name);
        const field_i = try pool.intern(f.field_name);
        var class_buf: [160]u8 = undefined;
        const class_s = try std.fmt.bufPrint(&class_buf, "{s}.{s}", .{ owner_i, field_i });
        const class_i = try pool.intern(class_s);
        try out.put(.{ .owner = owner_i, .field = field_i }, class_i);
    }
}

// -----------------------------------------------------------------
// Lock-ordering analysis.
// -----------------------------------------------------------------
//
// For each CheckResult (one entry-point walk) we already have a per-
// ident event stream with lock/unlock/defer_unlock events that reflect
// BOTH direct in-body lock ops and callee-effects folded in via
// `foldSummary` at call sites. That stream, flattened and sorted by
// seq (the global insertion counter the walker stamps on every event),
// replays the function's observable lock-acquire behavior in source
// order.
//
// Simulating a lock stack over the flattened stream yields every
// ordered (outer → inner) pair the function introduces. Pairs emitted
// by different entries all flow into a single global directed graph
// whose nodes are lock CLASSES (interned strings like
// "Process._gen_lock"). A cycle in this graph = a potential deadlock,
// regardless of which specific instance each thread holds.
//
// Same-type self-edges are suppressed when both events belong to the
// same non-zero `group_id` — that's our marker for an ordered-pair
// helper call (`lockPair(a, b)`) which internally address-orders its
// acquires.

fn lockClassFor(pool: *Pool, slab_type: []const u8) ![]const u8 {
    var buf: [128]u8 = undefined;
    const printed = try std.fmt.bufPrint(&buf, "{s}._gen_lock", .{slab_type});
    return pool.intern(printed);
}

fn flattenEventsBySeq(
    gpa: Allocator,
    events: *const EventMap,
    out: *ArrayList(FlatEvent),
) !void {
    var it = events.iterator();
    while (it.next()) |kv| {
        const ident = kv.key_ptr.*;
        for (kv.value_ptr.items) |ev| {
            try out.append(gpa, .{ .ident = ident, .ev = ev });
        }
    }
    std.sort.heap(FlatEvent, out.items, {}, lessFlatEvent);
}

const FlatEvent = struct {
    ident: []const u8,
    ev: Event,
};

fn lessFlatEvent(_: void, a: FlatEvent, b: FlatEvent) bool {
    return a.ev.seq < b.ev.seq;
}

const HeldLock = struct {
    ident: []const u8,
    class: []const u8,
    group_id: u32,
    seq: u32,
};

fn collectLockPairsFromResult(
    gpa: Allocator,
    pool: *Pool,
    res: *const CheckResult,
    out: *ArrayList(LockPair),
) !void {
    var flat = ArrayList(FlatEvent).empty;
    defer flat.deinit(gpa);
    try flattenEventsBySeq(gpa, &res.events, &flat);

    var held = ArrayList(HeldLock).empty;
    defer held.deinit(gpa);

    for (flat.items) |f| {
        switch (f.ev.kind) {
            .lock, .lock_with_gen => {
                const new_class = if (f.ev.lock_class.len > 0)
                    f.ev.lock_class
                else blk: {
                    if (f.ev.slab_type.len == 0) break :blk @as([]const u8, "");
                    break :blk try lockClassFor(pool, f.ev.slab_type);
                };
                if (new_class.len == 0) continue;
                for (held.items) |h| {
                    // Ordered-pair suppression: same class + same non-zero
                    // group = helper-enforced address-ordered acquire, not
                    // a cycle edge.
                    const same_class = mem.eql(u8, h.class, new_class);
                    const same_group = h.group_id != 0 and h.group_id == f.ev.group_id;
                    if (same_class and same_group) continue;
                    try out.append(gpa, .{
                        .outer = h.class,
                        .inner = new_class,
                        .file_rel = res.entry.file_rel,
                        .line = f.ev.src_line,
                        .entry_name = res.entry.name,
                        .outer_ident = h.ident,
                        .inner_ident = f.ident,
                    });
                }
                try held.append(gpa, .{
                    .ident = f.ident,
                    .class = new_class,
                    .group_id = f.ev.group_id,
                    .seq = f.ev.seq,
                });
            },
            .unlock => {
                // Only plain `.unlock` actually releases the held slot —
                // `.defer_unlock` is a marker at the `defer <ident>.unlock()`
                // source line; the real release is a synthesized `.unlock`
                // event the walker fires when the pending defer pops at
                // scope exit. Popping on `.defer_unlock` too would release
                // the held lock right at the defer line, which is wrong:
                // callees that take further locks AFTER `defer ref.unlock()`
                // would appear to be running with `ref` already released,
                // and the resulting lock-pair graph would miss the real
                // nested acquires.
                var i: isize = @as(isize, @intCast(held.items.len)) - 1;
                while (i >= 0) : (i -= 1) {
                    if (mem.eql(u8, held.items[@intCast(i)].ident, f.ident)) {
                        _ = held.orderedRemove(@intCast(i));
                        break;
                    }
                }
            },
            .defer_unlock => {},
            else => {},
        }
    }
}

// -----------------------------------------------------------------
// Cycle detection via Tarjan's SCC.
// -----------------------------------------------------------------

const AdjList = ArrayList([]const u8);
const AdjMap = StringHashMap(AdjList);

fn buildGraph(
    gpa: Allocator,
    pairs: []const LockPair,
    adj: *AdjMap,
    nodes: *ArrayList([]const u8),
) !void {
    var seen_node = StringHashMap(void).init(gpa);
    defer seen_node.deinit();
    for (pairs) |p| {
        if (!seen_node.contains(p.outer)) {
            try seen_node.put(p.outer, {});
            try nodes.append(gpa, p.outer);
        }
        if (!seen_node.contains(p.inner)) {
            try seen_node.put(p.inner, {});
            try nodes.append(gpa, p.inner);
        }
        const gop = try adj.getOrPut(p.outer);
        if (!gop.found_existing) gop.value_ptr.* = AdjList.empty;
        // Dedup successor entries.
        var already = false;
        for (gop.value_ptr.items) |e| {
            if (mem.eql(u8, e, p.inner)) {
                already = true;
                break;
            }
        }
        if (!already) try gop.value_ptr.append(gpa, p.inner);
    }
    // Ensure every node appears as a key even if it has no outgoing edges
    // (Tarjan's iterates keys; isolated nodes are fine).
    for (nodes.items) |n| {
        const gop = try adj.getOrPut(n);
        if (!gop.found_existing) gop.value_ptr.* = AdjList.empty;
    }
}

const TarjanCtx = struct {
    gpa: Allocator,
    adj: *AdjMap,
    index_map: StringHashMap(u32),
    lowlink: StringHashMap(u32),
    on_stack: StringHashMap(void),
    stack: ArrayList([]const u8),
    next_index: u32,
    sccs: ArrayList([][]const u8),
};

fn tarjanStrongconnect(t: *TarjanCtx, v: []const u8) WalkError!void {
    try t.index_map.put(v, t.next_index);
    try t.lowlink.put(v, t.next_index);
    t.next_index += 1;
    try t.stack.append(t.gpa, v);
    try t.on_stack.put(v, {});

    const edges = t.adj.getPtr(v) orelse unreachable;
    for (edges.items) |w| {
        if (!t.index_map.contains(w)) {
            try tarjanStrongconnect(t, w);
            const wll = t.lowlink.get(w).?;
            const vll = t.lowlink.get(v).?;
            if (wll < vll) try t.lowlink.put(v, wll);
        } else if (t.on_stack.contains(w)) {
            const widx = t.index_map.get(w).?;
            const vll = t.lowlink.get(v).?;
            if (widx < vll) try t.lowlink.put(v, widx);
        }
    }

    const vll = t.lowlink.get(v).?;
    const vidx = t.index_map.get(v).?;
    if (vll == vidx) {
        var scc = ArrayList([]const u8).empty;
        errdefer scc.deinit(t.gpa);
        while (true) {
            const w = t.stack.pop().?;
            _ = t.on_stack.remove(w);
            try scc.append(t.gpa, w);
            if (mem.eql(u8, w, v)) break;
        }
        try t.sccs.append(t.gpa, try scc.toOwnedSlice(t.gpa));
    }
}

fn findLockCycles(
    gpa: Allocator,
    pairs: []const LockPair,
    out_cycles: *ArrayList([][]const u8),
) !void {
    var adj = AdjMap.init(gpa);
    defer {
        var it = adj.valueIterator();
        while (it.next()) |v| v.deinit(gpa);
        adj.deinit();
    }
    var nodes = ArrayList([]const u8).empty;
    defer nodes.deinit(gpa);
    try buildGraph(gpa, pairs, &adj, &nodes);

    var t = TarjanCtx{
        .gpa = gpa,
        .adj = &adj,
        .index_map = StringHashMap(u32).init(gpa),
        .lowlink = StringHashMap(u32).init(gpa),
        .on_stack = StringHashMap(void).init(gpa),
        .stack = ArrayList([]const u8).empty,
        .next_index = 0,
        .sccs = ArrayList([][]const u8).empty,
    };
    defer {
        t.index_map.deinit();
        t.lowlink.deinit();
        t.on_stack.deinit();
        t.stack.deinit(gpa);
        // Note: we transfer ownership of SCC slices to out_cycles, so we
        // don't deinit sccs here — but cycles that didn't make the cut
        // (size-1 with no self-loop) must be freed.
    }

    for (nodes.items) |n| {
        if (!t.index_map.contains(n)) try tarjanStrongconnect(&t, n);
    }

    // Keep non-trivial SCCs (size > 1) and singletons with a self-loop.
    for (t.sccs.items) |scc| {
        var keep = scc.len > 1;
        if (!keep and scc.len == 1) {
            const n = scc[0];
            if (adj.getPtr(n)) |succ| {
                for (succ.items) |w| {
                    if (mem.eql(u8, w, n)) {
                        keep = true;
                        break;
                    }
                }
            }
        }
        if (keep) {
            try out_cycles.append(gpa, scc);
        } else {
            gpa.free(scc);
        }
    }
    t.sccs.deinit(gpa);
}

// -----------------------------------------------------------------
// Main
// -----------------------------------------------------------------

const Args = struct {
    summary: bool = false,
    verbose: bool = false,
    entry_filter: ?[]const u8 = null,
    list_slab_types: bool = false,
    list_lock_pairs: bool = false,
    list_methods: bool = false,
    print_help: bool = false,
};

fn parseArgs(gpa: Allocator) !Args {
    _ = gpa;
    var args = Args{};
    var it = std.process.args();
    _ = it.next();
    while (it.next()) |a| {
        if (mem.eql(u8, a, "--summary")) {
            args.summary = true;
        } else if (mem.eql(u8, a, "--verbose") or mem.eql(u8, a, "-v")) {
            args.verbose = true;
        } else if (mem.eql(u8, a, "--list-slab-types")) {
            args.list_slab_types = true;
        } else if (mem.eql(u8, a, "--list-methods")) {
            args.list_methods = true;
        } else if (mem.eql(u8, a, "--list-lock-pairs")) {
            args.list_lock_pairs = true;
        } else if (mem.eql(u8, a, "--help") or mem.eql(u8, a, "-h")) {
            args.print_help = true;
        } else if (mem.eql(u8, a, "--entry")) {
            if (it.next()) |val| args.entry_filter = val;
        }
    }
    return args;
}

fn printHelp(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\Usage: check_gen_lock [options]
        \\
        \\Static analyzer for SecureSlab gen-lock coverage on kernel slab-backed
        \\objects. Scans every kernel/**/*.zig file and reports:
        \\
        \\  - Bare-pointer invariant violations (*T where T is slab-backed and
        \\    SlabRef(T) is required).
        \\  - .ptr bypass sites that name a SlabRef's raw pointer outside a
        \\    lock() / unlock() bracket, unless explicitly marked self-alive.
        \\  - Per-entry-point gen-lock bracketing: every access to a slab-typed
        \\    local in a syscall / exception handler must be tight-preceded by
        \\    a lock and tight-followed by an unlock on the same ident.
        \\
        \\Options:
        \\  --summary             one line per entry with finding counts
        \\  --verbose, -v         per-ident access and lock-op summary
        \\  --entry NAME          drill into a single handler
        \\  --list-slab-types     print discovered slab-backed types and exit
        \\  --list-methods        print discovered (receiver, method) pairs
        \\  --help, -h            show this help
        \\
        \\Exit status is nonzero if any err-severity findings are emitted.
        \\
    );
}

// Repo root is the parent of the parent of the exe directory.
fn findRepoRoot(gpa: Allocator) ![]const u8 {
    const cwd = try std.process.getCwdAlloc(gpa);
    defer gpa.free(cwd);
    // Walk up until we find a directory that contains `kernel/`.
    var cur = try gpa.dupe(u8, cwd);
    while (true) {
        const candidate = try fs.path.join(gpa, &.{ cur, "kernel" });
        defer gpa.free(candidate);
        if (fs.cwd().access(candidate, .{})) |_| {
            return cur;
        } else |_| {}
        // Go up.
        if (fs.path.dirname(cur)) |parent| {
            const up = try gpa.dupe(u8, parent);
            gpa.free(cur);
            cur = up;
            if (mem.eql(u8, cur, "/")) {
                gpa.free(cur);
                return error.RepoRootNotFound;
            }
        } else {
            gpa.free(cur);
            return error.RepoRootNotFound;
        }
    }
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

    const repo_root = try findRepoRoot(gpa);
    defer gpa.free(repo_root);
    const kernel_dir = try fs.path.join(gpa, &.{ repo_root, "kernel" });
    defer gpa.free(kernel_dir);

    // Collect file list.
    var paths = ArrayList([]const u8).empty;
    defer {
        for (paths.items) |p| gpa.free(p);
        paths.deinit(gpa);
    }
    var rels = ArrayList([]const u8).empty;
    defer {
        for (rels.items) |p| gpa.free(p);
        rels.deinit(gpa);
    }
    try walkZigFiles(gpa, kernel_dir, repo_root, &paths, &rels);

    // Load + tokenize.
    var files = ArrayList(*SourceFile).empty;
    defer {
        for (files.items) |sf| {
            sf.deinit(gpa);
            gpa.destroy(sf);
        }
        files.deinit(gpa);
    }
    var tokens = ArrayList([]const Tok).empty;
    defer {
        for (tokens.items) |t| gpa.free(t);
        tokens.deinit(gpa);
    }

    for (paths.items, rels.items) |p, r| {
        const sf = try gpa.create(SourceFile);
        sf.* = loadSourceFile(gpa, try gpa.dupe(u8, p), try gpa.dupe(u8, r)) catch |e| {
            gpa.destroy(sf);
            std.debug.print("error loading {s}: {s}\n", .{ p, @errorName(e) });
            continue;
        };
        try files.append(gpa, sf);
        const toks = try tokenizeFile(gpa, sf);
        try tokens.append(gpa, toks);
    }

    // Slab types.
    var slab_types = SlabTypeMap.init(gpa);
    defer slab_types.deinit(gpa);
    try findSlabTypes(gpa, files.items, tokens.items, &slab_types);

    if (args.list_slab_types) {
        try w.writeAll("Slab-backed types:\n");
        // Sort by name.
        var names = ArrayList([]const u8).empty;
        defer names.deinit(gpa);
        var stit = slab_types.inner.keyIterator();
        while (stit.next()) |k| try names.append(gpa, k.*);
        std.sort.heap([]const u8, names.items, {}, lessStr);
        for (names.items) |nm| {
            const st = slab_types.inner.get(nm).?;
            try w.print("  {s:<20} {s}:{d}\n", .{ nm, st.file_rel, st.line });
        }
        try w.flush();
        return 0;
    }

    // Struct fields.
    var struct_fields = ArrayList(StructField).empty;
    defer struct_fields.deinit(gpa);
    for (files.items, tokens.items) |sf, t| {
        try scanStructFields(gpa, sf, t, &struct_fields);
    }

    // Bare-ptr findings.
    var bare_ptr = ArrayList(BarePtrFinding).empty;
    defer {
        for (bare_ptr.items) |f| {
            gpa.free(f.struct_name);
            gpa.free(f.field_name);
            gpa.free(f.field_type);
        }
        bare_ptr.deinit(gpa);
    }
    try findBareSlabPointerFields(gpa, struct_fields.items, &slab_types, &bare_ptr);
    std.sort.heap(BarePtrFinding, bare_ptr.items, {}, lessBarePtr);

    // `.ptr` bypass findings.
    var slab_field_names = SliceSet.init(gpa);
    defer slab_field_names.deinit();
    try collectSlabFieldNames(struct_fields.items, &slab_field_names);
    var ptr_bypasses = ArrayList(PtrBypassFinding).empty;
    defer {
        for (ptr_bypasses.items) |f| {
            gpa.free(f.chain);
            gpa.free(f.context);
        }
        ptr_bypasses.deinit(gpa);
    }
    try findPtrBypasses(gpa, files.items, &slab_field_names, &ptr_bypasses);

    // Fn index.
    var fn_index = FnIndex.init(gpa);
    defer {
        var it = fn_index.valueIterator();
        while (it.next()) |fi_ptr| {
            const fi = fi_ptr.*;
            if (fi.other_params.len > 0) gpa.free(fi.other_params);
            gpa.destroy(fi);
        }
        fn_index.deinit();
    }
    try buildFnIndex(gpa, files.items, tokens.items, &slab_types, &fn_index);

    if (args.list_methods) {
        try w.print("Methods on slab-backed types ({d}):\n", .{fn_index.count()});
        // Sort by "recv.name".
        var pairs = ArrayList(MethodPair).empty;
        defer pairs.deinit(gpa);
        var it = fn_index.iterator();
        while (it.next()) |kv| try pairs.append(gpa, .{ .key = kv.key_ptr.*, .fi = kv.value_ptr.* });
        std.sort.heap(MethodPair, pairs.items, {}, lessPair);
        for (pairs.items) |p| {
            try w.print("  {s}.{s:<30} {s}:{d}\n", .{ p.key.recv, p.key.name, p.fi.file_rel, p.fi.line });
        }
        try w.flush();
        return 0;
    }

    // Entry points.
    var entries = ArrayList(EntryPoint).empty;
    defer entries.deinit(gpa);
    try findEntryPoints(gpa, files.items, tokens.items, &entries);

    // Filter.
    if (args.entry_filter) |ef| {
        var filtered = ArrayList(EntryPoint).empty;
        errdefer filtered.deinit(gpa);
        for (entries.items) |e| if (mem.eql(u8, e.name, ef)) try filtered.append(gpa, e);
        entries.deinit(gpa);
        entries = filtered;
        if (entries.items.len == 0) {
            try w.print("no entry matching {s}\n", .{ef});
            try w.flush();
            return 2;
        }
    }

    // Analyze each entry.
    var pool = Pool.init(gpa);
    defer pool.deinit();

    // Build lock-field registry now that pool exists: every struct
    // field whose declared type is in LOCK_TYPE_NAMES maps to a class
    // name of the form "<OwnerStruct>.<field>".
    var lock_fields = LockFieldMap.init(gpa);
    defer lock_fields.deinit();
    try buildLockFieldMap(gpa, &pool, struct_fields.items, &lock_fields);

    // Struct field type map (owner.field → bare type) used for walking
    // multi-segment receiver chains like `a.b.c.lock()` when resolving
    // the owner of `c`'s lock field.
    var field_types = StructFieldTypeMap.init(gpa);
    defer field_types.deinit();
    try buildStructFieldTypeMap(&pool, struct_fields.items, &field_types);

    // Module-level globals. Every `var/const NAME: TYPE` at file scope
    // contributes a NAME → element type entry; walks resolve locals
    // that reference these globals (e.g. `const state =
    // &core_states[i];`) so downstream lock-field accesses through
    // those locals classify correctly.
    var module_globals = StringStringMap.init(gpa);
    defer module_globals.deinit();
    for (files.items, tokens.items) |sf, t| {
        try scanModuleGlobals(gpa, &pool, sf, t, &module_globals);
    }
    if (args.list_lock_pairs) {
        try w.print("\nModule globals ({d}):\n", .{module_globals.count()});
        var mit = module_globals.iterator();
        while (mit.next()) |kv| {
            try w.print("  {s} : {s}\n", .{ kv.key_ptr.*, kv.value_ptr.* });
        }
        try w.print("\nLock fields ({d}):\n", .{lock_fields.count()});
        var lit = lock_fields.iterator();
        while (lit.next()) |kv| {
            try w.print("  {s}.{s} → {s}\n", .{ kv.key_ptr.owner, kv.key_ptr.field, kv.value_ptr.* });
        }
        try w.writeAll("\n");
    }

    var results = ArrayList(CheckResult).empty;
    defer {
        for (results.items) |*r| r.deinit(gpa);
        results.deinit(gpa);
    }

    var summaries = SummaryMap.init(gpa);
    defer {
        var sit = summaries.valueIterator();
        while (sit.next()) |sp| {
            const s = sp.*;
            if (s.events.len > 0) gpa.free(s.events);
            if (s.param_types.len > 0) gpa.free(s.param_types);
            if (s.param_names.len > 0) gpa.free(s.param_names);
            gpa.destroy(s);
        }
        summaries.deinit();
    }

    for (entries.items) |*entry| {
        var env = SlabEnv.init(gpa);
        var events = EventMap.init(gpa);
        try analyzeEntry(gpa, &pool, files.items, tokens.items, &slab_types, &fn_index, &summaries, &lock_fields, &module_globals, &field_types, entry, &env, &events);
        var res = CheckResult{
            .entry = entry,
            .env = env,
            .events = events,
            .findings = ArrayList(Finding).empty,
        };
        try bracketCheck(gpa, &res);
        try results.append(gpa, res);
    }

    // Sort: by (file, line).
    std.sort.heap(CheckResult, results.items, {}, lessResult);

    var total_errs: u32 = 0;
    var total_infos: u32 = 0;
    var total_tracked: u32 = 0;
    for (results.items) |*res| {
        var errs: u32 = 0;
        var infos: u32 = 0;
        for (res.findings.items) |f| {
            if (f.severity == .err) errs += 1;
            if (f.severity == .info) infos += 1;
        }
        total_errs += errs;
        total_infos += infos;
        total_tracked += @intCast(res.env.map.count());
        if (args.summary) {
            if (res.env.map.count() > 0 or errs > 0 or infos > 0) {
                try w.print("{s:<34}tracked={d:>2}  err={d:>2}  info={d:>2}  [{s}:{d}]\n", .{
                    res.entry.name,
                    res.env.map.count(),
                    errs,
                    infos,
                    res.entry.file_rel,
                    res.entry.line,
                });
            }
        } else {
            try printEntry(gpa, w, res, args.verbose);
        }
    }

    // Bare-ptr findings.
    if (bare_ptr.items.len > 0) {
        try w.writeAll("\n");
        try w.print("Fat-pointer invariant violations ({d} bare *T fields for slab-backed T):\n", .{bare_ptr.items.len});
        for (bare_ptr.items) |f| {
            try w.print("  [ERR ] {s}:{d}  {s}.{s}: {s}  → use SlabRef({s})\n", .{
                f.file_rel, f.line, f.struct_name, f.field_name, f.field_type, f.slab_type,
            });
        }
    }
    total_errs += @intCast(bare_ptr.items.len);

    // `.ptr` bypass.
    if (ptr_bypasses.items.len > 0) {
        try w.writeAll("\n");
        try w.print("SlabRef `.ptr` bypass ({d} sites):\n", .{ptr_bypasses.items.len});
        for (ptr_bypasses.items) |f| {
            try w.print("  [ERR ] {s}:{d}  {s}  →  use `<ref>.lock()` / `<ref>.unlock()` bracket\n", .{ f.file_rel, f.line, f.chain });
            const trunc_len = @min(f.context.len, 120);
            try w.print("         {s}\n", .{f.context[0..trunc_len]});
        }
    }
    total_errs += @intCast(ptr_bypasses.items.len);

    // Lock-ordering analysis.
    var all_pairs = ArrayList(LockPair).empty;
    defer all_pairs.deinit(gpa);
    for (results.items) |*res| {
        try collectLockPairsFromResult(gpa, &pool, res, &all_pairs);
    }

    // Widened lock-pair coverage: walk every slab-type method in the
    // fn_index as if it were an entry point, *for pair collection only*.
    // Bracket-check findings from these walks are discarded — those are
    // already covered by the summary-fold pipeline from the real
    // entries. What this adds is lock events on NON-PARAM receivers
    // (`self.perm_lock`, `proc.vm`, etc.) that summaries can't carry
    // upward because ParamEvent only tracks effects on params.
    {
        var fit = fn_index.iterator();
        while (fit.next()) |kv| {
            const fi = kv.value_ptr.*;
            const fn_name = kv.key_ptr.name;

            // Skip if already a primary entry (exact name + file).
            var is_primary = false;
            for (entries.items) |pe| {
                if (mem.eql(u8, pe.name, fn_name) and
                    mem.eql(u8, pe.file_rel, fi.file_rel))
                {
                    is_primary = true;
                    break;
                }
            }
            if (is_primary) continue;

            const synth = EntryPoint{
                .name = fn_name,
                .file_path = fi.file_path,
                .file_rel = fi.file_rel,
                .line = fi.line,
                .body_start_line = fi.body_start_line,
                .body_end_line = fi.body_end_line,
            };
            var env = SlabEnv.init(gpa);
            var events = EventMap.init(gpa);
            analyzeEntry(
                gpa, &pool, files.items, tokens.items,
                &slab_types, &fn_index, &summaries,
                &lock_fields, &module_globals, &field_types,
                &synth, &env, &events,
            ) catch {
                // Best-effort cleanup on error.
                var eit = events.valueIterator();
                while (eit.next()) |al| al.deinit(gpa);
                events.deinit();
                env.deinit();
                continue;
            };
            var synth_res = CheckResult{
                .entry = &synth,
                .env = env,
                .events = events,
                .findings = ArrayList(Finding).empty,
            };
            collectLockPairsFromResult(gpa, &pool, &synth_res, &all_pairs) catch {};
            // CheckResult.deinit frees env, events, and findings.
            synth_res.deinit(gpa);
        }
    }
    if (args.list_lock_pairs) {
        try w.writeAll("\n");
        try w.print("Lock-ordering pairs ({d}):\n", .{all_pairs.items.len});
        for (all_pairs.items) |p| {
            try w.print("  {s} → {s}  at {s}:{d}  in {s}()  [{s} held, {s} acquired]\n", .{
                p.outer, p.inner, p.file_rel, p.line, p.entry_name,
                p.outer_ident, p.inner_ident,
            });
        }
    }

    // Same-type overlap: two locks of the same class held at once
    // without going through a blessed ordered-pair helper. This is the
    // textbook two-instance deadlock — thread A holds instance1 and
    // waits on instance2; thread B holds instance2 and waits on
    // instance1. The fix is `lockPair(a, b)` (kernel/utils/sync.zig),
    // which acquires in stable address order and breaks the cycle.
    var same_type_overlaps = ArrayList(LockPair).empty;
    defer same_type_overlaps.deinit(gpa);
    for (all_pairs.items) |p| {
        if (!mem.eql(u8, p.outer, p.inner)) continue;
        // Dedup against earlier same-type overlaps on (file, line, class).
        var dup = false;
        for (same_type_overlaps.items) |q| {
            if (mem.eql(u8, p.file_rel, q.file_rel) and p.line == q.line and
                mem.eql(u8, p.outer, q.outer))
            {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        try same_type_overlaps.append(gpa, p);
    }
    if (same_type_overlaps.items.len > 0) {
        try w.writeAll("\n");
        try w.print("Same-type lock overlap ({d} sites — require lockPair/unlockPair):\n", .{same_type_overlaps.items.len});
        for (same_type_overlaps.items) |p| {
            try w.print(
                "  [ERR ] {s} held while acquiring another {s}  at {s}:{d}  in {s}()\n" ++
                "          [{s} held, {s} acquired]  → wrap via `zag.utils.sync.lockPair(&a, &b)`\n",
                .{
                    p.outer, p.outer, p.file_rel, p.line, p.entry_name,
                    p.outer_ident, p.inner_ident,
                },
            );
        }
    }
    total_errs += @intCast(same_type_overlaps.items.len);

    var cycles = ArrayList([][]const u8).empty;
    defer {
        for (cycles.items) |scc| gpa.free(scc);
        cycles.deinit(gpa);
    }
    try findLockCycles(gpa, all_pairs.items, &cycles);

    if (cycles.items.len > 0) {
        try w.writeAll("\n");
        try w.print("Lock-ordering cycles ({d}):\n", .{cycles.items.len});
        for (cycles.items, 0..) |scc, ci| {
            try w.print("  Cycle {d} ({d} classes):", .{ ci + 1, scc.len });
            // Node list — keep it compact.
            for (scc, 0..) |c, i| {
                if (i > 0) try w.writeAll(" ⇄ ");
                try w.print(" {s}", .{c});
            }
            try w.writeAll("\n");
            // Representative edges inside this SCC. Dedup by
            // (outer, inner) so we don't spam identical entries
            // discovered from multiple entry walks.
            const EdgeKey = struct {
                fn matches(a: LockPair, b: LockPair) bool {
                    return mem.eql(u8, a.outer, b.outer) and
                        mem.eql(u8, a.inner, b.inner) and
                        mem.eql(u8, a.file_rel, b.file_rel) and
                        a.line == b.line;
                }
            };
            var shown: usize = 0;
            for (all_pairs.items, 0..) |p, pi| {
                var in_o = false;
                var in_i = false;
                for (scc) |c| {
                    if (mem.eql(u8, c, p.outer)) in_o = true;
                    if (mem.eql(u8, c, p.inner)) in_i = true;
                }
                if (!(in_o and in_i)) continue;
                // Dedup against earlier items in this SCC's listing.
                var dup = false;
                for (all_pairs.items[0..pi]) |q| {
                    var inq_o = false;
                    var inq_i = false;
                    for (scc) |c| {
                        if (mem.eql(u8, c, q.outer)) inq_o = true;
                        if (mem.eql(u8, c, q.inner)) inq_i = true;
                    }
                    if (!(inq_o and inq_i)) continue;
                    if (EdgeKey.matches(p, q)) {
                        dup = true;
                        break;
                    }
                }
                if (dup) continue;
                try w.print(
                    "    [ERR ] {s} → {s}  at {s}:{d}  in {s}()\n",
                    .{ p.outer, p.inner, p.file_rel, p.line, p.entry_name },
                );
                shown += 1;
                if (shown >= 8) {
                    try w.writeAll("    ... (additional edges suppressed)\n");
                    break;
                }
            }
        }
        try w.print(
            "  Resolution: establish a stable acquire order across all sites, or\n" ++
            "  wrap same-type nestings in `lockPair(a, b)` for address-ordered acquire.\n",
            .{},
        );
    }
    total_errs += @intCast(cycles.items.len);

    try w.writeAll("\n");
    try w.print("Summary: {d} entries, {d} tracked idents, {d} err, {d} info\n", .{ results.items.len, total_tracked, total_errs, total_infos });
    try w.print("         {d} slab-backed types discovered\n", .{slab_types.inner.count()});
    try w.print("         {d} bare-pointer fat-pointer violations\n", .{bare_ptr.items.len});
    try w.print("         {d} `.ptr` bypass sites\n", .{ptr_bypasses.items.len});
    try w.print("         {d} lock-ordering pairs, {d} cycles\n", .{ all_pairs.items.len, cycles.items.len });

    try w.flush();
    if (total_errs > 0) return 1;
    return 0;
}

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return mem.lessThan(u8, a, b);
}

const MethodPair = struct { key: FnKey, fi: *FnInfo };

fn lessPair(_: void, a: MethodPair, b: MethodPair) bool {
    const c = mem.order(u8, a.key.recv, b.key.recv);
    if (c == .lt) return true;
    if (c == .gt) return false;
    return mem.lessThan(u8, a.key.name, b.key.name);
}

fn lessResult(_: void, a: CheckResult, b: CheckResult) bool {
    const c = mem.order(u8, a.entry.file_rel, b.entry.file_rel);
    if (c == .lt) return true;
    if (c == .gt) return false;
    return a.entry.line < b.entry.line;
}

fn lessBarePtr(_: void, a: BarePtrFinding, b: BarePtrFinding) bool {
    const c = mem.order(u8, a.file_rel, b.file_rel);
    if (c == .lt) return true;
    if (c == .gt) return false;
    return a.line < b.line;
}

fn printEntry(gpa: Allocator, w: *std.Io.Writer, res: *const CheckResult, verbose: bool) !void {
    _ = gpa;
    try w.writeAll("\n");
    try w.print("=== {s}  [{s}:{d}]\n", .{ res.entry.name, res.entry.file_rel, res.entry.line });
    if (res.env.map.count() == 0) {
        try w.writeAll("    (no slab-typed idents tracked)\n");
        return;
    }
    try w.writeAll("    tracked: ");
    // Build "k:v, k:v".
    var first = true;
    var it = res.env.map.iterator();
    while (it.next()) |kv| {
        if (!first) try w.writeAll(", ");
        first = false;
        try w.print("{s}:{s}", .{ kv.key_ptr.*, kv.value_ptr.* });
    }
    try w.writeAll("\n");
    if (verbose) {
        var itA = res.events.iterator();
        while (itA.next()) |kv| {
            const ident = kv.key_ptr.*;
            const evs = kv.value_ptr.items;
            if (evs.len == 0) continue;
            var n_access: usize = 0;
            var min_l: u32 = std.math.maxInt(u32);
            var max_l: u32 = 0;
            for (evs) |e| {
                if (e.kind != .access) continue;
                n_access += 1;
                if (e.src_line < min_l) min_l = e.src_line;
                if (e.src_line > max_l) max_l = e.src_line;
            }
            if (n_access == 0) continue;
            try w.print("      {s} accesses on L{d}..L{d} ({d} refs)\n", .{ ident, min_l, max_l, n_access });
        }
        var itB = res.events.iterator();
        while (itB.next()) |kv| {
            const ident = kv.key_ptr.*;
            for (kv.value_ptr.items) |ev| {
                if (ev.kind == .access) continue;
                try w.print("      lock-op L{d}: {s}.{s}\n", .{ ev.src_line, ident, eventKindName(ev.kind) });
            }
        }
    }
    for (res.findings.items) |f| {
        const tag = switch (f.severity) {
            .err => "[ERR ]",
            .warn => "[WARN]",
            .info => "[INFO]",
        };
        try w.print("    {s} L{d}: {s}\n", .{ tag, f.line_no, f.message });
    }
}

fn eventKindName(k: EventKind) []const u8 {
    return switch (k) {
        .access => "access",
        .lock => "lock",
        .unlock => "unlock",
        .lock_with_gen => "lockWithGen",
        .defer_unlock => "defer-unlock",
    };
}
