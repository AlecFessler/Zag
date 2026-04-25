//! Token-based dead-code detector for Zag.
//!
//! Reimplementation of `tools/dead_code.py` using `std.zig.Tokenizer`
//! instead of regex over raw source. The token stream gives us:
//!
//!   * comment / string-literal awareness for free,
//!   * accurate brace/paren/bracket depth (so "top-level" is real),
//!   * a clean way to spot identifier chains (`foo.bar.baz`) and to
//!     classify them as either a real use or an alias re-export.
//!
//! The headline win over the regex tool: re-export aliases like
//!
//!     // utils/sync/sync.zig
//!     pub const lockPair = spin_lock.lockPair;
//!
//! are recognized as alias edges, not real uses. The mention of
//! `lockPair` on the RHS does not mark `spin_lock.lockPair` live by
//! itself — only an actual call from outside any alias RHS does.
//!
//! Algorithm:
//!
//!   1. Walk every `.zig` file under the repo (excl. `.zig-cache/`,
//!      `zig-out/`, `.git/`). Files inside the user's chosen
//!      target_dir AND outside `tests/` are the "source set" — only
//!      these get reported. Everything else is scanned for references
//!      so tests still keep their dependencies live.
//!
//!   2. Tokenize each file once. Collect:
//!        - top-level decl Defs (`pub fn`, `fn`, `pub const`, `const`,
//!          `pub var`, `var`, with `extern fn` / `export fn` flagged),
//!        - field/variant Defs inside struct/enum bodies,
//!        - import edges: `const X = @import("path.zig")` →
//!          (FileId map; named modules like `@import("zag")` resolve
//!          via basename),
//!        - alias edges: `const X = a.b.c.d;` (RHS is just a chain of
//!          identifiers and dots) → unresolved chain stored on the Def,
//!        - identifier-chain Uses (`foo.bar.baz`) at every expression
//!          position, tagged with the alias-decl owner if the use sits
//!          on the RHS of an alias decl ("weak").
//!
//!   3. Liveness propagation:
//!        - Seed with strong uses, `panic` / `main`, and `export fn`s.
//!        - Resolve each chain segment-by-segment in the file scope,
//!          following imports across files and following aliases by
//!          inlining their RHS into the chain. Mark every Def touched
//!          along the resolution path live.
//!        - Field/variant Defs and methods (`fn` with a parent
//!          container) become live if `.<name>` appears anywhere in
//!          the repo as a token sequence — same loose heuristic as the
//!          Python tool, since type inference is out of scope.
//!        - When a previously-dead Def becomes live, re-resolve its
//!          alias_target chain (if any) so transitive aliases activate.
//!
//!   4. Report Defs in the source set that never went live, grouped
//!      by file and matching the Python tool's text format. Exit code
//!      nonzero iff any are reported.

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const ascii = std.ascii;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const AutoHashMap = std.AutoHashMap;
const Tokenizer = std.zig.Tokenizer;
const Token = std.zig.Token;
const Tag = std.zig.Token.Tag;

// -----------------------------------------------------------------
// Config
// -----------------------------------------------------------------

/// Functions whose names are resolved by linker / runtime / reflection
/// and should never be flagged.
const EXEMPT_FUNCTION_NAMES = [_][]const u8{ "panic", "main" };

const REPO_DIRS_TO_WALK = [_][]const u8{
    "kernel",
    "routerOS",
    "hyprvOS",
    "bootloader",
    "tools",
    "tests",
};

const SKIP_DIR_COMPONENTS = [_][]const u8{
    ".zig-cache",
    "zig-out",
    ".git",
};

// -----------------------------------------------------------------
// Types
// -----------------------------------------------------------------

const FileId = u32;
const DefId = u32;

const DefKind = enum {
    function,
    @"struct",
    @"enum",
    @"union",
    @"const",
    @"var",
    import,
    field,
    variant,

    fn label(self: DefKind) []const u8 {
        return switch (self) {
            .function => "FUNCTION",
            .@"struct" => "STRUCT",
            .@"enum" => "ENUM",
            .@"union" => "UNION",
            .@"const" => "CONST",
            .@"var" => "VAR",
            .import => "IMPORT",
            .field => "FIELD",
            .variant => "VARIANT",
        };
    }
};

const Def = struct {
    file: FileId,
    name: []const u8,
    line: u32,
    kind: DefKind,
    parent: ?[]const u8 = null, // for fields/variants
    is_pub: bool = false,
    is_top_level: bool = false,
    is_export: bool = false,
    /// If this decl is a re-export alias of the form
    /// `pub? const X = a.b.c.<lastIdent>;` — chain of identifiers on RHS.
    /// `null` for non-aliasing decls.
    alias_target: ?[]const []const u8 = null,
    /// If this decl is `const X = @import("path.zig")` — index of the
    /// resolved file (or null if path could not be resolved).
    import_target: ?FileId = null,
};

const Use = struct {
    in_file: FileId,
    chain: []const []const u8,
    /// True iff this use sits on the RHS of a top-level alias decl
    /// (`pub? const X = chain;`). Such uses are not direct evidence of
    /// liveness; they are activated only when X itself becomes live.
    weak_owner: ?DefId,
};

const FileScope = struct {
    /// Top-level decls (functions, consts, vars, imports, alias re-exports
    /// — NOT inner fields/variants) keyed by name.
    decls: StringHashMap(DefId),

    /// All function/const/var defs declared anywhere in the file
    /// (regardless of container nesting). Lookup target for bare-name
    /// uses inside container methods (a sibling method call like
    /// `deliverFaultToWaiter(x, y)` inside `Process`'s methods has no
    /// container qualifier in the source). May contain multiple DefIds
    /// per name when distinct containers each define a method of the
    /// same name; we mark them all live (safe over-approximation).
    any_decls: StringHashMap(ArrayList(DefId)),
};

const FileEntry = struct {
    path: []const u8, // absolute
    rel_path: []const u8, // relative to repo root
    basename: []const u8, // filename without ".zig"
    /// True for files inside the user's chosen target_dir (kernel, routerOS, ...)
    /// and not under tests/ or .zig-cache/. Definitions in non-source files
    /// (e.g. tests) are still scanned but never flagged.
    is_source: bool,
};

// -----------------------------------------------------------------
// Globals (single-shot CLI, single-thread — globals are fine and keep
// the resolution code readable.)
// -----------------------------------------------------------------

var g_arena_state: std.heap.ArenaAllocator = undefined;
var g_arena: Allocator = undefined;

var g_files: ArrayList(FileEntry) = .{};
var g_file_scopes: ArrayList(FileScope) = .{};
var g_defs: ArrayList(Def) = .{};
var g_uses: ArrayList(Use) = .{};

/// Maps a basename ("spin_lock") → list of FileIds that match. Used by
/// `@import("spin_lock.zig")` resolution when we can't find the file by
/// path joining.
var g_basename_index: StringHashMap(ArrayList(FileId)) = undefined;

/// Maps absolute path → FileId.
var g_path_index: StringHashMap(FileId) = undefined;

/// Liveness flag per Def.
var g_live: []bool = &.{};

/// Reverse alias edges: for each Def D, list of alias Defs A such that
/// resolving A's RHS reaches D. Pre-computed before live propagation.
var g_reverse_aliases: []ArrayList(DefId) = &.{};

/// Field-name set: every `.<ident>` token sequence in the entire repo.
/// Used to keep struct fields / enum variants live (we don't do real
/// type resolution, so any `.field_name` mention keeps `field_name`
/// alive — same heuristic as the Python tool).
var g_field_uses: StringHashMap(void) = undefined;

/// Repo root absolute path.
var g_repo_root: []const u8 = "";

// -----------------------------------------------------------------
// Path / IO helpers
// -----------------------------------------------------------------

fn isSkippedDir(name: []const u8) bool {
    for (SKIP_DIR_COMPONENTS) |s| {
        if (mem.eql(u8, name, s)) return true;
    }
    return false;
}

fn joinPath(a: Allocator, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts, 0..) |p, i| {
        total += p.len;
        if (i + 1 < parts.len) total += 1;
    }
    const out = try a.alloc(u8, total);
    var idx: usize = 0;
    for (parts, 0..) |p, i| {
        @memcpy(out[idx .. idx + p.len], p);
        idx += p.len;
        if (i + 1 < parts.len) {
            out[idx] = '/';
            idx += 1;
        }
    }
    return out;
}

fn dirname(path: []const u8) []const u8 {
    var i = path.len;
    while (i > 0) {
        i -= 1;
        if (path[i] == '/') return path[0..i];
    }
    return "";
}

fn basenameNoExt(path: []const u8) []const u8 {
    var start: usize = 0;
    var j: usize = path.len;
    while (j > 0) {
        j -= 1;
        if (path[j] == '/') {
            start = j + 1;
            break;
        }
    }
    const file = path[start..];
    if (mem.endsWith(u8, file, ".zig")) {
        return file[0 .. file.len - 4];
    }
    return file;
}

fn relToRepo(abs: []const u8) []const u8 {
    if (mem.startsWith(u8, abs, g_repo_root)) {
        var s = abs[g_repo_root.len..];
        if (s.len > 0 and s[0] == '/') s = s[1..];
        return s;
    }
    return abs;
}

fn pathContainsTests(rel: []const u8) bool {
    var it = mem.tokenizeAny(u8, rel, "/");
    while (it.next()) |seg| {
        if (mem.eql(u8, seg, "tests")) return true;
        if (mem.eql(u8, seg, "redteam")) return true;
    }
    return false;
}

fn readFileAlloc(a: Allocator, path: []const u8) ![:0]u8 {
    const f = try fs.openFileAbsolute(path, .{});
    defer f.close();
    const stat = try f.stat();
    const buf = try a.allocSentinel(u8, stat.size, 0);
    _ = try f.readAll(buf);
    return buf;
}

// -----------------------------------------------------------------
// File discovery
// -----------------------------------------------------------------

fn walkDir(a: Allocator, abs_dir: []const u8, target_rel: []const u8) !void {
    var dir = fs.openDirAbsolute(abs_dir, .{ .iterate = true }) catch return;
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind == .directory) {
            if (isSkippedDir(entry.name)) continue;
            const sub = try joinPath(a, &.{ abs_dir, entry.name });
            try walkDir(a, sub, target_rel);
        } else if (entry.kind == .file) {
            if (!mem.endsWith(u8, entry.name, ".zig")) continue;
            const abs = try joinPath(a, &.{ abs_dir, entry.name });
            const rel = relToRepo(abs);
            const rel_owned = try a.dupe(u8, rel);
            const bn = try a.dupe(u8, basenameNoExt(entry.name));
            const is_source = blk: {
                if (target_rel.len == 0) break :blk false;
                if (!mem.startsWith(u8, rel, target_rel)) break :blk false;
                if (rel.len > target_rel.len and rel[target_rel.len] != '/') break :blk false;
                if (pathContainsTests(rel)) break :blk false;
                break :blk true;
            };
            const fid: FileId = @intCast(g_files.items.len);
            try g_files.append(a, .{
                .path = abs,
                .rel_path = rel_owned,
                .basename = bn,
                .is_source = is_source,
            });
            const gop = try g_basename_index.getOrPut(bn);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            try gop.value_ptr.append(a, fid);
            try g_path_index.put(abs, fid);
        }
    }
}

// -----------------------------------------------------------------
// Tokenizer-driven parse
// -----------------------------------------------------------------

const ParseCtx = struct {
    a: Allocator,
    file: FileId,
    src: [:0]const u8,
    toks: []Token, // pre-collected token slice
    /// Byte offset → 1-based line number.
    line_starts: []const u32,
};

fn lineOf(ctx: *const ParseCtx, byte_off: usize) u32 {
    // Binary search.
    var lo: usize = 0;
    var hi: usize = ctx.line_starts.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (ctx.line_starts[mid] <= byte_off) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return @intCast(lo); // 1-based
}

fn computeLineStarts(a: Allocator, src: []const u8) ![]u32 {
    var out: ArrayList(u32) = .{};
    try out.append(a, 0);
    for (src, 0..) |c, i| {
        if (c == '\n') try out.append(a, @intCast(i + 1));
    }
    return out.toOwnedSlice(a);
}

fn tokSlice(ctx: *const ParseCtx, t: Token) []const u8 {
    return ctx.src[t.loc.start..t.loc.end];
}

/// Brace-depth tracker honoring (), [], {} nesting via tokens (not
/// characters in strings/comments — the tokenizer already handles those).
const Depth = struct {
    paren: i32 = 0,
    bracket: i32 = 0,
    brace: i32 = 0,

    fn isTopBraceOnly(self: Depth) bool {
        // Top-level if no brace nesting (paren/bracket within a top-level
        // decl is fine — the decl is still at module scope).
        return self.brace == 0;
    }
};

const ContainerKind = enum { @"struct", @"enum", @"union", none };

const ContainerFrame = struct {
    kind: ContainerKind,
    name: []const u8, // owning type name (best-effort; "" if unknown)
    /// Brace depth AT WHICH THIS FRAME OPENED. We pop when depth returns
    /// to this value.
    depth_at_open: i32,
};

/// Walks tokens and emits defs + uses + alias edges into the global
/// arena-backed structures.
fn parseFile(ctx: *ParseCtx) !void {
    const a = ctx.a;
    const file = ctx.file;
    const toks = ctx.toks;

    // Per-file scope: top-level decl name → DefId.
    var scope = FileScope{ .decls = StringHashMap(DefId).init(a), .any_decls = StringHashMap(ArrayList(DefId)).init(a) };

    var depth = Depth{};
    var container_stack: ArrayList(ContainerFrame) = .{};
    // Pending "next const/fn declares a container of kind X with name Y".
    // We walk tokens linearly and infer container entry/exit from braces.

    // Last-seen pending container kind (set when we see `= struct/enum/union`
    // or `extern struct` etc.) — applies to the next `{` we encounter.
    var pending_container_name: ?[]const u8 = null;
    var pending_container_kind: ContainerKind = .none;

    // True iff the next `{` we see opens a function body (so we must
    // suppress Def emission for any inner const/var/fn until the matching
    // `}`).
    var pending_fn_body: bool = false;

    // Stack of brace depths at which we entered fn bodies. fn_body_depth >0
    // means "currently inside a fn body" and decl emission is suppressed.
    var fn_body_stack: ArrayList(i32) = .{};

    var i: usize = 0;
    while (i < toks.len) : (i += 1) {
        const t = toks[i];
        switch (t.tag) {
            .l_brace => {
                if (pending_container_kind != .none) {
                    try container_stack.append(a, .{
                        .kind = pending_container_kind,
                        .name = pending_container_name orelse "",
                        .depth_at_open = depth.brace,
                    });
                    pending_container_kind = .none;
                    pending_container_name = null;
                }
                if (pending_fn_body) {
                    try fn_body_stack.append(a, depth.brace);
                    pending_fn_body = false;
                }
                depth.brace += 1;
            },
            .r_brace => {
                depth.brace -= 1;
                // Pop container if we exited it.
                while (container_stack.items.len > 0 and
                    container_stack.items[container_stack.items.len - 1].depth_at_open >= depth.brace)
                {
                    _ = container_stack.pop();
                }
                while (fn_body_stack.items.len > 0 and
                    fn_body_stack.items[fn_body_stack.items.len - 1] >= depth.brace)
                {
                    _ = fn_body_stack.pop();
                }
            },
            .l_paren => depth.paren += 1,
            .r_paren => depth.paren -= 1,
            .l_bracket => depth.bracket += 1,
            .r_bracket => depth.bracket -= 1,

            .keyword_const, .keyword_var, .keyword_fn => {
                if (!isDeclHead(toks, i)) continue;
                const in_fn_body = fn_body_stack.items.len > 0;
                if (try tryParseDecl(ctx, &scope, &container_stack, &depth, &i, &pending_container_name, &pending_container_kind, &pending_fn_body, in_fn_body)) {
                    continue;
                }
            },

            .identifier => {
                // Accumulate identifier chain `a.b.c` as a single Use.
                try emitIdentChain(ctx, file, toks, &i, null);
            },

            else => {},
        }
    }

    if (g_file_scopes.items.len <= file) {
        try g_file_scopes.resize(a, file + 1);
    }
    g_file_scopes.items[file] = scope;
}

/// Emit a Use for an identifier chain starting at toks[i.*]. `i.*` is
/// advanced to the last identifier of the chain (so the outer loop's
/// `+= 1` resumes past it).
///
/// `weak_owner` — pass non-null when the chain sits on the RHS of a
/// top-level alias decl, so liveness propagation can defer activation.
fn emitIdentChain(
    ctx: *ParseCtx,
    file: FileId,
    toks: []Token,
    i: *usize,
    weak_owner: ?DefId,
) !void {
    const a = ctx.a;
    const first_name = tokSlice(ctx, toks[i.*]);

    // Filter out builtin-ish noise: `_` in `for (xs) |_|` etc. The
    // tokenizer emits `_` as identifier.
    if (first_name.len == 0) return;

    var chain: ArrayList([]const u8) = .{};
    try chain.append(a, first_name);

    var j = i.* + 1;
    while (j + 1 < toks.len and toks[j].tag == .period and toks[j + 1].tag == .identifier) {
        try chain.append(a, tokSlice(ctx, toks[j + 1]));
        j += 2;
    }
    i.* = j - 1;

    // Field-use side-channel: if chain.len == 1 and previous token was a
    // period, this was a `.field` access (we already emitted it inside the
    // outer chain logic — but if a struct literal `.{ .x = 1 }` produces
    // bare `.x`, we won't see it here). Actually the chain captures
    // `Foo.bar.baz` as a multi-segment. For `.field` standalone (struct
    // literal field initializer) we capture in the dedicated period-pre-ident
    // pass below.

    try g_uses.append(a, .{
        .in_file = file,
        .chain = try chain.toOwnedSlice(a),
        .weak_owner = weak_owner,
    });
}

/// Returns true iff `toks[i]` (a `const`/`var`/`fn` token) is the head
/// of a real declaration. We walk backward over leading modifiers to
/// find the first one (e.g. `pub`); the token preceding that must be a
/// statement boundary. This rejects `const` used as a type qualifier
/// inside `[*:0]const u8`, `extern` as a calling-convention keyword
/// inside a fn signature, etc.
fn isDeclHead(toks: []Token, i: usize) bool {
    var head = i;
    while (head > 0) {
        const prev = toks[head - 1].tag;
        if (prev == .keyword_pub or prev == .keyword_extern or prev == .keyword_export or prev == .keyword_threadlocal or prev == .keyword_inline or prev == .keyword_noinline) {
            head -= 1;
            continue;
        }
        break;
    }
    if (head == 0) return true;
    var pred_idx = head - 1;
    while (pred_idx > 0 and (toks[pred_idx].tag == .doc_comment or toks[pred_idx].tag == .container_doc_comment)) {
        pred_idx -= 1;
    }
    const pred = toks[pred_idx].tag;
    return pred == .semicolon or
        pred == .l_brace or
        pred == .r_brace or
        pred == .comma or
        pred == .doc_comment or
        pred == .container_doc_comment;
}

/// Try to parse a top-level OR inner-container declaration starting at
/// toks[i.*]. On success, emits a Def, advances `i` past the entire decl
/// (up to and including its terminating `;` for vars/consts/imports, or
/// up to the body `{` for functions / containers), updates depth/container
/// state, and returns true. On failure (not actually a decl) returns false
/// without consuming.
fn tryParseDecl(
    ctx: *ParseCtx,
    scope: *FileScope,
    container_stack: *ArrayList(ContainerFrame),
    depth: *Depth,
    i_ptr: *usize,
    pending_name: *?[]const u8,
    pending_kind: *ContainerKind,
    pending_fn_body: *bool,
    in_fn_body: bool,
) !bool {
    const a = ctx.a;
    const toks = ctx.toks;
    var i = i_ptr.*;
    const file = ctx.file;

    // Walk backward to discover modifiers. `i` is at `const`/`var`/`fn`.
    var is_pub = false;
    var is_export = false;
    var head = i;
    while (head > 0) {
        const prev = toks[head - 1].tag;
        switch (prev) {
            .keyword_pub => {
                is_pub = true;
                head -= 1;
            },
            .keyword_extern => head -= 1,
            .keyword_export => {
                is_export = true;
                head -= 1;
            },
            .keyword_threadlocal, .keyword_inline, .keyword_noinline => head -= 1,
            else => break,
        }
    }

    const top_level = container_stack.items.len == 0 and depth.brace == 0;

    switch (toks[i].tag) {
        .keyword_fn => {
            // `fn name(...)`
            if (i + 1 >= toks.len or toks[i + 1].tag != .identifier) return false;
            const name = tokSlice(ctx, toks[i + 1]);
            const line = lineOf(ctx, toks[i + 1].loc.start);

            // Determine parent container (if inside one).
            var parent_name: ?[]const u8 = null;
            if (container_stack.items.len > 0) {
                parent_name = container_stack.items[container_stack.items.len - 1].name;
            }

            // Suppress Def emission for fn-body-local nested fns (rare).
            if (!in_fn_body) {
                const def_id: DefId = @intCast(g_defs.items.len);
                try g_defs.append(a, .{
                    .file = file,
                    .name = name,
                    .line = line,
                    .kind = .function,
                    .parent = parent_name,
                    .is_pub = is_pub,
                    .is_top_level = top_level,
                    .is_export = is_export,
                });
                if (top_level) {
                    try scope.decls.put(name, def_id);
                }
                const gop = try scope.any_decls.getOrPut(name);
                if (!gop.found_existing) gop.value_ptr.* = .{};
                try gop.value_ptr.append(a, def_id);
            }

            // Walk parameters and return type, emitting use-chains for
            // identifiers (so `?*std.builtin.StackTrace` keeps `std` and
            // `StackTrace` live). Skip parameter NAMES (the identifier
            // immediately followed by `:`). Anonymous return-type structs
            // (`fn f() struct { ... } { body }`) require tracking whether
            // the next `{` opens a type body or the fn body.
            i += 2;
            var local_paren: i32 = 0;
            var local_brace: i32 = 0;
            var pending_typebody: bool = false;
            // Track whether this fn has a body (vs. extern proto).
            var has_body = false;
            while (i < toks.len) {
                const tag = toks[i].tag;
                switch (tag) {
                    .l_paren => {
                        local_paren += 1;
                        i += 1;
                    },
                    .r_paren => {
                        local_paren -= 1;
                        i += 1;
                    },
                    .keyword_struct, .keyword_enum, .keyword_union, .keyword_opaque => {
                        if (local_paren == 0 and local_brace == 0) {
                            pending_typebody = true;
                        }
                        i += 1;
                    },
                    .l_brace => {
                        if (local_paren == 0 and local_brace == 0 and !pending_typebody) {
                            has_body = true;
                            break;
                        }
                        if (pending_typebody) pending_typebody = false;
                        local_brace += 1;
                        i += 1;
                    },
                    .r_brace => {
                        local_brace -= 1;
                        i += 1;
                    },
                    .semicolon => {
                        if (local_paren == 0 and local_brace == 0) break;
                        i += 1;
                    },
                    .identifier => {
                        // Detect param name: identifier followed by `:` at
                        // paren_depth == 1 and brace_depth == 0 (i.e. inside
                        // the param list, not inside a return-type struct).
                        const is_param_name = (local_paren == 1 and local_brace == 0 and i + 1 < toks.len and toks[i + 1].tag == .colon);
                        if (is_param_name) {
                            i += 1;
                            continue;
                        }
                        // Don't double-emit if preceded by `.`.
                        const before_period = i > 0 and toks[i - 1].tag == .period;
                        if (before_period) {
                            i += 1;
                            continue;
                        }
                        var ip = i;
                        try emitIdentChain(ctx, file, toks, &ip, null);
                        i = ip + 1;
                    },
                    else => i += 1,
                }
            }

            if (has_body) {
                pending_fn_body.* = true;
            }
            // Don't consume the `{` — let the outer loop see it and bump
            // brace depth.
            i_ptr.* = i - 1; // outer `+= 1` resumes at i
            return true;
        },

        .keyword_const, .keyword_var => {
            const is_var = toks[i].tag == .keyword_var;
            if (i + 1 >= toks.len or toks[i + 1].tag != .identifier) return false;
            const name = tokSlice(ctx, toks[i + 1]);
            const line = lineOf(ctx, toks[i + 1].loc.start);
            // After name we may have `: Type` or `=` or `;`.
            const k = i + 2;

            // Optional `: Type` clause — consume until `=` or `;`.
            // (Type's identifiers are uses; we'll re-emit via the
            //  generic identifier loop AFTER this decl is registered,
            //  by NOT swallowing those tokens. So: we *don't* skip
            //  through the type — we let outer pass see the idents.
            //  But that means our outer loop will re-enter `tryParseDecl`
            //  on the next ident? No — the outer loop only triggers
            //  tryParseDecl on keyword_pub/const/var/fn/etc. Identifiers
            //  go through the .identifier branch. So leaving `i_ptr`
            //  pointing at the name token's position+2 lets the outer
            //  loop walk the `: Type = ...` portion as plain idents. )
            //
            // Approach: classify what we have on the RHS. If it's a
            // chain-only alias (top-level), record alias_target. Then
            // skip to and including the terminating `;`. While doing so,
            // emit identifier-chain uses tagged with `weak_owner` if
            // alias, otherwise tagged null (strong). For non-alias RHS
            // we still emit normal uses (so `pub const X = foo();` keeps
            // foo live).

            // First detect: is this an @import?
            var is_import = false;
            var import_target: ?FileId = null;

            // Find the `=` (if any) before `;`. Track brace depth so we
            // don't terminate on `;` inside an `orelse { ... return; ... };`
            // block or a struct-literal body.
            var eq_idx: ?usize = null;
            var sc_idx: usize = k;
            var sc_brace: i32 = 0;
            var sc_paren: i32 = 0;
            var sc_bracket: i32 = 0;
            while (sc_idx < toks.len) {
                const tt = toks[sc_idx].tag;
                switch (tt) {
                    .l_brace => sc_brace += 1,
                    .r_brace => sc_brace -= 1,
                    .l_paren => sc_paren += 1,
                    .r_paren => sc_paren -= 1,
                    .l_bracket => sc_bracket += 1,
                    .r_bracket => sc_bracket -= 1,
                    .equal => {
                        if (eq_idx == null and sc_brace == 0 and sc_paren == 0 and sc_bracket == 0) {
                            eq_idx = sc_idx;
                        }
                    },
                    .semicolon => {
                        if (sc_brace == 0 and sc_paren == 0 and sc_bracket == 0) break;
                    },
                    else => {},
                }
                sc_idx += 1;
            }
            const semi = sc_idx;

            // Detect @import on the RHS (allow it to be the entire RHS).
            if (eq_idx) |eq| {
                // Look at the token right after `=`.
                if (eq + 1 < toks.len and toks[eq + 1].tag == .builtin) {
                    const bname = tokSlice(ctx, toks[eq + 1]);
                    if (mem.eql(u8, bname, "@import") and eq + 4 < toks.len and
                        toks[eq + 2].tag == .l_paren and
                        toks[eq + 3].tag == .string_literal and
                        toks[eq + 4].tag == .r_paren and
                        eq + 5 == semi)
                    {
                        is_import = true;
                        const lit = tokSlice(ctx, toks[eq + 3]);
                        // Strip surrounding quotes.
                        if (lit.len >= 2 and lit[0] == '"' and lit[lit.len - 1] == '"') {
                            const inner = lit[1 .. lit.len - 1];
                            import_target = resolveImportPath(ctx.file, inner);
                        }
                    }
                }
            }

            // Detect chain alias RHS:
            //   `(pub )? const NAME = a.b.c.d ;`
            // where the RHS is exactly an identifier-chain (idents and dots).
            var alias_target: ?[]const []const u8 = null;
            var rhs_first_ident: ?usize = null;
            if (eq_idx) |eq| {
                if (!is_import) {
                    var ok = true;
                    var p = eq + 1;
                    var chain: ArrayList([]const u8) = .{};
                    if (p < semi and toks[p].tag == .identifier) {
                        rhs_first_ident = p;
                        try chain.append(a, tokSlice(ctx, toks[p]));
                        p += 1;
                        while (p + 1 < semi and toks[p].tag == .period and toks[p + 1].tag == .identifier) {
                            try chain.append(a, tokSlice(ctx, toks[p + 1]));
                            p += 2;
                        }
                        if (p != semi) ok = false;
                    } else {
                        ok = false;
                    }
                    if (ok) {
                        alias_target = try chain.toOwnedSlice(a);
                    }
                }
            }

            // Detect container kind for `const X = (extern|packed)? (struct|enum|union)`.
            var ck: ContainerKind = .none;
            if (eq_idx) |eq| {
                var p = eq + 1;
                while (p < semi) : (p += 1) {
                    switch (toks[p].tag) {
                        .keyword_extern, .keyword_packed => continue,
                        .keyword_struct => {
                            ck = .@"struct";
                            break;
                        },
                        .keyword_enum => {
                            ck = .@"enum";
                            break;
                        },
                        .keyword_union => {
                            ck = .@"union";
                            break;
                        },
                        else => break,
                    }
                }
            }

            const kind: DefKind = if (is_var) .@"var" else if (is_import) .import else switch (ck) {
                .@"struct" => .@"struct",
                .@"enum" => .@"enum",
                .@"union" => .@"union",
                .none => .@"const",
            };

            // Determine parent container (if inside one) — for inner
            // container decls we still record them as `const`-kind defs
            // attached to this file's scope (top_level=false). The Python
            // tool tracks struct/enum/union definitions whether or not
            // they're nested.
            var parent_name: ?[]const u8 = null;
            if (container_stack.items.len > 0) {
                parent_name = container_stack.items[container_stack.items.len - 1].name;
            }

            var def_id: DefId = 0;
            if (!in_fn_body) {
                def_id = @intCast(g_defs.items.len);
                try g_defs.append(a, .{
                    .file = file,
                    .name = name,
                    .line = line,
                    .kind = kind,
                    .parent = parent_name,
                    .is_pub = is_pub,
                    .is_top_level = top_level,
                    .is_export = is_export,
                    .alias_target = alias_target,
                    .import_target = import_target,
                });
                if (top_level) {
                    try scope.decls.put(name, def_id);
                }
                const gop = try scope.any_decls.getOrPut(name);
                if (!gop.found_existing) gop.value_ptr.* = .{};
                try gop.value_ptr.append(a, def_id);
            }

            // Now emit uses for everything between `=` and `;` (RHS) and
            // also for the type clause between `:` and `=` (if present).
            // For container decls (struct/enum/union body), we DO NOT emit
            // uses for the body — the body's idents are decls + their own
            // RHS uses, handled by the outer loop after we hand control
            // back at the `{`.

            // Emit type-clause uses (between name and `=`).
            // Only for non-container decls.
            if (ck == .none) {
                const start_uses = i + 2;
                const end_uses = if (eq_idx) |eq| eq else semi;
                try emitUsesInRange(ctx, file, toks, start_uses, end_uses, null);

                // Emit RHS uses if present and not import.
                if (eq_idx) |eq| {
                    const rhs_start = eq + 1;
                    const rhs_end = semi;
                    if (!is_import) {
                        // If alias: weak_owner = def_id, but suppress emitting
                        // here and re-emit as weak so liveness propagation works.
                        const weak_owner: ?DefId = if (alias_target != null and !in_fn_body) def_id else null;
                        try emitUsesInRange(ctx, file, toks, rhs_start, rhs_end, weak_owner);
                    }
                }
            }

            // Now position the cursor.
            if (ck != .none) {
                // Container body follows — set pending_kind so the next `{`
                // pushes a container frame. Position `i` just before the
                // `{` so the outer loop sees the `{` as next token.
                pending_kind.* = ck;
                pending_name.* = name;
                // Find first `{` after `=`.
                var p = (eq_idx orelse semi) + 1;
                while (p < toks.len and toks[p].tag != .l_brace) p += 1;
                i_ptr.* = p - 1; // outer `+= 1` resumes at the `{`
                return true;
            } else {
                i_ptr.* = semi; // outer `+= 1` resumes after `;`
                return true;
            }
        },

        else => return false,
    }
}

fn emitUsesInRange(
    ctx: *ParseCtx,
    file: FileId,
    toks: []Token,
    start: usize,
    end: usize,
    weak_owner: ?DefId,
) !void {
    var p = start;
    while (p < end) {
        if (toks[p].tag == .identifier) {
            // Build chain — but skip if preceded by a `.` (means it's a
            // continuation of a chain that should have been picked up as
            // part of a previous identifier's chain). However we just
            // started at `start` which is right after `=` or `:`, so
            // `toks[start-1]` is the `=`/`:` — never a period. For interior
            // periods the inner chain logic eats them.
            const before_is_period = p > 0 and toks[p - 1].tag == .period;
            if (before_is_period) {
                // This identifier was a `.field` — we already track field
                // uses in the global pass below. Skip here so we don't
                // produce noisy 1-segment chains for fields.
                p += 1;
                continue;
            }
            var ip = p;
            try emitIdentChain(ctx, file, toks, &ip, weak_owner);
            p = ip + 1;
        } else {
            p += 1;
        }
    }
}

/// Resolve `@import("...")` path relative to the importing file. Returns
/// the FileId of the imported file, or null if unresolvable (e.g. the
/// path refers to a stdlib file).
fn resolveImportPath(importer_file: FileId, raw_path: []const u8) ?FileId {
    // Common stdlib names: never resolve.
    if (mem.eql(u8, raw_path, "std") or mem.eql(u8, raw_path, "builtin") or mem.eql(u8, raw_path, "root")) {
        return null;
    }

    // Path-shaped: resolve relative to importer dir.
    if (mem.endsWith(u8, raw_path, ".zig") or mem.indexOfScalar(u8, raw_path, '/') != null) {
        const importer_path = g_files.items[importer_file].path;
        const importer_dir = dirname(importer_path);
        const candidate = std.fs.path.resolvePosix(g_arena, &.{ importer_dir, raw_path }) catch return null;
        if (g_path_index.get(candidate)) |fid| return fid;
        // Path didn't match: fall through to basename lookup.
    }

    // Named module (e.g. `@import("zag")`, `@import("lib")`, `@import("kprof")`).
    // Build.zig modules map to a single .zig file; we look up by basename.
    // If exactly one file matches, use it. If multiple, prefer one in the
    // same top-level subtree as the importer.
    const bn_key = blk: {
        // Strip any directory prefix and `.zig` suffix.
        const base = basenameNoExt(raw_path);
        break :blk base;
    };
    if (g_basename_index.get(bn_key)) |list| {
        if (list.items.len == 1) return list.items[0];
        // Disambiguate by shared top-level dir of importer.
        const importer_path = g_files.items[importer_file].path;
        for (list.items) |fid| {
            const cand_path = g_files.items[fid].path;
            if (mem.startsWith(u8, cand_path, dirname(importer_path))) return fid;
        }
        // Last resort: first.
        return list.items[0];
    }
    return null;
}

// -----------------------------------------------------------------
// Field-use side-channel pass
// -----------------------------------------------------------------

fn collectFieldUses(ctx: *ParseCtx) !void {
    const toks = ctx.toks;
    var p: usize = 0;
    while (p + 1 < toks.len) : (p += 1) {
        if (toks[p].tag == .period and toks[p + 1].tag == .identifier) {
            const nm = tokSlice(ctx, toks[p + 1]);
            // Skip if this is part of a longer chain that's already a use
            // (we'll have captured those via emitIdentChain). However for
            // our field/variant heuristic we just need ANY mention of
            // `.<name>` anywhere.
            if (nm.len == 0) continue;
            // Skip 0-len, skip if looks like reserved (none in identifier
            // tag — keywords have their own tags). Insert into set.
            const owned = nm; // arena-stable
            try g_field_uses.put(owned, {});
        }
    }
}

// -----------------------------------------------------------------
// Field/variant detection inside container bodies
// -----------------------------------------------------------------

/// Walk tokens and record FIELD / VARIANT defs for inner-container
/// statements. Done as a second pass so we know container boundaries.
fn collectFieldsAndVariants(ctx: *ParseCtx) !void {
    const a = ctx.a;
    const toks = ctx.toks;
    const file = ctx.file;

    var depth = Depth{};
    var container_stack: ArrayList(ContainerFrame) = .{};
    var pending_kind: ContainerKind = .none;
    var pending_name: ?[]const u8 = null;
    var pending_fn_body: bool = false;
    var fn_body_stack: ArrayList(i32) = .{};

    // We need to recognize statement boundaries. A field/variant statement
    // looks like one of:
    //   <ident> : <type> (= <default>)? ,           (field)
    //   <ident> ,                                   (variant)
    //   <ident> = <expr> ,                          (variant w/ explicit value)
    // … and is at the top level of a container body (depth_at_open + 1).
    //
    // Other items in container bodies — `pub fn`, `const`, `var`, etc.
    // — must be skipped.

    var i: usize = 0;
    while (i < toks.len) : (i += 1) {
        const t = toks[i];
        switch (t.tag) {
            .l_brace => {
                if (pending_kind != .none) {
                    try container_stack.append(a, .{
                        .kind = pending_kind,
                        .name = pending_name orelse "",
                        .depth_at_open = depth.brace,
                    });
                    pending_kind = .none;
                    pending_name = null;
                }
                if (pending_fn_body) {
                    try fn_body_stack.append(a, depth.brace);
                    pending_fn_body = false;
                }
                depth.brace += 1;
            },
            .r_brace => {
                depth.brace -= 1;
                while (container_stack.items.len > 0 and
                    container_stack.items[container_stack.items.len - 1].depth_at_open >= depth.brace)
                {
                    _ = container_stack.pop();
                }
                while (fn_body_stack.items.len > 0 and
                    fn_body_stack.items[fn_body_stack.items.len - 1] >= depth.brace)
                {
                    _ = fn_body_stack.pop();
                }
            },
            .l_paren => depth.paren += 1,
            .r_paren => depth.paren -= 1,
            .l_bracket => depth.bracket += 1,
            .r_bracket => depth.bracket -= 1,

            .keyword_fn => {
                if (!isDeclHead(toks, i)) continue;
                // `fn name(...)` — find matching `{` (body), tracking
                // anonymous return-type bodies so `fn f() struct {..} {..}`
                // doesn't treat the struct's `{` as the fn body.
                var p = i + 1;
                var local_paren: i32 = 0;
                var local_brace: i32 = 0;
                var pending_typebody: bool = false;
                while (p < toks.len) : (p += 1) {
                    switch (toks[p].tag) {
                        .l_paren => local_paren += 1,
                        .r_paren => local_paren -= 1,
                        .keyword_struct, .keyword_enum, .keyword_union, .keyword_opaque => {
                            if (local_paren == 0 and local_brace == 0) pending_typebody = true;
                        },
                        .l_brace => {
                            if (local_paren == 0 and local_brace == 0 and !pending_typebody) {
                                pending_fn_body = true;
                                break;
                            }
                            if (pending_typebody) pending_typebody = false;
                            local_brace += 1;
                        },
                        .r_brace => local_brace -= 1,
                        .semicolon => {
                            if (local_paren == 0 and local_brace == 0) break;
                        },
                        else => {},
                    }
                }
            },

            .keyword_const, .keyword_var => {
                if (!isDeclHead(toks, i)) continue;
                // Detect container-spawning const for inner pending kinds.
                if (t.tag == .keyword_const) {
                    // Look forward: `const NAME = (extern|packed)? (struct|enum|union) {`
                    if (i + 4 < toks.len and toks[i + 1].tag == .identifier and toks[i + 2].tag == .equal) {
                        var p = i + 3;
                        while (p < toks.len) : (p += 1) {
                            switch (toks[p].tag) {
                                .keyword_extern, .keyword_packed => continue,
                                .keyword_struct => {
                                    pending_kind = .@"struct";
                                    pending_name = tokSlice(ctx, toks[i + 1]);
                                    break;
                                },
                                .keyword_enum => {
                                    pending_kind = .@"enum";
                                    pending_name = tokSlice(ctx, toks[i + 1]);
                                    break;
                                },
                                .keyword_union => {
                                    pending_kind = .@"union";
                                    pending_name = tokSlice(ctx, toks[i + 1]);
                                    break;
                                },
                                else => break,
                            }
                        }
                    }
                }
                // Skip past this decl to its terminating `;` or to the body
                // `{` (which the outer loop will then consume into a
                // container frame). We just don't do anything else here;
                // the outer loop handles brace tracking.
            },

            .identifier => {
                // Only consider when we're in container body and at the
                // body's top level (depth.brace == top.depth_at_open + 1)
                // and we're at a "statement start" position (preceded by
                // `,` or `{`).
                if (container_stack.items.len == 0) continue;
                if (fn_body_stack.items.len > 0) continue;
                const top = container_stack.items[container_stack.items.len - 1];
                if (depth.brace != top.depth_at_open + 1) continue;
                if (depth.paren != 0 or depth.bracket != 0) continue;

                // Check predecessor: must be `,` or `{` (or doc-comment / nothing).
                var prev_idx: usize = i;
                while (prev_idx > 0) {
                    prev_idx -= 1;
                    const pt = toks[prev_idx].tag;
                    if (pt == .doc_comment or pt == .container_doc_comment) continue;
                    break;
                }
                if (prev_idx == i) continue;
                const prev_tag = toks[prev_idx].tag;
                if (prev_tag != .comma and prev_tag != .l_brace) continue;

                // Now distinguish field vs variant.
                if (top.kind == .@"struct" or top.kind == .@"union") {
                    if (i + 1 < toks.len and toks[i + 1].tag == .colon) {
                        const name = tokSlice(ctx, t);
                        const line = lineOf(ctx, t.loc.start);
                        try g_defs.append(a, .{
                            .file = file,
                            .name = name,
                            .line = line,
                            .kind = .field,
                            .parent = top.name,
                            .is_pub = false,
                            .is_top_level = false,
                            .is_export = false,
                        });
                    }
                } else if (top.kind == .@"enum") {
                    if (i + 1 < toks.len and (toks[i + 1].tag == .comma or toks[i + 1].tag == .equal or toks[i + 1].tag == .r_brace)) {
                        const name = tokSlice(ctx, t);
                        // skip `_` non-exhaustive marker
                        if (mem.eql(u8, name, "_")) continue;
                        const line = lineOf(ctx, t.loc.start);
                        try g_defs.append(a, .{
                            .file = file,
                            .name = name,
                            .line = line,
                            .kind = .variant,
                            .parent = top.name,
                            .is_pub = false,
                            .is_top_level = false,
                            .is_export = false,
                        });
                    }
                }
            },

            else => {},
        }
    }
}

// -----------------------------------------------------------------
// Liveness propagation
// -----------------------------------------------------------------

/// Resolve a chain in the file scope, marking live every Def touched
/// along the way. Returns the final resolved DefId (or null if
/// unresolved, e.g. the chain steps into stdlib or hits an unknown name).
fn resolveAndMarkLive(in_file: FileId, chain: []const []const u8, work: *ArrayList(DefId)) !void {
    if (chain.len == 0) return;
    var cur_file = in_file;
    var idx: usize = 0;
    var depth_guard: u32 = 0;

    while (idx < chain.len) {
        depth_guard += 1;
        if (depth_guard > 64) return;

        const seg = chain[idx];
        const scope = g_file_scopes.items[cur_file];
        var def_id_opt = scope.decls.get(seg);
        // Fall back to any-depth lookup for the FIRST segment only.
        // This handles bare-name calls between sibling methods inside a
        // container (`fn a() { b(); }` where both are members of struct
        // `Foo`). For deeper segments we want a strict member lookup.
        if (def_id_opt == null and idx == 0) {
            if (scope.any_decls.get(seg)) |list| {
                if (list.items.len > 0) {
                    // Mark all candidates live; resolution proceeds with
                    // the first (best-effort).
                    for (list.items) |id| try markLive(id, work);
                    def_id_opt = list.items[0];
                }
            }
        }
        const def_id = def_id_opt orelse return;
        try markLive(def_id, work);
        const def = g_defs.items[def_id];

        // If this def is an alias, expand its target chain inline.
        if (def.alias_target) |tgt| {
            // Replace seg with tgt + remainder.
            var combined: ArrayList([]const u8) = .{};
            try combined.appendSlice(g_arena, tgt);
            if (idx + 1 < chain.len) {
                try combined.appendSlice(g_arena, chain[idx + 1 ..]);
            }
            const new_chain = try combined.toOwnedSlice(g_arena);
            try resolveAndMarkLive(def.file, new_chain, work);
            return;
        }

        // If this def is an import, switch namespaces.
        if (def.kind == .import) {
            if (def.import_target) |new_file| {
                cur_file = new_file;
                idx += 1;
                continue;
            } else {
                // Unresolved import (stdlib etc.) — terminate.
                return;
            }
        }

        // Container types: resolve next segment as a member.
        if ((def.kind == .@"struct" or def.kind == .@"enum" or def.kind == .@"union") and idx + 1 < chain.len) {
            const member_name = chain[idx + 1];
            const member_id_opt = g_member_index.get(MemberKey{
                .file = def.file,
                .parent = def.name,
                .name = member_name,
            });
            if (member_id_opt) |mid| {
                try markLive(mid, work);
                const mdef = g_defs.items[mid];
                // If member is itself an alias, follow.
                if (mdef.alias_target) |tgt| {
                    var combined: ArrayList([]const u8) = .{};
                    try combined.appendSlice(g_arena, tgt);
                    if (idx + 2 < chain.len) {
                        try combined.appendSlice(g_arena, chain[idx + 2 ..]);
                    }
                    const new_chain = try combined.toOwnedSlice(g_arena);
                    try resolveAndMarkLive(mdef.file, new_chain, work);
                }
            }
            return;
        }

        // Otherwise, this is a real top-level decl. The remainder of the
        // chain (if any) refers to members of this decl (struct fields,
        // type members, etc.). We don't track those here in detail — if
        // any inner Def with the matching name exists in the same file,
        // the FIELD heuristic covers it. So stop.
        return;
    }
}

const MemberKey = struct {
    file: FileId,
    parent: []const u8,
    name: []const u8,

    pub fn hash(self: MemberKey) u64 {
        var h: u64 = std.hash.Wyhash.hash(0, std.mem.asBytes(&self.file));
        h ^= std.hash.Wyhash.hash(h, self.parent);
        h ^= std.hash.Wyhash.hash(h, self.name);
        return h;
    }

    pub fn eql(a: MemberKey, b: MemberKey) bool {
        return a.file == b.file and mem.eql(u8, a.parent, b.parent) and mem.eql(u8, a.name, b.name);
    }
};

const MemberKeyContext = struct {
    pub fn hash(_: MemberKeyContext, k: MemberKey) u64 {
        return k.hash();
    }
    pub fn eql(_: MemberKeyContext, a: MemberKey, b: MemberKey) bool {
        return MemberKey.eql(a, b);
    }
};

var g_member_index: std.HashMap(MemberKey, DefId, MemberKeyContext, std.hash_map.default_max_load_percentage) = undefined;

fn buildMemberIndex() !void {
    g_member_index = std.HashMap(MemberKey, DefId, MemberKeyContext, std.hash_map.default_max_load_percentage).init(g_arena);
    for (g_defs.items, 0..) |d, idx| {
        if (d.parent) |p| {
            try g_member_index.put(.{ .file = d.file, .parent = p, .name = d.name }, @intCast(idx));
        }
    }
}

fn markLive(def_id: DefId, work: *ArrayList(DefId)) !void {
    if (g_live[def_id]) return;
    g_live[def_id] = true;
    try work.append(g_arena, def_id);
}

fn propagate() !void {
    var work: ArrayList(DefId) = .{};

    // Seed: every strong use → resolve and mark live.
    for (g_uses.items) |u| {
        if (u.weak_owner != null) continue;
        try resolveAndMarkLive(u.in_file, u.chain, &work);
    }

    // Seed: exempt names + export fns are always live.
    for (g_defs.items, 0..) |d, idx| {
        if (d.is_export and d.kind == .function) {
            try markLive(@intCast(idx), &work);
        }
        if (d.kind == .function) {
            for (EXEMPT_FUNCTION_NAMES) |ex| {
                if (mem.eql(u8, d.name, ex)) {
                    try markLive(@intCast(idx), &work);
                }
            }
        }
    }

    // Field heuristic: fields/variants whose name appears anywhere as
    // `.<name>` are live.
    for (g_defs.items, 0..) |d, idx| {
        if (d.kind == .field or d.kind == .variant) {
            if (g_field_uses.contains(d.name)) {
                try markLive(@intCast(idx), &work);
            }
        }
    }

    // Method heuristic: methods (functions with a parent container) are
    // kept live if `.<name>` appears anywhere — same loose rule as fields.
    // Without real type resolution we can't tell `self.lock()` from
    // `unrelated.lock()`, but the Python tool has the same blind spot
    // (it greps the bare identifier and accepts the noise).
    for (g_defs.items, 0..) |d, idx| {
        if (d.kind == .function and d.parent != null) {
            if (g_field_uses.contains(d.name)) {
                try markLive(@intCast(idx), &work);
            }
        }
    }

    // Process worklist: when an alias becomes live, activate its weak uses.
    while (work.pop()) |def_id| {
        const d = g_defs.items[def_id];

        // If this def has weak uses on its RHS, activate them: any use
        // with weak_owner == def_id becomes a strong use now.
        if (d.alias_target) |tgt| {
            try resolveAndMarkLive(d.file, tgt, &work);
        }

        // Also: any use with weak_owner == def_id we've collected
        // separately (covers the case where a non-pure-alias `pub const X
        // = some.expr.using(others);` — but those have alias_target=null,
        // so they'd be flagged as strong from the start. So no extra
        // weak-list scan needed.)
    }
}

// -----------------------------------------------------------------
// Main
// -----------------------------------------------------------------

pub fn main() !void {
    g_arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer g_arena_state.deinit();
    g_arena = g_arena_state.allocator();

    var args = std.process.args();
    _ = args.next(); // exe
    const target_name: []const u8 = if (args.next()) |a| a else "kernel";

    // Repo root = parent of the directory containing this exe? No — we're
    // run from the repo root by convention. Use the grandparent of
    // tools/dead_code_zig/zig-out/bin via env var, or just CWD.
    var cwd_buf: [4096]u8 = undefined;
    const cwd = try std.fs.cwd().realpath(".", &cwd_buf);
    g_repo_root = try g_arena.dupe(u8, cwd);

    g_basename_index = StringHashMap(ArrayList(FileId)).init(g_arena);
    g_path_index = StringHashMap(FileId).init(g_arena);
    g_field_uses = StringHashMap(void).init(g_arena);

    // Walk all candidate top-level dirs.
    const target_rel = target_name;
    for (REPO_DIRS_TO_WALK) |sub| {
        const p = try joinPath(g_arena, &.{ g_repo_root, sub });
        var stat_dir = fs.openDirAbsolute(p, .{}) catch continue;
        stat_dir.close();
        try walkDir(g_arena, p, target_rel);
    }
    // Top-level *.zig files (e.g. build.zig at repo root)
    {
        var d = fs.openDirAbsolute(g_repo_root, .{ .iterate = true }) catch return error.NoRepoRoot;
        defer d.close();
        var it = d.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!mem.endsWith(u8, entry.name, ".zig")) continue;
            const abs = try joinPath(g_arena, &.{ g_repo_root, entry.name });
            const rel = relToRepo(abs);
            const rel_owned = try g_arena.dupe(u8, rel);
            const bn = try g_arena.dupe(u8, basenameNoExt(entry.name));
            const fid: FileId = @intCast(g_files.items.len);
            try g_files.append(g_arena, .{
                .path = abs,
                .rel_path = rel_owned,
                .basename = bn,
                .is_source = false,
            });
            const gop = try g_basename_index.getOrPut(bn);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            try gop.value_ptr.append(g_arena, fid);
            try g_path_index.put(abs, fid);
        }
    }

    // Count source files (target dir, non-tests) for the progress line.
    var src_count: u32 = 0;
    for (g_files.items) |fe| if (fe.is_source) {
        src_count += 1;
    };
    const stderr = std.fs.File.stderr();
    var nbuf: [256]u8 = undefined;
    const summary = try std.fmt.bufPrint(&nbuf, "Scanning {d} source files in {s}/ (with {d} repo files for refs)...\n", .{ src_count, target_name, g_files.items.len });
    _ = stderr.write(summary) catch {};

    // Pre-size scopes so file-id indexing is safe during parse.
    try g_file_scopes.resize(g_arena, g_files.items.len);
    for (0..g_files.items.len) |i| {
        g_file_scopes.items[i] = FileScope{ .decls = StringHashMap(DefId).init(g_arena), .any_decls = StringHashMap(ArrayList(DefId)).init(g_arena) };
    }

    // Pre-tokenize every file once and keep tokens around for both passes.
    var per_file_tokens = try g_arena.alloc([]Token, g_files.items.len);
    var per_file_src = try g_arena.alloc([:0]u8, g_files.items.len);
    var per_file_lines = try g_arena.alloc([]u32, g_files.items.len);

    for (g_files.items, 0..) |fe, i| {
        const src = readFileAlloc(g_arena, fe.path) catch {
            per_file_tokens[i] = &.{};
            per_file_src[i] = try g_arena.allocSentinel(u8, 0, 0);
            per_file_lines[i] = &.{};
            continue;
        };
        per_file_src[i] = src;
        per_file_lines[i] = try computeLineStarts(g_arena, src);
        var tk = Tokenizer.init(src);
        var list: ArrayList(Token) = .{};
        while (true) {
            const t = tk.next();
            try list.append(g_arena, t);
            if (t.tag == .eof) break;
        }
        per_file_tokens[i] = try list.toOwnedSlice(g_arena);
    }

    // Pass 1: parse decls + uses + alias edges.
    for (g_files.items, 0..) |_, i| {
        if (per_file_tokens[i].len == 0) continue;
        var ctx = ParseCtx{
            .a = g_arena,
            .file = @intCast(i),
            .src = per_file_src[i],
            .toks = per_file_tokens[i],
            .line_starts = per_file_lines[i],
        };
        try parseFile(&ctx);
    }

    // Pass 2: field/variant defs (needs container boundary tracking).
    for (g_files.items, 0..) |fe, i| {
        if (!fe.is_source) continue;
        if (per_file_tokens[i].len == 0) continue;
        var ctx = ParseCtx{
            .a = g_arena,
            .file = @intCast(i),
            .src = per_file_src[i],
            .toks = per_file_tokens[i],
            .line_starts = per_file_lines[i],
        };
        try collectFieldsAndVariants(&ctx);
    }

    // Pass 3: collect every `.<ident>` token across the whole repo.
    for (g_files.items, 0..) |_, i| {
        if (per_file_tokens[i].len == 0) continue;
        var ctx = ParseCtx{
            .a = g_arena,
            .file = @intCast(i),
            .src = per_file_src[i],
            .toks = per_file_tokens[i],
            .line_starts = per_file_lines[i],
        };
        try collectFieldUses(&ctx);
    }

    // Build member index for `Type.MEMBER` chain resolution.
    try buildMemberIndex();

    // Liveness.
    g_live = try g_arena.alloc(bool, g_defs.items.len);
    @memset(g_live, false);
    try propagate();

    // Report.
    const stdout = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = stdout.writer(&stdout_buf);
    const w = &stdout_writer.interface;

    // Group defs by file (only source-file defs).
    // We iterate g_files in order so output is stable.
    var unused_total: u32 = 0;
    for (g_files.items, 0..) |fe, fi| {
        if (!fe.is_source) continue;
        var first_for_file = true;
        for (g_defs.items, 0..) |d, di| {
            if (d.file != fi) continue;
            if (g_live[di]) continue;
            if (first_for_file) {
                try w.print("=== {s} ===\n", .{fe.rel_path});
                first_for_file = false;
            }
            // Match dead_code.py output: prefix parent only for FIELD /
            // VARIANT (Python does this implicitly because non-field defs
            // never carry a parent string).
            const show_parent = (d.kind == .field or d.kind == .variant) and d.parent != null;
            if (show_parent) {
                try w.print("  UNUSED {s}: {s}.{s} (line {d})\n", .{ d.kind.label(), d.parent.?, d.name, d.line });
            } else {
                try w.print("  UNUSED {s}: {s} (line {d})\n", .{ d.kind.label(), d.name, d.line });
            }
            unused_total += 1;
        }
        if (!first_for_file) try w.writeAll("\n");
    }

    if (unused_total == 0) {
        try w.writeAll("No unused code detected!\n");
    } else {
        try w.print("Total: {d} potentially unused items found.\n", .{unused_total});
        try w.writeAll("Review each item manually before removing \xE2\x80\x94 check for @field, @typeInfo, asm, and linker references.\n");
    }
    try w.flush();

    if (unused_total > 0) std.process.exit(1);
}
