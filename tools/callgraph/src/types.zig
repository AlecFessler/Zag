const std = @import("std");

pub const FnId = u32;

pub const SourceLoc = struct {
    file: []const u8,
    line: u32,
    col: u32 = 0,
};

pub const EdgeKind = enum {
    direct,
    dispatch_x64,
    dispatch_aarch64,
    vtable,
    indirect,
    leaf_userspace,

    pub fn jsonStringify(self: EdgeKind, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

pub const EntryKind = enum {
    syscall,
    trap,
    irq,
    boot,
    manual,

    pub fn jsonStringify(self: EntryKind, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

pub const TargetArch = enum {
    x86_64,
    aarch64,

    pub fn jsonStringify(self: TargetArch, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

pub const IrFunction = struct {
    id: FnId,
    mangled: []const u8,
    def_loc: ?SourceLoc = null,
};

pub const IrEdge = struct {
    from: FnId,
    to: ?FnId,
    site: SourceLoc,
    indirect: bool,
};

pub const IrGraph = struct {
    functions: []IrFunction,
    edges: []IrEdge,
};

pub const Function = struct {
    id: FnId,
    name: []const u8,
    mangled: []const u8,
    def_loc: SourceLoc,
    /// Line of the function's closing brace, sourced from the AST walker.
    /// 0 when the join couldn't pin a matching AstFunction (rare — IR
    /// fns whose def_loc didn't match any AST record). Consumers should
    /// fall back to a heuristic when 0 (e.g. next-fn boundary).
    /// Used by the review classifier to bound hunk-to-fn overlap to the
    /// real body extent instead of the loose next-fn-boundary heuristic.
    body_line_end: u32 = 0,
    is_entry: bool = false,
    entry_kind: ?EntryKind = null,
    callees: []EnrichedEdge,
    intra: []const Atom = &.{},
    /// Whether this function is reachable from any discovered entry point
    /// via a forward walk over IR call edges. Indirect, vtable, and
    /// leaf_userspace edges are not traversed during the reach pass —
    /// indirect/vtable because the target is unknown post-monomorphization,
    /// leaf_userspace because it's a synthetic terminator. Defaults true so
    /// graphs without computed reachability render as before.
    reachable: bool = true,
    /// True when this Function was synthesized from an AST-only walk: the
    /// LLVM IR has no `define` for it because the compiler inlined every
    /// call site (typical for `pub inline fn` helpers). The intra tree is
    /// still useful for Trace mode — it lets the user drill from a caller's
    /// `Foo.kEntry()` atom into kEntry's own body. The frontend uses this
    /// flag to render a small visual marker so the user knows the box was
    /// reconstructed from source rather than IR.
    is_ast_only: bool = false,
    /// Definitions this function references, by DefId. Built by the
    /// def_deps pass: walks each fn's signature + body for identifiers
    /// and dotted chains, resolves them against the file's import table
    /// + the global def-qname index, and records every successful match.
    /// Used by the diff/review feature so a struct edit flags every fn
    /// that depends on it, not just fns whose own line range was edited.
    /// Empty when the pass hasn't run (e.g. older snapshots).
    def_deps: []const DefId = &.{},
    /// Number of distinct entry points (boot/syscall/trap/irq) that can
    /// transitively reach this function via the same edge rules
    /// `reachable` uses. Surfaces "load-bearing" hubs in `find` output:
    /// a helper called from one syscall vs reached from twenty look very
    /// different in blast radius. 0 when not computed.
    entry_reach: u32 = 0,
};

pub const EnrichedEdge = struct {
    to: ?FnId,
    target_name: ?[]const u8 = null,
    kind: EdgeKind,
    site: SourceLoc,
};

pub const EntryPoint = struct {
    fn_id: FnId,
    kind: EntryKind,
    label: []const u8,
};

/// One reference to a callee from inside a function. Uses the resolved IR
/// edge — so target/kind reflect the IR truth, not AST guessing.
pub const Callee = struct {
    to: ?FnId,
    name: []const u8,
    kind: EdgeKind,
    site: SourceLoc,
};

pub const BranchKind = enum {
    if_else,
    switch_,

    pub fn jsonStringify(self: BranchKind, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

pub const ArmSeq = struct {
    label: []const u8,
    seq: []const Atom,
};

pub const BranchAtom = struct {
    kind: BranchKind,
    loc: SourceLoc,
    arms: []const ArmSeq,
};

/// A `while` or `for` loop. The body is the (already-simplified) atom
/// sequence produced by walking the loop body inline. Trace mode renders
/// this with a ↻ glyph + a border so the user sees execution may iterate.
pub const LoopAtom = struct {
    loc: SourceLoc,
    body: []const Atom,
};

/// One element of a function's intra-procedural sequence. After the simplify
/// pass each Atom is a call, a branch whose arms differ as sequences, or a
/// loop wrapping its body.
pub const Atom = union(enum) {
    call: Callee,
    branch: BranchAtom,
    loop: LoopAtom,

    pub fn jsonStringify(self: Atom, jw: anytype) !void {
        try jw.beginObject();
        switch (self) {
            .call => |c| {
                try jw.objectField("call");
                try jw.write(c);
            },
            .branch => |b| {
                try jw.objectField("branch");
                try jw.write(b);
            },
            .loop => |l| {
                try jw.objectField("loop");
                try jw.write(l);
            },
        }
        try jw.endObject();
    }
};

pub const DefKind = enum {
    /// Plain `const X = ...` not matching another shape (literal, alias).
    constant,
    /// `const X = struct { ... }`.
    struct_,
    /// `const X = union(enum) { ... }` or `const X = union { ... }`.
    union_,
    /// `const X = enum { ... }`.
    enum_,
    /// `const X = opaque { ... }`.
    opaque_,
    /// Top-level `var X = ...` (mutable global).
    global_var,

    pub fn jsonStringify(self: DefKind, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

pub const DefId = u32;

/// A reviewable top-level declaration that isn't a function: struct/union/
/// enum/opaque type definitions, plain consts (`const FOO = 0x1234`), and
/// top-level vars. Functions live in `Function`; this is everything else.
///
/// Line bounds cover the FULL declaration extent — for `pub const Foo =
/// struct { ... };`, that's from the leading `pub` token through the
/// trailing `;`. The diff hunks endpoint uses these bounds to flag a
/// definition as changed when any hunk overlaps.
pub const Definition = struct {
    id: DefId,
    name: []const u8,
    /// Dotted qualified name in the same shape as Function.qualified_name:
    /// `<module>.<container_path>.<name>`. Used for cross-file resolution
    /// of `OtherFile.SomeType` references.
    qualified_name: []const u8,
    file: []const u8,
    line_start: u32,
    line_end: u32,
    kind: DefKind,
    is_pub: bool = false,
};

pub const Graph = struct {
    functions: []Function,
    entry_points: []EntryPoint,
    /// Top-level non-function declarations that can be flagged as
    /// "changed" when their source overlaps a diff hunk. Optional —
    /// older clients ignore it; the diff feature reads it for
    /// def-dep-aware change tracking. Empty array (not null) when
    /// the walker found none.
    definitions: []Definition = &.{},
};

/// One field of a struct, with its resolved type qname when knowable. Used
/// by the receiver-chain resolver to walk `self.field1.field2.method()`
/// expressions through the field type chain.
pub const FieldType = struct {
    field_name: []const u8,
    /// Qualified type name of the field, when resolvable. Pointer / optional /
    /// const decoration is stripped — just the bare type qname. Empty when
    /// unresolvable (e.g. comptime types, anonymous structs, generic params).
    type_qname: []const u8,
};

/// Per-struct field-type table. The receiver-chain resolver looks up the
/// enclosing receiver type, then walks each segment of `self.x.y.z.method()`
/// through these tables until the final segment is the method name.
pub const StructTypeInfo = struct {
    /// Qualified name of the struct (e.g. `proc.process.Process`). Matches
    /// the prefix that AstFunction.qualified_name uses for methods declared
    /// inside the struct.
    qname: []const u8,
    fields: []const FieldType,
};

/// One re-export alias entry: a top-level `pub const X = some.dotted.chain;`
/// decl whose RHS resolves through the file's import table. The key is the
/// alias's qname in *user* form (`<file_module>.<X>`, e.g. `utils.sync.SpinLock`)
/// and the value is the underlying qname the chain resolved to (e.g.
/// `utils.sync.spin_lock.SpinLock`). The qname index downstream is populated
/// from real fn-decl qnames, so a `lookupCandidate` against the user-form
/// qname misses; consulting this table rewrites the prefix and retries.
pub const ReexportAlias = struct {
    /// User-form qname (`<file_module>.<X>`).
    key: []const u8,
    /// Underlying-target qname (the chain's resolution).
    target: []const u8,
};

/// One entry per function parameter, in declaration order. Used by join.zig's
/// all-callers-agree pass: when an AST-only inline fn has a fn-pointer
/// parameter and every call site passes the same `&fn` argument, the
/// parameter call inside the body is rewritten as a direct call to that fn.
/// `is_fn_ptr` is a heuristic on the type source slice (`fn (` substring) —
/// precise typing would require the compiler.
pub const ParamInfo = struct {
    name: []const u8,
    is_fn_ptr: bool,
};
