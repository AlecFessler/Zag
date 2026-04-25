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

pub const Graph = struct {
    functions: []Function,
    entry_points: []EntryPoint,
};
