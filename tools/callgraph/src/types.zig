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

pub const Graph = struct {
    functions: []Function,
    entry_points: []EntryPoint,
};
