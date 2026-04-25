// Per-function intra-procedural branch tree builder + simplifier.
//
// Walks a function's AST body, collects every call expression (preserving
// order), tracks the if/switch branch structure that wraps them, and runs a
// simplify pass that collapses any branch whose arms produce identical
// *sequences* of callees (same atoms, same order, recursively).
//
// Loops (`while`/`for`) emit a `Loop { body: []Atom }` wrapping their
// body's atoms — Trace mode renders the loop with a ↻ border so the user
// sees execution iterates. Graph mode reads the same body, just rendered
// linearly. `try` is just a Call (the implicit error-return path generates
// no callees).
//
// The output is a flat `[]types.Atom` slice: a sequence of `call`, `branch`,
// and `loop` records. Branches recursively nest through `arms[].seq` and
// loops through `body`. Arms keep the calls in source order; the simplify
// pass only removes branches, never reorders within a sequence.

const std = @import("std");

const types = @import("../types.zig");

const Atom = types.Atom;
const ArmSeq = types.ArmSeq;
const BranchAtom = types.BranchAtom;
const BranchKind = types.BranchKind;
const Callee = types.Callee;
const EdgeKind = types.EdgeKind;
const FnId = types.FnId;
const LoopAtom = types.LoopAtom;
const SourceLoc = types.SourceLoc;

pub const CallSiteMap = std.StringHashMap([]const Callee);

/// Hash key suitable for `CallSiteMap`. Caller owns the returned slice via
/// the same arena passed to buildIntra.
pub fn callSiteKey(arena: std.mem.Allocator, file: []const u8, line: u32) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}:{d}", .{ file, line });
}

/// Build the intra-function atom sequence for one fn_decl. `fn_node` is the
/// std.zig.Ast node index of the fn_decl. `callsites` is keyed by
/// `<file>:<line>` (use `callSiteKey`) and contains every IR-resolved
/// callee originating from this function.
pub fn buildIntra(
    arena: std.mem.Allocator,
    file: []const u8,
    fn_node: u32,
    ast: *const std.zig.Ast,
    callsites: CallSiteMap,
) ![]const Atom {
    const node_idx: std.zig.Ast.Node.Index = @enumFromInt(fn_node);

    // The body of a fn_decl is the second node in node_and_node.
    if (ast.nodeTag(node_idx) != .fn_decl) return &.{};
    const body_node = ast.nodeData(node_idx).node_and_node[1];

    var ctx = Ctx{
        .arena = arena,
        .ast = ast,
        .file = file,
        .callsites = callsites,
    };

    var seq = std.ArrayList(IrNode){};
    try walkExpr(&ctx, body_node, &seq);

    // Append every defer block we noted at function-end. defers are LIFO in
    // Zig — last-declared runs first — but for "set of callees" purposes the
    // order doesn't matter; we keep declaration order for readability.
    for (ctx.defers.items) |d| {
        try walkExpr(&ctx, d, &seq);
    }

    // Simplify in place.
    simplifySeq(arena, &seq);

    return try lowerSeq(arena, seq.items);
}

// ---------------------------------------------------------------------- IR

/// Internal builder node. We work with this tree first, run simplify on it,
/// then lower to types.Atom for JSON. Keeping the two distinct is cheap and
/// lets simplify mutate freely without worrying about JSON shape.
const IrNode = union(enum) {
    call: Callee,
    branch: BranchIr,
    loop: LoopIr,
};

const BranchIr = struct {
    kind: BranchKind,
    loc: SourceLoc,
    arms: []ArmIr,
};

const ArmIr = struct {
    label: []const u8,
    seq: std.ArrayList(IrNode),
};

const LoopIr = struct {
    loc: SourceLoc,
    body: std.ArrayList(IrNode),
};

const Ctx = struct {
    arena: std.mem.Allocator,
    ast: *const std.zig.Ast,
    file: []const u8,
    callsites: CallSiteMap,
    /// Defer / errdefer expression nodes accumulated at function scope.
    /// Walked at function-end so their calls show up in the sequence.
    defers: std.ArrayList(std.zig.Ast.Node.Index) = .{},
};

// ---------------------------------------------------------------------- walk

/// Walk an arbitrary expression / statement. Branch-shaped nodes (if,
/// switch) emit a Branch; call nodes emit a Call; loops inline their body;
/// everything else recurses into its child nodes via `forEachChild`.
fn walkExpr(
    ctx: *Ctx,
    node: std.zig.Ast.Node.Index,
    out: *std.ArrayList(IrNode),
) anyerror!void {
    const tag = ctx.ast.nodeTag(node);
    switch (tag) {
        .root => return,

        // Block — iterate statements.
        .block, .block_semicolon, .block_two, .block_two_semicolon => {
            var buf: [2]std.zig.Ast.Node.Index = undefined;
            const stmts = ctx.ast.blockStatements(&buf, node) orelse return;
            for (stmts) |s| try walkExpr(ctx, s, out);
        },

        // Calls.
        .call, .call_comma, .call_one, .call_one_comma => {
            try emitCall(ctx, node, out);
        },

        // Branches that we may or may not preserve (depends on simplify).
        .if_simple, .@"if" => {
            try emitIf(ctx, node, out);
        },
        .@"switch", .switch_comma => {
            try emitSwitch(ctx, node, out);
        },

        // Loops — emit a Loop { body: ... }. Calls in the cond/inputs run
        // before the loop decides whether to iterate, so they belong to the
        // enclosing sequence; the else arm runs when the loop completes
        // normally, also enclosing. The `cont_expr` runs each iteration so
        // it lives inside the body.
        .while_simple, .while_cont, .@"while" => {
            const w = ctx.ast.fullWhile(node).?;
            try walkExpr(ctx, w.ast.cond_expr, out);
            var body = std.ArrayList(IrNode){};
            try walkExpr(ctx, w.ast.then_expr, &body);
            if (w.ast.cont_expr.unwrap()) |c| try walkExpr(ctx, c, &body);
            const loc = ctx.ast.tokenLocation(0, w.ast.while_token);
            try out.append(ctx.arena, .{ .loop = .{
                .loc = .{
                    .file = ctx.file,
                    .line = @intCast(loc.line + 1),
                    .col = @intCast(loc.column + 1),
                },
                .body = body,
            } });
            if (w.ast.else_expr.unwrap()) |e| try walkExpr(ctx, e, out);
        },
        .for_simple, .@"for" => {
            const f = ctx.ast.fullFor(node).?;
            for (f.ast.inputs) |inp| try walkExpr(ctx, inp, out);
            var body = std.ArrayList(IrNode){};
            try walkExpr(ctx, f.ast.then_expr, &body);
            const loc = ctx.ast.tokenLocation(0, f.ast.for_token);
            try out.append(ctx.arena, .{ .loop = .{
                .loc = .{
                    .file = ctx.file,
                    .line = @intCast(loc.line + 1),
                    .col = @intCast(loc.column + 1),
                },
                .body = body,
            } });
            if (f.ast.else_expr.unwrap()) |e| try walkExpr(ctx, e, out);
        },

        // Defer / errdefer — run on scope exit. For v1 stash at function-end.
        .@"defer" => {
            const expr = ctx.ast.nodeData(node).node;
            try ctx.defers.append(ctx.arena, expr);
        },
        .@"errdefer" => {
            const expr = ctx.ast.nodeData(node).opt_token_and_node[1];
            try ctx.defers.append(ctx.arena, expr);
        },

        // Var decls — descend into init expression.
        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            const vd = ctx.ast.fullVarDecl(node) orelse return;
            if (vd.ast.init_node.unwrap()) |init_node| {
                try walkExpr(ctx, init_node, out);
            }
        },

        // Test/fn/proto decls — skip (handled elsewhere or n/a).
        .test_decl, .fn_decl, .fn_proto, .fn_proto_simple, .fn_proto_multi, .fn_proto_one => return,

        // For everything else (arbitrary expressions that may contain calls),
        // visit each child node generically.
        else => try forEachChild(ctx, node, out),
    }
}

/// Visit each direct-child Node.Index of `node`. We model the per-tag data
/// layout from std.zig.Ast (matching firstToken/lastToken's switch). For any
/// tag we don't recognize we fall through silently — at worst we miss a
/// nested call inside an exotic construct.
fn forEachChild(
    ctx: *Ctx,
    node: std.zig.Ast.Node.Index,
    out: *std.ArrayList(IrNode),
) anyerror!void {
    const tag = ctx.ast.nodeTag(node);
    const data = ctx.ast.nodeData(node);
    switch (tag) {
        // node-only.
        .bool_not, .negation, .bit_not, .negation_wrap, .address_of, .@"try",
        .optional_type, .@"suspend", .@"resume", .@"nosuspend", .@"comptime",
        .deref, .@"defer" => {
            try walkExpr(ctx, data.node, out);
        },

        // opt_node only.
        .@"return" => {
            if (data.opt_node.unwrap()) |c| try walkExpr(ctx, c, out);
        },

        // opt_token_and_opt_node — only the second child is a node ref.
        .@"break" => {
            if (data.opt_token_and_opt_node[1].unwrap()) |c| try walkExpr(ctx, c, out);
        },

        // node_and_node binary ops + a handful of others.
        .@"catch",
        .equal_equal, .bang_equal,
        .less_than, .greater_than, .less_or_equal, .greater_or_equal,
        .assign_mul, .assign_div, .assign_mod, .assign_add, .assign_sub,
        .assign_shl, .assign_shl_sat, .assign_shr,
        .assign_bit_and, .assign_bit_xor, .assign_bit_or,
        .assign_mul_wrap, .assign_add_wrap, .assign_sub_wrap,
        .assign_mul_sat, .assign_add_sat, .assign_sub_sat, .assign,
        .merge_error_sets,
        .mul, .div, .mod, .array_mult,
        .mul_wrap, .mul_sat, .add, .sub, .array_cat,
        .add_wrap, .sub_wrap, .add_sat, .sub_sat,
        .shl, .shl_sat, .shr,
        .bit_and, .bit_xor, .bit_or,
        .@"orelse", .bool_and, .bool_or,
        .slice_open, .array_access, .array_init_one, .array_init_one_comma,
        .switch_range, .error_union, .array_type => {
            try walkExpr(ctx, data.node_and_node[0], out);
            try walkExpr(ctx, data.node_and_node[1], out);
        },

        // node_and_opt_node — second child optional.
        .for_range, .struct_init_one, .struct_init_one_comma => {
            try walkExpr(ctx, data.node_and_opt_node[0], out);
            if (data.node_and_opt_node[1].unwrap()) |c| try walkExpr(ctx, c, out);
        },

        // node_and_token — only the first is a node.
        .field_access, .unwrap_optional, .grouped_expression => {
            try walkExpr(ctx, data.node_and_token[0], out);
        },

        // node_and_extra: the `extra` is a SubRange or Slice/SliceSentinel/etc.
        .slice => {
            const sliced, const extra = data.node_and_extra;
            try walkExpr(ctx, sliced, out);
            const s = ctx.ast.extraData(extra, std.zig.Ast.Node.Slice);
            try walkExpr(ctx, s.start, out);
            try walkExpr(ctx, s.end, out);
        },
        .slice_sentinel => {
            const sliced, const extra = data.node_and_extra;
            try walkExpr(ctx, sliced, out);
            const s = ctx.ast.extraData(extra, std.zig.Ast.Node.SliceSentinel);
            try walkExpr(ctx, s.start, out);
            if (s.end.unwrap()) |e| try walkExpr(ctx, e, out);
            try walkExpr(ctx, s.sentinel, out);
        },
        .array_init, .array_init_comma, .struct_init, .struct_init_comma => {
            const ty, const extra = data.node_and_extra;
            try walkExpr(ctx, ty, out);
            const sub = ctx.ast.extraData(extra, std.zig.Ast.Node.SubRange);
            const slice = ctx.ast.extraDataSlice(sub, std.zig.Ast.Node.Index);
            for (slice) |c| try walkExpr(ctx, c, out);
        },
        // .call/.call_comma/.call_one/.call_one_comma handled by walkExpr.

        // opt_node_and_node.
        .switch_case_one, .switch_case_inline_one => {
            // values[0] (optional) + target_expr. Children here are normally
            // walked by emitSwitch; if we land here directly, recurse.
            const v, const target = data.opt_node_and_node;
            if (v.unwrap()) |x| try walkExpr(ctx, x, out);
            try walkExpr(ctx, target, out);
        },

        // extra_and_node (e.g., switch_case, switch_case_inline).
        .switch_case, .switch_case_inline => {
            const extra, const target = data.extra_and_node;
            const sub = ctx.ast.extraData(extra, std.zig.Ast.Node.SubRange);
            const slice = ctx.ast.extraDataSlice(sub, std.zig.Ast.Node.Index);
            for (slice) |c| try walkExpr(ctx, c, out);
            try walkExpr(ctx, target, out);
        },

        // Builtin calls — recurse into params for nested user calls.
        .builtin_call_two, .builtin_call_two_comma => {
            const a, const b = data.opt_node_and_opt_node;
            if (a.unwrap()) |x| try walkExpr(ctx, x, out);
            if (b.unwrap()) |x| try walkExpr(ctx, x, out);
        },
        .builtin_call, .builtin_call_comma => {
            const slice = ctx.ast.extraDataSlice(data.extra_range, std.zig.Ast.Node.Index);
            for (slice) |c| try walkExpr(ctx, c, out);
        },

        // Container init dot forms.
        .array_init_dot_two, .array_init_dot_two_comma,
        .struct_init_dot_two, .struct_init_dot_two_comma => {
            const a, const b = data.opt_node_and_opt_node;
            if (a.unwrap()) |x| try walkExpr(ctx, x, out);
            if (b.unwrap()) |x| try walkExpr(ctx, x, out);
        },
        .array_init_dot, .array_init_dot_comma,
        .struct_init_dot, .struct_init_dot_comma => {
            const slice = ctx.ast.extraDataSlice(data.extra_range, std.zig.Ast.Node.Index);
            for (slice) |c| try walkExpr(ctx, c, out);
        },

        // Leaves we don't descend into.
        .identifier, .string_literal, .multiline_string_literal, .number_literal,
        .char_literal, .unreachable_literal, .anyframe_literal, .error_set_decl,
        .enum_literal, .error_value, .asm_simple, .@"asm", .asm_legacy,
        .asm_input, .asm_output,
        .ptr_type_aligned, .ptr_type_sentinel, .ptr_type, .ptr_type_bit_range,
        .anyframe_type, .array_type_sentinel,
        .container_field_init, .container_field_align, .container_field,
        .container_decl, .container_decl_trailing, .container_decl_two,
        .container_decl_two_trailing, .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union, .tagged_union_trailing, .tagged_union_two,
        .tagged_union_two_trailing, .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        .@"continue" => return,

        // assign_destructure — extra_and_node.
        .assign_destructure => {
            _, const init_node = data.extra_and_node;
            try walkExpr(ctx, init_node, out);
        },

        else => return,
    }
}

fn emitCall(
    ctx: *Ctx,
    node: std.zig.Ast.Node.Index,
    out: *std.ArrayList(IrNode),
) !void {
    var buf: [1]std.zig.Ast.Node.Index = undefined;
    const call = ctx.ast.fullCall(&buf, node) orelse return;

    // Recurse into the callee expression and arg list first so nested calls
    // inside argument expressions show up before the outer call.
    try walkExpr(ctx, call.ast.fn_expr, out);
    for (call.ast.params) |p| try walkExpr(ctx, p, out);

    // Locate this call's source position. Use the first token of the
    // fn_expr — that's where Zig emits the !DILocation column for the call.
    const first_tok = ctx.ast.firstToken(call.ast.fn_expr);
    const loc = ctx.ast.tokenLocation(0, first_tok);
    const line: u32 = @intCast(loc.line + 1);
    const col: u32 = @intCast(loc.column + 1); // 1-based to match LLVM.

    const key = try callSiteKey(ctx.arena, ctx.file, line);
    const candidates_opt = ctx.callsites.get(key);

    if (candidates_opt) |candidates| {
        // Prefer column match. If multiple Callees share line, pick the one
        // whose col is closest to ours.
        var best: ?Callee = null;
        var best_dist: u32 = std.math.maxInt(u32);
        for (candidates) |c| {
            const cc: u32 = c.site.col;
            const d: u32 = if (cc > col) cc - col else col - cc;
            if (d < best_dist) {
                best_dist = d;
                best = c;
            }
        }
        if (best) |c| {
            try out.append(ctx.arena, .{ .call = c });
            return;
        }
    }

    // Synthetic fallback so the source position is still visible.
    const callee_name = try sliceTokenSource(ctx, first_tok);
    try out.append(ctx.arena, .{ .call = .{
        .to = null,
        .name = callee_name,
        .kind = .indirect,
        .site = .{ .file = ctx.file, .line = line, .col = col },
    } });
}

fn emitIf(
    ctx: *Ctx,
    node: std.zig.Ast.Node.Index,
    out: *std.ArrayList(IrNode),
) !void {
    const ifn = ctx.ast.fullIf(node) orelse return;

    // Calls inside the condition itself are part of the *enclosing* sequence
    // (they happen before the branch decides which arm runs).
    try walkExpr(ctx, ifn.ast.cond_expr, out);

    var arms = std.ArrayList(ArmIr){};

    // Then arm.
    var then_seq = std.ArrayList(IrNode){};
    try walkExpr(ctx, ifn.ast.then_expr, &then_seq);
    const cond_label = try makeIfLabel(ctx, ifn.ast.cond_expr, "if");
    try arms.append(ctx.arena, .{ .label = cond_label, .seq = then_seq });

    // Else arm — may be another if (else if), in which case we keep
    // descending so the chain reads as a flat list of arms.
    if (ifn.ast.else_expr.unwrap()) |else_node| {
        try collectElseIfChain(ctx, else_node, &arms);
    }

    const if_tok = ifn.ast.if_token;
    const loc = ctx.ast.tokenLocation(0, if_tok);
    const branch = BranchIr{
        .kind = .if_else,
        .loc = .{
            .file = ctx.file,
            .line = @intCast(loc.line + 1),
            .col = @intCast(loc.column + 1),
        },
        .arms = try arms.toOwnedSlice(ctx.arena),
    };
    try out.append(ctx.arena, .{ .branch = branch });
}

fn collectElseIfChain(
    ctx: *Ctx,
    node: std.zig.Ast.Node.Index,
    arms: *std.ArrayList(ArmIr),
) anyerror!void {
    const tag = ctx.ast.nodeTag(node);
    if (tag == .if_simple or tag == .@"if") {
        const ifn = ctx.ast.fullIf(node).?;
        var arm_seq = std.ArrayList(IrNode){};
        try walkExpr(ctx, ifn.ast.cond_expr, &arm_seq);
        try walkExpr(ctx, ifn.ast.then_expr, &arm_seq);
        const label = try makeIfLabel(ctx, ifn.ast.cond_expr, "else if");
        try arms.append(ctx.arena, .{ .label = label, .seq = arm_seq });
        if (ifn.ast.else_expr.unwrap()) |next| {
            try collectElseIfChain(ctx, next, arms);
        }
        return;
    }
    var seq = std.ArrayList(IrNode){};
    try walkExpr(ctx, node, &seq);
    try arms.append(ctx.arena, .{ .label = try ctx.arena.dupe(u8, "else"), .seq = seq });
}

fn emitSwitch(
    ctx: *Ctx,
    node: std.zig.Ast.Node.Index,
    out: *std.ArrayList(IrNode),
) !void {
    const sw = ctx.ast.fullSwitch(node) orelse return;

    try walkExpr(ctx, sw.ast.condition, out);

    var arms = std.ArrayList(ArmIr){};
    for (sw.ast.cases) |case_node| {
        const case = ctx.ast.fullSwitchCase(case_node) orelse continue;
        var seq = std.ArrayList(IrNode){};
        try walkExpr(ctx, case.ast.target_expr, &seq);

        const label = try makeSwitchArmLabel(ctx, case);
        try arms.append(ctx.arena, .{ .label = label, .seq = seq });
    }

    const sw_tok = sw.ast.switch_token;
    const loc = ctx.ast.tokenLocation(0, sw_tok);
    const branch = BranchIr{
        .kind = .switch_,
        .loc = .{
            .file = ctx.file,
            .line = @intCast(loc.line + 1),
            .col = @intCast(loc.column + 1),
        },
        .arms = try arms.toOwnedSlice(ctx.arena),
    };
    try out.append(ctx.arena, .{ .branch = branch });
}

// ---------------------------------------------------------------- labels

fn makeIfLabel(
    ctx: *Ctx,
    cond_expr: std.zig.Ast.Node.Index,
    prefix: []const u8,
) ![]const u8 {
    const cond_src = nodeSource(ctx, cond_expr);
    const oneline = try toOneLine(ctx.arena, cond_src);
    const trimmed = truncate(oneline, 40);
    return std.fmt.allocPrint(ctx.arena, "{s} ({s})", .{ prefix, trimmed });
}

fn makeSwitchArmLabel(ctx: *Ctx, case: std.zig.Ast.full.SwitchCase) ![]const u8 {
    if (case.ast.values.len == 0) {
        return try ctx.arena.dupe(u8, "else");
    }
    var pieces = std.ArrayList(u8){};
    for (case.ast.values, 0..) |v, i| {
        if (i > 0) try pieces.appendSlice(ctx.arena, ", ");
        try pieces.appendSlice(ctx.arena, nodeSource(ctx, v));
    }
    const oneline = try toOneLine(ctx.arena, pieces.items);
    const trimmed = truncate(oneline, 40);
    return ctx.arena.dupe(u8, trimmed);
}

fn nodeSource(ctx: *Ctx, node: std.zig.Ast.Node.Index) []const u8 {
    const first = ctx.ast.firstToken(node);
    const last = ctx.ast.lastToken(node);
    const start = ctx.ast.tokenStart(first);
    const last_start = ctx.ast.tokenStart(last);
    const last_slice = ctx.ast.tokenSlice(last);
    const end: usize = @as(usize, last_start) + last_slice.len;
    if (end <= start or end > ctx.ast.source.len) return "";
    return ctx.ast.source[start..end];
}

fn sliceTokenSource(ctx: *Ctx, tok: std.zig.Ast.TokenIndex) ![]const u8 {
    const s = ctx.ast.tokenSlice(tok);
    return try ctx.arena.dupe(u8, s);
}

fn truncate(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    return s[0..max];
}

/// Replace all whitespace runs with a single space and trim. Useful for
/// rendering multi-line conditions on a single arm-label row.
fn toOneLine(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    var buf = try arena.alloc(u8, s.len);
    var w: usize = 0;
    var prev_ws = true;
    for (s) |c| {
        const is_ws = c == ' ' or c == '\t' or c == '\n' or c == '\r';
        if (is_ws) {
            if (!prev_ws and w < buf.len) {
                buf[w] = ' ';
                w += 1;
            }
            prev_ws = true;
        } else {
            buf[w] = c;
            w += 1;
            prev_ws = false;
        }
    }
    while (w > 0 and buf[w - 1] == ' ') w -= 1;
    return buf[0..w];
}

// ---------------------------------------------------------------- simplify

/// Recursively simplify a sequence of IrNode in place.
///
/// Branch handling (changed Apr 2026):
///   1) recurse into each arm's seq + each loop's body.
///   2) compare arms as ordered sequences (seqEqualIr).
///   3) if all arms are pairwise sequence-equal, replace the branch with
///      one arm's contents (the longest arm — it has the most context for
///      rendering).
///
/// The old rule compared callee *sets*, which dropped execution-order
/// information that Trace mode needs (and that Graph mode is now slightly
/// more accurate for too). The new sequence-equality rule keeps any branch
/// whose arms differ in *what runs in what order*, even when the union of
/// callees is identical.
fn simplifySeq(arena: std.mem.Allocator, seq: *std.ArrayList(IrNode)) void {
    var i: usize = 0;
    while (i < seq.items.len) {
        switch (seq.items[i]) {
            .call => i += 1,
            .loop => {
                simplifySeq(arena, &seq.items[i].loop.body);
                i += 1;
            },
            .branch => {
                for (seq.items[i].branch.arms) |*arm| {
                    simplifySeq(arena, &arm.seq);
                }
                if (allArmsSameSequence(seq.items[i].branch.arms)) {
                    const arms = seq.items[i].branch.arms;
                    var pick: usize = 0;
                    for (arms, 0..) |a, j| {
                        if (a.seq.items.len > arms[pick].seq.items.len) pick = j;
                    }
                    const replacement = arms[pick].seq.items;
                    _ = seq.orderedRemove(i);
                    var k: usize = replacement.len;
                    while (k > 0) {
                        k -= 1;
                        seq.insert(arena, i, replacement[k]) catch return;
                    }
                    // Don't advance i — the spliced-in head may itself be
                    // a branch that now collapses against its successors.
                } else {
                    i += 1;
                }
            },
        }
    }
}

fn allArmsSameSequence(arms: []ArmIr) bool {
    if (arms.len <= 1) return true;
    const ref = arms[0].seq.items;
    var i: usize = 1;
    while (i < arms.len) : (i += 1) {
        if (!seqEqualIr(ref, arms[i].seq.items)) return false;
    }
    return true;
}

/// Structural sequence equality for IrNode lists. Calls compare by `to+kind`
/// (or by name+kind when `to` is null). Branches compare arm-by-arm
/// (labels ignored, arm order significant). Loops compare by body sequence.
fn seqEqualIr(a: []const IrNode, b: []const IrNode) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (!nodeEqualIr(a[i], b[i])) return false;
    }
    return true;
}

fn nodeEqualIr(a: IrNode, b: IrNode) bool {
    switch (a) {
        .call => |ac| switch (b) {
            .call => |bc| return calleeEqual(ac, bc),
            else => return false,
        },
        .branch => |ab| switch (b) {
            .branch => |bb| {
                if (ab.kind != bb.kind) return false;
                if (ab.arms.len != bb.arms.len) return false;
                var i: usize = 0;
                while (i < ab.arms.len) : (i += 1) {
                    if (!seqEqualIr(ab.arms[i].seq.items, bb.arms[i].seq.items)) return false;
                }
                return true;
            },
            else => return false,
        },
        .loop => |al| switch (b) {
            .loop => |bl| return seqEqualIr(al.body.items, bl.body.items),
            else => return false,
        },
    }
}

fn calleeEqual(a: Callee, b: Callee) bool {
    if (a.kind != b.kind) return false;
    if (a.to != null and b.to != null) return a.to.? == b.to.?;
    if (a.to == null and b.to == null) return std.mem.eql(u8, a.name, b.name);
    return false;
}

// ---------------------------------------------------------------- lower

fn lowerSeq(arena: std.mem.Allocator, ir: []const IrNode) anyerror![]const Atom {
    var out = try arena.alloc(Atom, ir.len);
    for (ir, 0..) |n, i| {
        out[i] = try lowerNode(arena, n);
    }
    return out;
}

fn lowerNode(arena: std.mem.Allocator, n: IrNode) anyerror!Atom {
    return switch (n) {
        .call => |c| .{ .call = c },
        .branch => |b| .{ .branch = .{
            .kind = b.kind,
            .loc = b.loc,
            .arms = try lowerArms(arena, b.arms),
        } },
        .loop => |l| .{ .loop = .{
            .loc = l.loc,
            .body = try lowerSeq(arena, l.body.items),
        } },
    };
}

fn lowerArms(arena: std.mem.Allocator, arms: []ArmIr) anyerror![]const ArmSeq {
    var out = try arena.alloc(ArmSeq, arms.len);
    for (arms, 0..) |a, i| {
        out[i] = .{
            .label = a.label,
            .seq = try lowerSeq(arena, a.seq.items),
        };
    }
    return out;
}
