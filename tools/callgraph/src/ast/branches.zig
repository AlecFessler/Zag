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
//
// Comptime arch pruning (Apr 2026): `switch (builtin.cpu.arch)` and
// `if (builtin.cpu.arch == .X)` resolve at compile time, so the IR only
// emits one arm. The walker now mirrors that: the matched arm's body is
// spliced inline, the others are dropped. This kills the noise where the
// AST showed `? indirect: x64.foo` calls that the IR couldn't prove direct
// because they were comptime-eliminated for the build's selected arch.
//
// Module-qualified call resolution (Apr 2026): when an `Foo.bar(...)` call
// has no IR-resolved match at its site, we look up `Foo` in the file's
// import table to build a candidate qname `<imports[Foo]>.bar`. If that
// candidate hits the global qname index, we emit a resolved Callee. This
// catches calls in the comptime-eliminated arch arm whose targets exist
// elsewhere in the AST, plus generic `pmm.alloc` / `arch.foo` patterns
// that previously fell through to `? indirect`.

const std = @import("std");

const walker = @import("walker.zig");
const types = @import("../types.zig");

const Atom = types.Atom;
const ArmSeq = types.ArmSeq;
const BranchAtom = types.BranchAtom;
const BranchKind = types.BranchKind;
const Callee = types.Callee;
const EdgeKind = types.EdgeKind;
const FnId = types.FnId;
const ImportTable = walker.ImportTable;
const LoopAtom = types.LoopAtom;
const SourceLoc = types.SourceLoc;
const TargetArch = types.TargetArch;

pub const CallSiteMap = std.StringHashMap([]const Callee);

/// Global qualified-name → function-id index. Populated by join.zig from the
/// IR-joined functions list. Used to turn `Foo.bar(...)` calls into resolved
/// Callees with a navigable `to` target. The companion KnownNames set covers
/// names that exist in the AST but not the IR (inline / comptime fns that
/// the LLVM IR no longer carries) — a hit there resolves to a named direct
/// call with `to=null`, which is still much better than the indirect synth
/// fallback.
pub const QNameIndex = std.StringHashMap(types.FnId);
pub const KnownNames = std.StringHashMap(void);

/// Hash key suitable for `CallSiteMap`. Caller owns the returned slice via
/// the same arena passed to buildIntra.
pub fn callSiteKey(arena: std.mem.Allocator, file: []const u8, line: u32) ![]const u8 {
    return std.fmt.allocPrint(arena, "{s}:{d}", .{ file, line });
}

/// Build the intra-function atom sequence for one fn_decl. `fn_node` is the
/// std.zig.Ast node index of the fn_decl. `callsites` is keyed by
/// `<file>:<line>` (use `callSiteKey`) and contains every IR-resolved
/// callee originating from this function.
///
/// `imports` and `qname_index` are optional. When supplied, the walker uses
/// them to resolve module-qualified call expressions (`Foo.bar()`) by
/// looking up `Foo` in the file's import table and then qualifying against
/// the global qname index. They also enable comptime arch-pruning of
/// `switch (builtin.cpu.arch)` and `if (builtin.cpu.arch == .X)` constructs
/// — without the imports we fall back to a source-text heuristic.
///
/// `receiver_name` / `receiver_type` are the enclosing function's first-param
/// binding name and its resolved struct qname (when the param has a
/// receiver-shaped type). Empty strings disable receiver-method resolution
/// for this function.
pub fn buildIntra(
    arena: std.mem.Allocator,
    file: []const u8,
    fn_node: u32,
    ast: *const std.zig.Ast,
    callsites: CallSiteMap,
    target_arch: types.TargetArch,
    imports: ?*const ImportTable,
    qname_index: ?*const QNameIndex,
    known_names: ?*const KnownNames,
    receiver_name: []const u8,
    receiver_type: []const u8,
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
        .target_arch = target_arch,
        .imports = imports,
        .qname_index = qname_index,
        .known_names = known_names,
        .receiver_name = receiver_name,
        .receiver_type = receiver_type,
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
    target_arch: TargetArch,
    /// Per-file local-binding → resolved-module-path table. Used by emitCall
    /// to resolve `Foo.bar()` chains and by emitSwitch / emitIf to detect
    /// `builtin.cpu.arch` dispatch sites. Optional; when null, emit falls
    /// back to source-text matching for the arch detect and skips the
    /// module-qualified call resolution entirely.
    imports: ?*const ImportTable,
    /// Global qualified-name → fn-id map for cross-module call resolution.
    /// Optional for the same reason as `imports`.
    qname_index: ?*const QNameIndex,
    /// Known qualified names (set). Catches AST-only names (inline / comptime
    /// fns missing from the IR). On hit we still produce a named direct
    /// Callee, just with `to=null`.
    known_names: ?*const KnownNames,
    /// Local binding name of the enclosing function's first parameter when it
    /// has a receiver-shaped type (e.g. `self`, `this`, `lock`). Empty when
    /// the function has no receiver — in that case `<name>.method()` calls
    /// fall through to indirect.
    receiver_name: []const u8,
    /// Qualified type name for `receiver_name`. E.g. `utils.sync.SpinLock` for
    /// `self: *SpinLock` declared inside `const SpinLock = struct {...}`.
    /// Combined with the called method name to form a qname-index lookup
    /// candidate (`<receiver_type>.<method>`).
    receiver_type: []const u8,
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
            // Prefer a direct IR resolution. If the IR is indirect at this
            // site, fall through to the AST import resolver — many indirect
            // edges are inline-eliminated calls whose targets we can recover
            // from the import table.
            if (c.kind != .indirect) {
                try out.append(ctx.arena, .{ .call = c });
                return;
            }
        }
    }

    // No direct IR match. Try AST-side import resolution: when the call
    // target is `Foo.bar(...)` and `Foo` is in the file's import table, we
    // can build a global-qname candidate `<imports[Foo]>.bar` and resolve
    // against the qname index. This catches calls the IR omitted because
    // they were inlined or comptime-eliminated for the build's selected arch.
    if (try resolveByImports(ctx, call.ast.fn_expr, line, col)) |resolved| {
        try out.append(ctx.arena, .{ .call = resolved });
        return;
    }

    // Receiver-method resolution: when the call expression is
    // `<binding>.method(...)` and `<binding>` matches the enclosing fn's
    // first-param binding name, build `<receiver_type>.method` and look it
    // up in the qname index. Resolves the bulk of `self.foo()` /
    // `lock.lock()` / `slab.alloc()` patterns the IR drops via inlining.
    //
    // Patterns intentionally NOT handled (kept as ? indirect for now):
    //   * `arr[0].method()` — receiver is an indexed expression.
    //   * `(expr).method()` — parenthesized receiver.
    //   * `func().method()` — call-result receiver.
    //   * Local-variable receivers (`var x = makeFoo(); x.method();`).
    //   * Optional/error-union peels (`if (x) |y| y.method();`).
    if (try resolveByReceiver(ctx, call.ast.fn_expr, line, col)) |resolved| {
        try out.append(ctx.arena, .{ .call = resolved });
        return;
    }

    // Last-resort: use the IR's indirect record if there was one — at least
    // it preserves the `to=null` site and any name the IR side filled in.
    if (candidates_opt) |candidates| {
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

/// Module-qualified call resolver. Pulls the leftmost identifier of a
/// `Foo.bar(...)` chain, looks it up in the file's import table, builds a
/// `<imported_module>.<rest>` qname candidate, and asks the global qname
/// index for a fn id. Returns null on any miss; the caller will fall back to
/// the indirect synthesis path.
fn resolveByImports(
    ctx: *Ctx,
    fn_expr: std.zig.Ast.Node.Index,
    line: u32,
    col: u32,
) !?Callee {
    const imports = ctx.imports orelse return null;

    const tag = ctx.ast.nodeTag(fn_expr);

    // Bare identifier call: `bareFn(...)`. The call may be a top-level fn
    // declared in this same file (in which case `<file_module>.bareFn` hits
    // the qname index) or a re-export bound to another module (in which case
    // the import table maps `bareFn` directly to its resolved module path).
    // Both lookups are cheap; try them in that order.
    if (tag == .identifier) {
        const ident = nodeSource(ctx, fn_expr);
        if (ident.len == 0) return null;
        // 1) Same-file top-level fn (dotted module path + ident).
        const file_mod = try fileToDottedModule(ctx.arena, ctx.file);
        if (file_mod.len > 0) {
            const same_file_cand = try std.fmt.allocPrint(
                ctx.arena,
                "{s}.{s}",
                .{ file_mod, ident },
            );
            if (try lookupCandidate(ctx, same_file_cand, line, col)) |c| return c;
        }
        // 2) Re-exported via the import table (`const X = some.module.X;`).
        if (imports.get(ident)) |resolved| {
            // resolved here is a module-path-style string already pointing at
            // the target. Try the bare resolved string as the candidate.
            if (try lookupCandidate(ctx, resolved, line, col)) |c| return c;
        }
        return null;
    }

    if (tag != .field_access) return null;

    const chain = chainSource(ctx, fn_expr) orelse return null;
    const dot = std.mem.indexOfScalar(u8, chain, '.') orelse return null;
    const head = chain[0..dot];
    const tail = chain[dot + 1 ..];
    if (tail.len == 0) return null;

    const resolved_head = imports.get(head) orelse return null;

    // Special case: walker.zig strips `/usr/lib/zig/std/` from stdlib paths,
    // so `std.fmt.X` lives in the qname index as `fmt.X` (not `std.fmt.X`).
    // When the head resolves to "std", try the stdlib-form first.
    if (std.mem.eql(u8, resolved_head, "std")) {
        if (try lookupCandidate(ctx, tail, line, col)) |c| return c;
    }

    const candidate = try std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ resolved_head, tail });
    return try lookupCandidate(ctx, candidate, line, col);
}

/// Receiver-method resolver. Pulls a `<binding>.method(...)` chain and, if
/// `<binding>` matches the enclosing function's recorded receiver binding
/// name, builds `<receiver_type>.method` and looks it up in the qname index.
/// Returns null when the call isn't shaped that way, when there's no
/// receiver binding for this fn, or when the candidate doesn't hit the
/// index.
fn resolveByReceiver(
    ctx: *Ctx,
    fn_expr: std.zig.Ast.Node.Index,
    line: u32,
    col: u32,
) !?Callee {
    if (ctx.receiver_name.len == 0) return null;
    if (ctx.receiver_type.len == 0) return null;

    const tag = ctx.ast.nodeTag(fn_expr);
    if (tag != .field_access) return null;

    const chain = chainSource(ctx, fn_expr) orelse return null;
    const dot = std.mem.indexOfScalar(u8, chain, '.') orelse return null;
    const head = chain[0..dot];
    const tail = chain[dot + 1 ..];
    if (tail.len == 0) return null;

    if (!std.mem.eql(u8, head, ctx.receiver_name)) return null;

    // `tail` may itself be a chain (`self.field.method()`) — we only resolve
    // the simple `<receiver>.<method>` form. Multi-step field chains require
    // tracking field types, which is out of scope for v1.
    if (std.mem.indexOfScalar(u8, tail, '.') != null) return null;

    const candidate = try std.fmt.allocPrint(
        ctx.arena,
        "{s}.{s}",
        .{ ctx.receiver_type, tail },
    );
    return try lookupCandidate(ctx, candidate, line, col);
}

/// Look `candidate` up in the qname index (preferred — gives us a `to` id)
/// then in the known-names set (fallback — name only, `to=null`). Returns
/// null on miss in both.
fn lookupCandidate(
    ctx: *Ctx,
    candidate: []const u8,
    line: u32,
    col: u32,
) !?Callee {
    if (ctx.qname_index) |qi| {
        if (qi.get(candidate)) |fn_id| {
            return Callee{
                .to = fn_id,
                .name = try ctx.arena.dupe(u8, candidate),
                .kind = .direct,
                .site = .{ .file = ctx.file, .line = line, .col = col },
            };
        }
    }
    if (ctx.known_names) |kn| {
        if (kn.contains(candidate)) {
            return Callee{
                .to = null,
                .name = try ctx.arena.dupe(u8, candidate),
                .kind = .direct,
                .site = .{ .file = ctx.file, .line = line, .col = col },
            };
        }
    }
    return null;
}

fn emitIf(
    ctx: *Ctx,
    node: std.zig.Ast.Node.Index,
    out: *std.ArrayList(IrNode),
) !void {
    const ifn = ctx.ast.fullIf(node) orelse return;

    // Comptime arch pruning: `if (builtin.cpu.arch == .x86_64) {…} else {…}`
    // and the equivalent `!=` form. v1 only handles the direct `==` / `!=`
    // form against a single arch tag; chained `or` (`.aarch64 or .arm`) is
    // not detected.
    if (classifyBuiltinCpuArchIf(ctx, ifn.ast.cond_expr)) |branch_match| {
        const take_then = switch (branch_match.op) {
            .eq => branch_match.arch == ctx.target_arch,
            .neq => branch_match.arch != ctx.target_arch,
        };
        if (take_then) {
            try walkExpr(ctx, ifn.ast.then_expr, out);
        } else if (ifn.ast.else_expr.unwrap()) |else_node| {
            try walkExpr(ctx, else_node, out);
        }
        return;
    }

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

    // Comptime arch pruning: if the scrutinee is `builtin.cpu.arch`, we can
    // pick exactly one arm — the one whose value matches target_arch — and
    // splice its body into `out` as if it were the only path.
    if (isBuiltinCpuArchScrutinee(ctx, sw.ast.condition)) {
        const arch_tag = archTagFor(ctx.target_arch);
        var matched_case: ?std.zig.Ast.Node.Index = null;
        var has_explicit_match = false;
        var else_case: ?std.zig.Ast.Node.Index = null;

        for (sw.ast.cases) |case_node| {
            const case = ctx.ast.fullSwitchCase(case_node) orelse continue;
            if (case.ast.values.len == 0) {
                else_case = case_node;
                continue;
            }
            for (case.ast.values) |v| {
                if (caseValueMatchesTag(ctx, v, arch_tag)) {
                    matched_case = case_node;
                    has_explicit_match = true;
                    break;
                }
            }
            if (has_explicit_match) break;
        }

        const chosen = matched_case orelse else_case;
        if (chosen) |case_node| {
            const case = ctx.ast.fullSwitchCase(case_node).?;
            try walkExpr(ctx, case.ast.target_expr, out);
            return;
        }
        // No matching arm and no else — fall through to the normal path
        // (rare; conservatively keep the switch so calls aren't dropped).
    }

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

// -------------------------------------------------------------- arch prune

/// Test whether `node` is the source-level expression `builtin.cpu.arch`.
/// We trust the file's import table when available — `head.cpu.arch` is the
/// dispatch site iff `imports[head] == "builtin"`. When the table isn't
/// available (callers that don't supply imports) we fall back to a literal
/// source-text match, since the kernel uses exactly the spelling
/// `builtin.cpu.arch` everywhere.
fn isBuiltinCpuArchScrutinee(ctx: *Ctx, node: std.zig.Ast.Node.Index) bool {
    const src = chainSource(ctx, node) orelse return false;
    if (!std.mem.endsWith(u8, src, "cpu.arch")) return false;

    if (ctx.imports) |imports| {
        const dot1 = std.mem.indexOfScalar(u8, src, '.') orelse return false;
        const head = src[0..dot1];
        const resolved = imports.get(head) orelse return false;
        return std.mem.eql(u8, resolved, "builtin");
    }
    // Fallback: match the canonical spelling used throughout the kernel.
    return std.mem.eql(u8, src, "builtin.cpu.arch");
}

/// Slice the source span for an identifier or `.field_access` chain. Other
/// node tags return null (the caller can decide how to handle).
fn chainSource(ctx: *Ctx, node: std.zig.Ast.Node.Index) ?[]const u8 {
    const tag = ctx.ast.nodeTag(node);
    if (tag != .field_access and tag != .identifier) return null;
    const first = ctx.ast.firstToken(node);
    const last = ctx.ast.lastToken(node);
    const start = ctx.ast.tokenStart(first);
    const last_start = ctx.ast.tokenStart(last);
    const last_slice = ctx.ast.tokenSlice(last);
    const end: usize = @as(usize, last_start) + last_slice.len;
    if (end <= start or end > ctx.ast.source.len) return null;
    return ctx.ast.source[start..end];
}

/// Non-allocating module-path slice for a file path. Mirrors the rules in
/// walker.filePathToModulePath (kernel root, /usr/lib/zig, /usr/lib/zig/std)
/// but returns a slice into a static-ish form. Returns an empty slice if the
/// path doesn't match any known root (the resolver then falls through).
///
/// Caveat: this returns the dotted module form by replacing `/` with `.` —
/// since we need a fresh allocation for that. Callers pass the file path
/// they got from emitCall (which is the resolved abs path). We re-allocate
/// the dotted form into the arena, which is fine for the rare bare-ident
/// resolution path.
fn filePathToModulePathSlice(file: []const u8) []const u8 {
    var rel: []const u8 = file;

    const zig_std_prefix = "/usr/lib/zig/std/";
    const zig_root_prefix = "/usr/lib/zig/";
    if (std.mem.startsWith(u8, rel, zig_std_prefix)) {
        rel = rel[zig_std_prefix.len..];
    } else if (std.mem.startsWith(u8, rel, zig_root_prefix)) {
        rel = rel[zig_root_prefix.len..];
    } else if (std.mem.indexOf(u8, rel, "/kernel/")) |i| {
        rel = rel[i + "/kernel/".len ..];
    } else if (std.mem.startsWith(u8, rel, "kernel/")) {
        rel = rel["kernel/".len..];
    } else {
        return "";
    }

    if (std.mem.endsWith(u8, rel, ".zig")) {
        rel = rel[0 .. rel.len - ".zig".len];
    }
    return rel;
}

/// Allocating dotted-module-path form. Slashes become dots. Used when we
/// need to construct a candidate qname against the global index.
fn fileToDottedModule(arena: std.mem.Allocator, file: []const u8) ![]const u8 {
    const rel = filePathToModulePathSlice(file);
    if (rel.len == 0) return "";
    const out = try arena.dupe(u8, rel);
    for (out) |*c| {
        if (c.* == '/') c.* = '.';
    }
    return out;
}

fn archTagFor(arch: TargetArch) []const u8 {
    return switch (arch) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
    };
}

/// Does the switch-case value source slice equal `.<tag>`? We accept a leading
/// dot (enum-literal form `.x86_64`) — that's the form `builtin.cpu.arch`
/// dispatch always uses in this codebase. Anything else is treated as
/// non-matching, which conservatively keeps the arm.
fn caseValueMatchesTag(
    ctx: *Ctx,
    value_node: std.zig.Ast.Node.Index,
    tag: []const u8,
) bool {
    const src = nodeSource(ctx, value_node);
    if (src.len < 2 or src[0] != '.') return false;
    const trimmed = std.mem.trim(u8, src[1..], &std.ascii.whitespace);
    return std.mem.eql(u8, trimmed, tag);
}

const ArchIfMatch = struct {
    arch: TargetArch,
    op: enum { eq, neq },
};

/// Classify an `if` condition as a `builtin.cpu.arch == .X` (or `!=`) form.
/// Returns null on anything we don't recognize. v1 only accepts the direct
/// equality / inequality form against a single arch tag — `or`-chains and
/// inversions like `!(builtin.cpu.arch == .x86_64)` are not handled.
fn classifyBuiltinCpuArchIf(ctx: *Ctx, cond_expr: std.zig.Ast.Node.Index) ?ArchIfMatch {
    const tag = ctx.ast.nodeTag(cond_expr);
    if (tag != .equal_equal and tag != .bang_equal) return null;
    const data = ctx.ast.nodeData(cond_expr);
    const lhs = data.node_and_node[0];
    const rhs = data.node_and_node[1];

    const lhs_is_arch = isBuiltinCpuArchScrutinee(ctx, lhs);
    const rhs_is_arch = isBuiltinCpuArchScrutinee(ctx, rhs);
    const tag_node: std.zig.Ast.Node.Index = if (lhs_is_arch) rhs else if (rhs_is_arch) lhs else return null;

    const tag_src = nodeSource(ctx, tag_node);
    if (tag_src.len < 2 or tag_src[0] != '.') return null;
    const tag_name = std.mem.trim(u8, tag_src[1..], &std.ascii.whitespace);

    const arch: TargetArch = if (std.mem.eql(u8, tag_name, "x86_64"))
        .x86_64
    else if (std.mem.eql(u8, tag_name, "aarch64"))
        .aarch64
    else
        return null;

    return .{
        .arch = arch,
        .op = if (tag == .equal_equal) .eq else .neq,
    };
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
