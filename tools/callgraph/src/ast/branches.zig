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
/// Global qname → return-type-qname index. Populated by join.zig from each
/// AstFunction's `return_type_qname` slot. Used by `inferCallReturnType` so
/// `const x = someFn(args);` bindings record the right struct qname for
/// downstream `x.method()` resolution. Empty entries (functions whose
/// return type couldn't be reduced) are simply omitted.
pub const FnReturnTypeIndex = std.StringHashMap([]const u8);
/// Global struct-qname → StructTypeInfo. Built by join.zig from the walker's
/// struct_types output. The receiver-chain resolver walks each `.field`
/// segment through this table until only the trailing method name remains.
pub const StructTypeIndex = std.StringHashMap(*const types.StructTypeInfo);
/// Re-export alias index. Maps a `<file_module>.<X>` user-form qname to the
/// underlying chain target. Used by `lookupCandidate` to rewrite candidate
/// prefixes whose path goes through a re-export — e.g. a candidate of
/// `utils.sync.SpinLock.lockIrqSave` is rewritten to
/// `utils.sync.spin_lock.SpinLock.lockIrqSave` (the form the qname index
/// actually carries because that's where the source-level fn lives).
pub const ReexportAliasIndex = std.StringHashMap([]const u8);

/// Per-fn fn-pointer parameter bindings. Maps an inline fn's parameter name
/// (e.g. `ktrampoline`) to the qname of the function the caller passed
/// (e.g. `main.kTrampoline`). Used by emitCall when an AST-only inline body
/// invokes a parameter — instead of rendering as `? indirect: ktrampoline`,
/// the param is looked up here and the call resolves to the bound fn directly.
/// join.zig populates the table by an all-callers-agree pass: only when every
/// call site to the inline fn passes the same `&fn` for a given parameter is
/// the binding recorded.
pub const ParamBindings = std.StringHashMap([]const u8);

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
    struct_types: ?*const StructTypeIndex,
    receiver_name: []const u8,
    receiver_type: []const u8,
    param_bindings: ?*const ParamBindings,
    aliases: ?*const ReexportAliasIndex,
    fn_return_types: ?*const FnReturnTypeIndex,
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
        .struct_types = struct_types,
        .receiver_name = receiver_name,
        .receiver_type = receiver_type,
        .param_bindings = param_bindings,
        .aliases = aliases,
        .fn_return_types = fn_return_types,
        .locals_stack = .{},
    };
    // Push the function-scope local frame. Subsequent block entries push
    // additional frames; the `head`-lookup walk visits every active frame.
    try ctx.locals_stack.append(arena, .{});

    // Register every named param with a resolvable struct type into the
    // function-scope frame. Without this, top-level functions whose first
    // arg is a struct-pointer-but-not-a-receiver (e.g. `pub fn recv(caller:
    // *ExecutionContext, ...)` declared outside ExecutionContext's container)
    // can't resolve `caller.field` chains — `computeReceiver` only marks the
    // arg as a receiver when the fn is declared inside the type's container,
    // and there's no other code path that knows the param's type. The locals
    // table is the natural home.
    {
        var proto_buf: [1]std.zig.Ast.Node.Index = undefined;
        if (ast.fullFnProto(&proto_buf, node_idx)) |fn_proto| {
            var it = fn_proto.iterate(ast);
            while (it.next()) |param| {
                const tok = param.name_token orelse continue;
                const pname = ast.tokenSlice(tok);
                if (pname.len == 0) continue;
                // Skip `self` / `this` / the explicit-receiver name — those
                // already route through the receiver path.
                if (receiver_name.len > 0 and std.mem.eql(u8, pname, receiver_name)) continue;
                const type_expr = param.type_expr orelse continue;
                const ptype = resolveLocalDeclType(&ctx, type_expr) catch "";
                if (ptype.len == 0) continue;
                const top = &ctx.locals_stack.items[0];
                _ = try top.getOrPutValue(arena, try arena.dupe(u8, pname), ptype);
            }
        }
    }

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
    /// Global struct-qname → StructTypeInfo. Drives the receiver-chain
    /// resolver: each `.field` segment of `self.x.y.method(...)` looks up the
    /// current struct, finds the named field, and advances to the field's
    /// type. Optional; when null we skip multi-step chain resolution.
    struct_types: ?*const StructTypeIndex,
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
    /// Optional fn-pointer parameter bindings — only populated when the
    /// enclosing fn is an AST-only inline whose call sites all pass the same
    /// `&fn` for a given param. emitCall consults this *before* falling
    /// through to the indirect synth path: a bare-identifier call whose
    /// fn_expr matches a binding key resolves directly to the bound qname.
    param_bindings: ?*const ParamBindings,
    /// Optional re-export alias index. Consulted by `lookupCandidate` when
    /// the direct qname-index probe misses, so a candidate that goes through
    /// a re-export prefix (e.g. `utils.sync.SpinLock.lockIrqSave`, where
    /// `SpinLock` is `pub const SpinLock = spin_lock.SpinLock;`) gets
    /// rewritten to the underlying form before retrying the lookup.
    aliases: ?*const ReexportAliasIndex,
    /// Optional fn-qname → return-type-qname index. Populated by join.zig.
    /// Consulted by `inferInitType` when a local's RHS is a call: lets
    /// `const port_ref = capability.typedRef(...) orelse return ...;`
    /// stamp `port_ref` with the SlabRef return type so a later
    /// `port_ref.lock(...)` call can resolve through the receiver path.
    fn_return_types: ?*const FnReturnTypeIndex,
    /// Defer / errdefer expression nodes accumulated at function scope.
    /// Walked at function-end so their calls show up in the sequence.
    defers: std.ArrayList(std.zig.Ast.Node.Index) = .{},
    /// Stack of local-binding scopes built up as we descend into blocks. The
    /// top frame holds the current block's `const name: T = ...` / `var
    /// name: T = ...` decls; head-lookup for receiver resolution scans every
    /// active frame from top to bottom (innermost first).
    locals_stack: std.ArrayList(LocalScope) = .{},
};

/// Per-block local-binding table. Populated as `walkBlockBody` iterates
/// statements and drained when the frame is popped. Entries with `type_qname
/// == ""` are still inserted so a later `local_var.method()` call can detect
/// "binding exists but unresolvable" and fall through to indirect rather
/// than mis-resolving via shadowed outer-scope names.
const LocalScope = std.StringHashMapUnmanaged([]const u8);

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

        // Block — iterate statements. Push a fresh locals scope for the block
        // so var/const decls inside don't leak into the parent scope, and so
        // shadowed bindings are seen innermost-first by the receiver
        // resolver. The function-scope frame is pushed by `buildIntra` and
        // covers the outermost body block; nested blocks add their own frame.
        .block, .block_semicolon, .block_two, .block_two_semicolon => {
            var buf: [2]std.zig.Ast.Node.Index = undefined;
            const stmts = ctx.ast.blockStatements(&buf, node) orelse return;
            const pushed = try pushLocalsScope(ctx);
            defer popLocalsScope(ctx, pushed);
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

        // Var decls — descend into init expression and, when the decl has an
        // explicit type annotation (`const x: Foo = ...;` / `var x: Bar =
        // ...;`), register the binding in the innermost locals scope so a
        // later `x.method()` call resolves through the receiver-chain path.
        // Inferred-type decls (no `: T`) leave the binding type unresolved —
        // pattern 4 (call-result types) is intentionally out of scope for v1.
        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            const vd = ctx.ast.fullVarDecl(node) orelse return;
            if (vd.ast.init_node.unwrap()) |init_node| {
                try walkExpr(ctx, init_node, out);
            }
            try recordLocalDecl(ctx, vd);
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

    // Fn-pointer parameter substitution: when this fn is an AST-only inline
    // whose all-callers-agree pass produced a binding for one of its params,
    // a bare-identifier call to that param resolves directly to the bound fn.
    // E.g. inside `pub inline fn kEntry(_, ktrampoline: *const fn (...) ...)`
    // the body's `ktrampoline(boot_info)` becomes a direct call to
    // `main.kTrampoline` (which is what `&kTrampoline` was passed in main.zig).
    if (try resolveByParamBinding(ctx, call.ast.fn_expr, line, col)) |resolved| {
        try out.append(ctx.arena, .{ .call = resolved });
        return;
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

/// Fn-pointer parameter resolver. When the call's fn_expr is a bare
/// identifier matching a key in `ctx.param_bindings`, the bound qname is
/// looked up against the qname index / known-names set and emitted as a
/// direct call. Returns null when there are no bindings, when the fn_expr
/// isn't a bare identifier, or when the binding doesn't resolve to a known
/// qname.
fn resolveByParamBinding(
    ctx: *Ctx,
    fn_expr: std.zig.Ast.Node.Index,
    line: u32,
    col: u32,
) !?Callee {
    const bindings = ctx.param_bindings orelse return null;
    if (ctx.ast.nodeTag(fn_expr) != .identifier) return null;
    const ident = nodeSource(ctx, fn_expr);
    if (ident.len == 0) return null;
    const bound_qname = bindings.get(ident) orelse return null;
    return try lookupCandidate(ctx, bound_qname, line, col);
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

/// Receiver-method resolver. Handles three shapes:
///
///   * `self.method(...)`               — single-hop receiver call.
///   * `self.f1.f2.method(...)`         — multi-hop chain through receiver
///                                        struct's field-type table.
///   * `localvar.method(...)` and       — same chain logic, where `localvar`
///     `localvar.field.method(...)`       was bound by `const x: T = ...`
///                                        / `var x: T = ...` with an
///                                        explicit type annotation.
///
/// Every chain step must succeed against the field-type index; any miss
/// yields null and the caller falls through to the existing indirect
/// fallback (better to not resolve than mis-resolve).
///
/// Patterns intentionally NOT handled (TODO):
///   * Receivers bound by call-result whose type would require return-type
///     inference (`const lock = self.acquireLock(); lock.unlock();`).
///   * Optional / error-union peels (`if (self.maybe_x) |x| x.method();`).
///   * Tuple-field receivers and anonymous-struct field access.
fn resolveByReceiver(
    ctx: *Ctx,
    fn_expr: std.zig.Ast.Node.Index,
    line: u32,
    col: u32,
) !?Callee {
    const tag = ctx.ast.nodeTag(fn_expr);
    if (tag != .field_access) return null;

    const chain = chainSource(ctx, fn_expr) orelse return null;
    const first_dot = std.mem.indexOfScalar(u8, chain, '.') orelse return null;
    const head = chain[0..first_dot];
    const tail = chain[first_dot + 1 ..];
    if (tail.len == 0) return null;

    // Pick a starting type. Prefer the enclosing fn's receiver, then any
    // matching local var with an explicit-typed binding. Locals shadow the
    // receiver: a same-named binding inside the body wins, mirroring Zig's
    // own scoping. If neither matches, give up — the call isn't a
    // receiver-or-local chain.
    var cur_type: []const u8 = "";
    if (lookupLocal(ctx, head)) |t| {
        cur_type = t;
    } else if (ctx.receiver_name.len > 0 and std.mem.eql(u8, head, ctx.receiver_name)) {
        cur_type = ctx.receiver_type;
    } else {
        return null;
    }
    if (cur_type.len == 0) return null;

    // Walk every dot-segment in `tail` except the last (which is the method
    // name). At each step look up the current struct in the field-type
    // index and advance to the named field's type.
    var rest = tail;
    while (std.mem.indexOfScalar(u8, rest, '.')) |dot_pos| {
        const segment = rest[0..dot_pos];
        rest = rest[dot_pos + 1 ..];
        const struct_idx = ctx.struct_types orelse return null;
        const sti_ptr = struct_idx.get(cur_type) orelse return null;
        const next_type = findFieldType(sti_ptr.*, segment) orelse return null;
        if (next_type.len == 0) return null;
        cur_type = next_type;
    }

    if (rest.len == 0) return null;

    const candidate = try std.fmt.allocPrint(
        ctx.arena,
        "{s}.{s}",
        .{ cur_type, rest },
    );
    return try lookupCandidate(ctx, candidate, line, col);
}

/// Find a field's resolved type-qname in a StructTypeInfo. Returns null when
/// the field isn't present; returns "" when the field is present but its
/// type couldn't be resolved at walk time. The caller treats both as a
/// resolution failure.
fn findFieldType(info: types.StructTypeInfo, field_name: []const u8) ?[]const u8 {
    for (info.fields) |f| {
        if (std.mem.eql(u8, f.field_name, field_name)) return f.type_qname;
    }
    return null;
}

// ------------------------------------------------------------ locals stack

/// Push a fresh locals scope. Returns true on success so the matching
/// `popLocalsScope` knows to actually pop (we don't trust callers to handle
/// errors mid-scope without leaking a frame).
fn pushLocalsScope(ctx: *Ctx) !bool {
    try ctx.locals_stack.append(ctx.arena, .{});
    return true;
}

fn popLocalsScope(ctx: *Ctx, pushed: bool) void {
    if (!pushed) return;
    if (ctx.locals_stack.items.len == 0) return;
    _ = ctx.locals_stack.pop();
}

/// Look up `name` in the locals stack, innermost-first. Returns the bound
/// type qname when found (may be ""), null when no scope contains the name.
fn lookupLocal(ctx: *Ctx, name: []const u8) ?[]const u8 {
    if (ctx.locals_stack.items.len == 0) return null;
    var i: usize = ctx.locals_stack.items.len;
    while (i > 0) {
        i -= 1;
        if (ctx.locals_stack.items[i].get(name)) |v| return v;
    }
    return null;
}

/// Record a `const X: T = ...` / `var X: T = ...` decl in the innermost
/// locals scope. Decls without an explicit type annotation are still
/// recorded with an empty type-qname so `x.method()` shadowing an outer
/// binding is suppressed (we know the binding exists; we just can't
/// resolve through it yet — pattern 4 / call-return-type would).
fn recordLocalDecl(ctx: *Ctx, vd: std.zig.Ast.full.VarDecl) !void {
    if (ctx.locals_stack.items.len == 0) return;
    const name_token = vd.ast.mut_token + 1;
    const name = ctx.ast.tokenSlice(name_token);
    if (name.len == 0) return;
    const name_dup = try ctx.arena.dupe(u8, name);

    var type_qname: []const u8 = "";
    if (vd.ast.type_node.unwrap()) |type_node| {
        // `const x: T = ...;` — explicit annotation wins, treat the RHS
        // as opaque.
        type_qname = resolveLocalDeclType(ctx, type_node) catch "";
    } else if (vd.ast.init_node.unwrap()) |init_node| {
        // `const x = expr;` — infer from the RHS so chains like
        // `cd_ref.lock(...)` resolve once the local's type is known. The
        // inference is deliberately conservative: returns "" for anything
        // we can't reduce to a struct qname, so a later receiver lookup
        // simply falls back to indirect rather than resolving wrong.
        type_qname = inferInitType(ctx, init_node) catch "";
    }

    var top = &ctx.locals_stack.items[ctx.locals_stack.items.len - 1];
    try top.put(ctx.arena, name_dup, type_qname);
}

/// Walk an initializer expression and return the qname of its underlying
/// struct type, or "" when not statically reducible. Handles the common
/// patterns the kernel uses for local bindings:
///
///   identifier         — alias to a local in scope or to the enclosing
///                        receiver; type qname comes from the locals stack
///                        / receiver_type.
///   field_access       — `head.field.chain.[…]`. Resolved via the same
///                        struct-types index the receiver-method resolver
///                        uses, walking each `.field` segment.
///   unwrap_optional    — `expr.?`. Same type as LHS.
///   deref              — `expr.*`. Same type as LHS (pointer→pointee
///                        already strips in resolveLocalDeclType; here the
///                        LHS already stores the pointee type).
///   grouped_expression — `(expr)`. Same as inner.
///   orelse / catch     — `expr orelse default` / `expr catch default`.
///                        Same as LHS — the unwrap removes the optional /
///                        error-union wrapping; the inferred type tracks
///                        the success case the local actually holds.
///   try                — `try expr`. Same as LHS.
///   call               — `someFn(args)`. Resolved via the global fn
///                        return-type index; "" when the callee or its
///                        return type aren't reducible. This closes the
///                        common `const x = receiver.method(...)` pattern.
///
/// All other forms (struct literals, builtins, comptime exprs, address-of,
/// etc.) yield "" — the locals scope still records the binding so a later
/// `x.method()` call sees "exists but unresolvable" and falls through to
/// indirect, mirroring resolveByReceiver's behaviour for the explicit-
/// annotation case.
fn inferInitType(ctx: *Ctx, node: std.zig.Ast.Node.Index) ![]const u8 {
    const tag = ctx.ast.nodeTag(node);
    switch (tag) {
        .identifier => {
            const ident = nodeSource(ctx, node);
            if (ident.len == 0) return "";
            // Locals shadow the receiver, mirroring resolveByReceiver.
            if (lookupLocal(ctx, ident)) |t| return t;
            if (ctx.receiver_name.len > 0 and std.mem.eql(u8, ident, ctx.receiver_name)) {
                return ctx.receiver_type;
            }
            return "";
        },

        .field_access => {
            // Walk `head.tail.chain` through the struct-types index, exactly
            // like resolveByReceiver — but here `chain` is the *whole*
            // expression (no trailing method to strip), so the final segment
            // also resolves to a field type.
            const chain = chainSource(ctx, node) orelse return "";
            const first_dot = std.mem.indexOfScalar(u8, chain, '.') orelse return "";
            const head = chain[0..first_dot];
            const tail = chain[first_dot + 1 ..];
            if (tail.len == 0) return "";

            var cur_type: []const u8 = "";
            if (lookupLocal(ctx, head)) |t| {
                cur_type = t;
            } else if (ctx.receiver_name.len > 0 and std.mem.eql(u8, head, ctx.receiver_name)) {
                cur_type = ctx.receiver_type;
            } else {
                return "";
            }
            if (cur_type.len == 0) return "";

            const struct_idx = ctx.struct_types orelse return "";
            var rest = tail;
            while (true) {
                const sti_ptr = struct_idx.get(cur_type) orelse return "";
                const dot_pos = std.mem.indexOfScalar(u8, rest, '.');
                if (dot_pos) |p| {
                    const segment = rest[0..p];
                    const next_type = findFieldType(sti_ptr.*, segment) orelse return "";
                    if (next_type.len == 0) return "";
                    cur_type = next_type;
                    rest = rest[p + 1 ..];
                    continue;
                }
                // Final segment.
                const next_type = findFieldType(sti_ptr.*, rest) orelse return "";
                if (next_type.len == 0) return "";
                return next_type;
            }
        },

        .unwrap_optional => {
            // node_and_token[0] is the LHS, the token is the trailing `?`.
            const lhs = ctx.ast.nodeData(node).node_and_token[0];
            return try inferInitType(ctx, lhs);
        },
        .deref => {
            // `.deref` carries a single child node — the pointer being
            // dereferenced. The pointee type matches what the LHS already
            // tracks (struct_types entries are stored stripped of pointer
            // decoration in the field-type table), so just recurse.
            const child = ctx.ast.nodeData(node).node;
            return try inferInitType(ctx, child);
        },
        .grouped_expression => {
            const inner = ctx.ast.nodeData(node).node_and_token[0];
            return try inferInitType(ctx, inner);
        },
        .@"orelse", .@"catch" => {
            // Both peel a layer: orelse strips optional, catch strips error
            // union. The inferred type is whatever the success-case LHS
            // resolves to; the fallback expression on the RHS doesn't bind
            // back to this local on the success path.
            const lhs = ctx.ast.nodeData(node).node_and_node[0];
            return try inferInitType(ctx, lhs);
        },
        .@"try" => {
            const child = ctx.ast.nodeData(node).node;
            return try inferInitType(ctx, child);
        },

        .call, .call_comma, .call_one, .call_one_comma => {
            return inferCallReturnType(ctx, node) catch "";
        },

        else => return "",
    }
}

/// Resolve a call expression to its function's return-type qname. Mirrors
/// emitCall's resolution ladder — IR-resolved callee → import-table lookup →
/// receiver-chain — then consults the global return-type index. Returns ""
/// for any miss so the caller falls through to "binding exists but
/// unresolvable".
fn inferCallReturnType(ctx: *Ctx, call_node: std.zig.Ast.Node.Index) ![]const u8 {
    const ret_idx = ctx.fn_return_types orelse return "";
    var buf: [1]std.zig.Ast.Node.Index = undefined;
    const call = ctx.ast.fullCall(&buf, call_node) orelse return "";

    const first_tok = ctx.ast.firstToken(call.ast.fn_expr);
    const loc = ctx.ast.tokenLocation(0, first_tok);
    const line: u32 = @intCast(loc.line + 1);
    const col: u32 = @intCast(loc.column + 1);

    // 1) IR-resolved direct call at this site — preferred when available.
    const key = try callSiteKey(ctx.arena, ctx.file, line);
    if (ctx.callsites.get(key)) |candidates| {
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
            if (c.kind != .indirect and c.name.len > 0) {
                if (ret_idx.get(c.name)) |t| if (t.len > 0) return t;
            }
        }
    }

    // 2) Import-table / same-file lookup (mirrors resolveByImports). Catches
    //    inlined-away calls the IR no longer carries.
    if (try resolveByImports(ctx, call.ast.fn_expr, line, col)) |resolved| {
        if (resolved.name.len > 0) {
            if (ret_idx.get(resolved.name)) |t| if (t.len > 0) return t;
        }
    }

    // 3) Receiver-chain lookup (mirrors resolveByReceiver). Catches
    //    `local.method(...)` once the local's own type is known.
    if (try resolveByReceiver(ctx, call.ast.fn_expr, line, col)) |resolved| {
        if (resolved.name.len > 0) {
            if (ret_idx.get(resolved.name)) |t| if (t.len > 0) return t;
        }
    }

    return "";
}

/// Resolve a local var-decl's annotated type to a struct qname, mirroring
/// the rules used for receiver and field types: strip pointer/optional/
/// const decoration, then handle dotted-chain (via imports) and bare-name
/// (same-file sibling) forms. Returns "" when the type isn't reducible.
fn resolveLocalDeclType(ctx: *Ctx, type_node: std.zig.Ast.Node.Index) ![]const u8 {
    const src = nodeSource(ctx, type_node);
    if (src.len == 0) return "";
    const stripped = stripPointerOptional(src);
    if (stripped.len == 0) return "";

    // Dotted chain — leftmost ident in the file's import table.
    if (looksLikeDottedChain(stripped)) {
        const imports = ctx.imports orelse return "";
        const dot = std.mem.indexOfScalar(u8, stripped, '.') orelse return "";
        const head = stripped[0..dot];
        const tail = stripped[dot + 1 ..];
        const resolved_head = imports.get(head) orelse return "";
        if (tail.len == 0) return try ctx.arena.dupe(u8, resolved_head);
        if (std.mem.eql(u8, resolved_head, "zag")) {
            return try ctx.arena.dupe(u8, tail);
        }
        return try std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ resolved_head, tail });
    }

    // Bare ident — first try the file's import table, since `const T = ...;`
    // may be an `@import(...)` or a re-export alias. Only fall through to
    // the same-file sibling form if the import table has no entry.
    if (isBareIdent(stripped)) {
        if (ctx.imports) |imports| {
            if (imports.get(stripped)) |q| {
                return try ctx.arena.dupe(u8, q);
            }
        }
        const file_mod = try fileToDottedModule(ctx.arena, ctx.file);
        if (file_mod.len == 0) return "";
        return try std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ file_mod, stripped });
    }

    return "";
}

/// Strip leading pointer/optional/const decoration AND a trailing generic-
/// args group from a type source span. Mirrors walker.stripPointerOptional
/// (kept in sync — see the comment there for why generic-args stripping
/// matters for the kernel's `Foo(comptime T: type) type {...}` factory
/// pattern).
fn stripPointerOptional(src: []const u8) []const u8 {
    var s = std.mem.trim(u8, src, &std.ascii.whitespace);
    while (s.len > 0) {
        if (s[0] == '*') {
            s = std.mem.trim(u8, s[1..], &std.ascii.whitespace);
            if (std.mem.startsWith(u8, s, "const ")) s = std.mem.trim(u8, s["const ".len..], &std.ascii.whitespace);
            if (std.mem.startsWith(u8, s, "volatile ")) s = std.mem.trim(u8, s["volatile ".len..], &std.ascii.whitespace);
            continue;
        }
        if (s[0] == '?') {
            s = std.mem.trim(u8, s[1..], &std.ascii.whitespace);
            continue;
        }
        if (s[0] == '[') return "";
        break;
    }
    return stripTrailingGenericArgs(s);
}

fn stripTrailingGenericArgs(s: []const u8) []const u8 {
    if (s.len == 0 or s[s.len - 1] != ')') return s;
    var depth: usize = 0;
    var i: usize = s.len;
    while (i > 0) {
        i -= 1;
        switch (s[i]) {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if (depth == 0) return std.mem.trim(u8, s[0..i], &std.ascii.whitespace);
            },
            else => {},
        }
    }
    return s;
}

fn looksLikeDottedChain(s: []const u8) bool {
    if (s.len == 0) return false;
    if (std.mem.indexOfScalar(u8, s, '.') == null) return false;
    return isIdentChars(s);
}

fn isBareIdent(s: []const u8) bool {
    if (s.len == 0) return false;
    if (std.mem.indexOfScalar(u8, s, '.') != null) return false;
    return isIdentChars(s);
}

fn isIdentChars(s: []const u8) bool {
    for (s) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '_' or c == '.';
        if (!ok) return false;
    }
    return true;
}

/// Look `candidate` up in the qname index (preferred — gives us a `to` id)
/// then in the known-names set (fallback — name only, `to=null`). Returns
/// null on miss in both.
///
/// On miss, walks left-to-right through the candidate looking for the
/// longest prefix that's a re-export alias key. If found, the prefix is
/// rewritten to the alias's resolved target (preserving the suffix) and the
/// lookup retries. Capped at 3 hops to avoid pathological alias chains.
fn lookupCandidate(
    ctx: *Ctx,
    candidate: []const u8,
    line: u32,
    col: u32,
) !?Callee {
    if (try lookupCandidateDirect(ctx, candidate, line, col)) |c| return c;

    // Alias-rewrite fallback. We try at most 3 hops, since a kernel re-export
    // chain shouldn't realistically exceed a couple links and we don't want
    // to thrash on a self-referential alias that slipped through.
    if (ctx.aliases) |aliases| {
        var current: []const u8 = candidate;
        var hops: u32 = 0;
        while (hops < 3) {
            const rewritten = rewriteWithAlias(ctx.arena, current, aliases) catch null;
            const r = rewritten orelse break;
            if (try lookupCandidateDirect(ctx, r, line, col)) |c| return c;
            current = r;
            hops += 1;
        }
    }

    return null;
}

fn lookupCandidateDirect(
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

/// Find the longest dot-bounded prefix of `candidate` that's a key in the
/// alias index, and rewrite the candidate by replacing that prefix with the
/// alias's target. Returns null when no prefix matches.
///
/// We scan from longest to shortest by walking dot positions right-to-left
/// — the first hit is the longest valid prefix. A prefix is "valid" only
/// when it ends at a dot (so `utils.sync` matches but `utils.s` doesn't),
/// preventing partial-segment collisions.
fn rewriteWithAlias(
    arena: std.mem.Allocator,
    candidate: []const u8,
    aliases: *const ReexportAliasIndex,
) !?[]const u8 {
    if (candidate.len == 0) return null;

    // Try the whole candidate (rare; would only fire if the candidate equals
    // an alias key with no method appended, which lookupCandidate's caller
    // wouldn't pass — but supporting it keeps the function self-contained).
    if (aliases.get(candidate)) |target| {
        return try arena.dupe(u8, target);
    }

    var i: usize = candidate.len;
    while (i > 0) {
        i -= 1;
        if (candidate[i] != '.') continue;
        const prefix = candidate[0..i];
        if (aliases.get(prefix)) |target| {
            const suffix = candidate[i..]; // includes the leading dot
            return try std.fmt.allocPrint(arena, "{s}{s}", .{ target, suffix });
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
