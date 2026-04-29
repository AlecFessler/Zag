const std = @import("std");
const types = @import("types.zig");

const ProvisionalEntity = types.ProvisionalEntity;
const AstNodeRow = types.AstNodeRow;
const AstEdgeRow = types.AstEdgeRow;
const EntityKind = types.EntityKind;

const Ast = std.zig.Ast;
const Node = Ast.Node;

pub const PassResult = struct {
    entities: []ProvisionalEntity,
    ast_nodes: []AstNodeRow,
    ast_edges: []AstEdgeRow,
};

const Walker = struct {
    palloc: std.mem.Allocator,
    tree: *const Ast,
    source: []const u8,
    file_id: u32,
    module_id: u32,
    module_qname: []const u8,
    next_node_id: *std.atomic.Value(u64),

    entities: std.ArrayList(ProvisionalEntity),
    nodes: std.ArrayList(AstNodeRow),
    edges: std.ArrayList(AstEdgeRow),
};

/// Slice B: walks the AST emitting BOTH provisional entity records AND
/// ast_node/ast_edge rows. A single traversal does double duty.
///
/// `next_node_id` is a shared atomic counter that hands out globally-unique
/// ast_node ids across all worker threads.
pub fn pass(
    palloc: std.mem.Allocator,
    source: [:0]const u8,
    file_id: u32,
    module_id: u32,
    module_qname: []const u8,
    next_node_id: *std.atomic.Value(u64),
) !PassResult {
    var tree = try Ast.parse(palloc, source, .zig);
    defer tree.deinit(palloc);

    var w: Walker = .{
        .palloc = palloc,
        .tree = &tree,
        .source = source,
        .file_id = file_id,
        .module_id = module_id,
        .module_qname = module_qname,
        .next_node_id = next_node_id,
        .entities = .empty,
        .nodes = .empty,
        .edges = .empty,
    };

    const root_decls = tree.rootDecls();
    for (root_decls) |decl| {
        try walkContainerMember(&w, decl, null, "");
    }

    return .{
        .entities = try w.entities.toOwnedSlice(palloc),
        .ast_nodes = try w.nodes.toOwnedSlice(palloc),
        .ast_edges = try w.edges.toOwnedSlice(palloc),
    };
}

// ── Emission helpers ──────────────────────────────────────────────────────

const KIND_FN_DECL = "fn_decl";
const KIND_BLOCK = "block";
const KIND_IF = "if";
const KIND_WHILE = "while";
const KIND_FOR = "for";
const KIND_SWITCH = "switch";
const KIND_SWITCH_PRONG = "switch_prong";
const KIND_CALL = "call";
const KIND_BUILTIN_CALL = "builtin_call";
const KIND_VAR_DECL = "var_decl";
const KIND_RETURN = "return";
const KIND_DEFER = "defer";
const KIND_ERRDEFER = "errdefer";
const KIND_CONTAINER_DECL = "container_decl";
const KIND_CONTAINER_FIELD = "container_field";

fn emitNode(w: *Walker, kind: []const u8, idx: Node.Index, parent_id: ?u64) !u64 {
    const id = w.next_node_id.fetchAdd(1, .monotonic);
    const span = nodeByteSpan(w.tree, idx);
    try w.nodes.append(w.palloc, .{
        .id = id,
        .file_id = w.file_id,
        .parent_id = parent_id,
        .kind = kind,
        .byte_start = span.start,
        .byte_end = span.end,
    });
    if (parent_id) |pid| {
        try w.edges.append(w.palloc, .{ .parent_id = pid, .child_id = id, .role = null });
    }
    return id;
}

// ── Container traversal: top-level decls + struct/union/enum members ──────

fn walkContainerMember(
    w: *Walker,
    idx: Node.Index,
    parent_id: ?u64,
    container_path: []const u8,
) anyerror!void {
    const tag = w.tree.nodeTag(idx);
    switch (tag) {
        .fn_decl, .fn_proto, .fn_proto_simple, .fn_proto_multi, .fn_proto_one => {
            try emitFn(w, idx, parent_id, container_path);
        },
        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            try emitVarConst(w, idx, parent_id, container_path);
        },
        .container_field, .container_field_init, .container_field_align => {
            const node_id = try emitNode(w, KIND_CONTAINER_FIELD, idx, parent_id);
            // Recurse into init/align expressions to catch calls in defaults.
            // Use lastToken-based descent: for slice B we skip this and accept that
            // calls inside field defaults are not parented through the field node.
            _ = node_id;
        },
        .test_decl => {
            // tests are ignored for kernel indexing
        },
        else => {},
    }
}

fn emitFn(
    w: *Walker,
    idx: Node.Index,
    parent_id: ?u64,
    container_path: []const u8,
) !void {
    var proto_buf: [1]Node.Index = undefined;
    const fn_proto = w.tree.fullFnProto(&proto_buf, idx) orelse return;
    const name_tok = fn_proto.name_token orelse return;
    const name = w.tree.tokenSlice(name_tok);

    const node_id = try emitNode(w, KIND_FN_DECL, idx, parent_id);

    const qualified = try buildQname(w, container_path, name);
    const span = nodeByteSpan(w.tree, idx);
    const lc = byteToLineCol(w.source, span.start);

    try w.entities.append(w.palloc, .{
        .kind = .fn_,
        .qualified_name = qualified,
        .module_id = w.module_id,
        .def_file_id = w.file_id,
        .def_byte_start = span.start,
        .def_byte_end = span.end,
        .def_line = lc.line,
        .def_col = lc.col,
        .is_slab_backed = false,
        .def_ast_node_id = node_id,
    });

    // Recurse into body (only fn_decl has a body; protos don't).
    if (w.tree.nodeTag(idx) == .fn_decl) {
        const body = w.tree.nodeData(idx).node_and_node[1];
        try walkExpr(w, body, node_id);
    }
}

fn emitVarConst(
    w: *Walker,
    idx: Node.Index,
    parent_id: ?u64,
    container_path: []const u8,
) !void {
    const vd = w.tree.fullVarDecl(idx) orelse return;
    const name_tok = vd.ast.mut_token + 1;
    const name = w.tree.tokenSlice(name_tok);

    const node_id = try emitNode(w, KIND_VAR_DECL, idx, parent_id);

    const qualified = try buildQname(w, container_path, name);
    const span = nodeByteSpan(w.tree, idx);
    const lc = byteToLineCol(w.source, span.start);

    const mut_text = w.tree.tokenSlice(vd.ast.mut_token);
    const kind: EntityKind = if (std.mem.eql(u8, mut_text, "const")) .const_ else .var_;

    try w.entities.append(w.palloc, .{
        .kind = kind,
        .qualified_name = qualified,
        .module_id = w.module_id,
        .def_file_id = w.file_id,
        .def_byte_start = span.start,
        .def_byte_end = span.end,
        .def_line = lc.line,
        .def_col = lc.col,
        .is_slab_backed = false,
        .def_ast_node_id = node_id,
    });

    // If init is a container_decl (struct/union/enum), recurse into its members
    // with the new container_path so nested fns get correctly qualified.
    if (vd.ast.init_node.unwrap()) |init_node| {
        var buf: [2]Node.Index = undefined;
        if (w.tree.fullContainerDecl(&buf, init_node)) |cd| {
            const new_path = if (container_path.len == 0)
                try w.palloc.dupe(u8, name)
            else
                try std.fmt.allocPrint(w.palloc, "{s}.{s}", .{ container_path, name });

            const cd_node_id = try emitNode(w, KIND_CONTAINER_DECL, init_node, node_id);
            for (cd.ast.members) |member| {
                try walkContainerMember(w, member, cd_node_id, new_path);
            }
        } else {
            // Non-container init: walk it as expression to catch calls.
            try walkExpr(w, init_node, node_id);
        }
    }
}

// ── Expression traversal: descend through fn bodies, control flow, calls ──

fn walkExpr(w: *Walker, idx: Node.Index, parent_id: ?u64) anyerror!void {
    const tag = w.tree.nodeTag(idx);

    switch (tag) {
        .block, .block_two, .block_semicolon, .block_two_semicolon => {
            const node_id = try emitNode(w, KIND_BLOCK, idx, parent_id);
            var buf: [2]Node.Index = undefined;
            if (w.tree.blockStatements(&buf, idx)) |stmts| {
                for (stmts) |s| try walkExpr(w, s, node_id);
            }
        },
        .if_simple, .@"if" => {
            const node_id = try emitNode(w, KIND_IF, idx, parent_id);
            const if_full = w.tree.fullIf(idx).?;
            try walkExpr(w, if_full.ast.cond_expr, node_id);
            try walkExpr(w, if_full.ast.then_expr, node_id);
            if (if_full.ast.else_expr.unwrap()) |e| try walkExpr(w, e, node_id);
        },
        .while_simple, .while_cont, .@"while" => {
            const node_id = try emitNode(w, KIND_WHILE, idx, parent_id);
            const wh = w.tree.fullWhile(idx).?;
            try walkExpr(w, wh.ast.cond_expr, node_id);
            if (wh.ast.cont_expr.unwrap()) |c| try walkExpr(w, c, node_id);
            try walkExpr(w, wh.ast.then_expr, node_id);
            if (wh.ast.else_expr.unwrap()) |e| try walkExpr(w, e, node_id);
        },
        .for_simple, .@"for" => {
            const node_id = try emitNode(w, KIND_FOR, idx, parent_id);
            const f = w.tree.fullFor(idx).?;
            for (f.ast.inputs) |i| try walkExpr(w, i, node_id);
            try walkExpr(w, f.ast.then_expr, node_id);
            if (f.ast.else_expr.unwrap()) |e| try walkExpr(w, e, node_id);
        },
        .@"switch", .switch_comma => {
            const node_id = try emitNode(w, KIND_SWITCH, idx, parent_id);
            const sw = w.tree.fullSwitch(idx).?;
            try walkExpr(w, sw.ast.condition, node_id);
            for (sw.ast.cases) |c| try walkExpr(w, c, node_id);
        },
        .switch_case_one, .switch_case, .switch_case_inline, .switch_case_inline_one => {
            const node_id = try emitNode(w, KIND_SWITCH_PRONG, idx, parent_id);
            const sc = w.tree.fullSwitchCase(idx).?;
            try walkExpr(w, sc.ast.target_expr, node_id);
        },
        .call, .call_one, .call_one_comma, .call_comma => {
            _ = try emitNode(w, KIND_CALL, idx, parent_id);
            // Call args walked in slice C if needed.
        },
        .builtin_call, .builtin_call_two, .builtin_call_comma, .builtin_call_two_comma => {
            _ = try emitNode(w, KIND_BUILTIN_CALL, idx, parent_id);
        },
        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            // Local vars inside fn bodies — walk for nested calls in init.
            try emitVarConst(w, idx, parent_id, "");
        },
        .@"return" => {
            const node_id = try emitNode(w, KIND_RETURN, idx, parent_id);
            if (w.tree.nodeData(idx).opt_node.unwrap()) |e| try walkExpr(w, e, node_id);
        },
        .@"defer" => {
            const node_id = try emitNode(w, KIND_DEFER, idx, parent_id);
            try walkExpr(w, w.tree.nodeData(idx).node, node_id);
        },
        .@"errdefer" => {
            const node_id = try emitNode(w, KIND_ERRDEFER, idx, parent_id);
            try walkExpr(w, w.tree.nodeData(idx).opt_token_and_node[1], node_id);
        },

        // Binary expressions where data is `node_and_node`: descend both sides.
        .equal_equal, .bang_equal, .less_than, .greater_than, .less_or_equal, .greater_or_equal,
        .add, .add_wrap, .add_sat, .sub, .sub_wrap, .sub_sat, .mul, .mul_wrap, .mul_sat,
        .div, .mod, .bool_and, .bool_or, .bit_and, .bit_or, .bit_xor, .shl, .shl_sat, .shr,
        .array_access, .array_cat, .array_mult, .@"catch", .@"orelse",
        .assign, .assign_add, .assign_sub, .assign_mul, .assign_div, .assign_mod,
        .assign_bit_and, .assign_bit_or, .assign_bit_xor, .assign_shl, .assign_shr,
        .assign_add_wrap, .assign_sub_wrap, .assign_mul_wrap,
        .assign_add_sat, .assign_sub_sat, .assign_mul_sat, .assign_shl_sat,
        .merge_error_sets, .error_union,
        => {
            const data = w.tree.nodeData(idx);
            try walkExpr(w, data.node_and_node[0], parent_id);
            try walkExpr(w, data.node_and_node[1], parent_id);
        },

        // Unary tagged with `node`: descend the operand.
        .negation, .negation_wrap, .bit_not, .bool_not, .address_of, .deref,
        .optional_type,
        => {
            try walkExpr(w, w.tree.nodeData(idx).node, parent_id);
        },

        // Tags with `node_and_token` data: walk the lhs node only.
        .field_access, .unwrap_optional, .grouped_expression => {
            try walkExpr(w, w.tree.nodeData(idx).node_and_token[0], parent_id);
        },

        .@"comptime", .@"nosuspend" => {
            try walkExpr(w, w.tree.nodeData(idx).node, parent_id);
        },

        // Container init (struct{}, [_]T{}, etc.) — descend into init values for calls.
        .struct_init_one, .struct_init_one_comma, .struct_init, .struct_init_comma,
        .struct_init_dot_two, .struct_init_dot_two_comma, .struct_init_dot, .struct_init_dot_comma,
        .array_init_one, .array_init_one_comma, .array_init, .array_init_comma,
        .array_init_dot_two, .array_init_dot_two_comma, .array_init_dot, .array_init_dot_comma,
        => {
            // Skip for slice B; nested calls in initializer expressions can wait.
        },

        // Anonymous container_decls in expression position (e.g. return struct {...})
        .container_decl, .container_decl_trailing, .container_decl_arg, .container_decl_arg_trailing,
        .container_decl_two, .container_decl_two_trailing,
        .tagged_union, .tagged_union_trailing, .tagged_union_two, .tagged_union_two_trailing,
        .tagged_union_enum_tag, .tagged_union_enum_tag_trailing,
        => {
            const node_id = try emitNode(w, KIND_CONTAINER_DECL, idx, parent_id);
            var buf: [2]Node.Index = undefined;
            if (w.tree.fullContainerDecl(&buf, idx)) |cd| {
                for (cd.ast.members) |member| {
                    try walkContainerMember(w, member, node_id, "");
                }
            }
        },

        else => {
            // Unrecognized tag — skip silently. This means some calls may not be
            // captured (e.g. inside @asm operands, anonymous lambdas, etc.).
            // Acceptable for slice B; refine in later slices.
        },
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn buildQname(w: *Walker, container_path: []const u8, name: []const u8) ![]const u8 {
    if (w.module_qname.len == 0) {
        if (container_path.len == 0) {
            return try w.palloc.dupe(u8, name);
        }
        return try std.fmt.allocPrint(w.palloc, "{s}.{s}", .{ container_path, name });
    }
    if (container_path.len == 0) {
        return try std.fmt.allocPrint(w.palloc, "{s}.{s}", .{ w.module_qname, name });
    }
    return try std.fmt.allocPrint(w.palloc, "{s}.{s}.{s}", .{ w.module_qname, container_path, name });
}

const ByteSpan = struct { start: u32, end: u32 };

fn nodeByteSpan(tree: *const Ast, node: Node.Index) ByteSpan {
    const first_tok = tree.firstToken(node);
    const last_tok = tree.lastToken(node);
    const start = tree.tokenStart(first_tok);
    const end_start = tree.tokenStart(last_tok);
    const end_slice = tree.tokenSlice(last_tok);
    return .{
        .start = start,
        .end = end_start + @as(u32, @intCast(end_slice.len)),
    };
}

const LineCol = struct { line: u32, col: u32 };

fn byteToLineCol(source: []const u8, byte: u32) LineCol {
    var line: u32 = 1;
    var col: u32 = 1;
    var i: usize = 0;
    while (i < byte and i < source.len) : (i += 1) {
        if (source[i] == '\n') {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    return .{ .line = line, .col = col };
}
