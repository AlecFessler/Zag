// Kernel AST walker.
//
// Recursively scans every `*.zig` file under `kernel_root` and emits one
// `AstFunction` per function declaration — top-level fns, methods inside
// struct/union/enum decls, and nested fns inside other fns. The qualified
// name format mirrors what the Zig compiler emits as the IR symbol /
// linkage name:
//
//     <module_path>.<container_path>.<fn_name>
//
// where `module_path` is derived from the file path (`kernel/memory/pmm.zig`
// → `memory.pmm`) and `container_path` is the chain of struct-like
// containers nesting the function. For top-level fns the container_path is
// empty.
//
// Files under `/usr/lib/zig/` (compiler builtins like `ubsan_rt.zig` that
// the kernel pulls in) are also walked — we strip the `/usr/lib/zig/` prefix
// (or `/usr/lib/zig/std/` for std modules) so the module path matches the
// IR's emission.

const std = @import("std");

const types = @import("../types.zig");

pub const FieldType = types.FieldType;
pub const StructTypeInfo = types.StructTypeInfo;
pub const ParamInfo = types.ParamInfo;
pub const ReexportAlias = types.ReexportAlias;

pub const AstFunction = struct {
    name: []const u8,
    qualified_name: []const u8,
    file: []const u8,
    line_start: u32,
    line_end: u32,
    is_pub: bool,
    /// AST node index of the fn_decl. 0 if not available (e.g., proto only).
    fn_node: u32 = 0,
    /// Local binding name of the first parameter when it has a struct-receiver
    /// shape (e.g. `self`, `this`, `lock`). Empty when there is no first param
    /// or its shape isn't recognizable. Paired with `receiver_type` by the
    /// resolver in `branches.emitCall` to turn `self.method()` calls into a
    /// fully-qualified candidate.
    receiver_name: []const u8 = "",
    /// Qualified name of the first parameter's type, when it points at a
    /// struct decl visible in the enclosing container chain. For
    /// `self: *SpinLock` declared inside `const SpinLock = struct {...}` in
    /// `kernel/utils/sync.zig`, this is `utils.sync.SpinLock`. Empty when the
    /// type isn't resolvable to a concrete container.
    receiver_type: []const u8 = "",
    /// Parameter list in declaration order. Used by join.zig's all-callers-
    /// agree pass to detect fn-pointer parameters and substitute their
    /// statically-known argument values into the AST-only inline body's
    /// intra. Empty when the proto had no params.
    params: []const ParamInfo = &.{},
};

/// Per-file map: local binding name → resolved module path. Built by
/// scanning each file's top-level `const X = @import(...)` /
/// `const X = some.chain;` decls. The resolved path is in the same
/// dotted module-path form the AST walker emits as `qualified_name`'s
/// prefix (e.g. `memory.pmm`, `arch.dispatch`, `std`, `builtin`). Used by
/// branches.zig to turn `Foo.bar(...)` calls into a global qname candidate.
pub const ImportTable = std.StringHashMap([]const u8);

/// Per-file parsed AST + source bytes. The branches builder needs both to
/// resolve node tags, token locations, and slice condition source.
pub const FileAst = struct {
    file: []const u8,
    source: [:0]const u8,
    tree: *std.zig.Ast,
    imports: ImportTable,
};

pub const WalkResult = struct {
    fns: []AstFunction,
    asts: []FileAst,
    /// Per-struct field-type tables built while walking each container_decl.
    /// Indexed by struct qname downstream in join.zig. Populated for every
    /// container the walker descends into; structs whose fields all fail to
    /// resolve are still emitted with an empty `fields` slice (cheaper than
    /// gating the entry on having at least one resolvable field).
    struct_types: []StructTypeInfo,
    /// Top-level `pub const X = some.dotted.chain;` re-export aliases. Built
    /// in a post-walk pass against each file's import table. Indexed
    /// downstream as `<file_module>.<X>` → resolved qname so the receiver-
    /// chain resolver can rewrite candidates whose prefix is a re-export
    /// (e.g. `utils.sync.SpinLock.lockIrqSave` → `utils.sync.spin_lock.SpinLock.lockIrqSave`).
    aliases: []ReexportAlias,
};

pub fn walkKernel(arena: std.mem.Allocator, kernel_root: []const u8) ![]AstFunction {
    const r = try walkKernelFull(arena, kernel_root);
    return r.fns;
}

pub fn walkKernelFull(arena: std.mem.Allocator, kernel_root: []const u8) !WalkResult {
    var results = std.ArrayList(AstFunction){};
    var asts = std.ArrayList(FileAst){};
    var struct_types = std.ArrayList(StructTypeInfo){};

    // Walk the kernel sources first.
    try walkRoot(arena, kernel_root, &results, &asts, &struct_types);

    // Also walk the Zig stdlib + ubsan_rt so compiler-builtin functions
    // (`ubsan_rt.handler`, `fmt.format.X`, etc.) can be enriched too.
    walkRoot(arena, "/usr/lib/zig", &results, &asts, &struct_types) catch |err| {
        std.debug.print("warning: skipping /usr/lib/zig walk: {s}\n", .{@errorName(err)});
    };

    const aliases = try buildAliasIndex(arena, asts.items);

    return .{
        .fns = try results.toOwnedSlice(arena),
        .asts = try asts.toOwnedSlice(arena),
        .struct_types = try struct_types.toOwnedSlice(arena),
        .aliases = aliases,
    };
}

/// Scan every parsed file's top-level decls. For each `pub const X = expr;`
/// (or non-pub — both are visible to the qname-rewrite logic) where `expr` is
/// a dotted chain that resolves through the file's import table, emit an
/// alias entry. The key is `<file_module>.<X>` (the user-form qname) and the
/// value is the resolved chain (the underlying-target qname).
///
/// Self-named index files (`<dir>/<dir>.zig`) get *two* alias entries: one
/// keyed by the literal file module path (e.g. `utils.sync.sync.X`) and one
/// keyed by the user-facing collapsed form (`utils.sync.X`). The collapsed
/// form is the spelling that downstream candidates carry, since the rest of
/// the receiver-resolver and the `zag.` strip both treat self-named index
/// files as accessible without the duplicated segment.
///
/// Skipped:
///   * RHS shapes that aren't a chain of `.field_access` / `identifier`
///     nodes (e.g. struct expressions, calls, integer literals).
///   * Chains whose head doesn't resolve through `imports` (drop silently).
///
/// First-write-wins on duplicate keys (rare; would require two files at the
/// same module path emitting the same `pub const X`).
fn buildAliasIndex(
    arena: std.mem.Allocator,
    files: []const FileAst,
) ![]ReexportAlias {
    var seen = std.StringHashMap(void).init(arena);
    var out = std.ArrayList(ReexportAlias){};
    for (files) |fa| {
        const file_mod = filePathToModulePath(arena, fa.file) catch continue;
        if (file_mod.len == 0) continue;
        // Collapsed form for `<dir>/<dir>.zig` files: drop the final
        // duplicate segment so `utils.sync.sync` becomes `utils.sync`.
        // This matches how user-side imports through `zag.utils.sync` see
        // these index files (the `zag.` strip + import-table resolution
        // never produces the duplicated segment).
        const collapsed_mod = collapseSelfNamedIndex(file_mod);
        const root_decls = fa.tree.rootDecls();
        for (root_decls) |decl| {
            const tag = fa.tree.nodeTag(decl);
            switch (tag) {
                .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {},
                else => continue,
            }
            const vd = fa.tree.fullVarDecl(decl) orelse continue;
            const init_node = vd.ast.init_node.unwrap() orelse continue;

            // Only `.field_access` (dotted chains, length >= 2) qualify as a
            // re-export — a bare `.identifier` RHS would be a single-token
            // alias whose key would just shadow the import-table entry; the
            // existing import-resolution code handles those without help.
            const init_tag = fa.tree.nodeTag(init_node);
            if (init_tag != .field_access) continue;

            const chain = nodeChainSource(fa.tree, init_node) orelse continue;
            const resolved = (resolveDottedChain(arena, chain, &fa.imports) catch continue) orelse continue;
            if (resolved.len == 0) continue;

            const name_token = vd.ast.mut_token + 1;
            const name = fa.tree.tokenSlice(name_token);
            if (name.len == 0) continue;

            try emitAliasEntry(arena, &seen, &out, file_mod, name, resolved);
            if (collapsed_mod.len != file_mod.len) {
                try emitAliasEntry(arena, &seen, &out, collapsed_mod, name, resolved);
            }
        }
    }
    return out.toOwnedSlice(arena);
}

/// Append one alias entry, deduping by key. Skips self-aliasing and
/// duplicate keys silently.
fn emitAliasEntry(
    arena: std.mem.Allocator,
    seen: *std.StringHashMap(void),
    out: *std.ArrayList(ReexportAlias),
    module_path: []const u8,
    name: []const u8,
    target: []const u8,
) !void {
    const key = try std.fmt.allocPrint(arena, "{s}.{s}", .{ module_path, name });
    if (std.mem.eql(u8, key, target)) return;
    const gop = try seen.getOrPut(key);
    if (gop.found_existing) return;
    try out.append(arena, .{ .key = key, .target = target });
}

/// If `module_path` ends with a duplicated last-segment (`a.b.b` shape, the
/// file-path translation of `<dir>/<dir>.zig`), return the collapsed form
/// (`a.b`). Otherwise return the input unchanged. Pure-function — slices the
/// input directly when possible.
fn collapseSelfNamedIndex(module_path: []const u8) []const u8 {
    // Find the last two segments. We need the path to have at least two
    // dot-separated components for collapsing to apply.
    const last_dot = std.mem.lastIndexOfScalar(u8, module_path, '.') orelse return module_path;
    const last_seg = module_path[last_dot + 1 ..];
    const prefix = module_path[0..last_dot];
    const second_last_dot = std.mem.lastIndexOfScalar(u8, prefix, '.');
    const second_last_seg = if (second_last_dot) |d| prefix[d + 1 ..] else prefix;
    if (!std.mem.eql(u8, last_seg, second_last_seg)) return module_path;
    return prefix;
}

fn walkRoot(
    arena: std.mem.Allocator,
    root: []const u8,
    results: *std.ArrayList(AstFunction),
    asts: *std.ArrayList(FileAst),
    struct_types: *std.ArrayList(StructTypeInfo),
) !void {
    const abs_root = std.fs.realpathAlloc(arena, root) catch |err| {
        std.debug.print("warning: could not resolve root '{s}': {s}\n", .{ root, @errorName(err) });
        return;
    };

    var dir = std.fs.openDirAbsolute(abs_root, .{ .iterate = true }) catch |err| {
        std.debug.print("warning: could not open root '{s}': {s}\n", .{ abs_root, @errorName(err) });
        return;
    };
    defer dir.close();

    var walker = try dir.walk(arena);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;
        if (std.mem.endsWith(u8, entry.path, "_test.zig")) continue;
        if (std.mem.startsWith(u8, entry.path, "tests/")) continue;
        if (std.mem.indexOf(u8, entry.path, "/tests/") != null) continue;

        // Compose absolute file path.
        const abs_file = try std.fs.path.join(arena, &.{ abs_root, entry.path });

        try walkFile(arena, abs_file, results, asts, struct_types);
    }
}

fn walkFile(
    arena: std.mem.Allocator,
    abs_file: []const u8,
    out: *std.ArrayList(AstFunction),
    asts: *std.ArrayList(FileAst),
    struct_types: *std.ArrayList(StructTypeInfo),
) !void {
    const file = std.fs.openFileAbsolute(abs_file, .{}) catch |err| {
        std.debug.print("warning: skip {s}: {s}\n", .{ abs_file, @errorName(err) });
        return;
    };
    defer file.close();

    const stat = file.stat() catch |err| {
        std.debug.print("warning: skip {s}: {s}\n", .{ abs_file, @errorName(err) });
        return;
    };
    if (stat.size > 16 * 1024 * 1024) {
        std.debug.print("warning: skip {s}: file too large\n", .{abs_file});
        return;
    }

    // Read the whole file into a sentinel-terminated buffer for the parser.
    const src_buf = arena.allocSentinel(u8, @intCast(stat.size), 0) catch |err| {
        std.debug.print("warning: skip {s}: {s}\n", .{ abs_file, @errorName(err) });
        return;
    };
    const n = file.readAll(src_buf) catch |err| {
        std.debug.print("warning: skip {s}: {s}\n", .{ abs_file, @errorName(err) });
        return;
    };
    if (n != src_buf.len) {
        std.debug.print("warning: skip {s}: short read\n", .{abs_file});
        return;
    }

    const tree_box = try arena.create(std.zig.Ast);
    tree_box.* = std.zig.Ast.parse(arena, src_buf, .zig) catch |err| {
        std.debug.print("warning: skip {s}: parse error {s}\n", .{ abs_file, @errorName(err) });
        return;
    };
    // Don't deinit; we let the arena own everything.

    if (tree_box.errors.len != 0) {
        // Report but continue — partial AST may still yield useful fns.
        // Don't spam: just log a single line with the error count.
        // (The first error is usually the most useful but rendering it
        // requires Writer plumbing we don't need here.)
    }

    const module_path = filePathToModulePath(arena, abs_file) catch |err| {
        std.debug.print("warning: skip {s}: module-path build failed {s}\n", .{ abs_file, @errorName(err) });
        return;
    };

    const root_decls = tree_box.rootDecls();

    // Import table is built before decl walking so emitFn's receiver-type
    // resolver can look up dotted type expressions (`*sync.SpinLock`)
    // through the file's imports while emitting AstFunction records.
    const imports = buildImportTable(arena, tree_box, abs_file, root_decls) catch
        ImportTable.init(arena);

    var ctx = WalkCtx{
        .arena = arena,
        .tree = tree_box,
        .file_abs = abs_file,
        .module_path = module_path,
        .imports = &imports,
        .out = out,
        .struct_types = struct_types,
    };
    // Collect any file-level field decls (rare; some files use the
    // file-as-struct pattern with top-level fields) into a StructTypeInfo
    // keyed by the file's module path. The receiver-type code already
    // recognizes that pattern, so a chain like `self.field.method()` against
    // a file-as-struct receiver can resolve through this table.
    try collectFieldsForContainer(&ctx, ctx.module_path, root_decls, "");
    for (root_decls) |decl| {
        try walkDecl(&ctx, decl, "");
    }

    try asts.append(arena, .{
        .file = abs_file,
        .source = src_buf,
        .tree = tree_box,
        .imports = imports,
    });
}

const WalkCtx = struct {
    arena: std.mem.Allocator,
    tree: *std.zig.Ast,
    file_abs: []const u8,
    module_path: []const u8,
    /// File-local import table used by `computeReceiver` to resolve dotted
    /// receiver-type expressions (e.g. `*sync.SpinLock`) into a qname.
    /// Pointer is stable for the life of the walk.
    imports: *const ImportTable,
    out: *std.ArrayList(AstFunction),
    /// Output sink for struct field-type tables collected as the walker
    /// descends into container_decls. Receiver-chain resolution in
    /// branches.zig consults this via a qname-keyed index.
    struct_types: *std.ArrayList(StructTypeInfo),
};

/// Walk a single decl node. `container_path` is the dotted chain of nesting
/// container names (e.g., "Foo.Bar"); empty at file top level.
fn walkDecl(ctx: *WalkCtx, node: std.zig.Ast.Node.Index, container_path: []const u8) anyerror!void {
    const tag = ctx.tree.nodeTag(node);
    switch (tag) {
        .fn_decl, .fn_proto, .fn_proto_simple, .fn_proto_multi, .fn_proto_one => {
            try emitFn(ctx, node, container_path);
        },
        .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
            try walkVarDecl(ctx, node, container_path);
        },
        .test_decl => {
            // test blocks: ignore at decl level; their bodies don't contribute
            // to the IR-callable fn set we're trying to enrich.
        },
        else => {},
    }
}

/// If a var_decl's RHS is a struct/union/enum/opaque container, recurse into
/// its members with an extended container path.
fn walkVarDecl(ctx: *WalkCtx, node: std.zig.Ast.Node.Index, container_path: []const u8) anyerror!void {
    const vd = ctx.tree.fullVarDecl(node) orelse return;
    const init_node = vd.ast.init_node.unwrap() orelse return;

    // The decl name is the token immediately after the mut token (`const`/`var`).
    const name_token = vd.ast.mut_token + 1;
    const name = ctx.tree.tokenSlice(name_token);

    // Recurse into the init expression looking for container_decls. The init
    // can be wrapped (e.g. `extern struct { ... }` is still a container_decl,
    // but `packed struct(u32) { ... }` is container_decl_arg). Other wrappers
    // (e.g. `if (x) struct {...} else struct {...}`) are rare enough we don't
    // chase them here.
    try recurseIntoTypeExpr(ctx, init_node, name, container_path);
}

/// Walk an expression node looking for container_decls and emit / recurse on
/// any nested fns we find. `decl_name` is the name of the surrounding decl
/// (used to extend the container_path when we descend into a container).
fn recurseIntoTypeExpr(
    ctx: *WalkCtx,
    node: std.zig.Ast.Node.Index,
    decl_name: []const u8,
    container_path: []const u8,
) anyerror!void {
    var buf: [2]std.zig.Ast.Node.Index = undefined;
    if (ctx.tree.fullContainerDecl(&buf, node)) |cd| {
        const new_container = if (container_path.len == 0)
            try ctx.arena.dupe(u8, decl_name)
        else
            try std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ container_path, decl_name });
        // Compose the full qname (including module path) for the field-type
        // index so cross-file lookups succeed.
        const struct_qname = try std.fmt.allocPrint(
            ctx.arena,
            "{s}.{s}",
            .{ ctx.module_path, new_container },
        );
        try collectFieldsForContainer(ctx, struct_qname, cd.ast.members, new_container);
        for (cd.ast.members) |member| {
            try walkDecl(ctx, member, new_container);
        }
    }
    // We deliberately don't chase arbitrary expressions here — the common
    // case is `const Foo = struct { ... };` which the fullContainerDecl
    // probe handles.
}

/// Build and emit a StructTypeInfo for one container's members. `struct_qname`
/// is the full dotted qname (`<module>.<container_path>` form) used to index
/// the table downstream. `container_path` is the relative container chain
/// inside the file — needed when a field type resolves to a same-file sibling
/// (Case 3b in computeReceiver).
fn collectFieldsForContainer(
    ctx: *WalkCtx,
    struct_qname: []const u8,
    members: []const std.zig.Ast.Node.Index,
    container_path: []const u8,
) anyerror!void {
    var fields = std.ArrayList(FieldType){};
    for (members) |member| {
        const tag = ctx.tree.nodeTag(member);
        const is_field = switch (tag) {
            .container_field, .container_field_init, .container_field_align => true,
            else => false,
        };
        if (!is_field) continue;

        const cf = ctx.tree.fullContainerField(member) orelse continue;
        // Skip tuple-like fields (no real name we can match against).
        if (cf.ast.tuple_like) continue;

        const name_tok = cf.ast.main_token;
        const field_name = ctx.tree.tokenSlice(name_tok);
        if (field_name.len == 0) continue;

        const type_node_opt = cf.ast.type_expr.unwrap() orelse continue;
        const type_qname = resolveFieldTypeQname(ctx, type_node_opt, container_path) catch "";
        try fields.append(ctx.arena, .{
            .field_name = try ctx.arena.dupe(u8, field_name),
            .type_qname = type_qname,
        });
    }
    if (fields.items.len == 0) return;
    try ctx.struct_types.append(ctx.arena, .{
        .qname = try ctx.arena.dupe(u8, struct_qname),
        .fields = try fields.toOwnedSlice(ctx.arena),
    });
}

/// Resolve a field's type expression to a bare struct qname, mirroring the
/// rules `computeReceiver` uses for first-param types. Empty string when the
/// type isn't resolvable (anytype, anonymous struct expressions, generic
/// params, slices/arrays, etc).
fn resolveFieldTypeQname(
    ctx: *WalkCtx,
    type_node: std.zig.Ast.Node.Index,
    container_path: []const u8,
) ![]const u8 {
    const src = nodeSourceSlice(ctx.tree, type_node);
    if (src.len == 0) return "";
    const stripped = stripPointerOptional(src);
    if (stripped.len == 0) return "";

    // `@This()` — same-container shortcut.
    if (std.mem.eql(u8, stripped, "@This()")) {
        return containerQName(ctx.arena, ctx.module_path, container_path);
    }

    // Bare type name matching the immediate-enclosing container's last
    // segment — same-container self-reference.
    const immediate = lastSegment(container_path);
    if (immediate.len > 0 and std.mem.eql(u8, stripped, immediate)) {
        return containerQName(ctx.arena, ctx.module_path, container_path);
    }

    // Bare type name matching the file's own last segment (file-as-struct).
    if (container_path.len == 0) {
        const file_seg = lastSegment(ctx.module_path);
        if (file_seg.len > 0 and std.mem.eql(u8, stripped, file_seg)) {
            return ctx.arena.dupe(u8, ctx.module_path);
        }
    }

    // Dotted chain via the file's import table.
    if (looksLikeDottedChain(stripped)) {
        if (try resolveDottedChain(ctx.arena, stripped, ctx.imports)) |q| {
            if (q.len > 0) return q;
        }
        return "";
    }

    // Bare unqualified type that didn't match any same-file pattern. Before
    // falling back to `<module_path>.<name>`, consult the file's import table
    // — if `stripped` is the local binding for an `@import(...)` or a
    // re-export alias, the import table already maps it to the resolved
    // module path. Without this step `lock: SpinLock` (where `SpinLock` is
    // `const SpinLock = zag.utils.sync.SpinLock;`) would resolve to the
    // wrong same-file qname instead of `utils.sync.SpinLock`.
    if (isBareIdent(stripped)) {
        if (ctx.imports.get(stripped)) |q| {
            return ctx.arena.dupe(u8, q);
        }
        if (ctx.module_path.len > 0) {
            return std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ ctx.module_path, stripped });
        }
    }

    return "";
}

fn emitFn(
    ctx: *WalkCtx,
    node: std.zig.Ast.Node.Index,
    container_path: []const u8,
) anyerror!void {
    var proto_buf: [1]std.zig.Ast.Node.Index = undefined;
    const fn_proto = ctx.tree.fullFnProto(&proto_buf, node) orelse return;
    const name_tok = fn_proto.name_token orelse return;
    const name = ctx.tree.tokenSlice(name_tok);

    const fn_token = fn_proto.ast.fn_token;
    const start_loc = ctx.tree.tokenLocation(0, fn_token);
    const line_start: u32 = @intCast(start_loc.line + 1);

    const last_tok = ctx.tree.lastToken(node);
    const end_loc = ctx.tree.tokenLocation(0, last_tok);
    const line_end: u32 = @intCast(end_loc.line + 1);

    const qualified = if (container_path.len == 0)
        try std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ ctx.module_path, name })
    else
        try std.fmt.allocPrint(ctx.arena, "{s}.{s}.{s}", .{ ctx.module_path, container_path, name });

    const is_pub = fn_proto.visib_token != null;

    const recv = computeReceiver(ctx, fn_proto, container_path);

    const params = collectParams(ctx, fn_proto) catch &.{};

    try ctx.out.append(ctx.arena, .{
        .name = try ctx.arena.dupe(u8, name),
        .qualified_name = qualified,
        .file = ctx.file_abs,
        .line_start = line_start,
        .line_end = line_end,
        .is_pub = is_pub,
        .fn_node = @intFromEnum(node),
        .receiver_name = recv.name,
        .receiver_type = recv.type_qname,
        .params = params,
    });

    // Recurse into the body so nested struct decls and inner fns are picked up.
    // If this fn returns a container (the `fn Foo(...) type { return struct {...} }`
    // pattern), the returned struct's members get a container path extended by
    // this fn's name. Plain nested structs inside the body get the same
    // treatment (rare but allowed).
    if (ctx.tree.nodeTag(node) == .fn_decl) {
        const body_node = ctx.tree.nodeData(node).node_and_node[1];
        const inner_container = if (container_path.len == 0)
            try ctx.arena.dupe(u8, name)
        else
            try std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ container_path, name });
        try walkBlock(ctx, body_node, inner_container);
    }
}

// ---------------------------------------------------------------- params

/// Iterate the fn proto's parameters in declaration order and emit one
/// ParamInfo per param. The `is_fn_ptr` heuristic matches a `fn (` substring
/// in the type's source slice, which catches both `*const fn (...)` pointer
/// types and bare `fn (...)` types. Anonymous (no-name) params and `anytype`
/// produce ParamInfo with an empty name — kept in the slice so positional
/// indexing into caller args still aligns. Skips when the proto has no params.
fn collectParams(
    ctx: *WalkCtx,
    fn_proto: std.zig.Ast.full.FnProto,
) ![]const ParamInfo {
    var list = std.ArrayList(ParamInfo){};
    var it = fn_proto.iterate(ctx.tree);
    while (it.next()) |p| {
        const name_slice: []const u8 = blk: {
            const tok = p.name_token orelse break :blk "";
            break :blk ctx.tree.tokenSlice(tok);
        };
        var is_fn_ptr = false;
        if (p.type_expr) |te| {
            const src = nodeSourceSlice(ctx.tree, te);
            // Match `fn (` (Zig style) or `fn(` (no space) — both forms
            // appear in the kernel. The substring check is good enough; we
            // never falsely classify a non-fn type as a fn pointer because
            // `fn` isn't a keyword usable in struct/integer/slice forms.
            if (std.mem.indexOf(u8, src, "fn (") != null or
                std.mem.indexOf(u8, src, "fn(") != null)
            {
                is_fn_ptr = true;
            }
        }
        try list.append(ctx.arena, .{
            .name = try ctx.arena.dupe(u8, name_slice),
            .is_fn_ptr = is_fn_ptr,
        });
    }
    return list.toOwnedSlice(ctx.arena);
}

// ---------------------------------------------------------------- receiver

const ReceiverInfo = struct {
    name: []const u8 = "",
    type_qname: []const u8 = "",
};

/// Compute the receiver-binding name and resolved type qname for the first
/// parameter of a function, when it has a struct-receiver shape. Used by
/// `branches.emitCall` to resolve `<binding>.method()` calls. Cases handled:
///
///  1. `self: *T` / `self: T` / `self: *const T` / `self: ?*T` where T is the
///     immediately-enclosing container's name — the canonical pattern for
///     methods declared inside `const T = struct { ... }`.
///  1b. File-as-struct: top-level functions of a file like `Io/Writer.zig`
///      whose first param is `*Writer`. The file itself is a container, so
///      the receiver type is the file's module path.
///  2. `self: *@This()` — `@This()` resolves to the immediately-enclosing
///     container (file or struct).
///  3. Dotted chain (`*sync.SpinLock`) whose leftmost identifier is in the
///     file's import table — the resolved chain is the receiver qname.
///  3b. Bare unqualified type that doesn't match the immediate container —
///      treated as a same-file sibling type. The resolver in
///      `branches.emitCall` will silently miss the qname index lookup if
///      the type doesn't actually exist there.
///
/// Anything else (anytype, `comptime T: type`, `[]Foo`, complex generic
/// expressions) yields empty fields, leaving those calls to the indirect
/// fallback.
fn computeReceiver(
    ctx: *WalkCtx,
    fn_proto: std.zig.Ast.full.FnProto,
    container_path: []const u8,
) ReceiverInfo {
    var it = fn_proto.iterate(ctx.tree);
    const first = it.next() orelse return .{};

    const name_tok = first.name_token orelse return .{};
    const binding = ctx.tree.tokenSlice(name_tok);
    if (binding.len == 0) return .{};

    const type_node = first.type_expr orelse return .{};

    const type_src = nodeSourceSlice(ctx.tree, type_node);
    if (type_src.len == 0) return .{};

    const stripped = stripPointerOptional(type_src);
    if (stripped.len == 0) return .{};

    // Case 2: `*@This()`.
    if (std.mem.eql(u8, stripped, "@This()")) {
        const qn = containerQName(ctx.arena, ctx.module_path, container_path) catch return .{};
        if (qn.len == 0) return .{};
        return .{
            .name = ctx.arena.dupe(u8, binding) catch return .{},
            .type_qname = qn,
        };
    }

    // Case 1: bare type name matches the immediate-enclosing container's
    // last segment.
    const immediate = lastSegment(container_path);
    if (immediate.len > 0 and std.mem.eql(u8, stripped, immediate)) {
        const qn = containerQName(ctx.arena, ctx.module_path, container_path) catch return .{};
        if (qn.len == 0) return .{};
        return .{
            .name = ctx.arena.dupe(u8, binding) catch return .{},
            .type_qname = qn,
        };
    }

    // Case 1b: file-as-struct. Top-level fns whose first param type matches
    // the file's last path segment (e.g. `*Writer` in `Io/Writer.zig`).
    if (container_path.len == 0) {
        const file_seg = lastSegment(ctx.module_path);
        if (file_seg.len > 0 and std.mem.eql(u8, stripped, file_seg)) {
            return .{
                .name = ctx.arena.dupe(u8, binding) catch return .{},
                .type_qname = ctx.arena.dupe(u8, ctx.module_path) catch return .{},
            };
        }
    }

    // Case 3: dotted chain whose leftmost identifier resolves through imports.
    if (looksLikeDottedChain(stripped)) {
        const resolved = resolveDottedChain(ctx.arena, stripped, ctx.imports) catch null;
        if (resolved) |q| if (q.len > 0) {
            return .{
                .name = ctx.arena.dupe(u8, binding) catch return .{},
                .type_qname = q,
            };
        };
    }

    // Case 3b: bare unqualified type. Before falling back to a same-file
    // sibling lookup, consult the import table — `self: *SpinLock` where
    // `const SpinLock = zag.utils.sync.SpinLock;` should resolve through the
    // import alias, not against `<module_path>.SpinLock`.
    if (isBareIdent(stripped)) {
        if (ctx.imports.get(stripped)) |q| {
            return .{
                .name = ctx.arena.dupe(u8, binding) catch return .{},
                .type_qname = ctx.arena.dupe(u8, q) catch return .{},
            };
        }
        if (ctx.module_path.len > 0) {
            const candidate = std.fmt.allocPrint(
                ctx.arena,
                "{s}.{s}",
                .{ ctx.module_path, stripped },
            ) catch return .{};
            return .{
                .name = ctx.arena.dupe(u8, binding) catch return .{},
                .type_qname = candidate,
            };
        }
    }

    return .{};
}

/// Slice the source text for an arbitrary node. Returns "" on out-of-range.
fn nodeSourceSlice(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) []const u8 {
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    const start = tree.tokenStart(first);
    const last_start = tree.tokenStart(last);
    const last_slice = tree.tokenSlice(last);
    const end: usize = @as(usize, last_start) + last_slice.len;
    if (end <= start or end > tree.source.len) return "";
    return tree.source[start..end];
}

/// Strip leading pointer/optional/sentinel tokens from a type source span.
/// Repeats until no more strippable prefix is found. Returns "" for slice/
/// array forms (`[N]T`, `[]T`, `[*]T`) since their element-method calls
/// can't be resolved through the receiver path anyway.
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
    return s;
}

/// Build the qname `<module_path>.<container_path>` (or just `<module_path>`
/// when container_path is empty).
fn containerQName(
    arena: std.mem.Allocator,
    module_path: []const u8,
    container_path: []const u8,
) ![]const u8 {
    if (container_path.len == 0) return try arena.dupe(u8, module_path);
    return try std.fmt.allocPrint(arena, "{s}.{s}", .{ module_path, container_path });
}

fn lastSegment(path: []const u8) []const u8 {
    if (path.len == 0) return path;
    const dot = std.mem.lastIndexOfScalar(u8, path, '.');
    return if (dot) |d| path[d + 1 ..] else path;
}

fn looksLikeDottedChain(s: []const u8) bool {
    if (s.len == 0) return false;
    return std.mem.indexOfScalar(u8, s, '.') != null and isIdentChars(s);
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

/// Descend an expression looking for container_decls. Handles the common
/// wrappers we see in kernel code:
///   `struct { ... }`                          — container_decl directly
///   `struct { ... }.field`                    — field_access wraps it
///   `(struct { ... })`                        — grouped_expression
///   `if (x) struct {...} else struct {...}`   — both branches checked
///   `&struct {...}`, `try ...`                — single-child unary wrappers
fn recurseExpressionForContainers(
    ctx: *WalkCtx,
    node: std.zig.Ast.Node.Index,
    container_path: []const u8,
) anyerror!void {
    var buf: [2]std.zig.Ast.Node.Index = undefined;
    if (ctx.tree.fullContainerDecl(&buf, node)) |cd| {
        for (cd.ast.members) |member| {
            try walkDecl(ctx, member, container_path);
        }
        return;
    }

    const tag = ctx.tree.nodeTag(node);
    switch (tag) {
        .field_access, .unwrap_optional => {
            // `lhs.field` / `lhs.?` — descend into lhs.
            const lhs = ctx.tree.nodeData(node).node_and_token[0];
            try recurseExpressionForContainers(ctx, lhs, container_path);
        },
        .grouped_expression => {
            // `(expr)` — descend.
            const inner = ctx.tree.nodeData(node).node_and_token[0];
            try recurseExpressionForContainers(ctx, inner, container_path);
        },
        .address_of, .negation, .negation_wrap, .bit_not, .bool_not, .optional_type, .@"try", .@"comptime", .@"nosuspend" => {
            // Single-child unary prefix.
            const inner = ctx.tree.nodeData(node).node;
            try recurseExpressionForContainers(ctx, inner, container_path);
        },
        .if_simple => {
            _, const then_expr = ctx.tree.nodeData(node).node_and_node;
            try recurseExpressionForContainers(ctx, then_expr, container_path);
        },
        .@"if" => {
            _, const extra_index = ctx.tree.nodeData(node).node_and_extra;
            const extra = ctx.tree.extraData(extra_index, std.zig.Ast.Node.If);
            try recurseExpressionForContainers(ctx, extra.then_expr, container_path);
            try recurseExpressionForContainers(ctx, extra.else_expr, container_path);
        },
        .block, .block_two, .block_semicolon, .block_two_semicolon => {
            try walkBlock(ctx, node, container_path);
        },
        else => {},
    }
}

/// Walk a block-like node (fn body, regular block, comptime block contents)
/// looking for nested decls.
fn walkBlock(
    ctx: *WalkCtx,
    node: std.zig.Ast.Node.Index,
    container_path: []const u8,
) anyerror!void {
    // If the body itself is just a single expression that is a container_decl
    // (e.g. inside a `comptime { ... }` or because it's the body of an init
    // expression), treat it as a container.
    var cd_buf: [2]std.zig.Ast.Node.Index = undefined;
    if (ctx.tree.fullContainerDecl(&cd_buf, node)) |cd| {
        for (cd.ast.members) |member| {
            try walkDecl(ctx, member, container_path);
        }
        return;
    }

    var buf: [2]std.zig.Ast.Node.Index = undefined;
    const stmts = ctx.tree.blockStatements(&buf, node) orelse return;
    for (stmts) |stmt| {
        const tag = ctx.tree.nodeTag(stmt);
        switch (tag) {
            .fn_decl, .fn_proto, .fn_proto_simple, .fn_proto_multi, .fn_proto_one => {
                try emitFn(ctx, stmt, container_path);
            },
            .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                try walkVarDecl(ctx, stmt, container_path);
            },
            .block, .block_two, .block_semicolon, .block_two_semicolon => {
                try walkBlock(ctx, stmt, container_path);
            },
            .@"return" => {
                // `return struct { ... }` and `return struct { ... }.field`
                // patterns — the returned container's members are nested under
                // the enclosing fn's name (which the caller already folded
                // into `container_path`).
                if (ctx.tree.nodeData(stmt).opt_node.unwrap()) |expr| {
                    try recurseExpressionForContainers(ctx, expr, container_path);
                }
            },
            else => {},
        }
    }
}

/// Map an absolute source path to the IR-style module path. Strips the
/// kernel-root prefix (or `/usr/lib/zig/[std/]` for compiler builtins),
/// drops the trailing `.zig`, and replaces `/` with `.`.
fn filePathToModulePath(arena: std.mem.Allocator, abs_file: []const u8) ![]const u8 {
    var rel: []const u8 = abs_file;

    const zig_std_prefix = "/usr/lib/zig/std/";
    const zig_root_prefix = "/usr/lib/zig/";
    if (std.mem.startsWith(u8, rel, zig_std_prefix)) {
        rel = rel[zig_std_prefix.len..];
    } else if (std.mem.startsWith(u8, rel, zig_root_prefix)) {
        rel = rel[zig_root_prefix.len..];
    } else {
        // Find "/kernel/" segment and strip up through it.
        if (std.mem.indexOf(u8, rel, "/kernel/")) |i| {
            rel = rel[i + "/kernel/".len ..];
        } else if (std.mem.startsWith(u8, rel, "kernel/")) {
            rel = rel["kernel/".len..];
        }
    }

    if (std.mem.endsWith(u8, rel, ".zig")) {
        rel = rel[0 .. rel.len - ".zig".len];
    }

    const out = try arena.dupe(u8, rel);
    for (out) |*c| {
        if (c.* == '/') c.* = '.';
    }
    return out;
}

// ---------------------------------------------------------------- imports

/// Build the per-file ImportTable from a file's top-level decls. Recognizes:
///   - `const X = @import("std");`               → "std"
///   - `const X = @import("builtin");`           → "builtin"
///   - `const X = @import("zag");`               → "zag"
///   - `const X = @import("rel/path.zig");`      → resolved-relative module path
///   - `const X = some.dotted.chain;`            → resolves chain through prior bindings
///
/// Two passes so chained derivations (`const X = zag.foo.bar;` after `const zag = @import("zag");`)
/// resolve regardless of declaration order. Anything we can't resolve is
/// silently dropped — branches.zig falls back to the raw call source for
/// those.
fn buildImportTable(
    arena: std.mem.Allocator,
    tree: *const std.zig.Ast,
    abs_file: []const u8,
    root_decls: []const std.zig.Ast.Node.Index,
) !ImportTable {
    var table = ImportTable.init(arena);

    // Pass 1: direct @import(...) calls.
    for (root_decls) |decl| {
        const tag = tree.nodeTag(decl);
        switch (tag) {
            .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {},
            else => continue,
        }
        const vd = tree.fullVarDecl(decl) orelse continue;
        const init_node = vd.ast.init_node.unwrap() orelse continue;
        const name_token = vd.ast.mut_token + 1;
        const name = tree.tokenSlice(name_token);

        if (try resolveImportRhs(arena, tree, abs_file, init_node, &table)) |resolved| {
            try table.put(try arena.dupe(u8, name), resolved);
        }
    }

    // Pass 2: dotted-chain derivations. Re-iterate decls until no new
    // resolutions happen — this lets `const X = zag.foo;` resolve even when
    // declared before `const zag = @import("zag");`. Cap at 5 iterations to
    // avoid pathological inputs.
    var iter: u32 = 0;
    while (iter < 5) {
        var added: bool = false;
        for (root_decls) |decl| {
            const tag = tree.nodeTag(decl);
            switch (tag) {
                .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {},
                else => continue,
            }
            const vd = tree.fullVarDecl(decl) orelse continue;
            const init_node = vd.ast.init_node.unwrap() orelse continue;
            const name_token = vd.ast.mut_token + 1;
            const name = tree.tokenSlice(name_token);
            if (table.contains(name)) continue;

            if (try resolveImportRhs(arena, tree, abs_file, init_node, &table)) |resolved| {
                try table.put(try arena.dupe(u8, name), resolved);
                added = true;
            }
        }
        if (!added) break;
        iter += 1;
    }

    return table;
}

/// Try to resolve the RHS of a top-level `const X = ...;` decl into a module
/// path. Returns null if the RHS isn't a recognizable @import or dotted chain
/// against a known binding.
fn resolveImportRhs(
    arena: std.mem.Allocator,
    tree: *const std.zig.Ast,
    abs_file: []const u8,
    rhs: std.zig.Ast.Node.Index,
    table: *const ImportTable,
) !?[]const u8 {
    const tag = tree.nodeTag(rhs);

    // `@import("...")` — builtin_call_two with one arg.
    if (tag == .builtin_call_two or tag == .builtin_call_two_comma) {
        const data = tree.nodeData(rhs);
        const builtin_tok = tree.nodeMainToken(rhs);
        const builtin_name = tree.tokenSlice(builtin_tok);
        if (!std.mem.eql(u8, builtin_name, "@import")) return null;
        const arg_a = data.opt_node_and_opt_node[0].unwrap() orelse return null;
        const arg_tag = tree.nodeTag(arg_a);
        if (arg_tag != .string_literal) return null;
        const str_tok = tree.nodeMainToken(arg_a);
        const raw = tree.tokenSlice(str_tok);
        // Strip surrounding quotes.
        if (raw.len < 2) return null;
        const inner = raw[1 .. raw.len - 1];
        return try resolveImportPath(arena, abs_file, inner);
    }
    if (tag == .builtin_call or tag == .builtin_call_comma) {
        const data = tree.nodeData(rhs);
        const builtin_tok = tree.nodeMainToken(rhs);
        const builtin_name = tree.tokenSlice(builtin_tok);
        if (!std.mem.eql(u8, builtin_name, "@import")) return null;
        const slice = tree.extraDataSlice(data.extra_range, std.zig.Ast.Node.Index);
        if (slice.len != 1) return null;
        const arg_tag = tree.nodeTag(slice[0]);
        if (arg_tag != .string_literal) return null;
        const str_tok = tree.nodeMainToken(slice[0]);
        const raw = tree.tokenSlice(str_tok);
        if (raw.len < 2) return null;
        const inner = raw[1 .. raw.len - 1];
        return try resolveImportPath(arena, abs_file, inner);
    }

    // Dotted chain: `field_access` — `lhs.field`. Walk down to the leftmost
    // identifier; if that identifier resolves through `table`, prepend the
    // resolved module path and append the trailing `.field` chain.
    if (tag == .field_access or tag == .identifier) {
        const chain = nodeChainSource(tree, rhs) orelse return null;
        return try resolveDottedChain(arena, chain, table);
    }

    return null;
}

/// Slice source for an identifier or chain of `.field_access` nodes. Returns
/// null if the node is anything else.
fn nodeChainSource(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) ?[]const u8 {
    const tag = tree.nodeTag(node);
    if (tag != .field_access and tag != .identifier) return null;
    const first_tok = tree.firstToken(node);
    const last_tok = tree.lastToken(node);
    const start = tree.tokenStart(first_tok);
    const last_start = tree.tokenStart(last_tok);
    const last_slice = tree.tokenSlice(last_tok);
    const end: usize = @as(usize, last_start) + last_slice.len;
    if (end <= start or end > tree.source.len) return null;
    return tree.source[start..end];
}

/// Resolve a dotted chain `Head.rest.of.chain` against the given table. If
/// `Head` is in the table, the result is `<table[Head]>.<rest.of.chain>`,
/// with the special case that for `zag` we strip the leading `zag.` (the
/// kernel's re-export root mirrors the kernel directory tree).
fn resolveDottedChain(
    arena: std.mem.Allocator,
    chain: []const u8,
    table: *const ImportTable,
) !?[]const u8 {
    const dot = std.mem.indexOfScalar(u8, chain, '.');
    const head = if (dot) |d| chain[0..d] else chain;
    const tail = if (dot) |d| chain[d + 1 ..] else "";

    const resolved_head = table.get(head) orelse return null;

    // Special case: `zag.<rest>` strips the `zag.` since zag is the
    // self-referencing root re-export. A plain `zag` head keeps the
    // resolved binding's value (which is also the literal "zag").
    if (std.mem.eql(u8, resolved_head, "zag")) {
        if (tail.len == 0) return try arena.dupe(u8, "zag");
        return try arena.dupe(u8, tail);
    }

    if (tail.len == 0) return try arena.dupe(u8, resolved_head);
    return try std.fmt.allocPrint(arena, "{s}.{s}", .{ resolved_head, tail });
}

/// Given an `@import("...")` argument string, produce the matching module
/// path. Special cases for "std" / "builtin" / "zag" / package roots. For
/// relative paths, resolve relative to the importing file's directory, strip
/// the kernel-root prefix, and translate `/` to `.` (matching the IR-style
/// module path filePathToModulePath emits).
fn resolveImportPath(
    arena: std.mem.Allocator,
    abs_importing_file: []const u8,
    import_arg: []const u8,
) !?[]const u8 {
    if (std.mem.eql(u8, import_arg, "std")) return try arena.dupe(u8, "std");
    if (std.mem.eql(u8, import_arg, "builtin")) return try arena.dupe(u8, "builtin");
    if (std.mem.eql(u8, import_arg, "zag")) return try arena.dupe(u8, "zag");

    // Anything that doesn't end in .zig is a named package import (e.g.
    // `@import("kprof")` resolved by build.zig). Best-effort: treat the bare
    // name as the module path. Works for `kprof` and `build_options`.
    if (!std.mem.endsWith(u8, import_arg, ".zig")) {
        return try arena.dupe(u8, import_arg);
    }

    // Relative path — join against the importing file's dir, then strip the
    // kernel prefix and turn into a dotted module path.
    const dir = std.fs.path.dirname(abs_importing_file) orelse return null;
    const joined = try std.fs.path.join(arena, &.{ dir, import_arg });
    // Normalize `..` segments without hitting the filesystem.
    const normalized = normalizePath(arena, joined) catch joined;
    return filePathToModulePath(arena, normalized) catch null;
}

/// Normalize a path string by collapsing `.` and `..` segments. Doesn't touch
/// the filesystem — purely textual.
fn normalizePath(arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    var stack = std.ArrayList([]const u8){};
    defer stack.deinit(arena);
    var it = std.mem.tokenizeScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (stack.items.len > 0) _ = stack.pop();
            continue;
        }
        try stack.append(arena, seg);
    }
    var total: usize = 0;
    for (stack.items) |s| total += s.len + 1;
    const buf = try arena.alloc(u8, total + 1);
    var w: usize = 0;
    if (std.mem.startsWith(u8, path, "/")) {
        buf[w] = '/';
        w += 1;
    }
    for (stack.items, 0..) |s, i| {
        if (i > 0) {
            buf[w] = '/';
            w += 1;
        }
        @memcpy(buf[w .. w + s.len], s);
        w += s.len;
    }
    return buf[0..w];
}

test "filePathToModulePath kernel" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings(
        "memory.pmm",
        try filePathToModulePath(a, "/home/alec/Zag/kernel/memory/pmm.zig"),
    );
    try std.testing.expectEqualStrings(
        "arch.x64.idt",
        try filePathToModulePath(a, "/home/alec/Zag/kernel/arch/x64/idt.zig"),
    );
}

test "filePathToModulePath zig builtins" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings(
        "ubsan_rt",
        try filePathToModulePath(a, "/usr/lib/zig/ubsan_rt.zig"),
    );
    try std.testing.expectEqualStrings(
        "fmt.float",
        try filePathToModulePath(a, "/usr/lib/zig/std/fmt/float.zig"),
    );
}
