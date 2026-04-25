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

pub const AstFunction = struct {
    name: []const u8,
    qualified_name: []const u8,
    file: []const u8,
    line_start: u32,
    line_end: u32,
    is_pub: bool,
};

pub fn walkKernel(arena: std.mem.Allocator, kernel_root: []const u8) ![]AstFunction {
    var results = std.ArrayList(AstFunction){};

    // Walk the kernel sources first.
    try walkRoot(arena, kernel_root, &results);

    // Also walk the Zig stdlib + ubsan_rt so compiler-builtin functions
    // (`ubsan_rt.handler`, `fmt.format.X`, etc.) can be enriched too.
    walkRoot(arena, "/usr/lib/zig", &results) catch |err| {
        std.debug.print("warning: skipping /usr/lib/zig walk: {s}\n", .{@errorName(err)});
    };

    return results.toOwnedSlice(arena);
}

fn walkRoot(
    arena: std.mem.Allocator,
    root: []const u8,
    results: *std.ArrayList(AstFunction),
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

        try walkFile(arena, abs_file, results);
    }
}

fn walkFile(
    arena: std.mem.Allocator,
    abs_file: []const u8,
    out: *std.ArrayList(AstFunction),
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

    var tree = std.zig.Ast.parse(arena, src_buf, .zig) catch |err| {
        std.debug.print("warning: skip {s}: parse error {s}\n", .{ abs_file, @errorName(err) });
        return;
    };
    // Don't deinit; we let the arena own everything.
    _ = &tree;

    if (tree.errors.len != 0) {
        // Report but continue — partial AST may still yield useful fns.
        // Don't spam: just log a single line with the error count.
        // (The first error is usually the most useful but rendering it
        // requires Writer plumbing we don't need here.)
    }

    const module_path = filePathToModulePath(arena, abs_file) catch |err| {
        std.debug.print("warning: skip {s}: module-path build failed {s}\n", .{ abs_file, @errorName(err) });
        return;
    };

    const root_decls = tree.rootDecls();
    var ctx = WalkCtx{
        .arena = arena,
        .tree = &tree,
        .file_abs = abs_file,
        .module_path = module_path,
        .out = out,
    };
    for (root_decls) |decl| {
        try walkDecl(&ctx, decl, "");
    }
}

const WalkCtx = struct {
    arena: std.mem.Allocator,
    tree: *std.zig.Ast,
    file_abs: []const u8,
    module_path: []const u8,
    out: *std.ArrayList(AstFunction),
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
        for (cd.ast.members) |member| {
            try walkDecl(ctx, member, new_container);
        }
    }
    // We deliberately don't chase arbitrary expressions here — the common
    // case is `const Foo = struct { ... };` which the fullContainerDecl
    // probe handles.
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

    try ctx.out.append(ctx.arena, .{
        .name = try ctx.arena.dupe(u8, name),
        .qualified_name = qualified,
        .file = ctx.file_abs,
        .line_start = line_start,
        .line_end = line_end,
        .is_pub = is_pub,
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
