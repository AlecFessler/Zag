// AST <-> IR call-graph verifier.
//
// For each parsed AST file, walks every fn_decl body and emits a record per
// call expression: `(file, line, col, raw_callee_source)`. The walker is
// intentionally dumb — it doesn't try to resolve the callee, just records
// the source span of the fn_expr so the report can show what the user wrote.
//
// Once the AST set is built, we compare against the IR edges:
//
//   - matched         : an AST call site at (file, line) where IR has a
//                       call edge originating from a function in the same
//                       file with the same `!dbg` line. We match on
//                       (file, line) only; LLVM column tracking is too
//                       finicky for argument-side calls and we'd rather
//                       under-report ir-only than over-report ast-only.
//   - ast-only        : AST call site with no matching IR edge. Likely
//                       dead-coded by the optimizer, inlined into the
//                       caller, or the comptime branch the compiler took
//                       didn't reach this expression.
//   - ir-only         : IR edge with no AST call site at the same (file,
//                       line). Likely a compiler-synthesized call (panic,
//                       ubsan, __zig_*, async/await wrappers, runtime
//                       intrinsics) or dispatch-style indirection the AST
//                       walker doesn't see.
//
// Trivial Zig builtins (`@TypeOf`, `@sizeOf`, `@as`, `@ptrCast`,
// `@bitCast`, `@panic`, ...) are filtered out of the AST set — they don't
// emit IR call edges and would otherwise dominate the ast-only list.
//
// We also emit the count of "dead AST functions" — fns the walker found
// whose qualified name has zero matching IR `def_loc` (i.e. the compiler
// dropped them entirely).

const std = @import("std");

const ast = @import("ast/index.zig");
const types = @import("types.zig");

const AstFunction = ast.AstFunction;
const FileAst = ast.FileAst;
const IrGraph = types.IrGraph;
const SourceLoc = types.SourceLoc;

/// Builtins that look like calls but aren't real edges — `@foo(...)` syntax
/// that the compiler implements as an instruction or inline expansion.
const trivial_builtins = [_][]const u8{
    "@TypeOf",
    "@sizeOf",
    "@alignOf",
    "@bitSizeOf",
    "@offsetOf",
    "@typeInfo",
    "@typeName",
    "@hasDecl",
    "@hasField",
    "@field",
    "@as",
    "@ptrCast",
    "@bitCast",
    "@intCast",
    "@enumFromInt",
    "@intFromEnum",
    "@intFromPtr",
    "@ptrFromInt",
    "@ptrFromAddr",
    "@floatFromInt",
    "@intFromFloat",
    "@floatCast",
    "@truncate",
    "@errorCast",
    "@alignCast",
    "@constCast",
    "@volatileCast",
    "@addrSpaceCast",
    "@FieldType",
    "@panic",
    "@unionInit",
    "@import",
    "@embedFile",
    "@compileError",
    "@compileLog",
    "@This",
    "@src",
    "@returnAddress",
    "@frameAddress",
    "@call",
    "@max",
    "@min",
    "@abs",
    "@ctz",
    "@clz",
    "@popCount",
    "@byteSwap",
    "@bitReverse",
    "@mulAdd",
    "@sqrt",
    "@sin",
    "@cos",
    "@tan",
    "@exp",
    "@exp2",
    "@log",
    "@log2",
    "@log10",
    "@floor",
    "@ceil",
    "@round",
    "@trunc",
    "@splat",
    "@reduce",
    "@shuffle",
    "@select",
    "@addWithOverflow",
    "@subWithOverflow",
    "@mulWithOverflow",
    "@shlWithOverflow",
    "@memset",
    "@memcpy",
    "@memmove",
    "@atomicLoad",
    "@atomicStore",
    "@atomicRmw",
    "@cmpxchgStrong",
    "@cmpxchgWeak",
    "@fence",
    "@prefetch",
    "@wasmMemorySize",
    "@wasmMemoryGrow",
    "@setRuntimeSafety",
    "@setEvalBranchQuota",
    "@setFloatMode",
    "@setCold",
    "@setAlignStack",
    "@breakpoint",
    "@trap",
    "@errorName",
    "@errorReturnTrace",
    "@inComptime",
    "@cImport",
    "@cInclude",
    "@cDefine",
    "@cUndef",
    "@extern",
    "@export",
    "@workItemId",
    "@workGroupId",
    "@workGroupSize",
    "@Type",
    "@Vector",
    "@Frame",
    "@frame",
    "@asyncCall",
    "@suspend",
    "@resume",
    "@await",
    "@tagName",
};

/// One AST-detected call site. `callee` is the raw source slice of the
/// fn_expr (e.g. `vmm.alloc`, `pmm.allocPage`, `@panic`).
pub const AstCall = struct {
    file: []const u8,
    line: u32,
    col: u32,
    callee: []const u8,
    /// Whether the call is a `@builtin(...)` form. We keep these in the
    /// raw set but filter them before the diff so reports stay readable.
    is_builtin: bool,
};

/// Run the verify pass and print the punch list to `out`.
///
/// Allocator is used for transient state — call-site list, hash sets, sample
/// buffers. The report itself is streamed line-by-line.
pub fn run(
    allocator: std.mem.Allocator,
    out: *std.io.Writer,
    ir_graph: types.IrGraph,
    ast_fns: []const AstFunction,
    file_asts: []const FileAst,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 1. Resolve the file path each AstFunction lives in into a realpath so
    //    we can compare to IR `!dbg` files (which the IR parser carries
    //    through verbatim from the DIFile records).
    var realpath_cache = std.StringHashMap([]const u8).init(a);
    var ast_calls = std.ArrayList(AstCall){};

    for (file_asts) |fa| {
        const resolved = try resolvePath(a, &realpath_cache, fa.file);
        try collectFileCalls(a, resolved, fa.tree, &ast_calls);
    }

    // 2. Build per-file (line) sets so the diff is O(N + M).
    const KeyMap = std.StringHashMap(u32); // "file:line" -> count
    var ast_by_loc = KeyMap.init(a);
    var ast_total_filtered: usize = 0;
    var ast_total_raw: usize = 0;
    for (ast_calls.items) |c| {
        ast_total_raw += 1;
        if (c.is_builtin) continue;
        ast_total_filtered += 1;
        const k = try std.fmt.allocPrint(a, "{s}:{d}", .{ c.file, c.line });
        const gop = try ast_by_loc.getOrPut(k);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    var ir_by_loc = KeyMap.init(a);
    var ir_edge_total: usize = 0;
    for (ir_graph.edges) |e| {
        ir_edge_total += 1;
        const resolved = try resolvePath(a, &realpath_cache, e.site.file);
        const k = try std.fmt.allocPrint(a, "{s}:{d}", .{ resolved, e.site.line });
        const gop = try ir_by_loc.getOrPut(k);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    // 3. Compute matched / ast-only / ir-only at the (file, line) level.
    //    "matched" counts the lower of AST and IR multiplicity per key —
    //    so two AST calls and one IR edge on the same line contribute 1
    //    matched + 1 ast-only.
    var matched: usize = 0;
    var ast_only_count: usize = 0;
    var ir_only_count: usize = 0;

    var ast_only_samples = std.ArrayList(AstCall){};
    var ir_only_samples = std.ArrayList(SourceLoc){};

    {
        var it = ast_by_loc.iterator();
        while (it.next()) |kv| {
            const ast_n = kv.value_ptr.*;
            const ir_n = ir_by_loc.get(kv.key_ptr.*) orelse 0;
            const m = @min(ast_n, ir_n);
            matched += m;
            if (ast_n > m) ast_only_count += (ast_n - m);
        }
    }
    {
        var it = ir_by_loc.iterator();
        while (it.next()) |kv| {
            const ir_n = kv.value_ptr.*;
            const ast_n = ast_by_loc.get(kv.key_ptr.*) orelse 0;
            if (ir_n > ast_n) ir_only_count += (ir_n - ast_n);
        }
    }

    // 4. Pull a small sample for each side. We iterate the source lists in
    //    declaration order so the samples are stable across runs.
    const sample_cap: usize = 10;
    {
        // For ast-only: an AstCall whose (file, line) IR doesn't have, or
        // has fewer of than the AST.
        var seen = std.StringHashMap(u32).init(a); // remaining ir budget per key
        var it = ir_by_loc.iterator();
        while (it.next()) |kv| try seen.put(kv.key_ptr.*, kv.value_ptr.*);
        for (ast_calls.items) |c| {
            if (c.is_builtin) continue;
            const k = try std.fmt.allocPrint(a, "{s}:{d}", .{ c.file, c.line });
            const ir_left = seen.get(k) orelse 0;
            if (ir_left > 0) {
                try seen.put(k, ir_left - 1);
                continue;
            }
            if (ast_only_samples.items.len < sample_cap) {
                try ast_only_samples.append(a, c);
            }
        }
    }
    {
        var seen = std.StringHashMap(u32).init(a);
        var it = ast_by_loc.iterator();
        while (it.next()) |kv| try seen.put(kv.key_ptr.*, kv.value_ptr.*);
        for (ir_graph.edges) |e| {
            const resolved = try resolvePath(a, &realpath_cache, e.site.file);
            const k = try std.fmt.allocPrint(a, "{s}:{d}", .{ resolved, e.site.line });
            const ast_left = seen.get(k) orelse 0;
            if (ast_left > 0) {
                try seen.put(k, ast_left - 1);
                continue;
            }
            if (ir_only_samples.items.len < sample_cap) {
                try ir_only_samples.append(a, .{
                    .file = resolved,
                    .line = e.site.line,
                    .col = e.site.col,
                });
            }
        }
    }

    // 5. Dead AST functions: AstFunction.qualified_name with zero IR
    //    function whose def_loc matches its (file, line_start). Use the
    //    same (file, line) join the regular pipeline uses.
    var ir_def_keys = std.StringHashMap(void).init(a);
    for (ir_graph.functions) |f| {
        const loc = f.def_loc orelse continue;
        const resolved = try resolvePath(a, &realpath_cache, loc.file);
        const k = try std.fmt.allocPrint(a, "{s}:{d}", .{ resolved, loc.line });
        try ir_def_keys.put(k, {});
    }
    var dead_ast_count: usize = 0;
    var dead_ast_samples = std.ArrayList(*const AstFunction){};
    for (ast_fns) |*af| {
        const resolved = try resolvePath(a, &realpath_cache, af.file);
        const k = try std.fmt.allocPrint(a, "{s}:{d}", .{ resolved, af.line_start });
        if (!ir_def_keys.contains(k)) {
            dead_ast_count += 1;
            if (dead_ast_samples.items.len < sample_cap) {
                try dead_ast_samples.append(a, af);
            }
        }
    }

    // 6. Stream the report.
    try out.print("== verify ==\n", .{});
    try out.print("total IR edges:       {d}\n", .{ir_edge_total});
    try out.print("total AST call sites: {d}  ({d} after filtering trivial @-builtins; raw {d})\n", .{
        ast_total_filtered, ast_total_filtered, ast_total_raw,
    });
    try out.print("matched:              {d}\n", .{matched});
    try out.print("ast-only (probably dead/inlined):    {d}\n", .{ast_only_count});
    try out.print("ir-only (probably synthesized/dispatch): {d}\n", .{ir_only_count});
    try out.print("dead AST fns (compiler dropped them entirely): {d}\n", .{dead_ast_count});

    if (ast_only_samples.items.len > 0) {
        try out.print("\nast-only sample (first {d}):\n", .{ast_only_samples.items.len});
        for (ast_only_samples.items) |c| {
            const display = trimKernelPrefix(c.file);
            try out.print("  {s}:{d}:{d} -> {s}\n", .{ display, c.line, c.col, c.callee });
        }
    }
    if (ir_only_samples.items.len > 0) {
        try out.print("\nir-only sample (first {d}):\n", .{ir_only_samples.items.len});
        for (ir_only_samples.items) |loc| {
            const display = trimKernelPrefix(loc.file);
            try out.print("  {s}:{d}:{d}\n", .{ display, loc.line, loc.col });
        }
    }
    if (dead_ast_samples.items.len > 0) {
        try out.print("\ndead AST fn sample (first {d}):\n", .{dead_ast_samples.items.len});
        for (dead_ast_samples.items) |af| {
            const display = trimKernelPrefix(af.file);
            try out.print("  {s}:{d}  {s}\n", .{ display, af.line_start, af.qualified_name });
        }
    }
    try out.print("\n", .{});
    try out.flush();
}

// --------------------------------------------------------------- collection

/// Walk a parsed AST tree and emit one AstCall per call expression. Files
/// are visited as a flat token-tag scan over `tree.nodes` — every node tagged
/// with one of the call/builtin_call variants is a call site.
fn collectFileCalls(
    arena: std.mem.Allocator,
    file_resolved: []const u8,
    tree: *std.zig.Ast,
    out: *std.ArrayList(AstCall),
) !void {
    const node_count = tree.nodes.len;
    var i: u32 = 0;
    while (i < node_count) {
        const idx: std.zig.Ast.Node.Index = @enumFromInt(i);
        const tag = tree.nodeTag(idx);
        switch (tag) {
            .call, .call_comma, .call_one, .call_one_comma => {
                try emitUserCall(arena, file_resolved, tree, idx, out);
            },
            .builtin_call,
            .builtin_call_comma,
            .builtin_call_two,
            .builtin_call_two_comma,
            => {
                try emitBuiltinCall(arena, file_resolved, tree, idx, out);
            },
            else => {},
        }
        i += 1;
    }
}

fn emitUserCall(
    arena: std.mem.Allocator,
    file_resolved: []const u8,
    tree: *std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    out: *std.ArrayList(AstCall),
) !void {
    var buf: [1]std.zig.Ast.Node.Index = undefined;
    const call = tree.fullCall(&buf, node) orelse return;
    const first_tok = tree.firstToken(call.ast.fn_expr);
    const loc = tree.tokenLocation(0, first_tok);
    const line: u32 = @intCast(loc.line + 1);
    const col: u32 = @intCast(loc.column + 1);

    const callee_src = nodeSourceSlice(tree, call.ast.fn_expr);
    try out.append(arena, .{
        .file = file_resolved,
        .line = line,
        .col = col,
        .callee = try arena.dupe(u8, callee_src),
        .is_builtin = false,
    });
}

fn emitBuiltinCall(
    arena: std.mem.Allocator,
    file_resolved: []const u8,
    tree: *std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    out: *std.ArrayList(AstCall),
) !void {
    // The first token of a builtin_call is the `@name` identifier.
    const first_tok = tree.firstToken(node);
    const tok_slice = tree.tokenSlice(first_tok);
    const loc = tree.tokenLocation(0, first_tok);
    const line: u32 = @intCast(loc.line + 1);
    const col: u32 = @intCast(loc.column + 1);

    const is_trivial = isTrivialBuiltin(tok_slice);
    try out.append(arena, .{
        .file = file_resolved,
        .line = line,
        .col = col,
        .callee = try arena.dupe(u8, tok_slice),
        .is_builtin = is_trivial,
    });
}

fn isTrivialBuiltin(name: []const u8) bool {
    for (trivial_builtins) |b| {
        if (std.mem.eql(u8, name, b)) return true;
    }
    return false;
}

// ------------------------------------------------------------------- utils

fn nodeSourceSlice(tree: *std.zig.Ast, node: std.zig.Ast.Node.Index) []const u8 {
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    const start = tree.tokenStart(first);
    const last_start = tree.tokenStart(last);
    const last_slice = tree.tokenSlice(last);
    const end: usize = @as(usize, last_start) + last_slice.len;
    if (end <= start or end > tree.source.len) return "";
    return tree.source[start..end];
}

fn resolvePath(
    arena: std.mem.Allocator,
    cache: *std.StringHashMap([]const u8),
    path: []const u8,
) ![]const u8 {
    if (cache.get(path)) |hit| return hit;
    const resolved = std.fs.realpathAlloc(arena, path) catch try arena.dupe(u8, path);
    try cache.put(try arena.dupe(u8, path), resolved);
    return resolved;
}

/// Trim everything up through `/kernel/` (or the bare `kernel/` prefix) so
/// the report doesn't drown in leading absolute-path noise.
fn trimKernelPrefix(path: []const u8) []const u8 {
    if (std.mem.indexOf(u8, path, "/kernel/")) |i| {
        return path[i + 1 ..];
    }
    if (std.mem.startsWith(u8, path, "kernel/")) return path;
    if (std.mem.indexOf(u8, path, "/usr/lib/zig/")) |i| {
        return path[i + 1 ..];
    }
    return path;
}
