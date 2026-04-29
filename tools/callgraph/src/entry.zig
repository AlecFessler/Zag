// Structural entry-point discovery.
//
// Replaces the path-suffix heuristic with a real walk of the kernel's entry
// shape. The kernel is a microkernel — every code path begins at one of:
//
//   1. Syscalls — `kernel/syscall/dispatch.zig::dispatch` is a single
//      `switch (syscall_num)` whose arms each call one `sys*` handler.
//   2. Traps    — vectors 0–31. On x64 each is registered with
//      `interrupts.registerVector(vec, handler, .exception)`. On aarch64
//      handlers are referenced from the `exceptionVectorTable` asm thunk.
//   3. IRQs     — vectors 32+. Same registration helper as traps but kind
//      `.external`.
//   4. Boot     — `kEntry` (the bootloader hand-off symbol) plus any other
//      `export fn ... callconv(.naked)` (SMP trampolines, asm vector tables
//      that the rest of the kernel doesn't directly call).
//
// Each Discovered entry is keyed by the AST `qualified_name` so it joins
// against `types.Function.name` after the IR/AST join.

const std = @import("std");

const ast = @import("ast/index.zig");
const types = @import("types.zig");

const AstFunction = ast.AstFunction;
const FileAst = ast.FileAst;

pub const Discovered = struct {
    /// Function name as it appears in the IR / display layer. Use the
    /// *qualified* name (e.g., "syscall.system.sysWrite") so it joins to
    /// `types.Function.name` without ambiguity.
    name: []const u8,
    kind: types.EntryKind,
    /// Optional human-readable label (e.g., for a syscall "syscall #5: open").
    /// Defaults to `name` if null.
    label: ?[]const u8 = null,
};

pub fn discover(
    arena: std.mem.Allocator,
    kernel_root: []const u8,
    arch: []const u8,
    ast_fns: []const AstFunction,
    file_asts: []const FileAst,
) ![]const Discovered {
    _ = kernel_root; // not strictly needed — we work off realpaths inside ast/file_asts.

    var out = std.ArrayList(Discovered){};
    // Track names we've already added so we don't double-record (e.g. a
    // syscall handler that also appears in some other heuristic, or an
    // export-naked fn that's also pulled in via vectors).
    var seen = std.StringHashMap(void).init(arena);

    var ctx = DiscoverCtx{
        .arena = arena,
        .arch = arch,
        .ast_fns = ast_fns,
        .file_asts = file_asts,
        .out = &out,
        .seen = &seen,
    };

    try discoverSyscalls(&ctx);
    if (std.mem.eql(u8, arch, "x64")) {
        try discoverX64IdtRegistrations(&ctx);
    } else if (std.mem.eql(u8, arch, "aarch64")) {
        try discoverAarch64Vectors(&ctx);
    }
    try discoverBoot(&ctx);

    return out.toOwnedSlice(arena);
}

const DiscoverCtx = struct {
    arena: std.mem.Allocator,
    arch: []const u8,
    ast_fns: []const AstFunction,
    file_asts: []const FileAst,
    out: *std.ArrayList(Discovered),
    seen: *std.StringHashMap(void),

    fn add(self: *DiscoverCtx, name: []const u8, kind: types.EntryKind, label: ?[]const u8) !void {
        if (self.seen.contains(name)) return;
        try self.seen.put(name, {});
        try self.out.append(self.arena, .{
            .name = name,
            .kind = kind,
            .label = label,
        });
    }
};

// ─────────────────────────────────────────────────────────────── Syscalls

/// Locate `kernel/syscall/dispatch.zig::dispatch` and parse its
/// `switch (syscall_num)` body. Each case has the shape:
///
///     .write => system.sysWrite(arg0, arg1),
///     .mem_perms => .{ .ret = memory.sysMemPerms(...) },
///     .ipc_send => ipc.sysIpcSend(ctx),
///     ._mem_mmio_unmap_removed => .{ .ret = E_INVAL },   // skip
///     _ => .{ .ret = E_INVAL },                          // skip
///
/// For each case that *contains* a call expression we record the syscall
/// label (left side of `=>`) plus the qualified name of the handler fn.
fn discoverSyscalls(ctx: *DiscoverCtx) !void {
    const dispatch_fa = findFileAstSuffix(ctx.file_asts, "kernel/syscall/dispatch.zig") orelse {
        std.debug.print("entry: kernel/syscall/dispatch.zig not found in AST walk\n", .{});
        return;
    };

    const dispatch_fn = findFnInFile(ctx.ast_fns, dispatch_fa.file, "dispatch") orelse {
        std.debug.print("entry: dispatch fn not found in {s}\n", .{dispatch_fa.file});
        return;
    };
    if (dispatch_fn.fn_node == 0) return;

    // Build an `unqualified-name -> qualified-name` lookup limited to
    // `kernel/syscall/*` so each switch arm's `system.sysWrite` resolves
    // to `syscall.system.sysWrite`.
    var by_name = std.StringHashMap([]const u8).init(ctx.arena);
    for (ctx.ast_fns) |f| {
        if (std.mem.indexOf(u8, f.file, "/kernel/syscall/") == null) continue;
        try by_name.put(f.name, f.qualified_name);
    }

    const tree = dispatch_fa.tree;
    const fn_node: std.zig.Ast.Node.Index = @enumFromInt(dispatch_fn.fn_node);
    if (tree.nodeTag(fn_node) != .fn_decl) return;
    const body_node = tree.nodeData(fn_node).node_and_node[1];

    const switch_node = findFirstSwitch(tree, body_node) orelse {
        std.debug.print("entry: no switch found in dispatch body\n", .{});
        return;
    };

    const sw = tree.fullSwitch(switch_node) orelse return;
    for (sw.ast.cases) |case_node| {
        const case = tree.fullSwitchCase(case_node) orelse continue;

        // Skip default `_` case.
        if (case.ast.values.len == 0) continue;

        // Find the *first* call expression inside the case's target. Skip
        // arms whose target is a literal/struct-literal with no call
        // (`.foo => .{ .ret = E_INVAL }` and the like).
        const call_node = findFirstCall(tree, case.ast.target_expr) orelse continue;

        const callee_ident = calleeLastIdent(tree, call_node) orelse continue;

        // Skip @bitCast, E_INVAL fallbacks, and other non-syscall-handler
        // bodies. Those filter out by virtue of `callee_ident` being
        // something we don't have in our local lookup.
        const qualified = by_name.get(callee_ident) orelse continue;

        // Use the case label (e.g. ".write") for the user-facing dropdown.
        const value_node = case.ast.values[0];
        const value_src = nodeSource(tree, value_node);
        const label = try std.fmt.allocPrint(ctx.arena, "syscall: {s}", .{trimDot(value_src)});

        try ctx.add(qualified, .syscall, label);
    }
}

// ─────────────────────────────────────────────────────── x64 IDT discovery

/// Architectural exception names — used as labels for traps so the dropdown
/// reads "trap #14: page_fault" instead of just the handler fn name.
/// Intel SDM Vol 3A Table 7-1.
const x64_trap_names: [32]?[]const u8 = blk: {
    var t: [32]?[]const u8 = .{null} ** 32;
    t[0] = "divide_by_zero";
    t[1] = "single_step_debug";
    t[2] = "non_maskable_interrupt";
    t[3] = "breakpoint";
    t[4] = "overflow";
    t[5] = "bound_range_exceeded";
    t[6] = "invalid_opcode";
    t[7] = "device_not_available";
    t[8] = "double_fault";
    t[9] = "coprocessor_segment_overrun";
    t[10] = "invalid_tss";
    t[11] = "segment_not_present";
    t[12] = "stack_segment_fault";
    t[13] = "general_protection_fault";
    t[14] = "page_fault";
    t[16] = "x87_floating_point";
    t[17] = "alignment_check";
    t[18] = "machine_check";
    t[19] = "simd_floating_point";
    t[20] = "virtualization";
    t[30] = "security";
    break :blk t;
};

/// Walk every kernel arch x64 file and collect calls to
/// `interrupts.registerVector(vector, handler_fn, .kind)`. The `kind` arg
/// (`.exception`, `.external`, `.software`) tells us trap vs irq.
fn discoverX64IdtRegistrations(ctx: *DiscoverCtx) !void {
    var by_name = std.StringHashMap([]const u8).init(ctx.arena);
    for (ctx.ast_fns) |f| {
        if (std.mem.indexOf(u8, f.file, "/kernel/arch/x64/") == null) continue;
        try by_name.put(f.name, f.qualified_name);
    }

    for (ctx.file_asts) |*fa| {
        if (std.mem.indexOf(u8, fa.file, "/kernel/arch/x64/") == null) continue;

        var walker = NodeWalker{ .tree = fa.tree };
        defer walker.deinit();
        while (walker.next()) |n| {
            const tag = fa.tree.nodeTag(n);
            switch (tag) {
                .call, .call_comma, .call_one, .call_one_comma => {},
                else => continue,
            }
            var buf: [1]std.zig.Ast.Node.Index = undefined;
            const call = fa.tree.fullCall(&buf, n) orelse continue;
            const callee = calleeLastIdent(fa.tree, n) orelse continue;
            if (!std.mem.eql(u8, callee, "registerVector")) continue;
            if (call.ast.params.len != 3) continue;

            const vec_src = nodeSource(fa.tree, call.ast.params[0]);
            const handler_ident = calleeArgIdent(fa.tree, call.ast.params[1]) orelse continue;
            const kind_src = nodeSource(fa.tree, call.ast.params[2]);
            const qualified = by_name.get(handler_ident) orelse continue;

            const vector = parseVectorLiteral(vec_src);
            const is_external = std.mem.indexOf(u8, kind_src, "external") != null;
            const is_exception = std.mem.indexOf(u8, kind_src, "exception") != null;

            const entry_kind: types.EntryKind = if (is_exception)
                .trap
            else if (is_external)
                .irq
            else
                .trap;

            const label = try buildVectorLabel(ctx.arena, entry_kind, vector, vec_src, handler_ident);
            try ctx.add(qualified, entry_kind, label);
        }
    }
}

fn buildVectorLabel(
    arena: std.mem.Allocator,
    kind: types.EntryKind,
    vector: ?u32,
    vec_src: []const u8,
    handler_ident: []const u8,
) ![]const u8 {
    if (vector) |v| {
        if (v < x64_trap_names.len) {
            if (x64_trap_names[v]) |nm| {
                return std.fmt.allocPrint(arena, "{s} #{d}: {s}", .{ kindName(kind), v, nm });
            }
        }
        return std.fmt.allocPrint(arena, "{s} #{d}: {s}", .{ kindName(kind), v, handler_ident });
    }
    return std.fmt.allocPrint(arena, "{s} {s}: {s}", .{ kindName(kind), trimWs(vec_src), handler_ident });
}

fn kindName(k: types.EntryKind) []const u8 {
    return switch (k) {
        .syscall => "syscall",
        .trap => "trap",
        .irq => "irq",
        .boot => "boot",
        .manual => "manual",
    };
}

/// Best-effort conversion of a vector-arg source slice to an integer.
/// Handles plain integer literals (`32`), `@intFromEnum(IntVecs.spurious)`
/// — for the latter we resolve a small known set of named vectors taken
/// from `arch/x64/interrupts.zig::IntVecs`.
fn parseVectorLiteral(src: []const u8) ?u32 {
    const trimmed = trimWs(src);
    if (trimmed.len == 0) return null;

    if (std.mem.indexOf(u8, trimmed, "IntVecs.pmu") != null) return 0xFB;
    if (std.mem.indexOf(u8, trimmed, "IntVecs.kprof_dump") != null) return 0xFC;
    if (std.mem.indexOf(u8, trimmed, "IntVecs.tlb_shootdown") != null) return 0xFD;
    if (std.mem.indexOf(u8, trimmed, "IntVecs.sched") != null) return 0xFE;
    if (std.mem.indexOf(u8, trimmed, "IntVecs.spurious") != null) return 0xFF;
    if (std.mem.indexOf(u8, trimmed, "IntVecs.fpu_flush") != null) return 0xFA;
    if (std.mem.indexOf(u8, trimmed, "PMI_VECTOR") != null) return 0xFB;

    if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X")) {
        return std.fmt.parseInt(u32, trimmed[2..], 16) catch null;
    }
    return std.fmt.parseInt(u32, trimmed, 10) catch null;
}

// ─────────────────────────────────────────────── aarch64 vector discovery

/// On aarch64 the exception vector table is an asm thunk that branches to
/// six Zig functions: handleSyncCurrentEl, handleIrqCurrentEl,
/// handleSyncLowerEl, handleIrqLowerEl, handleUnexpected (and re-uses some
/// of these). Record each as either a trap (sync) or irq (irq), labelled
/// per the ARM ARM D1.10.2 vector layout where possible.
fn discoverAarch64Vectors(ctx: *DiscoverCtx) !void {
    const handlers = [_]struct { name: []const u8, kind: types.EntryKind, label: []const u8 }{
        .{ .name = "handleSyncLowerEl", .kind = .trap, .label = "trap: sync (lower EL — syscalls/page faults)" },
        .{ .name = "handleSyncCurrentEl", .kind = .trap, .label = "trap: sync (current EL — kernel faults)" },
        .{ .name = "handleIrqLowerEl", .kind = .irq, .label = "irq: lower EL (device interrupts from userspace)" },
        .{ .name = "handleIrqCurrentEl", .kind = .irq, .label = "irq: current EL (kernel IRQ)" },
        .{ .name = "handleUnexpected", .kind = .trap, .label = "trap: unexpected vector (FIQ/SError/AArch32)" },
    };

    for (handlers) |h| {
        const af = findFnAarch64(ctx.ast_fns, h.name) orelse continue;
        const lbl = try ctx.arena.dupe(u8, h.label);
        try ctx.add(af.qualified_name, h.kind, lbl);
    }
}

fn findFnAarch64(ast_fns: []const AstFunction, name: []const u8) ?*const AstFunction {
    for (ast_fns) |*f| {
        if (std.mem.indexOf(u8, f.file, "/kernel/arch/aarch64/") == null) continue;
        if (std.mem.eql(u8, f.name, name)) return f;
    }
    return null;
}

// ─────────────────────────────────────────────────────────────── Boot

fn discoverBoot(ctx: *DiscoverCtx) !void {
    // 1. kEntry — find by name. There's exactly one in the kernel.
    for (ctx.ast_fns) |*f| {
        if (std.mem.eql(u8, f.name, "kEntry") and
            std.mem.indexOf(u8, f.file, "/kernel/") != null)
        {
            const lbl = try ctx.arena.dupe(u8, "boot: kEntry");
            try ctx.add(f.qualified_name, .boot, lbl);
        }
    }

    // 2. Every `export fn ... callconv(.naked)` in the target arch is
    //    boot-relevant — interrupt stubs, syscall entry, vector tables,
    //    SMP trampolines.
    for (ctx.file_asts) |*fa| {
        if (std.mem.indexOf(u8, fa.file, "/kernel/arch/") != null) {
            const is_x64 = std.mem.indexOf(u8, fa.file, "/kernel/arch/x64/") != null;
            const is_aarch64 = std.mem.indexOf(u8, fa.file, "/kernel/arch/aarch64/") != null;
            if (!is_x64 and !is_aarch64) continue;
            if (is_x64 and !std.mem.eql(u8, ctx.arch, "x64")) continue;
            if (is_aarch64 and !std.mem.eql(u8, ctx.arch, "aarch64")) continue;
        }

        try collectExportNakedFns(ctx, fa);
    }
}

/// Find every `export fn name() callconv(.naked) ...` in a file. Done by
/// pattern-matching the source slice between the proto's first/last tokens.
fn collectExportNakedFns(ctx: *DiscoverCtx, fa: *const FileAst) !void {
    for (ctx.ast_fns) |*f| {
        if (!std.mem.eql(u8, f.file, fa.file)) continue;
        if (f.fn_node == 0) continue;
        const node: std.zig.Ast.Node.Index = @enumFromInt(f.fn_node);
        if (fa.tree.nodeTag(node) != .fn_decl) continue;

        var proto_buf: [1]std.zig.Ast.Node.Index = undefined;
        const proto = fa.tree.fullFnProto(&proto_buf, node) orelse continue;
        const first_tok = proto.ast.fn_token;
        // Look up to ~6 tokens before the fn for `export`/`pub export`.
        const start_tok = if (first_tok >= 6) first_tok - 6 else 0;
        const start = fa.tree.tokenStart(start_tok);
        const last_tok = fa.tree.lastToken(node);
        const last_start = fa.tree.tokenStart(last_tok);
        const last_slice = fa.tree.tokenSlice(last_tok);
        const end: usize = @as(usize, last_start) + last_slice.len;
        if (end <= start or end > fa.tree.source.len) continue;
        const decl_src = fa.tree.source[start..end];

        const cap = std.mem.indexOfScalar(u8, decl_src, '{') orelse decl_src.len;
        const header = decl_src[0..cap];
        const has_export = std.mem.indexOf(u8, header, "export ") != null or
            std.mem.indexOf(u8, header, "export\n") != null;
        const has_naked = std.mem.indexOf(u8, header, "callconv(.naked)") != null or
            std.mem.indexOf(u8, header, "callconv(.Naked)") != null;
        if (!has_export or !has_naked) continue;

        const lbl = try std.fmt.allocPrint(ctx.arena, "boot: {s} (naked export)", .{f.name});
        try ctx.add(f.qualified_name, .boot, lbl);
    }
}

// ─────────────────────────────────────────────────────── AST utilities

fn findFileAstSuffix(file_asts: []const FileAst, suffix: []const u8) ?*const FileAst {
    for (file_asts) |*fa| {
        if (std.mem.endsWith(u8, fa.file, suffix)) return fa;
    }
    return null;
}

fn findFnInFile(ast_fns: []const AstFunction, file: []const u8, name: []const u8) ?*const AstFunction {
    for (ast_fns) |*f| {
        if (!std.mem.eql(u8, f.file, file)) continue;
        if (std.mem.eql(u8, f.name, name)) return f;
    }
    return null;
}

fn nodeSource(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) []const u8 {
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    const start = tree.tokenStart(first);
    const last_start = tree.tokenStart(last);
    const last_slice = tree.tokenSlice(last);
    const end: usize = @as(usize, last_start) + last_slice.len;
    if (end <= start or end > tree.source.len) return "";
    return tree.source[start..end];
}

fn trimWs(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t' or s[i] == '\n' or s[i] == '\r')) i += 1;
    var j: usize = s.len;
    while (j > i and (s[j - 1] == ' ' or s[j - 1] == '\t' or s[j - 1] == '\n' or s[j - 1] == '\r')) j -= 1;
    return s[i..j];
}

fn trimDot(s: []const u8) []const u8 {
    const t = trimWs(s);
    if (t.len > 0 and t[0] == '.') return t[1..];
    return t;
}

/// For a call expression node, return the unqualified callee identifier:
/// `system.sysWrite(...)` → "sysWrite", `pageFaultHandler` → "pageFaultHandler".
fn calleeLastIdent(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) ?[]const u8 {
    var buf: [1]std.zig.Ast.Node.Index = undefined;
    const call = tree.fullCall(&buf, node) orelse return null;
    return calleeArgIdent(tree, call.ast.fn_expr);
}

/// Take an expression node (e.g. the second arg of registerVector — which is
/// a *handler* identifier, possibly qualified `module.handler`) and return
/// the trailing identifier name.
fn calleeArgIdent(tree: *const std.zig.Ast, expr: std.zig.Ast.Node.Index) ?[]const u8 {
    const tag = tree.nodeTag(expr);
    switch (tag) {
        .identifier => {
            const t = tree.firstToken(expr);
            return tree.tokenSlice(t);
        },
        .field_access => {
            const _and = tree.nodeData(expr).node_and_token;
            const tok = _and[1];
            return tree.tokenSlice(tok);
        },
        else => return null,
    }
}

/// Walk a body looking for the first `switch` node. Used for the dispatch fn.
fn findFirstSwitch(tree: *const std.zig.Ast, root: std.zig.Ast.Node.Index) ?std.zig.Ast.Node.Index {
    var w = NodeWalker{ .tree = tree };
    defer w.deinit();
    w.seed(root) catch return null;
    while (w.next()) |n| {
        const tag = tree.nodeTag(n);
        if (tag == .@"switch" or tag == .switch_comma) return n;
    }
    return null;
}

/// Walk a sub-tree looking for the first call expression. Used for each
/// switch arm's target_expr.
fn findFirstCall(tree: *const std.zig.Ast, root: std.zig.Ast.Node.Index) ?std.zig.Ast.Node.Index {
    var w = NodeWalker{ .tree = tree };
    defer w.deinit();
    w.seed(root) catch return null;
    while (w.next()) |n| {
        const tag = tree.nodeTag(n);
        switch (tag) {
            .call, .call_comma, .call_one, .call_one_comma => return n,
            else => {},
        }
    }
    return null;
}

/// Generic depth-first walker over Zig AST node children. Iterates every
/// node reachable from a root. Caller seeds explicitly with `seed()` (for
/// sub-tree walks) or lets `next()` lazily seed with rootDecls (for
/// whole-file walks).
const NodeWalker = struct {
    tree: *const std.zig.Ast,
    stack: std.ArrayList(std.zig.Ast.Node.Index) = .{},
    initialized: bool = false,

    fn deinit(self: *NodeWalker) void {
        self.stack.deinit(std.heap.page_allocator);
    }

    fn seed(self: *NodeWalker, node: std.zig.Ast.Node.Index) !void {
        self.initialized = true;
        try self.stack.append(std.heap.page_allocator, node);
    }

    fn next(self: *NodeWalker) ?std.zig.Ast.Node.Index {
        if (!self.initialized) {
            self.initialized = true;
            for (self.tree.rootDecls()) |d| {
                self.stack.append(std.heap.page_allocator, d) catch return null;
            }
        }
        const node = self.stack.pop() orelse return null;
        self.pushChildren(node) catch {};
        return node;
    }

    fn pushChildren(self: *NodeWalker, node: std.zig.Ast.Node.Index) !void {
        const tag = self.tree.nodeTag(node);
        const data = self.tree.nodeData(node);
        const a = std.heap.page_allocator;
        switch (tag) {
            .root => {},

            .bool_not, .negation, .bit_not, .negation_wrap, .address_of, .@"try",
            .optional_type, .@"suspend", .@"resume", .@"nosuspend", .@"comptime",
            .deref, .@"defer" => {
                try self.stack.append(a, data.node);
            },

            .@"return" => {
                if (data.opt_node.unwrap()) |c| try self.stack.append(a, c);
            },

            .@"catch", .equal_equal, .bang_equal,
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
            .switch_range, .error_union, .array_type,
            .fn_decl => {
                try self.stack.append(a, data.node_and_node[0]);
                try self.stack.append(a, data.node_and_node[1]);
            },

            .for_range, .struct_init_one, .struct_init_one_comma => {
                try self.stack.append(a, data.node_and_opt_node[0]);
                if (data.node_and_opt_node[1].unwrap()) |c| try self.stack.append(a, c);
            },

            .field_access, .unwrap_optional, .grouped_expression => {
                try self.stack.append(a, data.node_and_token[0]);
            },

            .call_one, .call_one_comma => {
                try self.stack.append(a, data.node_and_opt_node[0]);
                if (data.node_and_opt_node[1].unwrap()) |c| try self.stack.append(a, c);
            },
            .call, .call_comma => {
                const fn_expr, const extra = data.node_and_extra;
                try self.stack.append(a, fn_expr);
                const sub = self.tree.extraData(extra, std.zig.Ast.Node.SubRange);
                const slice = self.tree.extraDataSlice(sub, std.zig.Ast.Node.Index);
                for (slice) |c| try self.stack.append(a, c);
            },

            .block, .block_semicolon, .block_two, .block_two_semicolon => {
                var buf: [2]std.zig.Ast.Node.Index = undefined;
                if (self.tree.blockStatements(&buf, node)) |stmts| {
                    for (stmts) |s| try self.stack.append(a, s);
                }
            },

            .if_simple => {
                try self.stack.append(a, data.node_and_node[0]);
                try self.stack.append(a, data.node_and_node[1]);
            },
            .@"if" => {
                _, const extra_index = data.node_and_extra;
                const extra = self.tree.extraData(extra_index, std.zig.Ast.Node.If);
                try self.stack.append(a, extra.then_expr);
                try self.stack.append(a, extra.else_expr);
            },

            .@"switch", .switch_comma => {
                if (self.tree.fullSwitch(node)) |sw| {
                    try self.stack.append(a, sw.ast.condition);
                    for (sw.ast.cases) |c| try self.stack.append(a, c);
                }
            },

            .switch_case_one, .switch_case_inline_one => {
                const v, const target = data.opt_node_and_node;
                if (v.unwrap()) |x| try self.stack.append(a, x);
                try self.stack.append(a, target);
            },
            .switch_case, .switch_case_inline => {
                const extra, const target = data.extra_and_node;
                const sub = self.tree.extraData(extra, std.zig.Ast.Node.SubRange);
                const slice = self.tree.extraDataSlice(sub, std.zig.Ast.Node.Index);
                for (slice) |c| try self.stack.append(a, c);
                try self.stack.append(a, target);
            },

            .while_simple, .while_cont, .@"while" => {
                if (self.tree.fullWhile(node)) |wh| {
                    try self.stack.append(a, wh.ast.cond_expr);
                    try self.stack.append(a, wh.ast.then_expr);
                    if (wh.ast.else_expr.unwrap()) |e| try self.stack.append(a, e);
                    if (wh.ast.cont_expr.unwrap()) |c| try self.stack.append(a, c);
                }
            },
            .for_simple, .@"for" => {
                if (self.tree.fullFor(node)) |fr| {
                    for (fr.ast.inputs) |inp| try self.stack.append(a, inp);
                    try self.stack.append(a, fr.ast.then_expr);
                    if (fr.ast.else_expr.unwrap()) |e| try self.stack.append(a, e);
                }
            },

            .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                if (self.tree.fullVarDecl(node)) |vd| {
                    if (vd.ast.init_node.unwrap()) |i| try self.stack.append(a, i);
                }
            },

            .builtin_call_two, .builtin_call_two_comma => {
                const x, const y = data.opt_node_and_opt_node;
                if (x.unwrap()) |c| try self.stack.append(a, c);
                if (y.unwrap()) |c| try self.stack.append(a, c);
            },
            .builtin_call, .builtin_call_comma => {
                const slice = self.tree.extraDataSlice(data.extra_range, std.zig.Ast.Node.Index);
                for (slice) |c| try self.stack.append(a, c);
            },

            .array_init_dot_two, .array_init_dot_two_comma,
            .struct_init_dot_two, .struct_init_dot_two_comma => {
                const x, const y = data.opt_node_and_opt_node;
                if (x.unwrap()) |c| try self.stack.append(a, c);
                if (y.unwrap()) |c| try self.stack.append(a, c);
            },
            .array_init_dot, .array_init_dot_comma,
            .struct_init_dot, .struct_init_dot_comma => {
                const slice = self.tree.extraDataSlice(data.extra_range, std.zig.Ast.Node.Index);
                for (slice) |c| try self.stack.append(a, c);
            },

            .array_init, .array_init_comma, .struct_init, .struct_init_comma => {
                const ty, const extra = data.node_and_extra;
                try self.stack.append(a, ty);
                const sub = self.tree.extraData(extra, std.zig.Ast.Node.SubRange);
                const slice = self.tree.extraDataSlice(sub, std.zig.Ast.Node.Index);
                for (slice) |c| try self.stack.append(a, c);
            },

            .slice => {
                const sliced, const extra = data.node_and_extra;
                try self.stack.append(a, sliced);
                const s = self.tree.extraData(extra, std.zig.Ast.Node.Slice);
                try self.stack.append(a, s.start);
                try self.stack.append(a, s.end);
            },
            .slice_sentinel => {
                const sliced, const extra = data.node_and_extra;
                try self.stack.append(a, sliced);
                const s = self.tree.extraData(extra, std.zig.Ast.Node.SliceSentinel);
                try self.stack.append(a, s.start);
                if (s.end.unwrap()) |e| try self.stack.append(a, e);
                try self.stack.append(a, s.sentinel);
            },

            else => {},
        }
    }
};
