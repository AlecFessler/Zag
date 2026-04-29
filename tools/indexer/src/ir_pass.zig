const std = @import("std");
const types = @import("types.zig");

const IrFnRow = types.IrFnRow;
const IrCallRow = types.IrCallRow;

pub const PassResult = struct {
    ir_fns: []IrFnRow,
    ir_calls: []IrCallRow,
    /// Entity IDs that have at least one ir_fn define. Used to set is_ast_only
    /// on the complement.
    has_ir_define: std.AutoHashMapUnmanaged(u32, void),
};

/// Parse a `kernel.<arch>.ll` file and emit ir_fn + ir_call rows.
///
/// Resolution against entities goes through `entity_by_qname`, which the
/// orchestrator builds from the final entity table after stage 2.5. Names are
/// stripped of monomorphization suffixes (`__anon_NNNN` etc.) before lookup.
pub fn pass(
    palloc: std.mem.Allocator,
    ir_path: []const u8,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
) !PassResult {
    const f = try std.fs.cwd().openFile(ir_path, .{});
    defer f.close();
    const stat = try f.stat();
    const bytes = try palloc.alloc(u8, @intCast(stat.size));
    const n = try f.readAll(bytes);
    if (n != bytes.len) return error.ShortRead;
    const text: []const u8 = bytes[0..n];

    // Pre-pass: build dbg metadata id → source line table.
    // DILocation entries live in the metadata section at the bottom of the IR
    // file (after all function bodies), so we have to scan for them up front.
    var dbg_lines: std.AutoHashMapUnmanaged(u32, u32) = .empty;
    {
        var meta_iter = std.mem.splitScalar(u8, text, '\n');
        while (meta_iter.next()) |raw_line| {
            // Format: `!NNNN = !DILocation(line: M, column: K, scope: !P)`
            if (raw_line.len < 8 or raw_line[0] != '!') continue;
            const eq_idx = std.mem.indexOf(u8, raw_line, " = !DILocation(") orelse continue;
            const id_str = raw_line[1..eq_idx];
            const id = std.fmt.parseInt(u32, id_str, 10) catch continue;
            const after_paren = raw_line[eq_idx + " = !DILocation(".len ..];
            const line_kw = "line: ";
            const ln_idx = std.mem.indexOf(u8, after_paren, line_kw) orelse continue;
            const after_kw = after_paren[ln_idx + line_kw.len ..];
            // Line number ends at next `,` or `)`.
            var end: usize = 0;
            while (end < after_kw.len and after_kw[end] >= '0' and after_kw[end] <= '9') end += 1;
            if (end == 0) continue;
            const line_no = std.fmt.parseInt(u32, after_kw[0..end], 10) catch continue;
            try dbg_lines.put(palloc, id, line_no);
        }
    }

    var ir_fns: std.ArrayList(IrFnRow) = .empty;
    var ir_calls: std.ArrayList(IrCallRow) = .empty;
    var has_ir: std.AutoHashMapUnmanaged(u32, void) = .empty;

    var current_caller_id: ?u32 = null;
    var line_iter = std.mem.splitScalar(u8, text, '\n');

    while (line_iter.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        if (current_caller_id == null) {
            // Looking for `define ... @name(...) ... {`
            if (std.mem.startsWith(u8, line, "define ")) {
                const at_idx = std.mem.indexOfScalar(u8, line, '@') orelse continue;
                const name_end = nameEnd(line, at_idx + 1);
                const ir_name = line[at_idx + 1 .. name_end];
                if (ir_name.len == 0) continue;

                // Skip LLVM-internal builtins.
                if (std.mem.startsWith(u8, ir_name, "llvm.")) continue;

                const stripped = stripMonoSuffix(ir_name);
                if (entity_by_qname.get(stripped)) |entity_id| {
                    try ir_fns.append(palloc, .{
                        .entity_id = entity_id,
                        .ir_name = ir_name,
                        .attrs = extractAttrs(palloc, line) catch null,
                    });
                    try has_ir.put(palloc, entity_id, {});
                    current_caller_id = entity_id;
                } else {
                    // No entity match — could be __ubsan_*, llvm.*, etc. Track
                    // as "we entered a function" so we still skip over its body.
                    current_caller_id = 0; // sentinel: in-fn, no caller_entity
                }
            }
        } else {
            // Inside a function body.
            if (std.mem.eql(u8, line, "}")) {
                current_caller_id = null;
                continue;
            }
            const caller = current_caller_id.?;
            if (caller == 0) continue; // unknown caller; skip
            try parseCallLine(palloc, line, caller, entity_by_qname, &dbg_lines, &ir_calls);
        }
    }

    return .{
        .ir_fns = try ir_fns.toOwnedSlice(palloc),
        .ir_calls = try ir_calls.toOwnedSlice(palloc),
        .has_ir_define = has_ir,
    };
}

fn parseCallLine(
    palloc: std.mem.Allocator,
    line: []const u8,
    caller: u32,
    entity_by_qname: *const std.StringHashMapUnmanaged(u32),
    dbg_lines: *const std.AutoHashMapUnmanaged(u32, u32),
    out: *std.ArrayList(IrCallRow),
) !void {
    // Resolve `!dbg !N` (if present) to a source line via the metadata table.
    const site_line: u32 = blk: {
        const tag = ", !dbg !";
        const idx = std.mem.lastIndexOf(u8, line, tag) orelse break :blk 0;
        const after = line[idx + tag.len ..];
        var end: usize = 0;
        while (end < after.len and after[end] >= '0' and after[end] <= '9') end += 1;
        if (end == 0) break :blk 0;
        const id = std.fmt.parseInt(u32, after[0..end], 10) catch break :blk 0;
        break :blk dbg_lines.get(id) orelse 0;
    };
    // Look for `  call ` or `  invoke ` (with leading whitespace).
    const trimmed = std.mem.trimLeft(u8, line, " \t");
    const after_call: []const u8 = blk: {
        // `call`, `invoke`, `tail call`, `musttail call`, `notail call`
        if (std.mem.startsWith(u8, trimmed, "call ")) break :blk trimmed["call ".len..];
        if (std.mem.startsWith(u8, trimmed, "invoke ")) break :blk trimmed["invoke ".len..];
        if (std.mem.startsWith(u8, trimmed, "tail call ")) break :blk trimmed["tail call ".len..];
        if (std.mem.startsWith(u8, trimmed, "musttail call ")) break :blk trimmed["musttail call ".len..];
        if (std.mem.startsWith(u8, trimmed, "notail call ")) break :blk trimmed["notail call ".len..];
        // Could also start with `%X = call ...`
        if (std.mem.indexOf(u8, trimmed, "= call ")) |eq_pos| {
            break :blk trimmed[eq_pos + "= call ".len ..];
        }
        if (std.mem.indexOf(u8, trimmed, "= invoke ")) |eq_pos| {
            break :blk trimmed[eq_pos + "= invoke ".len ..];
        }
        if (std.mem.indexOf(u8, trimmed, "= tail call ")) |eq_pos| {
            break :blk trimmed[eq_pos + "= tail call ".len ..];
        }
        return;
    };

    // Find the callee target. Look for the first `@` or `%` that introduces
    // the callee. Skip past type tokens up to the first `@`/`%` followed by
    // an identifier.
    var i: usize = 0;
    while (i < after_call.len) {
        const ch = after_call[i];
        if (ch == '@') {
            const name_end = nameEnd(after_call, i + 1);
            const name = after_call[i + 1 .. name_end];

            // Skip inline assembly, asm sideeffect, etc. — those have no @name.
            if (name.len == 0) return;

            if (std.mem.startsWith(u8, name, "llvm.")) {
                try out.append(palloc, .{
                    .caller_entity_id = caller,
                    .callee_entity_id = null,
                    .call_kind = "intrinsic",
                    .resolved_via = null,
                    .confidence = null,
                    .ast_node_id = null,
                    .site_line = site_line,
                });
                return;
            }

            const stripped = stripMonoSuffix(name);
            const callee_id = entity_by_qname.get(stripped);
            try out.append(palloc, .{
                .caller_entity_id = caller,
                .callee_entity_id = callee_id,
                .call_kind = "direct",
                .resolved_via = null,
                .confidence = null,
                .ast_node_id = null,
                .site_line = site_line,
            });
            return;
        } else if (ch == '%') {
            // Indirect call through a register/SSA value.
            try out.append(palloc, .{
                .caller_entity_id = caller,
                .callee_entity_id = null,
                .call_kind = "indirect",
                .resolved_via = null,
                .confidence = null,
                .ast_node_id = null,
                .site_line = site_line,
            });
            return;
        } else if (ch == '"') {
            // Skip quoted asm template, e.g. `call void asm sideeffect "stac"`.
            // Just bail — these are inline asm, not function calls.
            return;
        }
        i += 1;
    }
}

/// Find the end of an identifier starting at `start` in `s`.
fn nameEnd(s: []const u8, start: usize) usize {
    var i = start;
    while (i < s.len) {
        const c = s[i];
        // LLVM identifier chars: letters, digits, `.`, `_`, `$`, `-`
        if (std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '$' or c == '-') {
            i += 1;
        } else break;
    }
    return i;
}

/// Strip Zig's monomorphization suffix `__anon_NNNN` (and related variants
/// like `__struct_NNNN`) so generics map back to the AST-level qualified name.
fn stripMonoSuffix(name: []const u8) []const u8 {
    // Find the last `__` that precedes a known suffix prefix.
    const SUFFIX_PREFIXES = [_][]const u8{ "__anon_", "__struct_", "__enum_", "__union_" };
    for (SUFFIX_PREFIXES) |pref| {
        if (std.mem.lastIndexOf(u8, name, pref)) |pos| {
            return name[0..pos];
        }
    }
    return name;
}

fn extractAttrs(palloc: std.mem.Allocator, line: []const u8) !?[]const u8 {
    // Extract the comma-separated attribute words between `define` and `@`,
    // plus trailing `unnamed_addr`, `#N`, etc. For slice C just record the
    // linkage-prefix portion so we can distinguish weak/internal/etc. later.
    const at_idx = std.mem.indexOfScalar(u8, line, '@') orelse return null;
    const head = std.mem.trim(u8, line[0..at_idx], " \t");
    if (head.len == 0) return null;
    return try palloc.dupe(u8, head);
}
