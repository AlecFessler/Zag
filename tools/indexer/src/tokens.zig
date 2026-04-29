const std = @import("std");
const types = @import("types.zig");

const TokenRow = types.TokenRow;

/// Produces TokenRow records for one file. Allocations in `allocator`.
/// Returned slice references `source` for token text — keep source alive.
pub fn tokenize(allocator: std.mem.Allocator, source: [:0]const u8) ![]TokenRow {
    var tokenizer = std.zig.Tokenizer.init(source);
    var rows: std.ArrayList(TokenRow) = .empty;

    var paren_depth: i32 = 0;
    var brace_depth: i32 = 0;
    var idx: u32 = 0;

    while (true) {
        const tok = tokenizer.next();
        const text = source[tok.loc.start..tok.loc.end];
        const kind_str = tagToString(tok.tag);

        const this_paren = paren_depth;
        const this_brace = brace_depth;

        switch (tok.tag) {
            .l_paren => paren_depth += 1,
            .r_paren => paren_depth = @max(0, paren_depth - 1),
            .l_brace => brace_depth += 1,
            .r_brace => brace_depth = @max(0, brace_depth - 1),
            else => {},
        }

        try rows.append(allocator, .{
            .idx = idx,
            .kind = kind_str,
            .byte_start = @intCast(tok.loc.start),
            .byte_len = @intCast(tok.loc.end - tok.loc.start),
            .text = text,
            .paren_depth = @intCast(@max(0, this_paren)),
            .brace_depth = @intCast(@max(0, this_brace)),
        });
        idx += 1;

        if (tok.tag == .eof) break;
    }

    return try rows.toOwnedSlice(allocator);
}

/// Static string per token tag — no allocation needed when emitting.
fn tagToString(tag: std.zig.Token.Tag) []const u8 {
    return @tagName(tag);
}
