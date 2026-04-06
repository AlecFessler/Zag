const std = @import("std");
const ansi = @import("ansi.zig");

pub const SyntaxColor = enum(u8) {
    default,
    keyword,
    string,
    number,
    comment,
    builtin,
    type_ident,
    asm_address,
    asm_mnemonic,
    asm_register,
    asm_immediate,
    asm_label,

    pub fn escape(c: SyntaxColor) []const u8 {
        return switch (c) {
            .default => "",
            .keyword => ansi.fg_keyword,
            .string => ansi.fg_string,
            .number => ansi.fg_number,
            .comment => ansi.fg_comment,
            .builtin => ansi.fg_builtin,
            .type_ident => ansi.fg_type,
            .asm_address => ansi.fg_asm_address,
            .asm_mnemonic => ansi.fg_asm_mnemonic,
            .asm_register => ansi.fg_asm_register,
            .asm_immediate => ansi.fg_asm_immediate,
            .asm_label => ansi.fg_asm_label,
        };
    }
};

pub fn highlightZigLine(line: []const u8, colors: []SyntaxColor) void {
    @memset(colors[0..line.len], .default);
    var buf: [4096]u8 = undefined;
    if (line.len >= buf.len) return;
    @memcpy(buf[0..line.len], line);
    buf[line.len] = 0;
    const z_line: [:0]const u8 = buf[0..line.len :0];

    var tok = std.zig.Tokenizer.init(z_line);
    var prev_end: usize = 0;

    while (true) {
        const token = tok.next();
        if (token.tag == .eof) break;

        if (token.loc.start > prev_end) {
            const gap = z_line[prev_end..token.loc.start];
            if (std.mem.indexOf(u8, gap, "//")) |offset| {
                @memset(colors[prev_end + offset .. line.len], .comment);
                return;
            }
        }

        const color = classifyZigToken(token.tag, z_line[token.loc.start..token.loc.end]);
        @memset(colors[token.loc.start..token.loc.end], color);
        prev_end = token.loc.end;
    }

    if (prev_end < line.len) {
        const gap = z_line[prev_end..line.len];
        if (std.mem.indexOf(u8, gap, "//")) |offset| {
            @memset(colors[prev_end + offset .. line.len], .comment);
        }
    }
}

pub fn highlightDisasm(text: []const u8, is_label: bool, colors: []SyntaxColor) void {
    @memset(colors[0..text.len], .default);
    if (is_label) {
        @memset(colors[0..text.len], .asm_label);
        return;
    }

    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return;
    @memset(colors[0 .. colon + 1], .asm_address);

    var pos = colon + 1;
    while (pos < text.len and text[pos] == ' ') : (pos += 1) {}

    // Mnemonic
    const mn_start = pos;
    while (pos < text.len and text[pos] != ' ') : (pos += 1) {}
    if (mn_start < pos) @memset(colors[mn_start..pos], .asm_mnemonic);

    // Operands
    while (pos < text.len) {
        if (text[pos] == '<') {
            const end = std.mem.indexOfScalarPos(u8, text, pos + 1, '>') orelse text.len - 1;
            @memset(colors[pos .. end + 1], .asm_label);
            pos = end + 1;
        } else if (text[pos] == '0' and pos + 1 < text.len and text[pos + 1] == 'x') {
            const s = pos;
            pos += 2;
            while (pos < text.len and std.ascii.isHex(text[pos])) : (pos += 1) {}
            @memset(colors[s..pos], .asm_immediate);
        } else if (std.ascii.isAlphabetic(text[pos])) {
            const s = pos;
            while (pos < text.len and (std.ascii.isAlphanumeric(text[pos]) or text[pos] == '_')) : (pos += 1) {}
            if (isX86Register(text[s..pos])) @memset(colors[s..pos], .asm_register);
        } else {
            pos += 1;
        }
    }
}

fn classifyZigToken(tag: std.zig.Token.Tag, text: []const u8) SyntaxColor {
    return switch (tag) {
        .string_literal, .multiline_string_literal_line, .char_literal => .string,
        .number_literal => .number,
        .builtin => .builtin,
        .doc_comment, .container_doc_comment => .comment,
        .identifier => classifyIdentifier(text),
        else => if (isKeywordTag(tag)) .keyword else .default,
    };
}

fn isKeywordTag(tag: std.zig.Token.Tag) bool {
    const t = @intFromEnum(tag);
    return t >= @intFromEnum(std.zig.Token.Tag.keyword_addrspace) and
        t <= @intFromEnum(std.zig.Token.Tag.keyword_while);
}

fn classifyIdentifier(text: []const u8) SyntaxColor {
    if (text.len == 0) return .default;
    if (std.zig.primitives.isPrimitive(text)) return .type_ident;
    if (text[0] >= 'A' and text[0] <= 'Z') return .type_ident;
    return .default;
}

fn isX86Register(name: []const u8) bool {
    const regs = std.StaticStringMap(void).initComptime(.{
        .{ "rax", {} }, .{ "rbx", {} }, .{ "rcx", {} }, .{ "rdx", {} },
        .{ "rsi", {} }, .{ "rdi", {} }, .{ "rsp", {} }, .{ "rbp", {} },
        .{ "r8", {} },  .{ "r9", {} },  .{ "r10", {} }, .{ "r11", {} },
        .{ "r12", {} }, .{ "r13", {} }, .{ "r14", {} }, .{ "r15", {} },
        .{ "eax", {} }, .{ "ebx", {} }, .{ "ecx", {} }, .{ "edx", {} },
        .{ "esi", {} }, .{ "edi", {} }, .{ "esp", {} }, .{ "ebp", {} },
        .{ "ax", {} },  .{ "bx", {} },  .{ "cx", {} },  .{ "dx", {} },
        .{ "si", {} },  .{ "di", {} },  .{ "sp", {} },  .{ "bp", {} },
        .{ "al", {} },  .{ "bl", {} },  .{ "cl", {} },  .{ "dl", {} },
        .{ "ah", {} },  .{ "bh", {} },  .{ "ch", {} },  .{ "dh", {} },
        .{ "sil", {} }, .{ "dil", {} }, .{ "spl", {} }, .{ "bpl", {} },
        .{ "r8b", {} }, .{ "r9b", {} }, .{ "r10b", {} }, .{ "r11b", {} },
        .{ "r12b", {} }, .{ "r13b", {} }, .{ "r14b", {} }, .{ "r15b", {} },
        .{ "r8w", {} }, .{ "r9w", {} }, .{ "r10w", {} }, .{ "r11w", {} },
        .{ "r12w", {} }, .{ "r13w", {} }, .{ "r14w", {} }, .{ "r15w", {} },
        .{ "r8d", {} }, .{ "r9d", {} }, .{ "r10d", {} }, .{ "r11d", {} },
        .{ "r12d", {} }, .{ "r13d", {} }, .{ "r14d", {} }, .{ "r15d", {} },
        .{ "xmm0", {} }, .{ "xmm1", {} }, .{ "xmm2", {} }, .{ "xmm3", {} },
        .{ "xmm4", {} }, .{ "xmm5", {} }, .{ "xmm6", {} }, .{ "xmm7", {} },
        .{ "xmm8", {} }, .{ "xmm9", {} }, .{ "xmm10", {} }, .{ "xmm11", {} },
        .{ "xmm12", {} }, .{ "xmm13", {} }, .{ "xmm14", {} }, .{ "xmm15", {} },
        .{ "cs", {} },  .{ "ds", {} },  .{ "es", {} },  .{ "fs", {} },
        .{ "gs", {} },  .{ "ss", {} },  .{ "rip", {} }, .{ "eip", {} },
        .{ "cr0", {} }, .{ "cr2", {} }, .{ "cr3", {} }, .{ "cr4", {} },
    });
    return regs.has(name);
}
