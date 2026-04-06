const std = @import("std");

const Allocator = std.mem.Allocator;

pub const DisasmLine = struct {
    address: u64,
    text: []const u8,
    is_label: bool,
};

pub fn runObjdump(gpa: Allocator, path: []const u8) ![]const u8 {
    var child = std.process.Child.init(
        &.{ "objdump", "-d", "-M", "intel", path },
        gpa,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    const stdout = try child.stdout.?.readToEndAlloc(gpa, std.math.maxInt(u32));
    _ = try child.wait();

    return stdout;
}

pub fn parseDisasm(
    gpa: Allocator,
    output: []const u8,
    lines: *std.ArrayList(DisasmLine),
    addr_map: *std.AutoHashMap(u64, usize),
) void {
    var iter = std.mem.splitScalar(u8, output, '\n');
    while (iter.next()) |line| {
        if (line.len == 0) continue;

        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (parseInstructionAddr(trimmed)) |addr| {
            const display = extractInstruction(gpa, trimmed, addr) catch line;
            if (display.len == 0) continue;
            const idx = lines.items.len;
            lines.append(gpa, .{
                .address = addr,
                .text = display,
                .is_label = false,
            }) catch continue;
            addr_map.put(addr, idx) catch {};
        } else if (isLabelLine(trimmed)) {
            lines.append(gpa, .{
                .address = 0,
                .text = extractLabel(trimmed),
                .is_label = true,
            }) catch continue;
        }
    }
}

pub fn parseHexAddr(s: []const u8) ?u64 {
    var end: usize = 0;
    const start: usize = if (s.len > 2 and s[0] == '0' and s[1] == 'x') 2 else 0;
    end = start;
    while (end < s.len and std.ascii.isHex(s[end])) end += 1;
    if (end == start) return null;
    return std.fmt.parseInt(u64, s[start..end], 16) catch null;
}

fn extractInstruction(gpa: Allocator, line: []const u8, addr: u64) ![]const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return line;
    const after_colon = line[colon + 1 ..];
    const first_tab = std.mem.indexOfScalar(u8, after_colon, '\t') orelse return "";
    const after_hex = after_colon[first_tab + 1 ..];
    const second_tab = std.mem.indexOfScalar(u8, after_hex, '\t') orelse return "";
    const instruction = std.mem.trimLeft(u8, after_hex[second_tab + 1 ..], " ");
    if (instruction.len == 0) return "";
    return std.fmt.allocPrint(gpa, "{x}: {s}", .{ addr, instruction });
}

fn extractLabel(line: []const u8) []const u8 {
    const open = std.mem.indexOfScalar(u8, line, '<') orelse return line;
    const close = std.mem.indexOfScalar(u8, line, '>') orelse return line;
    if (close > open) return line[open .. close + 1];
    return line;
}

fn parseInstructionAddr(line: []const u8) ?u64 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    if (colon == 0) return null;
    const hex = line[0..colon];
    for (hex) |c| {
        if (!std.ascii.isHex(c)) return null;
    }
    return std.fmt.parseInt(u64, hex, 16) catch null;
}

fn isLabelLine(line: []const u8) bool {
    if (line.len == 0) return false;
    return std.mem.endsWith(u8, line, ">:") or
        (line[0] != ' ' and std.mem.indexOfScalar(u8, line, '<') != null);
}
