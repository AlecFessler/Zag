const font = @import("font8x16.zig");

// ── Color ─────────────────────────────────────────────────────────────

pub const Color = struct {
    r: u8,
    g: u8,
    b: u8,

    pub const white = Color{ .r = 0xFF, .g = 0xFF, .b = 0xFF };
    pub const black = Color{ .r = 0x00, .g = 0x00, .b = 0x00 };
    pub const dark_blue = Color{ .r = 0x0a, .g = 0x0a, .b = 0x1a };
    pub const dark_gray = Color{ .r = 0x30, .g = 0x30, .b = 0x30 };
    pub const light_gray = Color{ .r = 0xc0, .g = 0xc0, .b = 0xc0 };
    pub const red = Color{ .r = 0xFF, .g = 0x00, .b = 0x00 };
    pub const green = Color{ .r = 0x00, .g = 0xFF, .b = 0x00 };
    pub const blue = Color{ .r = 0x30, .g = 0x60, .b = 0xc0 };

    pub fn eql(a: Color, b: Color) bool {
        return a.r == b.r and a.g == b.g and a.b == b.b;
    }
};

// ── Edges ─────────────────────────────────────────────────────────────

pub const Edges = struct {
    top: u16 = 0,
    right: u16 = 0,
    bottom: u16 = 0,
    left: u16 = 0,

    pub fn all(v: u16) Edges {
        return .{ .top = v, .right = v, .bottom = v, .left = v };
    }

    pub fn symmetric(h: u16, v: u16) Edges {
        return .{ .top = v, .right = h, .bottom = v, .left = h };
    }

    pub fn horizontal(h: u16) Edges {
        return .{ .left = h, .right = h };
    }

    pub fn vertical(v: u16) Edges {
        return .{ .top = v, .bottom = v };
    }
};

// ── Border ────────────────────────────────────────────────────────────

pub const Border = struct {
    color: Color = Color.white,
    width: u8 = 0,
};

// ── Style ─────────────────────────────────────────────────────────────

pub const FlexDirection = enum { row, column };

pub const Style = struct {
    width: ?u32 = null,
    height: ?u32 = null,
    flex_direction: FlexDirection = .column,
    padding: Edges = .{},
    margin: Edges = .{},
    gap: u16 = 0,
    background: ?Color = null,
    border: Border = .{},
    font_color: Color = Color.white,
    font_size: u8 = 1,
};

// ── Node ──────────────────────────────────────────────────────────────

pub const MAX_NODES = 64;
pub const NONE: u8 = 0xFF;

pub const NodeKind = enum { box, text, text_box };

pub const Node = struct {
    kind: NodeKind = .box,
    style: Style = .{},
    parent: u8 = NONE,
    first_child: u8 = NONE,
    next_sibling: u8 = NONE,
    child_count: u8 = 0,
    text_ptr: [*]const u8 = undefined,
    text_len: u16 = 0,
    layout_x: u32 = 0,
    layout_y: u32 = 0,
    layout_w: u32 = 0,
    layout_h: u32 = 0,
    scroll_y: u32 = 0,
};

// ── UI ────────────────────────────────────────────────────────────────

pub const UI = struct {
    nodes: [MAX_NODES]Node = [_]Node{.{}} ** MAX_NODES,
    node_count: u8 = 0,
    root: u8 = NONE,
    pixels: [*]u32,
    width: u32,
    height: u32,
    stride: u32,
    format: u8,

    pub fn init(pixels: [*]u32, width: u32, height: u32, stride: u32, format: u8) UI {
        return .{
            .pixels = pixels,
            .width = width,
            .height = height,
            .stride = stride,
            .format = format,
        };
    }

    pub fn createBox(self: *UI, style: Style) u8 {
        return self.allocNode(.{ .kind = .box, .style = style });
    }

    pub fn createText(self: *UI, text: []const u8, style: Style) u8 {
        var node = Node{ .kind = .text, .style = style };
        node.text_ptr = text.ptr;
        node.text_len = @intCast(text.len);
        return self.allocNode(node);
    }

    pub fn createTextBox(self: *UI, text: []const u8, style: Style) u8 {
        var node = Node{ .kind = .text_box, .style = style };
        node.text_ptr = text.ptr;
        node.text_len = @intCast(text.len);
        return self.allocNode(node);
    }

    pub fn addChild(self: *UI, parent_idx: u8, child_idx: u8) void {
        if (parent_idx >= self.node_count or child_idx >= self.node_count) return;
        self.nodes[child_idx].parent = parent_idx;
        var parent = &self.nodes[parent_idx];
        if (parent.first_child == NONE) {
            parent.first_child = child_idx;
        } else {
            var last = parent.first_child;
            while (self.nodes[last].next_sibling != NONE) {
                last = self.nodes[last].next_sibling;
            }
            self.nodes[last].next_sibling = child_idx;
        }
        parent.child_count += 1;
    }

    pub fn setRoot(self: *UI, node: u8) void {
        self.root = node;
    }

    pub fn clear(self: *UI) void {
        self.node_count = 0;
        self.root = NONE;
        self.nodes = [_]Node{.{}} ** MAX_NODES;
    }

    // ── Layout ────────────────────────────────────────────────────────

    pub fn layout(self: *UI) void {
        if (self.root == NONE) return;
        self.layoutNode(self.root, 0, 0, self.width, self.height);
    }

    fn layoutNode(self: *UI, idx: u8, x: u32, y: u32, avail_w: u32, avail_h: u32) void {
        if (idx >= self.node_count) return;
        var node = &self.nodes[idx];
        const s = node.style;

        // Apply margin
        const ml: u32 = s.margin.left;
        const mr: u32 = s.margin.right;
        const mt: u32 = s.margin.top;
        const mb: u32 = s.margin.bottom;
        const margin_x = x + ml;
        const margin_y = y + mt;
        const margin_w = if (avail_w > ml + mr) avail_w - ml - mr else 0;
        const margin_h = if (avail_h > mt + mb) avail_h - mt - mb else 0;

        // Compute box dimensions
        const box_w = s.width orelse margin_w;
        const box_h = s.height orelse blk: {
            if (node.kind == .text) {
                break :blk @as(u32, font.height) * @as(u32, s.font_size);
            }
            break :blk margin_h;
        };

        node.layout_x = margin_x;
        node.layout_y = margin_y;
        node.layout_w = box_w;
        node.layout_h = box_h;

        // Compute inner content area (inside border + padding)
        const bw: u32 = s.border.width;
        const pl: u32 = s.padding.left;
        const pr: u32 = s.padding.right;
        const pt: u32 = s.padding.top;
        const pb: u32 = s.padding.bottom;
        const inset_l = bw + pl;
        const inset_r = bw + pr;
        const inset_t = bw + pt;
        const inset_b = bw + pb;
        const inner_x = margin_x + inset_l;
        const inner_y = margin_y + inset_t;
        const inner_w = if (box_w > inset_l + inset_r) box_w - inset_l - inset_r else 0;
        const inner_h = if (box_h > inset_t + inset_b) box_h - inset_t - inset_b else 0;

        // For text nodes, compute intrinsic width
        if (node.kind == .text) {
            const text_w = @as(u32, node.text_len) * font.width * @as(u32, s.font_size);
            if (s.width == null) {
                node.layout_w = @min(text_w + inset_l + inset_r, margin_w);
            }
            return;
        }

        // Layout children for box nodes
        if (node.kind != .box or node.first_child == NONE) return;

        // Count children and determine fixed vs auto sizes
        const is_row = s.flex_direction == .row;
        var fixed_total: u32 = 0;
        var auto_count: u32 = 0;
        var child_count: u32 = 0;
        {
            var ci = node.first_child;
            while (ci != NONE) : (ci = self.nodes[ci].next_sibling) {
                const cs = self.nodes[ci].style;
                const fixed_main = if (is_row) cs.width else cs.height;
                const cm_before: u32 = if (is_row) cs.margin.left else cs.margin.top;
                const cm_after: u32 = if (is_row) cs.margin.right else cs.margin.bottom;
                if (fixed_main) |fm| {
                    fixed_total += fm + cm_before + cm_after;
                } else if (self.nodes[ci].kind == .text) {
                    const tw = @as(u32, self.nodes[ci].text_len) * font.width * @as(u32, cs.font_size);
                    const th = @as(u32, font.height) * @as(u32, cs.font_size);
                    const intr = if (is_row) tw else th;
                    fixed_total += intr + cm_before + cm_after;
                } else {
                    auto_count += 1;
                }
                child_count += 1;
            }
        }

        const total_gap: u32 = if (child_count > 1) @as(u32, s.gap) * (child_count - 1) else 0;
        const main_avail = if (is_row) inner_w else inner_h;
        const remaining = if (main_avail > fixed_total + total_gap) main_avail - fixed_total - total_gap else 0;
        const auto_size = if (auto_count > 0) remaining / auto_count else 0;

        // Position children
        var cursor: u32 = 0;
        var ci = node.first_child;
        var first = true;
        while (ci != NONE) {
            if (!first) cursor += s.gap;
            first = false;

            const cs = self.nodes[ci].style;
            const fixed_main = if (is_row) cs.width else cs.height;
            const cm_before: u32 = if (is_row) cs.margin.left else cs.margin.top;
            const cm_after: u32 = if (is_row) cs.margin.right else cs.margin.bottom;

            var child_main: u32 = undefined;
            if (fixed_main) |fm| {
                child_main = fm + cm_before + cm_after;
            } else if (self.nodes[ci].kind == .text) {
                const tw = @as(u32, self.nodes[ci].text_len) * font.width * @as(u32, cs.font_size);
                const th = @as(u32, font.height) * @as(u32, cs.font_size);
                child_main = (if (is_row) tw else th) + cm_before + cm_after;
            } else {
                child_main = auto_size;
            }

            const child_x = if (is_row) inner_x + cursor else inner_x;
            const child_y = if (is_row) inner_y else inner_y + cursor;
            const child_w = if (is_row) child_main else inner_w;
            const child_h = if (is_row) inner_h else child_main;

            self.layoutNode(ci, child_x, child_y, child_w, child_h);
            cursor += child_main;
            ci = self.nodes[ci].next_sibling;
        }
    }

    // ── Rendering ─────────────────────────────────────────────────────

    pub fn render(self: *UI) void {
        if (self.root == NONE) return;
        self.renderNode(self.root);
    }

    fn renderNode(self: *UI, idx: u8) void {
        if (idx >= self.node_count) return;
        const node = &self.nodes[idx];

        // Background
        if (node.style.background) |bg| {
            self.drawRect(node.layout_x, node.layout_y, node.layout_w, node.layout_h, self.packPixel(bg));
        }

        // Border
        const bw: u32 = node.style.border.width;
        if (bw > 0) {
            self.drawBorder(node.layout_x, node.layout_y, node.layout_w, node.layout_h, node.style.border);
        }

        switch (node.kind) {
            .text => {
                const inset_x = node.layout_x + @as(u32, node.style.border.width) + @as(u32, node.style.padding.left);
                const inset_y = node.layout_y + @as(u32, node.style.border.width) + @as(u32, node.style.padding.top);
                const inner_w = node.layout_w;
                const text = node.text_ptr[0..node.text_len];
                self.drawText(inset_x, inset_y, text, inner_w, self.packPixel(node.style.font_color), node.style.font_size);
            },
            .text_box => {
                const inset_x = node.layout_x + @as(u32, node.style.border.width) + @as(u32, node.style.padding.left);
                const inset_y = node.layout_y + @as(u32, node.style.border.width) + @as(u32, node.style.padding.top);
                const inset_r = @as(u32, node.style.border.width) + @as(u32, node.style.padding.right);
                const inset_b = @as(u32, node.style.border.width) + @as(u32, node.style.padding.bottom);
                const inner_w = if (node.layout_w > @as(u32, node.style.padding.left) + inset_r) node.layout_w - @as(u32, node.style.padding.left) - inset_r else 0;
                const inner_h = if (node.layout_h > @as(u32, node.style.padding.top) + inset_b) node.layout_h - @as(u32, node.style.padding.top) - inset_b else 0;
                const text = node.text_ptr[0..node.text_len];
                self.drawTextWrapped(inset_x, inset_y, text, inner_w, inner_h, self.packPixel(node.style.font_color), node.style.font_size, node.scroll_y);
            },
            .box => {
                var ci = node.first_child;
                while (ci != NONE) {
                    self.renderNode(ci);
                    ci = self.nodes[ci].next_sibling;
                }
            },
        }
    }

    // ── Drawing primitives ────────────────────────────────────────────

    fn packPixel(self: *const UI, c: Color) u32 {
        if (self.format == 0) { // BGR8
            return @as(u32, c.b) | (@as(u32, c.g) << 8) | (@as(u32, c.r) << 16);
        } else { // RGB8
            return @as(u32, c.r) | (@as(u32, c.g) << 8) | (@as(u32, c.b) << 16);
        }
    }

    fn drawRect(self: *UI, x: u32, y: u32, w: u32, h: u32, color: u32) void {
        var py: u32 = y;
        while (py < y + h and py < self.height) : (py += 1) {
            var px: u32 = x;
            while (px < x + w and px < self.width) : (px += 1) {
                self.pixels[py * self.stride + px] = color;
            }
        }
    }

    fn drawBorder(self: *UI, x: u32, y: u32, w: u32, h: u32, border: Border) void {
        const bw: u32 = border.width;
        const color = self.packPixel(border.color);
        // Top
        self.drawRect(x, y, w, bw, color);
        // Bottom
        if (h > bw) self.drawRect(x, y + h - bw, w, bw, color);
        // Left
        self.drawRect(x, y, bw, h, color);
        // Right
        if (w > bw) self.drawRect(x + w - bw, y, bw, h, color);
    }

    fn drawChar(self: *UI, px: u32, py: u32, char: u8, fg: u32, size: u8) void {
        const s: u32 = size;
        const glyph_start = @as(u32, char) * font.height;
        const glyph = font.data[glyph_start..][0..font.height];
        for (0..font.height) |row| {
            const bits = glyph[row];
            for (0..font.width) |col| {
                if ((bits >> @as(u3, @intCast(7 - col))) & 1 != 0) {
                    var sy: u32 = 0;
                    while (sy < s) : (sy += 1) {
                        var sx: u32 = 0;
                        while (sx < s) : (sx += 1) {
                            const dx = px + @as(u32, @intCast(col)) * s + sx;
                            const dy = py + @as(u32, @intCast(row)) * s + sy;
                            if (dx < self.width and dy < self.height) {
                                self.pixels[dy * self.stride + dx] = fg;
                            }
                        }
                    }
                }
            }
        }
    }

    fn drawText(self: *UI, px: u32, py: u32, text: []const u8, max_w: u32, fg: u32, size: u8) void {
        const char_w: u32 = font.width * @as(u32, size);
        var cx = px;
        for (text) |ch| {
            if (cx + char_w > px + max_w) break;
            self.drawChar(cx, py, ch, fg, size);
            cx += char_w;
        }
    }

    fn drawTextWrapped(self: *UI, px: u32, py: u32, text: []const u8, max_w: u32, max_h: u32, fg: u32, size: u8, scroll_y: u32) void {
        const char_w: u32 = font.width * @as(u32, size);
        const char_h: u32 = font.height * @as(u32, size);
        if (char_w == 0 or char_h == 0 or max_w == 0) return;
        const cols = max_w / char_w;
        if (cols == 0) return;

        var line: u32 = 0;
        var i: u32 = 0;
        while (i < text.len) {
            const line_start = i;
            // Find end of this line (newline or cols chars)
            var line_end = i;
            while (line_end < text.len and text[line_end] != '\n' and (line_end - line_start) < cols) {
                line_end += 1;
            }

            if (line >= scroll_y) {
                const draw_y = py + (line - scroll_y) * char_h;
                if (draw_y + char_h > py + max_h) break;
                self.drawText(px, draw_y, text[line_start..line_end], max_w, fg, size);
            }

            // Skip newline
            if (line_end < text.len and text[line_end] == '\n') line_end += 1;
            i = line_end;
            line += 1;
        }
    }

    fn allocNode(self: *UI, node: Node) u8 {
        if (self.node_count >= MAX_NODES) return NONE;
        const idx = self.node_count;
        self.nodes[idx] = node;
        self.node_count += 1;
        return idx;
    }
};

// ── Tiling ───────────────────────────────────────────────────────────

pub const Tile = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
};

pub const MAX_TILES = 16;
const MAX_TILE_NODES = 2 * MAX_TILES - 1;

const SplitDir = enum(u8) { horizontal, vertical };

const TileNode = struct {
    occupied: bool = false,
    is_leaf: bool = true,
    app_index: u8 = 0,
    split_dir: SplitDir = .horizontal,
};

pub const TileTree = struct {
    nodes: [MAX_TILE_NODES]TileNode = [_]TileNode{.{}} ** MAX_TILE_NODES,
    tiles: [MAX_TILES]Tile = undefined,

    fn left(i: usize) usize {
        return 2 * i + 1;
    }

    fn right(i: usize) usize {
        return 2 * i + 2;
    }

    fn depth(idx: usize) u32 {
        if (idx == 0) return 0;
        var d: u32 = 0;
        var i = idx;
        while (i > 0) {
            i = (i - 1) / 2;
            d += 1;
        }
        return d;
    }

    fn findLeaf(self: *const TileTree, idx: usize, app_index: u8) ?usize {
        if (idx >= MAX_TILE_NODES or !self.nodes[idx].occupied) return null;
        if (self.nodes[idx].is_leaf) {
            if (self.nodes[idx].app_index == app_index) return idx;
            return null;
        }
        return self.findLeaf(left(idx), app_index) orelse self.findLeaf(right(idx), app_index);
    }

    fn firstLeaf(self: *const TileTree, idx: usize) ?usize {
        if (idx >= MAX_TILE_NODES or !self.nodes[idx].occupied) return null;
        if (self.nodes[idx].is_leaf) return idx;
        return self.firstLeaf(left(idx)) orelse self.firstLeaf(right(idx));
    }

    pub fn addWindow(self: *TileTree, app_index: u8, active: u8) void {
        if (!self.nodes[0].occupied) {
            self.nodes[0] = .{ .occupied = true, .is_leaf = true, .app_index = app_index };
            return;
        }

        const target = self.findLeaf(0, active) orelse self.firstLeaf(0) orelse return;

        const l = left(target);
        const r = right(target);
        if (l >= MAX_TILE_NODES or r >= MAX_TILE_NODES) return;

        const d = depth(target);
        const dir: SplitDir = if (d % 2 == 0) .horizontal else .vertical;

        const old_app = self.nodes[target].app_index;
        self.nodes[target] = .{ .occupied = true, .is_leaf = false, .split_dir = dir };
        self.nodes[l] = .{ .occupied = true, .is_leaf = true, .app_index = old_app };
        self.nodes[r] = .{ .occupied = true, .is_leaf = true, .app_index = app_index };
    }

    pub fn removeWindow(self: *TileTree, app_index: u8) void {
        const leaf_idx = self.findLeaf(0, app_index) orelse return;

        if (leaf_idx == 0) {
            self.nodes[0].occupied = false;
            return;
        }

        const parent_idx = (leaf_idx - 1) / 2;
        const sibling_idx = if (leaf_idx == left(parent_idx)) right(parent_idx) else left(parent_idx);

        self.nodes[parent_idx] = self.nodes[sibling_idx];

        if (!self.nodes[sibling_idx].is_leaf) {
            self.copySubtree(sibling_idx, parent_idx);
        }

        self.clearSubtree(sibling_idx);
        self.nodes[leaf_idx].occupied = false;
    }

    fn copySubtree(self: *TileTree, from: usize, to: usize) void {
        const fl = left(from);
        const fr = right(from);
        const tl = left(to);
        const tr = right(to);
        if (fl >= MAX_TILE_NODES or tl >= MAX_TILE_NODES) return;

        self.nodes[tl] = self.nodes[fl];
        self.nodes[tr] = self.nodes[fr];

        if (self.nodes[fl].occupied and !self.nodes[fl].is_leaf) self.copySubtree(fl, tl);
        if (self.nodes[fr].occupied and !self.nodes[fr].is_leaf) self.copySubtree(fr, tr);
    }

    fn clearSubtree(self: *TileTree, idx: usize) void {
        self.nodes[idx].occupied = false;
        const l = left(idx);
        const r = right(idx);
        if (l < MAX_TILE_NODES and self.nodes[l].occupied) self.clearSubtree(l);
        if (r < MAX_TILE_NODES and self.nodes[r].occupied) self.clearSubtree(r);
    }

    pub fn layout(self: *TileTree, screen_w: u32, screen_h: u32, gap: u32) void {
        self.layoutNode(0, 0, 0, screen_w, screen_h, gap);
    }

    fn layoutNode(self: *TileTree, idx: usize, x: u32, y: u32, w: u32, h: u32, gap: u32) void {
        if (idx >= MAX_TILE_NODES or !self.nodes[idx].occupied) return;

        if (self.nodes[idx].is_leaf) {
            const ai = self.nodes[idx].app_index;
            if (ai < MAX_TILES) {
                self.tiles[ai] = .{ .x = x, .y = y, .w = w, .h = h };
            }
            return;
        }

        const l = left(idx);
        const r = right(idx);

        if (self.nodes[idx].split_dir == .horizontal) {
            const half = w / 2;
            const g = if (half > gap) gap else 0;
            self.layoutNode(l, x, y, half - g, h, gap);
            self.layoutNode(r, x + half + g, y, w - half - g, h, gap);
        } else {
            const half = h / 2;
            const g = if (half > gap) gap else 0;
            self.layoutNode(l, x, y, w, half - g, gap);
            self.layoutNode(r, x, y + half + g, w, h - half - g, gap);
        }
    }
};

// ── Unit Tests ────────────────────────────────────────────────────────

const std = @import("std");
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

fn makeUI(comptime W: u32, comptime H: u32, buf: *[W * H]u32) UI {
    @memset(buf, 0);
    return UI.init(buf, W, H, W, 0);
}

// ── Layout tests ──────────────────────────────────────────────────────

test "single box fills root" {
    var buf: [100 * 80]u32 = undefined;
    var ui = makeUI(100, 80, &buf);
    const root = ui.createBox(.{});
    ui.setRoot(root);
    ui.layout();
    try expectEqual(@as(u32, 0), ui.nodes[root].layout_x);
    try expectEqual(@as(u32, 0), ui.nodes[root].layout_y);
    try expectEqual(@as(u32, 100), ui.nodes[root].layout_w);
    try expectEqual(@as(u32, 80), ui.nodes[root].layout_h);
}

test "fixed-size child" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const root = ui.createBox(.{ .flex_direction = .column });
    const child = ui.createBox(.{ .height = 50 });
    ui.setRoot(root);
    ui.addChild(root, child);
    ui.layout();
    try expectEqual(@as(u32, 50), ui.nodes[child].layout_h);
    try expectEqual(@as(u32, 100), ui.nodes[child].layout_w);
}

test "padding reduces inner area" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const root = ui.createBox(.{ .padding = Edges.all(10) });
    const child = ui.createBox(.{});
    ui.setRoot(root);
    ui.addChild(root, child);
    ui.layout();
    try expectEqual(@as(u32, 10), ui.nodes[child].layout_x);
    try expectEqual(@as(u32, 10), ui.nodes[child].layout_y);
    try expectEqual(@as(u32, 80), ui.nodes[child].layout_w);
    try expectEqual(@as(u32, 80), ui.nodes[child].layout_h);
}

test "margin offsets child" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const root = ui.createBox(.{});
    const child = ui.createBox(.{ .margin = Edges.all(8) });
    ui.setRoot(root);
    ui.addChild(root, child);
    ui.layout();
    try expectEqual(@as(u32, 8), ui.nodes[child].layout_x);
    try expectEqual(@as(u32, 8), ui.nodes[child].layout_y);
    try expectEqual(@as(u32, 84), ui.nodes[child].layout_w);
    try expectEqual(@as(u32, 84), ui.nodes[child].layout_h);
}

test "column flex two auto children" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const root = ui.createBox(.{ .flex_direction = .column });
    const c1 = ui.createBox(.{});
    const c2 = ui.createBox(.{});
    ui.setRoot(root);
    ui.addChild(root, c1);
    ui.addChild(root, c2);
    ui.layout();
    try expectEqual(@as(u32, 50), ui.nodes[c1].layout_h);
    try expectEqual(@as(u32, 50), ui.nodes[c2].layout_h);
    try expectEqual(@as(u32, 0), ui.nodes[c1].layout_y);
    try expectEqual(@as(u32, 50), ui.nodes[c2].layout_y);
}

test "column flex fixed + auto" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const root = ui.createBox(.{ .flex_direction = .column });
    const c1 = ui.createBox(.{ .height = 30 });
    const c2 = ui.createBox(.{});
    ui.setRoot(root);
    ui.addChild(root, c1);
    ui.addChild(root, c2);
    ui.layout();
    try expectEqual(@as(u32, 30), ui.nodes[c1].layout_h);
    try expectEqual(@as(u32, 70), ui.nodes[c2].layout_h);
    try expectEqual(@as(u32, 30), ui.nodes[c2].layout_y);
}

test "row flex two auto children" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const root = ui.createBox(.{ .flex_direction = .row });
    const c1 = ui.createBox(.{});
    const c2 = ui.createBox(.{});
    ui.setRoot(root);
    ui.addChild(root, c1);
    ui.addChild(root, c2);
    ui.layout();
    try expectEqual(@as(u32, 50), ui.nodes[c1].layout_w);
    try expectEqual(@as(u32, 50), ui.nodes[c2].layout_w);
    try expectEqual(@as(u32, 0), ui.nodes[c1].layout_x);
    try expectEqual(@as(u32, 50), ui.nodes[c2].layout_x);
}

test "gap between children" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const root = ui.createBox(.{ .flex_direction = .column, .gap = 10 });
    const c1 = ui.createBox(.{});
    const c2 = ui.createBox(.{});
    ui.setRoot(root);
    ui.addChild(root, c1);
    ui.addChild(root, c2);
    ui.layout();
    // Available: 100, gap: 10, two auto children: (100-10)/2 = 45 each
    try expectEqual(@as(u32, 45), ui.nodes[c1].layout_h);
    try expectEqual(@as(u32, 45), ui.nodes[c2].layout_h);
    try expectEqual(@as(u32, 0), ui.nodes[c1].layout_y);
    try expectEqual(@as(u32, 55), ui.nodes[c2].layout_y); // 45 + 10
}

test "nested boxes" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const outer = ui.createBox(.{ .padding = Edges.all(10) });
    const inner = ui.createBox(.{ .padding = Edges.all(5) });
    const leaf = ui.createBox(.{});
    ui.setRoot(outer);
    ui.addChild(outer, inner);
    ui.addChild(inner, leaf);
    ui.layout();
    try expectEqual(@as(u32, 15), ui.nodes[leaf].layout_x);
    try expectEqual(@as(u32, 15), ui.nodes[leaf].layout_y);
    try expectEqual(@as(u32, 70), ui.nodes[leaf].layout_w);
    try expectEqual(@as(u32, 70), ui.nodes[leaf].layout_h);
}

test "border reduces content area" {
    var buf: [100 * 100]u32 = undefined;
    var ui = makeUI(100, 100, &buf);
    const root = ui.createBox(.{ .border = .{ .width = 2, .color = Color.white } });
    const child = ui.createBox(.{});
    ui.setRoot(root);
    ui.addChild(root, child);
    ui.layout();
    try expectEqual(@as(u32, 2), ui.nodes[child].layout_x);
    try expectEqual(@as(u32, 2), ui.nodes[child].layout_y);
    try expectEqual(@as(u32, 96), ui.nodes[child].layout_w);
    try expectEqual(@as(u32, 96), ui.nodes[child].layout_h);
}

test "padding + border + margin combined" {
    var buf: [200 * 200]u32 = undefined;
    var ui = makeUI(200, 200, &buf);
    const root = ui.createBox(.{
        .border = .{ .width = 3, .color = Color.white },
        .padding = Edges.all(7),
    });
    const child = ui.createBox(.{ .margin = Edges.all(5) });
    ui.setRoot(root);
    ui.addChild(root, child);
    ui.layout();
    // child offset = border(3) + padding(7) + margin(5) = 15
    try expectEqual(@as(u32, 15), ui.nodes[child].layout_x);
    try expectEqual(@as(u32, 15), ui.nodes[child].layout_y);
    // child size = 200 - 2*(border+padding) - 2*margin = 200 - 20 - 10 = 170
    try expectEqual(@as(u32, 170), ui.nodes[child].layout_w);
    try expectEqual(@as(u32, 170), ui.nodes[child].layout_h);
}

test "text node intrinsic size" {
    var buf: [200 * 100]u32 = undefined;
    var ui = makeUI(200, 100, &buf);
    const root = ui.createBox(.{});
    const txt = ui.createText("Hello", .{ .font_size = 1 });
    ui.setRoot(root);
    ui.addChild(root, txt);
    ui.layout();
    // "Hello" = 5 chars * 8px = 40px wide, 16px tall
    try expectEqual(@as(u32, 40), ui.nodes[txt].layout_w);
    try expectEqual(@as(u32, 16), ui.nodes[txt].layout_h);
}

// ── Rendering tests ───────────────────────────────────────────────────

test "background fill" {
    var buf: [10 * 10]u32 = undefined;
    var ui = makeUI(10, 10, &buf);
    const root = ui.createBox(.{ .background = Color.red });
    ui.setRoot(root);
    ui.layout();
    ui.render();
    const red_px = ui.packPixel(Color.red);
    for (0..10) |y| {
        for (0..10) |x| {
            try expectEqual(red_px, buf[y * 10 + x]);
        }
    }
}

test "border rendering" {
    var buf: [20 * 20]u32 = undefined;
    var ui = makeUI(20, 20, &buf);
    const root = ui.createBox(.{ .border = .{ .width = 2, .color = Color.white } });
    ui.setRoot(root);
    ui.layout();
    ui.render();
    const white_px = ui.packPixel(Color.white);
    // Top-left corner should be border
    try expectEqual(white_px, buf[0 * 20 + 0]);
    try expectEqual(white_px, buf[1 * 20 + 0]);
    // Interior (5,5) should NOT be border (it's 0 since no background)
    try expectEqual(@as(u32, 0), buf[5 * 20 + 5]);
    // Bottom-right border
    try expectEqual(white_px, buf[19 * 20 + 19]);
    try expectEqual(white_px, buf[18 * 20 + 19]);
}

test "child drawn inside parent padding" {
    var buf: [20 * 20]u32 = undefined;
    var ui = makeUI(20, 20, &buf);
    const parent = ui.createBox(.{ .padding = Edges.all(4), .background = Color.red });
    const child = ui.createBox(.{ .background = Color.blue });
    ui.setRoot(parent);
    ui.addChild(parent, child);
    ui.layout();
    ui.render();
    const red_px = ui.packPixel(Color.red);
    const blue_px = ui.packPixel(Color.blue);
    // (3,3) is in parent padding area
    try expectEqual(red_px, buf[3 * 20 + 3]);
    // (4,4) is start of child area
    try expectEqual(blue_px, buf[4 * 20 + 4]);
    // (15,15) is last pixel of child (20-4-1=15)
    try expectEqual(blue_px, buf[15 * 20 + 15]);
    // (16,16) is back in padding
    try expectEqual(red_px, buf[16 * 20 + 16]);
}

test "text renders glyph pixels" {
    // Character 'A' (0x41) in font8x16: check a known bit pattern
    // Row 0-3 of 'A' at 8x16 are typically 0x00, then the shape starts
    var buf: [20 * 20]u32 = undefined;
    var ui = makeUI(20, 20, &buf);
    const root = ui.createBox(.{ .background = Color.black });
    const txt = ui.createText("A", .{ .font_color = Color.white, .font_size = 1 });
    ui.setRoot(root);
    ui.addChild(root, txt);
    ui.layout();
    ui.render();
    const white_px = ui.packPixel(Color.white);
    // The glyph for 'A' (0x41) should have some set pixels
    // Check that at least one pixel in the glyph area is white
    var found_fg = false;
    for (0..16) |y| {
        for (0..8) |x| {
            if (buf[y * 20 + x] == white_px) {
                found_fg = true;
                break;
            }
        }
    }
    try expect(found_fg);
}
