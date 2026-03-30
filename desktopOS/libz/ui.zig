const lib = @import("lib");
const font = lib.font;

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
        self.drawRect(x, y, w, bw, color);
        if (h > bw) self.drawRect(x, y + h - bw, w, bw, color);
        self.drawRect(x, y, bw, h, color);
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
            var line_end = i;
            while (line_end < text.len and text[line_end] != '\n' and (line_end - line_start) < cols) {
                line_end += 1;
            }

            if (line >= scroll_y) {
                const draw_y = py + (line - scroll_y) * char_h;
                if (draw_y + char_h > py + max_h) break;
                self.drawText(px, draw_y, text[line_start..line_end], max_w, fg, size);
            }

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
