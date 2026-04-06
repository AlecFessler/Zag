const lib = @import("lib");

const font = lib.font;
const ui_mod = lib.ui;

const Color = ui_mod.Color;
const Edges = ui_mod.Edges;
const UI = ui_mod.UI;

const HISTORY_SIZE = 4096;
const INPUT_SIZE = 256;
const RENDER_SIZE = HISTORY_SIZE + INPUT_SIZE + 16;

// ── Buffer state ─────────────────────────────────────────────────────
var history_buf: [HISTORY_SIZE]u8 = undefined;
var history_len: u16 = 0;

var input_buf: [INPUT_SIZE]u8 = undefined;
var input_len: u16 = 0;

var render_buf: [RENDER_SIZE]u8 = undefined;
var render_len: u16 = 0;

// ── Configurable colors ─────────────────────────────────────────────
pub var bg_color: Color = Color{ .r = 0x1a, .g = 0x1a, .b = 0x2e };

pub fn setBgColor(r: u8, g: u8, b: u8) void {
    bg_color = Color{ .r = r, .g = g, .b = b };
}

// ── Public accessors ─────────────────────────────────────────────────
pub fn inputBuf() []u8 {
    return input_buf[0..INPUT_SIZE];
}

pub fn inputLen() *u16 {
    return &input_len;
}

pub fn appendHistory(text: []const u8) void {
    for (text) |ch| {
        if (history_len >= HISTORY_SIZE) break;
        history_buf[history_len] = ch;
        history_len += 1;
    }
}

pub fn clearHistory() void {
    history_len = 0;
}

// ── Render buffer management ─────────────────────────────────────────
fn rebuildRenderBuf() void {
    render_len = 0;
    const hl: usize = history_len;
    if (hl > 0) {
        @memcpy(render_buf[0..hl], history_buf[0..hl]);
        render_len = @intCast(hl);
    }
    const prompt = "> ";
    const pl: usize = prompt.len;
    @memcpy(render_buf[render_len..][0..pl], prompt);
    render_len += @intCast(pl);
    const il: usize = input_len;
    if (il > 0) {
        @memcpy(render_buf[render_len..][0..il], input_buf[0..il]);
        render_len += @intCast(il);
    }
    render_buf[render_len] = '_';
    render_len += 1;
}

fn calcScrollY(text_w: u32, text_h: u32) u32 {
    const char_w: u32 = font.width;
    const char_h: u32 = font.height;
    if (char_w == 0 or char_h == 0 or text_w == 0) return 0;
    const cols = text_w / char_w;
    if (cols == 0) return 0;

    var lines: u32 = 0;
    var i: u32 = 0;
    const len: u32 = render_len;
    while (i < len) {
        const line_start = i;
        while (i < len and render_buf[i] != '\n' and (i - line_start) < cols) {
            i += 1;
        }
        lines += 1;
        if (i < len and render_buf[i] == '\n') i += 1;
    }

    const visible_lines = text_h / char_h;
    if (lines > visible_lines) {
        return lines - visible_lines;
    }
    return 0;
}

// ── Frame rendering ──────────────────────────────────────────────────
pub fn renderFrame(frame_pixels: [*]u32, width: u32, height: u32, stride: u32) void {
    if (width == 0 or height == 0) return;

    var ui_state = UI.init(frame_pixels, width, height, stride, 0);
    const ui = &ui_state;

    const root = ui.createBox(.{
        .flex_direction = .column,
        .background = bg_color,
    });
    ui.setRoot(root);

    rebuildRenderBuf();

    const text_w = if (width > 16) width - 16 else 0;
    const text_h = if (height > 16) height - 16 else 0;
    const scroll = calcScrollY(text_w, text_h);

    var body_node = ui.createTextBox(render_buf[0..render_len], .{
        .padding = Edges.all(8),
        .font_color = Color{ .r = 0x00, .g = 0xcc, .b = 0x00 },
        .font_size = 1,
    });
    _ = &body_node;
    ui.addChild(root, body_node);

    ui.layout();

    if (body_node != ui_mod.NONE) {
        ui.nodes[body_node].scroll_y = scroll;
    }

    ui.render();
}
