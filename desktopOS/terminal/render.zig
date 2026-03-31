const lib = @import("lib");

const font = lib.font;
const perms = lib.perms;
const syscall = lib.syscall;
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

// ── Display state ────────────────────────────────────────────────────
pub var frame_pixels: [*]u32 = undefined;
pub var frame_bytes: [*]u8 = undefined;
pub var frame_byte_size: u64 = 0;
pub var render_width: u32 = 0;
pub var render_height: u32 = 0;
pub var render_stride: u32 = 0;
pub var render_format: u32 = 0;

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

pub fn updateDisplayInfo(width: u32, height: u32, stride: u32, format: u32) void {
    render_width = width;
    render_height = height;
    render_stride = stride;
    render_format = format;
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
pub fn renderFrame() void {
    const width = render_width;
    const height = render_height;
    const stride = render_stride;
    const format = render_format;
    if (width == 0 or height == 0) return;

    var ui_state = UI.init(frame_pixels, width, height, stride, @intCast(format));
    const ui = &ui_state;

    const root = ui.createBox(.{
        .flex_direction = .column,
        .background = Color{ .r = 0x1a, .g = 0x1a, .b = 0x2e },
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

pub fn allocFrameBuffer() void {
    const pixel_count: usize = @as(usize, render_width) * @as(usize, render_height);
    frame_byte_size = @intCast(pixel_count * 4);
    const aligned_size = ((frame_byte_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const fb_vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const fb_vm = syscall.vm_reserve(0, aligned_size, fb_vm_rights);
    if (fb_vm.val < 0) {
        syscall.write("terminal: FAIL vm_reserve frame buffer\n");
        return;
    }
    frame_pixels = @ptrFromInt(fb_vm.val2);
    frame_bytes = @ptrCast(frame_pixels);
}
