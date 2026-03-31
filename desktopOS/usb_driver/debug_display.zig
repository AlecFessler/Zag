const lib = @import("lib");

const channel = lib.channel;
const display = lib.display;
const font = lib.font;
const perms = lib.perms;
const syscall = lib.syscall;
const ui_mod = lib.ui;

const Color = ui_mod.Color;
const Edges = ui_mod.Edges;
const UI = ui_mod.UI;

// ── Log buffer ──────────────────────────────────────────────────────
const LOG_SIZE = 4096;

var log_buf: [LOG_SIZE]u8 = undefined;
var log_len: u16 = 0;

// ── Display state ───────────────────────────────────────────────────
var frame_pixels: [*]u32 = undefined;
var frame_bytes: [*]u8 = undefined;
var frame_byte_size: u64 = 0;
var render_width: u32 = 0;
var render_height: u32 = 0;
var render_stride: u32 = 0;
var render_format: u32 = 0;

var display_client: display.Client = undefined;
var initialized: bool = false;

// ── Public API ──────────────────────────────────────────────────────

pub fn init() bool {
    const display_channel_id: u64 = 399;

    const display_chan = channel.requestConnection(
        @enumFromInt(@intFromEnum(display.protocol_id)),
        display_channel_id,
        display.SHM_SIZE,
        10_000_000_000,
    ) orelse {
        syscall.write("usb_driver: FAIL debug display requestConnection\n");
        return false;
    };
    display_client = display.Client.init(display_chan);

    // Wait for render target info from compositor
    var retries: u32 = 0;
    while (retries < 50000) : (retries += 1) {
        if (display_client.recv()) |msg| {
            switch (msg) {
                .render_target => |info| {
                    render_width = info.width;
                    render_height = info.height;
                    render_stride = info.stride;
                    render_format = info.format;
                    break;
                },
                else => {},
            }
        }
        syscall.thread_yield();
    } else {
        syscall.write("usb_driver: FAIL debug display no render target\n");
        return false;
    }

    // Allocate frame buffer
    const pixel_count: usize = @as(usize, render_width) * @as(usize, render_height);
    frame_byte_size = @intCast(pixel_count * 4);
    const aligned_size = ((frame_byte_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const fb_vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const fb_vm = syscall.vm_reserve(0, aligned_size, fb_vm_rights);
    if (fb_vm.val < 0) {
        syscall.write("usb_driver: FAIL debug display vm_reserve\n");
        return false;
    }
    frame_pixels = @ptrFromInt(fb_vm.val2);
    frame_bytes = @ptrCast(frame_pixels);

    initialized = true;
    return true;
}

pub fn log(text: []const u8) void {
    appendLog(text);
    if (initialized) {
        renderFrame();
        sendFrame();
    }
}

pub fn logU32(val: u32) void {
    appendU32(val);
}

pub fn logHex(val: u64) void {
    appendHex(val);
}

pub fn flush() void {
    if (initialized) {
        renderFrame();
        sendFrame();
    }
}

// ── Log buffer management ───────────────────────────────────────────

fn appendLog(text: []const u8) void {
    for (text) |ch| {
        if (log_len >= LOG_SIZE) break;
        log_buf[log_len] = ch;
        log_len += 1;
    }
}

fn appendU32(val: u32) void {
    var buf: [10]u8 = undefined;
    var n = val;
    var idx: usize = buf.len;
    if (n == 0) {
        appendLog("0");
        return;
    }
    while (n > 0) {
        idx -= 1;
        buf[idx] = '0' + @as(u8, @truncate(n % 10));
        n /= 10;
    }
    appendLog(buf[idx..]);
}

fn appendHex(val: u64) void {
    const hex_chars = "0123456789abcdef";
    var buf: [18]u8 = undefined;
    buf[0] = '0';
    buf[1] = 'x';
    var v = val;
    var idx: usize = buf.len;
    if (v == 0) {
        appendLog("0x0");
        return;
    }
    while (v > 0) {
        idx -= 1;
        buf[idx] = hex_chars[@as(usize, @truncate(v & 0xF))];
        v >>= 4;
    }
    // Shift hex digits right after "0x" prefix
    const digit_count = buf.len - idx;
    var i: usize = 0;
    while (i < digit_count) : (i += 1) {
        buf[2 + i] = buf[idx + i];
    }
    appendLog(buf[0 .. 2 + digit_count]);
}

// ── Scroll calculation ──────────────────────────────────────────────

fn calcScrollY(text_w: u32, text_h: u32) u32 {
    const char_w: u32 = font.width;
    const char_h: u32 = font.height;
    if (char_w == 0 or char_h == 0 or text_w == 0) return 0;
    const cols = text_w / char_w;
    if (cols == 0) return 0;

    var lines: u32 = 0;
    var i: u32 = 0;
    const len: u32 = log_len;
    while (i < len) {
        const line_start = i;
        while (i < len and log_buf[i] != '\n' and (i - line_start) < cols) {
            i += 1;
        }
        lines += 1;
        if (i < len and log_buf[i] == '\n') i += 1;
    }

    const visible_lines = text_h / char_h;
    if (lines > visible_lines) {
        return lines - visible_lines;
    }
    return 0;
}

// ── Frame rendering ─────────────────────────────────────────────────

fn renderFrame() void {
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

    const text_w = if (width > 16) width - 16 else 0;
    const text_h = if (height > 16) height - 16 else 0;
    const scroll = calcScrollY(text_w, text_h);

    var body_node = ui.createTextBox(log_buf[0..log_len], .{
        .padding = Edges.all(8),
        .font_color = Color{ .r = 0xff, .g = 0xaa, .b = 0x00 },
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

fn sendFrame() void {
    display_client.sendFrame(frame_bytes[0..frame_byte_size]) catch {};
}
