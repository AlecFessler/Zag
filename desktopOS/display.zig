/// Framebuffer display rendering for Zag desktopOS.
/// Extracted from routerOS/router/main.zig — provides text-mode rendering
/// on top of a GOP (Graphics Output Protocol) framebuffer.
const font = @import("font8x16.zig");
const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

// ── Framebuffer display ────────────────────────────────────────────
const MARGIN = 8;
const FB_MAX_LINES = 128;
const FB_MAX_COLS = 200;
const Color = struct { r: u8, g: u8, b: u8 };
const FG_COLOR = Color{ .r = 0xc0, .g = 0xc0, .b = 0xc0 };
const BG_COLOR = Color{ .r = 0x0a, .g = 0x0a, .b = 0x1a };
const HEADER_FG = Color{ .r = 0x40, .g = 0xa0, .b = 0xff };

const DisplayInfo = struct {
    handle: u64,
    fb_size: u32,
    width: u16,
    height: u16,
    stride: u16,
    pixel_format: u8,
};

var fb_ptr: ?[*]volatile u32 = null;
var fb_display: DisplayInfo = undefined;
var fb_visible_cols: u32 = 0;
var fb_visible_rows: u32 = 0;
var fb_lines: [FB_MAX_LINES][FB_MAX_COLS]u8 = .{.{0} ** FB_MAX_COLS} ** FB_MAX_LINES;
var fb_line_lens: [FB_MAX_LINES]u16 = .{0} ** FB_MAX_LINES;
var fb_head: u32 = 0;
var fb_count: u32 = 0;

fn packPixel(c: Color) u32 {
    if (fb_display.pixel_format == 0) { // BGR8
        return @as(u32, c.b) | (@as(u32, c.g) << 8) | (@as(u32, c.r) << 16);
    } else { // RGB8
        return @as(u32, c.r) | (@as(u32, c.g) << 8) | (@as(u32, c.b) << 16);
    }
}

pub fn drawChar(px: u32, py: u32, char: u8, fg: u32, bg: u32) void {
    const fb = fb_ptr orelse return;
    const glyph = font.data[(@as(u32, char) * font.height)..][0..font.height];
    const stride: u32 = fb_display.stride;
    var row: u32 = 0;
    while (row < font.height) : (row += 1) {
        const bits = glyph[row];
        var col: u32 = 0;
        while (col < font.width) : (col += 1) {
            const pixel = if ((bits >> @intCast(7 - col)) & 1 != 0) fg else bg;
            fb[(py + row) * stride + (px + col)] = pixel;
        }
    }
}

pub fn drawString(px: u32, py: u32, text: []const u8, fg: u32, bg: u32) void {
    var x = px;
    for (text) |ch| {
        if (x + font.width > fb_display.width) break;
        drawChar(x, py, ch, fg, bg);
        x += font.width;
    }
}

pub fn clearRect(px: u32, py: u32, w: u32, ht: u32, color: u32) void {
    const fb = fb_ptr orelse return;
    const stride: u32 = fb_display.stride;
    var row: u32 = 0;
    while (row < ht) : (row += 1) {
        var col: u32 = 0;
        while (col < w) : (col += 1) {
            fb[(py + row) * stride + (px + col)] = color;
        }
    }
}

fn fbAppendLine(text: []const u8) void {
    const idx = (fb_head + fb_count) % FB_MAX_LINES;
    const len = @min(text.len, FB_MAX_COLS);
    @memcpy(fb_lines[idx][0..len], text[0..len]);
    fb_line_lens[idx] = @intCast(len);
    if (fb_count < FB_MAX_LINES) {
        fb_count += 1;
    } else {
        fb_head = (fb_head + 1) % FB_MAX_LINES;
    }
}

pub fn appendText(text: []const u8) void {
    var start: usize = 0;
    for (text, 0..) |ch, i| {
        if (ch == '\n') {
            fbAppendLine(text[start..i]);
            start = i + 1;
        }
    }
    if (start < text.len) {
        fbAppendLine(text[start..]);
    }
}

pub fn render() void {
    if (fb_ptr == null) return;
    const bg = packPixel(BG_COLOR);
    const fg_pixel = packPixel(FG_COLOR);
    const header_fg = packPixel(HEADER_FG);

    // Header
    const header_y = MARGIN;
    clearRect(MARGIN, header_y, fb_visible_cols * font.width, font.height, bg);
    drawString(MARGIN, header_y, "Zag Desktop", header_fg, bg);

    // Text area starts below header with a gap
    const text_y_start = MARGIN + font.height + 4;
    const text_rows = (fb_display.height - text_y_start - MARGIN) / font.height;

    // Determine which lines to show (last text_rows lines)
    const show_count = @min(fb_count, text_rows);
    const start_idx = if (fb_count > text_rows) (fb_head + fb_count - text_rows) % FB_MAX_LINES else fb_head;

    var row: u32 = 0;
    while (row < text_rows) : (row += 1) {
        const y = text_y_start + row * font.height;
        clearRect(MARGIN, y, fb_visible_cols * font.width, font.height, bg);
        if (row < show_count) {
            const line_idx = (start_idx + row) % FB_MAX_LINES;
            const len = fb_line_lens[line_idx];
            if (len > 0) {
                drawString(MARGIN, y, fb_lines[line_idx][0..len], fg_pixel, bg);
            }
        }
    }
}

pub fn findDisplay(perm_view_addr: u64) ?DisplayInfo {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
            entry.deviceClass() == @intFromEnum(perms.DeviceClass.display) and
            entry.deviceType() == @intFromEnum(perms.DeviceType.mmio))
        {
            return .{
                .handle = entry.handle,
                .fb_size = entry.deviceSizeOrPortCount(),
                .width = entry.fbWidth(),
                .height = entry.fbHeight(),
                .stride = entry.fbStride(),
                .pixel_format = entry.fbPixelFormat(),
            };
        }
    }
    return null;
}

pub fn init(perm_view_addr: u64) bool {
    const di = findDisplay(perm_view_addr) orelse return false;
    if (di.width == 0 or di.height == 0) return false;

    const aligned = ((di.fb_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .mmio = true }).bits();
    const vm = syscall.vm_reserve(0, aligned, vm_rights);
    if (vm.val < 0) return false;
    if (syscall.mmio_map(di.handle, @intCast(vm.val), 0) != 0) return false;

    fb_display = di;
    fb_ptr = @ptrFromInt(vm.val2);
    fb_visible_cols = (di.width - 2 * MARGIN) / font.width;
    fb_visible_rows = (di.height - 2 * MARGIN) / font.height;

    // Fill background
    const bg = packPixel(BG_COLOR);
    const stride: u32 = di.stride;
    const fb = fb_ptr.?;
    var y: u32 = 0;
    while (y < di.height) : (y += 1) {
        var x: u32 = 0;
        while (x < di.width) : (x += 1) {
            fb[y * stride + x] = bg;
        }
    }
    render();
    return true;
}

pub fn msg(text: []const u8) void {
    syscall.write(text);
    if (fb_ptr != null) {
        appendText(text);
        render();
    }
}

pub fn isActive() bool {
    return fb_ptr != null;
}
