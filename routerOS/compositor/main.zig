const font = @import("font8x16.zig");
const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MARGIN = 8;
const MAX_LINES = 128;
const MAX_COLS = 200;

const FG_COLOR = Color{ .r = 0xc0, .g = 0xc0, .b = 0xc0 };
const BG_COLOR = Color{ .r = 0x0a, .g = 0x0a, .b = 0x1a };
const HEADER_FG = Color{ .r = 0x40, .g = 0xa0, .b = 0xff };

const Color = struct { r: u8, g: u8, b: u8 };

const DisplayInfo = struct {
    handle: u64,
    fb_size: u32,
    width: u16,
    height: u16,
    stride: u16,
    pixel_format: u8,
};

// ── Text buffer (circular) ─────────────────────────────────────────
var lines: [MAX_LINES][MAX_COLS]u8 = .{.{0} ** MAX_COLS} ** MAX_LINES;
var line_lens: [MAX_LINES]u16 = .{0} ** MAX_LINES;
var head: u32 = 0;
var count: u32 = 0;

// ── Display state ──────────────────────────────────────────────────
var fb: [*]volatile u32 = undefined;
var display: DisplayInfo = undefined;
var visible_cols: u32 = 0;
var visible_rows: u32 = 0;

// Track mapped SHM handles
var mapped_shm_handles: [8]u64 = .{0} ** 8;
var num_mapped_shms: u32 = 0;
var perm_view_global: u64 = 0;

fn packPixel(c: Color) u32 {
    if (display.pixel_format == 0) { // BGR8
        return @as(u32, c.b) | (@as(u32, c.g) << 8) | (@as(u32, c.r) << 16);
    } else { // RGB8
        return @as(u32, c.r) | (@as(u32, c.g) << 8) | (@as(u32, c.b) << 16);
    }
}

fn drawChar(px: u32, py: u32, char: u8, fg: u32, bg: u32) void {
    const glyph = font.data[(@as(u32, char) * font.height)..][0..font.height];
    const stride: u32 = display.stride;
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

fn drawString(px: u32, py: u32, text: []const u8, fg: u32, bg: u32) void {
    var x = px;
    for (text) |ch| {
        if (x + font.width > display.width) break;
        drawChar(x, py, ch, fg, bg);
        x += font.width;
    }
}

fn clearRect(px: u32, py: u32, w: u32, h: u32, color: u32) void {
    const stride: u32 = display.stride;
    var row: u32 = 0;
    while (row < h) : (row += 1) {
        var col: u32 = 0;
        while (col < w) : (col += 1) {
            fb[(py + row) * stride + (px + col)] = color;
        }
    }
}

fn appendLine(text: []const u8) void {
    const idx = (head + count) % MAX_LINES;
    const len = @min(text.len, MAX_COLS);
    @memcpy(lines[idx][0..len], text[0..len]);
    line_lens[idx] = @intCast(len);
    if (count < MAX_LINES) {
        count += 1;
    } else {
        head = (head + 1) % MAX_LINES;
    }
}

fn appendText(text: []const u8) void {
    var start: usize = 0;
    for (text, 0..) |ch, i| {
        if (ch == '\n') {
            appendLine(text[start..i]);
            start = i + 1;
        }
    }
    if (start < text.len) {
        appendLine(text[start..]);
    }
}

fn renderTextBuffer() void {
    const bg = packPixel(BG_COLOR);
    const fg_pixel = packPixel(FG_COLOR);
    const header_fg = packPixel(HEADER_FG);

    // Header
    const header_y = MARGIN;
    clearRect(MARGIN, header_y, visible_cols * font.width, font.height, bg);
    drawString(MARGIN, header_y, "Zag OS", header_fg, bg);

    // Text area starts below header with a gap
    const text_y_start = MARGIN + font.height + 4;
    const text_rows = (display.height - text_y_start - MARGIN) / font.height;

    // Determine which lines to show (last text_rows lines)
    const show_count = @min(count, text_rows);
    const start_idx = if (count > text_rows) (head + count - text_rows) % MAX_LINES else head;

    var row: u32 = 0;
    while (row < text_rows) : (row += 1) {
        const y = text_y_start + row * font.height;
        clearRect(MARGIN, y, visible_cols * font.width, font.height, bg);
        if (row < show_count) {
            const line_idx = (start_idx + row) % MAX_LINES;
            const len = line_lens[line_idx];
            if (len > 0) {
                drawString(MARGIN, y, lines[line_idx][0..len], fg_pixel, bg);
            }
        }
    }
}

fn findDisplay(perm_view_addr: u64) ?DisplayInfo {
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

fn mmioMap(device_handle: u64, size: u64) ?[*]volatile u32 {
    const aligned = ((size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .mmio = true }).bits();
    const vm = syscall.vm_reserve(0, aligned, vm_rights);
    if (vm.val < 0) return null;
    if (syscall.mmio_map(device_handle, @intCast(vm.val), 0) != 0) return null;
    return @ptrFromInt(vm.val2);
}

fn isHandleMapped(handle: u64) bool {
    for (mapped_shm_handles[0..num_mapped_shms]) |h| {
        if (h == handle) return true;
    }
    return false;
}

fn recordMapped(handle: u64) void {
    if (num_mapped_shms < mapped_shm_handles.len) {
        mapped_shm_handles[num_mapped_shms] = handle;
        num_mapped_shms += 1;
    }
}

/// Find and map the next unmapped data SHM from the perm view.
fn findAndMapNextDataShm() ?*channel_mod.ChannelHeader {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_global);
    for (view) |*entry| {
        if (entry.entry_type != pv.ENTRY_TYPE_SHARED_MEMORY) continue;
        if (entry.field0 <= shm_protocol.COMMAND_SHM_SIZE) continue;
        if (isHandleMapped(entry.handle)) continue;

        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .execute = true,
            .shareable = true,
        }).bits();
        const vm = syscall.vm_reserve(0, entry.field0, vm_rights);
        if (vm.val < 0) continue;
        if (syscall.shm_map(entry.handle, @intCast(vm.val), 0) != 0) continue;

        recordMapped(entry.handle);
        return @ptrFromInt(vm.val2);
    }
    return null;
}

pub fn main(perm_view_addr: u64) void {
    perm_view_global = perm_view_addr;
    // compositor: starting (display only, no serial)

    display = findDisplay(perm_view_addr) orelse {
        syscall.write("compositor: no display device found\n");
        return;
    };

    if (display.width == 0 or display.height == 0) {
        syscall.write("compositor: display has zero dimensions\n");
        return;
    }

    fb = mmioMap(display.handle, display.fb_size) orelse {
        syscall.write("compositor: mmio_map failed\n");
        return;
    };

    visible_cols = (display.width - 2 * MARGIN) / font.width;
    visible_rows = (display.height - 2 * MARGIN) / font.height;

    // Fill background
    const bg = packPixel(BG_COLOR);
    const stride: u32 = display.stride;
    var y: u32 = 0;
    while (y < display.height) : (y += 1) {
        var x: u32 = 0;
        while (x < display.width) : (x += 1) {
            fb[y * stride + x] = bg;
        }
    }

    appendLine("compositor: display initialized");
    renderTextBuffer();
    // display initialized (shown on framebuffer)

    // Map command channel for IPC — record its handle so we skip it
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        appendLine("compositor: no command channel");
        renderTextBuffer();
        while (true) syscall.thread_yield();
    };
    {
        const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and entry.field0 <= shm_protocol.COMMAND_SHM_SIZE) {
                recordMapped(entry.handle);
                break;
            }
        }
    }

    // Wait for incoming connections — scan perm view for data SHMs
    var recv_buf: [1024]u8 = undefined;
    var chan: ?channel_mod.Channel = null;

    while (true) {
        // Check for new data SHM (connection from desktop_env)
        if (chan == null) {
            if (findAndMapNextDataShm()) |header| {
                chan = channel_mod.Channel.openAsSideA(header);
                if (chan != null) {
                    appendLine("compositor: client connected");
                    renderTextBuffer();
                    // client connected (shown on framebuffer)
                }
            }
        }

        // Poll for messages
        if (chan) |*c| {
            while (c.recv(&recv_buf)) |len| {
                appendText(recv_buf[0..len]);
                renderTextBuffer();
            }
            c.waitForMessage(50_000_000); // 50ms timeout
        } else {
            // No connections yet — wait for broker notification
            cmd.waitForNotification(50_000_000);
        }
    }
}
