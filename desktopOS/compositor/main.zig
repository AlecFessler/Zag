const lib = @import("lib");
const display_mod = @import("display.zig");

const channel = lib.channel;
const display = lib.display;
const mouse = lib.mouse;
const perms = lib.perms;
const syscall = lib.syscall;

const Display = display_mod.Display;

// ── Constants ────────────────────────────────────────────────────────
const MAX_PANES = 8;
const MAX_WINDOWS_PER_PANE = 8;
const MAX_TOTAL_WINDOWS = 16;

// ── Window / Pane state ──────────────────────────────────────────────
const Window = struct {
    active: bool = false,
    server: display.Server = undefined,
    frame_buf: [*]u8 = undefined,
    frame_size: usize = 0,
    width: u32 = 0,
    height: u32 = 0,
    has_frame: bool = false,
};

const Pane = struct {
    active: bool = false,
    window_count: u8 = 0,
    windows: [MAX_WINDOWS_PER_PANE]u8 = .{0} ** MAX_WINDOWS_PER_PANE,
    slide_offset: u8 = 0,
    focused: u8 = 0,
};

var windows: [MAX_TOTAL_WINDOWS]Window = .{Window{}} ** MAX_TOTAL_WINDOWS;
var window_count: u8 = 0;

var panes: [MAX_PANES]Pane = .{Pane{}} ** MAX_PANES;
var pane_count: u8 = 0;
var active_pane: u8 = 0;

// ── Cursor ───────────────────────────────────────────────────────────
const cursor_bitmap = [8]u8{
    0b11000000,
    0b11100000,
    0b11110000,
    0b11111000,
    0b11111100,
    0b11110000,
    0b10110000,
    0b00011000,
};

var cursor_x: i32 = 0;
var cursor_y: i32 = 0;

// ── Tiling layout ────────────────────────────────────────────────────
const TileLayout = struct {
    visible: [2]u8 = .{ 0, 0 },
    visible_count: u8 = 0,
    tile_w: u32 = 0,
    tile_h: u32 = 0,
};

fn computeLayout(pane: *const Pane, screen_w: u32, screen_h: u32) TileLayout {
    if (pane.window_count == 0) return .{};
    if (pane.window_count == 1) {
        return .{
            .visible = .{ 0, 0 },
            .visible_count = 1,
            .tile_w = screen_w,
            .tile_h = screen_h,
        };
    }
    // 2+ windows: two halves at slide_offset
    return .{
        .visible = .{ pane.slide_offset, pane.slide_offset + 1 },
        .visible_count = 2,
        .tile_w = screen_w / 2,
        .tile_h = screen_h,
    };
}

// ── Window management ────────────────────────────────────────────────
fn allocWindow() ?u8 {
    if (window_count >= MAX_TOTAL_WINDOWS) return null;
    const idx = window_count;
    window_count += 1;
    return idx;
}

fn addWindowToPane(pane_idx: u8, win_idx: u8) void {
    const pane = &panes[pane_idx];
    if (pane.window_count >= MAX_WINDOWS_PER_PANE) return;

    // Insert after the focused window
    const insert_pos: u8 = if (pane.window_count == 0) 0 else pane.focused + 1;

    // Shift windows right to make room
    var i: u8 = pane.window_count;
    while (i > insert_pos) : (i -= 1) {
        pane.windows[i] = pane.windows[i - 1];
    }
    pane.windows[insert_pos] = win_idx;
    pane.window_count += 1;

    // Focus the new window and slide so it's visible
    pane.focused = insert_pos;
    if (pane.window_count >= 2) {
        // Slide so the new window is visible (on the right half)
        const max_offset: u8 = pane.window_count - 2;
        if (insert_pos > 0) {
            pane.slide_offset = @min(insert_pos - 1, max_offset);
        } else {
            pane.slide_offset = 0;
        }
    }
}

fn registerWindow(chan: *channel.Channel, disp: *const Display) void {
    const win_idx = allocWindow() orelse {
        syscall.write("compositor: max windows reached\n");
        return;
    };

    const server = display.Server.init(chan);
    const pane = &panes[active_pane];
    const layout_before = computeLayout(pane, disp.width, disp.height);

    addWindowToPane(active_pane, win_idx);

    const layout_after = computeLayout(pane, disp.width, disp.height);

    // Allocate frame receive buffer for this window
    const tile_w = layout_after.tile_w;
    const tile_h = layout_after.tile_h;
    const frame_size: usize = @as(usize, tile_w) * @as(usize, tile_h) * 4;
    const aligned_size: u64 = ((frame_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const vm = syscall.vm_reserve(0, aligned_size, vm_rights);
    if (vm.val < 0) {
        syscall.write("compositor: FAIL vm_reserve window buf\n");
        return;
    }

    windows[win_idx] = .{
        .active = true,
        .server = server,
        .frame_buf = @ptrFromInt(vm.val2),
        .frame_size = frame_size,
        .width = tile_w,
        .height = tile_h,
        .has_frame = false,
    };

    // Send render target to new window
    server.sendRenderTarget(.{
        .width = tile_w,
        .height = tile_h,
        .stride = tile_w,
        .format = @intCast(disp.format),
    }) catch {
        syscall.write("compositor: FAIL sendRenderTarget\n");
        return;
    };

    // If we went from 1→2 visible windows, resize the existing window that was full-screen
    if (layout_before.visible_count == 1 and layout_after.visible_count == 2) {
        resizeExistingWindows(pane, &layout_after, disp);
    }

    syscall.write("compositor: registered window\n");
}

fn resizeExistingWindows(pane: *const Pane, layout: *const TileLayout, disp: *const Display) void {
    // Resize all windows in pane to the new tile size
    for (pane.windows[0..pane.window_count]) |wi| {
        const win = &windows[wi];
        if (!win.active) continue;
        if (win.width == layout.tile_w and win.height == layout.tile_h) continue;

        // Re-allocate frame buffer
        const new_size: usize = @as(usize, layout.tile_w) * @as(usize, layout.tile_h) * 4;
        const aligned: u64 = ((new_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
        const vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
        const vm = syscall.vm_reserve(0, aligned, vm_rights);
        if (vm.val < 0) continue;

        win.frame_buf = @ptrFromInt(vm.val2);
        win.frame_size = new_size;
        win.width = layout.tile_w;
        win.height = layout.tile_h;
        win.has_frame = false;

        win.server.sendWindowResized(.{
            .width = layout.tile_w,
            .height = layout.tile_h,
            .stride = layout.tile_w,
            .format = @intCast(disp.format),
        }) catch {};
    }
}

// ── Slide / Pane commands ────────────────────────────────────────────
fn handleSlideLeft() void {
    const pane = &panes[active_pane];
    if (pane.slide_offset > 0) {
        pane.slide_offset -= 1;
        pane.focused = pane.slide_offset;
    }
}

fn handleSlideRight() void {
    const pane = &panes[active_pane];
    if (pane.window_count >= 2 and pane.slide_offset < pane.window_count - 2) {
        pane.slide_offset += 1;
        pane.focused = pane.slide_offset + 1;
    }
}

fn handleRequestNewPane(from_server: *const display.Server) void {
    if (pane_count >= MAX_PANES) return;
    const new_id = pane_count;
    panes[new_id] = .{ .active = true };
    pane_count += 1;

    // Notify all active windows
    for (windows[0..window_count]) |*win| {
        if (win.active) {
            win.server.sendPaneCreated(new_id) catch {};
        }
    }
    _ = from_server;
}

fn handleSwitchPane(pane_id: u8) void {
    if (pane_id >= pane_count) return;
    active_pane = pane_id;

    // Notify all active windows
    for (windows[0..window_count]) |*win| {
        if (win.active) {
            win.server.sendPaneActivated(pane_id) catch {};
        }
    }
}

// ── Hit testing ─────────────────────────────────────────────────────
fn hitTestWindow(pane: *const Pane, layout: *const TileLayout, cx: i32, cy: i32) ?u8 {
    if (cx < 0 or cy < 0) return null;
    if (cy >= @as(i32, @intCast(layout.tile_h))) return null;
    if (layout.visible_count == 0) return null;

    const tw: i32 = @intCast(layout.tile_w);
    if (cx < tw) {
        const idx = layout.visible[0];
        if (idx < pane.window_count) return pane.windows[idx];
    } else if (layout.visible_count == 2 and cx < tw * 2) {
        const idx = layout.visible[1];
        if (idx < pane.window_count) return pane.windows[idx];
    }
    return null;
}

// ── Rendering ────────────────────────────────────────────────────────
fn clampI32(val: i32, min_v: i32, max_v: i32) i32 {
    if (val < min_v) return min_v;
    if (val > max_v) return max_v;
    return val;
}

fn drawCursor(disp: *const Display) void {
    const buf = disp.backBufBytes();
    const screen_w: i32 = @intCast(disp.width);
    const screen_h: i32 = @intCast(disp.height);
    const stride: usize = @intCast(disp.stride);

    for (cursor_bitmap, 0..) |row_bits, r| {
        const py = cursor_y + @as(i32, @intCast(r));
        if (py < 0 or py >= screen_h) continue;
        for (0..8) |c| {
            const px = cursor_x + @as(i32, @intCast(c));
            if (px < 0 or px >= screen_w) continue;
            const bit: u3 = @intCast(7 - c);
            if ((row_bits >> bit) & 1 == 0) continue;
            const offset: usize = (@as(usize, @intCast(py)) * stride + @as(usize, @intCast(px))) * 4;
            buf[offset + 0] = 0xFF;
            buf[offset + 1] = 0xFF;
            buf[offset + 2] = 0xFF;
            buf[offset + 3] = 0xFF;
        }
    }
}

fn blitWindow(hw_disp: *const Display, src: [*]const u8, src_w: u32, src_h: u32, dst_x: u32, dst_y: u32) void {
    const dst = hw_disp.backBufBytes();
    const dst_stride: usize = @intCast(hw_disp.stride);
    const dst_w: u32 = hw_disp.width;
    const dst_h: u32 = hw_disp.height;

    var y: u32 = 0;
    while (y < src_h and (dst_y + y) < dst_h) : (y += 1) {
        const src_off: usize = @as(usize, y) * @as(usize, src_w) * 4;
        const dst_off: usize = (@as(usize, dst_y + y) * dst_stride + @as(usize, dst_x)) * 4;
        const copy_w: usize = @min(src_w, dst_w - dst_x);
        @memcpy(dst[dst_off..][0 .. copy_w * 4], src[src_off..][0 .. copy_w * 4]);
    }
}

fn composite(disp: *const Display) void {
    const bg_color = packPixel(0x0a, 0x0a, 0x1a);
    disp.fill(bg_color);

    const pane = &panes[active_pane];
    const layout = computeLayout(pane, disp.width, disp.height);

    var i: u8 = 0;
    while (i < layout.visible_count) : (i += 1) {
        const pane_win_idx = layout.visible[i];
        if (pane_win_idx >= pane.window_count) continue;
        const win_idx = pane.windows[pane_win_idx];
        const win = &windows[win_idx];
        if (!win.active or !win.has_frame) continue;

        const dst_x: u32 = if (i == 0) 0 else layout.tile_w;
        blitWindow(disp, win.frame_buf, win.width, win.height, dst_x, 0);
    }

    drawCursor(disp);
    disp.present();
}

fn packPixel(r: u8, g: u8, b: u8) u32 {
    return @as(u32, b) | (@as(u32, g) << 8) | (@as(u32, r) << 16) | (0xFF << 24);
}

// ── Main ─────────────────────────────────────────────────────────────
pub fn main(perm_view_addr: u64) void {
    syscall.write("compositor: starting\n");

    var disp = Display.init(perm_view_addr) orelse {
        syscall.write("compositor: FAIL display init\n");
        return;
    };

    cursor_x = @intCast(disp.width / 2);
    cursor_y = @intCast(disp.height / 2);

    const bg_color = packPixel(0x0a, 0x0a, 0x1a);
    disp.fill(bg_color);
    disp.present();

    channel.makeDiscoverable(@enumFromInt(@intFromEnum(lib.Protocol.compositor)), 2) catch {
        syscall.write("compositor: FAIL makeDiscoverable\n");
        return;
    };
    syscall.write("compositor: discoverable\n");

    // Await mouse channel from usb_driver
    const mouse_chan = channel.awaitIncoming(100, 10_000_000_000) orelse {
        syscall.write("compositor: FAIL awaitIncoming(100) mouse channel timed out\n");
        return;
    };
    const mouse_server = mouse.Server.init(mouse_chan);
    syscall.write("compositor: mouse channel 100 connected\n");

    // Create default pane 0
    panes[0] = .{ .active = true };
    pane_count = 1;

    const screen_w: i32 = @intCast(disp.width);
    const screen_h: i32 = @intCast(disp.height);
    var needs_composite: bool = false;

    while (true) {
        // Accept new display channels dynamically
        if (channel.pollAnyIncoming()) |chan| {
            registerWindow(chan, &disp);
            needs_composite = true;

            // Default focus: send focus_change for the first window
            if (window_count == 1) {
                const sid = windows[0].server.chan.semantic_id_a;
                mouse_server.sendFocusChange(sid) catch {};
            }
        }

        // Drain all pending mouse events before compositing
        while (mouse_server.recv()) |msg| {
            switch (msg) {
                .mouse => |ev| {
                    cursor_x = clampI32(cursor_x + ev.dx, 0, screen_w - 1);
                    cursor_y = clampI32(cursor_y + ev.dy, 0, screen_h - 1);
                    needs_composite = true;

                    // Click-to-focus: send focus_change to USB driver
                    if (ev.buttons.left) {
                        const pane = &panes[active_pane];
                        const layout = computeLayout(pane, disp.width, disp.height);
                        if (hitTestWindow(pane, &layout, cursor_x, cursor_y)) |win_idx| {
                            const sid = windows[win_idx].server.chan.semantic_id_a;
                            mouse_server.sendFocusChange(sid) catch {};
                        }
                    }
                },
            }
        }

        // Poll all active windows for messages
        for (windows[0..window_count]) |*win| {
            if (!win.active) continue;
            if (win.server.recvMessage(win.frame_buf[0..win.frame_size])) |msg| {
                switch (msg) {
                    .frame => {
                        win.has_frame = true;
                        needs_composite = true;
                    },
                    .slide_left => {
                        handleSlideLeft();
                        needs_composite = true;
                    },
                    .slide_right => {
                        handleSlideRight();
                        needs_composite = true;
                    },
                    .request_new_pane => {
                        handleRequestNewPane(&win.server);
                    },
                    .switch_pane => |pane_id| {
                        handleSwitchPane(pane_id);
                        needs_composite = true;
                    },
                    .client_exit => {
                        win.active = false;
                        needs_composite = true;
                    },
                }
            }
        }

        if (needs_composite) {
            composite(&disp);
            needs_composite = false;
        }

        syscall.thread_yield();
    }
}
