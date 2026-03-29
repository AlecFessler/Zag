const lib = @import("lib");

const channel_mod = lib.channel;
const fb_proto = lib.framebuffer;
const input = lib.input;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
const MAX_APP_FBS = 4;
const MOUSE_CHAN_SIZE: u64 = 4 * syscall.PAGE4K; // 16 KB
const MAX_PIXELS: u64 = (fb_proto.FRAMEBUFFER_SHM_SIZE - fb_proto.PIXEL_DATA_OFFSET) / 4;
const BORDER_WIDTH: u32 = 2;
const BORDER_GAP: u32 = 2; // gap between tiled windows

// ── Display state ──────────────────────────────────────────────────
var screen_width: u32 = 0;
var screen_height: u32 = 0;
var screen_stride: u32 = 0;
var screen_format: u8 = 0; // 0=BGR8, 1=RGB8
var screen_fb: [*]volatile u32 = undefined;
var back_buf: [*]u32 = undefined;

// ── Mouse cursor ───────────────────────────────────────────────────
var cursor_x: i32 = 0;
var cursor_y: i32 = 0;

const CURSOR_W = 12;
const CURSOR_H = 16;
const cursor_bitmap = [CURSOR_H]u16{
    0b1000000000000000,
    0b1100000000000000,
    0b1110000000000000,
    0b1111000000000000,
    0b1111100000000000,
    0b1111110000000000,
    0b1111111000000000,
    0b1111111100000000,
    0b1111111110000000,
    0b1111111111000000,
    0b1111110000000000,
    0b1101111000000000,
    0b1000111000000000,
    0b0000011100000000,
    0b0000011100000000,
    0b0000001100000000,
};
const cursor_outline = [CURSOR_H]u16{
    0b1000000000000000,
    0b1100000000000000,
    0b1010000000000000,
    0b1001000000000000,
    0b1000100000000000,
    0b1000010000000000,
    0b1000001000000000,
    0b1000000100000000,
    0b1000000010000000,
    0b1000000001000000,
    0b1000010000000000,
    0b1001001000000000,
    0b1000001000000000,
    0b0000000100000000,
    0b0000000100000000,
    0b0000000000000000,
};

// ── App framebuffers ───────────────────────────────────────────────
const STALE_HEARTBEAT: u32 = 1_000_000; // iterations without heartbeat change → dead

const AppFramebuffer = struct {
    header: *fb_proto.FramebufferHeader,
    last_frame: u64,
    last_heartbeat: u64,
    stale_count: u32,
    shm_handle: u64,
    win_x: u32,
    win_y: u32,
    win_w: u32,
    win_h: u32,
    alive: bool = true,
};

var app_fbs: [MAX_APP_FBS]AppFramebuffer = undefined;
var num_app_fbs: u32 = 0;
var active_app: u32 = 0;
var cmd_channel: *shm_protocol.CommandChannel = undefined;

// ── Tiling ───────────────────────────────────────────────────────
const ui_mod = lib.ui;
var tile_tree: ui_mod.TileTree = .{};

fn retile() void {
    tile_tree.layout(screen_width, screen_height, BORDER_GAP);
    var i: u32 = 0;
    while (i < num_app_fbs) : (i += 1) {
        const t = tile_tree.tiles[i];
        app_fbs[i].win_x = t.x;
        app_fbs[i].win_y = t.y;
        app_fbs[i].win_w = t.w;
        app_fbs[i].win_h = t.h;
        updateAppDimensions(&app_fbs[i]);
    }
}

fn selectNextAliveApp() void {
    var j: u32 = 0;
    while (j < num_app_fbs) : (j += 1) {
        if (app_fbs[j].alive) {
            active_app = j;
            @atomicStore(u8, &cmd_channel.active_app_index, @intCast(j), .release);
            @atomicStore(u32, &cmd_channel.child_flags, @atomicLoad(u32, &cmd_channel.child_flags, .acquire) | shm_protocol.CHILD_FLAG_ACTIVE_CHANGED, .release);
            _ = @atomicRmw(u64, &cmd_channel.wake_flag, .Add, 1, .release);
            _ = syscall.futex_wake(&cmd_channel.wake_flag, 1);
            return;
        }
    }
    // No alive apps — set to invalid index
    active_app = num_app_fbs;
}

fn updateAppDimensions(afb: *AppFramebuffer) void {
    const hdr = afb.header;
    var w = afb.win_w;
    const h = afb.win_h;

    // Clamp to pixel budget
    const needed = @as(u64, w) * @as(u64, h);
    if (needed > MAX_PIXELS) {
        w = @intCast(MAX_PIXELS / @as(u64, h));
    }

    hdr.setWidth(w);
    hdr.setHeight(h);
    hdr.setStride(w);
    hdr.setFormat(screen_format);
    hdr.incrementLayoutGeneration();
}

// ── SHM tracking ──────────────────────────────────────────────────
var known_shm_handles: [16]u64 = .{0} ** 16;
var num_known_shm: u32 = 0;

fn isKnownShm(handle: u64) bool {
    for (known_shm_handles[0..num_known_shm]) |h| {
        if (h == handle) return true;
    }
    return false;
}

fn recordShm(handle: u64) void {
    if (num_known_shm < known_shm_handles.len) {
        known_shm_handles[num_known_shm] = handle;
        num_known_shm += 1;
    }
}

// ── Pixel helpers ──────────────────────────────────────────────────
fn packPixel(r: u8, g: u8, b: u8) u32 {
    if (screen_format == 0) { // BGR8
        return @as(u32, b) | (@as(u32, g) << 8) | (@as(u32, r) << 16);
    } else { // RGB8
        return @as(u32, r) | (@as(u32, g) << 8) | (@as(u32, b) << 16);
    }
}

fn fillScreen(color: u32) void {
    var y: u32 = 0;
    while (y < screen_height) : (y += 1) {
        var x: u32 = 0;
        while (x < screen_width) : (x += 1) {
            back_buf[y * screen_stride + x] = color;
        }
    }
}

fn blitAppFramebuffer(afb: *const AppFramebuffer) void {
    const hdr = afb.header;
    if (!hdr.isValid()) return;
    const src = hdr.pixelDataConst();
    const w = @min(hdr.readWidth(), afb.win_w);
    const h = @min(hdr.readHeight(), afb.win_h);
    const src_stride = hdr.readStride();
    const dst_x = afb.win_x;
    const dst_y = afb.win_y;
    var y: u32 = 0;
    while (y < h) : (y += 1) {
        const dy = dst_y + y;
        if (dy >= screen_height) break;
        var x: u32 = 0;
        while (x < w) : (x += 1) {
            const dx = dst_x + x;
            if (dx >= screen_width) break;
            back_buf[dy * screen_stride + dx] = src[y * src_stride + x];
        }
    }
}

fn drawWindowBorder(afb: *const AppFramebuffer, color: u32) void {
    const bw = BORDER_WIDTH;
    const x1 = if (afb.win_x >= bw) afb.win_x - bw else 0;
    const y1 = if (afb.win_y >= bw) afb.win_y - bw else 0;
    const x2 = @min(afb.win_x + afb.win_w + bw, screen_width);
    const y2 = @min(afb.win_y + afb.win_h + bw, screen_height);

    // Top
    var y: u32 = y1;
    while (y < @min(y1 + bw, y2)) : (y += 1) {
        var x: u32 = x1;
        while (x < x2) : (x += 1) {
            back_buf[y * screen_stride + x] = color;
        }
    }
    // Bottom
    y = if (y2 > bw) y2 - bw else 0;
    while (y < y2) : (y += 1) {
        var x: u32 = x1;
        while (x < x2) : (x += 1) {
            back_buf[y * screen_stride + x] = color;
        }
    }
    // Left
    y = y1;
    while (y < y2) : (y += 1) {
        var x: u32 = x1;
        while (x < @min(x1 + bw, x2)) : (x += 1) {
            back_buf[y * screen_stride + x] = color;
        }
    }
    // Right
    y = y1;
    while (y < y2) : (y += 1) {
        var x: u32 = if (x2 > bw) x2 - bw else 0;
        while (x < x2) : (x += 1) {
            back_buf[y * screen_stride + x] = color;
        }
    }
}

fn presentFrame() void {
    const total = screen_height * screen_stride;
    var i: u32 = 0;
    while (i < total) : (i += 1) {
        screen_fb[i] = back_buf[i];
    }
}

fn hitTestWindow(px: u32, py: u32) ?u32 {
    var i: u32 = 0;
    while (i < num_app_fbs) : (i += 1) {
        const afb = &app_fbs[i];
        if (!afb.alive) continue;
        if (px >= afb.win_x and px < afb.win_x + afb.win_w and
            py >= afb.win_y and py < afb.win_y + afb.win_h)
        {
            return i;
        }
    }
    return null;
}

fn drawCursor() void {
    const cx: u32 = @intCast(@max(0, cursor_x));
    const cy: u32 = @intCast(@max(0, cursor_y));
    const white = packPixel(0xFF, 0xFF, 0xFF);
    const black = packPixel(0x00, 0x00, 0x00);

    for (0..CURSOR_H) |row| {
        for (0..CURSOR_W) |col| {
            const px = cx + @as(u32, @intCast(col));
            const py = cy + @as(u32, @intCast(row));
            if (px >= screen_width or py >= screen_height) continue;
            const bit: u4 = @intCast(15 - col);
            if ((cursor_outline[row] >> bit) & 1 != 0) {
                back_buf[py * screen_stride + px] = black;
            } else if ((cursor_bitmap[row] >> bit) & 1 != 0) {
                back_buf[py * screen_stride + px] = white;
            }
        }
    }
}

pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse return;
    cmd_channel = cmd;
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Record command channel SHM
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 <= shm_protocol.COMMAND_SHM_SIZE) {
            recordShm(e.handle);
            break;
        }
    }

    // Find display device
    var display_handle: u64 = 0;
    var fb_size: u64 = 0;
    while (display_handle == 0) {
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
                entry.deviceClass() == @intFromEnum(perms.DeviceClass.display) and
                entry.deviceType() == @intFromEnum(perms.DeviceType.mmio))
            {
                display_handle = entry.handle;
                fb_size = entry.deviceSizeOrPortCount();
                screen_width = entry.fbWidth();
                screen_height = entry.fbHeight();
                screen_stride = entry.fbStride();
                screen_format = entry.fbPixelFormat();
                break;
            }
        }
        if (display_handle == 0) pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }

    if (screen_width == 0 or screen_height == 0) {
        syscall.write("compositor: invalid display dimensions\n");
        return;
    }

    // Map GOP framebuffer MMIO
    const aligned_size = ((fb_size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const mmio_vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .mmio = true,
        .write_combining = true,
    }).bits();
    const mmio_vm = syscall.vm_reserve(0, aligned_size, mmio_vm_rights);
    if (mmio_vm.val < 0) {
        syscall.write("compositor: vm_reserve failed\n");
        return;
    }
    if (syscall.mmio_map(display_handle, @intCast(mmio_vm.val), 0) != 0) {
        syscall.write("compositor: mmio_map failed\n");
        return;
    }
    screen_fb = @ptrFromInt(mmio_vm.val2);

    // Allocate WB-cached back buffer for double buffering (private memory, demand-paged)
    const bb_vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const bb_vm = syscall.vm_reserve(0, aligned_size, bb_vm_rights);
    if (bb_vm.val < 0) {
        syscall.write("compositor: back buffer vm_reserve failed\n");
        return;
    }
    back_buf = @ptrFromInt(bb_vm.val2);

    syscall.write("compositor: display ");
    writeU32(screen_width);
    syscall.write("x");
    writeU32(screen_height);
    syscall.write(" mapped\n");

    // Fill with dark blue background
    const bg_color = packPixel(0x0a, 0x0a, 0x1a);
    fillScreen(bg_color);

    // Center cursor
    cursor_x = @intCast(screen_width / 2);
    cursor_y = @intCast(screen_height / 2);

    // Look for internal mouse channel (16 KB, from device_manager)
    var mouse_chan: ?channel_mod.Channel = null;
    while (mouse_chan == null) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 == MOUSE_CHAN_SIZE and
                !isKnownShm(e.handle))
            {
                const chan_vm_rights = (perms.VmReservationRights{
                    .read = true,
                    .write = true,
                    .shareable = true,
                }).bits();
                const chan_vm = syscall.vm_reserve(0, MOUSE_CHAN_SIZE, chan_vm_rights);
                if (chan_vm.val >= 0) {
                    if (syscall.shm_map(e.handle, @intCast(chan_vm.val), 0) == 0) {
                        const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(chan_vm.val2);
                        mouse_chan = channel_mod.Channel.openAsSideB(chan_header);
                        if (mouse_chan != null) {
                            recordShm(e.handle);
                            syscall.write("compositor: mouse channel connected\n");
                        }
                    }
                }
                break;
            }
        }
        if (mouse_chan == null) pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }

    // Main compositing loop
    var recv_buf: [64]u8 = undefined;
    var needs_redraw: bool = true;
    var prev_left_down: bool = false;

    while (true) {
        // Receive input events (mouse + keyboard)
        var left_clicked = false;
        if (mouse_chan) |*mc| {
            while (mc.recv(&recv_buf)) |len| {
                if (len >= input.EVENT_SIZE) {
                    const tag = input.decodeTag(&recv_buf);
                    if (tag) |t| {
                        if (t == input.Tag.MOUSE) {
                            if (input.decodeMouse(&recv_buf)) |ev| {
                                cursor_x = @max(0, @min(@as(i32, @intCast(screen_width - 1)), cursor_x + ev.dx));
                                cursor_y = @max(0, @min(@as(i32, @intCast(screen_height - 1)), cursor_y + ev.dy));
                                needs_redraw = true;

                                // Detect left button click (transition from not-pressed to pressed)
                                const left_down = (ev.buttons & 1) != 0;
                                if (left_down and !prev_left_down) {
                                    left_clicked = true;
                                }
                                prev_left_down = left_down;
                            }
                        } else if (t == input.Tag.KEYBOARD) {
                            if (input.decodeKeyboard(&recv_buf)) |ev| {
                                // Super+T: spawn new terminal
                                const gui = (ev.modifiers & 0x88) != 0; // l_gui or r_gui
                                if (gui and ev.keycode == 0x17 and ev.state == input.KeyState.PRESSED) {
                                    // Signal parent (device_manager) to spawn a new app
                                    @atomicStore(u32, &cmd.child_flags, shm_protocol.CHILD_FLAG_SPAWN_APP, .release);
                                    _ = @atomicRmw(u64, &cmd.wake_flag, .Add, 1, .release);
                                    _ = syscall.futex_wake(&cmd.wake_flag, 1);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Handle click-to-focus
        if (left_clicked) {
            if (hitTestWindow(@intCast(@max(0, cursor_x)), @intCast(@max(0, cursor_y)))) |hit_idx| {
                if (hit_idx != active_app) {
                    active_app = hit_idx;
                    needs_redraw = true;
                    // Notify device_manager of active app change
                    @atomicStore(u8, &cmd.active_app_index, @intCast(hit_idx), .release);
                    @atomicStore(u32, &cmd.child_flags, @atomicLoad(u32, &cmd.child_flags, .acquire) | shm_protocol.CHILD_FLAG_ACTIVE_CHANGED, .release);
                    _ = @atomicRmw(u64, &cmd.wake_flag, .Add, 1, .release);
                    _ = syscall.futex_wake(&cmd.wake_flag, 1);
                }
            }
        }

        // Check for new app framebuffer SHMs (4 MB)
        if (num_app_fbs < MAX_APP_FBS) {
            for (view) |*e| {
                if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                    e.field0 == fb_proto.FRAMEBUFFER_SHM_SIZE and
                    !isKnownShm(e.handle))
                {
                    const fb_vm_rights = (perms.VmReservationRights{
                        .read = true,
                        .write = true,
                        .shareable = true,
                    }).bits();
                    const fb_vm = syscall.vm_reserve(0, fb_proto.FRAMEBUFFER_SHM_SIZE, fb_vm_rights);
                    if (fb_vm.val >= 0) {
                        if (syscall.shm_map(e.handle, @intCast(fb_vm.val), 0) == 0) {
                            const hdr: *fb_proto.FramebufferHeader = @ptrFromInt(fb_vm.val2);

                            const app_idx: u8 = @intCast(num_app_fbs);
                            app_fbs[num_app_fbs] = .{
                                .header = hdr,
                                .last_frame = 0,
                                .last_heartbeat = 0,
                                .stale_count = 0,
                                .shm_handle = e.handle,
                                .win_x = 0,
                                .win_y = 0,
                                .win_w = screen_width,
                                .win_h = screen_height,
                            };
                            num_app_fbs += 1;
                            recordShm(e.handle);

                            tile_tree.addWindow(app_idx, @intCast(active_app));
                            active_app = app_idx;
                            retile();

                            // Set frame_counter before magic so app starts fresh
                            @atomicStore(u64, &hdr.frame_counter, 0, .release);
                            // Magic last — signals to app that header is ready
                            hdr.setMagic(fb_proto.FRAMEBUFFER_MAGIC);
                            const magic_u64: *const u64 = @ptrCast(&hdr.magic);
                            _ = syscall.futex_wake(magic_u64, 0xFFFF);

                            syscall.write("compositor: app framebuffer connected\n");
                            needs_redraw = true;
                        }
                    }
                    break;
                }
            }
        }

        // Check for new frames + heartbeat liveness
        {
            var fi: u32 = 0;
            while (fi < num_app_fbs) : (fi += 1) {
                const afb = &app_fbs[fi];
                if (!afb.alive) continue;

                // Immediate detection: app cleared magic on exit
                if (afb.last_heartbeat > 0 and !afb.header.isValid()) {
                    afb.alive = false;
                    syscall.write("compositor: app exited, removing window\n");
                    tile_tree.removeWindow(@intCast(fi));
                    retile();
                    if (active_app == fi or active_app >= num_app_fbs or !app_fbs[active_app].alive) {
                        selectNextAliveApp();
                    }
                    needs_redraw = true;
                    continue;
                }

                // Heartbeat — app increments every loop iteration
                const hb = afb.header.readHeartbeat();
                if (hb != afb.last_heartbeat) {
                    afb.last_heartbeat = hb;
                    afb.stale_count = 0;
                } else if (afb.last_heartbeat > 0) {
                    afb.stale_count += 1;
                    if (afb.stale_count >= STALE_HEARTBEAT) {
                        afb.alive = false;
                        syscall.write("compositor: app stopped responding, removing window\n");
                        tile_tree.removeWindow(@intCast(fi));
                        retile();
                        if (active_app == fi or active_app >= num_app_fbs or !app_fbs[active_app].alive) {
                            selectNextAliveApp();
                        }
                        needs_redraw = true;
                        continue;
                    }
                }

                // Check for new rendered frames
                const current_frame = afb.header.readFrameCounter();
                if (current_frame != afb.last_frame) {
                    afb.last_frame = current_frame;
                    needs_redraw = true;
                }
            }
        }

        // Composite and render
        if (needs_redraw) {
            const bg = packPixel(0x0a, 0x0a, 0x1a);
            fillScreen(bg);

            // Draw inactive windows first, active last
            for (app_fbs[0..num_app_fbs], 0..) |*afb, i| {
                if (!afb.alive) continue;
                if (i != active_app) blitAppFramebuffer(afb);
            }
            if (active_app < num_app_fbs and app_fbs[active_app].alive) {
                blitAppFramebuffer(&app_fbs[active_app]);
                const border_color = packPixel(0x40, 0xa0, 0xff);
                drawWindowBorder(&app_fbs[active_app], border_color);
            }

            drawCursor();
            presentFrame();
            needs_redraw = false;
        }

        syscall.thread_yield();
    }
}

fn writeU32(val: u32) void {
    var buf: [10]u8 = undefined;
    var n = val;
    var i: usize = buf.len;
    if (n == 0) {
        syscall.write("0");
        return;
    }
    while (n > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(n % 10));
        n /= 10;
    }
    syscall.write(buf[i..]);
}
