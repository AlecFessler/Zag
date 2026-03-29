const lib = @import("lib");

const channel_mod = lib.channel;
const fb_proto = lib.framebuffer;
const input = lib.input;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
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
const AppFramebuffer = struct {
    header: *volatile fb_proto.FramebufferHeader,
    last_frame: u64,
    shm_handle: u64,
    win_x: u32,
    win_y: u32,
    win_w: u32,
    win_h: u32,
};

var app_fbs: [MAX_APP_FBS]AppFramebuffer = undefined;
var num_app_fbs: u32 = 0;
var active_app: u32 = 0;

// ── Tiling tree ───────────────────────────────────────────────────
const SplitDir = enum(u8) { horizontal, vertical };

const TileNode = struct {
    occupied: bool = false,
    is_leaf: bool = true,
    app_index: u8 = 0,
    split_dir: SplitDir = .horizontal,
};

const MAX_TILE_NODES = 15;
var tile_tree: [MAX_TILE_NODES]TileNode = [_]TileNode{.{}} ** MAX_TILE_NODES;

fn tileLeft(i: usize) usize {
    return 2 * i + 1;
}

fn tileRight(i: usize) usize {
    return 2 * i + 2;
}

fn addWindowToTree(app_index: u8) void {
    // If tree is empty, root becomes the leaf
    if (!tile_tree[0].occupied) {
        tile_tree[0] = .{ .occupied = true, .is_leaf = true, .app_index = app_index };
        return;
    }

    // Find the leaf to split — use the active app's leaf, or the first leaf
    var target: usize = 0;
    if (findLeafByApp(0, active_app)) |idx| {
        target = idx;
    } else {
        target = findFirstLeaf(0) orelse return;
    }

    const left = tileLeft(target);
    const right = tileRight(target);
    if (left >= MAX_TILE_NODES or right >= MAX_TILE_NODES) return;

    // Determine split direction based on depth
    const depth = tileDepth(target);
    const dir: SplitDir = if (depth % 2 == 0) .horizontal else .vertical;

    // Old leaf content goes left, new app goes right
    const old_app = tile_tree[target].app_index;
    tile_tree[target] = .{ .occupied = true, .is_leaf = false, .split_dir = dir };
    tile_tree[left] = .{ .occupied = true, .is_leaf = true, .app_index = old_app };
    tile_tree[right] = .{ .occupied = true, .is_leaf = true, .app_index = app_index };
}

fn removeWindowFromTree(app_index: u8) void {
    const leaf_idx = findLeafByApp(0, app_index) orelse return;

    if (leaf_idx == 0) {
        // Root leaf — just clear it
        tile_tree[0].occupied = false;
        return;
    }

    // Find parent and sibling
    const parent_idx = (leaf_idx - 1) / 2;
    const sibling_idx = if (leaf_idx == tileLeft(parent_idx)) tileRight(parent_idx) else tileLeft(parent_idx);

    // Sibling replaces parent
    tile_tree[parent_idx] = tile_tree[sibling_idx];

    // If sibling was a split node, move its subtree up
    if (!tile_tree[sibling_idx].is_leaf) {
        copySubtree(sibling_idx, parent_idx);
    }

    // Clear old positions
    clearSubtree(sibling_idx);
    tile_tree[leaf_idx].occupied = false;
}

fn copySubtree(from: usize, to: usize) void {
    const from_l = tileLeft(from);
    const from_r = tileRight(from);
    const to_l = tileLeft(to);
    const to_r = tileRight(to);
    if (from_l >= MAX_TILE_NODES or to_l >= MAX_TILE_NODES) return;

    tile_tree[to_l] = tile_tree[from_l];
    tile_tree[to_r] = tile_tree[from_r];

    if (tile_tree[from_l].occupied and !tile_tree[from_l].is_leaf) {
        copySubtree(from_l, to_l);
    }
    if (tile_tree[from_r].occupied and !tile_tree[from_r].is_leaf) {
        copySubtree(from_r, to_r);
    }
}

fn clearSubtree(idx: usize) void {
    tile_tree[idx].occupied = false;
    const l = tileLeft(idx);
    const r = tileRight(idx);
    if (l < MAX_TILE_NODES and tile_tree[l].occupied) clearSubtree(l);
    if (r < MAX_TILE_NODES and tile_tree[r].occupied) clearSubtree(r);
}

fn findLeafByApp(idx: usize, app_index: u32) ?usize {
    if (idx >= MAX_TILE_NODES or !tile_tree[idx].occupied) return null;
    if (tile_tree[idx].is_leaf) {
        if (tile_tree[idx].app_index == @as(u8, @intCast(app_index))) return idx;
        return null;
    }
    return findLeafByApp(tileLeft(idx), app_index) orelse findLeafByApp(tileRight(idx), app_index);
}

fn findFirstLeaf(idx: usize) ?usize {
    if (idx >= MAX_TILE_NODES or !tile_tree[idx].occupied) return null;
    if (tile_tree[idx].is_leaf) return idx;
    return findFirstLeaf(tileLeft(idx)) orelse findFirstLeaf(tileRight(idx));
}

fn tileDepth(idx: usize) u32 {
    if (idx == 0) return 0;
    var d: u32 = 0;
    var i = idx;
    while (i > 0) {
        i = (i - 1) / 2;
        d += 1;
    }
    return d;
}

fn layoutTileTree(idx: usize, x: u32, y: u32, w: u32, h: u32) void {
    if (idx >= MAX_TILE_NODES or !tile_tree[idx].occupied) return;

    if (tile_tree[idx].is_leaf) {
        const ai = tile_tree[idx].app_index;
        if (ai < num_app_fbs) {
            app_fbs[ai].win_x = x;
            app_fbs[ai].win_y = y;
            app_fbs[ai].win_w = w;
            app_fbs[ai].win_h = h;
        }
        return;
    }

    const left = tileLeft(idx);
    const right = tileRight(idx);

    if (tile_tree[idx].split_dir == .horizontal) {
        const half = w / 2;
        const gap = if (half > BORDER_GAP) BORDER_GAP else 0;
        layoutTileTree(left, x, y, half - gap, h);
        layoutTileTree(right, x + half + gap, y, w - half - gap, h);
    } else {
        const half = h / 2;
        const gap = if (half > BORDER_GAP) BORDER_GAP else 0;
        layoutTileTree(left, x, y, w, half - gap);
        layoutTileTree(right, x, y + half + gap, w, h - half - gap);
    }
}

fn retile() void {
    layoutTileTree(0, 0, 0, screen_width, screen_height);

    // Update each app's framebuffer header with new window dimensions
    var i: u32 = 0;
    while (i < num_app_fbs) : (i += 1) {
        updateAppDimensions(&app_fbs[i]);
    }
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

    const w_ptr: *u32 = @ptrCast(@volatileCast(@constCast(&hdr.width)));
    const h_ptr: *u32 = @ptrCast(@volatileCast(@constCast(&hdr.height)));
    const s_ptr: *u32 = @ptrCast(@volatileCast(@constCast(&hdr.stride)));
    const f_ptr: *u32 = @ptrCast(@volatileCast(@constCast(&hdr.format)));
    @atomicStore(u32, w_ptr, w, .release);
    @atomicStore(u32, h_ptr, h, .release);
    @atomicStore(u32, s_ptr, w, .release);
    @atomicStore(u32, f_ptr, screen_format, .release);
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
            screen_fb[y * screen_stride + x] = color;
        }
    }
}

fn blitAppFramebuffer(afb: *const AppFramebuffer) void {
    const hdr = afb.header;
    if (!hdr.isValid()) return;
    const src = hdr.pixelDataConst();
    const w_ptr: *const u32 = @ptrCast(@volatileCast(@constCast(&hdr.width)));
    const h_ptr: *const u32 = @ptrCast(@volatileCast(@constCast(&hdr.height)));
    const s_ptr: *const u32 = @ptrCast(@volatileCast(@constCast(&hdr.stride)));
    const w = @min(@atomicLoad(u32, w_ptr, .acquire), afb.win_w);
    const h = @min(@atomicLoad(u32, h_ptr, .acquire), afb.win_h);
    const src_stride = @atomicLoad(u32, s_ptr, .acquire);
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
            screen_fb[dy * screen_stride + dx] = src[y * src_stride + x];
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
            screen_fb[y * screen_stride + x] = color;
        }
    }
    // Bottom
    y = if (y2 > bw) y2 - bw else 0;
    while (y < y2) : (y += 1) {
        var x: u32 = x1;
        while (x < x2) : (x += 1) {
            screen_fb[y * screen_stride + x] = color;
        }
    }
    // Left
    y = y1;
    while (y < y2) : (y += 1) {
        var x: u32 = x1;
        while (x < @min(x1 + bw, x2)) : (x += 1) {
            screen_fb[y * screen_stride + x] = color;
        }
    }
    // Right
    y = y1;
    while (y < y2) : (y += 1) {
        var x: u32 = if (x2 > bw) x2 - bw else 0;
        while (x < x2) : (x += 1) {
            screen_fb[y * screen_stride + x] = color;
        }
    }
}

fn hitTestWindow(px: u32, py: u32) ?u32 {
    var i: u32 = 0;
    while (i < num_app_fbs) : (i += 1) {
        const afb = &app_fbs[i];
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
                screen_fb[py * screen_stride + px] = black;
            } else if ((cursor_bitmap[row] >> bit) & 1 != 0) {
                screen_fb[py * screen_stride + px] = white;
            }
        }
    }
}

pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse return;
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
        if (display_handle == 0) syscall.thread_yield();
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
    var mouse_wait: u32 = 0;
    while (mouse_chan == null and mouse_wait < 1000) : (mouse_wait += 1) {
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
        if (mouse_chan == null) syscall.thread_yield();
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
                            const hdr: *volatile fb_proto.FramebufferHeader = @ptrFromInt(fb_vm.val2);

                            const app_idx: u8 = @intCast(num_app_fbs);
                            app_fbs[num_app_fbs] = .{
                                .header = hdr,
                                .last_frame = 0,
                                .shm_handle = e.handle,
                                .win_x = 0,
                                .win_y = 0,
                                .win_w = screen_width,
                                .win_h = screen_height,
                            };
                            num_app_fbs += 1;
                            active_app = app_idx;
                            recordShm(e.handle);

                            // Add to tiling tree and recalculate layout
                            addWindowToTree(app_idx);
                            retile();

                            // Initialize header with tiled dimensions (retile already set them)
                            // Set frame_counter before magic so app starts fresh
                            const fc_ptr: *u64 = @ptrCast(@volatileCast(@constCast(&hdr.frame_counter)));
                            @atomicStore(u64, fc_ptr, 0, .release);
                            // Magic last — signals to app that header is ready
                            const m_ptr: *u32 = @ptrCast(@volatileCast(@constCast(&hdr.magic)));
                            @atomicStore(u32, m_ptr, fb_proto.FRAMEBUFFER_MAGIC, .release);

                            syscall.write("compositor: app framebuffer connected\n");
                            needs_redraw = true;
                        }
                    }
                    break;
                }
            }
        }

        // Check for new frames from apps
        for (app_fbs[0..num_app_fbs]) |*afb| {
            const current_frame = afb.header.readFrameCounter();
            if (current_frame != afb.last_frame) {
                afb.last_frame = current_frame;
                needs_redraw = true;
            }
        }

        // Composite and render
        if (needs_redraw) {
            const bg = packPixel(0x0a, 0x0a, 0x1a);
            fillScreen(bg);

            // Draw inactive windows first, active last
            for (app_fbs[0..num_app_fbs], 0..) |*afb, i| {
                if (i != active_app) blitAppFramebuffer(afb);
            }
            if (active_app < num_app_fbs) {
                blitAppFramebuffer(&app_fbs[active_app]);
                // Draw border around active window
                const border_color = packPixel(0x40, 0xa0, 0xff);
                drawWindowBorder(&app_fbs[active_app], border_color);
            }

            drawCursor();
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
