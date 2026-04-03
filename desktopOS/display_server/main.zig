const lib = @import("lib");
const display_mod = @import("display.zig");

const channel = lib.channel;
const display = lib.display;
const mouse = lib.mouse;
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const Channel = channel.Channel;
const Display = display_mod.Display;
const Protocol = lib.Protocol;

// ── Constants ────────────────────────────────────────────────────────
const MAX_CLIENTS = 16;

// ── Client connection state ─────────────────────────────────────────
const ClientConn = struct {
    active: bool = false,
    server: display.Server = .{},
    has_frame: bool = false,
};

var clients: [MAX_CLIENTS]ClientConn = .{ClientConn{}} ** MAX_CLIENTS;
var client_count: u8 = 0;

var next_magic: u32 = 1;

fn allocMagic() u32 {
    const m = next_magic;
    next_magic +%= 1;
    return m;
}

// ── SHM tracking ────────────────────────────────────────────────────
// Tracks SHMs in two bins:
//   own  — handles we created via connectAsA (must never be peeked/dispatched)
//   seen — handles from the perm_view we already dispatched
const ShmTracker = struct {
    own: [MAX_OWN]u64 = .{0} ** MAX_OWN,
    own_count: u8 = 0,
    seen: [MAX_SEEN]u64 = .{0} ** MAX_SEEN,
    seen_count: u8 = 0,

    const MAX_OWN = 8;
    const MAX_SEEN = 64;

    fn addOwn(self: *ShmTracker, handle: u64) void {
        if (self.own_count < MAX_OWN) {
            self.own[self.own_count] = handle;
            self.own_count += 1;
        }
    }

    fn isKnown(self: *const ShmTracker, handle: u64) bool {
        for (self.own[0..self.own_count]) |h| {
            if (h == handle) return true;
        }
        for (self.seen[0..self.seen_count]) |h| {
            if (h == handle) return true;
        }
        return false;
    }

    fn pollNew(self: *ShmTracker, view_addr: u64) ?u64 {
        const view: *const [128]perm_view.UserViewEntry = @ptrFromInt(view_addr);
        for (view) |*entry| {
            if (entry.entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
                if (!self.isKnown(entry.handle) and self.seen_count < MAX_SEEN) {
                    self.seen[self.seen_count] = entry.handle;
                    self.seen_count += 1;
                    return entry.handle;
                }
            }
        }
        return null;
    }
};

var shm_tracker = ShmTracker{};

// ── SHM mapping ─────────────────────────────────────────────────────
const MapResult = struct {
    ptr: [*]u8,
    vm_handle: u64,
};

fn mapShm(shm_handle: u64, size: u64) ?MapResult {
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.vm_reserve(0, size, vm_rights) catch return null;
    syscall.shm_map(shm_handle, vm.handle, 0) catch {
        syscall.revoke_perm(vm.handle);
        return null;
    };
    return .{ .ptr = @ptrFromInt(vm.addr), .vm_handle = vm.handle };
}

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

// ── Window management ───────────────────────────────────────────────
fn registerClient(chan: *Channel, disp: *const Display) void {
    if (client_count >= MAX_CLIENTS) {
        return;
    }

    const idx = client_count;
    client_count += 1;

    var server = display.Server.init(chan);
    const magic = allocMagic();

    server.sendRenderTarget(.{
        .width = disp.width,
        .height = disp.height,
        .stride = disp.width,
        .magic = magic,
    }) catch {
        return;
    };

    clients[idx] = .{
        .active = true,
        .server = server,
    };
}

/// Assign a pre-mapped framebuffer to the matching client connection by magic and index.
fn handleFramebufferShm(ptr: [*]const u8, shm_handle: u64, vm_handle: u64, magic: u32, index: u8) void {
    if (index > 1) return;
    for (clients[0..client_count]) |*conn| {
        if (!conn.active) continue;
        if (conn.server.magic == magic) {
            conn.server.setFramebuffer(ptr, shm_handle, vm_handle, index);
            if (conn.server.bothFbsMapped()) {
                conn.server.sendFbReady() catch {};
            }
            return;
        }
    }
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

fn blitWindow(hw_disp: *const Display, src: [*]const u8, src_w: u32, src_h: u32) void {
    const dst = hw_disp.backBufBytes();
    const dst_stride: usize = @intCast(hw_disp.stride);
    const dst_w: u32 = hw_disp.width;
    const dst_h: u32 = hw_disp.height;

    var y: u32 = 0;
    while (y < src_h and y < dst_h) : (y += 1) {
        const src_off: usize = @as(usize, y) * @as(usize, src_w) * 4;
        const dst_off: usize = @as(usize, y) * dst_stride * 4;
        const copy_w: usize = @min(src_w, dst_w);
        @memcpy(dst[dst_off..][0 .. copy_w * 4], src[src_off..][0 .. copy_w * 4]);
    }
}

fn composite(disp: *const Display) void {
    const bg_color = packPixel(0x0a, 0x0a, 0x1a);
    disp.fill(bg_color);

    // Blit the last client that has a frame, then swap its buffer
    var i: u8 = client_count;
    while (i > 0) {
        i -= 1;
        var conn = &clients[i];
        if (conn.active and conn.has_frame) {
            blitWindow(disp, conn.server.readPixels(), conn.server.width, conn.server.height);
            break;
        }
    }

    drawCursor(disp);
    disp.present();
}

fn packPixel(r: u8, g: u8, b: u8) u32 {
    return @as(u32, b) | (@as(u32, g) << 8) | (@as(u32, r) << 16) | (0xFF << 24);
}

// ── Main ─────────────────────────────────────────────────────────────
pub fn main(perm_view_addr: u64) void {
    var disp = Display.init(perm_view_addr) orelse return;

    cursor_x = @intCast(disp.width / 2);
    cursor_y = @intCast(disp.height / 2);

    const bg_color = packPixel(0x0a, 0x0a, 0x1a);
    disp.fill(bg_color);
    disp.present();

    // Broadcast as display server
    channel.broadcast(@intFromEnum(Protocol.display)) catch return;

    // Connect to mouse server (USB HID driver)
    var mouse_result_opt: ?mouse.ConnectResult = null;
    while (mouse_result_opt == null) {
        mouse_result_opt = mouse.connectToServer(perm_view_addr) catch |err| switch (err) {
            error.ServerNotFound => null,
            error.ChannelFailed => return,
        };
        if (mouse_result_opt == null) syscall.thread_yield();
    }
    const mouse_result = mouse_result_opt.?;
    const mouse_client = mouse_result.client;
    shm_tracker.addOwn(mouse_result.shm_handle);

    const screen_w: i32 = @intCast(disp.width);
    const screen_h: i32 = @intCast(disp.height);
    var needs_composite: bool = false;

    while (true) {
        // Accept all pending SHMs — map once, dispatch by header, keep mapping
        while (shm_tracker.pollNew(perm_view_addr)) |shm_handle| {
            // Try 4K first (command channels), then FB size
            if (mapShm(shm_handle, display.SHM_SIZE)) |map| {
                const proto_id = map.ptr[0];
                if (proto_id == @intFromEnum(Protocol.display)) {
                    const chan: *Channel = @ptrCast(@alignCast(map.ptr));
                    @atomicStore(u64, &chan.B_connected, 1, .release);
                    registerClient(chan, &disp);
                    needs_composite = true;
                }
            } else {
                const fb_size = @as(u64, disp.width) * @as(u64, disp.height) * 4;
                const aligned_fb = channel.alignToPages(fb_size);
                if (mapShm(shm_handle, aligned_fb)) |map| {
                    if (map.ptr[0] == @intFromEnum(Protocol.framebuffer)) {
                        const magic = @as(*align(1) const u32, @ptrCast(map.ptr[1..5])).*;
                        const index = map.ptr[5];
                        handleFramebufferShm(map.ptr, shm_handle, map.vm_handle, magic, index);
                    }
                }
            }
        }

        // Drain all pending mouse events
        while (mouse_client.recv()) |msg| {
            switch (msg) {
                .mouse => |ev| {
                    cursor_x = clampI32(cursor_x + ev.dx, 0, screen_w - 1);
                    cursor_y = clampI32(cursor_y + ev.dy, 0, screen_h - 1);
                    needs_composite = true;
                },
            }
        }

        // Poll all active client connections
        for (clients[0..client_count]) |*conn| {
            if (!conn.active) continue;
            if (conn.server.recv()) |msg| {
                switch (msg) {
                    .fb_sent => {},
                    .frame_ready => {
                        conn.has_frame = true;
                        conn.server.swapBuffer();
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
