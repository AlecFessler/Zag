const lib = @import("lib");

const channel = lib.channel;
const perms = lib.perms;
const syscall = lib.syscall;

const Channel = channel.Channel;
const Protocol = lib.Protocol;

pub const protocol_id: Protocol = .display;
pub const SHM_SIZE: u64 = syscall.PAGE4K;

// ── Connection ──────────────────────────────────────────────────────

pub const ConnectError = error{
    ServerNotFound,
    ChannelFailed,
};

/// Discovers the display server via broadcast table and connects a command channel.
pub fn connectToServer(perm_view_addr: u64) ConnectError!Client {
    const handle = channel.findBroadcastHandle(perm_view_addr, .display) orelse
        return error.ServerNotFound;
    const conn = Channel.connectAsA(handle, .display, SHM_SIZE) catch
        return error.ChannelFailed;
    return Client{
        .chan = conn.chan,
        .server_handle = handle,
    };
}

// ── Commands ─────────────────────────────────────────────────────────
// B→A (server → client)
const CMD_RENDER_TARGET: u8 = 0x01;
const CMD_WINDOW_RESIZED: u8 = 0x02;
const CMD_FB_READY: u8 = 0x03;

// A→B (client → server)
const CMD_FB_SENT: u8 = 0x10;
const CMD_FRAME_READY: u8 = 0x11;

const SURFACE_PAYLOAD = 16; // width(4) + height(4) + stride(4) + magic(4)
const MAX_WIRE = 17; // tag(1) + largest payload

// ── Types ────────────────────────────────────────────────────────────
pub const RenderTarget = struct {
    width: u32,
    height: u32,
    stride: u32,
    magic: u32,
};

const Fb = struct {
    ptr: [*]u8 = undefined,
    shm_handle: u64 = 0,
    vm_handle: u64 = 0,
    mapped: bool = false,
};

const ServerFb = struct {
    ptr: [*]const u8 = undefined,
    shm_handle: u64 = 0,
    vm_handle: u64 = 0,
    mapped: bool = false,
};

fn alignToPages(size: u64) u64 {
    return ((size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
}

// ── Client (app, side A) ────────────────────────────────────────────
pub const Client = struct {
    chan: *Channel = undefined,
    server_handle: u64 = 0,
    fb: [2]Fb = .{ Fb{}, Fb{} },
    active: u1 = 0,
    width: u32 = 0,
    height: u32 = 0,
    stride: u32 = 0,

    pub fn recv(self: *const Client) ?ClientMessage {
        var buf: [MAX_WIRE]u8 = undefined;
        const len = (self.chan.receiveMessage(.A, &buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            CMD_RENDER_TARGET => parseSurface(buf, len, .render_target),
            CMD_WINDOW_RESIZED => parseSurface(buf, len, .window_resized),
            CMD_FB_READY => .fb_ready,
            else => null,
        };
    }

    fn parseSurface(buf: [MAX_WIRE]u8, len: u64, tag: enum { render_target, window_resized }) ?ClientMessage {
        if (len != 1 + SURFACE_PAYLOAD) return null;
        const info = RenderTarget{
            .width = @as(*align(1) const u32, @ptrCast(buf[1..5])).*,
            .height = @as(*align(1) const u32, @ptrCast(buf[5..9])).*,
            .stride = @as(*align(1) const u32, @ptrCast(buf[9..13])).*,
            .magic = @as(*align(1) const u32, @ptrCast(buf[13..17])).*,
        };
        return switch (tag) {
            .render_target => .{ .render_target = info },
            .window_resized => .{ .window_resized = info },
        };
    }

    /// Creates two flat framebuffer SHMs, writes temporary metadata, and grants to server.
    pub fn setupFramebuffers(self: *Client, info: RenderTarget) !void {
        self.width = info.width;
        self.height = info.height;
        self.stride = info.stride;
        self.active = 0;

        const fb_size = @as(u64, info.stride) * @as(u64, info.height) * 4;
        const aligned = alignToPages(fb_size);

        const shm_rights = (perms.SharedMemoryRights{
            .read = true,
            .write = true,
            .grant = true,
        }).bits();
        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();

        for (0..2) |i| {
            const shm = syscall.shm_create_with_rights(aligned, shm_rights) catch
                return error.ChannelFailed;

            const vm = syscall.vm_reserve(0, aligned, vm_rights) catch
                return error.ChannelFailed;

            syscall.shm_map(shm, vm.handle, 0) catch
                return error.ChannelFailed;

            const ptr: [*]u8 = @ptrFromInt(vm.addr);

            // Write temporary metadata for server to identify this FB
            ptr[0] = @intFromEnum(Protocol.framebuffer);
            @as(*align(1) u32, @ptrCast(ptr[1..5])).* = info.magic;
            ptr[5] = @intCast(i);

            // Grant to display server
            syscall.grant_perm(shm, self.server_handle, shm_rights) catch
                return error.ChannelFailed;

            self.fb[i] = .{
                .ptr = ptr,
                .shm_handle = shm,
                .vm_handle = vm.handle,
                .mapped = true,
            };
        }

        // Tell server we sent the framebuffers
        const bytes = [1]u8{CMD_FB_SENT};
        try self.chan.sendMessage(.A, &bytes);
    }

    pub fn teardownFramebuffers(self: *Client) void {
        for (&self.fb) |*fb| {
            if (fb.mapped) {
                syscall.shm_unmap(fb.shm_handle, fb.vm_handle);
                syscall.revoke_perm(fb.shm_handle);
                fb.mapped = false;
            }
        }
    }

    /// Signals the server that the current framebuffer is ready, then swaps.
    pub fn sendFrameReady(self: *Client) !void {
        const bytes = [1]u8{CMD_FRAME_READY};
        try self.chan.sendMessage(.A, &bytes);
        self.active = ~self.active;
    }

    /// Returns a pointer to the current framebuffer the client should write into.
    pub fn pixels(self: *const Client) [*]u8 {
        return self.fb[self.active].ptr;
    }

    pub fn pixelsAsU32(self: *const Client) [*]u32 {
        return @ptrCast(@alignCast(self.fb[self.active].ptr));
    }

    pub const ClientMessage = union(enum) {
        render_target: RenderTarget,
        window_resized: RenderTarget,
        fb_ready: void,
    };
};

// ── Server (display server, side B) ─────────────────────────────────
pub const Server = struct {
    chan: *Channel = undefined,
    fb: [2]ServerFb = .{ ServerFb{}, ServerFb{} },
    active: u1 = 1,
    magic: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    stride: u32 = 0,
    fb_count: u8 = 0,

    pub fn init(chan: *Channel) Server {
        return .{ .chan = chan };
    }

    pub fn sendRenderTarget(self: *Server, info: RenderTarget) !void {
        self.magic = info.magic;
        self.width = info.width;
        self.height = info.height;
        self.stride = info.stride;
        var bytes: [1 + SURFACE_PAYLOAD]u8 = undefined;
        bytes[0] = CMD_RENDER_TARGET;
        encodeSurface(&bytes, info);
        try self.chan.sendMessage(.B, &bytes);
    }

    pub fn sendWindowResized(self: *Server, info: RenderTarget) !void {
        self.teardownFramebuffers();
        self.magic = info.magic;
        self.width = info.width;
        self.height = info.height;
        self.stride = info.stride;
        var bytes: [1 + SURFACE_PAYLOAD]u8 = undefined;
        bytes[0] = CMD_WINDOW_RESIZED;
        encodeSurface(&bytes, info);
        try self.chan.sendMessage(.B, &bytes);
    }

    pub fn sendFbReady(self: *const Server) !void {
        const bytes = [1]u8{CMD_FB_READY};
        try self.chan.sendMessage(.B, &bytes);
    }

    pub fn recv(self: *const Server) ?ServerMessage {
        var buf: [MAX_WIRE]u8 = undefined;
        const len = (self.chan.receiveMessage(.B, &buf) catch return null) orelse return null;
        if (len < 1) return null;
        return switch (buf[0]) {
            CMD_FB_SENT => .fb_sent,
            CMD_FRAME_READY => .frame_ready,
            else => null,
        };
    }

    /// Maps a framebuffer SHM that was granted by the client.
    /// Reads the temporary metadata (magic, index) from the first bytes.
    /// Returns true if this FB belongs to this server (magic matches).
    pub fn mapFramebuffer(self: *Server, shm_handle: u64) bool {
        const fb_size = @as(u64, self.stride) * @as(u64, self.height) * 4;
        const aligned = alignToPages(fb_size);

        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const vm = syscall.vm_reserve(0, aligned, vm_rights) catch return false;

        syscall.shm_map(shm_handle, vm.handle, 0) catch return false;

        const ptr: [*]const u8 = @ptrFromInt(vm.addr);

        // Read temporary metadata
        const magic = @as(*align(1) const u32, @ptrCast(ptr[1..5])).*;
        const index = ptr[5];

        if (magic != self.magic or index > 1) {
            syscall.shm_unmap(shm_handle, vm.handle);
            return false;
        }

        self.fb[index] = .{
            .ptr = ptr,
            .shm_handle = shm_handle,
            .vm_handle = vm.handle,
            .mapped = true,
        };
        self.fb_count += 1;
        return true;
    }

    /// Maps a framebuffer SHM at the full framebuffer size.
    /// Called when the compositor has already identified the magic and index.
    pub fn mapFramebufferDirect(self: *Server, shm_handle: u64, index: u8) bool {
        if (index > 1) return false;
        const fb_size = @as(u64, self.stride) * @as(u64, self.height) * 4;
        const aligned = alignToPages(fb_size);

        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const vm = syscall.vm_reserve(0, aligned, vm_rights) catch return false;

        syscall.shm_map(shm_handle, vm.handle, 0) catch return false;

        self.fb[index] = .{
            .ptr = @ptrFromInt(vm.addr),
            .shm_handle = shm_handle,
            .vm_handle = vm.handle,
            .mapped = true,
        };
        self.fb_count += 1;
        return true;
    }

    /// Assigns a pre-mapped framebuffer pointer directly.
    pub fn setFramebuffer(self: *Server, ptr: [*]const u8, shm_handle: u64, vm_handle: u64, index: u8) void {
        self.fb[index] = .{
            .ptr = ptr,
            .shm_handle = shm_handle,
            .vm_handle = vm_handle,
            .mapped = true,
        };
        self.fb_count += 1;
    }

    pub fn bothFbsMapped(self: *const Server) bool {
        return self.fb_count >= 2;
    }

    pub fn teardownFramebuffers(self: *Server) void {
        for (&self.fb) |*fb| {
            if (fb.mapped) {
                syscall.shm_unmap(fb.shm_handle, fb.vm_handle);
                fb.mapped = false;
            }
        }
        self.fb_count = 0;
    }

    /// Returns a pointer to the framebuffer the server should read from
    /// (the one the client just finished writing).
    pub fn readPixels(self: *const Server) [*]const u8 {
        return self.fb[self.active].ptr;
    }

    /// Swaps to the next buffer (call after processing FRAME_READY).
    pub fn swapBuffer(self: *Server) void {
        self.active = ~self.active;
    }

    fn encodeSurface(bytes: *[1 + SURFACE_PAYLOAD]u8, info: RenderTarget) void {
        @as(*align(1) u32, @ptrCast(bytes[1..5])).* = info.width;
        @as(*align(1) u32, @ptrCast(bytes[5..9])).* = info.height;
        @as(*align(1) u32, @ptrCast(bytes[9..13])).* = info.stride;
        @as(*align(1) u32, @ptrCast(bytes[13..17])).* = info.magic;
    }

    pub const ServerMessage = union(enum) {
        fb_sent: void,
        frame_ready: void,
    };
};
