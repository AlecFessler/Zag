const arp = @import("arp.zig");
const main = @import("main.zig");
const util = @import("util.zig");

const channel_mod = @import("lib").channel;
const lib = @import("lib");
const syscall = lib.syscall;

pub const MSG_UDP_SEND: u8 = 0x01;
pub const MSG_UDP_RECV: u8 = 0x02;
pub const MSG_UDP_BIND: u8 = 0x03;

pub const MAX_BINDINGS = 8;
pub const MAX_PENDING = 2;
const PENDING_BUF_SIZE = 256;

pub const AppId = enum(u8) { nfs = 0, ntp = 1 };

pub const UdpBinding = struct {
    valid: bool = false,
    port: u16 = 0,
    app: AppId = .nfs,
};

pub const PendingPacket = struct {
    valid: bool = false,
    dst_ip: [4]u8 = .{ 0, 0, 0, 0 },
    len: u16 = 0,
    data: [PENDING_BUF_SIZE]u8 = undefined,
};

pub fn handleAppMessage(data: []const u8, app: AppId) void {
    if (data.len < 1) return;
    switch (data[0]) {
        MSG_UDP_SEND => handleUdpSend(data),
        MSG_UDP_BIND => handleUdpBind(data, app),
        else => {},
    }
}

fn handleUdpBind(data: []const u8, app: AppId) void {
    if (data.len < 3) return;
    const port = util.readU16Be(data[1..3]);
    for (&main.udp_bindings) |*b| {
        if (!b.valid) {
            b.* = .{ .valid = true, .port = port, .app = app };
            return;
        }
    }
}

fn handleUdpSend(data: []const u8) void {
    if (data.len < 9) return;
    var dst_ip: [4]u8 = undefined;
    @memcpy(&dst_ip, data[1..5]);
    const dst_port = util.readU16Be(data[5..7]);
    const src_port = util.readU16Be(data[7..9]);
    const payload = data[9..];

    const udp_len: u16 = @intCast(8 + payload.len);
    const ip_total: u16 = 20 + udp_len;
    const frame_len: usize = 14 + @as(usize, ip_total);

    var frame: [2048]u8 = undefined;
    if (frame_len > frame.len) return;

    const gateway_mac = arp.lookup(&main.wan_iface.arp_table, dst_ip) orelse {
        arp.sendRequest(.wan, dst_ip);
        queuePending(dst_ip, data);
        return;
    };
    @memcpy(frame[0..6], &gateway_mac);
    @memcpy(frame[6..12], &main.wan_iface.mac);
    frame[12] = 0x08;
    frame[13] = 0x00;

    frame[14] = 0x45;
    frame[15] = 0x00;
    util.writeU16Be(frame[16..18], ip_total);
    frame[18] = 0;
    frame[19] = 0;
    frame[20] = 0;
    frame[21] = 0;
    frame[22] = 64;
    frame[23] = 17;
    frame[24] = 0;
    frame[25] = 0;
    @memcpy(frame[26..30], &main.wan_iface.ip);
    @memcpy(frame[30..34], &dst_ip);

    const ip_cs = util.computeChecksum(frame[14..34]);
    frame[24] = @truncate(ip_cs >> 8);
    frame[25] = @truncate(ip_cs);

    util.writeU16Be(frame[34..36], src_port);
    util.writeU16Be(frame[36..38], dst_port);
    util.writeU16Be(frame[38..40], udp_len);
    frame[40] = 0;
    frame[41] = 0;

    @memcpy(frame[42..][0..payload.len], payload);

    _ = main.wan_iface.txSendLocal(frame[0..frame_len]);
}

fn queuePending(dst_ip: [4]u8, data: []const u8) void {
    if (data.len > PENDING_BUF_SIZE) return;
    for (&main.pending_udp) |*p| {
        if (!p.valid) {
            p.valid = true;
            p.dst_ip = dst_ip;
            p.len = @intCast(data.len);
            @memcpy(p.data[0..data.len], data);
            return;
        }
    }
    main.pending_udp[0].valid = true;
    main.pending_udp[0].dst_ip = dst_ip;
    main.pending_udp[0].len = @intCast(data.len);
    @memcpy(main.pending_udp[0].data[0..data.len], data);
}

pub fn drainPending() void {
    for (&main.pending_udp) |*p| {
        if (!p.valid) continue;
        if (arp.lookup(&main.wan_iface.arp_table, p.dst_ip) != null) {
            handleUdpSend(p.data[0..p.len]);
            p.valid = false;
        }
    }
}

pub fn sendGratuitousArp() void {
    const gateway = [4]u8{ 10, 0, 2, 1 };
    arp.sendRequest(.wan, gateway);
}

pub fn forwardToApp(src_ip: [4]u8, src_port: u16, dst_port: u16, payload: []const u8) bool {
    var target_app: AppId = .nfs;
    var matched = false;
    for (&main.udp_bindings) |*b| {
        if (b.valid and b.port == dst_port) {
            target_app = b.app;
            matched = true;
            break;
        }
    }
    if (!matched) return false;

    var chan: *channel_mod.Channel = switch (target_app) {
        .nfs => &(main.nfs_chan orelse return false),
        .ntp => &(main.ntp_chan orelse return false),
    };

    var msg: [2048]u8 = undefined;
    const msg_len = 9 + payload.len;
    if (msg_len > msg.len) return false;

    msg[0] = MSG_UDP_RECV;
    @memcpy(msg[1..5], &src_ip);
    util.writeU16Be(msg[5..7], src_port);
    util.writeU16Be(msg[7..9], dst_port);
    @memcpy(msg[9..][0..payload.len], payload);

    _ = chan.send(msg[0..msg_len]);
    return true;
}
