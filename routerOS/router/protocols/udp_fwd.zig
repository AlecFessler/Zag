const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const h = router.hal.headers;
const main = router.state;
const util = router.util;

const Seqlock = lib.sync.Seqlock;
const channel_mod = lib.channel;
const syscall = lib.syscall;

pub const MSG_UDP_SEND: u8 = 0x01;
pub const MSG_UDP_RECV: u8 = 0x02;
pub const MSG_UDP_BIND: u8 = 0x03;

pub const MAX_BINDINGS = 16;
pub const MAX_PENDING = 8;
const PENDING_BUF_SIZE = 2048;

pub const AppId = enum(u8) { nfs = 0, ntp = 1 };

pub const UdpBinding = struct {
    seq: Seqlock = Seqlock.init(),
    valid: bool = false,
    port: u16 = 0,
    app: AppId = .nfs,
};

pub const PendingPacket = struct {
    state: u8 align(8) = 0, // 0=empty, 1=ready (atomic)
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
            b.seq.writeBegin();
            b.valid = true;
            b.port = port;
            b.app = app;
            b.seq.writeEnd();
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

    const eth = h.EthernetHeader.parseMut(&frame) orelse return;
    @memcpy(&eth.dst_mac, &gateway_mac);
    @memcpy(&eth.src_mac, &main.wan_iface.mac);
    eth.setEtherType(h.EthernetHeader.IPv4);

    const ip = h.Ipv4Header.parseMut(frame[14..]) orelse return;
    ip.ver_ihl = 0x45;
    ip.setTotalLen(ip_total);
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_UDP;
    @memcpy(&ip.src_ip, &main.wan_iface.ip);
    @memcpy(&ip.dst_ip, &dst_ip);
    ip.computeAndSetChecksum(&frame);

    const udp = h.UdpHeader.parseMut(frame[34..]) orelse return;
    udp.setSrcPort(src_port);
    udp.setDstPort(dst_port);
    udp.setLength(udp_len);
    udp.zeroChecksum();

    @memcpy(frame[42..][0..payload.len], payload);

    _ = main.wan_iface.txSendLocal(frame[0..frame_len], .service);
}

fn queuePending(dst_ip: [4]u8, data: []const u8) void {
    if (data.len > PENDING_BUF_SIZE) return;
    for (&main.pending_udp) |*p| {
        if (@atomicLoad(u8, &p.state, .acquire) == 0) {
            p.dst_ip = dst_ip;
            p.len = @intCast(data.len);
            @memcpy(p.data[0..data.len], data);
            @atomicStore(u8, &p.state, 1, .release);
            return;
        }
    }
    // Overwrite first slot as fallback
    const p = &main.pending_udp[0];
    p.dst_ip = dst_ip;
    p.len = @intCast(data.len);
    @memcpy(p.data[0..data.len], data);
    @atomicStore(u8, &p.state, 1, .release);
}

pub fn drainPending() void {
    for (&main.pending_udp) |*p| {
        if (@atomicLoad(u8, &p.state, .acquire) == 0) continue;
        if (arp.lookup(&main.wan_iface.arp_table, p.dst_ip) != null) {
            handleUdpSend(p.data[0..p.len]);
            @atomicStore(u8, &p.state, 0, .release);
        }
    }
}

pub fn sendGratuitousArp() void {
    arp.sendRequest(.wan, main.wan_gateway);
}

pub fn forwardToApp(src_ip: [4]u8, src_port: u16, dst_port: u16, payload: []const u8) bool {
    var target_app: AppId = .nfs;
    var matched = false;
    for (&main.udp_bindings) |*b| {
        const gen = b.seq.readBeginNonblock();
        const valid = b.valid;
        const port = b.port;
        const app = b.app;
        if (b.seq.readRetry(gen)) continue;
        if (valid and port == dst_port) {
            target_app = app;
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
