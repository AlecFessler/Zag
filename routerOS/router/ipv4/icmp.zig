const router = @import("router");

const arp = router.net.arp;
const main = router.state;
const util = router.util;

pub const PingState = enum { idle, arp_pending, echo_sent };

const ping_id: u16 = 0x5A47;
const timeout_ns: u64 = 3_000_000_000;
const total: u8 = 4;

pub fn sendEchoRequest() void {
    var pkt: [98]u8 = undefined;
    @memset(&pkt, 0);

    const ifc = main.getIface(main.ping_iface);

    @memcpy(pkt[0..6], &main.ping_target_mac);
    @memcpy(pkt[6..12], &ifc.mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    util.writeU16Be(pkt[16..18], 84);
    util.writeU16Be(pkt[18..20], ping_id);
    pkt[22] = 64;
    pkt[23] = 1;
    @memcpy(pkt[26..30], &ifc.ip);
    @memcpy(pkt[30..34], &main.ping_target_ip);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = util.computeChecksum(pkt[14..34]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    pkt[34] = 8;
    util.writeU16Be(pkt[38..40], ping_id);
    util.writeU16Be(pkt[40..42], main.ping_seq);

    pkt[36] = 0;
    pkt[37] = 0;
    const icmp_cs = util.computeChecksum(pkt[34..98]);
    pkt[36] = @truncate(icmp_cs >> 8);
    pkt[37] = @truncate(icmp_cs);

    main.ping_start_ns = util.now();
    main.ping_state = .echo_sent;
    _ = ifc.txSendLocal(&pkt);
}

pub fn handleEchoReply(pkt: []const u8, len: u32) void {
    if (main.ping_state != .echo_sent) return;
    if (len < 42) return;
    if (pkt[23] != 1) return;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const icmp_start = 14 + ip_hdr_len;
    if (icmp_start + 8 > len) return;
    if (pkt[icmp_start] != 0) return;

    const reply_id = util.readU16Be(pkt[icmp_start + 4 ..][0..2]);
    const reply_seq = util.readU16Be(pkt[icmp_start + 6 ..][0..2]);
    if (reply_id != ping_id or reply_seq != main.ping_seq) return;

    const rtt_us = (util.now() -| main.ping_start_ns) / 1000;
    main.ping_received += 1;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = util.appendStr(&resp, pos, "reply from ");
    pos = util.appendIp(&resp, pos, main.ping_target_ip);
    pos = util.appendStr(&resp, pos, ": seq=");
    pos = util.appendDec(&resp, pos, main.ping_seq);
    pos = util.appendStr(&resp, pos, " time=");
    pos = util.appendDec(&resp, pos, rtt_us);
    pos = util.appendStr(&resp, pos, "us");
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    main.ping_count += 1;
    if (main.ping_count >= total) {
        sendSummary();
        main.ping_state = .idle;
    } else {
        main.ping_seq += 1;
        sendEchoRequest();
    }
}

fn sendSummary() void {
    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = util.appendStr(&resp, pos, "--- ping ");
    pos = util.appendIp(&resp, pos, main.ping_target_ip);
    pos = util.appendStr(&resp, pos, ": ");
    pos = util.appendDec(&resp, pos, total);
    pos = util.appendStr(&resp, pos, " sent, ");
    pos = util.appendDec(&resp, pos, main.ping_received);
    pos = util.appendStr(&resp, pos, " received ---");
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }
}

pub fn checkTimeout() void {
    if (main.ping_state == .idle) return;
    if (util.now() -| main.ping_start_ns < timeout_ns) return;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    if (main.ping_state == .arp_pending) {
        pos = util.appendStr(&resp, pos, "ping: ARP timeout for ");
        pos = util.appendIp(&resp, pos, main.ping_target_ip);
    } else {
        pos = util.appendStr(&resp, pos, "request timeout: seq=");
        pos = util.appendDec(&resp, pos, main.ping_seq);
    }
    if (main.console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    main.ping_count += 1;
    if (main.ping_count >= total) {
        sendSummary();
        main.ping_state = .idle;
    } else {
        main.ping_seq += 1;
        if (main.ping_state == .arp_pending) {
            arp.sendRequest(main.ping_iface, main.ping_target_ip);
            main.ping_start_ns = util.now();
        } else {
            sendEchoRequest();
        }
    }
}
