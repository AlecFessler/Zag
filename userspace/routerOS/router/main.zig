const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const ARP_TABLE_SIZE = 16;

var nic_chan: channel_mod.Channel = undefined;
var console_chan: ?channel_mod.Channel = null;
var router_mac: [6]u8 = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
var router_ip: [4]u8 = .{ 10, 0, 2, 15 };

// ── ARP table ────────────────────────────────────────────────────────────

const ArpEntry = struct {
    ip: [4]u8,
    mac: [6]u8,
    valid: bool,
};

var arp_table: [ARP_TABLE_SIZE]ArpEntry = [_]ArpEntry{.{
    .ip = .{ 0, 0, 0, 0 },
    .mac = .{ 0, 0, 0, 0, 0, 0 },
    .valid = false,
}} ** ARP_TABLE_SIZE;

fn arpLookup(ip: [4]u8) ?[6]u8 {
    for (&arp_table) |*entry| {
        if (entry.valid and eql(&entry.ip, &ip)) return entry.mac;
    }
    return null;
}

fn arpLearn(ip: [4]u8, mac: [6]u8) void {
    for (&arp_table) |*entry| {
        if (entry.valid and eql(&entry.ip, &ip)) {
            @memcpy(&entry.mac, &mac);
            return;
        }
    }
    for (&arp_table) |*entry| {
        if (!entry.valid) {
            entry.ip = ip;
            @memcpy(&entry.mac, &mac);
            entry.valid = true;
            return;
        }
    }
    arp_table[0].ip = ip;
    @memcpy(&arp_table[0].mac, &mac);
    arp_table[0].valid = true;
}

// ── Ping state machine ──────────────────────────────────────────────────

const PingState = enum { idle, arp_pending, echo_sent };

var ping_state: PingState = .idle;
var ping_target_ip: [4]u8 = .{ 0, 0, 0, 0 };
var ping_target_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
var ping_seq: u16 = 0;
const ping_id: u16 = 0x5A47;
var ping_start_ns: u64 = 0;
const ping_timeout_ns: u64 = 3_000_000_000;
var ping_count: u8 = 0;
const ping_total: u8 = 4;
var ping_received: u8 = 0;

// ── String helpers ──────────────────────────────────────────────────────

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return eql(haystack[0..prefix.len], prefix);
}

fn appendStr(buf: []u8, pos: usize, s: []const u8) usize {
    const end = @min(pos + s.len, buf.len);
    @memcpy(buf[pos..end], s[0..(end - pos)]);
    return end;
}

fn appendDec(buf: []u8, pos: usize, val: u64) usize {
    if (val == 0) {
        if (pos < buf.len) {
            buf[pos] = '0';
            return pos + 1;
        }
        return pos;
    }
    var tmp: [20]u8 = undefined;
    var v = val;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        tmp[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    return appendStr(buf, pos, tmp[i..20]);
}

fn appendIp(buf: []u8, pos: usize, ip: [4]u8) usize {
    var p = pos;
    for (ip, 0..) |octet, idx| {
        p = appendDec(buf, p, octet);
        if (idx < 3) p = appendStr(buf, p, ".");
    }
    return p;
}

fn appendMac(buf: []u8, pos: usize, mac: [6]u8) usize {
    const hex_chars = "0123456789abcdef";
    var p = pos;
    for (mac, 0..) |byte, idx| {
        if (p + 2 > buf.len) break;
        buf[p] = hex_chars[byte >> 4];
        buf[p + 1] = hex_chars[byte & 0xf];
        p += 2;
        if (idx < 5) p = appendStr(buf, p, ":");
    }
    return p;
}

fn parseIp(s: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var octet: u16 = 0;
    var idx: usize = 0;
    var digits: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (digits == 0 or octet > 255 or idx >= 3) return null;
            ip[idx] = @truncate(octet);
            idx += 1;
            octet = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            digits += 1;
        } else {
            return null;
        }
    }
    if (digits == 0 or octet > 255 or idx != 3) return null;
    ip[3] = @truncate(octet);
    return ip;
}

// ── Packet helpers ──────────────────────────────────────────────────────

fn readU16Be(buf: []const u8) u16 {
    return @as(u16, buf[0]) << 8 | buf[1];
}

fn writeU16Be(buf: []u8, val: u16) void {
    buf[0] = @truncate(val >> 8);
    buf[1] = @truncate(val);
}

fn computeChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | data[i + 1];
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @truncate(~sum);
}

// ── ARP packet handling ─────────────────────────────────────────────────

fn sendArpRequest(target_ip: [4]u8) void {
    var pkt: [60]u8 = undefined;
    @memset(&pkt, 0);
    @memset(pkt[0..6], 0xFF);
    @memcpy(pkt[6..12], &router_mac);
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    pkt[14] = 0x00;
    pkt[15] = 0x01;
    pkt[16] = 0x08;
    pkt[17] = 0x00;
    pkt[18] = 0x06;
    pkt[19] = 0x04;
    pkt[20] = 0x00;
    pkt[21] = 0x01;
    @memcpy(pkt[22..28], &router_mac);
    @memcpy(pkt[28..32], &router_ip);
    @memset(pkt[32..38], 0);
    @memcpy(pkt[38..42], &target_ip);
    _ = nic_chan.send(&pkt);
}

fn handleArp(pkt: []u8, len: u32) ?[]u8 {
    if (len < 42) return null;
    const arp_start = 14;
    if (readU16Be(pkt[arp_start..][0..2]) != 0x0001) return null;
    if (readU16Be(pkt[arp_start + 2 ..][0..2]) != 0x0800) return null;
    if (readU16Be(pkt[arp_start + 6 ..][0..2]) != 0x0001) return null;

    if (!eql(pkt[arp_start + 24 ..][0..4], &router_ip)) return null;

    @memcpy(pkt[0..6], pkt[6..12]);
    @memcpy(pkt[6..12], &router_mac);

    writeU16Be(pkt[arp_start + 6 ..][0..2], 0x0002);

    var mac_tmp: [6]u8 = undefined;
    @memcpy(&mac_tmp, pkt[arp_start + 8 ..][0..6]);
    @memcpy(pkt[arp_start + 18 ..][0..6], &mac_tmp);
    @memcpy(pkt[arp_start + 8 ..][0..6], &router_mac);

    var ip_tmp: [4]u8 = undefined;
    @memcpy(&ip_tmp, pkt[arp_start + 14 ..][0..4]);
    @memcpy(pkt[arp_start + 24 ..][0..4], &ip_tmp);
    @memcpy(pkt[arp_start + 14 ..][0..4], &router_ip);

    if (len < 60) {
        @memset(pkt[42..60], 0);
        return pkt[0..60];
    }
    return pkt[0..len];
}

// ── ICMP handling ───────────────────────────────────────────────────────

fn handleIcmp(pkt: []u8, len: u32) ?[]u8 {
    if (len < 34) return null;
    if (pkt[23] != 1) return null;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const icmp_start = 14 + ip_hdr_len;
    if (icmp_start + 8 > len) return null;

    if (pkt[icmp_start] != 8) return null;

    @memcpy(pkt[0..6], pkt[6..12]);
    @memcpy(pkt[6..12], &router_mac);

    var tmp: [4]u8 = undefined;
    @memcpy(&tmp, pkt[26..30]);
    @memcpy(pkt[26..30], pkt[30..34]);
    @memcpy(pkt[30..34], &tmp);

    pkt[icmp_start] = 0;
    pkt[icmp_start + 2] = 0;
    pkt[icmp_start + 3] = 0;
    const cs = computeChecksum(pkt[icmp_start..len]);
    pkt[icmp_start + 2] = @truncate(cs >> 8);
    pkt[icmp_start + 3] = @truncate(cs);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = computeChecksum(pkt[14..][0..ip_hdr_len]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    return pkt[0..len];
}

// ── Outbound ping ───────────────────────────────────────────────────────

fn sendEchoRequest() void {
    var pkt: [98]u8 = undefined;
    @memset(&pkt, 0);

    @memcpy(pkt[0..6], &ping_target_mac);
    @memcpy(pkt[6..12], &router_mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    pkt[14] = 0x45;
    pkt[15] = 0x00;
    writeU16Be(pkt[16..18], 84);
    writeU16Be(pkt[18..20], ping_id);
    pkt[20] = 0x00;
    pkt[21] = 0x00;
    pkt[22] = 64;
    pkt[23] = 1;
    @memcpy(pkt[26..30], &router_ip);
    @memcpy(pkt[30..34], &ping_target_ip);

    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = computeChecksum(pkt[14..34]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);

    pkt[34] = 8;
    pkt[35] = 0;
    writeU16Be(pkt[38..40], ping_id);
    writeU16Be(pkt[40..42], ping_seq);

    pkt[36] = 0;
    pkt[37] = 0;
    const icmp_cs = computeChecksum(pkt[34..98]);
    pkt[36] = @truncate(icmp_cs >> 8);
    pkt[37] = @truncate(icmp_cs);

    ping_start_ns = @bitCast(syscall.clock_gettime());
    ping_state = .echo_sent;
    _ = nic_chan.send(&pkt);
}

fn handleEchoReply(pkt: []const u8, len: u32) void {
    if (ping_state != .echo_sent) return;
    if (len < 42) return;
    if (pkt[23] != 1) return;

    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const icmp_start = 14 + ip_hdr_len;
    if (icmp_start + 8 > len) return;

    if (pkt[icmp_start] != 0) return;

    const reply_id = readU16Be(pkt[icmp_start + 4 ..][0..2]);
    const reply_seq = readU16Be(pkt[icmp_start + 6 ..][0..2]);
    if (reply_id != ping_id or reply_seq != ping_seq) return;

    const now_ns: u64 = @bitCast(syscall.clock_gettime());
    const rtt_us = (now_ns -| ping_start_ns) / 1000;

    ping_received += 1;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = appendStr(&resp, pos, "reply from ");
    pos = appendIp(&resp, pos, ping_target_ip);
    pos = appendStr(&resp, pos, ": seq=");
    pos = appendDec(&resp, pos, ping_seq);
    pos = appendStr(&resp, pos, " time=");
    pos = appendDec(&resp, pos, rtt_us);
    pos = appendStr(&resp, pos, "us");

    if (console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    ping_count += 1;
    if (ping_count >= ping_total) {
        sendPingSummary();
        ping_state = .idle;
    } else {
        ping_seq += 1;
        sendEchoRequest();
    }
}

fn sendPingSummary() void {
    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    pos = appendStr(&resp, pos, "--- ping ");
    pos = appendIp(&resp, pos, ping_target_ip);
    pos = appendStr(&resp, pos, ": ");
    pos = appendDec(&resp, pos, ping_total);
    pos = appendStr(&resp, pos, " sent, ");
    pos = appendDec(&resp, pos, ping_received);
    pos = appendStr(&resp, pos, " received ---");
    if (console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }
}

fn checkPingTimeout() void {
    if (ping_state == .idle) return;

    const now_ns: u64 = @bitCast(syscall.clock_gettime());
    if (now_ns -| ping_start_ns < ping_timeout_ns) return;

    var resp: [128]u8 = undefined;
    var pos: usize = 0;
    if (ping_state == .arp_pending) {
        pos = appendStr(&resp, pos, "ping: ARP timeout for ");
        pos = appendIp(&resp, pos, ping_target_ip);
    } else {
        pos = appendStr(&resp, pos, "request timeout: seq=");
        pos = appendDec(&resp, pos, ping_seq);
    }
    if (console_chan) |*chan| {
        _ = chan.send(resp[0..pos]);
    }

    ping_count += 1;
    if (ping_count >= ping_total) {
        sendPingSummary();
        ping_state = .idle;
    } else {
        ping_seq += 1;
        if (ping_state == .arp_pending) {
            sendArpRequest(ping_target_ip);
            ping_start_ns = @bitCast(syscall.clock_gettime());
        } else {
            sendEchoRequest();
        }
    }
}

// ── Console commands ────────────────────────────────────────────────────

fn handleConsoleCommand(data: []const u8) void {
    var chan = &(console_chan orelse return);
    if (eql(data, "status")) {
        var resp: [128]u8 = undefined;
        var pos: usize = 0;
        pos = appendStr(&resp, pos, "router: running, IP ");
        pos = appendIp(&resp, pos, router_ip);
        pos = appendStr(&resp, pos, ", MAC ");
        pos = appendMac(&resp, pos, router_mac);
        _ = chan.send(resp[0..pos]);
    } else if (startsWith(data, "ping ")) {
        if (ping_state != .idle) {
            _ = chan.send("ping: already in progress");
            return;
        }
        if (parseIp(data[5..])) |ip| {
            ping_target_ip = ip;
            ping_seq = 0;
            ping_count = 0;
            ping_received = 0;

            if (arpLookup(ip)) |mac| {
                @memcpy(&ping_target_mac, &mac);
                sendEchoRequest();
            } else {
                ping_state = .arp_pending;
                ping_start_ns = @bitCast(syscall.clock_gettime());
                sendArpRequest(ip);
            }
        } else {
            _ = chan.send("ping: invalid IP address");
        }
    } else if (eql(data, "arp")) {
        var resp: [512]u8 = undefined;
        var pos: usize = 0;
        var count: u32 = 0;
        for (&arp_table) |*entry| {
            if (entry.valid) {
                if (count > 0) pos = appendStr(&resp, pos, "\n");
                pos = appendIp(&resp, pos, entry.ip);
                pos = appendStr(&resp, pos, " -> ");
                pos = appendMac(&resp, pos, entry.mac);
                count += 1;
            }
        }
        if (count == 0) {
            _ = chan.send("arp table: empty");
        } else {
            var hdr: [128]u8 = undefined;
            var hpos: usize = 0;
            hpos = appendStr(&hdr, hpos, "arp table (");
            hpos = appendDec(&hdr, hpos, count);
            hpos = appendStr(&hdr, hpos, " entries):");
            _ = chan.send(hdr[0..hpos]);
            _ = chan.send(resp[0..pos]);
        }
    } else {
        _ = chan.send("router: unknown command");
    }
}

// ── Main ────────────────────────────────────────────────────────────────

pub fn main(perm_view_addr: u64) void {
    syscall.write("router: started\n");

    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("router: no command channel\n");
        return;
    };

    const nic_entry = cmd.requestConnection(shm_protocol.ServiceId.NIC) orelse {
        syscall.write("router: NIC not allowed\n");
        return;
    };
    if (!cmd.waitForConnection(nic_entry)) {
        syscall.write("router: NIC connection failed\n");
        return;
    }
    syscall.write("router: NIC connected\n");

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();

    var shm_handles: [4]u64 = .{ 0, 0, 0, 0 };
    var shm_sizes: [4]u64 = .{ 0, 0, 0, 0 };
    var shm_count: u32 = 0;
    while (shm_count == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 > shm_protocol.COMMAND_SHM_SIZE and shm_count < 4) {
                shm_handles[shm_count] = e.handle;
                shm_sizes[shm_count] = e.field0;
                shm_count += 1;
            }
        }
        if (shm_count == 0) syscall.thread_yield();
    }

    const nic_vm = syscall.vm_reserve(0, shm_sizes[0], vm_rights);
    if (nic_vm.val < 0) {
        syscall.write("router: NIC vm_reserve failed\n");
        return;
    }
    if (syscall.shm_map(shm_handles[0], @intCast(nic_vm.val), 0) != 0) {
        syscall.write("router: NIC shm_map failed\n");
        return;
    }

    const nic_header: *channel_mod.ChannelHeader = @ptrFromInt(nic_vm.val2);
    nic_chan = channel_mod.Channel.openAsSideB(nic_header) orelse {
        syscall.write("router: NIC channel open failed\n");
        return;
    };

    syscall.write("router: NIC data channel ready\n");

    sendArpRequest(.{ 10, 0, 2, 2 });
    syscall.write("router: sent ARP request for 10.0.2.2\n");

    while (true) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and e.field0 > shm_protocol.COMMAND_SHM_SIZE and e.handle != shm_handles[0] and console_chan == null) {
                const con_vm = syscall.vm_reserve(0, e.field0, vm_rights);
                if (con_vm.val >= 0) {
                    if (syscall.shm_map(e.handle, @intCast(con_vm.val), 0) == 0) {
                        const con_header: *channel_mod.ChannelHeader = @ptrFromInt(con_vm.val2);
                        console_chan = channel_mod.Channel.initAsSideA(con_header, @truncate(e.field0));
                        syscall.write("router: console channel connected\n");
                    }
                }
                break;
            }
        }

        if (console_chan) |*chan| {
            var cmd_buf: [256]u8 = undefined;
            if (chan.recv(&cmd_buf)) |len| {
                handleConsoleCommand(cmd_buf[0..len]);
            }
        }

        var pkt_buf: [2048]u8 = undefined;
        if (nic_chan.recv(&pkt_buf)) |len| {
            if (len >= 14) {
                const ethertype = readU16Be(pkt_buf[12..14]);
                if (ethertype == 0x0806) {
                    if (len >= 42) {
                        var sender_mac: [6]u8 = undefined;
                        var sender_ip: [4]u8 = undefined;
                        @memcpy(&sender_mac, pkt_buf[22..28]);
                        @memcpy(&sender_ip, pkt_buf[28..32]);
                        arpLearn(sender_ip, sender_mac);

                        if (ping_state == .arp_pending) {
                            if (arpLookup(ping_target_ip)) |mac| {
                                @memcpy(&ping_target_mac, &mac);
                                sendEchoRequest();
                            }
                        }
                    }
                    if (handleArp(&pkt_buf, len)) |reply| {
                        _ = nic_chan.send(reply);
                    }
                } else if (ethertype == 0x0800) {
                    handleEchoReply(&pkt_buf, len);
                    if (handleIcmp(&pkt_buf, len)) |reply| {
                        _ = nic_chan.send(reply);
                    }
                }
            }
        }

        checkPingTimeout();
        syscall.thread_yield();
    }
}
