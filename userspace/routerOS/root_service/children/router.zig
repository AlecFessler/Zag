const lib = @import("lib");
const std = @import("std");

const channel_mod = lib.channel;
const shm_protocol = lib.shm_protocol;
const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

var nic_chan: channel_mod.Channel = undefined;
var console_chan: ?channel_mod.Channel = null;
var router_mac: [6]u8 = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
var router_ip: [4]u8 = .{ 10, 0, 2, 15 };

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| { if (x != y) return false; }
    return true;
}

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

fn handleConsoleCommand(data: []const u8) void {
    var chan = &(console_chan orelse return);
    if (eql(data, "status")) {
        _ = chan.send("router: running, NIC channel active, IP 10.0.2.15");
    } else {
        _ = chan.send("router: unknown query");
    }
}

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
    if (nic_vm.val < 0) { syscall.write("router: NIC vm_reserve failed\n"); return; }
    if (syscall.shm_map(shm_handles[0], @intCast(nic_vm.val), 0) != 0) { syscall.write("router: NIC shm_map failed\n"); return; }

    const nic_header: *channel_mod.ChannelHeader = @ptrFromInt(nic_vm.val2);
    nic_chan = channel_mod.Channel.openAsSideB(nic_header) orelse {
        syscall.write("router: NIC channel open failed\n");
        return;
    };

    syscall.write("router: NIC data channel ready\n");

    var arp_req: [42]u8 = undefined;
    @memset(&arp_req, 0);
    @memset(arp_req[0..6], 0xFF);
    @memcpy(arp_req[6..12], &router_mac);
    arp_req[12] = 0x08;
    arp_req[13] = 0x06;
    arp_req[14] = 0x00; arp_req[15] = 0x01;
    arp_req[16] = 0x08; arp_req[17] = 0x00;
    arp_req[18] = 0x06; arp_req[19] = 0x04;
    arp_req[20] = 0x00; arp_req[21] = 0x01;
    @memcpy(arp_req[22..28], &router_mac);
    @memcpy(arp_req[28..32], &router_ip);
    @memset(arp_req[32..38], 0);
    arp_req[38] = 10; arp_req[39] = 0; arp_req[40] = 2; arp_req[41] = 2;

    _ = nic_chan.send(&arp_req);
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
                    if (handleArp(&pkt_buf, len)) |reply| {
                        _ = nic_chan.send(reply);
                    }
                } else if (ethertype == 0x0800) {
                    if (handleIcmp(&pkt_buf, len)) |reply| {
                        _ = nic_chan.send(reply);
                    }
                }
            }
        }

        syscall.thread_yield();
    }
}
