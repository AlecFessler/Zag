const lib = @import("lib");

const arp = @import("arp.zig");
const dhcp_client = @import("dhcp_client.zig");
const dhcp_server = @import("dhcp_server.zig");
const dma = @import("dma.zig");
const dns = @import("dns.zig");
const e1000 = @import("e1000.zig");
const firewall = @import("firewall.zig");
const frag = @import("frag.zig");
const iface_mod = @import("iface.zig");
const nat = @import("nat.zig");
const ping_mod = @import("ping.zig");
const udp_fwd = @import("udp_fwd.zig");
const util = @import("util.zig");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
pub const lan_subnet: [4]u8 = .{ 192, 168, 1, 0 };
pub const lan_mask: [4]u8 = .{ 255, 255, 255, 0 };
pub const lan_broadcast: [4]u8 = .{ 192, 168, 1, 255 };
const MAINTENANCE_INTERVAL_NS: u64 = 10_000_000_000;
pub const Interface = enum { wan, lan };
const Iface = iface_mod.Iface;

// ── Global state ────────────────────────────────────────────────────────
pub var wan_iface: Iface = undefined;
pub var lan_iface: Iface = undefined;
pub var has_lan: bool = false;
pub var console_chan: ?channel_mod.Channel = null;
pub var nfs_chan: ?channel_mod.Channel = null;
pub var ntp_chan: ?channel_mod.Channel = null;
pub var nat_table: [nat.TABLE_SIZE]nat.NatEntry = .{nat.empty} ** nat.TABLE_SIZE;
pub var next_nat_port: u16 = 10000;
pub var port_forwards: [firewall.PORT_FWD_SIZE]firewall.PortForward = [_]firewall.PortForward{firewall.empty_fwd} ** firewall.PORT_FWD_SIZE;
pub var firewall_rules: [firewall.RULES_SIZE]firewall.FirewallRule = [_]firewall.FirewallRule{firewall.empty_rule} ** firewall.RULES_SIZE;
pub var dns_relays: [dns.RELAY_SIZE]dns.DnsRelay = [_]dns.DnsRelay{dns.empty} ** dns.RELAY_SIZE;
pub var next_dns_id: u16 = 1;
pub var upstream_dns: [4]u8 = .{ 10, 0, 2, 1 };
pub var dhcp_leases: [dhcp_server.TABLE_SIZE]dhcp_server.DhcpLease = [_]dhcp_server.DhcpLease{dhcp_server.empty} ** dhcp_server.TABLE_SIZE;
pub var dhcp_next_ip: u8 = 100;
pub var dhcp_client_state: dhcp_client.DhcpClientState = .idle;
pub var dhcp_client_xid: u32 = 0x5A470001;
pub var dhcp_server_ip: [4]u8 = .{ 0, 0, 0, 0 };
pub var dhcp_offered_ip: [4]u8 = .{ 0, 0, 0, 0 };
pub var dhcp_client_start_ns: u64 = 0;
pub var wan_ip_static: bool = true;
pub var ping_state: ping_mod.PingState = .idle;
pub var ping_target_ip: [4]u8 = .{ 0, 0, 0, 0 };
pub var ping_target_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
pub var ping_iface: Interface = .wan;
pub var ping_seq: u16 = 0;
pub var ping_start_ns: u64 = 0;
pub var ping_count: u8 = 0;
pub var ping_received: u8 = 0;
pub var frag_table: [frag.TABLE_SIZE]frag.FragEntry = [_]frag.FragEntry{frag.empty} ** frag.TABLE_SIZE;
pub var udp_bindings: [udp_fwd.MAX_BINDINGS]udp_fwd.UdpBinding = [_]udp_fwd.UdpBinding{.{}} ** udp_fwd.MAX_BINDINGS;
pub var pending_udp: [udp_fwd.MAX_PENDING]udp_fwd.PendingPacket = [_]udp_fwd.PendingPacket{.{}} ** udp_fwd.MAX_PENDING;
var last_maintenance_ns: u64 = 0;

pub fn getIface(role: Interface) *Iface {
    return if (role == .wan) &wan_iface else &lan_iface;
}

pub fn isInLanSubnet(ip: [4]u8) bool {
    return (ip[0] & lan_mask[0]) == (lan_subnet[0] & lan_mask[0]) and
        (ip[1] & lan_mask[1]) == (lan_subnet[1] & lan_mask[1]) and
        (ip[2] & lan_mask[2]) == (lan_subnet[2] & lan_mask[2]) and
        (ip[3] & lan_mask[3]) == (lan_subnet[3] & lan_mask[3]);
}

fn mmioMap(device_handle: u64, size: u64) ?u64 {
    const aligned = ((size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .mmio = true }).bits();
    const vm = syscall.vm_reserve(0, aligned, vm_rights);
    if (vm.val < 0) return null;
    if (syscall.mmio_map(device_handle, @intCast(vm.val), 0) != 0) return null;
    return vm.val2;
}

const NicInfo = struct { handle: u64, mmio_size: u64, pci_bus: u8, pci_dev: u5, pci_func: u3 };

fn findNicDevices(perm_view_addr: u64) struct { wan: ?NicInfo, lan: ?NicInfo } {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var first: ?NicInfo = null;
    var second: ?NicInfo = null;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
            entry.deviceClass() == @intFromEnum(perms.DeviceClass.network) and
            entry.deviceType() == @intFromEnum(perms.DeviceType.mmio))
        {
            const info = NicInfo{ .handle = entry.handle, .mmio_size = entry.deviceSizeOrPortCount(), .pci_bus = entry.pciBus(), .pci_dev = entry.pciDev(), .pci_func = entry.pciFunc() };
            if (first == null) first = info else if (second == null) second = info;
        }
    }
    return .{ .wan = first, .lan = second };
}

fn handleIcmp(role: Interface, pkt: []u8, len: u32) ?[]u8 {
    if (len < 34 or pkt[23] != 1) return null;
    const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
    const icmp_start = 14 + ip_hdr_len;
    if (icmp_start + 8 > len or pkt[icmp_start] != 8) return null;
    const ifc = getIface(role);
    @memcpy(pkt[0..6], pkt[6..12]);
    @memcpy(pkt[6..12], &ifc.mac);
    var tmp: [4]u8 = undefined;
    @memcpy(&tmp, pkt[26..30]);
    @memcpy(pkt[26..30], pkt[30..34]);
    @memcpy(pkt[30..34], &tmp);
    pkt[icmp_start] = 0;
    pkt[icmp_start + 2] = 0;
    pkt[icmp_start + 3] = 0;
    const cs = util.computeChecksum(pkt[icmp_start..len]);
    pkt[icmp_start + 2] = @truncate(cs >> 8);
    pkt[icmp_start + 3] = @truncate(cs);
    pkt[24] = 0;
    pkt[25] = 0;
    const ip_cs = util.computeChecksum(pkt[14..][0..ip_hdr_len]);
    pkt[24] = @truncate(ip_cs >> 8);
    pkt[25] = @truncate(ip_cs);
    return pkt[0..len];
}

fn periodicMaintenance() void {
    const ts = util.now();
    if (ts -| last_maintenance_ns < MAINTENANCE_INTERVAL_NS) return;
    last_maintenance_ns = ts;
    arp.expire(&wan_iface.arp_table);
    if (has_lan) arp.expire(&lan_iface.arp_table);
    nat.expire();
    frag.expire(&frag_table);
    dhcp_client.tick();
}

pub const PacketAction = enum {
    consumed, // Packet fully handled, return RX buffer to hardware
    forward_wan, // Forward to WAN (zero-copy: headers modified in-place)
    forward_lan, // Forward to LAN (zero-copy: headers modified in-place)
};

/// Process a received packet. Returns whether it should be forwarded zero-copy.
/// For forwarded packets, headers are modified IN-PLACE in the DMA buffer.
fn processPacket(role: Interface, pkt: []u8, len: u32) PacketAction {
    if (len < 14) return .consumed;
    const ifc = getIface(role);
    const ethertype = util.readU16Be(pkt[12..14]);

    if (ethertype == 0x0806) {
        // ARP: learn, reply, never forwarded
        if (len >= 42) {
            var sender_mac: [6]u8 = undefined;
            var sender_ip: [4]u8 = undefined;
            @memcpy(&sender_mac, pkt[22..28]);
            @memcpy(&sender_ip, pkt[28..32]);
            arp.learn(&ifc.arp_table, sender_ip, sender_mac);
            udp_fwd.drainPending();
            if (ping_state == .arp_pending and ping_iface == role) {
                if (arp.lookup(&ifc.arp_table, ping_target_ip)) |mac| {
                    @memcpy(&ping_target_mac, &mac);
                    ping_mod.sendEchoRequest();
                }
            }
        }
        if (arp.handle(role, pkt, len)) |reply| {
            _ = ifc.txSendLocal(reply);
        }
        return .consumed;
    }

    if (ethertype != 0x0800 or len < 34) return .consumed;

    // IPv4 packet
    var dst_ip: [4]u8 = undefined;
    @memcpy(&dst_ip, pkt[30..34]);
    const my_ip = &ifc.ip;
    const is_for_me = util.eql(&dst_ip, my_ip) or util.eql(&dst_ip, &lan_broadcast) or
        (dst_ip[0] == 255 and dst_ip[1] == 255 and dst_ip[2] == 255 and dst_ip[3] == 255);

    if (is_for_me) {
        // Packet addressed to us — handle locally, never zero-copy forward
        if (pkt[23] == 17) {
            const ip_hdr_len: u16 = (@as(u16, pkt[14] & 0x0F)) * 4;
            const udp_start = 14 + ip_hdr_len;
            if (udp_start + 4 <= len) {
                const udp_dst = util.readU16Be(pkt[udp_start + 2 ..][0..2]);
                if (udp_dst == 68 and role == .wan) { dhcp_client.handleResponse(pkt, len); return .consumed; }
                if (udp_dst == 67 and role == .lan) { dhcp_server.handle(pkt, len); return .consumed; }
                if (udp_dst == dns.DNS_PORT and role == .lan) { dns.handleFromLan(pkt, len); return .consumed; }
                if (udp_start + 8 <= len) {
                    var src_ip_udp: [4]u8 = undefined;
                    @memcpy(&src_ip_udp, pkt[26..30]);
                    const udp_src = util.readU16Be(pkt[udp_start..][0..2]);
                    if (udp_fwd.forwardToApp(src_ip_udp, udp_src, udp_dst, pkt[udp_start + 8 .. len])) return .consumed;
                }
            }
        }
        ping_mod.handleEchoReply(pkt, len);
        if (handleIcmp(role, pkt, len)) |reply| {
            _ = ifc.txSendLocal(reply);
        } else if (role == .wan and has_lan) {
            if (nat.forwardWanToLan(pkt, len)) return .forward_lan;
        }
        return .consumed;
    }

    // Packet not for us — forward to the other interface
    if (role == .lan and has_lan) {
        if (nat.forwardLanToWan(pkt, len)) return .forward_wan;
    }

    return .consumed;
}

fn detectAppChannels(view: *const [MAX_PERMS]pv.UserViewEntry, mapped_handles: *[8]u64, mapped_count: *u32) void {
    if (console_chan != null and nfs_chan != null and ntp_chan != null) return;
    for (view) |*entry| {
        if (entry.entry_type != pv.ENTRY_TYPE_SHARED_MEMORY or entry.field0 <= shm_protocol.COMMAND_SHM_SIZE) continue;
        var is_known = false;
        for (mapped_handles[0..mapped_count.*]) |kh| { if (kh == entry.handle) { is_known = true; break; } }
        if (is_known) continue;
        const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
        const vm = syscall.vm_reserve(0, entry.field0, vm_rights);
        if (vm.val < 0) continue;
        if (syscall.shm_map(entry.handle, @intCast(vm.val), 0) != 0) continue;
        const hdr: *channel_mod.ChannelHeader = @ptrFromInt(vm.val2);
        if (mapped_count.* < mapped_handles.len) { mapped_handles[mapped_count.*] = entry.handle; mapped_count.* += 1; }
        var ch = channel_mod.Channel.openAsSideA(hdr) orelse continue;
        var id_buf: [4]u8 = undefined;
        var attempts: u32 = 0;
        while (attempts < 100) : (attempts += 1) {
            if (ch.recv(&id_buf)) |id_len| {
                if (id_len >= 1) {
                    if (id_buf[0] == shm_protocol.ServiceId.NFS_CLIENT and nfs_chan == null) { nfs_chan = ch; syscall.write("router: NFS connected\n"); }
                    else if (id_buf[0] == shm_protocol.ServiceId.NTP_CLIENT and ntp_chan == null) { ntp_chan = ch; syscall.write("router: NTP connected\n"); }
                    else if (id_buf[0] == shm_protocol.ServiceId.CONSOLE and console_chan == null) { console_chan = ch; syscall.write("router: console connected\n"); }
                }
                break;
            }
            syscall.thread_yield();
        }
        break;
    }
}

pub fn main(perm_view_addr: u64) void {
    syscall.write("router: started\n");
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse { syscall.write("router: no cmd ch\n"); return; };
    _ = cmd;
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const nics = findNicDevices(perm_view_addr);
    const wan_nic = nics.wan orelse { syscall.write("router: no WAN\n"); return; };

    const wan_mmio_size = if (wan_nic.mmio_size == 0) syscall.PAGE4K else wan_nic.mmio_size;
    const wan_mmio = mmioMap(wan_nic.handle, wan_mmio_size) orelse { syscall.write("router: WAN MMIO fail\n"); return; };

    // DMA setup (WAN only — LAN uses same SHM when dual-NIC)
    var region = dma.setupSingle(wan_nic.handle) orelse { syscall.write("router: DMA fail\n"); return; };
    syscall.write("router: DMA ready\n");

    // Initialize wan_iface field-by-field to avoid large stack temporaries
    wan_iface.role = .wan;
    wan_iface.mmio_base = wan_mmio;
    wan_iface.mac = .{ 0, 0, 0, 0, 0, 0 };
    wan_iface.ip = .{ 10, 0, 2, 15 };
    wan_iface.dma_base = region.wan_dma_base;
    wan_iface.dma_region = &region;
    wan_iface.rx_descs = region.wanRxDescs();
    wan_iface.tx_descs = region.wanTxDescs();
    wan_iface.rx_tail = e1000.NUM_RX_DESC - 1;
    wan_iface.tx_tail = 0;
    wan_iface.rx_buf_state = .{.free} ** e1000.NUM_RX_DESC;
    wan_iface.rx_buf_tx_idx = .{0} ** e1000.NUM_RX_DESC;
    wan_iface.arp_table = .{arp.empty} ** arp.TABLE_SIZE;
    wan_iface.stats = .{};
    wan_iface.pending_tx_flag = 0;

    if (!e1000.init(.{
        .mmio_base = wan_mmio,
        .rx_descs_dma = region.wanDma(dma.WAN_RX_DESCS_OFF),
        .tx_descs_dma = region.wanDma(dma.WAN_TX_DESCS_OFF),
        .rx_bufs_dma_base = region.wanDma(dma.WAN_RX_BUFS_OFF),
        .tx_bufs_dma_base = region.wanDma(dma.WAN_TX_BUFS_OFF),
        .rx_descs = region.wanRxDescs(),
        .tx_descs = region.wanTxDescs(),
    })) { syscall.write("router: e1000 init fail\n"); return; }

    _ = syscall.pci_enable_bus_master(wan_nic.handle);
    wan_iface.mac = e1000.readMac(wan_mmio);
    syscall.write("router: WAN ready\n");

    arp.sendRequest(.wan, .{ 10, 0, 2, 1 });

    var mapped_handles: [8]u64 = .{0} ** 8;
    var mapped_count: u32 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and entry.field0 <= shm_protocol.COMMAND_SHM_SIZE and mapped_count < mapped_handles.len) {
            mapped_handles[mapped_count] = entry.handle;
            mapped_count += 1;
        }
    }

    // Spawn LAN poll thread if dual-NIC
    if (has_lan) {
        _ = syscall.thread_create(&lanPollThread, 0, 4);
        syscall.write("router: LAN thread spawned\n");
    }

    // WAN thread (runs on the initial/main thread):
    // Polls WAN RX, handles routing, console/NFS channels, maintenance.
    syscall.write("router: WAN thread running\n");
    var loop_n: u32 = 0;
    while (true) {
        loop_n +%= 1;

        // Channel detection + handling (cheap: one atomic read per channel)
        if (loop_n % 500 == 0) detectAppChannels(view, &mapped_handles, &mapped_count);
        if (console_chan) |*chan| {
            var cmd_buf: [256]u8 = undefined;
            if (chan.recv(&cmd_buf)) |cmd_len| {
                handleConsoleCommand(chan, cmd_buf[0..cmd_len]);
            }
        }
        if (nfs_chan) |*chan| {
            var nfs_buf: [2048]u8 = undefined;
            if (chan.recv(&nfs_buf)) |nfs_len| { udp_fwd.handleAppMessage(nfs_buf[0..nfs_len], .nfs); }
        }
        if (ntp_chan) |*chan| {
            var ntp_buf: [256]u8 = undefined;
            if (chan.recv(&ntp_buf)) |ntp_len| { udp_fwd.handleAppMessage(ntp_buf[0..ntp_len], .ntp); }
        }

        // WAN poll + zero-copy forwarding
        pollOnce(&wan_iface, &lan_iface, .wan);

        // Periodic tasks (only on WAN thread)
        ping_mod.checkTimeout();
        periodicMaintenance();
        syscall.thread_yield();
    }
}

// ── Console command dispatch ─────────────────────────────────────────────

fn handleConsoleCommand(chan: *channel_mod.Channel, cmd: []const u8) void {
    if (cmd.len == 0) return;
    var resp: [512]u8 = undefined;

    if (util.eql(cmd, "status")) {
        var p: usize = 0;
        p = util.appendStr(&resp, p, "WAN: ");
        p = util.appendIp(&resp, p, wan_iface.ip);
        p = util.appendStr(&resp, p, " mac=");
        p = util.appendMac(&resp, p, wan_iface.mac);
        if (has_lan) {
            p = util.appendStr(&resp, p, "\nLAN: ");
            p = util.appendIp(&resp, p, lan_iface.ip);
            p = util.appendStr(&resp, p, " mac=");
            p = util.appendMac(&resp, p, lan_iface.mac);
        }
        _ = chan.send(resp[0..p]);
    } else if (util.eql(cmd, "ifstat")) {
        var p: usize = 0;
        p = util.appendStr(&resp, p, "WAN rx=");
        p = util.appendDec(&resp, p, wan_iface.stats.rx_packets);
        p = util.appendStr(&resp, p, " tx=");
        p = util.appendDec(&resp, p, wan_iface.stats.tx_packets);
        p = util.appendStr(&resp, p, " drop=");
        p = util.appendDec(&resp, p, wan_iface.stats.rx_dropped);
        if (has_lan) {
            p = util.appendStr(&resp, p, "\nLAN rx=");
            p = util.appendDec(&resp, p, lan_iface.stats.rx_packets);
            p = util.appendStr(&resp, p, " tx=");
            p = util.appendDec(&resp, p, lan_iface.stats.tx_packets);
            p = util.appendStr(&resp, p, " drop=");
            p = util.appendDec(&resp, p, lan_iface.stats.rx_dropped);
        }
        _ = chan.send(resp[0..p]);
    } else if (util.eql(cmd, "arp")) {
        sendArpTable(chan, "WAN", &wan_iface.arp_table);
        if (has_lan) sendArpTable(chan, "LAN", &lan_iface.arp_table);
        _ = chan.send("---");
    } else if (util.eql(cmd, "nat")) {
        var count: u32 = 0;
        for (&nat_table) |*e| {
            if (@atomicLoad(u8, &e.state, .acquire) != 1) continue; // 1 = active
            var p: usize = 0;
            const proto_str: []const u8 = if (e.protocol == 6) "tcp" else if (e.protocol == 17) "udp" else "icmp";
            p = util.appendStr(&resp, p, proto_str);
            p = util.appendStr(&resp, p, " ");
            p = util.appendIp(&resp, p, e.lan_ip);
            p = util.appendStr(&resp, p, ":");
            p = util.appendDec(&resp, p, e.lan_port);
            p = util.appendStr(&resp, p, " -> :");
            p = util.appendDec(&resp, p, e.wan_port);
            p = util.appendStr(&resp, p, " -> ");
            p = util.appendIp(&resp, p, e.dst_ip);
            p = util.appendStr(&resp, p, ":");
            p = util.appendDec(&resp, p, e.dst_port);
            _ = chan.send(resp[0..p]);
            count += 1;
        }
        if (count == 0) _ = chan.send("(empty)");
        _ = chan.send("---");
    } else if (util.eql(cmd, "leases")) {
        var count: u32 = 0;
        for (&dhcp_leases) |*l| {
            if (!l.valid) continue;
            var p: usize = 0;
            p = util.appendIp(&resp, p, l.ip);
            p = util.appendStr(&resp, p, " ");
            p = util.appendMac(&resp, p, l.mac);
            _ = chan.send(resp[0..p]);
            count += 1;
        }
        if (count == 0) _ = chan.send("(empty)");
        _ = chan.send("---");
    } else if (util.eql(cmd, "rules")) {
        var count: u32 = 0;
        for (&firewall_rules) |*r| {
            if (!r.valid) continue;
            var p: usize = 0;
            const action_str: []const u8 = if (r.action == .block) "block" else "allow";
            p = util.appendStr(&resp, p, action_str);
            p = util.appendStr(&resp, p, " ");
            p = util.appendIp(&resp, p, r.src_ip);
            if (r.protocol != 0) {
                p = util.appendStr(&resp, p, " proto=");
                p = util.appendDec(&resp, p, r.protocol);
            }
            if (r.dst_port != 0) {
                p = util.appendStr(&resp, p, " port=");
                p = util.appendDec(&resp, p, r.dst_port);
            }
            _ = chan.send(resp[0..p]);
            count += 1;
        }
        for (&port_forwards) |*f| {
            if (!f.valid) continue;
            var p: usize = 0;
            const proto_str: []const u8 = if (f.protocol == .tcp) "tcp" else "udp";
            p = util.appendStr(&resp, p, "forward ");
            p = util.appendStr(&resp, p, proto_str);
            p = util.appendStr(&resp, p, " :");
            p = util.appendDec(&resp, p, f.wan_port);
            p = util.appendStr(&resp, p, " -> ");
            p = util.appendIp(&resp, p, f.lan_ip);
            p = util.appendStr(&resp, p, ":");
            p = util.appendDec(&resp, p, f.lan_port);
            _ = chan.send(resp[0..p]);
            count += 1;
        }
        if (count == 0) _ = chan.send("(empty)");
        _ = chan.send("---");
    } else if (util.startsWith(cmd, "ping ")) {
        const ip = util.parseIp(cmd[5..]) orelse {
            _ = chan.send("invalid IP");
            return;
        };
        ping_target_ip = ip;
        ping_seq = 0;
        ping_count = 0;
        ping_received = 0;
        ping_iface = if (isInLanSubnet(ip)) .lan else .wan;
        const ifc = getIface(ping_iface);
        if (arp.lookup(&ifc.arp_table, ip)) |mac| {
            @memcpy(&ping_target_mac, &mac);
            ping_mod.sendEchoRequest();
        } else {
            ping_state = .arp_pending;
            ping_start_ns = util.now();
            arp.sendRequest(ping_iface, ip);
        }
    } else if (util.startsWith(cmd, "block ")) {
        const ip = util.parseIp(cmd[6..]) orelse {
            _ = chan.send("invalid IP");
            return;
        };
        for (&firewall_rules) |*r| {
            if (!r.valid) {
                r.* = .{ .valid = true, .action = .block, .src_ip = ip, .src_mask = .{ 255, 255, 255, 255 }, .protocol = 0, .dst_port = 0 };
                _ = chan.send("OK");
                return;
            }
        }
        _ = chan.send("firewall table full");
    } else if (util.startsWith(cmd, "allow ")) {
        const ip = util.parseIp(cmd[6..]) orelse {
            _ = chan.send("invalid IP");
            return;
        };
        for (&firewall_rules) |*r| {
            if (r.valid and r.action == .block and util.eql(&r.src_ip, &ip)) {
                r.valid = false;
                _ = chan.send("OK");
                return;
            }
        }
        _ = chan.send("rule not found");
    } else if (util.startsWith(cmd, "forward ")) {
        // forward tcp|udp <wport> <lip> <lport>
        const args = cmd[8..];
        var proto: util.Protocol = .tcp;
        var rest: []const u8 = args;
        if (util.startsWith(args, "tcp ")) {
            rest = args[4..];
        } else if (util.startsWith(args, "udp ")) {
            proto = .udp;
            rest = args[4..];
        } else {
            _ = chan.send("usage: forward tcp|udp <wport> <lip> <lport>");
            return;
        }
        const parsed = util.parsePortIpPort(rest) orelse {
            _ = chan.send("usage: forward tcp|udp <wport> <lip> <lport>");
            return;
        };
        for (&port_forwards) |*f| {
            if (!f.valid) {
                f.* = .{ .valid = true, .protocol = proto, .wan_port = parsed.port1, .lan_ip = parsed.ip, .lan_port = parsed.port2 };
                _ = chan.send("OK");
                return;
            }
        }
        _ = chan.send("port forward table full");
    } else if (util.startsWith(cmd, "dns ")) {
        const ip = util.parseIp(cmd[4..]) orelse {
            _ = chan.send("invalid IP");
            return;
        };
        upstream_dns = ip;
        _ = chan.send("OK");
    } else if (util.eql(cmd, "dhcp-client")) {
        var p: usize = 0;
        const state_str: []const u8 = switch (dhcp_client_state) {
            .idle => "idle",
            .discovering => "discovering",
            .requesting => "requesting",
            .bound => "bound",
        };
        p = util.appendStr(&resp, p, "DHCP client: ");
        p = util.appendStr(&resp, p, state_str);
        if (dhcp_client_state == .idle) {
            dhcp_client.sendDiscover();
            dhcp_client_state = .discovering;
            dhcp_client_start_ns = util.now();
            p = util.appendStr(&resp, p, " -> discovering");
        }
        _ = chan.send(resp[0..p]);
    } else {
        _ = chan.send("unknown router command");
    }
}

fn sendArpTable(chan: *channel_mod.Channel, label: []const u8, table: *const [arp.TABLE_SIZE]arp.ArpEntry) void {
    var resp: [256]u8 = undefined;
    var count: u32 = 0;
    for (table) |*e| {
        if (!e.valid) continue;
        var p: usize = 0;
        p = util.appendStr(&resp, p, label);
        p = util.appendStr(&resp, p, " ");
        p = util.appendIp(&resp, p, e.ip);
        p = util.appendStr(&resp, p, " ");
        p = util.appendMac(&resp, p, e.mac);
        _ = chan.send(resp[0..p]);
        count += 1;
    }
    if (count == 0) {
        var p: usize = 0;
        p = util.appendStr(&resp, p, label);
        p = util.appendStr(&resp, p, " (empty)");
        _ = chan.send(resp[0..p]);
    }
}

// ── Poll thread ─────────────────────────────────────────────────────────

/// Poll one interface: receive a packet, process it, forward zero-copy if needed.
fn pollOnce(self_iface: *Iface, other_iface: *Iface, role: Interface) void {
    // Drain any pending TX from the main thread (lock-free)
    self_iface.drainPendingTx();

    // Reclaim any RX buffers that were lent to the other NIC's TX
    if (has_lan) self_iface.reclaimTxPending(other_iface);

    _ = e1000.readReg(self_iface.mmio_base, e1000.REG_ICR);
    const rx = self_iface.rxPoll() orelse return;
    const buf_ptr = self_iface.rxBufPtr(rx.index);
    const pkt = buf_ptr[0..rx.len];

    const action = processPacket(role, pkt, rx.len);
    switch (action) {
        .consumed => self_iface.rxReturn(rx.index),
        .forward_lan => {
            if (has_lan) {
                const dma_addr = self_iface.rxBufDmaForDevice(rx.index, other_iface);
                if (other_iface.txSendZeroCopy(dma_addr, rx.len)) {
                    self_iface.rx_buf_state[rx.index] = .tx_pending;
                    self_iface.rx_buf_tx_idx[rx.index] = @truncate(other_iface.tx_tail -% 1);
                } else {
                    self_iface.rxReturn(rx.index);
                }
            } else {
                self_iface.rxReturn(rx.index);
            }
        },
        .forward_wan => {
            const dma_addr = self_iface.rxBufDmaForDevice(rx.index, other_iface);
            if (other_iface.txSendZeroCopy(dma_addr, rx.len)) {
                self_iface.rx_buf_state[rx.index] = .tx_pending;
                self_iface.rx_buf_tx_idx[rx.index] = @truncate(other_iface.tx_tail -% 1);
            } else {
                self_iface.rxReturn(rx.index);
            }
        },
    }
}

/// LAN poll thread entry point. Polls LAN NIC, forwards to WAN via zero-copy.
fn lanPollThread() void {
    syscall.write("router: LAN poll thread started\n");
    while (true) {
        pollOnce(&lan_iface, &wan_iface, .lan);
        syscall.thread_yield();
    }
}
