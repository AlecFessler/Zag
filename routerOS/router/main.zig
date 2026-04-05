const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const dhcp_client = router.protocols.dhcp_client;
const dhcp_server = router.protocols.dhcp_server;
const dhcpv6_client = router.protocols.ipv6.dhcp_client;
const dma = router.hal.dma;
const dns = router.protocols.dns;
const nic = router.hal.nic;
const firewall = router.protocols.ipv4.firewall;
const firewall6 = router.protocols.ipv6.firewall;
const frag = router.protocols.frag;
const h = router.hal.headers;
const iface_mod = router.hal.iface;
const icmpv6 = router.protocols.ipv6.icmp;
const log = router.log;
const nat = router.protocols.ipv4.nat;
const ndp = router.protocols.ipv6.ndp;
const pcp = router.protocols.pcp;
const ping_mod = router.protocols.ipv4.icmp;
const slaac = router.protocols.ipv6.slaac;
const tcp_stack = router.protocols.tcp_stack;
const udp_fwd = router.protocols.udp_fwd;
const upnp = router.protocols.upnp;
const util = router.util;

const Arena = lib.arena.Arena;
const channel = lib.channel;
const http_proto = lib.http;
const ntp_proto = lib.ntp;
const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;
const text_cmd = lib.text_command;

const Channel = channel.Channel;
const HttpServer = http_proto.Server;

const MAX_PERMS = 128;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
pub const lan_subnet: [4]u8 = .{ 10, 1, 1, 0 };
pub const lan_mask: [4]u8 = .{ 255, 255, 255, 0 };
pub const lan_broadcast: [4]u8 = .{ 10, 1, 1, 255 };
const MAINTENANCE_INTERVAL_NS: u64 = 10_000_000_000;
pub const Interface = enum { wan, lan };
const Iface = iface_mod.Iface;

// ── Global state ────────────────────────────────────────────────────────
pub var wan_iface: Iface = undefined;
pub var lan_iface: Iface = undefined;
pub var has_lan: bool = false;
pub var console_chan: ?*Channel = null;
pub var nfs_chan: ?*Channel = null;
pub var ntp_chan: ?*Channel = null;
pub var http_chan: ?*Channel = null;
pub var nat_table: [nat.TABLE_SIZE]nat.NatEntry = .{nat.empty} ** nat.TABLE_SIZE;
pub var next_nat_port: u16 = 10000;
pub var port_forwards: [firewall.PORT_FWD_SIZE]firewall.PortForward = [_]firewall.PortForward{firewall.empty_fwd} ** firewall.PORT_FWD_SIZE;
pub var firewall_rules: [firewall.RULES_SIZE]firewall.FirewallRule = [_]firewall.FirewallRule{firewall.empty_rule} ** firewall.RULES_SIZE;
pub var dns_relays: [dns.RELAY_SIZE]dns.DnsRelay = [_]dns.DnsRelay{dns.empty} ** dns.RELAY_SIZE;
pub var dns_cache: [dns.CACHE_SIZE]dns.DnsCacheEntry = .{dns.empty_cache} ** dns.CACHE_SIZE;
pub var next_dns_id: u16 = 1;
pub var upstream_dns: [4]u8 = .{ 10, 0, 2, 1 };
pub var tz_offset_minutes: i16 = -360; // CST (UTC-6) default
pub var wan_gateway: [4]u8 = .{ 10, 0, 2, 1 };
pub var dhcp_leases: [dhcp_server.TABLE_SIZE]dhcp_server.DhcpLease = [_]dhcp_server.DhcpLease{dhcp_server.empty} ** dhcp_server.TABLE_SIZE;
pub var dhcp_static_leases: [dhcp_server.STATIC_TABLE_SIZE]dhcp_server.StaticLease = [_]dhcp_server.StaticLease{dhcp_server.empty_static} ** dhcp_server.STATIC_TABLE_SIZE;
pub var dhcp_next_ip: u8 = 100;
pub var dhcp_client_state: dhcp_client.DhcpClientState = .idle;
pub var dhcp_client_xid: u32 = 0x5A470001;
pub var dhcp_server_ip: [4]u8 = .{ 0, 0, 0, 0 };
pub var dhcp_offered_ip: [4]u8 = .{ 0, 0, 0, 0 };
pub var dhcp_client_start_ns: u64 = 0;
pub var dhcp_client_bound_ns: u64 = 0;
pub var dhcp_client_lease_time_ns: u64 = 86400_000_000_000; // default 24h
pub var wan_ip_static: bool = true;
pub var ping_state: ping_mod.PingState = .idle;
pub var ping_target_ip: [4]u8 = .{ 0, 0, 0, 0 };
pub var ping_target_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
pub var ping_iface: Interface = .wan;
pub var ping_seq: u16 = 0;
pub var ping_start_ns: u64 = 0;
pub var ping_count: u8 = 0;
pub var ping_received: u8 = 0;
pub var traceroute_state: ping_mod.TracerouteState = .idle;
pub var traceroute_target_ip: [4]u8 = .{ 0, 0, 0, 0 };
pub var traceroute_target_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
pub var traceroute_iface: Interface = .wan;
pub var traceroute_ttl: u8 = 1;
pub var traceroute_start_ns: u64 = 0;
pub var traceroute_max_hops: u8 = 30;
pub var frag_table: [frag.TABLE_SIZE]frag.FragEntry = [_]frag.FragEntry{frag.empty} ** frag.TABLE_SIZE;
pub var udp_bindings: [udp_fwd.MAX_BINDINGS]udp_fwd.UdpBinding = [_]udp_fwd.UdpBinding{.{}} ** udp_fwd.MAX_BINDINGS;
pub var pending_udp: [udp_fwd.MAX_PENDING]udp_fwd.PendingPacket = [_]udp_fwd.PendingPacket{.{}} ** udp_fwd.MAX_PENDING;
var last_maintenance_ns: u64 = 0;
var perm_view: ?*const [MAX_PERMS]pv.UserViewEntry = null;
var perm_view_addr_global: u64 = 0;



// ── IPv6 global state ────────────────────────────────────────────────────
pub var wan_ndp_table: [ndp.TABLE_SIZE]ndp.NdpEntry = .{ndp.empty} ** ndp.TABLE_SIZE;
pub var lan_ndp_table: [ndp.TABLE_SIZE]ndp.NdpEntry = .{ndp.empty} ** ndp.TABLE_SIZE;
pub var conn6_table: [firewall6.CONN_TABLE_SIZE]firewall6.ConnEntry = .{firewall6.empty} ** firewall6.CONN_TABLE_SIZE;
pub var dhcpv6_state: dhcpv6_client.Dhcpv6State = .idle;
pub var dhcpv6_xid: u32 = 0x5A4701;
pub var dhcpv6_server_duid: [128]u8 = .{0} ** 128;
pub var dhcpv6_server_duid_len: u8 = 0;
pub var dhcpv6_start_ns: u64 = 0;
pub var delegated_prefix: dhcpv6_client.DelegatedPrefix = dhcpv6_client.empty_prefix;
pub var last_ra_ns: u64 = 0;
pub var wan_gateway_ip6: [16]u8 = .{0} ** 16;

pub fn getIface(role: Interface) *Iface {
    return if (role == .wan) &wan_iface else &lan_iface;
}

pub fn isInLanSubnet(ip: [4]u8) bool {
    return (ip[0] & lan_mask[0]) == (lan_subnet[0] & lan_mask[0]) and
        (ip[1] & lan_mask[1]) == (lan_subnet[1] & lan_mask[1]) and
        (ip[2] & lan_mask[2]) == (lan_subnet[2] & lan_mask[2]) and
        (ip[3] & lan_mask[3]) == (lan_subnet[3] & lan_mask[3]);
}

fn readU64Be(b: *const [8]u8) u64 {
    return @as(u64, b[0]) << 56 | @as(u64, b[1]) << 48 |
        @as(u64, b[2]) << 40 | @as(u64, b[3]) << 32 |
        @as(u64, b[4]) << 24 | @as(u64, b[5]) << 16 |
        @as(u64, b[6]) << 8 | @as(u64, b[7]);
}

fn mmioMap(device_handle: u64, size: u64) ?u64 {
    const aligned = ((size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .mmio = true }).bits();
    const vm = syscall.vm_reserve(0, aligned, vm_rights) catch return null;
    syscall.mmio_map(device_handle, vm.handle, 0) catch return null;
    return vm.addr;
}

const NicInfo = struct { handle: u64, mmio_size: u64, pci_bus: u8, pci_dev: u5, pci_func: u3 };

/// Intel X550 vendor:device ID
const X550_VENDOR: u16 = 0x8086;
const X550_DEVICE: u16 = 0x1563;

fn findNicDevices(perm_view_addr: u64) struct { wan: ?NicInfo, lan: ?NicInfo } {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var first: ?NicInfo = null;
    var second: ?NicInfo = null;

    // First pass: look for Intel X550 NICs specifically
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
            entry.deviceClass() == @intFromEnum(perms.DeviceClass.network) and
            entry.deviceType() == @intFromEnum(perms.DeviceType.mmio) and
            entry.pciVendor() == X550_VENDOR and entry.pciDevice() == X550_DEVICE)
        {
            const info = NicInfo{ .handle = entry.handle, .mmio_size = entry.deviceSizeOrPortCount(), .pci_bus = entry.pciBus(), .pci_dev = entry.pciDev(), .pci_func = entry.pciFunc() };
            if (first == null) first = info else if (second == null) second = info;
        }
    }

    // Fallback: if no X550 found, take any MMIO network device (e.g. e1000 in QEMU)
    if (first == null) {
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and
                entry.deviceClass() == @intFromEnum(perms.DeviceClass.network) and
                entry.deviceType() == @intFromEnum(perms.DeviceType.mmio))
            {
                const info = NicInfo{ .handle = entry.handle, .mmio_size = entry.deviceSizeOrPortCount(), .pci_bus = entry.pciBus(), .pci_dev = entry.pciDev(), .pci_func = entry.pciFunc() };
                if (first == null) first = info else if (second == null) second = info;
            }
        }
    }

    return .{ .wan = first, .lan = second };
}

pub fn handleIcmp(role: Interface, pkt: []u8, len: u32) ?[]u8 {
    const ip = h.Ipv4Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return null;
    if (len < h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN or ip.protocol != h.Ipv4Header.PROTO_ICMP) return null;
    const ip_hdr_len = ip.headerLen();
    const icmp_start = h.EthernetHeader.LEN + ip_hdr_len;
    if (icmp_start + h.IcmpHeader.LEN > len) return null;
    const icmp = h.IcmpHeader.parseMut(pkt[icmp_start..]) orelse return null;
    if (icmp.icmp_type != h.IcmpHeader.TYPE_ECHO_REQUEST) return null;
    const ifc = getIface(role);
    @memcpy(pkt[0..6], pkt[6..12]);
    @memcpy(pkt[6..12], &ifc.mac);
    var tmp: [4]u8 = undefined;
    @memcpy(&tmp, &ip.src_ip);
    ip.src_ip = ip.dst_ip;
    ip.dst_ip = tmp;
    icmp.icmp_type = h.IcmpHeader.TYPE_ECHO_REPLY;
    icmp.computeAndSetChecksum(pkt[icmp_start..len]);
    ip.computeAndSetChecksum(pkt);
    return pkt[0..len];
}

/// Clamp TCP MSS option on SYN/SYN-ACK packets to 1460 (1500 MTU - 40).
/// Only modifies packets with SYN flag set and MSS option present.
pub fn clampMss(pkt: []u8, len: u32) void {
    const ip = h.Ipv4Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const tcp_start = h.EthernetHeader.LEN + ip_hdr_len;
    if (tcp_start + h.TcpHeader.MIN_LEN > len) return;

    const tcp = h.TcpHeader.parseMut(pkt[tcp_start..]) orelse return;
    if (tcp.flags & h.TcpHeader.SYN == 0) return; // Not SYN

    const tcp_data_offset = tcp.dataOffset();
    if (tcp_data_offset <= h.TcpHeader.MIN_LEN) return; // No options

    // Walk TCP options looking for MSS (kind=2, len=4)
    var i: usize = tcp_start + 20;
    const opts_end = tcp_start + tcp_data_offset;
    while (i + 1 < opts_end and i + 1 < len) {
        const kind = pkt[i];
        if (kind == 0) break; // End of options
        if (kind == 1) { // NOP
            i += 1;
            continue;
        }
        const opt_len = pkt[i + 1];
        if (opt_len < 2) break;
        if (kind == 2 and opt_len == 4 and i + 3 < len) {
            const mss = util.readU16Be(pkt[i + 2 ..][0..2]);
            if (mss > 1460) {
                util.writeU16Be(pkt[i + 2 ..][0..2], 1460);
                // Recompute TCP checksum
                util.recomputeTransportChecksum(pkt, tcp_start, len, 6);
            }
            return;
        }
        i += opt_len;
    }
}

/// Send an ICMP error message (TTL exceeded, dest unreachable, etc.)
/// back to the source of the original packet.
pub fn sendIcmpError(role: Interface, orig_pkt: []const u8, orig_len: u32, icmp_type: u8, icmp_code: u8) void {
    if (orig_len < h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN) return;
    const ifc = getIface(role);

    // ICMP error payload: original IP header + first 8 bytes of original payload
    const orig_ip = h.Ipv4Header.parse(orig_pkt[h.EthernetHeader.LEN..]) orelse return;
    const orig_ihl = orig_ip.headerLen();
    const payload_start: usize = h.EthernetHeader.LEN; // start of original IP header
    const payload_end = @min(payload_start + orig_ihl + 8, orig_len);
    const payload_len: u16 = @intCast(payload_end - payload_start);

    // Build response: 14 eth + 20 IP + 8 ICMP header + payload
    const icmp_total: u16 = @as(u16, h.IcmpHeader.LEN) + payload_len;
    const ip_total: u16 = @as(u16, h.Ipv4Header.MIN_LEN) + icmp_total;
    const frame_len: usize = @max(@as(usize, @as(u16, h.EthernetHeader.LEN) + ip_total), 60);

    var pkt: [600]u8 = undefined;
    @memset(pkt[0..frame_len], 0);

    // Ethernet: reply to source
    @memcpy(pkt[0..6], orig_pkt[6..12]); // dst = original src MAC
    @memcpy(pkt[6..12], &ifc.mac);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // IP header
    pkt[14] = 0x45; // version 4, IHL 5
    util.writeU16Be(pkt[16..18], ip_total);
    const ip = h.Ipv4Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return;
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_ICMP;
    ip.src_ip = ifc.ip;
    ip.dst_ip = orig_ip.src_ip;

    // IP checksum
    ip.computeAndSetChecksum(&pkt);

    // ICMP header
    const icmp_start: usize = h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN;
    const icmp_hdr = h.IcmpHeader.parseMut(pkt[icmp_start..]) orelse return;
    icmp_hdr.icmp_type = icmp_type;
    icmp_hdr.code = icmp_code;
    // bytes 4-7 are unused (zero) for TTL exceeded and most unreachable codes

    // ICMP payload: original IP header + 8 bytes
    @memcpy(pkt[icmp_start + h.IcmpHeader.LEN ..][0..payload_len], orig_pkt[payload_start..payload_end]);

    // ICMP checksum
    icmp_hdr.computeAndSetChecksum(pkt[icmp_start..][0..icmp_total]);

    _ = ifc.txSendLocal(pkt[0..frame_len], .dataplane);
}

pub fn periodicMaintenance() void {
    const ts = util.now();
    if (ts -| last_maintenance_ns < MAINTENANCE_INTERVAL_NS) return;
    last_maintenance_ns = ts;
    arp.expire(&wan_iface.arp_table);
    if (has_lan) arp.expire(&lan_iface.arp_table);
    nat.expire();
    frag.expire(&frag_table);
    dhcp_server.expireLeases();
    dhcp_client.tick();
    ndp.expire(&wan_ndp_table);
    if (has_lan) ndp.expire(&lan_ndp_table);
    firewall6.expire();
    dns.expireCache();
    firewall.expireLeases(&port_forwards, ts);
    dhcpv6_client.tick();
    if (has_lan) slaac.tick();
}

pub const PacketAction = enum {
    consumed, // Packet fully handled, return RX buffer to hardware
    forward_wan, // Forward to WAN (zero-copy: headers modified in-place)
    forward_lan, // Forward to LAN (zero-copy: headers modified in-place)
};

fn isIpv6ForUs(ifc: *const Iface, dst_ip6: [16]u8) bool {
    if (util.eql(&dst_ip6, &ifc.ip6_link_local)) return true;
    if (ifc.ip6_global_valid and util.eql(&dst_ip6, &ifc.ip6_global)) return true;
    // Solicited-node multicast for our link-local
    const snm_ll = util.solicitedNodeMulticast(ifc.ip6_link_local);
    if (util.eql(&dst_ip6, &snm_ll)) return true;
    if (ifc.ip6_global_valid) {
        const snm_gl = util.solicitedNodeMulticast(ifc.ip6_global);
        if (util.eql(&dst_ip6, &snm_gl)) return true;
    }
    // All-nodes multicast (ff02::1)
    if (dst_ip6[0] == 0xff and dst_ip6[1] == 0x02 and dst_ip6[15] == 0x01 and
        util.isAllZeros(dst_ip6[2..15])) return true;
    // All-routers multicast (ff02::2)
    if (dst_ip6[0] == 0xff and dst_ip6[1] == 0x02 and dst_ip6[15] == 0x02 and
        util.isAllZeros(dst_ip6[2..15])) return true;
    return false;
}

pub fn processIpv6Packet(role: Interface, pkt: []u8, len: u32) PacketAction {
    if (len < h.EthernetHeader.LEN + h.Ipv6Header.LEN) return .consumed;

    const ip6 = h.Ipv6Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return .consumed;
    const ifc = getIface(role);
    const is_for_me = isIpv6ForUs(ifc, ip6.dst_ip);

    // Learn source neighbor
    var src_mac: [6]u8 = undefined;
    @memcpy(&src_mac, pkt[6..12]);
    const ndp_tbl = if (role == .wan) &wan_ndp_table else &lan_ndp_table;
    if (!util.isAllZeros(&ip6.src_ip)) ndp.learn(ndp_tbl, ip6.src_ip, src_mac, false);

    if (ip6.next_header == 58 and len >= h.EthernetHeader.LEN + h.Ipv6Header.LEN + 1) {
        const icmpv6_type = pkt[h.EthernetHeader.LEN + h.Ipv6Header.LEN];

        // NDP: NS/NA
        if (icmpv6_type == 135 or icmpv6_type == 136) {
            if (ndp.handle(role, pkt, len)) |reply| {
                _ = ifc.txSendLocal(reply, .dataplane);
            }
            return .consumed;
        }
        // Router Solicitation on LAN
        if (icmpv6_type == 133 and role == .lan) {
            slaac.handleRouterSolicitation(pkt, len);
            return .consumed;
        }
        // Router Advertisement on WAN (learn gateway)
        if (icmpv6_type == 134 and role == .wan) {
            return .consumed;
        }
        // Echo Request
        if (icmpv6_type == 128 and is_for_me) {
            if (icmpv6.handleEchoRequest(role, pkt, len)) |reply| {
                _ = ifc.txSendLocal(reply, .dataplane);
            }
            return .consumed;
        }
        // Echo Reply
        if (icmpv6_type == 129) {
            icmpv6.handleEchoReply(pkt, len);
            return .consumed;
        }
    }

    // UDP — check for DHCPv6
    if (ip6.next_header == 17 and is_for_me and len >= h.EthernetHeader.LEN + h.Ipv6Header.LEN + 4) {
        const udp_dst = util.readU16Be(pkt[h.EthernetHeader.LEN + h.Ipv6Header.LEN + 2 ..][0..2]);
        if (udp_dst == 546 and role == .wan) {
            dhcpv6_client.handleResponse(pkt, len);
            return .consumed;
        }
    }

    if (is_for_me) return .consumed;

    // Not for us — forward (no NAT for IPv6)
    if (ip6.hop_limit <= 1) {
        icmpv6.sendError(role, pkt, len, 3, 0); // Time Exceeded
        return .consumed;
    }
    ip6.hop_limit -= 1; // Decrement hop limit (no IP checksum to update!)

    if (role == .lan and has_lan) {
        // LAN → WAN
        firewall6.allowOutbound(pkt, len);
        const gw_mac = ndp.lookup(&wan_ndp_table, wan_gateway_ip6) orelse {
            ndp.sendNeighborSolicitation(.wan, wan_gateway_ip6);
            return .consumed;
        };
        @memcpy(pkt[0..6], &gw_mac);
        @memcpy(pkt[6..12], &wan_iface.mac);
        return .forward_wan;
    }
    if (role == .wan and has_lan) {
        // WAN → LAN
        if (!firewall6.allowInbound(pkt, len)) return .consumed;
        const inner_dst = ip6.dst_ip;
        const dst_mac = ndp.lookup(&lan_ndp_table, inner_dst) orelse {
            ndp.sendNeighborSolicitation(.lan, inner_dst);
            return .consumed;
        };
        @memcpy(pkt[0..6], &dst_mac);
        @memcpy(pkt[6..12], &lan_iface.mac);
        return .forward_lan;
    }

    return .consumed;
}

/// Process a received packet. Returns whether it should be forwarded zero-copy.
/// For forwarded packets, headers are modified IN-PLACE in the DMA buffer.
pub fn processPacket(role: Interface, pkt: []u8, len: u32) PacketAction {
    if (len < h.EthernetHeader.LEN) return .consumed;
    const ifc = getIface(role);
    const eth = h.EthernetHeader.parse(pkt) orelse return .consumed;
    const ethertype = eth.etherType();

    if (ethertype == h.EthernetHeader.ARP) {
        // ARP: learn, reply, never forwarded
        if (len >= h.EthernetHeader.LEN + h.ArpHeader.LEN) {
            const arp_hdr = h.ArpHeader.parse(pkt[h.EthernetHeader.LEN..]) orelse return .consumed;
            arp.learn(&ifc.arp_table, arp_hdr.sender_ip, arp_hdr.sender_mac);
            udp_fwd.drainPending();
            if (ping_state == .arp_pending and ping_iface == role) {
                if (arp.lookup(&ifc.arp_table, ping_target_ip)) |mac| {
                    @memcpy(&ping_target_mac, &mac);
                    ping_mod.sendEchoRequest();
                }
            }
            if (traceroute_state == .arp_pending and traceroute_iface == role) {
                // For non-local traceroute, resolve gateway MAC
                const resolve_ip = if (traceroute_iface == .wan) wan_gateway else traceroute_target_ip;
                if (arp.lookup(&ifc.arp_table, resolve_ip)) |mac| {
                    @memcpy(&traceroute_target_mac, &mac);
                    ping_mod.sendTracerouteProbe();
                }
            }
        }
        if (arp.handle(role, pkt, len)) |reply| {
            _ = ifc.txSendLocal(reply, .dataplane);
        }
        return .consumed;
    }

    if (ethertype == h.EthernetHeader.IPv6) return processIpv6Packet(role, pkt, len);

    if (ethertype != h.EthernetHeader.IPv4 or len < h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN) return .consumed;

    // IPv4 packet
    const ip = h.Ipv4Header.parseMut(pkt[h.EthernetHeader.LEN..]) orelse return .consumed;
    const dst_ip = ip.dst_ip;
    const my_ip = &ifc.ip;
    const is_for_me = util.eql(&dst_ip, my_ip) or util.eql(&dst_ip, &lan_broadcast) or
        (dst_ip[0] == 255 and dst_ip[1] == 255 and dst_ip[2] == 255 and dst_ip[3] == 255) or
        (role == .lan and (dst_ip[0] & 0xF0) == 0xE0); // LAN multicast (224.0.0.0/4)

    if (is_for_me) {
        // Packet addressed to us — handle locally, never zero-copy forward

        // TCP — HTTP server on LAN port 80
        if (ip.protocol == h.Ipv4Header.PROTO_TCP and role == .lan) {
            if (tcp_stack.handleTcp(pkt, len)) return .consumed;
        }

        if (ip.protocol == h.Ipv4Header.PROTO_UDP) {
            const ip_hdr_len = ip.headerLen();
            const udp_start = h.EthernetHeader.LEN + ip_hdr_len;
            if (udp_start + 4 <= len) {
                const udp_dst = util.readU16Be(pkt[udp_start + 2 ..][0..2]);
                if (udp_dst == 68 and role == .wan) {
                    dhcp_client.handleResponse(pkt, len);
                    return .consumed;
                }
                if (udp_dst == 67 and role == .lan) {
                    dhcp_server.handle(pkt, len);
                    return .consumed;
                }
                if (udp_dst == dns.DNS_PORT and role == .lan) {
                    dns.handleFromLan(pkt, len);
                    return .consumed;
                }
                if (udp_dst == upnp.SSDP_PORT and role == .lan) {
                    upnp.handleSsdp(pkt, len);
                    return .consumed;
                }
                if (udp_dst == pcp.PCP_PORT and role == .lan) {
                    pcp.handleRequest(pkt, len);
                    return .consumed;
                }
                if (role == .wan) {
                    const udp_src_port = util.readU16Be(pkt[udp_start..][0..2]);
                    if (udp_src_port == dns.DNS_PORT) {
                        dns.handleFromWan(pkt, len);
                        return .consumed;
                    }
                }
                if (udp_start + 8 <= len) {
                    const src_ip_udp = ip.src_ip;
                    const udp_src = util.readU16Be(pkt[udp_start..][0..2]);
                    if (udp_fwd.forwardToApp(src_ip_udp, udp_src, udp_dst, pkt[udp_start + 8 .. len])) return .consumed;
                }
                // Check port forwarding before declaring unreachable
                if (role == .wan and has_lan) {
                    if (firewall.handlePortForward(pkt, len)) return .consumed;
                    if (nat.forwardWanToLan(pkt, len)) return .forward_lan;
                }
                // No handler matched — send ICMP Port Unreachable (Type 3, Code 3)
                // Don't send for broadcasts
                if (!util.eql(&dst_ip, &lan_broadcast) and
                    dst_ip[0] != 255)
                {
                    sendIcmpError(role, pkt, len, 3, 3);
                }
                return .consumed;
            }
        }
        ping_mod.handleEchoReply(pkt, len);
        ping_mod.handleTimeExceeded(pkt, len);
        ping_mod.handleTracerouteEchoReply(pkt, len);
        if (handleIcmp(role, pkt, len)) |reply| {
            _ = ifc.txSendLocal(reply, .dataplane);
        } else if (role == .wan and has_lan) {
            if (firewall.handlePortForward(pkt, len)) return .consumed;
            if (nat.forwardWanToLan(pkt, len)) return .forward_lan;
        }
        return .consumed;
    }

    // Packet not for us — forward to the other interface
    // Check TTL before forwarding
    if (ip.ttl <= 1) {
        // TTL expired — send ICMP Time Exceeded (Type 11, Code 0)
        sendIcmpError(role, pkt, len, 11, 0);
        return .consumed;
    }
    // Decrement TTL and recompute IP checksum
    ip.ttl -= 1;
    ip.computeAndSetChecksum(pkt);

    // TCP MSS clamping on SYN/SYN-ACK traversing the router
    if (ip.protocol == h.Ipv4Header.PROTO_TCP) clampMss(pkt, len);

    if (role == .lan and has_lan) {
        if (firewall.reversePortForward(pkt, len)) return .forward_wan;
        if (nat.forwardLanToWan(pkt, len)) return .forward_wan;
    }

    return .consumed;
}


var known_shm_handles: [32]u64 = .{0} ** 32;
var known_shm_count: u8 = 0;

fn addKnownShmHandle(handle: u64) void {
    if (known_shm_count < 32) {
        known_shm_handles[known_shm_count] = handle;
        known_shm_count += 1;
    }
}

fn pollNewShm(view_addr: u64) ?u64 {
    const v: *const [128]pv.UserViewEntry = @ptrFromInt(view_addr);
    for (v) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            var known = false;
            for (known_shm_handles[0..known_shm_count]) |kh| {
                if (kh == entry.handle) {
                    known = true;
                    break;
                }
            }
            if (!known and known_shm_count < 32) {
                known_shm_handles[known_shm_count] = entry.handle;
                known_shm_count += 1;
                return entry.handle;
            }
        }
    }
    return null;
}

fn detectAppChannels(perm_view_addr_local: u64) void {
    const shm_handle = pollNewShm(perm_view_addr_local) orelse return;
    const chan = Channel.connectAsB(shm_handle, 4 * syscall.PAGE4K) catch return;
    switch (chan.protocol_id) {
        @intFromEnum(lib.Protocol.nfs_client) => {
            nfs_chan = chan;
            log.write(.nfs_connected);
        },
        @intFromEnum(lib.Protocol.ntp_client) => {
            ntp_chan = chan;
            log.write(.ntp_connected);
        },
        @intFromEnum(lib.Protocol.http_server) => {
            http_chan = chan;
            log.write(.http_connected);
        },
        @intFromEnum(lib.Protocol.console) => {
            console_chan = chan;
            log.write(.console_connected);
        },
        else => {},
    }
}

fn crashReasonName(reason: pv.CrashReason) []const u8 {
    return switch (reason) {
        .none => "none",
        .stack_overflow => "stack_overflow",
        .stack_underflow => "stack_underflow",
        .invalid_read => "invalid_read",
        .invalid_write => "invalid_write",
        .invalid_execute => "invalid_execute",
        .unmapped_access => "unmapped_access",
        .out_of_memory => "out_of_memory",
        .arithmetic_fault => "arithmetic_fault",
        .illegal_instruction => "illegal_instruction",
        .alignment_fault => "alignment_fault",
        .protection_fault => "protection_fault",
        .normal_exit => "normal_exit",
        .killed => "killed",
        .revoked => "revoked",
        _ => "unknown",
    };
}

pub fn main(perm_view_addr: u64) void {
    perm_view_addr_global = perm_view_addr;
    channel.broadcast(@intFromEnum(lib.Protocol.router)) catch {};
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    perm_view = view;

    // Detect restart: slot 0 (self) has restart_count and crash_reason
    const self_entry = &view[0];
    const restart_count = self_entry.processRestartCount();
    if (restart_count > 0) {
        const reason = self_entry.processCrashReason();
        var rbuf: [80]u8 = undefined;
        var rp: usize = 0;
        rp = util.appendStr(&rbuf, rp, "router: RESTARTED (#");
        rp = util.appendDec(&rbuf, rp, restart_count);
        rp = util.appendStr(&rbuf, rp, ") reason=");
        rp = util.appendStr(&rbuf, rp, crashReasonName(reason));
        rp = util.appendStr(&rbuf, rp, "\n");
        syscall.write(rbuf[0..rp]);
    }

    // Scan for NICs — retry until WAN is found (grant may race with proc start)
    var nics: @TypeOf(findNicDevices(perm_view_addr)) = undefined;
    while (true) {
        nics = findNicDevices(perm_view_addr);
        if (nics.wan != null) break;
        pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }
    // Also wait for LAN if not yet visible
    if (nics.lan == null) {
        var retry: u32 = 0;
        while (retry < 200 and nics.lan == null) : (retry += 1) {
            pv.waitForChange(perm_view_addr, 10_000_000); // 10ms
            nics = findNicDevices(perm_view_addr);
        }
    }
    const wan_nic = nics.wan.?;

    const wan_mmio_size = if (wan_nic.mmio_size == 0) syscall.PAGE4K else wan_nic.mmio_size;
    const wan_mmio = mmioMap(wan_nic.handle, wan_mmio_size) orelse {
        syscall.write("router: WAN MMIO fail — halted\n");
        while (true) pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    };

    // DMA setup — create SHM, map WAN, optionally also map LAN
    const lan_handle: ?u64 = if (nics.lan) |ln| ln.handle else null;
    var region = dma.setupWan(wan_nic.handle, lan_handle) orelse {
        syscall.write("router: DMA fail — halted\n");
        while (true) pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    };
    const dual_dma_ok = region.lan_dma_base != 0;

    // Initialize WAN interface
    wan_iface.role = .wan;
    wan_iface.mmio_base = wan_mmio;
    wan_iface.mac = .{ 0, 0, 0, 0, 0, 0 };
    wan_iface.ip = .{ 10, 0, 2, 15 };
    wan_iface.dma_base = region.wan_dma_base;
    wan_iface.dma_region = &region;
    wan_iface.rx_descs = region.wanRxDescs();
    wan_iface.tx_descs = region.wanTxDescs();
    wan_iface.rx_tail = nic.NUM_RX_DESC - 1;
    wan_iface.tx_tail = 0;
    wan_iface.rx_buf_state = .{.free} ** nic.NUM_RX_DESC;
    wan_iface.rx_buf_tx_idx = .{0} ** nic.NUM_RX_DESC;
    wan_iface.arp_table = .{arp.empty} ** arp.TABLE_SIZE;
    wan_iface.stats = .{};
    wan_iface.pending_tx = .{ .{}, .{} };

    if (!nic.init(.{
        .mmio_base = wan_mmio,
        .rx_descs_dma = region.wanDma(dma.WAN_RX_DESCS_OFF),
        .tx_descs_dma = region.wanDma(dma.WAN_TX_DESCS_OFF),
        .rx_bufs_dma_base = region.wanDma(dma.WAN_RX_BUFS_OFF),
        .tx_bufs_dma_base = region.wanDma(dma.WAN_TX_BUFS_OFF),
        .rx_descs = region.wanRxDescs(),
        .tx_descs = region.wanTxDescs(),
    })) {
        syscall.write("router: WAN NIC init fail — halted\n");
        while (true) pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }
    syscall.pci_enable_bus_master(wan_nic.handle);
    wan_iface.mac = nic.readMac(wan_mmio);
    wan_iface.ip6_link_local = util.macToLinkLocal(wan_iface.mac);

    // Initialize LAN interface if dual-NIC DMA succeeded
    if (dual_dma_ok) {
        const lan_nic = nics.lan.?;
        const lan_mmio_size = if (lan_nic.mmio_size == 0) syscall.PAGE4K else lan_nic.mmio_size;
        if (mmioMap(lan_nic.handle, lan_mmio_size)) |lan_mmio| {
            if (nic.init(.{
                .mmio_base = lan_mmio,
                .rx_descs_dma = region.lanDma(dma.LAN_RX_DESCS_OFF),
                .tx_descs_dma = region.lanDma(dma.LAN_TX_DESCS_OFF),
                .rx_bufs_dma_base = region.lanDma(dma.LAN_RX_BUFS_OFF),
                .tx_bufs_dma_base = region.lanDma(dma.LAN_TX_BUFS_OFF),
                .rx_descs = region.lanRxDescs(),
                .tx_descs = region.lanTxDescs(),
            })) {
                syscall.pci_enable_bus_master(lan_nic.handle);

                lan_iface.role = .lan;
                lan_iface.mmio_base = lan_mmio;
                lan_iface.mac = nic.readMac(lan_mmio);
                lan_iface.ip6_link_local = util.macToLinkLocal(lan_iface.mac);
                lan_iface.ip = .{ 10, 1, 1, 1 };
                lan_iface.dma_base = region.lan_dma_base;
                lan_iface.dma_region = &region;
                lan_iface.rx_descs = region.lanRxDescs();
                lan_iface.tx_descs = region.lanTxDescs();
                lan_iface.rx_tail = nic.NUM_RX_DESC - 1;
                lan_iface.tx_tail = 0;
                lan_iface.rx_buf_state = .{.free} ** nic.NUM_RX_DESC;
                lan_iface.rx_buf_tx_idx = .{0} ** nic.NUM_RX_DESC;
                lan_iface.arp_table = .{arp.empty} ** arp.TABLE_SIZE;
                lan_iface.stats = .{};
                lan_iface.pending_tx = .{ .{}, .{} };

                has_lan = true;
            }
        }
    }
    arp.sendRequest(.wan, wan_gateway);
    if (has_lan) arp.sendRequest(.lan, .{ 10, 1, 1, 50 });

    // Spawn LAN poll thread if dual-NIC
    if (has_lan) {
        _ = syscall.thread_create(&lanPollThread, 0, 4) catch 0;
    }

    // Record DMA SHM as known so channel detection ignores it
    addKnownShmHandle(region.shm_handle);

    // Spawn service thread for console/NFS/NTP channel handling
    _ = syscall.thread_create(&serviceThread, 0, 4) catch 0;

    // Pin WAN thread to core 1 (non-preemptible)
    const affinity_ok = if (syscall.set_affinity(1 << 1)) |_| true else |_| false;
    if (affinity_ok) {
        syscall.thread_yield(); // migrate to core 1
        syscall.pin_exclusive() catch {};
    }

    // WAN thread (runs on the initial/main thread):
    // Pure data-plane: polls WAN RX, handles routing, forwards to LAN.
    while (true) {
        pollOnce(&wan_iface, &lan_iface, .wan);
    }
}

// ── Console command dispatch ─────────────────────────────────────────────

fn handleConsoleCommand(chan: *Channel, cmd: []const u8) void {
    if (cmd.len == 0) return;
    const srv = text_cmd.Server.init(chan);
    var resp: [512]u8 = undefined;

    if (util.eql(cmd, "status")) {
        var p: usize = 0;
        p = util.appendStr(&resp, p, "WAN: ");
        p = util.appendIp(&resp, p, wan_iface.ip);
        p = util.appendStr(&resp, p, " gw=");
        p = util.appendIp(&resp, p, wan_gateway);
        p = util.appendStr(&resp, p, " mac=");
        p = util.appendMac(&resp, p, wan_iface.mac);
        if (has_lan) {
            p = util.appendStr(&resp, p, "\nLAN: ");
            p = util.appendIp(&resp, p, lan_iface.ip);
            p = util.appendStr(&resp, p, " mac=");
            p = util.appendMac(&resp, p, lan_iface.mac);
        }
        srv.sendText(resp[0..p]);
        srv.sendEnd();
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
        srv.sendText(resp[0..p]);
        srv.sendEnd();
    } else if (util.eql(cmd, "arp")) {
        sendArpTable(chan, "WAN", &wan_iface.arp_table);
        if (has_lan) sendArpTable(chan, "LAN", &lan_iface.arp_table);
        srv.sendEnd();
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
            srv.sendText(resp[0..p]);
            count += 1;
        }
        if (count == 0) srv.sendText("(empty)");
        srv.sendEnd();
    } else if (util.eql(cmd, "leases")) {
        var count: u32 = 0;
        for (&dhcp_leases) |*l| {
            const gen = l.seq.readBegin();
            const valid = l.valid;
            const l_ip = l.ip;
            const l_mac = l.mac;
            if (l.seq.readRetry(gen)) continue;
            if (!valid) continue;
            var p: usize = 0;
            p = util.appendIp(&resp, p, l_ip);
            p = util.appendStr(&resp, p, " ");
            p = util.appendMac(&resp, p, l_mac);
            srv.sendText(resp[0..p]);
            count += 1;
        }
        if (count == 0) srv.sendText("(empty)");
        srv.sendEnd();
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
            srv.sendText(resp[0..p]);
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
            srv.sendText(resp[0..p]);
            count += 1;
        }
        if (count == 0) srv.sendText("(empty)");
        srv.sendEnd();
    } else if (util.startsWith(cmd, "ping ")) {
        const ip = util.parseIp(cmd[5..]) orelse {
            srv.sendText("invalid IP");
            srv.sendEnd();
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
    } else if (util.startsWith(cmd, "traceroute ")) {
        if (traceroute_state != .idle) {
            srv.sendText("traceroute already in progress");
            srv.sendEnd();
            return;
        }
        const ip = util.parseIp(cmd[11..]) orelse {
            srv.sendText("invalid IP");
            srv.sendEnd();
            return;
        };
        traceroute_target_ip = ip;
        traceroute_ttl = 1;
        traceroute_iface = if (isInLanSubnet(ip)) .lan else .wan;
        const ifc = getIface(traceroute_iface);
        // Send header line
        var p: usize = 0;
        p = util.appendStr(&resp, p, "traceroute to ");
        p = util.appendIp(&resp, p, ip);
        p = util.appendStr(&resp, p, ", ");
        p = util.appendDec(&resp, p, traceroute_max_hops);
        p = util.appendStr(&resp, p, " hops max");
        srv.sendText(resp[0..p]);
        // Resolve MAC and send first probe
        if (arp.lookup(&ifc.arp_table, ip)) |mac| {
            @memcpy(&traceroute_target_mac, &mac);
            ping_mod.sendTracerouteProbe();
        } else {
            // For traceroute, we route through the gateway, so use gateway MAC
            if (traceroute_iface == .wan) {
                if (arp.lookup(&ifc.arp_table, wan_gateway)) |gw_mac| {
                    @memcpy(&traceroute_target_mac, &gw_mac);
                    ping_mod.sendTracerouteProbe();
                } else {
                    traceroute_state = .arp_pending;
                    traceroute_start_ns = util.now();
                    arp.sendRequest(traceroute_iface, wan_gateway);
                }
            } else {
                traceroute_state = .arp_pending;
                traceroute_start_ns = util.now();
                arp.sendRequest(traceroute_iface, ip);
            }
        }
    } else if (util.startsWith(cmd, "block ")) {
        const ip = util.parseIp(cmd[6..]) orelse {
            srv.sendText("invalid IP");
            srv.sendEnd();
            return;
        };
        for (&firewall_rules) |*r| {
            if (!r.valid) {
                r.seq.writeBegin();
                r.valid = true;
                r.action = .block;
                r.src_ip = ip;
                r.src_mask = .{ 255, 255, 255, 255 };
                r.protocol = 0;
                r.dst_port = 0;
                r.seq.writeEnd();
                srv.sendText("OK");
                srv.sendEnd();
                return;
            }
        }
        srv.sendText("firewall table full");
        srv.sendEnd();
    } else if (util.startsWith(cmd, "allow ")) {
        const ip = util.parseIp(cmd[6..]) orelse {
            srv.sendText("invalid IP");
            srv.sendEnd();
            return;
        };
        for (&firewall_rules) |*r| {
            if (r.valid and r.action == .block and util.eql(&r.src_ip, &ip)) {
                r.seq.writeBegin();
                r.valid = false;
                r.seq.writeEnd();
                srv.sendText("OK");
                srv.sendEnd();
                return;
            }
        }
        srv.sendText("rule not found");
        srv.sendEnd();
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
            srv.sendText("usage: forward tcp|udp <wport> <lip> <lport>");
            srv.sendEnd();
            return;
        }
        const parsed = util.parsePortIpPort(rest) orelse {
            srv.sendText("usage: forward tcp|udp <wport> <lip> <lport>");
            srv.sendEnd();
            return;
        };
        for (&port_forwards) |*f| {
            if (!f.valid) {
                f.seq.writeBegin();
                f.valid = true;
                f.protocol = proto;
                f.wan_port = parsed.port1;
                f.lan_ip = parsed.ip;
                f.lan_port = parsed.port2;
                f.seq.writeEnd();
                srv.sendText("OK");
                srv.sendEnd();
                return;
            }
        }
        srv.sendText("port forward table full");
        srv.sendEnd();
    } else if (util.startsWith(cmd, "dns ")) {
        const ip = util.parseIp(cmd[4..]) orelse {
            srv.sendText("invalid IP");
            srv.sendEnd();
            return;
        };
        upstream_dns = ip;
        srv.sendText("OK");
        srv.sendEnd();
    } else if (util.eql(cmd, "dhcp-client")) {
        var p: usize = 0;
        const state_str: []const u8 = switch (dhcp_client_state) {
            .idle => "idle",
            .discovering => "discovering",
            .requesting => "requesting",
            .bound => "bound",
            .rebinding => "rebinding",
        };
        p = util.appendStr(&resp, p, "DHCP client: ");
        p = util.appendStr(&resp, p, state_str);
        if (dhcp_client_state == .idle) {
            dhcp_client.sendDiscover();
            dhcp_client_state = .discovering;
            dhcp_client_start_ns = util.now();
            p = util.appendStr(&resp, p, " -> discovering");
        }
        srv.sendText(resp[0..p]);
        srv.sendEnd();
    } else if (util.eql(cmd, "dhcp-test-rebind")) {
        if (dhcp_client_state == .bound or dhcp_client_state == .requesting) {
            dhcp_client_xid +%= 1;
            dhcp_client.sendRebind();
            srv.sendText("rebinding");
        } else {
            srv.sendText("not bound");
        }
        srv.sendEnd();
    } else if (util.eql(cmd, "dhcpv6")) {
        var p: usize = 0;
        const state_str: []const u8 = switch (dhcpv6_state) {
            .idle => "idle",
            .soliciting => "soliciting",
            .requesting => "requesting",
            .bound => "bound",
        };
        p = util.appendStr(&resp, p, "DHCPv6: ");
        p = util.appendStr(&resp, p, state_str);
        if (dhcpv6_state != .bound) {
            dhcpv6_client.sendSolicit();
            p = util.appendStr(&resp, p, " -> soliciting");
        }
        srv.sendText(resp[0..p]);
        srv.sendEnd();
    } else if (util.eql(cmd, "static-leases")) {
        var count: u32 = 0;
        for (&dhcp_static_leases) |*s| {
            if (@atomicLoad(u8, &s.state, .acquire) == 0) continue;
            var p: usize = 0;
            p = util.appendIp(&resp, p, s.ip);
            p = util.appendStr(&resp, p, " ");
            p = util.appendMac(&resp, p, s.mac);
            srv.sendText(resp[0..p]);
            count += 1;
        }
        if (count == 0) srv.sendText("(empty)");
        srv.sendEnd();
    } else if (util.startsWith(cmd, "static-lease ")) {
        const args = cmd[13..];
        if (args.len < 19) {
            srv.sendText("usage: static-lease <mac> <ip>");
            srv.sendEnd();
            return;
        }
        const mac = util.parseMac(args[0..17]) orelse {
            srv.sendText("invalid MAC");
            srv.sendEnd();
            return;
        };
        if (args[17] != ' ') {
            srv.sendText("usage: static-lease <mac> <ip>");
            srv.sendEnd();
            return;
        }
        const ip = util.parseIp(args[18..]) orelse {
            srv.sendText("invalid IP");
            srv.sendEnd();
            return;
        };
        if (ip[0] != 10 or ip[1] != 1 or ip[2] != 1 or ip[3] < 2) {
            srv.sendText("IP must be 10.1.1.2-255");
            srv.sendEnd();
            return;
        }
        for (&dhcp_static_leases) |*s| {
            if (@atomicLoad(u8, &s.state, .acquire) != 0 and (util.eql(&s.mac, &mac) or util.eql(&s.ip, &ip))) {
                srv.sendText("conflict: MAC or IP already reserved");
                srv.sendEnd();
                return;
            }
        }
        for (&dhcp_static_leases) |*s| {
            if (@atomicLoad(u8, &s.state, .acquire) == 0) {
                s.mac = mac;
                s.ip = ip;
                @atomicStore(u8, &s.state, 1, .release);
                srv.sendText("OK");
                srv.sendEnd();
                return;
            }
        }
        srv.sendText("static lease table full");
        srv.sendEnd();
    } else if (util.eql(cmd, "get-config")) {
        // Serialize current config as lines (multi-response)
        // DNS upstream
        if (!util.eql(&upstream_dns, &[4]u8{ 10, 0, 2, 1 })) {
            var p: usize = 0;
            p = util.appendStr(&resp, p, "dns ");
            p = util.appendIp(&resp, p, upstream_dns);
            srv.sendText(resp[0..p]);
        }
        // Firewall block rules
        for (&firewall_rules) |*r| {
            if (!r.valid) continue;
            var p: usize = 0;
            p = util.appendStr(&resp, p, "block ");
            p = util.appendIp(&resp, p, r.src_ip);
            srv.sendText(resp[0..p]);
        }
        // Port forwards
        for (&port_forwards) |*f| {
            if (!f.valid) continue;
            var p: usize = 0;
            const proto_str: []const u8 = if (f.protocol == .tcp) "tcp" else "udp";
            p = util.appendStr(&resp, p, "forward ");
            p = util.appendStr(&resp, p, proto_str);
            p = util.appendStr(&resp, p, " ");
            p = util.appendDec(&resp, p, f.wan_port);
            p = util.appendStr(&resp, p, " ");
            p = util.appendIp(&resp, p, f.lan_ip);
            p = util.appendStr(&resp, p, " ");
            p = util.appendDec(&resp, p, f.lan_port);
            srv.sendText(resp[0..p]);
        }
        // Static DHCP leases
        for (&dhcp_static_leases) |*s| {
            if (@atomicLoad(u8, &s.state, .acquire) == 0) continue;
            var p: usize = 0;
            p = util.appendStr(&resp, p, "static-lease ");
            p = util.appendMac(&resp, p, s.mac);
            p = util.appendStr(&resp, p, " ");
            p = util.appendIp(&resp, p, s.ip);
            srv.sendText(resp[0..p]);
        }
        srv.sendEnd();
    } else {
        srv.sendText("unknown router command");
        srv.sendEnd();
    }
}

fn sendArpTable(chan: *Channel, label: []const u8, table: *const [arp.TABLE_SIZE]arp.ArpEntry) void {
    const srv = text_cmd.Server.init(chan);
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
        srv.sendText(resp[0..p]);
        count += 1;
    }
    if (count == 0) {
        var p: usize = 0;
        p = util.appendStr(&resp, p, label);
        p = util.appendStr(&resp, p, " (empty)");
        srv.sendText(resp[0..p]);
    }
}

// ── Poll thread ─────────────────────────────────────────────────────────

/// Poll one interface: receive a packet, process it, forward zero-copy if needed.
fn pollOnce(self_iface: *Iface, other_iface: *Iface, role: Interface) void {
    // Drain any pending TX from the main thread (lock-free)
    self_iface.drainPendingTx();

    // Reclaim any RX buffers that were lent to the other NIC's TX
    if (has_lan) self_iface.reclaimTxPending(other_iface);

    nic.clearIrq(self_iface.mmio_base);
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

/// Service thread: handles console commands, NFS/NTP app messages, and channel detection.
/// Runs on core 0 (preemptive) so it doesn't interfere with the pinned data-plane threads.
fn serviceThread() void {
    if (perm_view == null) return;
    var loop_n: u32 = 0;

    log.write(.service_started);

    var svc_arena = Arena.init(1 << 30) orelse return;
    const a = svc_arena.allocator();

    const cmd_buf = a.alloc(u8, 256) catch return;
    const nfs_buf = a.alloc(u8, 2048) catch return;
    const ntp_buf = a.alloc(u8, 256) catch return;
    const http_buf = a.alloc(u8, 8192) catch return;
    var http_chunks_expected: u8 = 0;
    var http_chunks_received: u8 = 0;
    const state_buf = a.alloc(u8, 4096) catch return;

    while (true) {
        loop_n +%= 1;

        // Channel detection (periodically scan for new SHM channels)
        if (loop_n % 50 == 0) detectAppChannels(perm_view_addr_global);

        // Console command handling
        if (console_chan) |chan| {
            const con_srv = text_cmd.Server.init(chan);
            if (con_srv.recvCommand(cmd_buf)) |cmd| {
                switch (cmd) {
                    .text => |text| handleConsoleCommand(chan, text),
                    else => {},
                }
            }
        }

        // NFS app messages
        if (nfs_chan) |chan| {
            if (chan.receiveMessage(.B, nfs_buf) catch null) |nfs_len| {
                udp_fwd.handleAppMessage(nfs_buf[0..nfs_len], .nfs);
            }
        }

        // NTP app messages
        if (ntp_chan) |chan| {
            if (chan.receiveMessage(.B, ntp_buf) catch null) |ntp_len| {
                if (ntp_len >= 17 and ntp_buf[0] == ntp_proto.CMD_TIME_SYNC) {
                    // [0] = CMD_TIME_SYNC, [1..9] = unix_secs, [9..17] = mono_ns
                    const unix_secs = readU64Be(ntp_buf[1..9]);
                    const mono_ns = readU64Be(ntp_buf[9..17]);
                    log.updateNtpTime(unix_secs, mono_ns);
                } else {
                    udp_fwd.handleAppMessage(ntp_buf[0..ntp_len], .ntp);
                }
            }
        }

        // HTTP server app messages
        if (http_chan) |chan| {
            if (chan.receiveMessage(.B, http_buf) catch null) |hlen| {
                if (hlen >= 3 and http_buf[0] == http_proto.CMD_HTTP_RESPONSE) {
                    const chunk_idx = http_buf[1];
                    const total_chunks = http_buf[2];
                    const chunk_data = http_buf[3..hlen];

                    if (chunk_idx == 0) {
                        // First chunk: parse metadata and send HTTP header + body start
                        http_chunks_expected = total_chunks;
                        http_chunks_received = 1;
                        handleHttpResponseStreaming(chunk_data, total_chunks == 1);
                    } else {
                        // Continuation chunk: send body data directly as TCP
                        http_chunks_received += 1;
                        const is_last = (http_chunks_received >= http_chunks_expected);
                        if (is_last) {
                            // Last chunk: send data + FIN
                            tcp_stack.sendTcpChunk(chunk_data);
                            tcp_stack.sendTcpFin();
                            http_chunks_expected = 0;
                            http_chunks_received = 0;
                        } else {
                            tcp_stack.sendTcpChunk(chunk_data);
                        }
                    }
                } else {
                    handleHttpServerMessage(http_buf[0..hlen], chan, state_buf);
                }
            }
        }

        // Periodic maintenance (timers, expiry, DHCP ticks)
        periodicMaintenance();
        ping_mod.checkTimeout();
        ping_mod.checkTracerouteTimeout();

        // Drain log ring buffer and flush to NFS
        log.drainAndFlush(&nfs_chan, loop_n);

        syscall.thread_yield();
    }
}

fn handleHttpServerMessage(data: []const u8, chan: *Channel, buf: []u8) void {
    if (data.len < 1) return;
    const srv = HttpServer.init(chan);
    switch (data[0]) {
        http_proto.CMD_STATE_QUERY => {
            if (data.len < 2) return;
            handleStateQuery(data[1], &srv, buf);
        },
        http_proto.CMD_HTTP_RESPONSE => {
            // Handled by chunked reassembly in service loop; should not reach here
        },
        http_proto.CMD_MUTATION_REQUEST => {
            if (data.len < 2) return;
            handleMutationRequest(data[1..], &srv, buf);
        },
        else => {},
    }
}

fn handleStateQuery(endpoint: u8, srv: *const HttpServer, buf: []u8) void {
    const json_len: usize = switch (endpoint) {
        0 => tcp_stack.formatJsonStatus(buf),
        1 => tcp_stack.formatJsonIfstat(buf),
        2 => tcp_stack.formatJsonArp(buf),
        3 => tcp_stack.formatJsonNat(buf),
        4 => tcp_stack.formatJsonLeases(buf),
        5 => tcp_stack.formatJsonRules(buf),
        else => 0,
    };
    srv.sendStateResponse(buf[0..json_len]);
}

/// Parse chunk 0 of MSG_HTTP_RESPONSE from http_server and send via TCP.
/// Wire format: [body_len:2 BE][slen:1][status...][ctlen:1][ct...][body_start...]
/// If is_complete, sends with FIN. Otherwise, sends header + body start without FIN.
fn handleHttpResponseStreaming(data: []const u8, is_complete: bool) void {
    var p: usize = 0;

    // Parse total body length (2 bytes BE)
    if (p + 2 > data.len) return;
    const body_len: u64 = @as(u64, data[p]) << 8 | @as(u64, data[p + 1]);
    p += 2;

    // Parse status
    if (p >= data.len) return;
    const slen: usize = data[p];
    p += 1;
    if (p + slen > data.len) return;
    const status = data[p..][0..slen];
    p += slen;

    // Parse content-type
    if (p >= data.len) return;
    const ctlen: usize = data[p];
    p += 1;
    if (p + ctlen > data.len) return;
    const content_type = data[p..][0..ctlen];
    p += ctlen;

    // Remaining is the first body data
    const body_start = data[p..];

    // Build HTTP/1.0 response header
    var hdr: [256]u8 = undefined;
    var hp: usize = 0;
    hp = util.appendStr(&hdr, hp, "HTTP/1.0 ");
    hp = util.appendStr(&hdr, hp, status);
    hp = util.appendStr(&hdr, hp, "\r\nContent-Type: ");
    hp = util.appendStr(&hdr, hp, content_type);
    hp = util.appendStr(&hdr, hp, "\r\nContent-Length: ");
    hp = util.appendDec(&hdr, hp, body_len);
    hp = util.appendStr(&hdr, hp, "\r\nConnection: close\r\n\r\n");

    if (is_complete) {
        // Single chunk — send header + body with FIN (original path)
        tcp_stack.sendHttpResponse(hdr[0..hp], body_start);
    } else {
        // Multi-chunk — send header + first body data without FIN
        tcp_stack.sendTcpChunk(hdr[0..hp]);
        tcp_stack.sendTcpChunk(body_start);
    }
}

/// Handle a mutation request from http_server.
/// Wire format: [mutation_type:1][params...]
/// Mutation types: 0=block, 1=allow, 2=forward, 3=unforward, 4=dns
fn handleMutationRequest(data: []const u8, srv: *const HttpServer, _: []u8) void {
    if (data.len < 1) return;
    const mutation_type = data[0];
    const params = data[1..];

    const result: []const u8 = switch (mutation_type) {
        0 => mutateBlock(params),
        1 => mutateAllow(params),
        2 => mutateForward(params),
        3 => mutateUnforward(params),
        4 => mutateDns(params),
        5 => mutateTimezone(params),
        6 => mutateForwardLeased(params),
        else => "{\"ok\":false,\"error\":\"unknown mutation\"}",
    };

    srv.sendMutationResponse(result);
}

fn mutateBlock(params: []const u8) []const u8 {
    const ip = util.parseIp(params) orelse return "{\"ok\":false,\"error\":\"invalid ip\"}";
    for (&firewall_rules) |*r| {
        if (!r.valid) {
            r.seq.writeBegin();
            r.valid = true;
            r.action = .block;
            r.src_ip = ip;
            r.src_mask = .{ 255, 255, 255, 255 };
            r.protocol = 0;
            r.dst_port = 0;
            r.seq.writeEnd();
            return "{\"ok\":true}";
        }
    }
    return "{\"ok\":false,\"error\":\"firewall table full\"}";
}

fn mutateAllow(params: []const u8) []const u8 {
    const ip = util.parseIp(params) orelse return "{\"ok\":false,\"error\":\"invalid ip\"}";
    for (&firewall_rules) |*r| {
        if (r.valid and r.action == .block and util.eql(&r.src_ip, &ip)) {
            r.seq.writeBegin();
            r.valid = false;
            r.seq.writeEnd();
            return "{\"ok\":true}";
        }
    }
    return "{\"ok\":false,\"error\":\"rule not found\"}";
}

fn mutateForward(params: []const u8) []const u8 {
    // Format: <proto_byte><wan_port:2><lan_ip:4><lan_port:2>
    if (params.len < 9) return "{\"ok\":false,\"error\":\"invalid format\"}";
    const proto: util.Protocol = if (params[0] == 0) .tcp else .udp;
    const wan_port = util.readU16Be(params[1..3]);
    const lan_ip = params[3..7].*;
    const lan_port = util.readU16Be(params[7..9]);
    for (&port_forwards) |*f| {
        if (!f.valid) {
            f.seq.writeBegin();
            f.valid = true;
            f.protocol = proto;
            f.wan_port = wan_port;
            f.lan_ip = lan_ip;
            f.lan_port = lan_port;
            f.seq.writeEnd();
            return "{\"ok\":true}";
        }
    }
    return "{\"ok\":false,\"error\":\"port forward table full\"}";
}

fn mutateForwardLeased(params: []const u8) []const u8 {
    // Format: <proto_byte><wan_port:2><lan_ip:4><lan_port:2><lease_secs:4><source:1>
    if (params.len < 14) return "{\"ok\":false,\"error\":\"invalid format\"}";
    const proto: util.Protocol = if (params[0] == 0) .tcp else .udp;
    const wan_port = util.readU16Be(params[1..3]);
    const lan_ip = params[3..7].*;
    const lan_port = util.readU16Be(params[7..9]);
    const lease_secs = @as(u32, params[9]) << 24 | @as(u32, params[10]) << 16 | @as(u32, params[11]) << 8 | @as(u32, params[12]);
    const source: firewall.PortFwdSource = switch (params[13]) {
        1 => .upnp,
        2 => .pcp,
        else => .manual,
    };
    const expiry_ns: u64 = if (lease_secs > 0) util.now() + @as(u64, lease_secs) * 1_000_000_000 else 0;
    if (firewall.portFwdAddLeased(&port_forwards, proto, wan_port, lan_ip, lan_port, expiry_ns, source))
        return "{\"ok\":true}";
    return "{\"ok\":false,\"error\":\"port forward table full\"}";
}

fn mutateUnforward(params: []const u8) []const u8 {
    // Format: <wan_port:2>
    if (params.len < 2) return "{\"ok\":false,\"error\":\"invalid format\"}";
    const wan_port = util.readU16Be(params[0..2]);
    // Try both protocols for backward compat (no proto in wire format)
    if (firewall.portFwdDelete(&port_forwards, .tcp, wan_port))
        return "{\"ok\":true}";
    if (firewall.portFwdDelete(&port_forwards, .udp, wan_port))
        return "{\"ok\":true}";
    return "{\"ok\":false,\"error\":\"forward not found\"}";
}

fn mutateDns(params: []const u8) []const u8 {
    if (params.len < 4) return "{\"ok\":false,\"error\":\"invalid ip\"}";
    upstream_dns = params[0..4].*;
    return "{\"ok\":true}";
}

fn mutateTimezone(params: []const u8) []const u8 {
    if (params.len < 2) return "{\"ok\":false,\"error\":\"invalid offset\"}";
    const offset: i16 = @bitCast([2]u8{ params[0], params[1] });
    if (offset < -840 or offset > 840) return "{\"ok\":false,\"error\":\"offset out of range\"}";
    tz_offset_minutes = offset;
    // Forward to NTP client
    if (ntp_chan) |chan| {
        chan.sendMessage(.B, &[_]u8{ ntp_proto.RESP_SET_TIMEZONE, params[0], params[1] }) catch {};
    }
    return "{\"ok\":true}";
}

/// LAN poll thread entry point. Polls LAN NIC, forwards to WAN via zero-copy.
fn lanPollThread() void {
    // Pin LAN thread to core 2 (non-preemptible)
    const affinity_ok = if (syscall.set_affinity(1 << 2)) |_| true else |_| false;
    if (affinity_ok) {
        syscall.thread_yield(); // migrate to core 2
        syscall.pin_exclusive() catch {};
    }

    while (true) {
        pollOnce(&lan_iface, &wan_iface, .lan);
    }
}
