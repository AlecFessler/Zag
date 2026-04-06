const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const dhcp_client = router.protocols.dhcp_client;
const dhcp_server = router.protocols.dhcp_server;
const dhcpv6_client = router.protocols.ipv6.dhcp_client;
const dns = router.protocols.dns;
const e1000 = router.hal.e1000;
const firewall = router.protocols.ipv4.firewall;
const firewall6 = router.protocols.ipv6.firewall;
const frag = router.protocols.frag;
const nat = router.protocols.ipv4.nat;
const ndp = router.protocols.ipv6.ndp;
const state = router.state;
const syscall = lib.syscall;
const udp_fwd = router.protocols.udp_fwd;

const Iface = router.hal.iface.Iface;
const Interface = state.Interface;
const PacketAction = state.PacketAction;

pub const WAN_MAC = [6]u8{ 0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01 };
pub const LAN_MAC = [6]u8{ 0xDE, 0xAD, 0x00, 0x00, 0x00, 0x02 };
pub const WAN_IP = [4]u8{ 10, 0, 2, 15 };
pub const LAN_IP = [4]u8{ 10, 1, 1, 1 };
pub const WAN_GATEWAY_IP = [4]u8{ 10, 0, 2, 1 };
pub const WAN_GATEWAY_MAC = [6]u8{ 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01 };

// LAN hosts pre-seeded in ARP table
pub const lan_hosts = [4]struct { ip: [4]u8, mac: [6]u8 }{
    .{ .ip = .{ 10, 1, 1, 100 }, .mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x64 } },
    .{ .ip = .{ 10, 1, 1, 101 }, .mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x65 } },
    .{ .ip = .{ 10, 1, 1, 102 }, .mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x66 } },
    .{ .ip = .{ 10, 1, 1, 103 }, .mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x67 } },
};

pub const InjectResult = struct {
    action: PacketAction,
    /// For forward actions: the modified input buffer IS the output.
    output_len: u32,
    /// Locally-generated reply captured from pending_tx_buf (ICMP reply, ARP reply, etc.)
    wan_reply: ?[]const u8,
    wan_reply_len: u16,
    lan_reply: ?[]const u8,
    lan_reply_len: u16,
    /// Pre-modification copy of the packet (before processPacket modified it in-place)
    pre_buf: [2048]u8 = undefined,
    pre_len: u32 = 0,
};

// Buffers to copy pending TX data into (since pending_tx_buf gets reused)
var wan_reply_buf: [e1000.PACKET_BUF_SIZE]u8 = undefined;
var lan_reply_buf: [e1000.PACKET_BUF_SIZE]u8 = undefined;

pub fn initRouter() void {
    // Initialize interfaces without DMA hardware
    state.wan_iface = makeIface(.wan, WAN_MAC, WAN_IP);
    state.lan_iface = makeIface(.lan, LAN_MAC, LAN_IP);
    state.has_lan = true;

    // Clear all tables
    state.nat_table = .{nat.empty} ** nat.TABLE_SIZE;
    state.next_nat_port = 10000;
    state.port_forwards = .{firewall.empty_fwd} ** firewall.PORT_FWD_SIZE;
    state.firewall_rules = .{firewall.empty_rule} ** firewall.RULES_SIZE;
    state.dns_relays = .{dns.empty} ** dns.RELAY_SIZE;
    state.dns_cache = .{dns.empty_cache} ** dns.CACHE_SIZE;
    state.next_dns_id = 1;
    state.upstream_dns = .{ 10, 0, 2, 1 };
    state.wan_gateway = WAN_GATEWAY_IP;
    state.dhcp_leases = .{dhcp_server.empty} ** dhcp_server.TABLE_SIZE;
    state.dhcp_static_leases = .{dhcp_server.empty_static} ** dhcp_server.STATIC_TABLE_SIZE;
    state.dhcp_next_ip = 100;
    state.dhcp_client_state = .idle;
    state.wan_ip_static = true;
    state.ping_state = .idle;
    state.traceroute_state = .idle;
    state.frag_table = .{frag.empty} ** frag.TABLE_SIZE;
    state.udp_bindings = .{udp_fwd.UdpBinding{}} ** udp_fwd.MAX_BINDINGS;
    state.pending_udp = .{udp_fwd.PendingPacket{}} ** udp_fwd.MAX_PENDING;
    state.console_chan = null;
    state.nfs_chan = null;
    state.ntp_chan = null;
    state.http_chan = null;

    // IPv6 state
    state.wan_ndp_table = .{ndp.empty} ** ndp.TABLE_SIZE;
    state.lan_ndp_table = .{ndp.empty} ** ndp.TABLE_SIZE;
    state.conn6_table = .{firewall6.empty} ** firewall6.CONN_TABLE_SIZE;
    state.dhcpv6_state = .idle;

    // Pre-seed ARP: gateway on WAN
    arp.learn(&state.wan_iface.arp_table, WAN_GATEWAY_IP, WAN_GATEWAY_MAC);

    // Pre-seed ARP: LAN hosts
    for (lan_hosts) |host| {
        arp.learn(&state.lan_iface.arp_table, host.ip, host.mac);
    }

    // Reset simulated clock
    syscall.fuzzer_clock_ns = 1_000_000_000; // start at 1 second
}

pub fn resetRouter() void {
    initRouter();
}

pub fn injectPacket(role: Interface, pkt: []u8, len: u32) InjectResult {
    // Save pre-modification copy for oracle comparison
    var result = InjectResult{
        .action = .consumed,
        .output_len = len,
        .wan_reply = null,
        .wan_reply_len = 0,
        .lan_reply = null,
        .lan_reply_len = 0,
        .pre_len = len,
    };
    if (len > 0) @memcpy(result.pre_buf[0..len], pkt[0..len]);

    // Reset pending TX rings on both interfaces
    state.wan_iface.pending_tx = .{ .{}, .{} };
    state.lan_iface.pending_tx = .{ .{}, .{} };

    // Call the router's packet processing
    const action = state.processPacket(role, pkt, len);
    result.action = action;

    // Capture replies from pending TX rings (check both rings per interface)
    inline for (0..2) |ring_idx| {
        const wan_ring = &state.wan_iface.pending_tx[ring_idx];
        const wan_head = @as(*volatile u64, &wan_ring.head).*;
        const wan_tail = @atomicLoad(u64, &wan_ring.tail, .acquire);
        if (wan_head != wan_tail) {
            const slot: usize = @intCast(wan_head % Iface.TX_RING_SLOTS);
            const rlen = wan_ring.lens[slot];
            @memcpy(wan_reply_buf[0..rlen], wan_ring.bufs[slot][0..rlen]);
            result.wan_reply = wan_reply_buf[0..rlen];
            result.wan_reply_len = rlen;
            @atomicStore(u64, &wan_ring.head, wan_head +% 1, .release);
        }
    }
    inline for (0..2) |ring_idx| {
        const lan_ring = &state.lan_iface.pending_tx[ring_idx];
        const lan_head = @as(*volatile u64, &lan_ring.head).*;
        const lan_tail = @atomicLoad(u64, &lan_ring.tail, .acquire);
        if (lan_head != lan_tail) {
            const slot: usize = @intCast(lan_head % Iface.TX_RING_SLOTS);
            const rlen = lan_ring.lens[slot];
            @memcpy(lan_reply_buf[0..rlen], lan_ring.bufs[slot][0..rlen]);
            result.lan_reply = lan_reply_buf[0..rlen];
            result.lan_reply_len = rlen;
            @atomicStore(u64, &lan_ring.head, lan_head +% 1, .release);
        }
    }

    return result;
}

pub fn advanceClock(ns: u64) void {
    // Saturate to prevent overflow — clock wrapping would break lease expiry logic
    const capped: i64 = if (ns > 0x7FFFFFFFFFFFFFFF) 0x7FFFFFFFFFFFFFFF else @intCast(ns);
    const result = @addWithOverflow(syscall.fuzzer_clock_ns, capped);
    syscall.fuzzer_clock_ns = if (result[1] != 0) 0x7FFFFFFFFFFFFFFF else result[0];
}

fn makeIface(role: router.hal.iface.Role, mac: [6]u8, ip: [4]u8) Iface {
    return .{
        .role = role,
        .mmio_base = 0,
        .mac = mac,
        .ip = ip,
        // DMA fields set to undefined — never accessed by processPacket
        .dma_base = 0,
        .dma_region = undefined,
        .rx_descs = undefined,
        .tx_descs = undefined,
        .rx_tail = 0,
        .tx_tail = 0,
        .rx_buf_state = .{.free} ** e1000.NUM_RX_DESC,
        .rx_buf_tx_idx = .{0} ** e1000.NUM_RX_DESC,
        .arp_table = .{arp.empty} ** arp.TABLE_SIZE,
        .stats = .{},
    };
}
