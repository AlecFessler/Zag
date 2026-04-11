const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const dhcp_client = router.protocols.dhcp_client;
const dhcp_server = router.protocols.dhcp_server;
const dhcpv6_client = router.protocols.ipv6.dhcp_client;
const dma = router.hal.dma;
const dns = router.protocols.dns;
const firewall = router.protocols.ipv4.firewall;
const firewall6 = router.protocols.ipv6.firewall;
const frag = router.protocols.frag;
const iface_mod = router.hal.iface;
const nat = router.protocols.ipv4.nat;
const ndp = router.protocols.ipv6.ndp;
const nic = router.hal.nic;
const packet = router.packet;
const ping_mod = router.protocols.ipv4.icmp;
const service = router.service;
const udp_fwd = router.protocols.udp_fwd;
const util = router.util;

const channel = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const Channel = channel.Channel;

const MAX_PERMS = 128;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
pub const lan_subnet: [4]u8 = .{ 10, 1, 1, 0 };
pub const lan_mask: [4]u8 = .{ 255, 255, 255, 0 };
pub const lan_broadcast: [4]u8 = .{ 10, 1, 1, 255 };
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
pub var perm_view: ?*const [MAX_PERMS]pv.UserViewEntry = null;
pub var perm_view_addr_global: u64 = 0;

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

fn mmioMap(device_handle: u64, size: u64) ?u64 {
    const aligned = ((size + syscall.PAGE4K - 1) / syscall.PAGE4K) * syscall.PAGE4K;
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .mmio = true }).bits();
    const vm = syscall.mem_reserve(0, aligned, vm_rights) catch return null;
    syscall.mem_mmio_map(device_handle, vm.handle, 0) catch return null;
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
        rp = util.appendStr(&rbuf, rp, service.crashReasonName(reason));
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
    service.addKnownShmHandle(region.shm_handle);

    // Spawn service thread for console/NFS/NTP channel handling
    _ = syscall.thread_create(&service.serviceThread, 0, 4) catch 0;

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

    const action = packet.process(role, pkt, rx.len);
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
