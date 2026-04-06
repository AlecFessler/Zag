const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const dhcp_client = router.protocols.dhcp_client;
const dhcp_server = router.protocols.dhcp_server;
const dhcpv6_client = router.protocols.ipv6.dhcp_client;
const firewall = router.protocols.ipv4.firewall;
const main = router.state;
const nat = router.protocols.ipv4.nat;
const ping_mod = router.protocols.ipv4.icmp;
const util = router.util;

const channel = lib.channel;
const text_cmd = lib.text_command;

const Channel = channel.Channel;

pub fn handleCommand(chan: *Channel, cmd: []const u8) void {
    if (cmd.len == 0) return;
    const srv = text_cmd.Server.init(chan);
    var resp: [512]u8 = undefined;

    if (util.eql(cmd, "status")) {
        var p: usize = 0;
        p = util.appendStr(&resp, p, "WAN: ");
        p = util.appendIp(&resp, p, main.wan_iface.ip);
        p = util.appendStr(&resp, p, " gw=");
        p = util.appendIp(&resp, p, main.wan_gateway);
        p = util.appendStr(&resp, p, " mac=");
        p = util.appendMac(&resp, p, main.wan_iface.mac);
        if (main.has_lan) {
            p = util.appendStr(&resp, p, "\nLAN: ");
            p = util.appendIp(&resp, p, main.lan_iface.ip);
            p = util.appendStr(&resp, p, " mac=");
            p = util.appendMac(&resp, p, main.lan_iface.mac);
        }
        srv.sendText(resp[0..p]);
        srv.sendEnd();
    } else if (util.eql(cmd, "ifstat")) {
        var p: usize = 0;
        p = util.appendStr(&resp, p, "WAN rx=");
        p = util.appendDec(&resp, p, main.wan_iface.stats.rx_packets);
        p = util.appendStr(&resp, p, " tx=");
        p = util.appendDec(&resp, p, main.wan_iface.stats.tx_packets);
        p = util.appendStr(&resp, p, " drop=");
        p = util.appendDec(&resp, p, main.wan_iface.stats.rx_dropped);
        if (main.has_lan) {
            p = util.appendStr(&resp, p, "\nLAN rx=");
            p = util.appendDec(&resp, p, main.lan_iface.stats.rx_packets);
            p = util.appendStr(&resp, p, " tx=");
            p = util.appendDec(&resp, p, main.lan_iface.stats.tx_packets);
            p = util.appendStr(&resp, p, " drop=");
            p = util.appendDec(&resp, p, main.lan_iface.stats.rx_dropped);
        }
        srv.sendText(resp[0..p]);
        srv.sendEnd();
    } else if (util.eql(cmd, "arp")) {
        sendArpTable(chan, "WAN", &main.wan_iface.arp_table);
        if (main.has_lan) sendArpTable(chan, "LAN", &main.lan_iface.arp_table);
        srv.sendEnd();
    } else if (util.eql(cmd, "nat")) {
        var count: u32 = 0;
        for (&main.nat_table) |*e| {
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
        for (&main.dhcp_leases) |*l| {
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
        for (&main.firewall_rules) |*r| {
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
        for (&main.port_forwards) |*f| {
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
        main.ping_target_ip = ip;
        main.ping_seq = 0;
        main.ping_count = 0;
        main.ping_received = 0;
        main.ping_iface = if (main.isInLanSubnet(ip)) .lan else .wan;
        const ifc = main.getIface(main.ping_iface);
        if (arp.lookup(&ifc.arp_table, ip)) |mac| {
            @memcpy(&main.ping_target_mac, &mac);
            ping_mod.sendEchoRequest();
        } else {
            main.ping_state = .arp_pending;
            main.ping_start_ns = util.now();
            arp.sendRequest(main.ping_iface, ip);
        }
    } else if (util.startsWith(cmd, "traceroute ")) {
        if (main.traceroute_state != .idle) {
            srv.sendText("traceroute already in progress");
            srv.sendEnd();
            return;
        }
        const ip = util.parseIp(cmd[11..]) orelse {
            srv.sendText("invalid IP");
            srv.sendEnd();
            return;
        };
        main.traceroute_target_ip = ip;
        main.traceroute_ttl = 1;
        main.traceroute_iface = if (main.isInLanSubnet(ip)) .lan else .wan;
        const ifc = main.getIface(main.traceroute_iface);
        // Send header line
        var p: usize = 0;
        p = util.appendStr(&resp, p, "traceroute to ");
        p = util.appendIp(&resp, p, ip);
        p = util.appendStr(&resp, p, ", ");
        p = util.appendDec(&resp, p, main.traceroute_max_hops);
        p = util.appendStr(&resp, p, " hops max");
        srv.sendText(resp[0..p]);
        // Resolve MAC and send first probe
        if (arp.lookup(&ifc.arp_table, ip)) |mac| {
            @memcpy(&main.traceroute_target_mac, &mac);
            ping_mod.sendTracerouteProbe();
        } else {
            // For traceroute, we route through the gateway, so use gateway MAC
            if (main.traceroute_iface == .wan) {
                if (arp.lookup(&ifc.arp_table, main.wan_gateway)) |gw_mac| {
                    @memcpy(&main.traceroute_target_mac, &gw_mac);
                    ping_mod.sendTracerouteProbe();
                } else {
                    main.traceroute_state = .arp_pending;
                    main.traceroute_start_ns = util.now();
                    arp.sendRequest(main.traceroute_iface, main.wan_gateway);
                }
            } else {
                main.traceroute_state = .arp_pending;
                main.traceroute_start_ns = util.now();
                arp.sendRequest(main.traceroute_iface, ip);
            }
        }
    } else if (util.startsWith(cmd, "block ")) {
        const ip = util.parseIp(cmd[6..]) orelse {
            srv.sendText("invalid IP");
            srv.sendEnd();
            return;
        };
        for (&main.firewall_rules) |*r| {
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
        for (&main.firewall_rules) |*r| {
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
        for (&main.port_forwards) |*f| {
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
        main.upstream_dns = ip;
        srv.sendText("OK");
        srv.sendEnd();
    } else if (util.eql(cmd, "dhcp-client")) {
        var p: usize = 0;
        const state_str: []const u8 = switch (main.dhcp_client_state) {
            .idle => "idle",
            .discovering => "discovering",
            .requesting => "requesting",
            .bound => "bound",
            .rebinding => "rebinding",
        };
        p = util.appendStr(&resp, p, "DHCP client: ");
        p = util.appendStr(&resp, p, state_str);
        if (main.dhcp_client_state == .idle) {
            dhcp_client.sendDiscover();
            main.dhcp_client_state = .discovering;
            main.dhcp_client_start_ns = util.now();
            p = util.appendStr(&resp, p, " -> discovering");
        }
        srv.sendText(resp[0..p]);
        srv.sendEnd();
    } else if (util.eql(cmd, "dhcp-test-rebind")) {
        if (main.dhcp_client_state == .bound or main.dhcp_client_state == .requesting) {
            main.dhcp_client_xid +%= 1;
            dhcp_client.sendRebind();
            srv.sendText("rebinding");
        } else {
            srv.sendText("not bound");
        }
        srv.sendEnd();
    } else if (util.eql(cmd, "dhcpv6")) {
        var p: usize = 0;
        const state_str: []const u8 = switch (main.dhcpv6_state) {
            .idle => "idle",
            .soliciting => "soliciting",
            .requesting => "requesting",
            .bound => "bound",
        };
        p = util.appendStr(&resp, p, "DHCPv6: ");
        p = util.appendStr(&resp, p, state_str);
        if (main.dhcpv6_state != .bound) {
            dhcpv6_client.sendSolicit();
            p = util.appendStr(&resp, p, " -> soliciting");
        }
        srv.sendText(resp[0..p]);
        srv.sendEnd();
    } else if (util.eql(cmd, "static-leases")) {
        var count: u32 = 0;
        for (&main.dhcp_static_leases) |*s| {
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
        for (&main.dhcp_static_leases) |*s| {
            if (@atomicLoad(u8, &s.state, .acquire) != 0 and (util.eql(&s.mac, &mac) or util.eql(&s.ip, &ip))) {
                srv.sendText("conflict: MAC or IP already reserved");
                srv.sendEnd();
                return;
            }
        }
        for (&main.dhcp_static_leases) |*s| {
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
        if (!util.eql(&main.upstream_dns, &[4]u8{ 10, 0, 2, 1 })) {
            var p: usize = 0;
            p = util.appendStr(&resp, p, "dns ");
            p = util.appendIp(&resp, p, main.upstream_dns);
            srv.sendText(resp[0..p]);
        }
        // Firewall block rules
        for (&main.firewall_rules) |*r| {
            if (!r.valid) continue;
            var p: usize = 0;
            p = util.appendStr(&resp, p, "block ");
            p = util.appendIp(&resp, p, r.src_ip);
            srv.sendText(resp[0..p]);
        }
        // Port forwards
        for (&main.port_forwards) |*f| {
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
        for (&main.dhcp_static_leases) |*s| {
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
