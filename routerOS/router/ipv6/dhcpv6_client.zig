const router = @import("router");

const main = router.state;
const util = router.util;

pub const Dhcpv6State = enum { idle, soliciting, requesting, bound };

pub const DelegatedPrefix = struct {
    prefix: [16]u8,
    prefix_len: u8,
    valid: bool,
    preferred_lifetime_ns: u64,
    valid_lifetime_ns: u64,
    bound_ns: u64,
};

pub const empty_prefix = DelegatedPrefix{
    .prefix = .{0} ** 16,
    .prefix_len = 0,
    .valid = false,
    .preferred_lifetime_ns = 0,
    .valid_lifetime_ns = 0,
    .bound_ns = 0,
};

// DHCPv6 message types
const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 2;
const REQUEST: u8 = 3;
const REPLY: u8 = 7;

// DHCPv6 option codes
const OPT_CLIENT_ID: u16 = 1;
const OPT_SERVER_ID: u16 = 2;
const OPT_IA_PD: u16 = 25;
const OPT_IA_PD_PREFIX: u16 = 26;
const OPT_ELAPSED_TIME: u16 = 8;

const ALL_DHCP_SERVERS: [16]u8 = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2 };

/// Build a DUID-LL (link-layer) from MAC.
fn writeDuidLL(buf: []u8, mac: [6]u8) usize {
    // DUID type 3 (DUID-LL), hardware type 1 (Ethernet)
    util.writeU16Be(buf[0..2], 3);
    util.writeU16Be(buf[2..4], 1);
    @memcpy(buf[4..10], &mac);
    return 10;
}

/// Send DHCPv6 Solicit with IA_PD requesting prefix delegation.
pub fn sendSolicit() void {
    var pkt: [200]u8 = undefined;
    @memset(&pkt, 0);

    const ifc = &main.wan_iface;
    const dst_mac = util.multicastMac6(ALL_DHCP_SERVERS);

    // Ethernet
    @memcpy(pkt[0..6], &dst_mac);
    @memcpy(pkt[6..12], &ifc.mac);
    pkt[12] = 0x86;
    pkt[13] = 0xDD;

    // IPv6 header
    pkt[14] = 0x60;
    pkt[20] = 17; // UDP
    pkt[21] = 255;
    @memcpy(pkt[22..38], &ifc.ip6_link_local);
    @memcpy(pkt[38..54], &ALL_DHCP_SERVERS);

    // UDP header at offset 54
    util.writeU16Be(pkt[54..56], 546); // src port
    util.writeU16Be(pkt[56..58], 547); // dst port

    // DHCPv6 message at offset 62
    var pos: usize = 62;
    pkt[pos] = SOLICIT;
    pkt[pos + 1] = @truncate(main.dhcpv6_xid >> 16);
    pkt[pos + 2] = @truncate(main.dhcpv6_xid >> 8);
    pkt[pos + 3] = @truncate(main.dhcpv6_xid);
    pos += 4;

    // Client ID option
    util.writeU16Be(pkt[pos..][0..2], OPT_CLIENT_ID);
    const duid_len = writeDuidLL(pkt[pos + 4 ..], ifc.mac);
    util.writeU16Be(pkt[pos + 2 ..][0..2], @truncate(duid_len));
    pos += 4 + duid_len;

    // Elapsed time option
    util.writeU16Be(pkt[pos..][0..2], OPT_ELAPSED_TIME);
    util.writeU16Be(pkt[pos + 2 ..][0..2], 2);
    util.writeU16Be(pkt[pos + 4 ..][0..2], 0);
    pos += 6;

    // IA_PD option (requesting prefix delegation)
    util.writeU16Be(pkt[pos..][0..2], OPT_IA_PD);
    util.writeU16Be(pkt[pos + 2 ..][0..2], 12); // length: IAID(4) + T1(4) + T2(4)
    // IAID = 1
    pkt[pos + 7] = 1;
    pos += 16;

    // Fill lengths
    const udp_len: u16 = @truncate(pos - 54);
    util.writeU16Be(pkt[58..60], udp_len);
    util.writeU16Be(pkt[18..20], udp_len); // IPv6 payload = UDP

    const total_len = pos;
    _ = ifc.txSendLocal(pkt[0..total_len]);
    main.dhcpv6_state = .soliciting;
    main.dhcpv6_start_ns = util.now();
    util.logEvent("dhcpv6: sent SOLICIT\n");
}

/// Handle DHCPv6 response (Advertise or Reply).
pub fn handleResponse(pkt: []const u8, len: u32) void {
    if (len < 66) return; // eth(14) + ipv6(40) + udp(8) + dhcpv6(4)

    const msg_type = pkt[62];
    const xid = @as(u32, pkt[63]) << 16 | @as(u32, pkt[64]) << 8 | pkt[65];
    if (xid != main.dhcpv6_xid) return;

    // Parse options
    var pos: usize = 66;
    while (pos + 4 <= len) {
        const opt_code = util.readU16Be(pkt[pos..][0..2]);
        const opt_len: usize = util.readU16Be(pkt[pos + 2 ..][0..2]);
        pos += 4;
        if (pos + opt_len > len) break;

        if (opt_code == OPT_SERVER_ID and opt_len <= 128) {
            @memcpy(main.dhcpv6_server_duid[0..opt_len], pkt[pos..][0..opt_len]);
            main.dhcpv6_server_duid_len = @truncate(opt_len);
        }
        if (opt_code == OPT_IA_PD and opt_len >= 12) {
            // Parse IA_PD sub-options for prefix
            var sub_pos = pos + 12; // skip IAID + T1 + T2
            while (sub_pos + 4 <= pos + opt_len) {
                const sub_code = util.readU16Be(pkt[sub_pos..][0..2]);
                const sub_len: usize = util.readU16Be(pkt[sub_pos + 2 ..][0..2]);
                sub_pos += 4;
                if (sub_pos + sub_len > pos + opt_len) break;

                if (sub_code == OPT_IA_PD_PREFIX and sub_len >= 25) {
                    // preferred(4) + valid(4) + prefix_len(1) + prefix(16)
                    const pref_lt = @as(u32, pkt[sub_pos]) << 24 | @as(u32, pkt[sub_pos + 1]) << 16 |
                        @as(u32, pkt[sub_pos + 2]) << 8 | pkt[sub_pos + 3];
                    const valid_lt = @as(u32, pkt[sub_pos + 4]) << 24 | @as(u32, pkt[sub_pos + 5]) << 16 |
                        @as(u32, pkt[sub_pos + 6]) << 8 | pkt[sub_pos + 7];
                    const plen = pkt[sub_pos + 8];
                    @memcpy(&main.delegated_prefix.prefix, pkt[sub_pos + 9 ..][0..16]);
                    main.delegated_prefix.prefix_len = plen;
                    main.delegated_prefix.preferred_lifetime_ns = @as(u64, pref_lt) * 1_000_000_000;
                    main.delegated_prefix.valid_lifetime_ns = @as(u64, valid_lt) * 1_000_000_000;
                }
                sub_pos += sub_len;
            }
        }
        pos += opt_len;
    }

    if (msg_type == ADVERTISE and main.dhcpv6_state == .soliciting) {
        util.logEvent("dhcpv6: received ADVERTISE\n");
        sendRequest();
    } else if (msg_type == REPLY and (main.dhcpv6_state == .requesting or main.dhcpv6_state == .bound)) {
        main.dhcpv6_state = .bound;
        main.delegated_prefix.valid = true;
        main.delegated_prefix.bound_ns = util.now();

        // Compute global addresses from prefix
        main.wan_iface.ip6_global = util.prefixToGlobal(
            main.delegated_prefix.prefix,
            main.delegated_prefix.prefix_len,
            main.wan_iface.mac,
        );
        main.wan_iface.ip6_global_valid = true;

        if (main.has_lan) {
            main.lan_iface.ip6_global = util.prefixToGlobal(
                main.delegated_prefix.prefix,
                main.delegated_prefix.prefix_len,
                main.lan_iface.mac,
            );
            main.lan_iface.ip6_global_valid = true;
        }

        util.logEvent("dhcpv6: bound, prefix delegated\n");
    }
}

fn sendRequest() void {
    var pkt: [250]u8 = undefined;
    @memset(&pkt, 0);

    const ifc = &main.wan_iface;
    const dst_mac = util.multicastMac6(ALL_DHCP_SERVERS);

    @memcpy(pkt[0..6], &dst_mac);
    @memcpy(pkt[6..12], &ifc.mac);
    pkt[12] = 0x86;
    pkt[13] = 0xDD;
    pkt[14] = 0x60;
    pkt[20] = 17;
    pkt[21] = 255;
    @memcpy(pkt[22..38], &ifc.ip6_link_local);
    @memcpy(pkt[38..54], &ALL_DHCP_SERVERS);

    util.writeU16Be(pkt[54..56], 546);
    util.writeU16Be(pkt[56..58], 547);

    var pos: usize = 62;
    pkt[pos] = REQUEST;
    pkt[pos + 1] = @truncate(main.dhcpv6_xid >> 16);
    pkt[pos + 2] = @truncate(main.dhcpv6_xid >> 8);
    pkt[pos + 3] = @truncate(main.dhcpv6_xid);
    pos += 4;

    // Client ID
    util.writeU16Be(pkt[pos..][0..2], OPT_CLIENT_ID);
    const duid_len = writeDuidLL(pkt[pos + 4 ..], ifc.mac);
    util.writeU16Be(pkt[pos + 2 ..][0..2], @truncate(duid_len));
    pos += 4 + duid_len;

    // Server ID
    if (main.dhcpv6_server_duid_len > 0) {
        const slen: usize = main.dhcpv6_server_duid_len;
        util.writeU16Be(pkt[pos..][0..2], OPT_SERVER_ID);
        util.writeU16Be(pkt[pos + 2 ..][0..2], @truncate(slen));
        @memcpy(pkt[pos + 4 ..][0..slen], main.dhcpv6_server_duid[0..slen]);
        pos += 4 + slen;
    }

    // IA_PD
    util.writeU16Be(pkt[pos..][0..2], OPT_IA_PD);
    util.writeU16Be(pkt[pos + 2 ..][0..2], 12);
    pkt[pos + 7] = 1;
    pos += 16;

    const udp_len: u16 = @truncate(pos - 54);
    util.writeU16Be(pkt[58..60], udp_len);
    util.writeU16Be(pkt[18..20], udp_len);

    _ = ifc.txSendLocal(pkt[0..pos]);
    main.dhcpv6_state = .requesting;
    main.dhcpv6_start_ns = util.now();
    util.logEvent("dhcpv6: sent REQUEST\n");
}

pub fn tick() void {
    const now = util.now();
    if (main.dhcpv6_state == .bound) {
        // Renew at 50% of valid lifetime
        if (main.delegated_prefix.valid_lifetime_ns > 0) {
            const t1 = main.delegated_prefix.valid_lifetime_ns / 2;
            if (now -% main.delegated_prefix.bound_ns > t1) {
                util.logEvent("dhcpv6: T1 renewal\n");
                main.dhcpv6_xid +%= 1;
                sendRequest();
            }
        }
        return;
    }
    if (main.dhcpv6_state == .idle) return;
    if (now -% main.dhcpv6_start_ns > 10_000_000_000) {
        util.logEvent("dhcpv6: timeout, retrying\n");
        main.dhcpv6_xid +%= 1;
        sendSolicit();
    }
}
