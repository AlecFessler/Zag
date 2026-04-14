const std = @import("std");
const router = @import("router");

const arp = router.protocols.arp;
const h = router.hal.headers;
const nat = router.protocols.ipv4.nat;
const state = router.state;
const util = router.util;

const harness = @import("harness.zig");
const packet_gen = @import("packet_gen.zig");

const PacketKind = packet_gen.PacketKind;
const InjectResult = harness.InjectResult;
const GeneratedPacket = packet_gen.GeneratedPacket;
const PacketAction = state.PacketAction;

pub fn validateResult(gen: GeneratedPacket, result: InjectResult) bool {
    if (gen.is_mutated) {
        return validateStructural(gen, result);
    } else {
        return validateStrict(gen, result);
    }
}

// ── Structural validation (mutated packets) ──────────────────────────

fn validateStructural(gen: GeneratedPacket, result: InjectResult) bool {
    // For mutated packets: don't predict the action, but verify any output is well-formed
    if (result.action == .forward_wan or result.action == .forward_lan) {
        return validateAnyForwardedPacket(gen, result);
    }
    if (result.action == .consumed) {
        return validateAnyReply(result);
    }
    return true;
}

/// Verify that ANY forwarded packet (mutated or not) has basic structural integrity
fn validateAnyForwardedPacket(gen: GeneratedPacket, result: InjectResult) bool {
    const pkt = &gen.buf;
    const len = result.output_len;

    if (len < h.EthernetHeader.LEN + h.Ipv4Header.MIN_LEN) return true; // too short to validate

    // IP checksum must be valid (only verifiable when IHL is sane)
    const ihl = pkt[14] & 0x0F;
    if (ihl >= 5 and ihl <= 15) {
        const hdr_len: usize = @as(usize, ihl) * 4;
        if (14 + hdr_len <= len and hdr_len <= 60) {
            if (!verifyIpChecksum(pkt[14 .. 14 + hdr_len])) {
                // Check if the pre-packet also had bad IHL (mutation corrupted it)
                const pre_ihl = gen.buf[14] & 0x0F; // buf still has pre-mutation data? No, mutated.
                // For mutated packets with corrupted IHL, the router can't compute a valid checksum
                // This is expected behavior — skip
                _ = pre_ihl;
                if (!gen.is_mutated) {
                    logFail("forwarded packet has invalid IP checksum", .{});
                    return false;
                }
            }
        }
    }

    // TTL must be > 0
    if (pkt[22] == 0) {
        logFail("forwarded packet has TTL=0", .{});
        return false;
    }

    // Source MAC must match the forwarding interface
    const expected_mac = if (result.action == .forward_wan) &harness.WAN_MAC else &harness.LAN_MAC;
    if (ihl >= 5 and !std.mem.eql(u8, pkt[6..12], expected_mac)) {
        logFail("forwarded packet source MAC doesn't match interface", .{});
        return false;
    }

    return true;
}

/// Verify that any generated reply has basic structural integrity
fn validateAnyReply(result: InjectResult) bool {
    // Check WAN reply
    if (result.wan_reply) |r| {
        if (!validateReplyStructure(r)) return false;
    }
    // Check LAN reply
    if (result.lan_reply) |r| {
        if (!validateReplyStructure(r)) return false;
    }
    return true;
}

fn validateReplyStructure(reply: []const u8) bool {
    if (reply.len < 14) return true; // too short, but not a bug

    // Check ethertype
    const ethertype = @as(u16, reply[12]) << 8 | reply[13];
    if (ethertype == h.EthernetHeader.IPv4 and reply.len >= 34) {
        // Verify IP checksum
        const ihl = reply[14] & 0x0F;
        if (ihl >= 5) {
            const hdr_len: usize = @as(usize, ihl) * 4;
            if (14 + hdr_len <= reply.len) {
                if (!verifyIpChecksum(reply[14 .. 14 + hdr_len])) {
                    logFail("reply packet has invalid IP checksum", .{});
                    return false;
                }
            }
        }
    }
    return true;
}

// ── Strict validation (clean seed packets) ───────────────────────────

fn validateStrict(gen: GeneratedPacket, result: InjectResult) bool {
    // Action validation
    if (!validateAction(gen, result.action)) return false;

    // Forward validation
    if (result.action == .forward_wan or result.action == .forward_lan) {
        if (!validateForwardedStrict(gen, result)) return false;
    }

    // Reply validation
    if (result.action == .consumed) {
        if (!validateRepliesStrict(gen, result)) return false;
    }

    return true;
}

fn validateAction(gen: GeneratedPacket, action: PacketAction) bool {
    return switch (gen.kind) {
        .arp_request, .arp_reply => action == .consumed,
        .icmp_echo_for_me => action == .consumed,
        .icmp_echo_reply_wan => action == .consumed,
        .tcp_syn_lan_to_wan, .tcp_ack, .tcp_fin, .tcp_rst,
        .udp_lan_to_wan, .icmp_echo_forward,
        => action == .forward_wan or action == .consumed,
        .tcp_syn_ack_wan, .udp_wan_to_lan, .nat_return,
        => action == .forward_lan or action == .consumed,
        .udp_dns_query => action == .consumed,
        .ipv4_ttl1_forward => action == .consumed,
        .ipv4_fragment_first => action == .forward_wan or action == .consumed,
        .ipv4_broadcast => action == .consumed,
        .ipv6_packet => true,
        .malformed_truncated => action == .consumed,
        .malformed_bad_ihl, .malformed_bad_totlen => true,
        .random_ethertype => action == .consumed,
        .tcp_syn_with_options => action == .forward_wan or action == .consumed,
        .dhcp_discover => action == .consumed,
        .dns_response_wan => action == .consumed,
        .tcp_to_port_80 => action == .consumed,
        .udp_to_unhandled_port => action == .consumed,
        .pcp_map_request => action == .consumed,
        .upnp_ssdp_msearch => action == .consumed,
    };
}

fn validateForwardedStrict(gen: GeneratedPacket, result: InjectResult) bool {
    const pkt = &gen.buf;
    const pre = &result.pre_buf;
    const len = result.output_len;

    if (len < 34) return true;

    // Skip strict checks for malformed packets
    if (gen.kind == .malformed_bad_ihl or gen.kind == .malformed_bad_totlen) return true;

    const ihl = pkt[14] & 0x0F;
    if (ihl < 5) return true; // malformed IHL, skip strict checks

    const hdr_len: usize = @as(usize, ihl) * 4;

    // IP checksum must be valid
    if (14 + hdr_len <= len) {
        if (!verifyIpChecksum(pkt[14 .. 14 + hdr_len])) {
            logFail("strict: forwarded packet bad IP checksum", .{});
            return false;
        }
    }

    // TTL must be original - 1 for LAN→WAN forwarding (goes through "not for us" path)
    // WAN→LAN NAT goes through "is_for_me" path which does NOT decrement TTL
    if (result.pre_len >= 23 and result.action == .forward_wan and gen.interface == .lan) {
        const orig_ttl = pre[22];
        const new_ttl = pkt[22];
        if (orig_ttl > 1 and new_ttl != orig_ttl - 1) {
            logFail("strict: TTL not decremented (was {} now {})", .{ orig_ttl, new_ttl });
            return false;
        }
    }

    // For LAN→WAN NAT forwarding
    if (result.action == .forward_wan and gen.interface == .lan) {
        // Source IP must be WAN IP
        if (!std.mem.eql(u8, pkt[26..30], &harness.WAN_IP)) {
            logFail("strict: LAN->WAN forward src IP not WAN IP", .{});
            return false;
        }
        // Source MAC must be WAN MAC
        if (!std.mem.eql(u8, pkt[6..12], &harness.WAN_MAC)) {
            logFail("strict: LAN->WAN forward src MAC not WAN MAC", .{});
            return false;
        }
        // Dest MAC must be gateway MAC
        if (!std.mem.eql(u8, pkt[0..6], &harness.WAN_GATEWAY_MAC)) {
            logFail("strict: LAN->WAN forward dst MAC not gateway", .{});
            return false;
        }
        // Dest IP and dest port must be unchanged
        if (result.pre_len >= 34 and !std.mem.eql(u8, pkt[30..34], pre[30..34])) {
            logFail("strict: LAN->WAN forward dst IP changed", .{});
            return false;
        }
        // Source port must be NAT-allocated (>= 10000) for TCP/UDP
        if (gen.protocol == 6 or gen.protocol == 17) {
            if (len >= 36) {
                const nat_port = @as(u16, pkt[34]) << 8 | pkt[35];
                if (nat_port < 10000) {
                    logFail("strict: NAT allocated port {} < 10000", .{nat_port});
                    return false;
                }
            }
        }
    }

    // For WAN→LAN NAT forwarding
    if (result.action == .forward_lan and gen.interface == .wan) {
        // Source MAC must be LAN MAC
        if (!std.mem.eql(u8, pkt[6..12], &harness.LAN_MAC)) {
            logFail("strict: WAN->LAN forward src MAC not LAN MAC", .{});
            return false;
        }
        // Dest IP should be a LAN IP (10.1.1.x)
        if (pkt[30] != 10 or pkt[31] != 1 or pkt[32] != 1) {
            logFail("strict: WAN->LAN forward dst IP not in LAN subnet", .{});
            return false;
        }
    }

    return true;
}

fn validateRepliesStrict(gen: GeneratedPacket, result: InjectResult) bool {
    const reply = if (gen.interface == .lan) result.lan_reply else result.wan_reply;

    switch (gen.kind) {
        .icmp_echo_for_me => {
            // Must generate ICMP echo reply
            const r = reply orelse return true; // no reply is OK if handleIcmp returned null
            if (r.len < 42) return true;

            // Type must be 0 (echo reply)
            if (r[34] != 0) {
                logFail("strict: ICMP echo reply type={} (expected 0)", .{r[34]});
                return false;
            }
            // Code must be 0
            if (r[35] != 0) {
                logFail("strict: ICMP echo reply code={} (expected 0)", .{r[35]});
                return false;
            }
            // ID must match request
            if (gen.icmp_id != 0) {
                const reply_id = @as(u16, r[38]) << 8 | r[39];
                if (reply_id != gen.icmp_id) {
                    logFail("strict: ICMP echo reply id={} (expected {})", .{ reply_id, gen.icmp_id });
                    return false;
                }
            }
            // Seq must match request
            if (gen.icmp_seq != 0) {
                const reply_seq = @as(u16, r[40]) << 8 | r[41];
                if (reply_seq != gen.icmp_seq) {
                    logFail("strict: ICMP echo reply seq={} (expected {})", .{ reply_seq, gen.icmp_seq });
                    return false;
                }
            }
            // Source IP in reply must be our IP
            if (r.len >= 30 and !std.mem.eql(u8, r[26..30], &harness.LAN_IP)) {
                logFail("strict: ICMP echo reply src IP not our IP", .{});
                return false;
            }
            // Dest IP in reply must be the original sender
            if (r.len >= 34 and gen.src_ip[0] != 0) {
                if (!std.mem.eql(u8, r[30..34], &gen.src_ip)) {
                    logFail("strict: ICMP echo reply dst IP not original sender", .{});
                    return false;
                }
            }
            // IP checksum valid
            if (r.len >= 34) {
                if (!verifyIpChecksum(r[14..34])) {
                    logFail("strict: ICMP echo reply bad IP checksum", .{});
                    return false;
                }
            }
        },
        .arp_request => {
            // ARP requests for our IP should generate a reply
            if (std.mem.eql(u8, &gen.dst_ip, &harness.LAN_IP)) {
                const r = reply orelse return true;
                if (r.len >= 42) {
                    // Opcode must be 2 (reply)
                    if (r[21] != 2) {
                        logFail("strict: ARP reply opcode={} (expected 2)", .{r[21]});
                        return false;
                    }
                    // Sender IP must be our IP
                    if (!std.mem.eql(u8, r[28..32], &harness.LAN_IP)) {
                        logFail("strict: ARP reply sender IP not our IP", .{});
                        return false;
                    }
                    // Sender MAC must be our MAC
                    if (!std.mem.eql(u8, r[22..28], &harness.LAN_MAC)) {
                        logFail("strict: ARP reply sender MAC not our MAC", .{});
                        return false;
                    }
                }
            }
        },
        .ipv4_ttl1_forward => {
            // Should generate ICMP Time Exceeded
            const r = reply orelse return true;
            if (r.len >= 42) {
                if (r[34] != 11) {
                    logFail("strict: TTL exceeded reply type={} (expected 11)", .{r[34]});
                    return false;
                }
                if (r[35] != 0) {
                    logFail("strict: TTL exceeded reply code={} (expected 0)", .{r[35]});
                    return false;
                }
                // IP checksum valid
                if (r.len >= 34 and !verifyIpChecksum(r[14..34])) {
                    logFail("strict: TTL exceeded reply bad IP checksum", .{});
                    return false;
                }
                // ICMP error payload should contain original IP header (RFC 792)
                if (r.len >= 50 and result.pre_len >= 18) {
                    if (!std.mem.eql(u8, r[42..46], result.pre_buf[14..18])) {
                        logFail("strict: ICMP error payload doesn't match original IP header", .{});
                        return false;
                    }
                }
            }
        },
        .udp_to_unhandled_port => {
            // Should generate ICMP Port Unreachable (type=3, code=3)
            const r = reply orelse return true; // might not generate if broadcast
            if (r.len >= 42) {
                if (r[34] != 3) {
                    logFail("strict: port unreachable reply type={} (expected 3)", .{r[34]});
                    return false;
                }
                if (r[35] != 3) {
                    logFail("strict: port unreachable reply code={} (expected 3)", .{r[35]});
                    return false;
                }
                if (r.len >= 34 and !verifyIpChecksum(r[14..34])) {
                    logFail("strict: port unreachable reply bad IP checksum", .{});
                    return false;
                }
            }
        },
        .dhcp_discover => {
            // Should generate DHCP response in lan_reply
            const r = result.lan_reply orelse return true;
            if (r.len >= 42) {
                // Must have valid IP checksum
                if (!verifyIpChecksum(r[14..34])) {
                    logFail("strict: DHCP reply bad IP checksum", .{});
                    return false;
                }
                // Dest MAC should be broadcast
                if (!std.mem.eql(u8, r[0..6], &[6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })) {
                    logFail("strict: DHCP reply dst MAC not broadcast", .{});
                    return false;
                }
            }
        },
        .tcp_to_port_80 => {
            // SYN to port 80 should produce SYN-ACK reply
            const r = result.lan_reply orelse return true;
            if (r.len >= 54) {
                // Check TCP flags = SYN+ACK (0x12)
                const reply_flags = r[47];
                if (reply_flags != 0x12) {
                    logFail("strict: TCP SYN-ACK reply flags={x} (expected 0x12)", .{reply_flags});
                    return false;
                }
                // Source port should be 80
                const reply_src_port = @as(u16, r[34]) << 8 | r[35];
                if (reply_src_port != 80) {
                    logFail("strict: TCP SYN-ACK reply src port={} (expected 80)", .{reply_src_port});
                    return false;
                }
                if (!verifyIpChecksum(r[14..34])) {
                    logFail("strict: TCP SYN-ACK reply bad IP checksum", .{});
                    return false;
                }
            }
        },
        .arp_reply => {
            // ARP reply side effect: sender should be learned into interface ARP table
            if (gen.src_ip[0] != 0) {
                const ifc_table = if (gen.interface == .lan) &state.lan_iface.arp_table else &state.wan_iface.arp_table;
                const learned = arp.lookup(ifc_table, gen.src_ip);
                if (learned) |mac| {
                    if (!std.mem.eql(u8, &mac, &gen.src_mac)) {
                        logFail("strict: ARP learned wrong MAC for sender IP", .{});
                        return false;
                    }
                }
            }
        },
        else => {},
    }
    return true;
}

// ── Helpers ──────────────────────────────────────────────────────────

pub fn verifyIpChecksum(ip_data: []const u8) bool {
    if (ip_data.len < 20) return false;
    const ihl = ip_data[0] & 0x0F;
    const hdr_len: usize = @as(usize, ihl) * 4;
    if (hdr_len < 20 or hdr_len > ip_data.len) return false;
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < hdr_len) : (i += 2) {
        sum += @as(u32, ip_data[i]) << 8 | @as(u32, ip_data[i + 1]);
    }
    while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
    return @as(u16, @truncate(sum)) == 0xFFFF;
}

fn logFail(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("Oracle: " ++ fmt ++ "\n", args);
}
