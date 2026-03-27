const router = @import("router");

const firewall = router.ipv4.firewall;
const h = router.net.headers;
const main = router.state;
const util = router.util;

pub const PCP_PORT: u16 = 5351;

// PCP constants (RFC 6887)
const PCP_VERSION: u8 = 2;
const OPCODE_MAP: u8 = 1;
const OPCODE_PEER: u8 = 2;

// PCP result codes
const RESULT_SUCCESS: u8 = 0;
const RESULT_UNSUPP_VERSION: u8 = 1;
const RESULT_NOT_AUTHORIZED: u8 = 2;
const RESULT_MALFORMED_REQUEST: u8 = 3;
const RESULT_UNSUPP_OPCODE: u8 = 4;
const RESULT_NO_RESOURCES: u8 = 8;

// PCP header offsets (request)
const HDR_VERSION: usize = 0;
const HDR_OPCODE: usize = 1; // R(1 bit) + Opcode(7 bits)
const HDR_LIFETIME: usize = 4; // 4 bytes BE
const HDR_CLIENT_IP: usize = 8; // 16 bytes (v4-mapped for IPv4)
const HDR_LEN: usize = 24;

// MAP opcode offsets (after header)
const MAP_NONCE: usize = 0; // 12 bytes
const MAP_PROTOCOL: usize = 12; // 1 byte (IANA protocol number)
const MAP_RESERVED: usize = 13; // 3 bytes
const MAP_INTERNAL_PORT: usize = 16; // 2 bytes BE
const MAP_EXTERNAL_PORT: usize = 18; // 2 bytes BE
const MAP_EXTERNAL_IP: usize = 20; // 16 bytes (v4-mapped)
const MAP_LEN: usize = 36;

const MIN_LEASE: u32 = 120;
const MAX_LEASE: u32 = 7200;

pub fn handleRequest(pkt: []u8, len: u32) void {
    const eth_ip_udp = h.EthernetHeader.LEN + 20 + 8; // 14 + 20 + 8 = 42
    if (len < eth_ip_udp + HDR_LEN) return;

    const payload = pkt[eth_ip_udp..len];
    if (payload.len < HDR_LEN) return;

    // Parse IP/UDP headers for response
    const ip = h.Ipv4Header.parseMut(pkt[14..]) orelse return;
    const ip_hdr_len = ip.headerLen();
    const udp_start = 14 + ip_hdr_len;
    if (udp_start + 8 > len) return;

    const src_ip = ip.src_ip;
    const src_mac = pkt[6..12].*;
    const src_port = util.readU16Be(pkt[udp_start..][0..2]);

    const pcp_data = pkt[udp_start + 8 .. len];
    if (pcp_data.len < HDR_LEN) return;

    const version = pcp_data[HDR_VERSION];
    const opcode_byte = pcp_data[HDR_OPCODE];
    const is_response = (opcode_byte & 0x80) != 0;
    if (is_response) return; // Ignore responses
    const opcode = opcode_byte & 0x7F;

    if (version != PCP_VERSION) {
        sendResponse(src_ip, src_mac, src_port, opcode, RESULT_UNSUPP_VERSION, 0, pcp_data);
        return;
    }

    switch (opcode) {
        OPCODE_MAP => handleMap(src_ip, src_mac, src_port, pcp_data),
        else => sendResponse(src_ip, src_mac, src_port, opcode, RESULT_UNSUPP_OPCODE, 0, pcp_data),
    }
}

fn handleMap(src_ip: [4]u8, src_mac: [6]u8, src_port: u16, pcp_data: []const u8) void {
    if (pcp_data.len < HDR_LEN + MAP_LEN) {
        sendResponse(src_ip, src_mac, src_port, OPCODE_MAP, RESULT_MALFORMED_REQUEST, 0, pcp_data);
        return;
    }

    const lifetime = readU32Be(pcp_data[HDR_LIFETIME..][0..4]);
    const map_data = pcp_data[HDR_LEN..];

    const protocol_num = map_data[MAP_PROTOCOL];
    const internal_port = util.readU16Be(map_data[MAP_INTERNAL_PORT..][0..2]);
    var external_port = util.readU16Be(map_data[MAP_EXTERNAL_PORT..][0..2]);

    // Convert IANA protocol to our Protocol enum
    const proto: util.Protocol = switch (protocol_num) {
        6 => .tcp,
        17 => .udp,
        else => {
            sendResponse(src_ip, src_mac, src_port, OPCODE_MAP, RESULT_MALFORMED_REQUEST, 0, pcp_data);
            return;
        },
    };

    // Delete mapping
    if (lifetime == 0) {
        if (external_port != 0) {
            _ = firewall.portFwdDelete(&main.port_forwards, proto, external_port);
        }
        sendMapResponse(src_ip, src_mac, src_port, RESULT_SUCCESS, 0, protocol_num, internal_port, external_port, pcp_data);
        return;
    }

    // Clamp lifetime per RFC 6887
    const clamped_lifetime = if (lifetime < MIN_LEASE) MIN_LEASE else if (lifetime > MAX_LEASE) MAX_LEASE else lifetime;

    // Use suggested external port, or pick one if 0
    if (external_port == 0) {
        external_port = internal_port;
    }

    // Check if port is already in use by a different mapping
    if (firewall.portFwdLookup(&main.port_forwards, proto, external_port)) |existing| {
        // If same client, update in place
        if (!util.eql(&existing.lan_ip, &src_ip) or existing.lan_port != internal_port) {
            // Port conflict — try to find an available port
            external_port = findAvailablePort(proto, internal_port);
            if (external_port == 0) {
                sendResponse(src_ip, src_mac, src_port, OPCODE_MAP, RESULT_NO_RESOURCES, 0, pcp_data);
                return;
            }
        } else {
            // Same mapping — delete old and re-add with new lease
            _ = firewall.portFwdDelete(&main.port_forwards, proto, external_port);
        }
    }

    const expiry_ns = util.now() + @as(u64, clamped_lifetime) * 1_000_000_000;
    if (!firewall.portFwdAddLeased(&main.port_forwards, proto, external_port, src_ip, internal_port, expiry_ns, .pcp)) {
        sendResponse(src_ip, src_mac, src_port, OPCODE_MAP, RESULT_NO_RESOURCES, 0, pcp_data);
        return;
    }

    sendMapResponse(src_ip, src_mac, src_port, RESULT_SUCCESS, clamped_lifetime, protocol_num, internal_port, external_port, pcp_data);
}

fn findAvailablePort(proto: util.Protocol, preferred: u16) u16 {
    // Try preferred first, then scan upward
    var port: u16 = if (preferred >= 1024) preferred else 1024;
    var attempts: u16 = 0;
    while (attempts < 100) : (attempts += 1) {
        if (firewall.portFwdLookup(&main.port_forwards, proto, port) == null) {
            return port;
        }
        port +%= 1;
        if (port < 1024) port = 1024;
    }
    return 0;
}

fn sendMapResponse(dst_ip: [4]u8, dst_mac: [6]u8, dst_port: u16, result_code: u8, lifetime: u32, protocol: u8, internal_port: u16, external_port: u16, req_data: []const u8) void {
    // Build PCP MAP response
    var pcp_resp: [HDR_LEN + MAP_LEN]u8 = .{0} ** (HDR_LEN + MAP_LEN);

    // Header
    pcp_resp[HDR_VERSION] = PCP_VERSION;
    pcp_resp[HDR_OPCODE] = 0x80 | OPCODE_MAP; // Response bit + opcode
    pcp_resp[2] = 0; // Reserved
    pcp_resp[3] = result_code;
    writeU32Be(pcp_resp[HDR_LIFETIME..][0..4], lifetime);
    // Epoch time — seconds since start (use monotonic clock approximation)
    const epoch = @as(u32, @truncate(util.now() / 1_000_000_000));
    writeU32Be(pcp_resp[HDR_CLIENT_IP..][0..4], epoch);

    // MAP opcode data
    var map_resp = pcp_resp[HDR_LEN..];
    // Copy nonce from request
    if (req_data.len >= HDR_LEN + MAP_NONCE + 12) {
        @memcpy(map_resp[MAP_NONCE..][0..12], req_data[HDR_LEN + MAP_NONCE ..][0..12]);
    }
    map_resp[MAP_PROTOCOL] = protocol;
    util.writeU16Be(map_resp[MAP_INTERNAL_PORT..][0..2], internal_port);
    util.writeU16Be(map_resp[MAP_EXTERNAL_PORT..][0..2], external_port);
    // External IP — v4-mapped: ::ffff:x.x.x.x
    map_resp[MAP_EXTERNAL_IP + 10] = 0xff;
    map_resp[MAP_EXTERNAL_IP + 11] = 0xff;
    @memcpy(map_resp[MAP_EXTERNAL_IP + 12 ..][0..4], &main.wan_iface.ip);

    sendUdpResponse(dst_ip, dst_mac, dst_port, &pcp_resp);
}

fn sendResponse(dst_ip: [4]u8, dst_mac: [6]u8, dst_port: u16, opcode: u8, result_code: u8, lifetime: u32, req_data: []const u8) void {
    // Generic PCP error response (header only, echo opcode-specific data)
    const resp_len = if (req_data.len > HDR_LEN) @min(req_data.len, HDR_LEN + MAP_LEN) else HDR_LEN;
    var pcp_resp: [HDR_LEN + MAP_LEN]u8 = .{0} ** (HDR_LEN + MAP_LEN);

    pcp_resp[HDR_VERSION] = PCP_VERSION;
    pcp_resp[HDR_OPCODE] = 0x80 | opcode;
    pcp_resp[2] = 0;
    pcp_resp[3] = result_code;
    writeU32Be(pcp_resp[HDR_LIFETIME..][0..4], lifetime);
    const epoch = @as(u32, @truncate(util.now() / 1_000_000_000));
    writeU32Be(pcp_resp[HDR_CLIENT_IP..][0..4], epoch);

    // Copy opcode-specific data from request if present
    if (req_data.len > HDR_LEN and resp_len > HDR_LEN) {
        const copy_len = resp_len - HDR_LEN;
        @memcpy(pcp_resp[HDR_LEN..][0..copy_len], req_data[HDR_LEN..][0..copy_len]);
    }

    sendUdpResponse(dst_ip, dst_mac, dst_port, pcp_resp[0..resp_len]);
}

fn sendUdpResponse(dst_ip: [4]u8, dst_mac: [6]u8, dst_port: u16, payload: []const u8) void {
    const udp_len: u16 = @intCast(8 + payload.len);
    const ip_total: u16 = 20 + udp_len;
    const frame_len: usize = 14 + @as(usize, ip_total);

    var frame: [512]u8 = undefined;
    if (frame_len > frame.len) return;

    // Ethernet header
    @memcpy(frame[0..6], &dst_mac);
    @memcpy(frame[6..12], &main.lan_iface.mac);
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IP header
    const ip = h.Ipv4Header.parseMut(frame[14..]) orelse return;
    ip.ver_ihl = 0x45;
    ip.setTotalLen(ip_total);
    ip.ttl = 64;
    ip.protocol = h.Ipv4Header.PROTO_UDP;
    @memcpy(&ip.src_ip, &main.lan_iface.ip);
    @memcpy(&ip.dst_ip, &dst_ip);
    ip.computeAndSetChecksum(&frame);

    // UDP header
    const udp = h.UdpHeader.parseMut(frame[34..]) orelse return;
    udp.setSrcPort(PCP_PORT);
    udp.setDstPort(dst_port);
    udp.setLength(udp_len);
    udp.zeroChecksum();

    // Payload
    @memcpy(frame[42..][0..payload.len], payload);

    _ = main.lan_iface.txSendLocal(frame[0..frame_len]);
}

fn readU32Be(b: *const [4]u8) u32 {
    return @as(u32, b[0]) << 24 | @as(u32, b[1]) << 16 | @as(u32, b[2]) << 8 | @as(u32, b[3]);
}

fn writeU32Be(b: *[4]u8, v: u32) void {
    b[0] = @intCast(v >> 24);
    b[1] = @intCast((v >> 16) & 0xFF);
    b[2] = @intCast((v >> 8) & 0xFF);
    b[3] = @intCast(v & 0xFF);
}
