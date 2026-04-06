const lib = @import("lib");
const router = @import("router");

const firewall = router.protocols.ipv4.firewall;
const main = router.state;
const tcp_stack = router.protocols.tcp_stack;
const util = router.util;

const channel = lib.channel;
const http_proto = lib.http;
const ntp_proto = lib.ntp;

const Channel = channel.Channel;
const HttpServer = http_proto.Server;

pub fn handleMessage(data: []const u8, chan: *Channel, buf: []u8) void {
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
pub fn handleResponseStreaming(data: []const u8, is_complete: bool) void {
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
            return "{\"ok\":true}";
        }
    }
    return "{\"ok\":false,\"error\":\"firewall table full\"}";
}

fn mutateAllow(params: []const u8) []const u8 {
    const ip = util.parseIp(params) orelse return "{\"ok\":false,\"error\":\"invalid ip\"}";
    for (&main.firewall_rules) |*r| {
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
    for (&main.port_forwards) |*f| {
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
    if (firewall.portFwdAddLeased(&main.port_forwards, proto, wan_port, lan_ip, lan_port, expiry_ns, source))
        return "{\"ok\":true}";
    return "{\"ok\":false,\"error\":\"port forward table full\"}";
}

fn mutateUnforward(params: []const u8) []const u8 {
    // Format: <wan_port:2>
    if (params.len < 2) return "{\"ok\":false,\"error\":\"invalid format\"}";
    const wan_port = util.readU16Be(params[0..2]);
    // Try both protocols for backward compat (no proto in wire format)
    if (firewall.portFwdDelete(&main.port_forwards, .tcp, wan_port))
        return "{\"ok\":true}";
    if (firewall.portFwdDelete(&main.port_forwards, .udp, wan_port))
        return "{\"ok\":true}";
    return "{\"ok\":false,\"error\":\"forward not found\"}";
}

fn mutateDns(params: []const u8) []const u8 {
    if (params.len < 4) return "{\"ok\":false,\"error\":\"invalid ip\"}";
    main.upstream_dns = params[0..4].*;
    return "{\"ok\":true}";
}

fn mutateTimezone(params: []const u8) []const u8 {
    if (params.len < 2) return "{\"ok\":false,\"error\":\"invalid offset\"}";
    const offset: i16 = @bitCast([2]u8{ params[0], params[1] });
    if (offset < -840 or offset > 840) return "{\"ok\":false,\"error\":\"offset out of range\"}";
    main.tz_offset_minutes = offset;
    // Forward to NTP client
    if (main.ntp_chan) |chan| {
        chan.sendMessage(.B, &[_]u8{ ntp_proto.RESP_SET_TIMEZONE, params[0], params[1] }) catch {};
    }
    return "{\"ok\":true}";
}
