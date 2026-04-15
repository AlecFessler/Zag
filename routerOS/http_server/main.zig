const lib = @import("lib");

const channel = lib.channel;
const http_proto = lib.http;
const syscall = lib.syscall;

const Channel = channel.Channel;
const HttpClient = http_proto.Client;

// ── Configuration ───────────────────────────────────────────────────

const DEFAULT_SHM_SIZE = 4 * syscall.PAGE4K;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

// ── State ───────────────────────────────────────────────────────────

var router_chan: *Channel = undefined;
var http_client: HttpClient = undefined;

// ── Entry point ─────────────────────────────────────────────────────

pub fn main(perm_view_addr: u64) void {
    channel.perm_view_addr = perm_view_addr;

    // Broadcast as HTTP_SERVER
    channel.broadcast(@intFromEnum(lib.Protocol.http_server)) catch {};

    // Connect to router as side A via broadcast table
    var handle: u64 = 0;
    while (handle == 0) {
        handle = channel.findBroadcastHandle(perm_view_addr, .router) orelse 0;
        if (handle == 0) syscall.thread_yield();
    }
    router_chan = (Channel.connectAsA(handle, .http_server, DEFAULT_SHM_SIZE) catch return).chan;
    http_client = HttpClient.init(router_chan);

    // Main loop
    while (true) {
        var router_buf: [8192]u8 = undefined;
        if (http_client.recv(&router_buf)) |msg| {
            switch (msg) {
                .http_request => |data| handleHttpRequest(data),
                .state_response, .mutation_response => {},
            }
        } else {
            http_client.waitForMessage(10_000_000); // 10ms
        }
    }
}

// ── HTTP request parsing ────────────────────────────────────────────

fn handleHttpRequest(raw: []const u8) void {
    if (raw.len < 5) {
        sendHttpResponse("400 Bad Request", "text/plain", "Bad Request");
        return;
    }

    var method_end: usize = 0;
    while (method_end < raw.len and raw[method_end] != ' ') : (method_end += 1) {}
    if (method_end >= raw.len) {
        sendHttpResponse("400 Bad Request", "text/plain", "Bad Request");
        return;
    }
    const method = raw[0..method_end];
    const path_start = method_end + 1;

    var path_end: usize = path_start;
    while (path_end < raw.len and raw[path_end] != ' ' and raw[path_end] != '\r') : (path_end += 1) {}
    const path = raw[path_start..path_end];

    if (eql(method, "GET")) {
        handleGet(path);
    } else if (eql(method, "POST")) {
        handlePost(path, raw);
    } else {
        sendHttpResponse("405 Method Not Allowed", "text/plain", "Method Not Allowed");
    }
}

// ── GET handlers ────────────────────────────────────────────────────

fn handleGet(path: []const u8) void {
    if (eql(path, "/") or eql(path, "/index.html")) {
        sendHttpResponse("200 OK", "text/html", HTML_PAGE);
    } else if (eql(path, "/api/status")) {
        sendStateQueryResponse(http_proto.EP_STATUS);
    } else if (eql(path, "/api/ifstat")) {
        sendStateQueryResponse(http_proto.EP_IFSTAT);
    } else if (eql(path, "/api/arp")) {
        sendStateQueryResponse(http_proto.EP_ARP);
    } else if (eql(path, "/api/nat")) {
        sendStateQueryResponse(http_proto.EP_NAT);
    } else if (eql(path, "/api/leases")) {
        sendStateQueryResponse(http_proto.EP_LEASES);
    } else if (eql(path, "/api/rules")) {
        sendStateQueryResponse(http_proto.EP_RULES);
    } else if (eql(path, "/upnp/rootDesc.xml")) {
        sendHttpResponse("200 OK", "text/xml", UPNP_ROOT_DESC);
    } else if (eql(path, "/upnp/WANIPConn.xml")) {
        sendHttpResponse("200 OK", "text/xml", UPNP_WANIP_DESC);
    } else {
        sendHttpResponse("404 Not Found", "text/plain", "Not Found");
    }
}

fn sendStateQueryResponse(endpoint: u8) void {
    http_client.sendStateQuery(endpoint);

    var buf: [8192]u8 = undefined;
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        if (http_client.recv(&buf)) |msg| {
            switch (msg) {
                .state_response => |data| {
                    sendHttpResponse("200 OK", "application/json", data);
                    return;
                },
                else => {},
            }
        }
        http_client.waitForMessage(500_000_000); // 500ms
    }

    sendHttpResponse("503 Service Unavailable", "text/plain", "State query timeout");
}

// ── POST handlers ───────────────────────────────────────────────────

fn handlePost(path: []const u8, raw: []const u8) void {
    const block_prefix = "/api/block/";
    const allow_prefix = "/api/allow/";
    const forward_prefix = "/api/forward/";
    const unforward_prefix = "/api/unforward/";
    const dns_prefix = "/api/dns/";

    if (path.len > block_prefix.len and startsWith(path, block_prefix)) {
        const ip = parseIp(path[block_prefix.len..]) orelse return sendMutationError("invalid ip");
        var msg: [6]u8 = undefined;
        msg[0] = http_proto.CMD_MUTATION_REQUEST;
        msg[1] = http_proto.MUT_BLOCK;
        @memcpy(msg[2..6], &ip);
        sendMutationAndRespond(&msg);
    } else if (path.len > allow_prefix.len and startsWith(path, allow_prefix)) {
        const ip = parseIp(path[allow_prefix.len..]) orelse return sendMutationError("invalid ip");
        var msg: [6]u8 = undefined;
        msg[0] = http_proto.CMD_MUTATION_REQUEST;
        msg[1] = http_proto.MUT_ALLOW;
        @memcpy(msg[2..6], &ip);
        sendMutationAndRespond(&msg);
    } else if (path.len > forward_prefix.len and startsWith(path, forward_prefix)) {
        handleAddForward(path[forward_prefix.len..]);
    } else if (path.len > unforward_prefix.len and startsWith(path, unforward_prefix)) {
        handleRemoveForward(path[unforward_prefix.len..]);
    } else if (path.len > dns_prefix.len and startsWith(path, dns_prefix)) {
        const ip = parseIp(path[dns_prefix.len..]) orelse return sendMutationError("invalid ip");
        var msg: [6]u8 = undefined;
        msg[0] = http_proto.CMD_MUTATION_REQUEST;
        msg[1] = http_proto.MUT_DNS;
        @memcpy(msg[2..6], &ip);
        sendMutationAndRespond(&msg);
    } else if (startsWith(path, "/api/timezone/")) {
        const tz_prefix = "/api/timezone/";
        if (path.len > tz_prefix.len) {
            handleSetTimezone(path[tz_prefix.len..]);
        } else {
            sendMutationError("missing offset");
        }
    } else if (eql(path, "/upnp/control/WANIPConn1")) {
        handleSoapAction(raw);
    } else {
        sendHttpResponse("404 Not Found", "text/plain", "Not Found");
    }
}

fn handleAddForward(args: []const u8) void {
    // Expected: <proto>/<wport>/<lip>/<lport>
    var proto_byte: u8 = 0; // 0=tcp
    var i: usize = 0;

    if (startsWith(args, "tcp/")) {
        i = 4;
    } else if (startsWith(args, "udp/")) {
        proto_byte = 1;
        i = 4;
    } else return sendMutationError("invalid protocol");

    // Parse wan_port
    const wport = parseU16(args[i..]) orelse return sendMutationError("invalid wan port");
    i += wport.len;
    if (i >= args.len or args[i] != '/') return sendMutationError("invalid format");
    i += 1;

    // Parse lan_ip
    var ip_end = i;
    while (ip_end < args.len and args[ip_end] != '/') : (ip_end += 1) {}
    const lip = parseIp(args[i..ip_end]) orelse return sendMutationError("invalid lan ip");
    if (ip_end >= args.len) return sendMutationError("missing lan port");
    i = ip_end + 1;

    // Parse lan_port
    const lport = parseU16(args[i..]) orelse return sendMutationError("invalid lan port");

    // Build mutation: [MSG][http_proto.MUT_FORWARD][proto:1][wan_port:2][lan_ip:4][lan_port:2]
    var msg: [11]u8 = undefined;
    msg[0] = http_proto.CMD_MUTATION_REQUEST;
    msg[1] = http_proto.MUT_FORWARD;
    msg[2] = proto_byte;
    msg[3] = @intCast(wport.val >> 8);
    msg[4] = @intCast(wport.val & 0xff);
    @memcpy(msg[5..9], &lip);
    msg[9] = @intCast(lport.val >> 8);
    msg[10] = @intCast(lport.val & 0xff);
    sendMutationAndRespond(&msg);
}

fn handleRemoveForward(args: []const u8) void {
    const wport = parseU16(args) orelse return sendMutationError("invalid port");
    var msg: [4]u8 = undefined;
    msg[0] = http_proto.CMD_MUTATION_REQUEST;
    msg[1] = http_proto.MUT_UNFORWARD;
    msg[2] = @intCast(wport.val >> 8);
    msg[3] = @intCast(wport.val & 0xff);
    sendMutationAndRespond(&msg);
}

fn handleSetTimezone(args: []const u8) void {
    // Parse signed integer offset in minutes from URL path
    if (args.len == 0) return sendMutationError("missing offset");
    var i: usize = 0;
    var negative = false;
    if (args[0] == '-') {
        negative = true;
        i += 1;
    } else if (args[0] == '+') {
        i += 1;
    }
    var val: i16 = 0;
    var digits: usize = 0;
    while (i < args.len and args[i] >= '0' and args[i] <= '9') : (i += 1) {
        val = val * 10 + @as(i16, args[i] - '0');
        digits += 1;
    }
    if (digits == 0) return sendMutationError("invalid offset");
    if (negative) val = -val;

    const offset_bytes: [2]u8 = @bitCast(val);
    var msg: [4]u8 = undefined;
    msg[0] = http_proto.CMD_MUTATION_REQUEST;
    msg[1] = http_proto.MUT_TIMEZONE;
    msg[2] = offset_bytes[0];
    msg[3] = offset_bytes[1];
    sendMutationAndRespond(&msg);
}

fn sendMutationAndRespond(msg: []const u8) void {
    http_client.sendMutationRequest(msg);

    var buf: [8192]u8 = undefined;
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        if (http_client.recv(&buf)) |resp| {
            switch (resp) {
                .mutation_response => |data| {
                    sendHttpResponse("200 OK", "application/json", data);
                    return;
                },
                else => {},
            }
        }
        http_client.waitForMessage(500_000_000); // 500ms
    }

    sendHttpResponse("503 Service Unavailable", "text/plain", "Mutation timeout");
}

fn sendMutationError(msg: []const u8) void {
    var buf: [128]u8 = undefined;
    var p: usize = 0;
    p = appendSlice(&buf, p, "{\"ok\":false,\"error\":\"");
    p = appendSlice(&buf, p, msg);
    p = appendSlice(&buf, p, "\"}");
    sendHttpResponse("200 OK", "application/json", buf[0..p]);
}

// ── HTTP response builder ───────────────────────────────────────────

fn sendHttpResponse(status: []const u8, content_type: []const u8, body: []const u8) void {
    // Wire format: [0x11][chunk_index:1][total_chunks:1][payload...]
    // Chunk 0 payload: [body_len:2 BE][slen:1][status...][ctlen:1][ct...][body_start...]
    // Chunk 1..N payload: [body_continuation...]
    const CHUNK_PAYLOAD = 1900;

    // Build header metadata: [body_len_hi][body_len_lo][slen][status][ctlen][ct]
    var meta: [512]u8 = undefined;
    var mp: usize = 0;
    const body_len_u16: u16 = @intCast(@min(body.len, 65535));
    meta[mp] = @intCast(body_len_u16 >> 8);
    mp += 1;
    meta[mp] = @intCast(body_len_u16 & 0xFF);
    mp += 1;
    const slen: u8 = @intCast(@min(status.len, 255));
    meta[mp] = slen;
    mp += 1;
    @memcpy(meta[mp..][0..slen], status[0..slen]);
    mp += slen;
    const ctlen: u8 = @intCast(@min(content_type.len, 255));
    meta[mp] = ctlen;
    mp += 1;
    @memcpy(meta[mp..][0..ctlen], content_type[0..ctlen]);
    mp += ctlen;

    const total_payload = mp + body.len;
    const total_chunks: u8 = @intCast((total_payload + CHUNK_PAYLOAD - 1) / CHUNK_PAYLOAD);

    var sent: usize = 0;
    var chunk_idx: u8 = 0;

    while (chunk_idx < total_chunks) : (chunk_idx += 1) {
        var msg: [1950]u8 = undefined;
        msg[0] = http_proto.CMD_HTTP_RESPONSE;
        msg[1] = chunk_idx;
        msg[2] = total_chunks;
        var p: usize = 3;

        const chunk_end = @min(sent + CHUNK_PAYLOAD, total_payload);
        while (sent < chunk_end) : (sent += 1) {
            if (sent < mp) {
                msg[p] = meta[sent];
            } else {
                msg[p] = body[sent - mp];
            }
            p += 1;
        }

        // Wait until ring buffer has space (router must consume previous chunk)
        while (true) {
            router_chan.sendMessage(.A, msg[0..p]) catch {
                router_chan.waitForMessage(.A, 50_000_000); // 50ms
                continue;
            };
            break;
        }
    }
}

// ── UPnP SOAP handling ──────────────────────────────────────────────

fn handleSoapAction(raw: []const u8) void {
    // Use full raw request for tag extraction (body may be in same buffer as headers)
    // The SOAP XML tags are unique enough to not conflict with HTTP headers

    // Determine action from SOAPAction header or body
    if (containsStr(raw, "AddPortMapping")) {
        handleSoapAddPortMapping(raw);
    } else if (containsStr(raw, "DeletePortMapping")) {
        handleSoapDeletePortMapping(raw);
    } else if (containsStr(raw, "GetExternalIPAddress")) {
        handleSoapGetExternalIP();
    } else if (containsStr(raw, "GetSpecificPortMappingEntry")) {
        handleSoapGetSpecificEntry(raw);
    } else {
        sendSoapFault("401", "Invalid Action");
    }
}

fn handleSoapAddPortMapping(raw: []const u8) void {
    // Extract parameters from SOAP XML (search full raw — body follows headers in same buffer)
    const ext_port = extractTagU16(raw, "NewExternalPort") orelse {
        sendSoapFault("402", "Missing ExternalPort");
        return;
    };
    const int_port = extractTagU16(raw, "NewInternalPort") orelse {
        sendSoapFault("402", "Missing InternalPort");
        return;
    };
    const proto_str = extractTagValue(raw, "NewProtocol");
    var proto_byte: u8 = 0; // TCP
    if (proto_str) |ps| {
        if (containsStr(ps, "UDP") or containsStr(ps, "udp")) proto_byte = 1;
    }
    const client_ip = extractTagIp(raw, "NewInternalClient") orelse {
        sendSoapFault("402", "Missing InternalClient");
        return;
    };
    const lease = extractTagU32(raw, "NewLeaseDuration") orelse 0;

    // Build http_proto.MUT_FORWARD_LEASED message
    // Format: [MSG][MUT][proto:1][wan_port:2][lan_ip:4][lan_port:2][lease_secs:4][source:1]
    var msg: [16]u8 = undefined;
    msg[0] = http_proto.CMD_MUTATION_REQUEST;
    msg[1] = http_proto.MUT_FORWARD_LEASED;
    msg[2] = proto_byte;
    msg[3] = @intCast(ext_port >> 8);
    msg[4] = @intCast(ext_port & 0xff);
    @memcpy(msg[5..9], &client_ip);
    msg[9] = @intCast(int_port >> 8);
    msg[10] = @intCast(int_port & 0xff);
    msg[11] = @intCast((lease >> 24) & 0xff);
    msg[12] = @intCast((lease >> 16) & 0xff);
    msg[13] = @intCast((lease >> 8) & 0xff);
    msg[14] = @intCast(lease & 0xff);
    msg[15] = 1; // source = upnp

    http_client.sendMutationRequest(&msg);

    // Wait for response
    var buf: [8192]u8 = undefined;
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        if (http_client.recv(&buf)) |resp| {
            switch (resp) {
                .mutation_response => |data| {
                    if (containsStr(data, "\"ok\":true")) {
                        sendSoapResponse("AddPortMappingResponse", "");
                    } else {
                        sendSoapFault("718", "ConflictInMappingEntry");
                    }
                    return;
                },
                else => {},
            }
        }
        http_client.waitForMessage(500_000_000);
    }
    sendSoapFault("501", "Action Failed");
}

fn handleSoapDeletePortMapping(body: []const u8) void {
    const ext_port = extractTagU16(body, "NewExternalPort") orelse {
        sendSoapFault("402", "Missing ExternalPort");
        return;
    };
    _ = extractTagValue(body, "NewProtocol"); // Ignored — unforward tries both

    var msg: [4]u8 = undefined;
    msg[0] = http_proto.CMD_MUTATION_REQUEST;
    msg[1] = http_proto.MUT_UNFORWARD;
    msg[2] = @intCast(ext_port >> 8);
    msg[3] = @intCast(ext_port & 0xff);
    sendMutationAndRespond(&msg);
}

fn handleSoapGetExternalIP() void {
    // Query router status to get WAN IP
    http_client.sendStateQuery(http_proto.EP_STATUS);

    var buf: [8192]u8 = undefined;
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        if (http_client.recv(&buf)) |resp| {
            switch (resp) {
                .state_response => |data| {
                    const ip_str = extractJsonWanIp(data);
                    var resp_buf: [256]u8 = undefined;
                    var p: usize = 0;
                    p = appendSlice(&resp_buf, p, "<NewExternalIPAddress>");
                    p = appendSlice(&resp_buf, p, ip_str);
                    p = appendSlice(&resp_buf, p, "</NewExternalIPAddress>");
                    sendSoapResponse("GetExternalIPAddressResponse", resp_buf[0..p]);
                    return;
                },
                else => {},
            }
        }
        http_client.waitForMessage(500_000_000);
    }
    sendSoapFault("501", "Action Failed");
}

fn handleSoapGetSpecificEntry(body: []const u8) void {
    // We can't query individual port forwards via existing IPC, so return 714 NoSuchEntryInArray
    // This is acceptable — many routers return this for non-existent entries
    _ = body;
    sendSoapFault("714", "NoSuchEntryInArray");
}

fn extractJsonWanIp(json: []const u8) []const u8 {
    // Find "ip":" inside the wan object: {"wan":{"ip":"10.0.2.15",...}}
    const prefix = "\"ip\":\"";
    var i: usize = 0;
    while (i + prefix.len < json.len) : (i += 1) {
        if (eql(json[i..][0..prefix.len], prefix)) {
            const start = i + prefix.len;
            var end = start;
            while (end < json.len and json[end] != '"') : (end += 1) {}
            return json[start..end];
        }
    }
    return "0.0.0.0";
}

fn sendSoapResponse(action_name: []const u8, inner: []const u8) void {
    var buf: [2048]u8 = undefined;
    var p: usize = 0;
    p = appendSlice(&buf, p, "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:");
    p = appendSlice(&buf, p, action_name);
    p = appendSlice(&buf, p, " xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">");
    p = appendSlice(&buf, p, inner);
    p = appendSlice(&buf, p, "</u:");
    p = appendSlice(&buf, p, action_name);
    p = appendSlice(&buf, p, "></s:Body></s:Envelope>");
    sendHttpResponse("200 OK", "text/xml; charset=\"utf-8\"", buf[0..p]);
}

fn sendSoapFault(code: []const u8, desc: []const u8) void {
    var buf: [1024]u8 = undefined;
    var p: usize = 0;
    p = appendSlice(&buf, p, "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>");
    p = appendSlice(&buf, p, code);
    p = appendSlice(&buf, p, "</errorCode><errorDescription>");
    p = appendSlice(&buf, p, desc);
    p = appendSlice(&buf, p, "</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>");
    sendHttpResponse("500 Internal Server Error", "text/xml; charset=\"utf-8\"", buf[0..p]);
}

fn containsStr(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (eql(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

fn extractTagValue(xml: []const u8, tag: []const u8) ?[]const u8 {
    // Find <tag>value</tag> and return value
    // Search for "<tag>" opening
    var i: usize = 0;
    while (i + tag.len + 2 < xml.len) : (i += 1) {
        if (xml[i] == '<' and i + 1 + tag.len + 1 <= xml.len and
            eql(xml[i + 1 ..][0..tag.len], tag) and xml[i + 1 + tag.len] == '>')
        {
            const val_start = i + 1 + tag.len + 1;
            var val_end = val_start;
            while (val_end < xml.len and xml[val_end] != '<') : (val_end += 1) {}
            return xml[val_start..val_end];
        }
    }
    return null;
}

fn extractTagU16(xml: []const u8, tag: []const u8) ?u16 {
    const val = extractTagValue(xml, tag) orelse return null;
    return parseU16Simple(val);
}

fn extractTagU32(xml: []const u8, tag: []const u8) ?u32 {
    const val = extractTagValue(xml, tag) orelse return null;
    var result: u32 = 0;
    for (val) |c| {
        if (c >= '0' and c <= '9') {
            result = result * 10 + @as(u32, c - '0');
        } else break;
    }
    return result;
}

fn extractTagIp(xml: []const u8, tag: []const u8) ?[4]u8 {
    const val = extractTagValue(xml, tag) orelse return null;
    return parseIp(val);
}

fn parseU16Simple(s: []const u8) ?u16 {
    var val: u16 = 0;
    var digits: usize = 0;
    for (s) |c| {
        if (c >= '0' and c <= '9') {
            val = val *% 10 +% @as(u16, c - '0');
            digits += 1;
        } else break;
    }
    if (digits == 0) return null;
    return val;
}

// ── UPnP XML descriptors ────────────────────────────────────────────

const UPNP_ROOT_DESC = @embedFile("rootDesc.xml");
const UPNP_WANIP_DESC = @embedFile("WANIPConn.xml");

// ── Utilities ───────────────────────────────────────────────────────

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn startsWith(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return eql(haystack[0..prefix.len], prefix);
}

fn appendSlice(buf: []u8, pos: usize, s: []const u8) usize {
    const n = @min(s.len, buf.len - pos);
    @memcpy(buf[pos..][0..n], s[0..n]);
    return pos + n;
}

fn parseIp(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet: usize = 0;
    var val: u16 = 0;
    var digits: usize = 0;
    for (s) |c| {
        if (c >= '0' and c <= '9') {
            val = val * 10 + @as(u16, c - '0');
            if (val > 255) return null;
            digits += 1;
        } else if (c == '.') {
            if (digits == 0 or octet >= 3) return null;
            result[octet] = @intCast(val);
            octet += 1;
            val = 0;
            digits = 0;
        } else break;
    }
    if (digits == 0 or octet != 3) return null;
    result[3] = @intCast(val);
    return result;
}

const ParsedU16 = struct { val: u16, len: usize };

fn parseU16(s: []const u8) ?ParsedU16 {
    var val: u16 = 0;
    var i: usize = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
        val = val *% 10 +% @as(u16, s[i] - '0');
    }
    if (i == 0) return null;
    return .{ .val = val, .len = i };
}

// ── Embedded HTML Management Page ───────────────────────────────────

const HTML_PAGE = @embedFile("index.html");
