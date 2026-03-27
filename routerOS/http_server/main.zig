const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

// ── Message tags (must match router/services/tcp_stack.zig) ─────────

const MSG_HTTP_REQUEST: u8 = 0x10;
const MSG_HTTP_RESPONSE: u8 = 0x11;
const MSG_STATE_QUERY: u8 = 0x12;
const MSG_STATE_RESPONSE: u8 = 0x13;
const MSG_MUTATION_REQUEST: u8 = 0x14;
const MSG_MUTATION_RESPONSE: u8 = 0x15;

// ── State query endpoint IDs ────────────────────────────────────────

const EP_STATUS: u8 = 0;
const EP_IFSTAT: u8 = 1;
const EP_ARP: u8 = 2;
const EP_NAT: u8 = 3;
const EP_LEASES: u8 = 4;
const EP_RULES: u8 = 5;

// ── Mutation types ──────────────────────────────────────────────────

const MUT_BLOCK: u8 = 0;
const MUT_ALLOW: u8 = 1;
const MUT_FORWARD: u8 = 2;
const MUT_UNFORWARD: u8 = 3;
const MUT_DNS: u8 = 4;
const MUT_TIMEZONE: u8 = 5;

// ── Configuration ───────────────────────────────────────────────────

const MAX_PERMS = 128;

// ── State ───────────────────────────────────────────────────────────

var router_chan: channel_mod.Channel = undefined;
var has_router: bool = false;

// ── Entry point ─────────────────────────────────────────────────────

pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("http_server: no command channel\n");
        return;
    };

    const router_entry = cmd.requestConnection(shm_protocol.ServiceId.ROUTER) orelse {
        syscall.write("http_server: no router connection allowed\n");
        return;
    };
    if (!cmd.waitForConnection(router_entry)) {
        syscall.write("http_server: router connection failed\n");
        return;
    }
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var data_shm_handle: u64 = 0;
    var data_shm_size: u64 = 0;
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
            e.field0 > shm_protocol.COMMAND_SHM_SIZE and
            e.handle != router_entry.shm_handle)
        {
            data_shm_handle = e.handle;
            data_shm_size = e.field0;
            break;
        }
    }
    if (data_shm_handle == 0) {
        data_shm_handle = router_entry.shm_handle;
        data_shm_size = router_entry.shm_size;
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, data_shm_size, vm_rights);
    if (vm_result.val < 0) {
        syscall.write("http_server: vm_reserve failed\n");
        return;
    }
    if (syscall.shm_map(data_shm_handle, @intCast(vm_result.val), 0) != 0) {
        syscall.write("http_server: shm_map failed\n");
        return;
    }
    const header: *channel_mod.ChannelHeader = @ptrFromInt(vm_result.val2);
    router_chan = channel_mod.Channel.openAsSideB(header) orelse {
        syscall.write("http_server: channel open failed\n");
        return;
    };
    has_router = true;

    // Identify ourselves to the router
    _ = router_chan.send(&[_]u8{@truncate(shm_protocol.ServiceId.HTTP_SERVER)});

    syscall.write("http_server: started\n");

    const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

    // Main loop
    while (true) {
        var router_buf: [8192]u8 = undefined;
        if (router_chan.recv(&router_buf)) |len| {
            handleRouterMessage(router_buf[0..len]);
        } else {
            router_chan.rx.waitForData(MAX_TIMEOUT);
        }
    }
}

// ── Message handling ────────────────────────────────────────────────

fn handleRouterMessage(data: []const u8) void {
    if (data.len < 1) return;
    switch (data[0]) {
        MSG_HTTP_REQUEST => {
            handleHttpRequest(data[1..]);
        },
        else => {},
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
        handlePost(path);
    } else {
        sendHttpResponse("405 Method Not Allowed", "text/plain", "Method Not Allowed");
    }
}

// ── GET handlers ────────────────────────────────────────────────────

fn handleGet(path: []const u8) void {
    if (eql(path, "/") or eql(path, "/index.html")) {
        sendHttpResponse("200 OK", "text/html", HTML_PAGE);
    } else if (eql(path, "/api/status")) {
        sendStateQueryResponse(EP_STATUS);
    } else if (eql(path, "/api/ifstat")) {
        sendStateQueryResponse(EP_IFSTAT);
    } else if (eql(path, "/api/arp")) {
        sendStateQueryResponse(EP_ARP);
    } else if (eql(path, "/api/nat")) {
        sendStateQueryResponse(EP_NAT);
    } else if (eql(path, "/api/leases")) {
        sendStateQueryResponse(EP_LEASES);
    } else if (eql(path, "/api/rules")) {
        sendStateQueryResponse(EP_RULES);
    } else {
        sendHttpResponse("404 Not Found", "text/plain", "Not Found");
    }
}

fn sendStateQueryResponse(endpoint: u8) void {
    _ = router_chan.send(&[_]u8{ MSG_STATE_QUERY, endpoint });

    var buf: [8192]u8 = undefined;
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        if (router_chan.recv(&buf)) |len| {
            if (len >= 1 and buf[0] == MSG_STATE_RESPONSE) {
                sendHttpResponse("200 OK", "application/json", buf[1..len]);
                return;
            }
        }
        router_chan.rx.waitForData(500_000_000); // 500ms
    }

    sendHttpResponse("503 Service Unavailable", "text/plain", "State query timeout");
}

// ── POST handlers ───────────────────────────────────────────────────

fn handlePost(path: []const u8) void {
    const block_prefix = "/api/block/";
    const allow_prefix = "/api/allow/";
    const forward_prefix = "/api/forward/";
    const unforward_prefix = "/api/unforward/";
    const dns_prefix = "/api/dns/";

    if (path.len > block_prefix.len and startsWith(path, block_prefix)) {
        const ip = parseIp(path[block_prefix.len..]) orelse return sendMutationError("invalid ip");
        var msg: [6]u8 = undefined;
        msg[0] = MSG_MUTATION_REQUEST;
        msg[1] = MUT_BLOCK;
        @memcpy(msg[2..6], &ip);
        sendMutationAndRespond(&msg);
    } else if (path.len > allow_prefix.len and startsWith(path, allow_prefix)) {
        const ip = parseIp(path[allow_prefix.len..]) orelse return sendMutationError("invalid ip");
        var msg: [6]u8 = undefined;
        msg[0] = MSG_MUTATION_REQUEST;
        msg[1] = MUT_ALLOW;
        @memcpy(msg[2..6], &ip);
        sendMutationAndRespond(&msg);
    } else if (path.len > forward_prefix.len and startsWith(path, forward_prefix)) {
        handleAddForward(path[forward_prefix.len..]);
    } else if (path.len > unforward_prefix.len and startsWith(path, unforward_prefix)) {
        handleRemoveForward(path[unforward_prefix.len..]);
    } else if (path.len > dns_prefix.len and startsWith(path, dns_prefix)) {
        const ip = parseIp(path[dns_prefix.len..]) orelse return sendMutationError("invalid ip");
        var msg: [6]u8 = undefined;
        msg[0] = MSG_MUTATION_REQUEST;
        msg[1] = MUT_DNS;
        @memcpy(msg[2..6], &ip);
        sendMutationAndRespond(&msg);
    } else if (startsWith(path, "/api/timezone/")) {
        const tz_prefix = "/api/timezone/";
        if (path.len > tz_prefix.len) {
            handleSetTimezone(path[tz_prefix.len..]);
        } else {
            sendMutationError("missing offset");
        }
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

    // Build mutation: [MSG][MUT_FORWARD][proto:1][wan_port:2][lan_ip:4][lan_port:2]
    var msg: [11]u8 = undefined;
    msg[0] = MSG_MUTATION_REQUEST;
    msg[1] = MUT_FORWARD;
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
    msg[0] = MSG_MUTATION_REQUEST;
    msg[1] = MUT_UNFORWARD;
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
    msg[0] = MSG_MUTATION_REQUEST;
    msg[1] = MUT_TIMEZONE;
    msg[2] = offset_bytes[0];
    msg[3] = offset_bytes[1];
    sendMutationAndRespond(&msg);
}

fn sendMutationAndRespond(msg: []const u8) void {
    _ = router_chan.send(msg);

    var buf: [8192]u8 = undefined;
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        if (router_chan.recv(&buf)) |len| {
            if (len >= 1 and buf[0] == MSG_MUTATION_RESPONSE) {
                sendHttpResponse("200 OK", "application/json", buf[1..len]);
                return;
            }
        }
        router_chan.rx.waitForData(500_000_000); // 500ms
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
        msg[0] = MSG_HTTP_RESPONSE;
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
        while (!router_chan.send(msg[0..p])) {
            const head_val = @atomicLoad(u64, &router_chan.tx.head, .acquire);
            _ = syscall.futex_wait(&router_chan.tx.head, head_val, 50_000_000); // 50ms
        }
    }
}

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
