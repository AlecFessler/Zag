const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

// ── Message tags (must match router/services/web_tcp.zig) ───────────

const MSG_HTTP_REQUEST: u8 = 0x10;
const MSG_HTTP_RESPONSE: u8 = 0x11;
const MSG_STATE_QUERY: u8 = 0x12;
const MSG_STATE_RESPONSE: u8 = 0x13;

// ── State query endpoint IDs ────────────────────────────────────────

const EP_STATUS: u8 = 0;
const EP_IFSTAT: u8 = 1;
const EP_ARP: u8 = 2;
const EP_NAT: u8 = 3;
const EP_LEASES: u8 = 4;
const EP_RULES: u8 = 5;

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

    // Main loop
    while (true) {
        var router_buf: [8192]u8 = undefined;
        if (router_chan.recv(&router_buf)) |len| {
            handleRouterMessage(router_buf[0..len]);
        }
        syscall.thread_yield();
    }
}

// ── Message handling ────────────────────────────────────────────────

fn handleRouterMessage(data: []const u8) void {
    if (data.len < 1) return;
    switch (data[0]) {
        MSG_HTTP_REQUEST => {
            syscall.write("http_server: got req\n");
            handleHttpRequest(data[1..]);
        },
        else => {},
    }
}

fn handleHttpRequest(path: []const u8) void {
    // path_len == 0 means non-GET method (sentinel from router)
    if (path.len == 0) {
        sendHttpResponse("405 Method Not Allowed", "text/plain", "Method Not Allowed");
        return;
    }

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
    // Send state query to router
    _ = router_chan.send(&[_]u8{ MSG_STATE_QUERY, endpoint });

    // Wait for response (single-threaded, only one request at a time)
    var buf: [8192]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 50000) : (attempts += 1) {
        if (router_chan.recv(&buf)) |len| {
            if (len >= 1 and buf[0] == MSG_STATE_RESPONSE) {
                const json = buf[1..len];
                sendHttpResponse("200 OK", "application/json", json);
                return;
            }
        }
        syscall.thread_yield();
    }

    // Timeout — send error response
    sendHttpResponse("503 Service Unavailable", "text/plain", "State query timeout");
}

// ── HTTP response builder ───────────────────────────────────────────

fn sendHttpResponse(status: []const u8, content_type: []const u8, body: []const u8) void {
    // Build: [0x11][status_len:1][status...][ct_len:1][content_type...][body...]
    var msg: [8192]u8 = undefined;
    var p: usize = 0;

    msg[p] = MSG_HTTP_RESPONSE;
    p += 1;

    // Status
    const slen: u8 = @intCast(@min(status.len, 255));
    msg[p] = slen;
    p += 1;
    @memcpy(msg[p..][0..slen], status[0..slen]);
    p += slen;

    // Content-Type
    const ctlen: u8 = @intCast(@min(content_type.len, 255));
    msg[p] = ctlen;
    p += 1;
    @memcpy(msg[p..][0..ctlen], content_type[0..ctlen]);
    p += ctlen;

    // Body
    const blen = @min(body.len, msg.len - p);
    @memcpy(msg[p..][0..blen], body[0..blen]);
    p += blen;

    _ = router_chan.send(msg[0..p]);
}

// ── Utilities ───────────────────────────────────────────────────────

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

// ── Embedded HTML Page ──────────────────────────────────────────────

const HTML_PAGE =
    \\<!DOCTYPE html>
    \\<html><head><meta charset="utf-8"><title>Zag RouterOS</title>
    \\<style>
    \\*{margin:0;padding:0;box-sizing:border-box}
    \\body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px}
    \\h1{color:#0f0;margin-bottom:20px;font-size:1.4em}
    \\h2{color:#0af;margin:15px 0 8px;font-size:1.1em}
    \\.card{background:#16213e;border:1px solid #0a3d62;border-radius:6px;padding:12px;margin-bottom:12px}
    \\table{width:100%;border-collapse:collapse;font-size:0.9em}
    \\th{text-align:left;color:#0af;padding:4px 8px;border-bottom:1px solid #0a3d62}
    \\td{padding:4px 8px}
    \\tr:hover{background:#1a1a4e}
    \\.stat{display:inline-block;margin-right:20px}
    \\.label{color:#888}.val{color:#0f0}
    \\#err{color:#f44;margin:10px 0}
    \\</style></head><body>
    \\<h1>&gt; Zag RouterOS Management</h1>
    \\<div id="err"></div>
    \\<div class="card" id="status"><h2>Interfaces</h2><div id="status-body">Loading...</div></div>
    \\<div class="card" id="stats"><h2>Statistics</h2><div id="stats-body">Loading...</div></div>
    \\<div class="card"><h2>ARP Table</h2><table><thead><tr><th>Iface</th><th>IP</th><th>MAC</th></tr></thead><tbody id="arp-body"></tbody></table></div>
    \\<div class="card"><h2>NAT Table</h2><table><thead><tr><th>Proto</th><th>LAN</th><th>WAN Port</th><th>Destination</th></tr></thead><tbody id="nat-body"></tbody></table></div>
    \\<div class="card"><h2>DHCP Leases</h2><table><thead><tr><th>IP</th><th>MAC</th></tr></thead><tbody id="lease-body"></tbody></table></div>
    \\<div class="card"><h2>Firewall Rules</h2><table><thead><tr><th>Action</th><th>IP</th></tr></thead><tbody id="fw-body"></tbody></table><h2>Port Forwards</h2><table><thead><tr><th>Proto</th><th>WAN Port</th><th>LAN Target</th></tr></thead><tbody id="fwd-body"></tbody></table></div>
    \\<script>
    \\function f(u,cb){var x=new XMLHttpRequest();x.open('GET',u);x.onload=function(){if(x.status==200)cb(JSON.parse(x.responseText));};x.onerror=function(){document.getElementById('err').textContent='Connection error';};x.send();}
    \\function r(){
    \\f('/api/status',function(d){var h='';if(d.wan)h+='<span class="stat"><span class="label">WAN:</span> <span class="val">'+d.wan.ip+'</span> gw='+d.wan.gateway+' mac='+d.wan.mac+'</span>';if(d.lan)h+='<span class="stat"><span class="label">LAN:</span> <span class="val">'+d.lan.ip+'</span> mac='+d.lan.mac+'</span>';document.getElementById('status-body').innerHTML=h;});
    \\f('/api/ifstat',function(d){var h='';if(d.wan)h+='<span class="stat"><span class="label">WAN</span> rx=<span class="val">'+d.wan.rx+'</span> tx=<span class="val">'+d.wan.tx+'</span> drop='+d.wan.drop+'</span>';if(d.lan)h+=' <span class="stat"><span class="label">LAN</span> rx=<span class="val">'+d.lan.rx+'</span> tx=<span class="val">'+d.lan.tx+'</span> drop='+d.lan.drop+'</span>';document.getElementById('stats-body').innerHTML=h;});
    \\f('/api/arp',function(d){var h='';d.forEach(function(e){h+='<tr><td>'+e.iface+'</td><td>'+e.ip+'</td><td>'+e.mac+'</td></tr>';});document.getElementById('arp-body').innerHTML=h||'<tr><td colspan=3>empty</td></tr>';});
    \\f('/api/nat',function(d){var h='';d.forEach(function(e){h+='<tr><td>'+e.proto+'</td><td>'+e.lan_ip+':'+e.lan_port+'</td><td>:'+e.wan_port+'</td><td>'+e.dst_ip+':'+e.dst_port+'</td></tr>';});document.getElementById('nat-body').innerHTML=h||'<tr><td colspan=4>empty</td></tr>';});
    \\f('/api/leases',function(d){var h='';d.forEach(function(e){h+='<tr><td>'+e.ip+'</td><td>'+e.mac+'</td></tr>';});document.getElementById('lease-body').innerHTML=h||'<tr><td colspan=2>empty</td></tr>';});
    \\f('/api/rules',function(d){var h='';d.firewall.forEach(function(e){h+='<tr><td>'+e.action+'</td><td>'+e.ip+'</td></tr>';});document.getElementById('fw-body').innerHTML=h||'<tr><td colspan=2>none</td></tr>';var g='';d.forwards.forEach(function(e){g+='<tr><td>'+e.proto+'</td><td>:'+e.wan_port+'</td><td>'+e.lan_ip+':'+e.lan_port+'</td></tr>';});document.getElementById('fwd-body').innerHTML=g||'<tr><td colspan=3>none</td></tr>';});
    \\}
    \\r();setInterval(r,5000);
    \\</script></body></html>
;
