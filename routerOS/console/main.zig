const lib = @import("lib");

const channel = lib.channel;
const pv = lib.perm_view;
const reload_proto = lib.reload;
const syscall = lib.syscall;
const text_cmd = lib.text_command;

const Channel = channel.Channel;

const DEFAULT_SHM_SIZE = 4 * syscall.PAGE4K;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
const MAX_PERMS = 128;

var serial_chan: *Channel = undefined;
var router_chan: *Channel = undefined;
var nfs_chan: *Channel = undefined;
var ntp_chan: *Channel = undefined;
var root_chan: *Channel = undefined;
var has_router: bool = false;
var has_nfs: bool = false;
var has_ntp: bool = false;
var has_root: bool = false;
var perm_view_global: u64 = 0;

// ── Known SHM tracking ──────────────────────────────────────────────
var known_shm_handles: [32]u64 = .{0} ** 32;
var known_shm_count: u8 = 0;

fn addKnownShmHandle(handle: u64) void {
    if (known_shm_count < 32) {
        known_shm_handles[known_shm_count] = handle;
        known_shm_count += 1;
    }
}

fn pollNewShm(view_addr: u64) ?u64 {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(view_addr);
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            var known = false;
            for (known_shm_handles[0..known_shm_count]) |h| {
                if (h == entry.handle) {
                    known = true;
                    break;
                }
            }
            if (!known and known_shm_count < 32) {
                known_shm_handles[known_shm_count] = entry.handle;
                known_shm_count += 1;
                return entry.handle;
            }
        }
    }
    return null;
}

fn serialWrite(data: []const u8) void {
    serial_chan.sendMessage(.A, data) catch {};
}

fn serialWriteByte(byte: u8) void {
    const buf = [_]u8{byte};
    serial_chan.sendMessage(.A, &buf) catch {};
}

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

const CMD_MAX = 128;

fn processCommand(line: []const u8) void {
    if (line.len == 0) return;

    if (eql(line, "help")) {
        serialWrite("Available commands:\r\n");
        serialWrite("  help                     - show this help\r\n");
        serialWrite("  status                   - interface status\r\n");
        serialWrite("  ping <ip>                - ping an IP address\r\n");
        serialWrite("  traceroute <ip>          - trace route to IP\r\n");
        serialWrite("  arp                      - show ARP tables\r\n");
        serialWrite("  nat                      - show NAT table\r\n");
        serialWrite("  leases                   - show DHCP leases\r\n");
        serialWrite("  ifstat                   - interface statistics\r\n");
        serialWrite("  rules                    - firewall & port forward rules\r\n");
        serialWrite("  block <ip>               - block IP on WAN\r\n");
        serialWrite("  allow <ip>               - remove block rule\r\n");
        serialWrite("  forward <tcp|udp> <wport> <lip> <lport>\r\n");
        serialWrite("                           - port forward to LAN\r\n");
        serialWrite("  dns <ip>                 - set upstream DNS\r\n");
        serialWrite("  static-lease <mac> <ip>   - add static DHCP lease\r\n");
        serialWrite("  static-leases            - list static DHCP leases\r\n");
        serialWrite("  dhcp-client              - start/show WAN DHCP\r\n");
        serialWrite("  dhcpv6                   - start/show WAN DHCPv6-PD\r\n");
        serialWrite("  save-config              - save config to NFS\r\n");
        serialWrite("  load-config              - load config from NFS\r\n");
        serialWrite("  version                  - system version\r\n");
        serialWrite("  uptime                   - system uptime\r\n");
        serialWrite("  clear                    - clear screen\r\n");
        serialWrite("NFS commands:\r\n");
        serialWrite("  mount                    - mount NFS export\r\n");
        serialWrite("  ls [path]                - list directory\r\n");
        serialWrite("  cat <path>               - read file\r\n");
        serialWrite("  put <path>               - write file (end with empty line)\r\n");
        serialWrite("  mkdir <path>             - create directory\r\n");
        serialWrite("  rm <path>                - remove file\r\n");
        serialWrite("  rmdir <path>             - remove directory\r\n");
        serialWrite("  mv <src> <dst>           - rename file\r\n");
        serialWrite("  touch <path>             - create empty file\r\n");
        serialWrite("  stat <path>              - file attributes\r\n");
        serialWrite("NTP commands:\r\n");
        serialWrite("  time                     - show current time\r\n");
        serialWrite("  sync                     - sync time via NTP\r\n");
        serialWrite("  ntpserver <ip>           - set NTP server\r\n");
        serialWrite("  timezone <offset>        - set timezone (e.g. -6, +5:30)\r\n");
        serialWrite("System commands:\r\n");
        serialWrite("  reload <name>            - reload process from NFS\r\n");
    } else if (eql(line, "version")) {
        serialWrite("Zag RouterOS v0.1\r\n");
    } else if (eql(line, "uptime")) {
        const ns: u64 = syscall.clock_gettime();
        const secs = ns / 1_000_000_000;
        const mins = secs / 60;
        const hrs = mins / 60;
        printUptime(hrs, mins % 60, secs % 60);
    } else if (eql(line, "clear")) {
        serialWrite("\x1b[2J\x1b[H");
    } else if (eql(line, "status")) {
        routerCommand("status");
    } else if (startsWith(line, "traceroute ")) {
        routerMultiResponse(line);
    } else if (startsWith(line, "ping ")) {
        routerMultiResponse(line);
    } else if (eql(line, "arp")) {
        routerMultiResponse("arp");
    } else if (eql(line, "nat")) {
        routerMultiResponse("nat");
    } else if (eql(line, "leases")) {
        routerMultiResponse("leases");
    } else if (eql(line, "ifstat")) {
        routerCommand("ifstat");
    } else if (eql(line, "rules")) {
        routerMultiResponse("rules");
    } else if (startsWith(line, "block ")) {
        routerCommand(line);
    } else if (startsWith(line, "allow ")) {
        routerCommand(line);
    } else if (startsWith(line, "forward ")) {
        routerCommand(line);
    } else if (startsWith(line, "dns ")) {
        routerCommand(line);
    } else if (eql(line, "dhcp-client")) {
        routerCommand(line);
    } else if (eql(line, "dhcp-test-rebind")) {
        routerCommand(line);
    } else if (eql(line, "static-leases")) {
        routerMultiResponse("static-leases");
    } else if (startsWith(line, "static-lease ")) {
        routerCommand(line);
    } else if (eql(line, "dhcpv6")) {
        routerCommand(line);
    } else if (eql(line, "get-config")) {
        routerMultiResponse("get-config");
    } else if (eql(line, "save-config")) {
        saveConfig();
    } else if (eql(line, "load-config")) {
        loadConfig();
    } else if (eql(line, "mount")) {
        nfsMultiResponse("mount");
    } else if (startsWith(line, "ls")) {
        if (line.len <= 3)
            nfsMultiResponse("ls /")
        else
            nfsMultiResponse(line);
    } else if (startsWith(line, "cat ")) {
        nfsMultiResponse(line);
    } else if (startsWith(line, "put ")) {
        nfsPut(line);
    } else if (startsWith(line, "mkdir ")) {
        nfsMultiResponse(line);
    } else if (startsWith(line, "rm ")) {
        nfsMultiResponse(line);
    } else if (startsWith(line, "rmdir ")) {
        nfsMultiResponse(line);
    } else if (startsWith(line, "mv ")) {
        nfsMultiResponse(line);
    } else if (startsWith(line, "touch ")) {
        nfsMultiResponse(line);
    } else if (startsWith(line, "stat ")) {
        nfsMultiResponse(line);
    } else if (eql(line, "time")) {
        ntpMultiResponse("time");
    } else if (eql(line, "sync")) {
        ntpMultiResponse("sync");
    } else if (startsWith(line, "ntpserver ")) {
        ntpMultiResponse(line);
    } else if (startsWith(line, "timezone ")) {
        ntpMultiResponse(line);
    } else if (startsWith(line, "reload ")) {
        reloadCommand(line);
    } else {
        serialWrite("unknown command: ");
        serialWrite(line);
        serialWrite("\r\ntype 'help' for available commands\r\n");
    }
}

fn routerCommand(cmd: []const u8) void {
    if (!has_router) {
        serialWrite("router: not connected\r\n");
        return;
    }
    const client = text_cmd.Client.init(router_chan);
    client.sendCommand(cmd);
    var resp: [512]u8 = undefined;
    var attempts: u8 = 0;
    while (attempts < 20) : (attempts += 1) {
        if (client.recv(&resp)) |msg| {
            switch (msg) {
                .text => |text| {
                    serialWrite(text);
                    serialWrite("\r\n");
                    // Drain the RESP_END
                    var drain: [4]u8 = undefined;
                    _ = client.recv(&drain);
                    return;
                },
                .end => return,
                else => return,
            }
        }
        client.waitForMessage(50_000_000);
    }
    serialWrite("router: no response\r\n");
}

fn routerMultiResponse(cmd: []const u8) void {
    if (!has_router) {
        serialWrite("router: not connected\r\n");
        return;
    }
    const client = text_cmd.Client.init(router_chan);
    client.sendCommand(cmd);
    var resp: [512]u8 = undefined;
    var msg_count: u32 = 0;
    var done = false;
    var retries: u32 = 0;
    while (!done and msg_count < 40) {
        if (client.recv(&resp)) |msg| {
            switch (msg) {
                .text => |text| {
                    serialWrite(text);
                    serialWrite("\r\n");
                    msg_count += 1;
                },
                .end => {
                    done = true;
                },
                else => {
                    done = true;
                },
            }
        } else {
            client.waitForMessage(500_000_000); // 500ms
            if (client.recv(&resp)) |msg| {
                switch (msg) {
                    .text => |text| {
                        serialWrite(text);
                        serialWrite("\r\n");
                        msg_count += 1;
                    },
                    .end => {
                        done = true;
                    },
                    else => {
                        done = true;
                    },
                }
            } else {
                retries += 1;
                if (retries >= 12) done = true; // 6s total
            }
        }
    }
    if (msg_count == 0) {
        serialWrite("router: no response\r\n");
    }
}

fn nfsMultiResponse(cmd: []const u8) void {
    if (!has_nfs) {
        serialWrite("nfs: not connected\r\n");
        return;
    }
    const client = text_cmd.Client.init(nfs_chan);
    // Drain stale messages
    {
        var stale_buf: [2048]u8 = undefined;
        while (client.recv(&stale_buf) != null) {}
    }
    client.sendCommand(cmd);
    var resp: [2048]u8 = undefined;
    var msg_count: u32 = 0;
    var done = false;
    var retries: u32 = 0;
    while (!done and msg_count < 64) {
        if (client.recv(&resp)) |msg| {
            switch (msg) {
                .text => |text| {
                    serialWrite(text);
                    msg_count += 1;
                },
                .end => {
                    done = true;
                },
                .err => |text| {
                    serialWrite(text);
                    serialWrite("\r\n");
                    msg_count += 1;
                },
                .ack => |text| {
                    serialWrite(text);
                    msg_count += 1;
                },
            }
        } else {
            client.waitForMessage(500_000_000); // 500ms
            if (client.recv(&resp)) |msg| {
                switch (msg) {
                    .text => |text| {
                        serialWrite(text);
                        msg_count += 1;
                    },
                    .end => {
                        done = true;
                    },
                    .err => |text| {
                        serialWrite(text);
                        serialWrite("\r\n");
                        msg_count += 1;
                    },
                    .ack => |text| {
                        serialWrite(text);
                        msg_count += 1;
                    },
                }
            } else {
                retries += 1;
                if (retries >= 12) done = true; // 6s total
            }
        }
    }
    if (msg_count == 0) {
        serialWrite("nfs: no response\r\n");
    }
}

fn nfsPut(cmd: []const u8) void {
    if (!has_nfs) {
        serialWrite("nfs: not connected\r\n");
        return;
    }
    const client = text_cmd.Client.init(nfs_chan);
    client.sendCommand(cmd);

    // Wait for the ack response
    var resp: [256]u8 = undefined;
    var got_ack = false;
    var attempts: u32 = 0;
    while (attempts < 50) : (attempts += 1) {
        if (client.recv(&resp)) |msg| {
            switch (msg) {
                .ack => |text| {
                    serialWrite(text);
                    got_ack = true;
                },
                .err => |text| {
                    serialWrite(text);
                    serialWrite("\r\n");
                    return;
                },
                else => {},
            }
            break;
        }
        client.waitForMessage(100_000_000); // 100ms
    }
    if (!got_ack) {
        serialWrite("nfs: no response\r\n");
        return;
    }

    // Read lines from serial and send to NFS client.
    // Empty line = done.
    var line_buf: [CMD_MAX]u8 = undefined;
    var line_len: usize = 0;
    var rx_buf: [64]u8 = undefined;

    while (true) {
        if (serial_chan.receiveMessage(.A, &rx_buf) catch null) |len_u64| {
            const len: usize = @intCast(len_u64);
            for (rx_buf[0..len]) |byte| {
                if (byte == '\r' or byte == '\n') {
                    serialWrite("\r\n");
                    if (line_len == 0) {
                        // Empty line = done
                        client.sendDataEnd();
                        // Wait for commit response
                        nfsWaitResponse();
                        return;
                    }
                    client.sendData(line_buf[0..line_len]);
                    line_len = 0;
                } else if (byte == 127 or byte == 8) {
                    if (line_len > 0) {
                        line_len -= 1;
                        serialWrite("\x08 \x08");
                    }
                } else if (byte >= 32 and line_len < CMD_MAX) {
                    line_buf[line_len] = byte;
                    line_len += 1;
                    serialWriteByte(byte);
                }
            }
        }
        syscall.thread_yield();
    }
}

fn containsStr(haystack: []const u8, needle: []const u8) bool {
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (eql(haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

fn drainNfs() void {
    const client = text_cmd.Client.init(nfs_chan);
    var buf: [2048]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 20) : (attempts += 1) {
        if (client.recv(&buf)) |msg| {
            switch (msg) {
                .end => return,
                else => {
                    attempts = 0; // Reset on data
                },
            }
        }
        client.waitForMessage(50_000_000); // 50ms
    }
}

fn saveConfig() void {
    if (!has_router or !has_nfs) {
        serialWrite("save-config: router or NFS not connected\r\n");
        return;
    }

    // Get config lines from router
    const rclient = text_cmd.Client.init(router_chan);
    rclient.sendCommand("get-config");
    var lines: [64][256]u8 = undefined;
    var line_lens: [64]usize = .{0} ** 64;
    var count: usize = 0;

    var done = false;
    while (!done and count < 64) {
        var attempts: u32 = 0;
        while (attempts < 100) : (attempts += 1) {
            var resp: [256]u8 = undefined;
            if (rclient.recv(&resp)) |msg| {
                switch (msg) {
                    .text => |text| {
                        @memcpy(lines[count][0..text.len], text);
                        line_lens[count] = text.len;
                        count += 1;
                    },
                    .end => {
                        done = true;
                    },
                    else => {
                        done = true;
                    },
                }
                break;
            }
            rclient.waitForMessage(50_000_000); // 50ms
        }
        if (attempts >= 100) done = true;
    }

    if (count == 0) {
        serialWrite("save-config: no config to save\r\n");
        return;
    }

    // Write to NFS: put router.cfg
    const nclient = text_cmd.Client.init(nfs_chan);
    nclient.sendCommand("put router.cfg");

    // Wait for ack
    var ack_buf: [256]u8 = undefined;
    var got_ack = false;
    var ack_attempts: u32 = 0;
    while (ack_attempts < 50) : (ack_attempts += 1) {
        if (nclient.recv(&ack_buf)) |msg| {
            switch (msg) {
                .ack => {
                    got_ack = true;
                },
                else => {},
            }
            break;
        }
        nclient.waitForMessage(100_000_000); // 100ms
    }
    if (!got_ack) {
        serialWrite("save-config: NFS not responding\r\n");
        return;
    }

    // Send each config line
    for (0..count) |i| {
        nclient.sendData(lines[i][0..line_lens[i]]);
    }

    // Commit
    nclient.sendDataEnd();
    nfsWaitResponse();
    serialWrite("save-config: OK\r\n");
}

fn loadConfig() void {
    if (!has_router or !has_nfs) {
        serialWrite("load-config: router or NFS not connected\r\n");
        return;
    }

    // Read config from NFS
    const nclient = text_cmd.Client.init(nfs_chan);
    nclient.sendCommand("cat router.cfg");
    var resp: [2048]u8 = undefined;
    var config_data: [4096]u8 = undefined;
    var config_len: usize = 0;

    var done = false;
    while (!done) {
        var attempts: u32 = 0;
        while (attempts < 50) : (attempts += 1) {
            if (nclient.recv(&resp)) |msg| {
                switch (msg) {
                    .text => |text| {
                        const copy_len = @min(text.len, config_data.len - config_len);
                        @memcpy(config_data[config_len..][0..copy_len], text[0..copy_len]);
                        config_len += copy_len;
                    },
                    .end => {
                        done = true;
                    },
                    .err => {
                        // Error -- file not found
                        serialWrite("load-config: no config file\r\n");
                        return;
                    },
                    else => {},
                }
                break;
            }
            nclient.waitForMessage(100_000_000); // 100ms
        }
        if (attempts >= 50) done = true;
    }

    if (config_len == 0) {
        serialWrite("load-config: empty config\r\n");
        return;
    }

    // Parse lines and send each as a router command
    const rclient = text_cmd.Client.init(router_chan);
    var applied: u32 = 0;
    var start: usize = 0;
    for (0..config_len) |i| {
        if (config_data[i] == '\n' or i == config_len - 1) {
            var end = i;
            if (i == config_len - 1 and config_data[i] != '\n') end = i + 1;
            if (end > start) {
                const line = config_data[start..end];
                // Send to router as a command
                rclient.sendCommand(line);
                // Wait for response (discard it)
                var r_resp: [512]u8 = undefined;
                var r_attempts: u32 = 0;
                while (r_attempts < 50) : (r_attempts += 1) {
                    if (rclient.recv(&r_resp)) |_| break;
                    rclient.waitForMessage(50_000_000); // 50ms
                }
                applied += 1;
            }
            start = i + 1;
        }
    }

    serialWrite("load-config: applied ");
    var num_buf: [8]u8 = undefined;
    var n = applied;
    var digits: usize = 0;
    if (n == 0) {
        num_buf[0] = '0';
        digits = 1;
    } else {
        while (n > 0) {
            num_buf[7 - digits] = '0' + @as(u8, @truncate(n % 10));
            digits += 1;
            n /= 10;
        }
    }
    if (applied == 0) {
        serialWrite("0");
    } else {
        serialWrite(num_buf[8 - digits .. 8]);
    }
    serialWrite(" rules\r\n");
}

fn nfsWaitResponse() void {
    const client = text_cmd.Client.init(nfs_chan);
    var resp: [256]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 50) : (attempts += 1) {
        if (client.recv(&resp)) |msg| {
            switch (msg) {
                .end => return,
                .text => |text| {
                    serialWrite(text);
                    return;
                },
                .err => |text| {
                    serialWrite(text);
                    serialWrite("\r\n");
                    return;
                },
                .ack => |text| {
                    serialWrite(text);
                    return;
                },
            }
        }
        client.waitForMessage(100_000_000); // 100ms
    }
}

fn ntpMultiResponse(cmd: []const u8) void {
    if (!has_ntp) {
        serialWrite("ntp: not connected\r\n");
        return;
    }
    const client = text_cmd.Client.init(ntp_chan);
    // Drain stale
    {
        var stale_buf: [256]u8 = undefined;
        while (client.recv(&stale_buf) != null) {}
    }
    client.sendCommand(cmd);
    var resp: [256]u8 = undefined;
    var msg_count: u32 = 0;
    var done = false;
    var retries: u32 = 0;
    while (!done and msg_count < 8) {
        if (client.recv(&resp)) |msg| {
            switch (msg) {
                .text => |text| {
                    serialWrite(text);
                    msg_count += 1;
                },
                .end => {
                    done = true;
                },
                else => {
                    done = true;
                },
            }
        } else {
            client.waitForMessage(500_000_000); // 500ms
            if (client.recv(&resp)) |msg| {
                switch (msg) {
                    .text => |text| {
                        serialWrite(text);
                        msg_count += 1;
                    },
                    .end => {
                        done = true;
                    },
                    else => {
                        done = true;
                    },
                }
            } else {
                retries += 1;
                if (retries >= 12) done = true; // 6s total
            }
        }
    }
    if (msg_count == 0) {
        serialWrite("ntp: no response\r\n");
    }
}

fn reloadCommand(line: []const u8) void {
    if (!has_root) {
        serialWrite("reload: root service not connected\r\n");
        return;
    }
    const name = blk: {
        var rest = line;
        if (rest.len > 7) {
            rest = rest[7..];
            while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];
            if (rest.len > 0) break :blk rest;
        }
        serialWrite("usage: reload <name>\r\n");
        return;
    };

    const client = reload_proto.Client.init(root_chan);
    client.sendReload(name);

    var resp: [256]u8 = undefined;
    var done = false;
    var attempts: u32 = 0;
    while (!done and attempts < 200) : (attempts += 1) {
        if (client.recv(&resp)) |msg| {
            switch (msg) {
                .status => |text| {
                    serialWrite(text);
                    serialWrite("\r\n");
                    attempts = 0;
                },
                .ok => {
                    serialWrite("reload: OK\r\n");
                    done = true;
                },
                .err => |text| {
                    serialWrite("reload: error: ");
                    serialWrite(text);
                    serialWrite("\r\n");
                    done = true;
                },
            }
        } else {
            client.waitForMessage(100_000_000);
        }
    }

    if (!done) {
        serialWrite("reload: timeout\r\n");
        return;
    }

    reconnectService(name);
}

fn reconnectService(name: []const u8) void {
    if (eql(name, "router")) {
        reconnectBroadcast(.router);
        if (has_router) serialWrite("reconnected to router\r\n");
    } else if (eql(name, "nfs_client")) {
        reconnectBroadcast(.nfs_client);
        if (has_nfs) serialWrite("reconnected to nfs_client\r\n");
    } else if (eql(name, "ntp_client")) {
        reconnectBroadcast(.ntp_client);
        if (has_ntp) serialWrite("reconnected to ntp_client\r\n");
    } else if (eql(name, "http_server")) {
        reconnectBroadcast(.http_server);
    }
}

fn reconnectBroadcast(protocol: lib.Protocol) void {
    // Get the current (stale) handle so we can wait for a new one
    const old_handle = channel.findBroadcastHandle(perm_view_global, protocol) orelse 0;

    var handle: u64 = 0;
    var retries: u32 = 0;
    while (retries < 50000) : (retries += 1) {
        handle = channel.findBroadcastHandle(perm_view_global, protocol) orelse 0;
        if (handle != 0 and handle != old_handle) break;
        handle = 0;
        syscall.thread_yield();
    }
    // Fallback to whatever handle is available
    if (handle == 0) {
        handle = channel.findBroadcastHandle(perm_view_global, protocol) orelse return;
    }

    const conn = Channel.connectAsA(handle, .console, DEFAULT_SHM_SIZE) catch return;
    switch (protocol) {
        .router => {
            router_chan = conn.chan;
            has_router = true;
        },
        .nfs_client => {
            nfs_chan = conn.chan;
            has_nfs = true;
        },
        .ntp_client => {
            ntp_chan = conn.chan;
            has_ntp = true;
        },
        else => {},
    }
}

fn printUptime(hrs: u64, mins: u64, secs: u64) void {
    serialWrite("uptime: ");
    printDecSerial(hrs);
    serialWrite("h ");
    printDecSerial(mins);
    serialWrite("m ");
    printDecSerial(secs);
    serialWrite("s\r\n");
}

fn printDecSerial(val: u64) void {
    if (val == 0) {
        serialWrite("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var v = val;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    serialWrite(buf[i..20]);
}

pub fn main(perm_view_addr: u64) void {
    perm_view_global = perm_view_addr;

    // Serial is required -- poll until found
    var serial_handle: u64 = 0;
    while (serial_handle == 0) {
        serial_handle = channel.findBroadcastHandle(perm_view_addr, .serial) orelse 0;
        if (serial_handle == 0) syscall.thread_yield();
    }
    {
        const conn = Channel.connectAsA(serial_handle, .console, DEFAULT_SHM_SIZE) catch return;
        serial_chan = conn.chan;
        addKnownShmHandle(conn.shm_handle);
    }

    // Optional: router (limited retry)
    {
        var handle: u64 = 0;
        var retries: u32 = 0;
        while (handle == 0 and retries < 5000) : (retries += 1) {
            handle = channel.findBroadcastHandle(perm_view_addr, .router) orelse 0;
            if (handle == 0) syscall.thread_yield();
        }
        if (handle != 0) {
            if (Channel.connectAsA(handle, .console, DEFAULT_SHM_SIZE) catch null) |conn| {
                router_chan = conn.chan;
                has_router = true;
                addKnownShmHandle(conn.shm_handle);
            }
        }
    }

    // Optional: nfs_client (limited retry)
    {
        var handle: u64 = 0;
        var retries: u32 = 0;
        while (handle == 0 and retries < 5000) : (retries += 1) {
            handle = channel.findBroadcastHandle(perm_view_addr, .nfs_client) orelse 0;
            if (handle == 0) syscall.thread_yield();
        }
        if (handle != 0) {
            if (Channel.connectAsA(handle, .console, DEFAULT_SHM_SIZE) catch null) |conn| {
                nfs_chan = conn.chan;
                has_nfs = true;
                addKnownShmHandle(conn.shm_handle);
            }
        }
    }

    // Optional: ntp_client (limited retry)
    {
        var handle: u64 = 0;
        var retries: u32 = 0;
        while (handle == 0 and retries < 5000) : (retries += 1) {
            handle = channel.findBroadcastHandle(perm_view_addr, .ntp_client) orelse 0;
            if (handle == 0) syscall.thread_yield();
        }
        if (handle != 0) {
            if (Channel.connectAsA(handle, .console, DEFAULT_SHM_SIZE) catch null) |conn| {
                ntp_chan = conn.chan;
                has_ntp = true;
                addKnownShmHandle(conn.shm_handle);
            }
        }
    }

    // Root service channel: granted directly via SHM (not broadcast)
    // Uses protocol_id dispatch like desktopOS usb_driver pattern
    {
        var retries: u32 = 0;
        while (!has_root and retries < 5000) : (retries += 1) {
            if (pollNewShm(perm_view_addr)) |shm_handle| {
                if (Channel.connectAsB(shm_handle, DEFAULT_SHM_SIZE) catch null) |chan| {
                    if (chan.protocol_id == @intFromEnum(lib.Protocol.root_service)) {
                        root_chan = chan;
                        has_root = true;
                    }
                }
            } else {
                syscall.thread_yield();
            }
        }
    }

    serialWrite("\x1b[2J\x1b[H");
    serialWrite("=== Zag RouterOS Console ===\r\n");
    serialWrite("Type 'help' for available commands.\r\n");
    serialWrite("Use 'load-config' to restore saved settings.\r\n\r\n");
    serialWrite("> ");

    var line_buf: [CMD_MAX]u8 = undefined;
    var line_len: usize = 0;
    var rx_buf: [64]u8 = undefined;

    while (true) {
        if (serial_chan.receiveMessage(.A, &rx_buf) catch null) |len_u64| {
            const len: usize = @intCast(len_u64);
            for (rx_buf[0..len]) |byte| {
                if (byte == '\r' or byte == '\n') {
                    serialWrite("\r\n");
                    processCommand(line_buf[0..line_len]);
                    line_len = 0;
                    serialWrite("> ");
                } else if (byte == 127 or byte == 8) {
                    if (line_len > 0) {
                        line_len -= 1;
                        serialWrite("\x08 \x08");
                    }
                } else if (byte >= 32 and line_len < CMD_MAX) {
                    line_buf[line_len] = byte;
                    line_len += 1;
                    serialWriteByte(byte);
                }
            }
        }
        syscall.thread_yield();
    }
}
