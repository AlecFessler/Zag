const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

var serial_chan: channel_mod.Channel = undefined;
var router_chan: channel_mod.Channel = undefined;
var nfs_chan: channel_mod.Channel = undefined;
var ntp_chan: channel_mod.Channel = undefined;
var has_router: bool = false;
var has_nfs: bool = false;
var has_ntp: bool = false;

fn serialWrite(data: []const u8) void {
    _ = serial_chan.send(data);
}

fn serialWriteByte(byte: u8) void {
    const buf = [_]u8{byte};
    _ = serial_chan.send(&buf);
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
    } else if (eql(line, "version")) {
        serialWrite("Zag RouterOS v0.1\r\n");
    } else if (eql(line, "uptime")) {
        const ns: u64 = @bitCast(syscall.clock_gettime());
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
    _ = router_chan.send(cmd);
    var resp: [512]u8 = undefined;
    var attempts: u8 = 0;
    while (attempts < 20) : (attempts += 1) {
        if (router_chan.recv(&resp)) |len| {
            serialWrite(resp[0..len]);
            serialWrite("\r\n");
            return;
        }
        router_chan.rx.waitForData(50_000_000); // 50ms
    }
    serialWrite("router: no response\r\n");
}

fn routerMultiResponse(cmd: []const u8) void {
    if (!has_router) {
        serialWrite("router: not connected\r\n");
        return;
    }
    _ = router_chan.send(cmd);
    var resp: [512]u8 = undefined;
    var msg_count: u32 = 0;
    var done = false;
    while (!done and msg_count < 40) {
        if (router_chan.recv(&resp)) |len| {
            serialWrite(resp[0..len]);
            serialWrite("\r\n");
            msg_count += 1;
            if (len >= 3 and resp[0] == '-' and resp[1] == '-' and resp[2] == '-') {
                done = true;
            }
        } else {
            router_chan.rx.waitForData(50_000_000); // 50ms
            if (router_chan.recv(&resp)) |len| {
                serialWrite(resp[0..len]);
                serialWrite("\r\n");
                msg_count += 1;
                if (len >= 3 and resp[0] == '-' and resp[1] == '-' and resp[2] == '-') {
                    done = true;
                }
            } else {
                done = true; // timed out, no more data
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
    // Drain any stale messages (e.g. auto-mount response) before sending new command
    {
        var stale_buf: [2048]u8 = undefined;
        while (nfs_chan.recv(&stale_buf) != null) {}
    }
    _ = nfs_chan.send(cmd);
    var resp: [2048]u8 = undefined;
    var msg_count: u32 = 0;
    var done = false;
    while (!done and msg_count < 64) {
        if (nfs_chan.recv(&resp)) |len| {
            if (len == 0) {
                done = true;
                continue;
            }
            if (len > 0 and resp[0] == 0xFF) {
                serialWrite(resp[1..len]);
                serialWrite("\r\n");
            } else {
                serialWrite(resp[0..len]);
            }
            msg_count += 1;
        } else {
            nfs_chan.rx.waitForData(50_000_000); // 50ms
            if (nfs_chan.recv(&resp)) |len| {
                if (len == 0) {
                    done = true;
                    continue;
                }
                if (len > 0 and resp[0] == 0xFF) {
                    serialWrite(resp[1..len]);
                    serialWrite("\r\n");
                } else {
                    serialWrite(resp[0..len]);
                }
                msg_count += 1;
            } else {
                done = true;
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
    // Send the put command to NFS client
    _ = nfs_chan.send(cmd);

    // Wait for the "OK: send data" response
    var resp: [256]u8 = undefined;
    var got_ack = false;
    var attempts: u32 = 0;
    while (attempts < 50) : (attempts += 1) {
        if (nfs_chan.recv(&resp)) |len| {
            serialWrite(resp[0..len]);
            got_ack = true;
            break;
        }
        nfs_chan.rx.waitForData(100_000_000); // 100ms
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
        if (serial_chan.recv(&rx_buf)) |len| {
            for (rx_buf[0..len]) |byte| {
                if (byte == '\r' or byte == '\n') {
                    serialWrite("\r\n");
                    if (line_len == 0) {
                        // Empty line = done, send empty to NFS client
                        _ = nfs_chan.send(&[_]u8{});
                        // Wait for commit response
                        nfsWaitResponse();
                        return;
                    }
                    _ = nfs_chan.send(line_buf[0..line_len]);
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

fn autoLoadConfig() void {
    // Quick check: send NFS status query and see if we get a response
    _ = nfs_chan.send("status");
    var resp: [256]u8 = undefined;
    var nfs_alive = false;
    var attempts: u32 = 0;
    while (attempts < 20) : (attempts += 1) {
        if (nfs_chan.recv(&resp)) |_| {
            nfs_alive = true;
            break;
        }
        nfs_chan.rx.waitForData(100_000_000); // 100ms
    }

    if (!nfs_alive) {
        syscall.write("console: NFS not ready, skipping config load\n");
        return;
    }

    // NFS client is alive — try mount
    _ = nfs_chan.send("mount");
    var mounted = false;
    attempts = 0;
    while (attempts < 50) : (attempts += 1) {
        if (nfs_chan.recv(&resp)) |len| {
            if (len == 0) {
                mounted = true;
                break;
            }
            if (len >= 5) {
                if (containsStr(resp[0..len], "mounted") or containsStr(resp[0..len], "OK")) {
                    mounted = true;
                }
            }
            break;
        }
        nfs_chan.rx.waitForData(100_000_000); // 100ms
    }
    drainNfs();

    if (!mounted) {
        syscall.write("console: NFS mount failed, skipping config load\n");
        return;
    }

    syscall.write("console: loading config from NFS\n");
    loadConfig();
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
    var buf: [2048]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 20) : (attempts += 1) {
        if (nfs_chan.recv(&buf)) |len| {
            if (len == 0) return; // EOF
            attempts = 0; // Reset on data
        }
        nfs_chan.rx.waitForData(50_000_000); // 50ms
    }
}

fn saveConfig() void {
    if (!has_router or !has_nfs) {
        serialWrite("save-config: router or NFS not connected\r\n");
        return;
    }

    // Get config lines from router
    _ = router_chan.send("get-config");
    var lines: [64][256]u8 = undefined;
    var line_lens: [64]usize = .{0} ** 64;
    var count: usize = 0;

    var done = false;
    while (!done and count < 64) {
        var attempts: u32 = 0;
        while (attempts < 100) : (attempts += 1) {
            var resp: [256]u8 = undefined;
            if (router_chan.recv(&resp)) |len| {
                if (len >= 3 and resp[0] == '-' and resp[1] == '-' and resp[2] == '-') {
                    done = true;
                } else if (len > 0) {
                    @memcpy(lines[count][0..len], resp[0..len]);
                    line_lens[count] = len;
                    count += 1;
                }
                break;
            }
            router_chan.rx.waitForData(50_000_000); // 50ms
        }
        if (attempts >= 100) done = true;
    }

    if (count == 0) {
        serialWrite("save-config: no config to save\r\n");
        return;
    }

    // Write to NFS: put router.cfg
    _ = nfs_chan.send("put router.cfg");

    // Wait for ack
    var ack_buf: [256]u8 = undefined;
    var got_ack = false;
    var ack_attempts: u32 = 0;
    while (ack_attempts < 50) : (ack_attempts += 1) {
        if (nfs_chan.recv(&ack_buf)) |_| {
            got_ack = true;
            break;
        }
        nfs_chan.rx.waitForData(100_000_000); // 100ms
    }
    if (!got_ack) {
        serialWrite("save-config: NFS not responding\r\n");
        return;
    }

    // Send each config line
    for (0..count) |i| {
        _ = nfs_chan.send(lines[i][0..line_lens[i]]);
        // NFS put only takes one data message then commits on empty
        // But our NFS client sends one WRITE per data message
        // Wait briefly for the write to complete
        nfs_chan.rx.waitForData(50_000_000); // 50ms
    }

    // Empty line = EOF/commit
    _ = nfs_chan.send(&[_]u8{});
    nfsWaitResponse();
    serialWrite("save-config: OK\r\n");
}

fn loadConfig() void {
    if (!has_router or !has_nfs) {
        serialWrite("load-config: router or NFS not connected\r\n");
        return;
    }

    // Read config from NFS
    _ = nfs_chan.send("cat router.cfg");
    var resp: [2048]u8 = undefined;
    var config_data: [4096]u8 = undefined;
    var config_len: usize = 0;

    var done = false;
    while (!done) {
        var attempts: u32 = 0;
        while (attempts < 50) : (attempts += 1) {
            if (nfs_chan.recv(&resp)) |len| {
                if (len == 0) {
                    done = true;
                } else if (len > 0 and resp[0] == 0xFF) {
                    // Error — file not found
                    serialWrite("load-config: no config file\r\n");
                    return;
                } else {
                    const copy_len = @min(len, config_data.len - config_len);
                    @memcpy(config_data[config_len..][0..copy_len], resp[0..copy_len]);
                    config_len += copy_len;
                }
                break;
            }
            nfs_chan.rx.waitForData(100_000_000); // 100ms
        }
        if (attempts >= 50) done = true;
    }

    if (config_len == 0) {
        serialWrite("load-config: empty config\r\n");
        return;
    }

    // Parse lines and send each as a router command
    var applied: u32 = 0;
    var start: usize = 0;
    for (0..config_len) |i| {
        if (config_data[i] == '\n' or i == config_len - 1) {
            var end = i;
            if (i == config_len - 1 and config_data[i] != '\n') end = i + 1;
            if (end > start) {
                const line = config_data[start..end];
                // Send to router as a command
                _ = router_chan.send(line);
                // Wait for response (discard it)
                var r_resp: [512]u8 = undefined;
                var r_attempts: u32 = 0;
                while (r_attempts < 50) : (r_attempts += 1) {
                    if (router_chan.recv(&r_resp)) |_| break;
                    router_chan.rx.waitForData(50_000_000); // 50ms
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
    var resp: [256]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 50) : (attempts += 1) {
        if (nfs_chan.recv(&resp)) |len| {
            if (len == 0) return; // EOF
            serialWrite(resp[0..len]);
            return;
        }
        nfs_chan.rx.waitForData(100_000_000); // 100ms
    }
}

fn ntpMultiResponse(cmd: []const u8) void {
    if (!has_ntp) {
        serialWrite("ntp: not connected\r\n");
        return;
    }
    // Drain any stale messages (e.g. auto-sync response) before sending new command
    {
        var stale_buf: [256]u8 = undefined;
        while (ntp_chan.recv(&stale_buf) != null) {}
    }
    _ = ntp_chan.send(cmd);
    var resp: [256]u8 = undefined;
    var msg_count: u32 = 0;
    var done = false;
    while (!done and msg_count < 8) {
        if (ntp_chan.recv(&resp)) |len| {
            if (len == 0) {
                done = true;
                continue;
            }
            serialWrite(resp[0..len]);
            msg_count += 1;
        } else {
            ntp_chan.rx.waitForData(50_000_000); // 50ms
            if (ntp_chan.recv(&resp)) |len| {
                if (len == 0) {
                    done = true;
                    continue;
                }
                serialWrite(resp[0..len]);
                msg_count += 1;
            } else {
                done = true;
            }
        }
    }
    if (msg_count == 0) {
        serialWrite("ntp: no response\r\n");
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

var mapped_handles: [16]u64 = .{0} ** 16;
var num_mapped: u32 = 0;

fn isHandleMapped(handle: u64) bool {
    for (mapped_handles[0..num_mapped]) |h| {
        if (h == handle) return true;
    }
    return false;
}

fn recordMapped(handle: u64) void {
    if (num_mapped < mapped_handles.len) {
        mapped_handles[num_mapped] = handle;
        num_mapped += 1;
    }
}

fn mapNextDataShm(perm_view_addr: u64) ?*channel_mod.ChannelHeader {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type != pv.ENTRY_TYPE_SHARED_MEMORY) continue;
        if (entry.field0 <= shm_protocol.COMMAND_SHM_SIZE) continue;
        if (isHandleMapped(entry.handle)) continue;
        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const vm = syscall.vm_reserve(0, entry.field0, vm_rights);
        if (vm.val < 0) continue;
        if (syscall.shm_map(entry.handle, @intCast(vm.val), 0) != 0) continue;
        recordMapped(entry.handle);
        return @ptrFromInt(vm.val2);
    }
    return null;
}

fn waitAndMapNextShm(perm_view_addr: u64) *channel_mod.ChannelHeader {
    while (true) {
        if (mapNextDataShm(perm_view_addr)) |header| return header;
        pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }
}

pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse return;

    // Record command SHM handle so we skip it
    {
        const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and entry.field0 <= shm_protocol.COMMAND_SHM_SIZE) {
                recordMapped(entry.handle);
                break;
            }
        }
    }

    // Serial is required — wait for it.
    var serial_entry: *shm_protocol.ConnectionEntry = undefined;
    while (true) {
        serial_entry = cmd.requestConnection(shm_protocol.ServiceId.SERIAL) orelse {
            cmd.waitForNotification(MAX_TIMEOUT);
            continue;
        };
        break;
    }
    _ = cmd.waitForConnection(serial_entry);
    // Map the next data SHM that appears — it's the serial channel
    const serial_header = waitAndMapNextShm(perm_view_addr);
    serial_chan = channel_mod.Channel.openAsSideA(serial_header) orelse return;

    // Optional connections — request, wait, then map each as it appears
    const router_entry = cmd.requestConnection(shm_protocol.ServiceId.ROUTER);
    const nfs_entry = cmd.requestConnection(shm_protocol.ServiceId.NFS_CLIENT);
    const ntp_entry = cmd.requestConnection(shm_protocol.ServiceId.NTP_CLIENT);

    if (router_entry) |re| {
        _ = cmd.waitForConnection(re);
        const header = waitAndMapNextShm(perm_view_addr);
        if (channel_mod.Channel.openAsSideB(header)) |ch| {
            router_chan = ch;
            has_router = true;
            _ = router_chan.send(&[_]u8{@truncate(shm_protocol.ServiceId.CONSOLE)});
        }
    }

    if (nfs_entry) |ne| {
        _ = cmd.waitForConnection(ne);
        const header = waitAndMapNextShm(perm_view_addr);
        if (channel_mod.Channel.openAsSideB(header)) |ch| {
            nfs_chan = ch;
            has_nfs = true;
        }
    }

    if (ntp_entry) |nte| {
        _ = cmd.waitForConnection(nte);
        const header = waitAndMapNextShm(perm_view_addr);
        if (channel_mod.Channel.openAsSideB(header)) |ch| {
            ntp_chan = ch;
            has_ntp = true;
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
        if (serial_chan.recv(&rx_buf)) |len| {
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
