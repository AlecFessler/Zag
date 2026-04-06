const lib = @import("lib");
const router = @import("router");

const arp = router.protocols.arp;
const console = router.console;
const dhcp_client = router.protocols.dhcp_client;
const dhcp_server = router.protocols.dhcp_server;
const dhcpv6_client = router.protocols.ipv6.dhcp_client;
const dns = router.protocols.dns;
const firewall = router.protocols.ipv4.firewall;
const firewall6 = router.protocols.ipv6.firewall;
const frag = router.protocols.frag;
const http_handler = router.http_handler;
const log = router.log;
const main = router.state;
const nat = router.protocols.ipv4.nat;
const ndp = router.protocols.ipv6.ndp;
const ping_mod = router.protocols.ipv4.icmp;
const slaac = router.protocols.ipv6.slaac;
const tcp_stack = router.protocols.tcp_stack;
const udp_fwd = router.protocols.udp_fwd;
const util = router.util;

const Arena = lib.arena.Arena;
const channel = lib.channel;
const http_proto = lib.http;
const ntp_proto = lib.ntp;
const pv = lib.perm_view;
const syscall = lib.syscall;
const text_cmd = lib.text_command;

const Channel = channel.Channel;

const MAINTENANCE_INTERVAL_NS: u64 = 10_000_000_000;
var last_maintenance_ns: u64 = 0;

var known_shm_handles: [32]u64 = .{0} ** 32;
var known_shm_count: u8 = 0;

pub fn addKnownShmHandle(handle: u64) void {
    if (known_shm_count < 32) {
        known_shm_handles[known_shm_count] = handle;
        known_shm_count += 1;
    }
}

fn pollNewShm(view_addr: u64) ?u64 {
    const v: *const [128]pv.UserViewEntry = @ptrFromInt(view_addr);
    for (v) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            var known = false;
            for (known_shm_handles[0..known_shm_count]) |kh| {
                if (kh == entry.handle) {
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

fn detectAppChannels(perm_view_addr_local: u64) void {
    const shm_handle = pollNewShm(perm_view_addr_local) orelse return;
    const chan = Channel.connectAsB(shm_handle, 4 * syscall.PAGE4K) catch return;
    switch (chan.protocol_id) {
        @intFromEnum(lib.Protocol.nfs_client) => {
            main.nfs_chan = chan;
            log.write(.nfs_connected);
        },
        @intFromEnum(lib.Protocol.ntp_client) => {
            main.ntp_chan = chan;
            log.write(.ntp_connected);
        },
        @intFromEnum(lib.Protocol.http_server) => {
            main.http_chan = chan;
            log.write(.http_connected);
        },
        @intFromEnum(lib.Protocol.console) => {
            main.console_chan = chan;
            log.write(.console_connected);
        },
        else => {},
    }
}

pub fn crashReasonName(reason: pv.CrashReason) []const u8 {
    return switch (reason) {
        .none => "none",
        .stack_overflow => "stack_overflow",
        .stack_underflow => "stack_underflow",
        .invalid_read => "invalid_read",
        .invalid_write => "invalid_write",
        .invalid_execute => "invalid_execute",
        .unmapped_access => "unmapped_access",
        .out_of_memory => "out_of_memory",
        .arithmetic_fault => "arithmetic_fault",
        .illegal_instruction => "illegal_instruction",
        .alignment_fault => "alignment_fault",
        .protection_fault => "protection_fault",
        .normal_exit => "normal_exit",
        .killed => "killed",
        .revoked => "revoked",
        _ => "unknown",
    };
}

pub fn periodicMaintenance() void {
    const ts = util.now();
    if (ts -| last_maintenance_ns < MAINTENANCE_INTERVAL_NS) return;
    last_maintenance_ns = ts;
    arp.expire(&main.wan_iface.arp_table);
    if (main.has_lan) arp.expire(&main.lan_iface.arp_table);
    nat.expire();
    frag.expire(&main.frag_table);
    dhcp_server.expireLeases();
    dhcp_client.tick();
    ndp.expire(&main.wan_ndp_table);
    if (main.has_lan) ndp.expire(&main.lan_ndp_table);
    firewall6.expire();
    dns.expireCache();
    firewall.expireLeases(&main.port_forwards, ts);
    dhcpv6_client.tick();
    if (main.has_lan) slaac.tick();
}

fn readU64Be(b: *const [8]u8) u64 {
    return @as(u64, b[0]) << 56 | @as(u64, b[1]) << 48 |
        @as(u64, b[2]) << 40 | @as(u64, b[3]) << 32 |
        @as(u64, b[4]) << 24 | @as(u64, b[5]) << 16 |
        @as(u64, b[6]) << 8 | @as(u64, b[7]);
}

/// Service thread: handles console commands, NFS/NTP app messages, and channel detection.
/// Runs on core 0 (preemptive) so it doesn't interfere with the pinned data-plane threads.
pub fn serviceThread() void {
    if (main.perm_view == null) return;
    var loop_n: u32 = 0;

    log.write(.service_started);

    var svc_arena = Arena.init(1 << 30) orelse return;
    const a = svc_arena.allocator();

    const cmd_buf = a.alloc(u8, 256) catch return;
    const nfs_buf = a.alloc(u8, 2048) catch return;
    const ntp_buf = a.alloc(u8, 256) catch return;
    const http_buf = a.alloc(u8, 8192) catch return;
    var http_chunks_expected: u8 = 0;
    var http_chunks_received: u8 = 0;
    const state_buf = a.alloc(u8, 4096) catch return;

    while (true) {
        loop_n +%= 1;

        // Channel detection (periodically scan for new SHM channels)
        if (loop_n % 50 == 0) detectAppChannels(main.perm_view_addr_global);

        // Console command handling
        if (main.console_chan) |chan| {
            const con_srv = text_cmd.Server.init(chan);
            if (con_srv.recvCommand(cmd_buf)) |cmd| {
                switch (cmd) {
                    .text => |text| console.handleCommand(chan, text),
                    else => {},
                }
            }
        }

        // NFS app messages
        if (main.nfs_chan) |chan| {
            if (chan.receiveMessage(.B, nfs_buf) catch null) |nfs_len| {
                udp_fwd.handleAppMessage(nfs_buf[0..nfs_len], .nfs);
            }
        }

        // NTP app messages
        if (main.ntp_chan) |chan| {
            if (chan.receiveMessage(.B, ntp_buf) catch null) |ntp_len| {
                if (ntp_len >= 17 and ntp_buf[0] == ntp_proto.CMD_TIME_SYNC) {
                    // [0] = CMD_TIME_SYNC, [1..9] = unix_secs, [9..17] = mono_ns
                    const unix_secs = readU64Be(ntp_buf[1..9]);
                    const mono_ns = readU64Be(ntp_buf[9..17]);
                    log.updateNtpTime(unix_secs, mono_ns);
                } else {
                    udp_fwd.handleAppMessage(ntp_buf[0..ntp_len], .ntp);
                }
            }
        }

        // HTTP server app messages
        if (main.http_chan) |chan| {
            if (chan.receiveMessage(.B, http_buf) catch null) |hlen| {
                if (hlen >= 3 and http_buf[0] == http_proto.CMD_HTTP_RESPONSE) {
                    const chunk_idx = http_buf[1];
                    const total_chunks = http_buf[2];
                    const chunk_data = http_buf[3..hlen];

                    if (chunk_idx == 0) {
                        // First chunk: parse metadata and send HTTP header + body start
                        http_chunks_expected = total_chunks;
                        http_chunks_received = 1;
                        http_handler.handleResponseStreaming(chunk_data, total_chunks == 1);
                    } else {
                        // Continuation chunk: send body data directly as TCP
                        http_chunks_received += 1;
                        const is_last = (http_chunks_received >= http_chunks_expected);
                        if (is_last) {
                            // Last chunk: send data + FIN
                            tcp_stack.sendTcpChunk(chunk_data);
                            tcp_stack.sendTcpFin();
                            http_chunks_expected = 0;
                            http_chunks_received = 0;
                        } else {
                            tcp_stack.sendTcpChunk(chunk_data);
                        }
                    }
                } else {
                    http_handler.handleMessage(http_buf[0..hlen], chan, state_buf);
                }
            }
        }

        // Periodic maintenance (timers, expiry, DHCP ticks)
        periodicMaintenance();
        ping_mod.checkTimeout();
        ping_mod.checkTracerouteTimeout();

        // Drain log ring buffer and flush to NFS
        log.drainAndFlush(&main.nfs_chan, loop_n);

        syscall.thread_yield();
    }
}
