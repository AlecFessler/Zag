const lib = @import("lib");

const channel_mod = lib.channel;
const embedded = @import("embedded_children");
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_PERMS = 128;
const BENCH_SENDER_ID: u32 = 0xFE;
const BENCH_ECHO_ID: u32 = 0xFF;
const WARMUP_ITERS = 100;

// ---------------------------------------------------------------------------
// Child spawning (minimal broker for bench_echo)
// ---------------------------------------------------------------------------

var echo_channel: ?channel_mod.Channel = null;

fn spawnEchoAndConnect(perm_view_addr: u64) bool {
    _ = perm_view_addr;
    const cmd_shm = syscall.shm_create(shm_protocol.COMMAND_SHM_SIZE);
    if (cmd_shm <= 0) {
        syscall.write("bench: shm_create failed\n");
        return false;
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .execute = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_protocol.COMMAND_SHM_SIZE, vm_rights);
    if (vm_result.val < 0) return false;

    const map_rc = syscall.shm_map(@intCast(cmd_shm), @intCast(vm_result.val), 0);
    if (map_rc != 0) return false;

    const cmd: *shm_protocol.CommandChannel = @ptrFromInt(vm_result.val2);
    cmd.init();
    cmd.addAllowedConnection(BENCH_SENDER_ID);

    const elf = embedded.bench_echo;
    const child_rights = (perms.ProcessRights{ .grant_to = true, .mem_reserve = true }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(elf.ptr), elf.len, child_rights);
    if (proc_handle <= 0) {
        syscall.write("bench: proc_create failed\n");
        return false;
    }

    const grant_rights = (perms.SharedMemoryRights{
        .read = true, .write = true, .grant = true,
    }).bits();
    _ = syscall.grant_perm(@intCast(cmd_shm), @intCast(proc_handle), grant_rights);

    const data_shm = syscall.shm_create(4 * syscall.PAGE4K);
    if (data_shm <= 0) {
        syscall.write("bench: data shm_create failed\n");
        return false;
    }

    const data_vm = syscall.vm_reserve(0, 4 * syscall.PAGE4K, vm_rights);
    if (data_vm.val < 0) return false;
    if (syscall.shm_map(@intCast(data_shm), @intCast(data_vm.val), 0) != 0) return false;

    const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(data_vm.val2);
    const chan_a = channel_mod.Channel.initAsSideA(chan_header, 4 * syscall.PAGE4K);

    _ = syscall.grant_perm(@intCast(data_shm), @intCast(proc_handle), grant_rights);

    // Wait for echo to request connection, then broker it
    var attempts: u32 = 0;
    while (attempts < 100_000) : (attempts += 1) {
        for (cmd.connections[0..cmd.num_connections]) |*entry| {
            if (@as(*volatile u32, &entry.status).* == @intFromEnum(shm_protocol.ConnectionStatus.requested)) {
                @as(*volatile u64, &entry.shm_handle).* = @intCast(data_shm);
                @as(*volatile u64, &entry.shm_size).* = 4 * syscall.PAGE4K;
                @as(*volatile u32, &entry.status).* = @intFromEnum(shm_protocol.ConnectionStatus.connected);
                cmd.notifyChild();
                syscall.write("bench: brokered connection to echo\n");
                echo_channel = chan_a;
                return true;
            }
        }
        syscall.thread_yield();
    }

    syscall.write("bench: echo never requested connection\n");
    return false;
}

// ---------------------------------------------------------------------------
// Local channel helpers
// ---------------------------------------------------------------------------

fn allocPages(n: u32) ?[*]u8 {
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const vm_result = syscall.vm_reserve(0, n * syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) return null;
    return @ptrFromInt(vm_result.val2);
}

fn initLocalChannel(comptime n_pages: u32) ?struct { a: channel_mod.Channel, b: channel_mod.Channel } {
    const base = allocPages(n_pages) orelse return null;
    const header: *channel_mod.ChannelHeader = @ptrCast(@alignCast(base));
    const a = channel_mod.Channel.initAsSideA(header, n_pages * syscall.PAGE4K);
    const b = channel_mod.Channel.openAsSideB(header) orelse return null;
    return .{ .a = a, .b = b };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn ts() u64 {
    return @bitCast(syscall.clock_gettime());
}

fn reportResult(label: []const u8, total_ns: u64, iters: u64) void {
    const avg = total_ns / iters;
    syscall.write("  ");
    syscall.write(label);
    syscall.write(": ");
    t.printDec(avg);
    syscall.write(" ns/op  (");
    t.printDec(iters);
    syscall.write(" iters, ");
    t.printDec(total_ns);
    syscall.write(" total ns)\n");
}

fn reportThroughput(label: []const u8, total_bytes: u64, total_ns: u64) void {
    const bpn_x1000 = if (total_ns > 0) (total_bytes * 1000) / total_ns else 0;
    syscall.write("  ");
    syscall.write(label);
    syscall.write(": ");
    t.printDec(total_bytes);
    syscall.write(" bytes in ");
    t.printDec(total_ns);
    syscall.write(" ns  (");
    t.printDec(bpn_x1000 / 1000);
    syscall.write(".");
    const frac = bpn_x1000 % 1000;
    if (frac < 100) syscall.write("0");
    if (frac < 10) syscall.write("0");
    t.printDec(frac);
    syscall.write(" bytes/ns)\n");
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

pub fn main(perm_view_addr: u64) void {
    syscall.write("=== IPC Channel Benchmarks ===\n");
    const start_ns = ts();

    t.section("channel performance (local)");
    perfSendRecvLatency();
    perfSmallMessageThroughput();
    perfLargeMessageThroughput();
    perfVaryingMessageSizes();
    perfBatchedSendRecv();
    perfRingFullBackpressure();

    t.section("channel performance (cross-process)");
    if (spawnEchoAndConnect(perm_view_addr)) {
        perfCrossProcessRTT();
    } else {
        t.fail("perf: failed to spawn/connect bench_echo");
    }

    const elapsed_ms = (ts() - start_ns) / 1_000_000;
    syscall.write("\nAll benchmarks completed in ");
    t.printDec(elapsed_ms);
    syscall.write("ms\n");
    syscall.shutdown();
}

// ---------------------------------------------------------------------------
// Local (single-process) benchmarks
// ---------------------------------------------------------------------------

fn perfSendRecvLatency() void {
    var ch = initLocalChannel(1) orelse { t.fail("perf latency: alloc failed"); return; };
    const msg = "ping";
    var buf: [64]u8 = undefined;

    var w: u32 = 0;
    while (w < WARMUP_ITERS) : (w += 1) { _ = ch.a.send(msg); _ = ch.b.recv(&buf); }

    const ITERS: u64 = 10_000;
    const start = ts();
    var i: u64 = 0;
    while (i < ITERS) : (i += 1) { _ = ch.a.send(msg); _ = ch.b.recv(&buf); }
    reportResult("send+recv 4B latency", ts() - start, ITERS);
    t.pass("perf: send+recv latency measured");
}

fn perfSmallMessageThroughput() void {
    var ch = initLocalChannel(4) orelse { t.fail("perf small throughput: alloc failed"); return; };
    const msg = "0123456789abcdef";
    var buf: [64]u8 = undefined;

    var w: u32 = 0;
    while (w < WARMUP_ITERS) : (w += 1) { _ = ch.a.send(msg); _ = ch.b.recv(&buf); }

    const BATCH = 500;
    const ROUNDS: u64 = 20;
    const total_msgs = BATCH * ROUNDS;
    const total_bytes = total_msgs * msg.len;

    const start = ts();
    var round: u64 = 0;
    while (round < ROUNDS) : (round += 1) {
        var s: u32 = 0;
        while (s < BATCH) : (s += 1) {
            while (!ch.a.send(msg)) { _ = ch.b.recv(&buf); }
        }
        while (ch.b.hasMessage()) { _ = ch.b.recv(&buf); }
    }
    const elapsed = ts() - start;
    reportThroughput("16B msg throughput", total_bytes, elapsed);
    reportResult("16B msg per-message", elapsed, total_msgs);
    t.pass("perf: small message throughput measured");
}

fn perfLargeMessageThroughput() void {
    var ch = initLocalChannel(4) orelse { t.fail("perf large throughput: alloc failed"); return; };
    var payload: [1024]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    var buf: [1024]u8 = undefined;

    var w: u32 = 0;
    while (w < WARMUP_ITERS) : (w += 1) { _ = ch.a.send(&payload); _ = ch.b.recv(&buf); }

    const ITERS: u64 = 5_000;
    const total_bytes = ITERS * payload.len;
    const start = ts();
    var i: u64 = 0;
    while (i < ITERS) : (i += 1) {
        while (!ch.a.send(&payload)) { _ = ch.b.recv(&buf); }
        while (ch.b.hasMessage()) { _ = ch.b.recv(&buf); }
    }
    const elapsed = ts() - start;
    reportThroughput("1024B msg throughput", total_bytes, elapsed);
    reportResult("1024B msg per-message", elapsed, ITERS);
    t.pass("perf: large message throughput measured");
}

fn perfVaryingMessageSizes() void {
    var ch = initLocalChannel(4) orelse { t.fail("perf varying sizes: alloc failed"); return; };
    var payload: [512]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    var buf: [512]u8 = undefined;
    const sizes = [_]u32{ 1, 8, 64, 256, 512 };
    const labels = [_][]const u8{ "1B   send+recv", "8B   send+recv", "64B  send+recv", "256B send+recv", "512B send+recv" };
    const ITERS: u64 = 5_000;

    for (sizes, 0..) |size, idx| {
        const msg_slice = payload[0..size];
        var w: u32 = 0;
        while (w < WARMUP_ITERS) : (w += 1) { _ = ch.a.send(msg_slice); _ = ch.b.recv(&buf); }
        const start = ts();
        var i: u64 = 0;
        while (i < ITERS) : (i += 1) { _ = ch.a.send(msg_slice); _ = ch.b.recv(&buf); }
        reportResult(labels[idx], ts() - start, ITERS);
    }
    t.pass("perf: varying message sizes measured");
}

fn perfBatchedSendRecv() void {
    var ch = initLocalChannel(4) orelse { t.fail("perf batched: alloc failed"); return; };
    const msg = "batch-test-msg!";
    var buf: [64]u8 = undefined;

    var w: u32 = 0;
    while (w < WARMUP_ITERS) : (w += 1) { _ = ch.a.send(msg); _ = ch.b.recv(&buf); }

    const BATCH_SIZES = [_]u32{ 10, 50, 100 };
    const BATCH_LABELS = [_][]const u8{ "batch=10  send+recv", "batch=50  send+recv", "batch=100 send+recv" };
    const ROUNDS: u64 = 200;

    for (BATCH_SIZES, 0..) |batch_size, idx| {
        const start = ts();
        var round: u64 = 0;
        while (round < ROUNDS) : (round += 1) {
            var s: u32 = 0;
            while (s < batch_size) : (s += 1) { if (!ch.a.send(msg)) break; }
            var r: u32 = 0;
            while (r < batch_size) : (r += 1) { _ = ch.b.recv(&buf) orelse break; }
        }
        reportResult(BATCH_LABELS[idx], ts() - start, ROUNDS * @as(u64, batch_size));
    }
    t.pass("perf: batched send/recv measured");
}

fn perfRingFullBackpressure() void {
    var ch = initLocalChannel(1) orelse { t.fail("perf backpressure: alloc failed"); return; };
    const msg = "fill-msg";
    var buf: [64]u8 = undefined;

    var filled: u32 = 0;
    while (ch.a.send(msg)) { filled += 1; }

    const ITERS: u64 = 10_000;
    const start = ts();
    var i: u64 = 0;
    while (i < ITERS) : (i += 1) { _ = ch.a.send(msg); }
    const full_elapsed = ts() - start;

    while (ch.b.hasMessage()) { _ = ch.b.recv(&buf); }

    const start2 = ts();
    i = 0;
    while (i < ITERS) : (i += 1) { _ = ch.a.send(msg); _ = ch.b.recv(&buf); }
    const normal_elapsed = ts() - start2;

    reportResult("send (ring full, rejected)", full_elapsed, ITERS);
    reportResult("send (ring has space)", normal_elapsed, ITERS);
    syscall.write("  ring capacity: ");
    t.printDec(filled);
    syscall.write(" msgs of 8B\n");
    t.pass("perf: backpressure cost measured");
}

// ---------------------------------------------------------------------------
// Cross-process round-trip (futex wake/wait via brokered SHM channel)
// ---------------------------------------------------------------------------

fn perfCrossProcessRTT() void {
    var chan = echo_channel orelse { t.fail("perf cross-process: no channel"); return; };
    const ITERS: u64 = 5_000;
    var buf: [2048]u8 = undefined;

    // 4B RTT
    const msg4 = "rtt!";
    var w: u32 = 0;
    while (w < WARMUP_ITERS) : (w += 1) {
        _ = chan.send(msg4);
        chan.waitForMessage();
        _ = chan.recv(&buf);
    }
    var start = ts();
    var i: u64 = 0;
    while (i < ITERS) : (i += 1) {
        _ = chan.send(msg4);
        chan.waitForMessage();
        _ = chan.recv(&buf);
    }
    reportResult("cross-process RTT (4B)", ts() - start, ITERS);

    // 64B RTT
    var p64: [64]u8 = undefined;
    for (&p64, 0..) |*b, j| b.* = @truncate(j);
    w = 0;
    while (w < WARMUP_ITERS) : (w += 1) { _ = chan.send(&p64); chan.waitForMessage(); _ = chan.recv(&buf); }
    start = ts();
    i = 0;
    while (i < ITERS) : (i += 1) { _ = chan.send(&p64); chan.waitForMessage(); _ = chan.recv(&buf); }
    reportResult("cross-process RTT (64B)", ts() - start, ITERS);

    // 512B RTT
    var p512: [512]u8 = undefined;
    for (&p512, 0..) |*b, j| b.* = @truncate(j);
    w = 0;
    while (w < WARMUP_ITERS) : (w += 1) { _ = chan.send(&p512); chan.waitForMessage(); _ = chan.recv(&buf); }
    start = ts();
    i = 0;
    while (i < ITERS) : (i += 1) { _ = chan.send(&p512); chan.waitForMessage(); _ = chan.recv(&buf); }
    reportResult("cross-process RTT (512B)", ts() - start, ITERS);

    // 1024B RTT
    var p1k: [1024]u8 = undefined;
    for (&p1k, 0..) |*b, j| b.* = @truncate(j);
    w = 0;
    while (w < WARMUP_ITERS) : (w += 1) { _ = chan.send(&p1k); chan.waitForMessage(); _ = chan.recv(&buf); }
    start = ts();
    i = 0;
    while (i < ITERS) : (i += 1) { _ = chan.send(&p1k); chan.waitForMessage(); _ = chan.recv(&buf); }
    reportResult("cross-process RTT (1024B)", ts() - start, ITERS);

    _ = chan.send("DONE");
    t.pass("perf: cross-process round-trip measured");
}
