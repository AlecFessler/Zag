const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Verifies discovery: should see leaf_a1b (ttl=2) and leaf_a2a (ttl=3), NOT leaf_a1a (ttl=1).
/// Requests channel_id=200 to leaf_a1b.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_a2b: starting, waiting for discovery entries\n");

    // Wait for entries to propagate
    var entries: [256]channel.DiscoveryTable.Entry = undefined;
    var count: u8 = 0;
    while (count < 2) {
        if (channel.discovery_table) |dt| {
            count = channel.readDT(dt, &entries);
        }
        if (count < 2) syscall.thread_yield();
    }

    // Verify: should see proto=2 (leaf_a1b) and proto=3 (leaf_a2a), NOT proto=1 (leaf_a1a)
    var saw_proto1 = false;
    var saw_proto2 = false;
    var saw_proto3 = false;
    var target_id: ?channel.SemanticID = null;
    for (entries[0..count]) |entry| {
        const p = @intFromEnum(entry.proto);
        if (p == 1) saw_proto1 = true;
        if (p == 2) {
            saw_proto2 = true;
            target_id = entry.id;
        }
        if (p == 3) saw_proto3 = true;
    }

    if (saw_proto1) syscall.write("leaf_a2b: FAIL saw proto=1 (leaf_a1a ttl=1 should not reach here)\n");
    if (!saw_proto2) {
        syscall.write("leaf_a2b: FAIL did not see proto=2 (leaf_a1b ttl=2)\n");
        return;
    }
    if (!saw_proto3) syscall.write("leaf_a2b: FAIL did not see proto=3 (leaf_a2a ttl=3)\n");
    syscall.write("leaf_a2b: PASS visibility correct\n");

    // Request channel to leaf_a1b
    const tid = target_id orelse return;
    syscall.write("leaf_a2b: requesting channel 200 to leaf_a1b\n");
    channel.requestChannel(tid, 200) catch {
        syscall.write("leaf_a2b: FAIL requestChannel failed\n");
        return;
    };

    const chan = channel.awaitChannel(200, 5_000_000_000) orelse {
        syscall.write("leaf_a2b: FAIL awaitChannel(200) timed out\n");
        return;
    };
    syscall.write("leaf_a2b: got channel 200, sending message\n");
    chan.enqueue(.A, "hello from a2b") catch {
        syscall.write("leaf_a2b: FAIL enqueue failed\n");
        return;
    };
    syscall.write("leaf_a2b: PASS channel 200 connected and message sent\n");
    while (true) {
        syscall.thread_yield();
    }
}
