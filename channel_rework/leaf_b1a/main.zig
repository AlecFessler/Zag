const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Should see only leaf_a2a (proto=3, ttl=3). NOT leaf_a1a or leaf_a1b.
/// Requests channel_id=100 to leaf_a2a.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_b1a: starting, waiting for discovery entries\n");

    var entries: [256]channel.DiscoveryTable.Entry = undefined;
    var count: u8 = 0;
    while (count < 1) {
        if (channel.discovery_table) |dt| {
            count = channel.readDT(dt, &entries);
        }
        if (count < 1) syscall.thread_yield();
    }

    var saw_proto1 = false;
    var saw_proto2 = false;
    var saw_proto3 = false;
    var target_id: ?channel.SemanticID = null;
    for (entries[0..count]) |entry| {
        const p = @intFromEnum(entry.proto);
        if (p == 1) saw_proto1 = true;
        if (p == 2) saw_proto2 = true;
        if (p == 3) {
            saw_proto3 = true;
            target_id = entry.id;
        }
    }

    if (saw_proto1) syscall.write("leaf_b1a: FAIL saw proto=1\n");
    if (saw_proto2) syscall.write("leaf_b1a: FAIL saw proto=2\n");
    if (!saw_proto3) {
        syscall.write("leaf_b1a: FAIL did not see proto=3\n");
        return;
    }
    syscall.write("leaf_b1a: PASS visibility correct\n");

    const tid = target_id orelse return;
    syscall.write("leaf_b1a: requesting channel 100 to leaf_a2a\n");
    channel.requestChannel(tid, 100) catch {
        syscall.write("leaf_b1a: FAIL requestChannel failed\n");
        return;
    };

    const chan = channel.awaitChannel(100, 5_000_000_000) orelse {
        syscall.write("leaf_b1a: FAIL awaitChannel(100) timed out\n");
        return;
    };
    syscall.write("leaf_b1a: got channel 100, sending message\n");
    chan.enqueue(.A, "hello from b1a") catch {
        syscall.write("leaf_b1a: FAIL enqueue failed\n");
        return;
    };
    syscall.write("leaf_b1a: PASS channel 100 connected and message sent\n");
    while (true) {
        syscall.thread_yield();
    }
}
