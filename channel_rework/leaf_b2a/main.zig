const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Should see only leaf_a2a (proto=3). Requests channel_id=300 to leaf_a2a.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_b2a: starting, waiting for discovery entries\n");

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

    if (saw_proto1) syscall.write("leaf_b2a: FAIL saw proto=1\n");
    if (saw_proto2) syscall.write("leaf_b2a: FAIL saw proto=2\n");
    if (!saw_proto3) {
        syscall.write("leaf_b2a: FAIL did not see proto=3\n");
        return;
    }
    syscall.write("leaf_b2a: PASS visibility correct\n");

    const tid = target_id orelse return;
    syscall.write("leaf_b2a: requesting channel 300 to leaf_a2a\n");
    channel.requestChannel(tid, 300) catch {
        syscall.write("leaf_b2a: FAIL requestChannel failed\n");
        return;
    };

    const chan = channel.awaitChannel(300, 5_000_000_000) orelse {
        syscall.write("leaf_b2a: FAIL awaitChannel(300) timed out\n");
        return;
    };
    syscall.write("leaf_b2a: got channel 300, sending message\n");
    chan.enqueue(.A, "hello from b2a") catch {
        syscall.write("leaf_b2a: FAIL enqueue failed\n");
        return;
    };
    syscall.write("leaf_b2a: PASS channel 300 connected and message sent\n");
    while (true) {
        syscall.thread_yield();
    }
}
