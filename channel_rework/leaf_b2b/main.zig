const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Verifies it sees only leaf_a2a (proto=3). Does not request any channels.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_b2b: starting, waiting for discovery entries\n");

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
    for (entries[0..count]) |entry| {
        const p = @intFromEnum(entry.proto);
        if (p == 1) saw_proto1 = true;
        if (p == 2) saw_proto2 = true;
        if (p == 3) saw_proto3 = true;
    }

    if (saw_proto1) syscall.write("leaf_b2b: FAIL saw proto=1\n");
    if (saw_proto2) syscall.write("leaf_b2b: FAIL saw proto=2\n");
    if (!saw_proto3) {
        syscall.write("leaf_b2b: FAIL did not see proto=3\n");
        return;
    }
    syscall.write("leaf_b2b: PASS visibility correct\n");
    while (true) {
        syscall.thread_yield();
    }
}
