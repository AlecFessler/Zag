const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Makes discoverable proto=2, ttl=2 (visible within manager_a subtree).
/// Awaits incoming channel 200 from leaf_a4.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_a2: making discoverable ttl=2\n");
    channel.makeDiscoverable(@enumFromInt(2), 2) catch {
        syscall.write("leaf_a2: FAIL makeDiscoverable\n");
        return;
    };
    syscall.write("leaf_a2: discoverable, waiting for channel 200\n");

    const chan = channel.awaitIncoming(200, 5_000_000_000) orelse {
        syscall.write("leaf_a2: FAIL awaitIncoming(200) timed out\n");
        return;
    };

    var buf: [64]u8 = undefined;
    var retries: u32 = 0;
    while (retries < 5000) : (retries += 1) {
        if (chan.dequeue(.B, &buf)) |_| {
            syscall.write("leaf_a2: PASS received message on channel 200\n");
            while (true) syscall.thread_yield();
        }
        syscall.thread_yield();
    }
    syscall.write("leaf_a2: FAIL no message on channel 200\n");
}
