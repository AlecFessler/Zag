const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Makes itself discoverable with proto=2, ttl=2 (visible within manager_a subtree).
/// Also awaits channel_id=200 from leaf_a2b.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_a1b: starting, making discoverable ttl=2\n");
    channel.makeDiscoverable(@enumFromInt(2), 2) catch {
        syscall.write("leaf_a1b: makeDiscoverable failed\n");
        return;
    };
    syscall.write("leaf_a1b: discoverable, waiting for channel 200\n");

    const chan = channel.awaitChannel(200, 5_000_000_000) orelse {
        syscall.write("leaf_a1b: FAIL awaitChannel(200) timed out\n");
        return;
    };
    syscall.write("leaf_a1b: got channel 200, reading message\n");

    var buf: [64]u8 = undefined;
    const len = chan.dequeue(.B, &buf) orelse {
        // Retry a few times
        var retries: u32 = 0;
        while (retries < 5000) : (retries += 1) {
            syscall.thread_yield();
            if (chan.dequeue(.B, &buf)) |l| {
                _ = l;
                syscall.write("leaf_a1b: PASS received message on channel 200\n");
                return;
            }
        }
        syscall.write("leaf_a1b: FAIL no message on channel 200\n");
        return;
    };
    _ = len;
    syscall.write("leaf_a1b: PASS received message on channel 200\n");
}
