const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Makes itself discoverable with proto=3, ttl=3 (visible to everything under root).
/// Awaits channel_id=100 (from leaf_b1a) and channel_id=300 (from leaf_b2a).
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_a2a: starting, making discoverable ttl=3\n");
    channel.makeDiscoverable(@enumFromInt(3), 3) catch {
        syscall.write("leaf_a2a: makeDiscoverable failed\n");
        return;
    };
    syscall.write("leaf_a2a: discoverable, waiting for channels\n");

    // Wait for channel 100 from leaf_b1a
    const chan100 = channel.awaitChannel(100, 5_000_000_000) orelse {
        syscall.write("leaf_a2a: FAIL awaitChannel(100) timed out\n");
        return;
    };
    syscall.write("leaf_a2a: got channel 100\n");
    waitForMessage(chan100, "100");

    // Wait for channel 300 from leaf_b2a
    const chan300 = channel.awaitChannel(300, 5_000_000_000) orelse {
        syscall.write("leaf_a2a: FAIL awaitChannel(300) timed out\n");
        return;
    };
    syscall.write("leaf_a2a: got channel 300\n");
    waitForMessage(chan300, "300");

    syscall.write("leaf_a2a: PASS all channels received\n");
    while (true) {
        syscall.thread_yield();
    }
}

fn waitForMessage(chan: *channel.Channel, name: []const u8) void {
    var buf: [64]u8 = undefined;
    var retries: u32 = 0;
    while (retries < 5000) : (retries += 1) {
        if (chan.dequeue(.B, &buf)) |_| {
            syscall.write("leaf_a2a: PASS received message on channel ");
            syscall.write(name);
            syscall.write("\n");
            return;
        }
        syscall.thread_yield();
    }
    syscall.write("leaf_a2a: FAIL no message on channel ");
    syscall.write(name);
    syscall.write("\n");
}
