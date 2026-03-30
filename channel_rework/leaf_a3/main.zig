const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Makes discoverable proto=3, ttl=3 (visible everywhere under root).
/// Awaits incoming channels 100 (from leaf_b1) and 300 (from leaf_b3).
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_a3: making discoverable ttl=3\n");
    channel.makeDiscoverable(@enumFromInt(3), 3) catch {
        syscall.write("leaf_a3: FAIL makeDiscoverable\n");
        return;
    };
    syscall.write("leaf_a3: discoverable, waiting for channels\n");

    const chan100 = channel.awaitIncoming(100, 5_000_000_000) orelse {
        syscall.write("leaf_a3: FAIL awaitIncoming(100) timed out\n");
        return;
    };
    var buf: [64]u8 = undefined;
    var retries: u32 = 0;
    while (retries < 5000) : (retries += 1) {
        if (chan100.dequeue(.B, &buf)) |_| {
            syscall.write("leaf_a3: PASS received message on channel 100\n");
            break;
        }
        syscall.thread_yield();
    }

    const chan300 = channel.awaitIncoming(300, 5_000_000_000) orelse {
        syscall.write("leaf_a3: FAIL awaitIncoming(300) timed out\n");
        return;
    };
    retries = 0;
    while (retries < 5000) : (retries += 1) {
        if (chan300.dequeue(.B, &buf)) |_| {
            syscall.write("leaf_a3: PASS received message on channel 300\n");
            while (true) syscall.thread_yield();
        }
        syscall.thread_yield();
    }
    syscall.write("leaf_a3: FAIL no message on channel 300\n");
}
