const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Async requestConnection: discovers leaf_a2 (proto=2), sends channel 200 request,
/// then polls until connected.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_b2: requesting async connection proto=2 ch=200\n");

    channel.requestConnectionAsync(@enumFromInt(2), 200) catch {
        syscall.write("leaf_b2: FAIL requestConnectionAsync\n");
        return;
    };
    syscall.write("leaf_b2: request sent, polling\n");

    var attempts: u32 = 0;
    while (attempts < 50000) : (attempts += 1) {
        if (channel.pollConnection(200)) |_| {
            syscall.write("leaf_b2: PASS async connection established\n");
            while (true) syscall.thread_yield();
        }
        syscall.thread_yield();
    }
    syscall.write("leaf_b2: FAIL pollConnection timed out\n");
}
