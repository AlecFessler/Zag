const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Async request to proto=3 (leaf_a3), channel 300. Polls until connected.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_b3: requesting async connection proto=3 ch=300\n");

    channel.requestConnectionAsync(@enumFromInt(3), 300) catch {
        syscall.write("leaf_b3: FAIL requestConnectionAsync\n");
        return;
    };

    var attempts: u32 = 0;
    while (attempts < 50000) : (attempts += 1) {
        if (channel.pollConnection(300)) |chan| {
            chan.enqueue(.A, "hello from b3") catch {
                syscall.write("leaf_b3: FAIL enqueue\n");
                return;
            };
            syscall.write("leaf_b3: PASS channel 300 connected and message sent\n");
            while (true) syscall.thread_yield();
        }
        syscall.thread_yield();
    }
    syscall.write("leaf_b3: FAIL pollConnection timed out\n");
}
