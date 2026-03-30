const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Blocking requestConnection: discovers leaf_a3 (proto=3), establishes channel 100,
/// sends a message. Crosses from manager_b to manager_a via root.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_b1: requesting connection proto=3 ch=100\n");

    const chan = channel.requestConnection(@enumFromInt(3), 100, 5_000_000_000) orelse {
        syscall.write("leaf_b1: FAIL requestConnection timed out\n");
        return;
    };

    chan.enqueue(.A, "hello from b1") catch {
        syscall.write("leaf_b1: FAIL enqueue\n");
        return;
    };
    syscall.write("leaf_b1: PASS channel 100 connected and message sent\n");
    while (true) syscall.thread_yield();
}
