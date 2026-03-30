const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Requests connection to proto=2 (leaf_a2, within manager_a), channel 200.
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_a4: requesting connection proto=2 ch=200\n");

    const chan = channel.requestConnection(@enumFromInt(2), 200, 5_000_000_000) orelse {
        syscall.write("leaf_a4: FAIL requestConnection timed out\n");
        return;
    };
    chan.enqueue(.A, "hello from a4") catch {
        syscall.write("leaf_a4: FAIL enqueue\n");
        return;
    };
    syscall.write("leaf_a4: PASS channel 200 connected and message sent\n");
    while (true) syscall.thread_yield();
}
