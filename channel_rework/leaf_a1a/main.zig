const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Makes itself discoverable with proto=1, ttl=1 (visible only within sub_a1 subtree)
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_a1a: starting, making discoverable ttl=1\n");
    channel.makeDiscoverable(@enumFromInt(1), 1) catch {
        syscall.write("leaf_a1a: makeDiscoverable failed\n");
        return;
    };
    syscall.write("leaf_a1a: discoverable, idling\n");
    while (true) {
        syscall.thread_yield();
    }
}
