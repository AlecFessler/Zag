const lib = @import("lib");

const channel = lib.channel;
const syscall = lib.syscall;

/// Makes discoverable with proto=1, ttl=1 (visible only within manager_a subtree)
pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("leaf_a1: making discoverable ttl=1\n");
    channel.makeDiscoverable(@enumFromInt(1), 1) catch {
        syscall.write("leaf_a1: FAIL makeDiscoverable\n");
        return;
    };
    syscall.write("leaf_a1: PASS discoverable\n");
    while (true) {
        syscall.thread_yield();
    }
}
