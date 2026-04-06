// No-op arch shim for userspace fuzzing.
const memory = @import("memory");
const perms = @import("perms");

const PAddr = memory.address.PAddr;
const VAddr = memory.address.VAddr;
const MemoryPerms = perms.memory.MemoryPerms;

pub const dispatch = struct {
    pub fn mapPage(_: PAddr, _: PAddr, _: VAddr, _: MemoryPerms) !void {}
    pub fn unmapPage(_: PAddr, _: VAddr) ?PAddr {
        return null;
    }
    pub fn resolveVaddr(_: PAddr, _: VAddr) ?PAddr {
        return null;
    }
    pub fn updatePagePerms(_: PAddr, _: VAddr, _: MemoryPerms) void {}
};
