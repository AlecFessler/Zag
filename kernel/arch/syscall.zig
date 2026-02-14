const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const address = zag.memory.address;

pub const SyscallNum = enum(u64) {
    write = 0,
    _,
};

pub fn dispatch(num: u64, arg0: u64, arg1: u64) void {
    const syscall_num: SyscallNum = @enumFromInt(num);
    switch (syscall_num) {
        .write => sysWrite(arg0, arg1),
        else => {
            arch.print("Unknown syscall: {}\n", .{num});
        },
    }
}

fn sysWrite(buf_ptr: u64, buf_len: u64) void {
    if (!validateUserPtr(buf_ptr, buf_len)) {
        arch.print("syscall write: bad user pointer\n", .{});
        return;
    }
    const buf: [*]const u8 = @ptrFromInt(buf_ptr);
    arch.print("{s}", .{buf[0..buf_len]});
}

fn validateUserPtr(ptr: u64, len: u64) bool {
    if (len == 0) return true;
    const end = std.math.add(u64, ptr, len) catch return false;
    return ptr >= address.AddrSpacePartition.user.start and
        end <= address.AddrSpacePartition.user.end;
}
