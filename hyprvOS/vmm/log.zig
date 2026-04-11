/// Debug logging helpers for hyprvOS VMM.
/// All output goes to Zag's serial console via the write syscall.

const lib = @import("lib");

const syscall = lib.syscall;

pub fn print(msg: []const u8) void {
    syscall.write(msg);
}

const hex_chars = "0123456789ABCDEF";

pub fn hex8(val: u8) void {
    var buf: [2]u8 = undefined;
    buf[0] = hex_chars[val >> 4];
    buf[1] = hex_chars[val & 0xF];
    syscall.write(&buf);
}

pub fn hex16(val: u16) void {
    hex8(@truncate(val >> 8));
    hex8(@truncate(val));
}

pub fn hex32(val: u32) void {
    hex16(@truncate(val >> 16));
    hex16(@truncate(val));
}

pub fn hex64(val: u64) void {
    hex32(@truncate(val >> 32));
    hex32(@truncate(val));
}

pub fn dec(val: u64) void {
    if (val == 0) {
        syscall.write("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 20;
    var v = val;
    while (v > 0) {
        i -= 1;
        buf[i] = @truncate((v % 10) + '0');
        v /= 10;
    }
    syscall.write(buf[i..20]);
}
