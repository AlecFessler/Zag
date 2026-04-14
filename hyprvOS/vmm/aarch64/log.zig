//! Minimal logging helper for the aarch64 hyprvOS VMM.
//!
//! All output is funnelled through the `write` syscall so the host kernel's
//! debug console sees it. No formatting framework — print strings and
//! fixed-width hex/dec helpers so the VMM keeps zero heap usage.

const lib = @import("lib");

const syscall = lib.syscall;

pub fn print(msg: []const u8) void {
    syscall.write(msg);
}

pub fn dec(v: u64) void {
    if (v == 0) {
        syscall.write("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = buf.len;
    var n = v;
    while (n > 0) {
        i -= 1;
        buf[i] = @intCast('0' + (n % 10));
        n /= 10;
    }
    syscall.write(buf[i..]);
}

const HEX_CHARS = "0123456789abcdef";

pub fn hex64(v: u64) void {
    var buf: [16]u8 = undefined;
    var i: usize = 16;
    while (i > 0) {
        i -= 1;
        buf[i] = HEX_CHARS[(v >> @as(u6, @intCast((15 - i) * 4))) & 0xF];
    }
    syscall.write(&buf);
}

pub fn hex32(v: u32) void {
    hex64(@as(u64, v));
}
