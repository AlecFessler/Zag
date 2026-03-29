const pv = @import("perm_view.zig");
const syscall = @import("syscall.zig");

const hex_chars = "0123456789abcdef";

pub fn printHex(val: u64) void {
    var buf: [18]u8 = undefined;
    buf[0] = '0';
    buf[1] = 'x';
    var v = val;
    var i: usize = 17;
    while (i >= 2) : (i -= 1) {
        buf[i] = hex_chars[@as(usize, @truncate(v & 0xf))];
        v >>= 4;
    }
    syscall.write(&buf);
}

pub fn printDec(val: u64) void {
    if (val == 0) {
        syscall.write("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var v = val;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    syscall.write(buf[i..20]);
}

pub fn printI64(val: i64) void {
    if (val < 0) {
        syscall.write("-");
        printHex(@bitCast(-val));
    } else {
        printHex(@bitCast(val));
    }
}

pub fn pass(name: []const u8) void {
    syscall.write("[PASS] ");
    syscall.write(name);
    syscall.write("\n");
}

pub fn fail(name: []const u8) void {
    syscall.write("[FAIL] ");
    syscall.write(name);
    syscall.write("\n");
}

pub fn failWithVal(name: []const u8, expected: i64, actual: i64) void {
    syscall.write("[FAIL] ");
    syscall.write(name);
    syscall.write(" expected=");
    printI64(expected);
    syscall.write(" actual=");
    printI64(actual);
    syscall.write("\n");
}

pub fn expectEqual(name: []const u8, expected: i64, actual: i64) void {
    if (expected == actual) {
        pass(name);
    } else {
        failWithVal(name, expected, actual);
    }
}

pub fn expectOk(name: []const u8, result: i64) void {
    if (result >= 0) {
        pass(name);
    } else {
        failWithVal(name, 0, result);
    }
}

pub fn section(name: []const u8) void {
    syscall.write("\n--- ");
    syscall.write(name);
    syscall.write(" ---\n");
}

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

pub fn waitUntilNonZero(ptr: *volatile u64) void {
    while (ptr.* == 0) {
        _ = syscall.futex_wait(@ptrFromInt(@intFromPtr(ptr)), 0, MAX_TIMEOUT);
    }
}

pub fn waitUntilAtLeast(ptr: *volatile u64, min: u64) void {
    while (ptr.* < min) {
        _ = syscall.futex_wait(@ptrFromInt(@intFromPtr(ptr)), ptr.*, MAX_TIMEOUT);
    }
}

pub fn waitForCleanup(handle: u64, perm_view_addr: u64) void {
    while (syscall.revoke_perm(handle) != -3) {
        pv.waitForChange(perm_view_addr, 10_000_000); // 10ms
    }
}
