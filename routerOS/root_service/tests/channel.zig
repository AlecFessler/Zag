const lib = @import("lib");
const std = @import("std");

const channel_mod = lib.channel;
const crc32 = lib.crc32;
const syscall = lib.syscall;
const t = lib.testing;
const perms = lib.perms;

fn allocPage() ?[*]u8 {
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const vm_result = syscall.vm_reserve(0, syscall.PAGE4K, vm_rights);
    if (vm_result.val < 0) return null;
    return @ptrFromInt(vm_result.val2);
}

pub fn run() void {
    t.section("SPSC channel");
    testSendRecvRoundTrip();
    testMultipleMessagesFIFO();
    testEmptyRecvReturnsNull();
    testRingWrapAround();
    testChannelMagicValidation();
    testBidirectional();
}

fn testSendRecvRoundTrip() void {
    const base = allocPage() orelse {
        t.fail("channel: alloc failed");
        return;
    };
    const header: *channel_mod.ChannelHeader = @ptrCast(@alignCast(base));

    var a = channel_mod.Channel.initAsSideA(header, syscall.PAGE4K);
    var b = channel_mod.Channel.openAsSideB(header) orelse {
        t.fail("channel: side B open failed");
        return;
    };

    const msg = "hello channel";
    if (!a.send(msg)) {
        t.fail("channel: send failed");
        return;
    }

    var buf: [64]u8 = undefined;
    if (b.recv(&buf)) |len| {
        if (len == msg.len and std.mem.eql(u8, buf[0..len], msg)) {
            t.pass("channel: single message send/recv matches");
        } else {
            t.fail("channel: data mismatch");
        }
    } else {
        t.fail("channel: recv returned null");
    }
}

fn testMultipleMessagesFIFO() void {
    const base = allocPage() orelse {
        t.fail("channel multi: alloc failed");
        return;
    };
    const header: *channel_mod.ChannelHeader = @ptrCast(@alignCast(base));

    var a = channel_mod.Channel.initAsSideA(header, syscall.PAGE4K);
    var b = channel_mod.Channel.openAsSideB(header) orelse {
        t.fail("channel multi: open failed");
        return;
    };

    const msgs = [_][]const u8{ "first", "second message", "3", "four!!" };
    for (msgs) |msg| {
        if (!a.send(msg)) {
            t.fail("channel multi: send failed");
            return;
        }
    }

    var buf: [64]u8 = undefined;
    var ok = true;
    for (msgs) |expected| {
        if (b.recv(&buf)) |len| {
            if (len != expected.len or !std.mem.eql(u8, buf[0..len], expected)) {
                ok = false;
                break;
            }
        } else {
            ok = false;
            break;
        }
    }

    if (ok) {
        t.pass("channel: 4 messages arrive in FIFO order");
    } else {
        t.fail("channel: FIFO ordering broken");
    }
}

fn testEmptyRecvReturnsNull() void {
    const base = allocPage() orelse {
        t.fail("channel empty: alloc failed");
        return;
    };
    const header: *channel_mod.ChannelHeader = @ptrCast(@alignCast(base));

    _ = channel_mod.Channel.initAsSideA(header, syscall.PAGE4K);
    var b = channel_mod.Channel.openAsSideB(header) orelse {
        t.fail("channel empty: open failed");
        return;
    };

    var buf: [64]u8 = undefined;
    if (b.recv(&buf) == null) {
        t.pass("channel: recv on empty ring returns null");
    } else {
        t.fail("channel: recv on empty ring should return null");
    }
}

fn testRingWrapAround() void {
    const base = allocPage() orelse {
        t.fail("channel wrap: alloc failed");
        return;
    };
    const header: *channel_mod.ChannelHeader = @ptrCast(@alignCast(base));

    var a = channel_mod.Channel.initAsSideA(header, syscall.PAGE4K);
    var b = channel_mod.Channel.openAsSideB(header) orelse {
        t.fail("channel wrap: open failed");
        return;
    };

    var buf: [256]u8 = undefined;
    const payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    var ok = true;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        if (!a.send(payload)) {
            ok = false;
            break;
        }
        if (b.recv(&buf)) |len| {
            if (len != payload.len or !std.mem.eql(u8, buf[0..len], payload)) {
                ok = false;
                break;
            }
        } else {
            ok = false;
            break;
        }
    }

    if (ok) {
        t.pass("channel: 20 send/recv cycles survive ring wrap-around");
    } else {
        t.fail("channel: ring wrap-around broke data integrity");
    }
}

fn testChannelMagicValidation() void {
    const base = allocPage() orelse {
        t.fail("channel magic: alloc failed");
        return;
    };
    const header: *channel_mod.ChannelHeader = @ptrCast(@alignCast(base));
    header.magic = 0;

    if (channel_mod.Channel.openAsSideB(header) == null) {
        t.pass("channel: openAsSideB rejects invalid magic");
    } else {
        t.fail("channel: openAsSideB accepted bad magic");
    }
}

fn testBidirectional() void {
    const base = allocPage() orelse {
        t.fail("channel bidi: alloc failed");
        return;
    };
    const header: *channel_mod.ChannelHeader = @ptrCast(@alignCast(base));

    var a = channel_mod.Channel.initAsSideA(header, syscall.PAGE4K);
    var b = channel_mod.Channel.openAsSideB(header) orelse {
        t.fail("channel bidi: open failed");
        return;
    };

    if (!a.send("from A")) {
        t.fail("channel bidi: A send failed");
        return;
    }
    if (!b.send("from B")) {
        t.fail("channel bidi: B send failed");
        return;
    }

    var buf: [64]u8 = undefined;
    var ok = true;

    if (b.recv(&buf)) |len| {
        if (!std.mem.eql(u8, buf[0..len], "from A")) ok = false;
    } else ok = false;

    if (a.recv(&buf)) |len| {
        if (!std.mem.eql(u8, buf[0..len], "from B")) ok = false;
    } else ok = false;

    if (ok) {
        t.pass("channel: bidirectional A->B and B->A both work");
    } else {
        t.fail("channel: bidirectional communication failed");
    }
}
