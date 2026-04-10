const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const ASLR_ZONE_START: u64 = 0x0000_0000_0000_1000;
const ASLR_ZONE_END: u64 = 0x0000_1000_0000_0000;

/// §2.1.34 — ELF segments and user stacks are placed in the ASLR zone `[0x0000_0000_0000_1000, 0x0000_1000_0000_0000)` with a randomized base.
pub fn main(_: u64) void {
    const N: usize = 4;
    var addrs: [N]u64 = undefined;
    const child_rights = (perms.ProcessRights{}).bits();
    for (0..N) |i| {
        const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
            @intFromPtr(children.child_report_main_addr.ptr),
            children.child_report_main_addr.len,
            child_rights,
        )));
        var reply: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(ch, &.{}, &reply);
        if (rc != 0) {
            t.failWithVal("§2.1.34 ipc_call", 0, rc);
            syscall.shutdown();
        }
        addrs[i] = reply.words[0];
    }

    // Every reported address must fall inside the ASLR zone.
    for (addrs) |a| {
        if (a < ASLR_ZONE_START or a >= ASLR_ZONE_END) {
            t.fail("§2.1.34 address outside ASLR zone");
            syscall.shutdown();
        }
    }

    // Randomization evidence: at least one pair of children loaded at
    // different base addresses. If all N children land on the exact same
    // address, the base is effectively a constant.
    var any_differ = false;
    for (1..N) |i| {
        if (addrs[i] != addrs[0]) {
            any_differ = true;
            break;
        }
    }

    if (any_differ) {
        t.pass("§2.1.34");
    } else {
        t.fail("§2.1.34 all children loaded at identical address");
    }
    syscall.shutdown();
}
