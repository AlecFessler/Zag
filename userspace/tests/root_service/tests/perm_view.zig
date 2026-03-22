const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_PERMS = 64;

pub fn run(perm_view_addr: u64) void {
    t.section("user permissions view");
    testViewMapped(perm_view_addr);
    testSelfHandle(perm_view_addr);
    testReserveAppearsInView(perm_view_addr);
}

fn getView(addr: u64) *const [MAX_PERMS]pv.UserViewEntry {
    return @ptrFromInt(addr);
}

fn testViewMapped(addr: u64) void {
    if (addr == 0) {
        t.fail("perm_view: addr is null");
        return;
    }
    const view = getView(addr);
    if (view[0].entry_type == pv.ENTRY_TYPE_PROCESS) {
        t.pass("perm_view: mapped and readable");
    } else {
        t.fail("perm_view: slot 0 not a process entry");
    }
}

fn testSelfHandle(addr: u64) void {
    const view = getView(addr);
    const slot0 = &view[0];
    t.expectEqual("perm_view: slot0 handle is 0", 0, @as(i64, @bitCast(slot0.handle)));
    if (slot0.entry_type != pv.ENTRY_TYPE_PROCESS) {
        t.fail("perm_view: slot0 type not process");
        return;
    }
    t.pass("perm_view: slot0 is HANDLE_SELF");
}

fn testReserveAppearsInView(addr: u64) void {
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const result = syscall.vm_reserve(0, syscall.PAGE4K, rights);
    if (result.val < 0) {
        t.fail("perm_view: vm_reserve failed");
        return;
    }
    const handle: u64 = @intCast(result.val);

    const view = getView(addr);
    var found = false;
    for (view) |*entry| {
        if (entry.handle == handle and entry.entry_type == pv.ENTRY_TYPE_VM_RESERVATION) {
            if (entry.field1 == syscall.PAGE4K) {
                found = true;
            }
            break;
        }
    }

    if (found) {
        t.pass("perm_view: reservation visible in view");
    } else {
        t.fail("perm_view: reservation not found in view");
    }
}
