const lib = @import("lib");

const perm_view = lib.perm_view;
const t = lib.testing;

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var count: u32 = 0;
    for (0..128) |i| {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_EMPTY) {
            count += 1;
        }
    }
    // Child should have exactly 1 entry: HANDLE_SELF (handle 0, type process).
    if (count == 1 and view[0].handle == 0 and view[0].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
        t.pass("§4.10.2");
    } else {
        t.fail("§4.10.2");
    }
}
