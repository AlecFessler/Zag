const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const PAGE: u64 = 4096;

/// Receives an SHM handle via IPC, maps it, writes `page_index + 1` as u64 to
/// the first word of every page (no demand-page delay — SHM pages must be
/// eagerly mapped per §2.2.4), then replies. The test parent verifies that
/// every page carries the child's mark immediately after the reply.
pub fn main(perm_view_addr: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }
    if (shm_handle == 0 or shm_size == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;

    const base = vm_result.val2;
    const n_pages = shm_size / PAGE;
    var i: u64 = 0;
    while (i < n_pages) : (i += 1) {
        const ptr: *volatile u64 = @ptrFromInt(base + i * PAGE);
        ptr.* = 0x1000_0000 + i + 1;
    }
    _ = syscall.ipc_reply(&.{});

    // Stay alive so the parent retains the mapping.
    var dummy: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&dummy), 0, @bitCast(@as(i64, -1)));
}
