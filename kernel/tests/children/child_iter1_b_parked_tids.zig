const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

var parked_futex: u64 align(8) = 0;
var started_count: u64 align(8) = 0;

fn parker() void {
    _ = @atomicRmw(u64, &started_count, .Add, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&started_count), 1);
    _ = syscall.futex_wait(@ptrCast(&parked_futex), 0, @bitCast(@as(i64, -1)));
}

fn faultNow() void {
    const p: *allowzero volatile u64 = @ptrFromInt(0x0);
    p.* = 0xDEAD;
}

/// §2.6.22 helper. Like child_parked_workers_then_fault but additionally
/// persists pre-restart thread IDs into SHM so the parent can assert that
/// none of them reappear in the post-restart perm view.
///
/// SHM layout (one page):
///   0  : pre_count (u64)
///   8  : pre_tids[pre_count] (u64 each)
/// 128  : post_count (u64)
/// 136  : post_tid (u64) — tid of the fresh initial thread after restart
/// 144  : done (u64) — futex wake cell for parent
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        _ = syscall.ipc_reply(&.{});

        var shm_handle: u64 = 0;
        var shm_size: u64 = 0;
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
                shm_handle = entry.handle;
                shm_size = entry.field0;
                break;
            }
        }
        if (shm_handle == 0) return;
        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
        if (vm_result.val < 0) return;
        if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;
        const base: u64 = vm_result.val2;

        _ = syscall.thread_create(&parker, 0, 4);
        _ = syscall.thread_create(&parker, 0, 4);
        _ = syscall.thread_create(&parker, 0, 4);
        while (@atomicLoad(u64, &started_count, .acquire) < 3) {
            syscall.thread_yield();
        }

        const pre_count_ptr: *u64 = @ptrFromInt(base + 0);
        var count: u64 = 0;
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_THREAD) {
                const slot_ptr: *u64 = @ptrFromInt(base + 8 + count * 8);
                slot_ptr.* = entry.threadTid();
                count += 1;
                if (count >= 15) break;
            }
        }
        pre_count_ptr.* = count;

        faultNow();
        return;
    }

    // --- Post-restart branch ---
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }
    if (shm_handle == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;
    const base: u64 = vm_result.val2;

    var post_count: u64 = 0;
    var post_tid: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_THREAD) {
            post_count += 1;
            post_tid = entry.threadTid();
        }
    }
    const post_count_ptr: *u64 = @ptrFromInt(base + 128);
    const post_tid_ptr: *u64 = @ptrFromInt(base + 136);
    const done_ptr: *u64 = @ptrFromInt(base + 144);
    post_count_ptr.* = post_count;
    post_tid_ptr.* = post_tid;
    done_ptr.* = 1;
    _ = syscall.futex_wake(done_ptr, 1);

    var park: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&park), 0, @bitCast(@as(i64, -1)));
}
