const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Helper for §2.6.5 / §2.6.12 / §2.6.17.
///
/// First boot:
///   1. Receive SHM (handle cap transfer) via IPC; map it at a fresh VA.
///   2. Write MAGIC to SHM[0] so a post-restart reader can confirm the
///      mapping persists.
///   3. Snapshot the sorted list of non-VM permission slot handle IDs into
///      SHM[pre_count @ slot 8, pre_list @ slots 16..].
///   4. Exit voluntarily — because we were spawned with `restart`, this
///      triggers §2.6.1 restart.
///
/// Restart boot (restart_count > 0):
///   5. Locate the SHM entry in our own perm view — if absent, §2.6.12
///      would be violated. (No IPC needed: perms table persisted.)
///   6. Re-reserve VM at a fresh VA, re-map the SHM, read back MAGIC.
///      A successful read confirms the SHM entry is still functional.
///   7. Re-enumerate non-VM slots and compare against the pre-restart list
///      in SHM (§2.6.5).
///   8. Read our own view[0].processRestartCount() — must be nonzero
///      (§2.6.17); the fact that we're executing this branch AT ALL
///      proves the view mapping persisted.
///   9. Publish a bitmask of results to SHM[result_offset] and wake the
///      parent on that cell.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    // --- Layout within the SHM page:
    //   0  : magic (u64)
    //   8  : pre_count (u64)
    //  16.. : handles[pre_count]  (u64 each, up to 120 entries)
    // 1000 : result mask (u64)
    // 1008 : done futex (u64)
    const MAGIC: u64 = 0xF00DBEEF_CAFE0001;
    const RESULT_OFF: u64 = 1000;
    const DONE_OFF: u64 = 1008;

    if (restart_count == 0) {
        // First boot — get SHM via IPC.
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        _ = syscall.ipc_reply(&.{});

        // Find SHM entry.
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
        const magic_ptr: *u64 = @ptrFromInt(base + 0);
        const pre_count_ptr: *u64 = @ptrFromInt(base + 8);
        const handles_base: u64 = base + 16;

        magic_ptr.* = MAGIC;

        // Snapshot non-VM slots (sorted by slot index; parent comparison
        // is by set membership, not order).
        var count: u64 = 0;
        for (view, 0..) |*entry, i| {
            if (i == 0) continue; // slot 0 is HANDLE_SELF, always present
            if (entry.entry_type == pv.ENTRY_TYPE_EMPTY) continue;
            if (entry.entry_type == pv.ENTRY_TYPE_VM_RESERVATION) continue;
            if (entry.entry_type == pv.ENTRY_TYPE_THREAD) continue; // threads don't persist
            const slot_ptr: *u64 = @ptrFromInt(handles_base + count * 8);
            slot_ptr.* = entry.handle;
            count += 1;
            if (count >= 120) break;
        }
        pre_count_ptr.* = count;

        // Voluntary exit → restart (we have restart context).
        return;
    }

    // --- Restart boot ---
    // 1. Find the SHM entry (§2.6.12 — SHM handle persists).
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    var shm_slot_present: bool = false;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            shm_slot_present = true;
            break;
        }
    }
    if (!shm_slot_present or shm_handle == 0) return;

    // 2. Re-map the SHM at a fresh VA and read MAGIC (§2.6.12 — mapping
    //    readable from a fresh VA proves the SHM entry is still functional).
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;
    const base: u64 = vm_result.val2;
    const magic_ptr: *u64 = @ptrFromInt(base + 0);
    const pre_count_ptr: *u64 = @ptrFromInt(base + 8);
    const handles_base: u64 = base + 16;
    const shm_magic_readable = magic_ptr.* == MAGIC;

    // 3. Re-enumerate non-VM slots and verify every pre-restart handle is
    //    still present (§2.6.5 — permissions table persists).
    const pre_count: u64 = pre_count_ptr.*;
    var perms_match = true;
    var pi: u64 = 0;
    while (pi < pre_count) : (pi += 1) {
        const want_ptr: *u64 = @ptrFromInt(handles_base + pi * 8);
        const want: u64 = want_ptr.*;
        var found = false;
        for (view) |*entry| {
            if (entry.handle == want and entry.entry_type != pv.ENTRY_TYPE_EMPTY) {
                found = true;
                break;
            }
        }
        if (!found) {
            perms_match = false;
            break;
        }
    }

    // 4. Read view[0].processRestartCount() (§2.6.17 — view mapping
    //    persists; we only reach this branch because restart_count > 0).
    const view_restart_count_nonzero = restart_count > 0;

    // 5. Publish result mask, wake parent.
    var result: u64 = 0;
    if (perms_match) result |= 1;
    if (shm_slot_present) result |= 2;
    if (shm_magic_readable) result |= 4;
    if (view_restart_count_nonzero) result |= 8;
    result |= (@as(u64, restart_count) << 32);

    const result_ptr: *u64 = @ptrFromInt(base + RESULT_OFF);
    const done_ptr: *u64 = @ptrFromInt(base + DONE_OFF);
    result_ptr.* = result;
    done_ptr.* = 1;
    _ = syscall.futex_wake(done_ptr, 1);

    // Park so our process stays alive and the SHM mapping in parent is
    // valid for reads. Any fault/exit would retrigger restart and loop.
    var park: u64 align(8) = 0;
    _ = syscall.futex_wait(@ptrCast(&park), 0, @bitCast(@as(i64, -1)));
}
