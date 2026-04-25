const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

fn recurse(depth: u64) u64 {
    if (depth == 0) return 0;
    var buf: [512]u8 = undefined;
    buf[0] = @truncate(depth);
    return buf[0] + recurse(depth - 1);
}

/// §2.6.20 helper. On first boot: receive SHM from parent, reserve a VM
/// region, map the SHM into it, write `OLD_VA_MARKER` so the parent can see
/// the mapping worked, then record the VA/reservation count + our VM slot
/// contents and crash. On restart: scan perm view for VM_RESERVATION
/// entries — per §2.6.6 there must be none left. Record the count into the
/// SHM (fresh mapping after restart) and reply.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    // Locate SHM (persists across restart).
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }

    if (restart_count == 0) {
        // Receive SHM transfer.
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;

        // Re-locate shm handle after the transfer.
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
                shm_handle = entry.handle;
                shm_size = entry.field0;
                break;
            }
        }
        if (shm_handle == 0 or shm_size == 0) return;

        // Count VM reservations BEFORE we make ours (just for reference).
        var vm_before: u64 = 0;
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_VM_RESERVATION) vm_before += 1;
        }

        // Reserve + map SHM into a NEW reservation so that after restart, the
        // reservation should be gone (per §2.6.18/§2.6.20).
        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const vm = syscall.mem_reserve(0, shm_size, vm_rights);
        if (vm.val < 0) return;
        if (syscall.mem_shm_map(shm_handle, @intCast(vm.val), 0) != 0) return;

        const base = vm.val2;
        const slot0: *volatile u64 = @ptrFromInt(base); // run counter
        const slot1: *volatile u64 = @ptrFromInt(base + 8); // vm_count_before_restart
        const slot3: *volatile u64 = @ptrFromInt(base + 24); // old_va
        // Note: slot2 (base + 16, vm_count_after_restart) is intentionally
        // left at the parent's initial value (0). The post-restart path
        // writes `vm_count_after + 1` to slot2 (always >= 1), which is
        // how the parent's `wait until slot2 != 0` distinguishes the
        // restart write from the first-boot state.
        slot0.* = 1;
        slot1.* = vm_before + 1; // our new one included
        slot3.* = base;
        _ = syscall.ipc_reply(&.{});
        _ = syscall.futex_wake(@ptrFromInt(base), 1);

        // Crash to force restart.
        _ = recurse(100_000);
        return;
    }

    // Post-restart path: SHM still exists (§2.6.12). Re-reserve + re-map to
    // get a fresh VA so we can write our observation.
    if (shm_handle == 0) return;
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();

    // BEFORE re-reserving, count VM reservations in our perm view. Per
    // §2.6.6/§2.6.18 it must be zero.
    var vm_count_after: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_VM_RESERVATION) vm_count_after += 1;
    }

    const vm = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm.val), 0) != 0) return;

    const base = vm.val2;
    const slot2: *volatile u64 = @ptrFromInt(base + 16);
    // Add 1 so the parent can distinguish the written sentinel value
    // (0xFFFF...) from 0: we write (vm_count_after + 1).
    slot2.* = vm_count_after + 1;
    _ = syscall.futex_wake(@ptrFromInt(base + 16), 1);

    // Wait for a final call from the test so we stay alive and the test
    // can observe the SHM state.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{vm_count_after});
}
