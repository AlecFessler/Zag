const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

fn threadFn() void {
    while (true) syscall.thread_yield();
}

/// §2.1.19 — Each entry has a type field: `process`, `vm_reservation`, `shared_memory`, `device_region`, `core_pin`, `dead_process`, or `thread`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // process: slot 0 is HANDLE_SELF → ENTRY_TYPE_PROCESS.
    // device_region: root service already owns device handles at boot.

    // thread: spawn a second thread that stays alive.
    const th_ret = syscall.thread_create(&threadFn, 0, 4);
    if (th_ret <= 0) {
        t.fail("§2.1.19 thread_create");
        syscall.shutdown();
    }
    const thread_handle: u64 = @bitCast(th_ret);

    // vm_reservation: reserve a page.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const vm_r = syscall.vm_reserve(0, 4096, rw.bits());
    if (vm_r.val <= 0) {
        t.fail("§2.1.19 vm_reserve");
        syscall.shutdown();
    }
    const vm_handle: u64 = @bitCast(vm_r.val);

    // shared_memory: create a SHM region.
    const shm_rc = syscall.shm_create(4096);
    if (shm_rc <= 0) {
        t.fail("§2.1.19 shm_create");
        syscall.shutdown();
    }
    const shm_handle: u64 = @bitCast(shm_rc);

    // core_pin: set single-core affinity and pin.
    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();
    const pin_rc = syscall.pin_exclusive();
    if (pin_rc < 0) {
        t.fail("§2.1.19 pin_exclusive");
        syscall.shutdown();
    }
    const pin_handle: u64 = @bitCast(pin_rc);

    // dead_process: spawn a non-restartable child that exits, so its entry
    // flips to dead_process.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_rights.bits(),
    )));
    var iters: u32 = 0;
    while (iters < 100000) : (iters += 1) {
        var found_dead = false;
        for (0..128) |i| {
            if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
                found_dead = true;
                break;
            }
        }
        if (found_dead) break;
        syscall.thread_yield();
    }

    // Sweep the view and collect which of the 7 type tags we observed.
    var seen_process = false;
    var seen_vm = false;
    var seen_shm = false;
    var seen_dev = false;
    var seen_pin = false;
    var seen_dead = false;
    var seen_thread = false;
    for (0..128) |i| {
        switch (view[i].entry_type) {
            perm_view.ENTRY_TYPE_PROCESS => seen_process = true,
            perm_view.ENTRY_TYPE_VM_RESERVATION => {
                if (view[i].handle == vm_handle) seen_vm = true;
            },
            perm_view.ENTRY_TYPE_SHARED_MEMORY => {
                if (view[i].handle == shm_handle) seen_shm = true;
            },
            perm_view.ENTRY_TYPE_DEVICE_REGION => seen_dev = true,
            perm_view.ENTRY_TYPE_CORE_PIN => {
                if (view[i].handle == pin_handle) seen_pin = true;
            },
            perm_view.ENTRY_TYPE_DEAD_PROCESS => {
                if (view[i].handle == child_handle) seen_dead = true;
            },
            perm_view.ENTRY_TYPE_THREAD => {
                if (view[i].handle == thread_handle) seen_thread = true;
            },
            else => {},
        }
    }

    if (seen_process and seen_vm and seen_shm and seen_dev and seen_pin and seen_dead and seen_thread) {
        t.pass("§2.1.19");
    } else {
        t.fail("§2.1.19");
    }
    syscall.shutdown();
}
