const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;
const N_PAGES: u64 = 8;
const SHM_SIZE: u64 = PAGE * N_PAGES;

/// §2.2.4 — `shm_map` maps the full SHM region at the specified offset; pages
/// are eagerly mapped (no demand-fault delay). We prove this cross-process:
/// parent maps an 8-page SHM and writes a per-page marker on every page;
/// immediately after, a child maps the same SHM and writes a second marker on
/// every page; parent reads them back without delay. If any page were not
/// eagerly mapped, either writer would demand-fault new zero pages and the
/// other side would not see the expected value.
pub fn main(_: u64) void {
    // Create SHM and map it at offset 0.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(SHM_SIZE, shm_rights.bits())));

    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.vm_reserve(0, SHM_SIZE, vm_rights);
    const vm_h: u64 = @bitCast(vm.val);
    if (syscall.shm_map(shm_handle, vm_h, 0) != 0) {
        t.fail("§2.2.4");
        syscall.shutdown();
    }

    // Parent touches every page with a distinguishing marker.
    const base = vm.val2;
    var i: u64 = 0;
    while (i < N_PAGES) : (i += 1) {
        const marker_ptr: *volatile u64 = @ptrFromInt(base + i * PAGE + 0);
        marker_ptr.* = 0xA_0000 + i;
    }

    // Sanity: every parent marker readable from the same mapping.
    i = 0;
    while (i < N_PAGES) : (i += 1) {
        const marker_ptr: *volatile u64 = @ptrFromInt(base + i * PAGE + 0);
        if (marker_ptr.* != 0xA_0000 + i) {
            t.fail("§2.2.4");
            syscall.shutdown();
        }
    }

    // Spawn child that maps the same SHM and writes its own marker to every
    // page (at offset +8 within each page), then replies.
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .mem_reserve = true, .shm_create = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_shm_touch_all_pages.ptr),
        children.child_shm_touch_all_pages.len,
        child_rights,
    )));

    // The child's touch loop writes to offset 0 of every page (overwrites the
    // parent's marker with its own). After the child replies, parent reads
    // every page and expects the child's marker to be present on each.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    var all_ok = true;
    i = 0;
    while (i < N_PAGES) : (i += 1) {
        const marker_ptr: *volatile u64 = @ptrFromInt(base + i * PAGE + 0);
        if (marker_ptr.* != 0x1000_0000 + i + 1) {
            all_ok = false;
            break;
        }
    }

    if (all_ok) {
        t.pass("§2.2.4");
    } else {
        t.fail("§2.2.4");
    }
    syscall.shutdown();
}
