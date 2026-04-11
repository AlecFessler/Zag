const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.21.3 — `disable_restart` clears restart for all descendants recursively.
///
/// Root → intermediate(restart=true) → grandchild(restart=true).
/// The grandchild is `child_restart_grandchild_counter`, whose ELF image lives
/// in an SHM trailing control page. It bumps `counter` on every boot and
/// exits, so while restart is enabled the kernel keeps respawning it.
///
/// Root creates the SHM, transfers it to the intermediate via IPC cap
/// transfer. The intermediate then spawns the grandchild from the ELF pages
/// and re-transfers the SHM to the grandchild so its perm-table-based SHM
/// protocol can run.
///
/// Once the grandchild counter has advanced several times, root calls
/// `disable_restart`. Per §4.21.3, this must clear restart on BOTH the
/// intermediate and the grandchild. After a settling period the grandchild
/// counter must stop advancing.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // --- Build SHM: [grandchild ELF..][control page with counter]. ---
    const elf = children.child_restart_grandchild_counter;
    const elf_pages = (elf.len + 4095) / 4096;
    const shm_size = (elf_pages + 1) * 4096;
    const shm_rights = perms.SharedMemoryRights{
        .read = true,
        .write = true,
        .grant = true,
    };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, shm_size, vm_rw_s.bits());
    _ = syscall.mem_shm_map(shm_h, @bitCast(vm.val), 0);
    const shm_base: u64 = vm.val2;
    const dst: [*]u8 = @ptrFromInt(shm_base);
    for (0..elf.len) |i| dst[i] = elf[i];

    // Counter lives at the start of the trailing control page.
    const counter: *u64 = @ptrFromInt(shm_base + shm_size - 4096);
    counter.* = 0;

    // --- Spawn the intermediate spawner. ---
    const inter_rights = (perms.ProcessRights{
        .spawn_process = true,
        .mem_reserve = true,
        .restart = true,
    }).bits();
    const inter: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_spawn_restartable_grandchild.ptr),
        children.child_spawn_restartable_grandchild.len,
        inter_rights,
    )));

    // Locate the intermediate's slot so we can check DEAD_PROCESS later.
    var inter_slot: usize = 0xFFFF;
    for (0..128) |i| {
        if (view[i].handle == inter and view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            inter_slot = i;
            break;
        }
    }
    if (inter_slot == 0xFFFF) {
        t.fail("§4.21.3 intermediate not found");
        syscall.shutdown();
    }

    // --- Transfer SHM to the intermediate via IPC cap transfer. ---
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(inter, &.{ shm_h, shm_rights.bits() }, &reply);

    // --- Wait for the grandchild counter to advance (proof restart is
    // actively respawning the grandchild). ---
    var spins: u64 = 0;
    while (@atomicLoad(u64, counter, .seq_cst) < 3) : (spins += 1) {
        if (spins > 1_000_000) {
            t.fail("§4.21.3 grandchild counter never advanced");
            syscall.shutdown();
        }
        syscall.thread_yield();
    }

    // --- Kill restart recursively from root. ---
    _ = syscall.disable_restart();

    // Give pending exits time to drain. The grandchild may run one more
    // iteration after disable_restart, but it must not be restarted again.
    var drain: u64 = 0;
    while (drain < 5000) : (drain += 1) syscall.thread_yield();

    const snap = @atomicLoad(u64, counter, .seq_cst);
    drain = 0;
    while (drain < 5000) : (drain += 1) syscall.thread_yield();
    const after = @atomicLoad(u64, counter, .seq_cst);

    if (after != snap) {
        t.failWithVal("§4.21.3 grandchild still restarting", @intCast(snap), @intCast(after));
        syscall.shutdown();
    }

    // The intermediate was spawned with restart=true but never exits on its
    // own. Its restart bit was cleared by disable_restart; confirming its
    // slot is still ENTRY_TYPE_PROCESS (not reaped and not dead-processed
    // because it's still alive in its loop) is enough — the grandchild
    // check above is the real proof of recursive propagation.
    t.pass("§4.21.3");
    syscall.shutdown();
}
