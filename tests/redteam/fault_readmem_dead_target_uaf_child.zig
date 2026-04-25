// Helper child for fault_readmem_dead_target_uaf.zig.
//
// Acts as either T (the to-be-killed target) or A (the fault_handler that
// reads after T's death) depending on the role word in the first ipc_recv.
// Two children of the same ELF are spawned by the PoC; each takes one role.
//
// Wire protocol — first ipc_recv from poc:
//   words[0] = ROLE_T_INIT or ROLE_A_INIT
//   For ROLE_A_INIT, poc additionally cap-transfers a process handle to T
//   (with fault_handler bit) — kernel inserts a new .process entry into
//   our perm_table; we recover the handle by scanning perm_view.

const lib = @import("lib");

const perms = lib.perms;
const perm_view = lib.perm_view;
const syscall = lib.syscall;

const ROLE_T_INIT: u64 = 1;
const ROLE_T_DIE: u64 = 2;
const ROLE_A_INIT: u64 = 3;
const ROLE_A_DO_READ: u64 = 4;

const PAGE4K: u64 = 4096;
// Picked so poc, T, and a possible victim can all hint the same VA inside
// the user partition without colliding with code/data/heap layout.
const SECRET_VA: u64 = 0x100_0000_0000;
const SECRET_VAL: u64 = 0xDEADBEEF_CAFEBABE;

fn roleT(view: [*]const perm_view.UserViewEntry) noreturn {
    _ = view;
    // Reserve one writable page at the agreed VA and stamp the secret so
    // that, before T dies, sysFaultReadMem on T at this VA would have
    // returned the secret. After T dies, the L1 PT and leaf page are
    // freed (and zeroed by PMM), so the walk should reach E_BADADDR — but
    // a vulnerable kernel must not even let the walk happen on a dead
    // target's address space.
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    const r = syscall.mem_reserve(SECRET_VA, PAGE4K, rights);
    if (r.val < 0) {
        _ = syscall.ipc_reply(&.{0xFFFF_FFFF_FFFF_FFFF});
        syscall.thread_exit();
    }
    @as(*volatile u64, @ptrFromInt(r.val2)).* = SECRET_VAL;

    // Reply with HANDLE_SELF cap-transfer carrying fault_handler so poc
    // becomes our fault handler and gains the fault_handler bit on its
    // existing T process-handle entry. (Per ipc.zig:156-167, an existing
    // entry pointing at us has the bit OR'd in; no new entry created.)
    const fh_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, fh_rights });

    // Wait for the kill signal. Reply, then thread_exit. Single-threaded
    // T, so thread_exit triggers process exit → cleanupPhase1 frees the
    // user address space, cleanupPhase2 (leaf) calls
    // poc.convertToDeadProcess(T) which converts poc's entry to
    // .dead_process. A's entry is NOT touched by either path.
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);
    _ = syscall.ipc_reply(&.{});
    syscall.thread_exit();
}

fn roleA(view: [*]const perm_view.UserViewEntry) noreturn {
    // Recover the handle the kernel just inserted via cap transfer:
    // initially our perm_table only contains slot 0 (HANDLE_SELF, also
    // ENTRY_TYPE_PROCESS). The newly-arrived entry is the only other
    // ENTRY_TYPE_PROCESS slot.
    var t_handle: u64 = 0;
    for (1..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS) {
            t_handle = view[i].handle;
            break;
        }
    }
    if (t_handle == 0) {
        _ = syscall.ipc_reply(&.{0xFFFF_FFFF_FFFF_FFFE});
        syscall.thread_exit();
    }

    // Ack ROLE_A_INIT with the recovered handle so poc can verify the
    // transfer arrived.
    _ = syscall.ipc_reply(&.{t_handle});

    // Wait for ROLE_A_DO_READ. By the time poc sends this, it has signalled
    // T to die and yielded enough for T's cleanupPhase1 + cleanupPhase2 to
    // complete. T's slab slot is preserved as a zombie tombstone (per
    // process.zig:1410), so SlabRef.lock() in sysFaultReadMem still
    // resolves; addr_space_root still holds the (now gutted) L4 root, with
    // L4 entries still pointing at freed L3 paddrs. A patched kernel would
    // reject the syscall with E_BADCAP because target is dead; the
    // vulnerable kernel walks into freed page tables and returns
    // E_BADADDR (or, with PMM reuse, real data from another process).
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);

    var buf: [8]u8 align(8) = .{0} ** 8;
    const rc = syscall.fault_read_mem(t_handle, SECRET_VA, @intFromPtr(&buf), 8);
    const value: u64 = @as(*align(1) const u64, @ptrCast(&buf)).*;
    _ = syscall.ipc_reply(&.{ @bitCast(rc), value });
    syscall.thread_exit();
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);

    switch (msg.words[0]) {
        ROLE_T_INIT => roleT(view),
        ROLE_A_INIT => roleA(view),
        else => {
            _ = syscall.ipc_reply(&.{0xFFFF_FFFF_FFFF_FFFD});
            syscall.thread_exit();
        },
    }
}
