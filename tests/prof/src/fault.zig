const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// kprof workload — drives handle_page_fault / map_page / sys_mem_reserve
/// by reserving VM ranges and touching one byte per page. When a range is
/// fully mapped, unmap it and start a fresh one so we keep faulting.
pub fn main(_: u64) void {
    const page_size: u64 = 4096;
    const range_size: u64 = 16 * 1024 * 1024; // 16 MiB per reservation
    const rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();

    while (true) {
        const res = syscall.mem_reserve(0, range_size, rights);
        if (res.val < 0) {
            syscall.thread_yield();
            continue;
        }
        const vm_handle: u64 = @bitCast(res.val);
        const base: [*]volatile u8 = @ptrFromInt(res.val2);

        var off: u64 = 0;
        while (off < range_size) {
            base[off] = 1;
            off += page_size;
        }

        _ = syscall.mem_unmap(vm_handle, 0, range_size);
    }
}
