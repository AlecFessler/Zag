const std = @import("std");

pub const CpuidFeatureEcx = enum(u32) {
    sse3 = 1 << 0, // Supplemental SSE3
    pclmul = 1 << 1, // Carryless multiply
    dtes64 = 1 << 2, // 64-bit debug store
    monitor = 1 << 3, // MONITOR/MWAIT instructions
    ds_cpl = 1 << 4, // CPL-qualified debug store
    vmx = 1 << 5, // Hardware virtualization
    smx = 1 << 6, // Safer mode extensions
    est = 1 << 7, // Enhanced SpeedStep
    tm2 = 1 << 8, // Thermal monitor 2
    ssse3 = 1 << 9, // Supplemental SSE3
    cid = 1 << 10, // Context ID
    sdbg = 1 << 11, // Silicon debug
    fma = 1 << 12, // Fused multiply-add
    cx16 = 1 << 13, // CMPXCHG16B instruction
    xtpr = 1 << 14, // xTPR update control
    pdcm = 1 << 15, // Perf/Debug capability MSR
    pcid = 1 << 17, // Process-context identifiers
    dca = 1 << 18, // Direct Cache Access
    sse4_1 = 1 << 19, // SSE4.1: adds dot-product, blend ops, rounding control
    sse4_2 = 1 << 20, // SSE4.2: adds string compare/CRC instructions
    x2apic = 1 << 21, // x2APIC mode support
    movbe = 1 << 22, // Big-endian byte load/store
    popcnt = 1 << 23, // POPCNT instruction
    tsc_deadline = 1 << 24, // TSC deadline mode in local APIC timer
    aes = 1 << 25, // AES-NI instructions
    xsave = 1 << 26, // XSAVE/XRSTOR
    osxsave = 1 << 27, // OS has enabled XSAVE in CR4
    avx = 1 << 28, // Advanced Vector Extensions
    f16c = 1 << 29, // Half-precision float conversion
    rdrand = 1 << 30, // Hardware RNG
    hypervisor = 1 << 31, // Running under a hypervisor
};

pub const CpuidFeatureEdx = enum(u32) {
    fpu = 1 << 0, // x87 FPU
    vme = 1 << 1, // Virtual 8086 extensions
    de = 1 << 2, // Debugging extensions
    pse = 1 << 3, // Page Size Extension
    tsc = 1 << 4, // Time Stamp Counter
    msr = 1 << 5, // Model Specific Registers
    pae = 1 << 6, // Physical Address Extension
    mce = 1 << 7, // Machine Check Exception
    cx8 = 1 << 8, // CMPXCHG8B
    lapic = 1 << 9, // Local APIC present
    sep = 1 << 11, // SYSENTER/SYSEXIT
    mtrr = 1 << 12, // Memory Type Range Registers
    pge = 1 << 13, // Global pages
    mca = 1 << 14, // Machine Check Architecture
    cmov = 1 << 15, // CMOV instruction
    pat = 1 << 16, // Page Attribute Table
    pse36 = 1 << 17, // 36-bit PSE
    psn = 1 << 18, // Processor serial number
    clflush = 1 << 19, // CLFLUSH instruction
    ds = 1 << 21, // Debug store
    acpi = 1 << 22, // Thermal/APIC extensions
    mmx = 1 << 23, // MMX: early SIMD integer ops
    fxsr = 1 << 24, // FXSAVE/FXRSTOR: fast FPU/SSE context save/restore
    sse = 1 << 25, // SSE: 128-bit SIMD floating-point
    sse2 = 1 << 26, // SSE2: expands SSE to cover integer ops
    ss = 1 << 27, // Self-snoop
    htt = 1 << 28, // Hyperthreading / multiple logical CPUs
    tm = 1 << 29, // Thermal Monitor
    ia64 = 1 << 30, // IA-64
    pbe = 1 << 31, // Pending Break Enable
};

pub const CpuidLeaf = enum(u32) {
    basic_max = 0x00000000,
    basic_features = 0x00000001,
    ext_max = 0x80000000,
    brand_0 = 0x80000002,
    brand_1 = 0x80000003,
    brand_2 = 0x80000004,
    ext_power = 0x80000007,
};

pub const CpuidPowerEdx = enum(u32) {
    ts = 1 << 0, // Temperature sensor available
    fid = 1 << 1, // Frequency ID control
    vid = 1 << 2, // Voltage ID control
    ttp = 1 << 3, // Thermal Trip
    tm = 1 << 4, // Hardware Thermal Management
    stc = 1 << 5, // Software Thermal Control
    step_100mhz = 1 << 6, // 100 MHz bus multiplier capability
    hwp = 1 << 7, // Hardware P-State
    constant_tsc = 1 << 8, // Invariant TSC
};

pub const Context = packed struct {
    regs: Registers,
    int_num: u64,
    err_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

pub const Registers = packed struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
};

pub const PrivilegeLevel = enum(u2) {
    ring_0 = 0x0,
    ring_3 = 0x3,
};

pub fn cpuid(eax: CpuidLeaf, ecx: u32) struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
} {
    var a = @intFromEnum(eax);
    var b: u32 = 0;
    var c = ecx;
    var d: u32 = 0;
    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [in_a] "{eax}" (@intFromEnum(eax)),
          [in_c] "{ecx}" (ecx),
    );
    return .{ .eax = a, .ebx = b, .ecx = c, .edx = d };
}

pub fn enableX2Apic(spurious_vector: u8) bool {
    std.debug.assert(spurious_vector >= 0x10);

    const feat = cpuid(.basic_features, 0);
    if (!hasFeatureEdx(feat.edx, .lapic)) return false;
    if (!hasFeatureEcx(feat.ecx, .x2apic)) return false;

    const IA32_APIC_BASE: u32 = 0x1B;
    const APIC_EN: u64 = 1 << 11;
    const X2APIC_EN: u64 = 1 << 10;

    var apic_base = rdmsr(IA32_APIC_BASE);
    apic_base |= (APIC_EN | X2APIC_EN);
    wrmsr(IA32_APIC_BASE, apic_base);

    const X2APIC_SVR: u32 = 0x80F;
    const SVR_APIC_ENABLE: u64 = 1 << 8;
    const svr_value: u64 = SVR_APIC_ENABLE | (@as(u64, spurious_vector));
    wrmsr(X2APIC_SVR, svr_value);

    return true;
}

pub fn hasFeatureEcx(reg: u32, feat: CpuidFeatureEcx) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

pub fn hasFeatureEdx(reg: u32, feat: CpuidFeatureEdx) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

pub fn hasPowerFeatureEdx(reg: u32, feat: CpuidPowerEdx) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

pub fn rdtscLFenced() u64 {
    var a: u32 = 0;
    var d: u32 = 0;
    asm volatile (
        \\ lfence
        \\ rdtsc
        : [a] "={eax}" (a),
          [d] "={edx}" (d)
        :
        : .{ .memory = true }
    );
    return (@as(u64, d) << 32) | a;
}

pub fn rdtscp() u64 {
    var a: u32 = 0;
    var d: u32 = 0;
    var c: u32 = 0;
    asm volatile (
        \\ rdtscp
        : [a] "={eax}" (a),
          [d] "={edx}" (d),
          [c] "={ecx}" (c)
        :
        : .{ .memory = true }
    );
    return (@as(u64, d) << 32) | a;
}

pub fn rdtscpLFenced() u64 {
    var a: u32 = 0;
    var d: u32 = 0;
    var c: u32 = 0;
    asm volatile (
        \\ rdtscp
        \\ lfence
        : [a] "={eax}" (a),
          [d] "={edx}" (d),
          [c] "={ecx}" (c)
        :
        : .{ .memory = true }
    );
    return (@as(u64, d) << 32) | a;
}

pub fn readCr2() u64 {
    var vaddr: u64 = 0;
    asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (vaddr),
    );
    return vaddr;
}

pub fn restoreInterrupts(saved_rflags: u64) void {
    const IF: u64 = 1 << 9;
    if ((saved_rflags & IF) != 0) {
        asm volatile ("sti");
    } else {
        asm volatile ("cli");
    }
}

pub fn saveAndDisableInterrupts() u64 {
    var rflags: u64 = 0;
    asm volatile ("pushfq; pop %[out]"
        : [out] "={rax}" (rflags)
    );
    asm volatile ("cli");
    return rflags;
}

pub fn invlpg(vaddr: u64) void {
    asm volatile (
        \\invlpg (%[a])
        :
        : [a] "r" (vaddr),
        : .{ .memory = true });
}

pub fn halt() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}

pub fn readCr3() u64 {
    var value: u64 = 0;
    asm volatile ("mov %%cr3, %[out]"
        : [out] "=r" (value),
    );
    return value;
}

pub fn writeCr3(value: u64) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (value),
    );
}

pub fn inb(port: u16) u8 {
    return asm volatile (
        \\inb %[port], %[ret]
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
        : .{.dx = true}
    );
}

pub fn outb(value: u8, port: u16) void {
    asm volatile (
        \\outb %[value], %[port]
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
        : .{.dx = true}
    );
}

pub fn lgdt(desc: *const anyopaque) void {
    asm volatile (
        \\lgdt (%[ptr])
        :
        : [ptr] "r" (desc),
    );
}

pub fn ltr(sel: u16) void {
    asm volatile (
        \\mov %[s], %%ax
        \\ltr %%ax
        :
        : [s] "ir" (sel),
    );
}

pub fn lidt(desc: *const anyopaque) void {
    asm volatile ("lidt (%[ptr])"
        :
        : [ptr] "r" (desc)
    );
}

pub fn wrmsr(msr: u32, value: u64) void {
    const lo: u32 = @truncate(value);
    const hi: u32 = @truncate(value >> 32);
    asm volatile (
        \\wrmsr
        :
        : [msr] "{ecx}" (msr),
          [lo] "{eax}" (lo),
          [hi] "{edx}" (hi),
    );
}

pub fn rdmsr(msr: u32) u64 {
    var lo: u32 = 0;
    var hi: u32 = 0;
    asm volatile (
        \\rdmsr
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, hi) << 32) | lo;
}
