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
    /// AMD extended features — ECX bit 2 = SVM support.
    /// AMD APM Vol 2, Section 15.4, CPUID Fn 8000_0001h.
    ext_features = 0x80000001,
    brand_0 = 0x80000002,
    brand_1 = 0x80000003,
    brand_2 = 0x80000004,
    ext_power = 0x80000007,
    /// SVM revision and feature identification.
    /// AMD APM Vol 2, Section 15.30.1, CPUID Fn 8000_000Ah.
    svm_features = 0x8000000A,
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

/// Size of FXSAVE area allocated below Context on kernel stack.
/// FXSAVE/FXRSTOR is handled in assembly prologue/epilogue.
pub const FXSAVE_SIZE: u64 = 512;

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

/// Raw CPUID for arbitrary leaf/subleaf numbers. Used by the PMU detection
/// path which needs leaf `0x0A` (architectural performance monitoring,
/// Intel SDM Vol 3 §18.2.2) — not worth broadening `CpuidLeaf` for.
pub fn cpuidRaw(leaf: u32, subleaf: u32) struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
} {
    var a: u32 = leaf;
    var b: u32 = 0;
    var c: u32 = subleaf;
    var d: u32 = 0;
    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [in_a] "{eax}" (leaf),
          [in_c] "{ecx}" (subleaf),
    );
    return .{ .eax = a, .ebx = b, .ecx = c, .edx = d };
}

pub fn enableInterrupts() void {
    asm volatile ("sti");
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
          [d] "={edx}" (d),
        :
        : .{ .memory = true });
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
          [c] "={ecx}" (c),
        :
        : .{ .memory = true });
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
          [c] "={ecx}" (c),
        :
        : .{ .memory = true });
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
        : [out] "={rax}" (rflags),
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

pub fn qemuShutdown() noreturn {
    // Drain COM1 before cutting power. `writeByte` in `serial.zig`
    // only waits for the Transmit Holding Register to empty (LSR
    // bit 5) between bytes — that guarantees the kernel never
    // overwrites bytes the UART hasn't picked up yet, but the FINAL
    // byte of the last `serial.print` is still shifting out when we
    // return. Poking `0x604` here immediately powers off the VM, so
    // without this wait QEMU cuts the chardev mid-shift and the
    // tail of the line is lost. Test `s2_4_9` flaked on this for a
    // long time — `[PASS] §2.4.9` would show up as a truncated
    // `[PAS` in ~40% of runs.
    //
    // Wait for LSR bit 6 ("Transmitter Empty", TEMT) which is the
    // strictly stronger signal: BOTH the THR AND the Transmitter
    // Shift Register are empty, i.e. the wire is actually idle.
    // COM1's LSR is at 0x3F8 + 5 = 0x3FD; drain is bounded so a
    // wedged UART can't hang the shutdown path forever.
    const COM1_LSR: u16 = 0x3FD;
    const TRANSMITTER_EMPTY: u8 = 0b0100_0000;
    var spins: u32 = 0;
    while ((inb(COM1_LSR) & TRANSMITTER_EMPTY) == 0) {
        spins += 1;
        if (spins >= 10_000_000) break;
    }

    asm volatile ("outw %[val], %[port]"
        :
        : [val] "{ax}" (@as(u16, 0x2000)),
          [port] "{dx}" (@as(u16, 0x604)),
    );
    unreachable;
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
        : .{ .dx = true });
}

pub fn outb(value: u8, port: u16) void {
    asm volatile (
        \\outb %[value], %[port]
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn inw(port: u16) u16 {
    return asm volatile (
        \\inw %[port], %[ret]
        : [ret] "={ax}" (-> u16),
        : [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn outw(value: u16, port: u16) void {
    asm volatile (
        \\outw %[value], %[port]
        :
        : [value] "{ax}" (value),
          [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn ind(port: u16) u32 {
    return asm volatile (
        \\inl %[port], %[ret]
        : [ret] "={eax}" (-> u32),
        : [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn outd(value: u32, port: u16) void {
    asm volatile (
        \\outl %[value], %[port]
        :
        : [value] "{eax}" (value),
          [port] "{dx}" (port),
        : .{ .dx = true });
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
        : [ptr] "r" (desc),
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

const IA32_PAT: u32 = 0x277;
// PAT0=WB, PAT1=WT, PAT2=UC-, PAT3=UC, PAT4=WB, PAT5=WC, PAT6=UC-, PAT7=UC
const PAT_VALUE: u64 = 0x00070106_00070406;

pub fn initPat() void {
    wrmsr(IA32_PAT, PAT_VALUE);
}

/// Enable CR0.AM (bit 18) so user-mode alignment check exceptions (#AC) fire
/// when RFLAGS.AC is set and an unaligned access occurs at CPL 3.
pub fn enableAlignmentCheck() void {
    var cr0 = asm ("mov %%cr0, %[cr0]"
        : [cr0] "=r" (-> u64),
    );
    cr0 |= (1 << 18);
    asm volatile ("mov %[cr0], %%cr0"
        :
        : [cr0] "r" (cr0),
    );
}

/// Enable CR4.SMEP (bit 20) and CR4.SMAP (bit 21) when supported.
///
/// SMEP: Supervisor Mode Execution Prevention. With SMEP set, an instruction
/// fetch from a user-mode page while running at CPL 0 raises #PF, foiling
/// the classic "point RIP at user memory" exploit chain.
///
/// SMAP: Supervisor Mode Access Prevention. With SMAP set, a data access to
/// a user-mode page while running at CPL 0 raises #PF unless RFLAGS.AC is 1
/// (set/cleared via STAC/CLAC). Kernel code that intentionally touches a
/// user buffer must bracket the access with `stac()` / `clac()`.
///
/// Feature bits: CPUID.(EAX=7,ECX=0):EBX bit 7 = SMEP, bit 20 = SMAP
/// (Intel SDM Vol 2A, CPUID — Structured Extended Feature Flags).
/// CR4 bit assignments: Intel SDM Vol 3A §2.5.
pub fn enableSmapSmep() void {
    const feat = cpuidRaw(0x7, 0);
    const SMEP_BIT: u32 = 1 << 7;
    const SMAP_BIT: u32 = 1 << 20;
    const has_smep = (feat.ebx & SMEP_BIT) != 0;
    const has_smap = (feat.ebx & SMAP_BIT) != 0;

    var cr4 = asm ("mov %%cr4, %[cr4]"
        : [cr4] "=r" (-> u64),
    );
    if (has_smep) cr4 |= (1 << 20);
    if (has_smap) cr4 |= (1 << 21);
    asm volatile ("mov %[cr4], %%cr4"
        :
        : [cr4] "r" (cr4),
    );
}

/// Set RFLAGS.AC so the current core may read/write user pages under SMAP.
/// Must be paired with `clac()`; keep the window as short as possible.
pub inline fn stac() void {
    asm volatile ("stac");
}

/// Clear RFLAGS.AC. Re-arms SMAP protection after a bracketed user access.
pub inline fn clac() void {
    asm volatile ("clac");
}

/// Enable speculative execution barriers (IBRS, STIBP) when supported.
///
/// IBRS (Indirect Branch Restricted Speculation): prevents indirect branch
/// predictions made at a lower privilege level from influencing execution at
/// a higher privilege level. Enhanced IBRS (eIBRS, "IBRS_ALL") is a
/// set-once-at-boot variant with zero ongoing overhead — available on
/// Coffee Lake Refresh / Zen 2 and later.
///
/// STIBP (Single Thread Indirect Branch Predictors): prevents one logical
/// processor from influencing the branch predictions of its sibling
/// hyperthread. Set alongside IBRS when supported.
///
/// Detection:
///   CPUID.(EAX=7,ECX=0):EDX bit 26 = IBRS/IBPB supported
///   CPUID.(EAX=7,ECX=0):EDX bit 27 = STIBP supported
///   IA32_ARCH_CAPABILITIES (MSR 0x10A) bit 2 = IBRS_ALL (eIBRS)
///
/// Intel SDM Vol 3A §4.10.1; AMD APM Vol 2 §3.2.8.
pub fn enableSpeculationBarriers() void {
    const feat = cpuidRaw(0x7, 0);
    const IBRS_BIT: u32 = 1 << 26;
    const STIBP_BIT: u32 = 1 << 27;
    const has_ibrs = (feat.edx & IBRS_BIT) != 0;
    const has_stibp = (feat.edx & STIBP_BIT) != 0;

    if (!has_ibrs and !has_stibp) return;

    const IA32_SPEC_CTRL: u32 = 0x48;
    var spec_ctrl: u64 = 0;
    if (has_ibrs) spec_ctrl |= (1 << 0); // IBRS
    if (has_stibp) spec_ctrl |= (1 << 1); // STIBP
    wrmsr(IA32_SPEC_CTRL, spec_ctrl);
}

/// Execute RDRAND and return a 64-bit hardware random value, or null if the
/// entropy source is unavailable or temporarily exhausted (CF=0).
///
/// Intel SDM Vol 1 §7.3.17; AMD APM Vol 3, RDRAND instruction reference.
pub fn rdrand() ?u64 {
    var value: u64 = 0;
    var success: u8 = 0;
    asm volatile (
        \\rdrand %[val]
        \\setc %[ok]
        : [val] "=r" (value),
          [ok] "=r" (success),
    );
    return if (success != 0) value else null;
}
