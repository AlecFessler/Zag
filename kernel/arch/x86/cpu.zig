//! CPU utilities for x86-64.
//!
//! Provides register snapshots and small privileged helpers used by the kernel,
//! including `hlt` loops, `invlpg`, reading `cr2`, and reloading segment
//! selectors after GDT setup. All functions assume CPL0 (ring 0).

const paging = @import("paging.zig");
const serial = @import("serial.zig");
const std = @import("std");

const VAddr = paging.VAddr;

pub const Context = packed struct {
    /// General registers saved by the common stub.
    regs: Registers,
    /// Interrupt vector number (pushed by per-vector stub).
    int_num: u64,
    /// Error code (real or synthetic 0 depending on vector).
    err_code: u64,
    /// Saved instruction pointer.
    rip: u64,
    /// Saved code segment selector.
    cs: u64,
    /// Saved RFLAGS.
    rflags: u64,
    /// Saved stack pointer.
    rsp: u64,
    /// Saved stack segment selector.
    ss: u64,
};

/// Snapshot of general-purpose registers saved/restored by interrupt/exception glue.
///
/// Layout matches the push/pop order used by our stubs so it can be copied
/// verbatim to/from the stack. All fields are 64-bit.
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

/// ECX feature bits returned from CPUID leaf `0x1:ECX`.
///
/// These bits describe CPU capabilities such as AVX, AES-NI, SSE4.1/2, etc.
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

/// EDX feature bits returned from CPUID leaf `0x1:EDX`.
///
/// Covers foundational CPU features: FPU, RDTSC, SSE, APIC presence, etc.
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

pub const CpuidLeaf = enum(u32) {
    basic_max = 0x00000000,
    basic_features = 0x00000001,
    ext_max = 0x80000000,
    brand_0 = 0x80000002,
    brand_1 = 0x80000003,
    brand_2 = 0x80000004,
    ext_power = 0x80000007,
};

/// Checks whether a given ECX CPUID feature bit is present.
///
/// Arguments:
/// - `reg`: value returned from CPUID leaf `0x1:ECX`.
/// - `feat`: desired feature.
///
/// Returns:
/// - `true` if present, `false` otherwise.
pub fn hasFeatureEcx(
    reg: u32,
    feat: CpuidFeatureEcx,
) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

/// Checks whether a given EDX CPUID feature bit is present.
///
/// Arguments:
/// - `reg`: value returned from CPUID leaf `0x1:EDX`.
/// - `feat`: desired feature from `CpuidFeatureEdx`.
///
/// Returns:
/// - `true` if the feature bit is set, `false` otherwise.
pub fn hasFeatureEdx(
    reg: u32,
    feat: CpuidFeatureEdx,
) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

/// Checks whether an extended (power/TSC) EDX CPUID feature bit is present.
///
/// This is used with CPUID leaf `0x80000007:EDX`, which reports advanced
/// power management and TSC behavior, including the invariant TSC bit.
///
/// Arguments:
/// - `reg`: value returned from CPUID leaf `0x80000007:EDX`.
/// - `feat`: desired feature from `CpuidPowerEdx`.
///
/// Returns:
/// - `true` if the feature bit is set, `false` otherwise.
pub fn hasPowerFeatureEdx(
    reg: u32,
    feat: CpuidPowerEdx,
) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

/// Executes the CPUID instruction with the provided input registers.
///
/// Arguments:
/// - `eax`: value loaded into EAX before executing `cpuid`.
/// - `ecx`: value loaded into ECX before executing `cpuid`.
///
/// Returns:
/// - Struct with the post-instruction register values:
///   - `eax`: EAX after `cpuid`
///   - `ebx`: EBX after `cpuid`
///   - `ecx`: ECX after `cpuid`
///   - `edx`: EDX after `cpuid`
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

/// Returns the CPU vendor identification string (12 bytes, no NUL terminator).
///
/// Arguments:
/// - `allocator`: allocator used to return the vendor string buffer.
///
/// Returns:
/// - `[]u8` of length 12 containing the vendor ID assembled as EBX||EDX||ECX.
///   Caller owns the buffer and must free it.
pub fn getVendorString(allocator: std.mem.Allocator) ![]u8 {
    const r = cpuid(.basic_max, 0);
    var out = try allocator.alloc(u8, 12);

    const b: [4]u8 = @bitCast(r.ebx);
    const d: [4]u8 = @bitCast(r.edx);
    const c: [4]u8 = @bitCast(r.ecx);

    @memcpy(out[0..4], &b);
    @memcpy(out[4..8], &d);
    @memcpy(out[8..12], &c);

    return out;
}

/// Returns the CPU brand string (48 bytes, no NUL terminator).
///
/// Arguments:
/// - `allocator`: allocator used to return the brand string buffer.
///
/// Returns:
/// - `[]u8` of length 48 built from CPUID leaves `0x80000002..4`.
///   Caller owns the buffer and must free it. Content/spacing is vendor-defined.
pub fn getBrandString(allocator: std.mem.Allocator) ![]u8 {
    var out = try allocator.alloc(u8, 48);
    var i: usize = 0;
    var leaf: u32 = @intFromEnum(CpuidLeaf.brand_0);

    while (leaf <= @intFromEnum(CpuidLeaf.brand_2)) {
        const r = cpuid(@enumFromInt(leaf), 0);

        const a: [4]u8 = @bitCast(r.eax);
        const b: [4]u8 = @bitCast(r.ebx);
        const c: [4]u8 = @bitCast(r.ecx);
        const d: [4]u8 = @bitCast(r.edx);

        @memcpy(out[i .. i + 4], &a);
        @memcpy(out[i + 4 .. i + 8], &b);
        @memcpy(out[i + 8 .. i + 12], &c);
        @memcpy(out[i + 12 .. i + 16], &d);

        i += 16;
        leaf += 1;
    }
    return out;
}

/// Halts the CPU in a tight loop (low-power wait until interrupt).
///
/// Never returns.
pub fn halt() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}

/// Reads one byte from an I/O port.
///
/// Arguments:
/// - `port`: I/O port to read from.
///
/// Returns:
/// - The byte read from `port`.
pub fn inb(port: u16) u8 {
    return asm volatile (
        \\inb %[port], %[ret]
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

/// Writes one byte to an I/O port.
///
/// Arguments:
/// - `value`: byte to write.
/// - `port`: I/O port to write to.
pub fn outb(
    value: u8,
    port: u16,
) void {
    asm volatile (
        \\outb %[value], %[port]
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
    );
}

/// Invalidates the TLB entry for `vaddr`.
///
/// Arguments:
/// - `vaddr`: virtual address whose page translation should be dropped
pub fn invlpg(vaddr: VAddr) void {
    asm volatile (
        \\invlpg (%[a])
        :
        : [a] "r" (vaddr.addr),
        : .{ .memory = true });
}

/// Reads `cr2` and returns the last page-fault linear address.
///
/// Returns:
/// - `VAddr` of the most recent page-faulting linear address.
pub fn read_cr2() VAddr {
    var addr: u64 = 0;
    asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (addr),
    );
    return VAddr.fromInt(addr);
}

/// Reloads CS/DS/ES/SS using known ring-0 selectors in the current GDT.
///
/// Assumes:
/// - Code selector = `0x08`
/// - Data selectors (DS/ES/SS) = `0x10`
pub fn reloadSegments() void {
    asm volatile (
        \\pushq $0x08
        \\leaq 1f(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\1:
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%ss
        ::: .{ .memory = true });
}

/// Enables or disables the CR0.WP (write-protect) bit.
///
/// When disabled, supervisor-mode writes may modify read-only pages.
/// Use with care; typically enable WP except for tightly controlled updates.
///
/// Arguments:
/// - `enable`: `true` to set WP (protect read-only pages), `false` to clear WP.
pub fn setWriteProtect(enable: bool) void {
    var cr0: u64 = 0;
    asm volatile ("mov %%cr0, %[out]"
        : [out] "=r" (cr0),
    );
    const wp_bit: u64 = 1 << 16;
    if (enable) {
        cr0 |= wp_bit;
    } else {
        cr0 &= ~wp_bit;
    }
    asm volatile ("mov %[in], %%cr0"
        :
        : [in] "r" (cr0),
        : .{ .memory = true });
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

/// Enables x2APIC mode and software-enables the local APIC via SVR.
///
/// - Sets IA32_APIC_BASE.EN (bit 11) and IA32_APIC_BASE.EXTD (bit 10)
/// - Programs x2APIC SVR MSR with the given spurious vector and APIC enable bit
pub fn enableX2Apic(spurious_vector: u8) void {
    std.debug.assert(spurious_vector >= 0x10);

    const feat = cpuid(.basic_features, 0);
    if (!hasFeatureEdx(feat.edx, .lapic)) @panic("Local APIC not present");
    if (!hasFeatureEcx(feat.ecx, .x2apic)) @panic("x2APIC not supported");

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
}

pub fn rdtscp() u64 {
    var a: u32 = 0;
    var d: u32 = 0;
    var c: u32 = 0;
    asm volatile ("rdtscp"
        : [a] "={eax}" (a),
          [d] "={edx}" (d),
          [c] "={ecx}" (c),
        :
        : .{ .memory = true }
    );
    return (@as(u64, d) << 32) | a;
}
