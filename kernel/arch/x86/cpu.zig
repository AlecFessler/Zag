//! CPU utilities for x86-64.
//!
//! Provides register snapshots and privileged helpers used by the kernel,
//! including interrupt control (`cli`/`sti`), port I/O, MSR access, TSC reads,
//! `invlpg`, `cr2` read, and GDT selector reload. All functions assume CPL0.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `CpuidFeatureEcx` – bit flags reported by CPUID leaf 0x1:ECX.
//! - `CpuidFeatureEdx` – bit flags reported by CPUID leaf 0x1:EDX.
//! - `CpuidLeaf` – symbolic CPUID leaf selectors used by this module.
//! - `CpuidPowerEdx` – power/TSC flags from CPUID 0x80000007:EDX.
//! - `Context` – full interrupt frame captured by the common stub.
//! - `Registers` – general-purpose register snapshot layout.
//!
//! ## Constants
//! - `VAddr` – type alias for virtual addresses used throughout paging.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `cpuid` – execute CPUID with given inputs, return {eax,ebx,ecx,edx}.
//! - `disableInterrupts` – clear IF (mask external interrupts).
//! - `enableInterrupts` – set IF (allow external interrupts).
//! - `enableX2Apic` – turn on x2APIC and software-enable local APIC.
//! - `getBrandString` – fetch 48-byte CPU brand string (allocates).
//! - `getVendorString` – fetch 12-byte vendor ID string (allocates).
//! - `halt` – low-power halt loop (never returns).
//! - `hasFeatureEcx` – test a CPUID ECX feature bit.
//! - `hasFeatureEdx` – test a CPUID EDX feature bit.
//! - `hasPowerFeatureEdx` – test a CPUID 0x80000007:EDX power/TSC bit.
//! - `inb` – read a byte from an I/O port.
//! - `invlpg` – invalidate one TLB entry for a virtual address.
//! - `interruptsEnabled` – query IF from RFLAGS.
//! - `outb` – write a byte to an I/O port.
//! - `rdmsr` – read a 64-bit MSR.
//! - `rdtsc_lfenced` – read TSC with LFENCE serialization (start).
//! - `rdtscp` – read TSC via RDTSCP (ordered, reads IA32_TSC_AUX).
//! - `rdtscp_lfenced` – RDTSCP then LFENCE (end).
//! - `read_cr2` – get last page-fault linear address.
//! - `reloadSegments` – reload ring-0 CS/DS/ES/SS from current GDT.
//! - `restoreInterrupts` – restore IF to a saved state.
//! - `saveAndDisableInterrupts` – save RFLAGS, then disable interrupts.
//! - `setWriteProtect` – set/clear CR0.WP write-protect bit.
//! - `wrmsr` – write a 64-bit MSR.

const paging = @import("paging.zig");
const serial = @import("serial.zig");
const std = @import("std");

/// Type alias for the kernel’s virtual address wrapper.
const VAddr = paging.VAddr;

/// CPUID feature bits reported in leaf 0x1:ECX.
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

/// CPUID feature bits reported in leaf 0x1:EDX.
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

/// Symbolic CPUID leaf selectors used by this module.
pub const CpuidLeaf = enum(u32) {
    basic_max = 0x00000000,
    basic_features = 0x00000001,
    ext_max = 0x80000000,
    brand_0 = 0x80000002,
    brand_1 = 0x80000003,
    brand_2 = 0x80000004,
    ext_power = 0x80000007,
};

/// Extended power/TSC feature bits from CPUID 0x80000007:EDX.
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

/// Summary:
/// Executes the CPUID instruction with the provided input registers.
///
/// Args:
/// - `eax`: CPUID leaf selector.
/// - `ecx`: subleaf/index value.
///
/// Return value(s):
/// - Struct containing post-instruction `eax`, `ebx`, `ecx`, and `edx`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
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

/// Summary:
/// Disable maskable interrupts by clearing IF in RFLAGS.
///
/// Args:
/// - None.
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn disableInterrupts() void {
    asm volatile ("cli");
}

/// Summary:
/// Enable maskable interrupts by setting IF in RFLAGS.
///
/// Args:
/// - None.
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn enableInterrupts() void {
    asm volatile ("sti");
}

/// Summary:
/// Enables x2APIC mode and software-enables the local APIC via SVR.
///
/// Args:
/// - `spurious_vector`: interrupt vector (≥ 0x10) to program into SVR.
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics if LAPIC or x2APIC are not supported per CPUID.
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

/// Summary:
/// Returns the CPU brand string (48 bytes, vendor-defined formatting, no NUL).
///
/// Args:
/// - `allocator`: allocator used to allocate the 48-byte result buffer.
///
/// Return value(s):
/// - `[]u8` of length 48; caller owns and must free.
///
/// Errors:
/// - May return allocator errors on allocation failure.
///
/// Panics:
/// - None.
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

/// Summary:
/// Returns the CPU vendor identification string (12 bytes, no NUL).
///
/// Args:
/// - `allocator`: allocator used to allocate the 12-byte result buffer.
///
/// Return value(s):
/// - `[]u8` of length 12 containing EBX||EDX||ECX; caller owns and must free.
///
/// Errors:
/// - May return allocator errors on allocation failure.
///
/// Panics:
/// - None.
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

/// Summary:
/// Halt in a tight loop (low-power wait until an interrupt).
///
/// Args:
/// - None.
///
/// Return value(s):
/// - Never returns (`noreturn`).
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn halt() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}

/// Summary:
/// Checks whether a given ECX CPUID feature bit is present.
///
/// Args:
/// - `reg`: value returned from CPUID leaf 0x1:ECX.
/// - `feat`: desired feature bit from `CpuidFeatureEcx`.
///
/// Return value(s):
/// - `true` if present; `false` otherwise.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn hasFeatureEcx(
    reg: u32,
    feat: CpuidFeatureEcx,
) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

/// Summary:
/// Checks whether a given EDX CPUID feature bit is present.
///
/// Args:
/// - `reg`: value returned from CPUID leaf 0x1:EDX.
/// - `feat`: desired feature bit from `CpuidFeatureEdx`.
///
/// Return value(s):
/// - `true` if present; `false` otherwise.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn hasFeatureEdx(
    reg: u32,
    feat: CpuidFeatureEdx,
) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

/// Summary:
/// Checks whether an extended power/TSC EDX feature bit is present.
///
/// Args:
/// - `reg`: value from CPUID leaf 0x80000007:EDX.
/// - `feat`: desired bit from `CpuidPowerEdx`.
///
/// Return value(s):
/// - `true` if present; `false` otherwise.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn hasPowerFeatureEdx(
    reg: u32,
    feat: CpuidPowerEdx,
) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

/// Summary:
/// Reads one byte from an I/O port.
///
/// Args:
/// - `port`: I/O port to read from.
///
/// Return value(s):
/// - The byte read from `port`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn inb(port: u16) u8 {
    return asm volatile (
        \\inb %[port], %[ret]
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

/// Summary:
/// Invalidates the TLB entry for a virtual address with `invlpg`.
///
/// Args:
/// - `vaddr`: virtual address whose page translation should be dropped.
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn invlpg(vaddr: VAddr) void {
    asm volatile (
        \\invlpg (%[a])
        :
        : [a] "r" (vaddr.addr),
        : .{ .memory = true });
}

/// Summary:
/// Returns whether IF (Interrupt Flag) is currently set in RFLAGS.
///
/// Args:
/// - None.
///
/// Return value(s):
/// - `true` if interrupts are enabled; `false` otherwise.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn interruptsEnabled() bool {
    const IF: u64 = 1 << 9;
    var rflags: u64 = 0;
    asm volatile ("pushfq; pop %[out]"
        : [out] "={rax}" (rflags)
    );
    return (rflags & IF) != 0;
}

/// Summary:
/// Writes one byte to an I/O port.
///
/// Args:
/// - `value`: byte to write.
/// - `port`: I/O port to write to.
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
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

/// Summary:
/// Reads a 64-bit Model Specific Register (MSR) using RDMSR.
///
/// Args:
/// - `msr`: MSR index (ECX).
///
/// Return value(s):
/// - 64-bit value read from the MSR.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
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

/// Summary:
/// Read TSC with LFENCE serialization before the read (best for “start”).
///
/// Args:
/// - None.
///
/// Return value(s):
/// - 64-bit TSC value.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn rdtsc_lfenced() u64 {
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

/// Summary:
/// Read TSC via RDTSCP (ordered; also reads IA32_TSC_AUX into ECX).
///
/// Args:
/// - None.
///
/// Return value(s):
/// - 64-bit TSC value (aux is discarded).
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
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

/// Summary:
/// Read TSC via RDTSCP then LFENCE (best for “end”).
///
/// Args:
/// - None.
///
/// Return value(s):
/// - 64-bit TSC value.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn rdtscp_lfenced() u64 {
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

/// Summary:
/// Reads `cr2` and returns the last page-fault linear address.
///
/// Args:
/// - None.
///
/// Return value(s):
/// - `VAddr` of the most recent page-faulting linear address.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn read_cr2() VAddr {
    var addr: u64 = 0;
    asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (addr),
    );
    return VAddr.fromInt(addr);
}

/// Summary:
/// Reloads CS/DS/ES/SS using known ring-0 selectors in the current GDT.
///
/// Args:
/// - None. Assumes CS=0x08 and DS/ES/SS=0x10 exist in the active GDT.
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
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

/// Summary:
/// Restore interrupts to a prior state captured from `saveAndDisableInterrupts()`.
///
/// Args:
/// - `saved_rflags`: RFLAGS value previously returned by `saveAndDisableInterrupts`.
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn restoreInterrupts(saved_rflags: u64) void {
    const IF: u64 = 1 << 9;
    if ((saved_rflags & IF) != 0) {
        asm volatile ("sti");
    } else {
        asm volatile ("cli");
    }
}

/// Summary:
/// Save current interrupt state and then disable interrupts (CLI).
///
/// Args:
/// - None.
///
/// Return value(s):
/// - The caller’s RFLAGS prior to disabling interrupts.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn saveAndDisableInterrupts() u64 {
    var rflags: u64 = 0;
    asm volatile ("pushfq; pop %[out]"
        : [out] "={rax}" (rflags)
    );
    asm volatile ("cli");
    return rflags;
}

/// Summary:
/// Enables or disables the CR0.WP (write-protect) bit.
///
/// Args:
/// - `enable`: `true` to set WP (enforce read-only pages), `false` to clear WP.
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
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

/// Summary:
/// Writes a 64-bit value to a Model Specific Register with WRMSR.
///
/// Args:
/// - `msr`: MSR index (ECX).
/// - `value`: 64-bit value to write (split into EDX:EAX).
///
/// Return value(s):
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
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
