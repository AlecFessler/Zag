/// Local APIC emulation for Linux guest boot.
/// Intel SDM Vol 3, Chapter 13 — xAPIC mode, single vCPU (APIC ID 0).
/// APIC registers are memory-mapped at base 0xFEE00000, 4 KiB region.
/// All registers are 32-bit, aligned on 128-bit (16-byte) boundaries.
/// Table 13-1: Local APIC Register Address Map.

const log = @import("log.zig");
const ioapic = @import("ioapic.zig");

pub const APIC_BASE: u64 = 0xFEE00000;

// Register offsets from APIC base (Table 13-1)
const REG_ID: u32 = 0x020; // Local APIC ID Register — R/W
const REG_VERSION: u32 = 0x030; // Local APIC Version Register — RO
const REG_TPR: u32 = 0x080; // Task Priority Register — R/W
const REG_APR: u32 = 0x090; // Arbitration Priority Register — RO
const REG_PPR: u32 = 0x0A0; // Processor Priority Register — RO
const REG_EOI: u32 = 0x0B0; // EOI Register — WO
const REG_LDR: u32 = 0x0D0; // Logical Destination Register — R/W
const REG_DFR: u32 = 0x0E0; // Destination Format Register — R/W
const REG_SVR: u32 = 0x0F0; // Spurious Interrupt Vector Register — R/W
const REG_ISR_BASE: u32 = 0x100; // ISR bits 31:0 through 255:224 (8 regs) — RO
const REG_TMR_BASE: u32 = 0x180; // TMR bits 31:0 through 255:224 (8 regs) — RO
const REG_IRR_BASE: u32 = 0x200; // IRR bits 31:0 through 255:224 (8 regs) — RO
const REG_ESR: u32 = 0x280; // Error Status Register — R/W
const REG_ICR_LO: u32 = 0x300; // Interrupt Command Register bits 0-31 — R/W
const REG_ICR_HI: u32 = 0x310; // Interrupt Command Register bits 32-63 — R/W
const REG_LVT_TIMER: u32 = 0x320; // LVT Timer Register — R/W
const REG_LVT_THERMAL: u32 = 0x330; // LVT Thermal Sensor Register — R/W
const REG_LVT_PERF: u32 = 0x340; // LVT Performance Monitoring Register — R/W
const REG_LVT_LINT0: u32 = 0x350; // LVT LINT0 Register — R/W
const REG_LVT_LINT1: u32 = 0x360; // LVT LINT1 Register — R/W
const REG_LVT_ERROR: u32 = 0x370; // LVT Error Register — R/W
const REG_TIMER_ICR: u32 = 0x380; // Timer Initial Count Register — R/W
const REG_TIMER_CCR: u32 = 0x390; // Timer Current Count Register — RO
const REG_TIMER_DCR: u32 = 0x3E0; // Timer Divide Configuration Register — R/W

// APIC register state — file-scope globals to avoid stack allocation.

/// APIC ID register (Figure 13-6). Bits 31:24 = APIC ID, rest reserved.
var apic_id: u32 = 0;

/// Task Priority Register. Bits 7:0 = task priority, rest reserved.
var tpr: u32 = 0;

/// Logical Destination Register. Bits 31:24 = logical APIC ID.
var ldr: u32 = 0;

/// Destination Format Register. Reset to all 1s (Section 13.4.7.1).
var dfr: u32 = 0xFFFFFFFF;

/// Spurious Interrupt Vector Register. Reset to 0x000000FF (Section 13.4.7.1).
/// Bit 8 = APIC software enable, bits 7:0 = spurious vector.
var svr: u32 = 0x000000FF;

/// Error Status Register.
var esr: u32 = 0;
var esr_shadow: u32 = 0; // Accumulates errors until next ESR write

/// Interrupt Command Register (64 bits, accessed as two 32-bit halves).
var icr_lo: u32 = 0;
var icr_hi: u32 = 0;

/// LVT registers. Reset to 0x00010000 (masked). Section 13.4.7.1.
var lvt_timer: u32 = 0x00010000;
var lvt_thermal: u32 = 0x00010000;
var lvt_perf: u32 = 0x00010000;
var lvt_lint0: u32 = 0x00010000;
var lvt_lint1: u32 = 0x00010000;
var lvt_error: u32 = 0x00010000;

/// Timer registers. All reset to 0.
var timer_initial_count: u32 = 0;
var timer_current_count: u32 = 0;
var timer_divide_config: u32 = 0;

/// Timer accumulator: fractional nanoseconds carried between tick() calls.
var timer_accum_ns: u64 = 0;

/// 256-bit vector registers: ISR, TMR, IRR (8 x 32-bit words each).
var isr: [8]u32 = .{0} ** 8;
var tmr: [8]u32 = .{0} ** 8;
var irr: [8]u32 = .{0} ** 8;

var log_count: u32 = 0;

/// Initialize all APIC registers to power-up/reset state (Section 13.4.7.1).
pub fn init() void {
    apic_id = 0; // vCPU 0
    tpr = 0;
    ldr = 0;
    dfr = 0xFFFFFFFF;
    svr = 0x000000FF; // APIC disabled (bit 8 = 0), spurious vector = 0xFF
    esr = 0;
    esr_shadow = 0;
    icr_lo = 0;
    icr_hi = 0;
    lvt_timer = 0x00010000;
    lvt_thermal = 0x00010000;
    lvt_perf = 0x00010000;
    lvt_lint0 = 0x00010000;
    lvt_lint1 = 0x00010000;
    lvt_error = 0x00010000;
    timer_initial_count = 0;
    timer_current_count = 0;
    timer_divide_config = 0;
    timer_accum_ns = 0;
    for (&isr) |*w| w.* = 0;
    for (&tmr) |*w| w.* = 0;
    for (&irr) |*w| w.* = 0;
    log.print("LAPIC: init done\n");
}

/// Handle MMIO read at offset from APIC base 0xFEE00000.
/// All APIC registers are 32-bit, 128-bit aligned (Table 13-1).
pub noinline fn read(offset: u32) u32 {
    return switch (offset) {
        REG_ID => apic_id,
        REG_VERSION => 0x00050014, // Version 0x14, Max LVT Entry = 5 (6 entries)
        REG_TPR => tpr,
        REG_APR => 0, // APR not used in xAPIC on modern processors
        REG_PPR => computePPR(),
        // EOI is write-only; reads return 0
        REG_EOI => 0,
        REG_LDR => ldr,
        REG_DFR => dfr,
        REG_SVR => svr,
        // ISR: 8 registers at 0x100-0x170
        REG_ISR_BASE, REG_ISR_BASE + 0x10, REG_ISR_BASE + 0x20, REG_ISR_BASE + 0x30,
        REG_ISR_BASE + 0x40, REG_ISR_BASE + 0x50, REG_ISR_BASE + 0x60, REG_ISR_BASE + 0x70,
        => isr[(offset - REG_ISR_BASE) >> 4],
        // TMR: 8 registers at 0x180-0x1F0
        REG_TMR_BASE, REG_TMR_BASE + 0x10, REG_TMR_BASE + 0x20, REG_TMR_BASE + 0x30,
        REG_TMR_BASE + 0x40, REG_TMR_BASE + 0x50, REG_TMR_BASE + 0x60, REG_TMR_BASE + 0x70,
        => tmr[(offset - REG_TMR_BASE) >> 4],
        // IRR: 8 registers at 0x200-0x270
        REG_IRR_BASE, REG_IRR_BASE + 0x10, REG_IRR_BASE + 0x20, REG_IRR_BASE + 0x30,
        REG_IRR_BASE + 0x40, REG_IRR_BASE + 0x50, REG_IRR_BASE + 0x60, REG_IRR_BASE + 0x70,
        => irr[(offset - REG_IRR_BASE) >> 4],
        REG_ESR => esr,
        REG_ICR_LO => icr_lo,
        REG_ICR_HI => icr_hi,
        REG_LVT_TIMER => lvt_timer,
        REG_LVT_THERMAL => lvt_thermal,
        REG_LVT_PERF => lvt_perf,
        REG_LVT_LINT0 => lvt_lint0,
        REG_LVT_LINT1 => lvt_lint1,
        REG_LVT_ERROR => lvt_error,
        REG_TIMER_ICR => timer_initial_count,
        REG_TIMER_CCR => timer_current_count,
        REG_TIMER_DCR => timer_divide_config,
        else => blk: {
            if (log_count < 10) {
                log_count += 1;
                log.print("LAPIC: unknown read offset=0x");
                log.hex32(offset);
                log.print("\n");
            }
            break :blk 0;
        },
    };
}

/// Handle MMIO write at offset from APIC base 0xFEE00000.
pub noinline fn write(offset: u32, value: u32) void {
    switch (offset) {
        REG_ID => apic_id = value & 0xFF000000, // Only bits 31:24 writable
        REG_TPR => tpr = value & 0xFF,
        REG_EOI => handleEOI(),
        REG_LDR => ldr = value & 0xFF000000,
        REG_DFR => dfr = value | 0x0FFFFFFF, // Bits 27:0 are all 1s (reserved)
        REG_SVR => svr = value & 0x1FF, // Bits 8:0 writable (enable + vector)
        REG_ESR => {
            // Section 13.5.3: Write to ESR clears it and latches accumulated errors.
            esr = esr_shadow;
            esr_shadow = 0;
        },
        REG_ICR_LO => {
            icr_lo = value;
            handleICR();
        },
        REG_ICR_HI => icr_hi = value,
        REG_LVT_TIMER => lvt_timer = value,
        REG_LVT_THERMAL => lvt_thermal = value,
        REG_LVT_PERF => lvt_perf = value,
        REG_LVT_LINT0 => lvt_lint0 = value,
        REG_LVT_LINT1 => lvt_lint1 = value,
        REG_LVT_ERROR => lvt_error = value,
        REG_TIMER_ICR => {
            timer_initial_count = value;
            timer_current_count = value;
            timer_accum_ns = 0;
            // Writing 0 stops the timer (Section 13.5.4)
        },
        REG_TIMER_DCR => timer_divide_config = value & 0x0B, // Only bits 3, 1:0 used
        else => {
            if (log_count < 10) {
                log_count += 1;
                log.print("LAPIC: unknown write offset=0x");
                log.hex32(offset);
                log.print(" val=0x");
                log.hex32(value);
                log.print("\n");
            }
        },
    }
}

/// Advance the APIC timer by elapsed_ns nanoseconds.
/// Called from the VMM exit loop. If the timer fires, sets the IRR bit
/// for the vector in the LVT timer register.
/// Section 13.5.4: APIC Timer.
pub noinline fn tick(elapsed_ns: u64) void {
    // Timer stopped if initial count is 0
    if (timer_initial_count == 0) return;
    // Timer stopped if current count already 0 in one-shot mode
    const timer_mode: u2 = @truncate((lvt_timer >> 17) & 0x3);
    if (timer_mode == 0 and timer_current_count == 0) return;
    // TSC-deadline mode (0b10) — stubbed
    if (timer_mode == 2) return;

    const divisor = getTimerDivisor();
    // Each "tick" of the APIC timer = divisor bus cycles.
    // We treat the bus clock as 1 GHz (1 ns per cycle) for simplicity.
    // So each APIC timer tick = divisor nanoseconds.
    const total_ns = timer_accum_ns + elapsed_ns;
    const ticks_elapsed = total_ns / divisor;
    timer_accum_ns = total_ns % divisor;

    if (ticks_elapsed == 0) return;

    if (timer_mode == 0) {
        // One-shot: count down to 0, fire once
        if (ticks_elapsed >= timer_current_count) {
            timer_current_count = 0;
            fireTimerInterrupt();
        } else {
            timer_current_count -= @truncate(ticks_elapsed);
        }
    } else if (timer_mode == 1) {
        // Periodic: count down, reload from initial count, repeat
        var remaining = ticks_elapsed;
        while (remaining > 0) {
            if (remaining >= timer_current_count) {
                remaining -= timer_current_count;
                timer_current_count = timer_initial_count;
                fireTimerInterrupt();
            } else {
                timer_current_count -= @truncate(remaining);
                remaining = 0;
            }
        }
    }
}

/// Return the highest-priority pending interrupt vector that can be
/// delivered (IRR set, ISR not set for that vector, priority > TPR).
/// Returns null if no deliverable interrupt is pending.
pub fn getPendingVector() ?u8 {
    // APIC must be software-enabled (SVR bit 8)
    if (svr & 0x100 == 0) return null;

    const irr_vec = highestSetBit(&irr) orelse return null;
    const isr_vec = highestSetBit(&isr) orelse 0;

    // Priority class = vector >> 4. An interrupt is deliverable if its
    // priority class is greater than both the ISR priority and TPR priority.
    const irr_prio = irr_vec >> 4;
    const isr_prio = isr_vec >> 4;
    const tpr_prio: u8 = @truncate((tpr >> 4) & 0xF);

    if (irr_prio > isr_prio and irr_prio > tpr_prio) {
        return irr_vec;
    }
    return null;
}

/// Accept an interrupt vector: move from IRR to ISR.
/// Called after the VMM injects the interrupt into the guest via VMCB.
pub fn acceptInterrupt(vector: u8) void {
    clearBit(&irr, vector);
    setBit(&isr, vector);
}

/// Set the IRR bit for an external interrupt vector.
/// Used by the IOAPIC to deliver interrupts to this LAPIC.
pub fn injectExternal(vector: u8) void {
    setBit(&irr, vector);
}

// --- Internal helpers ---

/// Compute Processor Priority Register (PPR).
/// PPR = max(TPR, highest ISR priority class : 0). Section 13.8.3.1.
fn computePPR() u32 {
    const isr_vec = highestSetBit(&isr) orelse 0;
    const isr_class: u32 = isr_vec >> 4;
    const tpr_class: u32 = (tpr >> 4) & 0xF;
    if (tpr_class >= isr_class) {
        return tpr; // TPR value as-is
    }
    // PPR[7:4] = ISR priority class, PPR[3:0] = 0
    return isr_class << 4;
}

/// EOI handling (Section 13.8.5): clear the highest-priority bit in ISR.
/// For level-triggered interrupts, also clear remote IRR in the IOAPIC.
fn handleEOI() void {
    const vec = highestSetBit(&isr) orelse return;
    clearBit(&isr, vec);
    // If this was a level-triggered interrupt (TMR bit set), notify IOAPIC
    if (getBit(&tmr, vec)) {
        ioapic.handleEOI(vec);
    }
}

/// Handle ICR write — IPI delivery (Section 13.6.1).
/// For single-vCPU emulation, only self-IPIs and broadcast are relevant.
fn handleICR() void {
    const vector: u8 = @truncate(icr_lo & 0xFF);
    const delivery_mode: u3 = @truncate((icr_lo >> 8) & 0x7);
    const shorthand: u2 = @truncate((icr_lo >> 18) & 0x3);

    switch (shorthand) {
        0b01 => {
            // Self IPI
            if (delivery_mode == 0b000) { // Fixed
                setBit(&irr, vector);
            }
        },
        else => {
            // For single vCPU, other shorthands are stubs
            if (log_count < 10) {
                log_count += 1;
                log.print("LAPIC: ICR shorthand=");
                log.dec(shorthand);
                log.print(" dm=");
                log.dec(delivery_mode);
                log.print(" vec=0x");
                log.hex8(vector);
                log.print("\n");
            }
        },
    }
    // Clear delivery status bit (bit 12) — delivery is always "complete"
    icr_lo &= ~@as(u32, 1 << 12);
}

/// Fire a timer interrupt: set IRR bit for the LVT timer vector.
fn fireTimerInterrupt() void {
    // Masked? (bit 16 of LVT timer)
    if (lvt_timer & 0x10000 != 0) return;
    const vector: u8 = @truncate(lvt_timer & 0xFF);
    if (vector < 16) {
        // Illegal vector — set ESR bit 5 (send illegal vector)
        esr_shadow |= (1 << 5);
        return;
    }
    setBit(&irr, vector);
}

/// Decode the timer divide configuration register (Figure 13-10).
/// Returns the divisor as a u64.
fn getTimerDivisor() u64 {
    // Divide value is encoded in bits 3, 1:0 of the DCR.
    // Bit layout: bit3 | bit1 | bit0 → 3-bit code
    const bits10: u3 = @truncate(timer_divide_config & 0x3);
    const bit3: u3 = @truncate((timer_divide_config >> 3) & 0x1);
    const code: u3 = (bit3 << 2) | bits10;
    return switch (code) {
        0b000 => 2,
        0b001 => 4,
        0b010 => 8,
        0b011 => 16,
        0b100 => 32,
        0b101 => 64,
        0b110 => 128,
        0b111 => 1,
    };
}

/// Find the highest set bit across a 256-bit vector (8 x 32-bit words).
/// Returns the bit index (0-255) or null if no bits are set.
/// Bit 0 of word 0 = vector 0, bit 31 of word 7 = vector 255.
fn highestSetBit(vec: *const [8]u32) ?u8 {
    var i: u8 = 8;
    while (i > 0) {
        i -= 1;
        if (vec[i] != 0) {
            // Find highest set bit in this 32-bit word
            var bit: u5 = 31;
            while (true) {
                if (vec[i] & (@as(u32, 1) << bit) != 0) {
                    return @as(u8, i) * 32 + bit;
                }
                if (bit == 0) break;
                bit -= 1;
            }
        }
    }
    return null;
}

/// Set a bit in a 256-bit vector.
fn setBit(vec: *[8]u32, bit_index: u8) void {
    const word: u3 = @truncate(bit_index >> 5);
    const bit: u5 = @truncate(bit_index & 0x1F);
    vec[word] |= @as(u32, 1) << bit;
}

/// Clear a bit in a 256-bit vector.
fn clearBit(vec: *[8]u32, bit_index: u8) void {
    const word: u3 = @truncate(bit_index >> 5);
    const bit: u5 = @truncate(bit_index & 0x1F);
    vec[word] &= ~(@as(u32, 1) << bit);
}

/// Test a bit in a 256-bit vector.
fn getBit(vec: *const [8]u32, bit_index: u8) bool {
    const word: u3 = @truncate(bit_index >> 5);
    const bit: u5 = @truncate(bit_index & 0x1F);
    return (vec[word] & (@as(u32, 1) << bit)) != 0;
}
