//! x2APIC MSR helpers and LAPIC timer control.
//!
//! Provides symbolic MSR indices for x2APIC registers and a small set of
//! utilities to arm/cancel the IA32_TSC_DEADLINE timer, send end-of-interrupt
//! (EOI), mask the legacy 8259 PIC, and program the LAPIC timer in TSC-deadline
//! mode. Designed to be freestanding and safe to invoke during early bring-up.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `X2ApicMsr` – symbolic MSR indices for x2APIC registers.
//!
//! ## Constants
//! - `tsc_deadline_msr` – MSR number for `IA32_TSC_DEADLINE`.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `armTscDeadline` – write a TSC deadline to IA32_TSC_DEADLINE.
//! - `cancelTscDeadline` – cancel any pending TSC deadline (write zero).
//! - `disablePic` – mask both 8259 PICs to avoid spurious IRQs.
//! - `endOfInterrupt` – write EOI to x2APIC EOI MSR.
//! - `programLocalApicTimerTscDeadline` – enable LAPIC timer in TSC-deadline mode with a vector.

const cpu = @import("cpu.zig");

/// Symbolic MSR indices for x2APIC registers.
pub const X2ApicMsr = enum(u32) {
    local_apic_id_register = 0x802,
    local_apic_version_register = 0x803,

    task_priority_register = 0x808,
    processor_priority_register = 0x80a,
    end_of_interrupt_register = 0x80b,
    logical_destination_register = 0x80d,
    spurious_interrupt_vector_register = 0x80f,

    in_service_register_bits_0_to_31 = 0x810,
    in_service_register_bits_32_to_63 = 0x811,
    in_service_register_bits_64_to_95 = 0x812,
    in_service_register_bits_96_to_127 = 0x813,
    in_service_register_bits_128_to_159 = 0x814,
    in_service_register_bits_160_to_191 = 0x815,
    in_service_register_bits_192_to_223 = 0x816,
    in_service_register_bits_224_to_255 = 0x817,

    trigger_mode_register_bits_0_to_31 = 0x818,
    trigger_mode_register_bits_32_to_63 = 0x819,
    trigger_mode_register_bits_64_to_95 = 0x81a,
    trigger_mode_register_bits_96_to_127 = 0x81b,
    trigger_mode_register_bits_128_to_159 = 0x81c,
    trigger_mode_register_bits_160_to_191 = 0x81d,
    trigger_mode_register_bits_192_to_223 = 0x81e,
    trigger_mode_register_bits_224_to_255 = 0x81f,

    interrupt_request_register_bits_0_to_31 = 0x820,
    interrupt_request_register_bits_32_to_63 = 0x821,
    interrupt_request_register_bits_64_to_95 = 0x822,
    interrupt_request_register_bits_96_to_127 = 0x823,
    interrupt_request_register_bits_128_to_159 = 0x824,
    interrupt_request_register_bits_160_to_191 = 0x825,
    interrupt_request_register_bits_192_to_223 = 0x826,
    interrupt_request_register_bits_224_to_255 = 0x827,

    error_status_register = 0x828,

    local_vector_table_corrected_machine_check_interrupt = 0x82f,
    interrupt_command_register = 0x830,

    local_vector_table_timer_register = 0x832,
    local_vector_table_thermal_sensor_register = 0x833,
    local_vector_table_performance_monitor_register = 0x834,
    local_vector_table_lint0_register = 0x835,
    local_vector_table_lint1_register = 0x836,
    local_vector_table_error_register = 0x837,

    timer_initial_count_register = 0x838,
    timer_current_count_register = 0x839,
    timer_divide_configuration_register = 0x83e,

    self_interrupt_register = 0x83f,
};

/// MSR number for `IA32_TSC_DEADLINE`.
pub const tsc_deadline_msr: u32 = 0x6e0;

/// Summary:
/// Arms the LAPIC TSC-deadline timer by writing `deadline_tsc` to `IA32_TSC_DEADLINE`.
///
/// Arguments:
/// - `deadline_tsc`: Absolute TSC value at which the timer interrupt should fire.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn armTscDeadline(deadline_tsc: u64) void {
    cpu.wrmsr(tsc_deadline_msr, deadline_tsc);
}

/// Summary:
/// Cancels any pending TSC-deadline interrupt by writing zero to `IA32_TSC_DEADLINE`.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn cancelTscDeadline() void {
    cpu.wrmsr(tsc_deadline_msr, 0);
}

/// Summary:
/// Disables the legacy 8259 PICs by masking all interrupts on both controllers.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn disablePic() void {
    cpu.outb(0xFF, 0x21);
    cpu.outb(0xFF, 0xA1);
}

/// Summary:
/// Signals End-Of-Interrupt (EOI) to the local x2APIC.
///
/// Arguments:
/// - None.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn endOfInterrupt() void {
    cpu.wrmsr(@intFromEnum(X2ApicMsr.end_of_interrupt_register), 0);
}

/// Summary:
/// Programs the LAPIC timer into TSC-deadline mode and sets the interrupt vector.
///
/// Arguments:
/// - `vector`: Interrupt vector (0–255) to be delivered when the deadline expires.
///
/// Returns:
/// - `void`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - Panics if the CPU does not support x2APIC TSC-deadline mode or invariant TSC.
pub fn programLocalApicTimerTscDeadline(vector: u8) void {
    const feat = cpu.cpuid(.basic_features, 0);
    if (!cpu.hasFeatureEcx(feat.ecx, .tsc_deadline)) @panic("TSC-deadline not supported");

    const max_ext = cpu.cpuid(.ext_max, 0).eax;
    if (max_ext < @intFromEnum(cpu.CpuidLeaf.ext_max)) @panic("Invariant TSC not supported");

    const pwr = cpu.cpuid(.ext_power, 0);
    if (!cpu.hasPowerFeatureEdx(pwr.edx, .constant_tsc)) @panic("Invariant TSC not supported");

    const TIMER_MODE_LSB: u6 = 17;
    const TSC_DEADLINE: u2 = 0b10;

    var lvt: u64 = vector;
    lvt |= (@as(u64, TSC_DEADLINE) << TIMER_MODE_LSB);
    cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), lvt);
}
