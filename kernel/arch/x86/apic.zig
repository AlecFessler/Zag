const cpu = @import("cpu.zig");

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

pub const tsc_deadline_msr: u32 = 0x6e0;

pub fn disablePic() void {
    cpu.outb(0xFF, 0x21);
    cpu.outb(0xFF, 0xA1);
}

pub fn programLocalApicTimerTscDeadline(vector: u8) void {
    const TIMER_MODE_LSB: u6 = 17;
    const TSC_DEADLINE: u2 = 0b10;

    var lvt: u64 = vector;
    lvt |= (@as(u64, TSC_DEADLINE) << TIMER_MODE_LSB);
    cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), lvt);
}

pub fn armTscDeadline(deadline_tsc: u64) void {
    cpu.wrmsr(tsc_deadline_msr, deadline_tsc);
}

pub fn cancelTscDeadline() void {
    cpu.wrmsr(tsc_deadline_msr, 0);
}

pub fn endOfInterrupt() void {
    cpu.wrmsr(@intFromEnum(X2ApicMsr.end_of_interrupt_register), 0);
}
