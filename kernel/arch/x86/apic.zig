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
const idt = @import("idt.zig");
const paging = @import("paging.zig");

const VAddr = paging.VAddr;

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

pub const Register = enum(u64) {
    lapic_id_reg = 0x20,
    lapic_version_reg = 0x30,
    task_prio_reg = 0x80,
    arbitration_prio_reg = 0x90,
    processor_prio_reg = 0xA0,
    eoi_reg = 0xB0,
    remote_read_reg = 0xC0,
    logical_dest_reg = 0xD0,
    dest_fmt_reg = 0xE0,
    spurious_int_vec_reg = 0xF0,
    in_service_0_reg = 0x100,
    in_service_1_reg = 0x110,
    in_service_2_reg = 0x120,
    in_service_3_reg = 0x130,
    in_service_4_reg = 0x140,
    in_service_5_reg = 0x150,
    in_service_6_reg = 0x160,
    in_service_7_reg = 0x170,
    trigger_mode_0_reg = 0x180,
    trigger_mode_1_reg = 0x190,
    trigger_mode_2_reg = 0x1A0,
    trigger_mode_3_reg = 0x1B0,
    trigger_mode_4_reg = 0x1C0,
    trigger_mode_5_reg = 0x1D0,
    trigger_mode_6_reg = 0x1E0,
    trigger_mode_7_reg = 0x1F0,
    int_request_0_reg = 0x200,
    int_request_1_reg = 0x210,
    int_request_2_reg = 0x220,
    int_request_3_reg = 0x230,
    int_request_4_reg = 0x240,
    int_request_5_reg = 0x250,
    int_request_6_reg = 0x260,
    int_request_7_reg = 0x270,
    err_status_reg = 0x280,
    lvt_corrected_machine_check_int_reg = 0x2F0,
    int_cmd_low_reg = 0x300,
    int_cmd_high_reg = 0x310,
    lvt_timer_reg = 0x320,
    lvt_thermal_sensor_reg = 0x330,
    lvt_perf_monitoring_counters_reg = 0x340,
    lvt_lint0_reg = 0x350,
    lvt_lint1_reg = 0x360,
    lvt_err_reg = 0x370,
    init_count_reg = 0x380,
    curr_count_reg = 0x390,
    div_config_reg = 0x3E0,
};

pub const LapicID = packed struct(u32) {
    _res0: u24 = 0,
    apic_id: u8,
};

pub const LapicVersion = packed struct(u32) {
    version: u8,
    _res0: u8 = 0,
    max_lvt_entry: u8,
    eoi_broadcast_suppression_support: bool,
    _res1: u7 = 0,
};

pub const TaskPrio = packed struct(u32) {
    subclass: u4,
    class: u4,
    _res: u24 = 0,
};

pub const ArbitrationPrio = packed struct(u32) {
    subclass: u4,
    class: u4,
    _res: u24 = 0,
};

pub const ProcessorPrio = packed struct(u32) {
    subclass: u4,
    class: u4,
    _res: u24 = 0,
};

pub const EOI = packed struct(u32) { eoi: u32 };

pub const RemoteRead = packed struct(u32) { val: u32 };

pub const LogicalDest = packed struct(u32) {
    _res: u24 = 0,
    logical_apic_id: u8,
};

pub const DestFmt = packed struct(u32) {
    _res: u28 = 0x0FFFFFFF,
    model: u4,
};

pub const SpuriousIntVec = packed struct(u32) {
    spurious_vector: u8,
    apic_enable: bool,
    focus_check_disable: bool,
    _res0: u2,
    eoi_bcast_supp: bool,
    _res1: u19,
};

pub const InService0 = packed struct(u32) { bits: u32 };
pub const InService1 = packed struct(u32) { bits: u32 };
pub const InService2 = packed struct(u32) { bits: u32 };
pub const InService3 = packed struct(u32) { bits: u32 };
pub const InService4 = packed struct(u32) { bits: u32 };
pub const InService5 = packed struct(u32) { bits: u32 };
pub const InService6 = packed struct(u32) { bits: u32 };
pub const InService7 = packed struct(u32) { bits: u32 };

pub const TriggerMode0 = packed struct(u32) { bits: u32 };
pub const TriggerMode1 = packed struct(u32) { bits: u32 };
pub const TriggerMode2 = packed struct(u32) { bits: u32 };
pub const TriggerMode3 = packed struct(u32) { bits: u32 };
pub const TriggerMode4 = packed struct(u32) { bits: u32 };
pub const TriggerMode5 = packed struct(u32) { bits: u32 };
pub const TriggerMode6 = packed struct(u32) { bits: u32 };
pub const TriggerMode7 = packed struct(u32) { bits: u32 };

pub const IntRequest0 = packed struct(u32) { bits: u32 };
pub const IntRequest1 = packed struct(u32) { bits: u32 };
pub const IntRequest2 = packed struct(u32) { bits: u32 };
pub const IntRequest3 = packed struct(u32) { bits: u32 };
pub const IntRequest4 = packed struct(u32) { bits: u32 };
pub const IntRequest5 = packed struct(u32) { bits: u32 };
pub const IntRequest6 = packed struct(u32) { bits: u32 };
pub const IntRequest7 = packed struct(u32) { bits: u32 };

pub const ErrStatus = packed struct(u32) { err: u32 };

pub const LvtCorrectedMachineCheckInt = packed struct(u32) {
    vector: u8,
    delivery_mode: u3,
    _res0: u1,
    delivery_status: bool,
    _res1: u3,
    mask: bool,
    _res2: u15,
};

pub const IntCmdLow = packed struct(u32) {
    vector: u8,
    deliv_mode: u3,
    dest_mode_logical: bool,
    deliv_status: bool,
    _res0: u1,
    level_assert: bool,
    trigger_mode_level: bool,
    _res1: u1,
    dest_shorthand: u2,
    _res2: u1,
    _res3: u12,
};

pub const IntCmdHigh = packed struct(u32) {
    _res0: u24,
    destination: u8,
};

pub const LvtTimer = packed struct(u32) {
    vector: u8,
    _res0: u4,
    delivery_status: bool,
    _res1: u3,
    mask: bool,
    timer_mode: u2,
    _res2: u13,
};

pub const LvtThermalSensor = packed struct(u32) {
    vector: u8,
    delivery_mode: u3,
    _res0: u1,
    delivery_status: bool,
    _res1: u3,
    mask: bool,
    _res2: u15,
};

pub const LvtPerfMonitoringCounters = packed struct(u32) {
    vector: u8,
    delivery_mode: u3,
    _res0: u1,
    delivery_status: bool,
    _res1: u3,
    mask: bool,
    _res2: u15,
};

pub const LvtLint0 = packed struct(u32) {
    vector: u8,
    delivery_mode: u3,
    _res0: u1,
    delivery_status: bool,
    polarity_low: bool,
    remote_irr: bool,
    trigger_mode_level: bool,
    mask: bool,
    _res1: u15,
};

pub const LvtLint1 = packed struct(u32) {
    vector: u8,
    delivery_mode: u3,
    _res0: u1,
    delivery_status: bool,
    polarity_low: bool,
    remote_irr: bool,
    trigger_mode_level: bool,
    mask: bool,
    _res1: u15,
};

pub const LvtErr = packed struct(u32) {
    vector: u8,
    _res0: u3,
    _res1: u1,
    delivery_status: bool,
    _res2: u3,
    mask: bool,
    _res3: u15,
};

pub const InitCount = packed struct(u32) {
    val: u32,
};

pub const CurrCount = packed struct(u32) {
    val: u32,
};

pub const DivConfig = packed struct(u32) {
    div0: u1,
    div1: u1,
    _res0: u1,
    div3: u1,
    _res1: u28,
};

pub const tsc_deadline_msr: u32 = 0x6e0;

pub var lapic_id: *volatile LapicID = undefined;
pub var lapic_version: *const volatile LapicVersion = undefined;
pub var task_prio: *volatile TaskPrio = undefined;
pub var arbitration_prio: *const volatile ArbitrationPrio = undefined;
pub var processor_prio: *const volatile ProcessorPrio = undefined;
pub var eoi: *volatile EOI = undefined;
pub var remote_read: *const volatile RemoteRead = undefined;
pub var logical_dest: *volatile LogicalDest = undefined;
pub var dest_fmt: *volatile DestFmt = undefined;
pub var spurious_int_vec: *volatile SpuriousIntVec = undefined;

pub var in_service_0: *const volatile InService0 = undefined;
pub var in_service_1: *const volatile InService1 = undefined;
pub var in_service_2: *const volatile InService2 = undefined;
pub var in_service_3: *const volatile InService3 = undefined;
pub var in_service_4: *const volatile InService4 = undefined;
pub var in_service_5: *const volatile InService5 = undefined;
pub var in_service_6: *const volatile InService6 = undefined;
pub var in_service_7: *const volatile InService7 = undefined;

pub var trigger_mode_0: *const volatile TriggerMode0 = undefined;
pub var trigger_mode_1: *const volatile TriggerMode1 = undefined;
pub var trigger_mode_2: *const volatile TriggerMode2 = undefined;
pub var trigger_mode_3: *const volatile TriggerMode3 = undefined;
pub var trigger_mode_4: *const volatile TriggerMode4 = undefined;
pub var trigger_mode_5: *const volatile TriggerMode5 = undefined;
pub var trigger_mode_6: *const volatile TriggerMode6 = undefined;
pub var trigger_mode_7: *const volatile TriggerMode7 = undefined;

pub var int_request_0: *const volatile IntRequest0 = undefined;
pub var int_request_1: *const volatile IntRequest1 = undefined;
pub var int_request_2: *const volatile IntRequest2 = undefined;
pub var int_request_3: *const volatile IntRequest3 = undefined;
pub var int_request_4: *const volatile IntRequest4 = undefined;
pub var int_request_5: *const volatile IntRequest5 = undefined;
pub var int_request_6: *const volatile IntRequest6 = undefined;
pub var int_request_7: *const volatile IntRequest7 = undefined;

pub var err_status: *volatile ErrStatus = undefined;

pub var lvt_corrected_machine_check_int: *volatile LvtCorrectedMachineCheckInt = undefined;
pub var int_cmd_low: *volatile IntCmdLow = undefined;
pub var int_cmd_high: *volatile IntCmdHigh = undefined;
pub var lvt_timer: *volatile LvtTimer = undefined;
pub var lvt_thermal_sensor: *volatile LvtThermalSensor = undefined;
pub var lvt_perf_monitoring_counters: *volatile LvtPerfMonitoringCounters = undefined;
pub var lvt_lint0: *volatile LvtLint0 = undefined;
pub var lvt_lint1: *volatile LvtLint1 = undefined;
pub var lvt_err: *volatile LvtErr = undefined;

pub var init_count: *volatile InitCount = undefined;
pub var curr_count: *const volatile CurrCount = undefined;
pub var div_config: *volatile DivConfig = undefined;

pub var x2Apic: bool = false;

pub const LVT_MASK_BIT: u6 = 16;
pub const LVT_MODE_SHIFT: u6 = 17;
pub const LVT_MODE_ONE_SHOT: u2 = 0;

/// Arms the LAPIC TSC-deadline timer by writing `deadline_tsc` to `IA32_TSC_DEADLINE`.
///
/// Arguments:
/// - `deadline_tsc`: absolute TSC value at which the timer interrupt should fire.
pub fn armTscDeadline(deadline_tsc: u64) void {
    cpu.wrmsr(tsc_deadline_msr, deadline_tsc);
}

/// Cancels any pending TSC-deadline interrupt by writing zero to `IA32_TSC_DEADLINE`.
pub fn cancelTscDeadline() void {
    cpu.wrmsr(tsc_deadline_msr, 0);
}

/// Disables the legacy 8259 PICs by masking all interrupts on both controllers.
pub fn disablePic() void {
    cpu.outb(0xFF, 0x21);
    cpu.outb(0xFF, 0xA1);
}

/// Signals End-Of-Interrupt (EOI) to the local APIC.
pub fn endOfInterrupt() void {
    if (x2Apic) {
        eoi.eoi = 0;
    } else {
        cpu.wrmsr(@intFromEnum(X2ApicMsr.end_of_interrupt_register), 0);
    }
}

/// Programs the LAPIC timer into TSC-deadline mode and sets the interrupt vector.
///
/// Arguments:
/// - `vector`: interrupt vector (0–255) to be delivered when the deadline expires.
///
/// Errors:
/// - `TscDeadlineNotSupported`: CPU lacks x2APIC TSC-deadline capability.
/// - `InvariantTscNotSupported`: CPU lacks invariant/constant TSC guarantees.
pub fn programLocalApicTimerTscDeadline(vector: u8) !void {
    const feat = cpu.cpuid(.basic_features, 0);
    if (!cpu.hasFeatureEcx(feat.ecx, .tsc_deadline)) {
        return error.TscDeadlineNotSupported;
    }

    const max_ext = cpu.cpuid(.ext_max, 0).eax;
    if (max_ext < @intFromEnum(cpu.CpuidLeaf.ext_max)) {
        return error.InvariantTscNotSupported;
    }

    const pwr = cpu.cpuid(.ext_power, 0);
    if (!cpu.hasPowerFeatureEdx(pwr.edx, .constant_tsc)) {
        return error.InvariantTscNotSupported;
    }

    const TIMER_MODE_LSB: u6 = 17;
    const TSC_DEADLINE: u2 = 0b10;

    var lvt: u64 = vector;
    lvt |= (@as(u64, TSC_DEADLINE) << TIMER_MODE_LSB);
    cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), lvt);
}

pub fn init(lapic_base_virt: VAddr) void {
    disablePic();

    if (cpu.enableX2Apic(@intFromEnum(idt.IntVectors.spurious))) |_| {
        x2Apic = false;
        return;
    } else |_| {
        x2Apic = true;
    }

    const base_addr = lapic_base_virt.addr;

    lapic_id = @ptrFromInt(base_addr + @intFromEnum(Register.lapic_id_reg));
    lapic_version = @ptrFromInt(base_addr + @intFromEnum(Register.lapic_version_reg));
    task_prio = @ptrFromInt(base_addr + @intFromEnum(Register.task_prio_reg));
    arbitration_prio = @ptrFromInt(base_addr + @intFromEnum(Register.arbitration_prio_reg));
    processor_prio = @ptrFromInt(base_addr + @intFromEnum(Register.processor_prio_reg));
    eoi = @ptrFromInt(base_addr + @intFromEnum(Register.eoi_reg));
    remote_read = @ptrFromInt(base_addr + @intFromEnum(Register.remote_read_reg));
    logical_dest = @ptrFromInt(base_addr + @intFromEnum(Register.logical_dest_reg));
    dest_fmt = @ptrFromInt(base_addr + @intFromEnum(Register.dest_fmt_reg));
    spurious_int_vec = @ptrFromInt(base_addr + @intFromEnum(Register.spurious_int_vec_reg));

    in_service_0 = @ptrFromInt(base_addr + @intFromEnum(Register.in_service_0_reg));
    in_service_1 = @ptrFromInt(base_addr + @intFromEnum(Register.in_service_1_reg));
    in_service_2 = @ptrFromInt(base_addr + @intFromEnum(Register.in_service_2_reg));
    in_service_3 = @ptrFromInt(base_addr + @intFromEnum(Register.in_service_3_reg));
    in_service_4 = @ptrFromInt(base_addr + @intFromEnum(Register.in_service_4_reg));
    in_service_5 = @ptrFromInt(base_addr + @intFromEnum(Register.in_service_5_reg));
    in_service_6 = @ptrFromInt(base_addr + @intFromEnum(Register.in_service_6_reg));
    in_service_7 = @ptrFromInt(base_addr + @intFromEnum(Register.in_service_7_reg));

    trigger_mode_0 = @ptrFromInt(base_addr + @intFromEnum(Register.trigger_mode_0_reg));
    trigger_mode_1 = @ptrFromInt(base_addr + @intFromEnum(Register.trigger_mode_1_reg));
    trigger_mode_2 = @ptrFromInt(base_addr + @intFromEnum(Register.trigger_mode_2_reg));
    trigger_mode_3 = @ptrFromInt(base_addr + @intFromEnum(Register.trigger_mode_3_reg));
    trigger_mode_4 = @ptrFromInt(base_addr + @intFromEnum(Register.trigger_mode_4_reg));
    trigger_mode_5 = @ptrFromInt(base_addr + @intFromEnum(Register.trigger_mode_5_reg));
    trigger_mode_6 = @ptrFromInt(base_addr + @intFromEnum(Register.trigger_mode_6_reg));
    trigger_mode_7 = @ptrFromInt(base_addr + @intFromEnum(Register.trigger_mode_7_reg));

    int_request_0 = @ptrFromInt(base_addr + @intFromEnum(Register.int_request_0_reg));
    int_request_1 = @ptrFromInt(base_addr + @intFromEnum(Register.int_request_1_reg));
    int_request_2 = @ptrFromInt(base_addr + @intFromEnum(Register.int_request_2_reg));
    int_request_3 = @ptrFromInt(base_addr + @intFromEnum(Register.int_request_3_reg));
    int_request_4 = @ptrFromInt(base_addr + @intFromEnum(Register.int_request_4_reg));
    int_request_5 = @ptrFromInt(base_addr + @intFromEnum(Register.int_request_5_reg));
    int_request_6 = @ptrFromInt(base_addr + @intFromEnum(Register.int_request_6_reg));
    int_request_7 = @ptrFromInt(base_addr + @intFromEnum(Register.int_request_7_reg));

    err_status = @ptrFromInt(base_addr + @intFromEnum(Register.err_status_reg));

    lvt_corrected_machine_check_int = @ptrFromInt(base_addr + @intFromEnum(Register.lvt_corrected_machine_check_int_reg));
    int_cmd_low = @ptrFromInt(base_addr + @intFromEnum(Register.int_cmd_low_reg));
    int_cmd_high = @ptrFromInt(base_addr + @intFromEnum(Register.int_cmd_high_reg));
    lvt_timer = @ptrFromInt(base_addr + @intFromEnum(Register.lvt_timer_reg));
    lvt_thermal_sensor = @ptrFromInt(base_addr + @intFromEnum(Register.lvt_thermal_sensor_reg));
    lvt_perf_monitoring_counters = @ptrFromInt(base_addr + @intFromEnum(Register.lvt_perf_monitoring_counters_reg));
    lvt_lint0 = @ptrFromInt(base_addr + @intFromEnum(Register.lvt_lint0_reg));
    lvt_lint1 = @ptrFromInt(base_addr + @intFromEnum(Register.lvt_lint1_reg));
    lvt_err = @ptrFromInt(base_addr + @intFromEnum(Register.lvt_err_reg));

    init_count = @ptrFromInt(base_addr + @intFromEnum(Register.init_count_reg));
    curr_count = @ptrFromInt(base_addr + @intFromEnum(Register.curr_count_reg));
    div_config = @ptrFromInt(base_addr + @intFromEnum(Register.div_config_reg));
}

pub fn initLapicTimer(div_code: u32, vector: u8, masked: bool) void {
    if (x2Apic) {
        const d: DivConfig = .{
            .div0 = @intCast(div_code & 0b001),
            .div1 = @intCast((div_code >> 1) & 0b001),
            ._res0 = 0,
            .div3 = @intCast((div_code >> 3) & 0b001),
            ._res1 = 0,
        };
        div_config.* = d;

        const l: LvtTimer = .{
            .vector = vector,
            ._res0 = 0,
            .delivery_status = false,
            ._res1 = 0,
            .mask = masked,
            .timer_mode = LVT_MODE_ONE_SHOT,
            ._res2 = 0,
        };
        lvt_timer.* = l;
    } else {
        const m: u64 = vector | (@as(u64, LVT_MODE_ONE_SHOT) << LVT_MODE_SHIFT) | (@as(u64, @intFromBool(masked)) << LVT_MASK_BIT);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.timer_divide_configuration_register), div_code);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), m);
    }
}

pub fn armLapicOneShot(ticks: u32, vector: u8) void {
    if (x2Apic) {
        const l: LvtTimer = .{
            .vector = vector,
            ._res0 = 0,
            .delivery_status = false,
            ._res1 = 0,
            .mask = false,
            .timer_mode = LVT_MODE_ONE_SHOT,
            ._res2 = 0,
        };
        lvt_timer.* = l;
        init_count.* = .{ .val = ticks };
    } else {
        const m: u64 = vector | (@as(u64, LVT_MODE_ONE_SHOT) << LVT_MODE_SHIFT);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), m);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.timer_initial_count_register), ticks);
    }
}
