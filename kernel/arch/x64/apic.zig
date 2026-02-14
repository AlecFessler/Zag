const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const cpu = zag.arch.x64.cpu;
const interrupts = zag.arch.x64.interrupts;
const paging = zag.arch.x64.paging;

const LocalApic = zag.arch.x64.acpi.LocalApic;
const VAddr = zag.memory.address.VAddr;

// ── Register offsets (xAPIC MMIO) ────────────────────────────────

pub const Register = enum(u32) {
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

// ── x2APIC MSR addresses ────────────────────────────────────────

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

// ── Packed struct types (used only for @bitCast, never via pointer deref) ──

pub const LvtTimer = packed struct(u32) {
    vector: u8,
    _res0: u4 = 0,
    delivery_status: bool,
    _res1: u3 = 0,
    mask: bool,
    timer_mode: u2,
    _res2: u13 = 0,
};

pub const SpuriousIntVec = packed struct(u32) {
    spurious_vector: u8,
    apic_enable: bool,
    focus_check_disable: bool,
    _res0: u2 = 0,
    eoi_bcast_supp: bool,
    _res1: u19 = 0,
};

pub const DivConfig = packed struct(u32) {
    div0: u1,
    div1: u1,
    _res0: u1 = 0,
    div3: u1,
    _res1: u28 = 0,
};

// ── Constants ────────────────────────────────────────────────────

pub const LVT_MASK_BIT: u6 = 16;
pub const LVT_MODE_SHIFT: u6 = 17;
pub const LVT_MODE_ONE_SHOT: u2 = 0;

pub const tsc_deadline_msr: u32 = 0x6e0;

// ── State ────────────────────────────────────────────────────────

var lapic_base: u64 = 0;
pub var x2Apic: bool = false;
pub var lapics: ?[]LocalApic = null;

// ── Raw MMIO helpers (always 32-bit aligned access) ─────────────

pub fn readReg(reg: Register) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(lapic_base + @intFromEnum(reg));
    return ptr.*;
}

pub fn writeReg(reg: Register, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(lapic_base + @intFromEnum(reg));
    ptr.* = val;
}

// ── Public API ───────────────────────────────────────────────────

pub fn armTscDeadline(deadline_tsc: u64) void {
    cpu.wrmsr(tsc_deadline_msr, deadline_tsc);
}

pub fn cancelTscDeadline() void {
    cpu.wrmsr(tsc_deadline_msr, 0);
}

pub fn endOfInterrupt() void {
    if (x2Apic) {
        cpu.wrmsr(@intFromEnum(X2ApicMsr.end_of_interrupt_register), 0);
    } else {
        writeReg(.eoi_reg, 0);
    }
}

pub fn programLocalApicTimerTscDeadline(vector: u8) bool {
    const feat = cpu.cpuid(.basic_features, 0);
    if (!cpu.hasFeatureEcx(feat.ecx, .tsc_deadline)) return false;

    const max_ext = cpu.cpuid(.ext_max, 0).eax;
    if (max_ext < @intFromEnum(cpu.CpuidLeaf.ext_max)) return false;

    const pwr = cpu.cpuid(.ext_power, 0);
    if (!cpu.hasPowerFeatureEdx(pwr.edx, .constant_tsc)) return false;

    const TIMER_MODE_LSB: u6 = 17;
    const TSC_DEADLINE: u2 = 0b10;

    var lvt: u64 = vector;
    lvt |= (@as(u64, TSC_DEADLINE) << TIMER_MODE_LSB);
    cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), lvt);

    return true;
}

pub fn init(lapic_base_virt: VAddr) void {
    // disable PIC
    cpu.outb(0xFF, 0x21);
    cpu.outb(0xFF, 0xA1);

    x2Apic = cpu.enableX2Apic(@intFromEnum(interrupts.IntVecs.spurious));
    if (x2Apic) return;

    lapic_base = lapic_base_virt.addr;
}

pub fn initLapicTimer(div_code: u32, vector: u8, masked: bool) void {
    if (x2Apic) {
        const m: u64 =
            vector | (@as(u64, LVT_MODE_ONE_SHOT) << LVT_MODE_SHIFT) | (@as(u64, @intFromBool(masked)) << LVT_MASK_BIT);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.timer_divide_configuration_register), div_code);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), m);
    } else {
        const d: DivConfig = .{
            .div0 = @intCast(div_code & 0b001),
            .div1 = @intCast((div_code >> 1) & 0b001),
            .div3 = @intCast((div_code >> 3) & 0b001),
        };
        writeReg(.div_config_reg, @bitCast(d));

        const l: LvtTimer = .{
            .vector = vector,
            .delivery_status = false,
            .mask = masked,
            .timer_mode = LVT_MODE_ONE_SHOT,
        };
        writeReg(.lvt_timer_reg, @bitCast(l));
    }
}

pub fn armLapicOneShot(ticks: u32, vector: u8) void {
    if (x2Apic) {
        const m: u64 = vector | (@as(u64, LVT_MODE_ONE_SHOT) << LVT_MODE_SHIFT);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.local_vector_table_timer_register), m);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.timer_initial_count_register), ticks);
    } else {
        const l: LvtTimer = .{
            .vector = vector,
            .delivery_status = false,
            .mask = false,
            .timer_mode = LVT_MODE_ONE_SHOT,
        };
        writeReg(.lvt_timer_reg, @bitCast(l));
        writeReg(.init_count_reg, ticks);
    }
}

pub fn coreCount() u64 {
    return lapics.?.len;
}

pub fn rawApicId() u32 {
    if (x2Apic) {
        return @intCast(cpu.rdmsr(@intFromEnum(X2ApicMsr.local_apic_id_register)));
    } else {
        return (readReg(.lapic_id_reg) >> 24) & 0xFF;
    }
}

pub fn coreID() u64 {
    const raw = rawApicId();
    for (lapics.?, 0..) |la, i| {
        if (la.apic_id == raw) return i;
    }
    unreachable;
}

pub fn waitForDelivery() void {
    if (x2Apic) return;
    while (readReg(.int_cmd_low_reg) & (1 << 12) != 0) {
        std.atomic.spinLoopHint();
    }
}

pub fn sendInitIpi(apic_id_target: u8) void {
    if (x2Apic) {
        const icr: u64 = (@as(u64, apic_id_target) << 32) | (0b101 << 8) | (1 << 14) | (1 << 15);
        cpu.wrmsr(@intFromEnum(X2ApicMsr.interrupt_command_register), icr);
    } else {
        writeReg(.int_cmd_high_reg, @as(u32, apic_id_target) << 24);
        writeReg(.int_cmd_low_reg, (0b101 << 8) | (1 << 14) | (1 << 15));
        waitForDelivery();
    }
}

pub fn sendSipi(apic_id_target: u8, vector: u8) void {
    if (x2Apic) {
        const icr: u64 = (@as(u64, apic_id_target) << 32) | (0b110 << 8) | vector;
        cpu.wrmsr(@intFromEnum(X2ApicMsr.interrupt_command_register), icr);
    } else {
        writeReg(.int_cmd_high_reg, @as(u32, apic_id_target) << 24);
        writeReg(.int_cmd_low_reg, (0b110 << 8) | @as(u32, vector));
        waitForDelivery();
    }
}

pub fn sendSelfIpi(vector: u8) void {
    if (x2Apic) {
        cpu.wrmsr(@intFromEnum(X2ApicMsr.self_interrupt_register), vector);
    } else {
        writeReg(.int_cmd_high_reg, 0);
        writeReg(.int_cmd_low_reg, @as(u32, vector) | (1 << 18));
    }
}

pub fn enableSpuriousVector(vector: u8) void {
    if (x2Apic) {
        _ = cpu.enableX2Apic(vector);
    } else {
        const svr: SpuriousIntVec = .{
            .spurious_vector = vector,
            .apic_enable = true,
            .focus_check_disable = false,
            .eoi_bcast_supp = false,
        };
        writeReg(.spurious_int_vec_reg, @bitCast(svr));
    }
}
