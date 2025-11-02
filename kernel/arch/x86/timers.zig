const paging = @import("paging.zig");

const VAddr = paging.VAddr;

pub const Hpet = packed struct {
    pub const GenCapsAndId = packed struct(u64) {
        revision_id: u8,
        num_timers: u5,
        counter_64_bit: bool,
        _res: u1 = 0,
        legacy_mapping_cap: bool,
        vendor_id: u16,
        counter_clock_period: u32,
    };

    pub const GenConfig = packed struct(u64) {
        enable: bool,
        legacy_mapping: bool,
        _res: u62 = 0,
    };

    pub const GenIntStatus = packed struct(u64) {
        level_triggered_timer_active: bool, // ignore if interrupt is edge triggered
        _res: u63 = 0,
    };

    pub const MainCounterVal = packed struct(u64) {
        val: u64,
    };

    pub const NthTimerConfigAndCaps = packed struct(u64) {
        _res0: u1 = 0,
        interrupt_level_triggered: bool,
        interrupt_enabled: bool,
        periodic_enabled: bool,
        periodic_supported: bool,
        comparator_64bit: bool,
        periodic_accumulator_set: bool,
        _res7: u1 = 0,
        force_32bit_mode: bool,
        ioapic_route_index: u5,
        fsb_delivery_enabled: bool,
        fsb_delivery_supported: bool,
        _res16_31: u16 = 0,
        ioapic_route_capabilities: u32,
    };

    pub const NthTimerComparatorVal = packed struct(u64) {
        comparator_value: u64,
    };

    pub const NthTimerFSBIntRoute = packed struct(u64) {
        message_address: u32,
        message_data: u32,
    };

    pub const Register = enum(u64) {
        gen_caps_and_id = 0x0,
        gen_config = 0x10,
        gen_int_status = 0x20,
        main_counter_val = 0xF0,
        nth_timer_config_and_caps = 0x100,
        nth_timer_comparator_val = 0x108,
        nth_timer_fsb_int_route = 0x110,
    };
    const nth_timer_offset = 0x20;

    gen_caps_and_id: *const volatile GenCapsAndId,
    gen_config: *volatile GenConfig,
    gen_int_status: *volatile GenIntStatus,
    main_counter_val: *volatile MainCounterVal,

    nth_timer_config_and_caps_base: [*]volatile NthTimerConfigAndCaps,
    nth_timer_comparator_val_base: [*]volatile NthTimerComparatorVal,
    nth_timer_fsb_int_route_base: [*]volatile NthTimerFSBIntRoute,

    pub fn init(base_virt: VAddr) Hpet {
        const base_addr = base_virt.addr;
        return .{
            .gen_caps_and_id = @ptrFromInt(base_addr + @intFromEnum(Register.gen_caps_and_id)),
            .gen_config = @ptrFromInt(base_addr + @intFromEnum(Register.gen_config)),
            .gen_int_status = @ptrFromInt(base_addr + @intFromEnum(Register.gen_int_status)),
            .main_counter_val = @ptrFromInt(base_addr + @intFromEnum(Register.main_counter_val)),

            .nth_timer_config_and_caps_base = @ptrFromInt(base_addr + @intFromEnum(Register.nth_timer_config_and_caps)),
            .nth_timer_comparator_val_base = @ptrFromInt(base_addr + @intFromEnum(Register.nth_timer_comparator_val)),
            .nth_timer_fsb_int_route_base = @ptrFromInt(base_addr + @intFromEnum(Register.nth_timer_fsb_int_route)),
        };
    }

    pub fn getNthTimerConfigAndCaps(self: *Hpet, n: usize) *volatile NthTimerConfigAndCaps {
        return @ptrFromInt(@intFromPtr(self.nth_timer_config_and_caps_base) + n * nth_timer_offset);
    }

    pub fn getNthTimerComparatorVal(self: *Hpet, n: usize) *volatile NthTimerComparatorVal {
        return @ptrFromInt(@intFromPtr(self.nth_timer_comparator_val_base) + n * nth_timer_offset);
    }

    pub fn getNthTimerFSBIntRoute(self: *Hpet, n: usize) *volatile NthTimerFSBIntRoute {
        return @ptrFromInt(@intFromPtr(self.nth_timer_fsb_int_route_base) + n * nth_timer_offset);
    }
};
