const cpu = @import("cpu.zig");
const paging = @import("paging.zig");

const VAddr = paging.VAddr;

pub const VTable = struct {
    now: *const fn (*anyopaque) u64,
};

pub const Timer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub fn now(self: *const Timer) u64 {
        return self.vtable.now(self.ptr);
    }
};

pub const Hpet = struct {
    pub const GenCapsAndId = packed struct(u64) {
        revision_id: u8,
        num_timers_minus_one: u5,
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
        comparator_val: u64,
    };

    pub const NthTimerFSBIntRoute = packed struct(u64) {
        message_address: u32,
        message_data: u32,
    };

    pub const HpetTimer = struct {
        config_and_caps: *volatile NthTimerConfigAndCaps,
        comparator_val: *volatile NthTimerComparatorVal,
        fsb_int_route: *volatile NthTimerFSBIntRoute,

        pub fn init(
            config_and_caps: *volatile NthTimerConfigAndCaps,
            comparator_val: *volatile NthTimerComparatorVal,
            fsb_int_route: *volatile NthTimerFSBIntRoute,
        ) HpetTimer {
            return .{
                .config_and_caps = config_and_caps,
                .comparator_val = comparator_val,
                .fsb_int_route = fsb_int_route,
            };
        }
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

    freq_hz: u64,

    gen_caps_and_id: *const volatile GenCapsAndId,
    gen_config: *volatile GenConfig,
    gen_int_status: *volatile GenIntStatus,
    main_counter_val: *volatile MainCounterVal,

    nth_timer_config_and_caps_base: [*]volatile NthTimerConfigAndCaps,
    nth_timer_comparator_val_base: [*]volatile NthTimerComparatorVal,
    nth_timer_fsb_int_route_base: [*]volatile NthTimerFSBIntRoute,

    pub fn init(base_virt: VAddr) Hpet {
        const base_addr = base_virt.addr;
        const gen_caps_and_id: *const volatile GenCapsAndId = @ptrFromInt(
            base_addr + @intFromEnum(Register.gen_caps_and_id),
        );
        return .{
            .freq_hz = 1_000_000_000_000_000 / @as(u64, gen_caps_and_id.counter_clock_period),

            .gen_caps_and_id = gen_caps_and_id,
            .gen_config = @ptrFromInt(
                base_addr + @intFromEnum(Register.gen_config),
            ),
            .gen_int_status = @ptrFromInt(
                base_addr + @intFromEnum(Register.gen_int_status),
            ),
            .main_counter_val = @ptrFromInt(
                base_addr + @intFromEnum(Register.main_counter_val),
            ),

            .nth_timer_config_and_caps_base = @ptrFromInt(
                base_addr + @intFromEnum(Register.nth_timer_config_and_caps),
            ),
            .nth_timer_comparator_val_base = @ptrFromInt(
                base_addr + @intFromEnum(Register.nth_timer_comparator_val),
            ),
            .nth_timer_fsb_int_route_base = @ptrFromInt(
                base_addr + @intFromEnum(Register.nth_timer_fsb_int_route),
            ),
        };
    }

    pub fn getNthTimer(self: *Hpet, n: u64) HpetTimer {
        if (n > self.gen_caps_and_id.num_timers_minus_one) {
            @panic("Tried to select non-existent hpet timer!");
        }
        return HpetTimer.init(
            self.getNthTimerConfigAndCaps(n),
            self.getNthTimerComparatorVal(n),
            self.getNthTimerFSBIntRoute(n),
        );
    }

    fn getNthTimerConfigAndCaps(self: *Hpet, n: u64) *volatile NthTimerConfigAndCaps {
        return @ptrFromInt(
            @intFromPtr(self.nth_timer_config_and_caps_base) + n * nth_timer_offset,
        );
    }

    fn getNthTimerComparatorVal(self: *Hpet, n: u64) *volatile NthTimerComparatorVal {
        return @ptrFromInt(
            @intFromPtr(self.nth_timer_comparator_val_base) + n * nth_timer_offset,
        );
    }

    fn getNthTimerFSBIntRoute(self: *Hpet, n: u64) *volatile NthTimerFSBIntRoute {
        return @ptrFromInt(
            @intFromPtr(self.nth_timer_fsb_int_route_base) + n * nth_timer_offset,
        );
    }

    pub fn timer(self: *Hpet) Timer {
        if (!self.gen_config.enable) {
            self.gen_config.enable = true;
        }
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
            },
        };
    }

    fn now(ctx: *anyopaque) u64 {
        const self: *Hpet = @alignCast(@ptrCast(ctx));
        return nanosFromTicksFloor(self.freq_hz, self.main_counter_val.val);
    }
};

const ONE_BILLION_NS = 1_000_000_000;
const TEN_MILLION_NS = 10_000_000;

pub const Tsc = struct {
    freq_hz: u64,

    pub fn init(hpet: *Hpet) Tsc {
        const hpet_iface = hpet.timer();

        var estimate: u64 = 0;

        for (0..3) |i| {
            const target_ns = TEN_MILLION_NS; // ~10ms

            const tsc_start = cpu.rdtsc_lfenced();
            const hpet_start_ns = hpet_iface.now();

            var now_ns = hpet_start_ns;
            while ((now_ns - hpet_start_ns) < target_ns) {
                now_ns = hpet_iface.now();
            }

            const hpet_end_ns = hpet_iface.now();
            const tsc_end = cpu.rdtscp_lfenced();

            const delta_tsc = tsc_end - tsc_start;
            const delta_hpet_ns = hpet_end_ns - hpet_start_ns;

            const sample_hz = (delta_tsc * ONE_BILLION_NS) / delta_hpet_ns;

            estimate = if (i == 0) sample_hz else (estimate + sample_hz) / 2;
        }

        return .{
            .freq_hz = estimate,
        };
    }

    pub fn timer(self: *Tsc) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
            },
        };
    }

    fn now(ctx: *anyopaque) u64 {
        const self: *Tsc = @alignCast(@ptrCast(ctx));
        return nanosFromTicksFloor(self.freq_hz, cpu.rdtscp());
    }
};

pub fn ticksFromNanosFloor(freq_hz: u64, ns: u64) u64 {
    return (freq_hz * ns) / ONE_BILLION_NS;
}

pub fn ticksFromNanosCeil(freq_hz: u64, ns: u64) u64 {
    return (freq_hz * ns + ONE_BILLION_NS - 1) / ONE_BILLION_NS;
}

pub fn nanosFromTicksFloor(freq_hz: u64, ticks: u64) u64 {
    return (ticks * ONE_BILLION_NS) / freq_hz;
}

pub fn nanosFromTicksCeil(freq_hz: u64, ticks: u64) u64 {
    return (ticks * ONE_BILLION_NS + freq_hz - 1) / freq_hz;
}
