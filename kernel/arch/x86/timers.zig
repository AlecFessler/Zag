//! HPET (High Precision Event Timer) registers, helpers, and time conversion utilities.
//!
//! Implements a memory-mapped HPET interface suitable for early kernel bring-up and
//! general timing facilities. Provides typed views over the HPET register block,
//! safe accessors for Nth timer/comparator/FSB routing triplets, adapters that
//! expose a generic `Timer` vtable (read time “now” in nanoseconds and arm an
//! interrupt deadline), a TSC (Time Stamp Counter) calibration helper using HPET,
//! and integer-safe tick↔nanoseconds conversion helpers.
//!
//! Designed to be freestanding with volatile-qualified register access and
//! no allocator requirements.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `Hpet` – memory-mapped HPET device with register pointers and helpers.
//! - `Hpet.GenCapsAndId` – capabilities/ID register layout (read-only).
//! - `Hpet.GenConfig` – general configuration register layout.
//! - `Hpet.GenIntStatus` – interrupt status register layout.
//! - `Hpet.MainCounterVal` – main counter value register layout.
//! - `Hpet.NthTimerConfigAndCaps` – per-timer configuration/capabilities layout.
//! - `Hpet.NthTimerComparatorVal` – per-timer comparator layout.
//! - `Hpet.NthTimerFSBIntRoute` – per-timer FSB interrupt routing layout.
//! - `Hpet.HpetTimer` – view over one HPET timer’s register triplet.
//! - `Hpet.Register` – symbolic offsets for the HPET register block.
//! - `Lapic` – local APIC one-shot timer calibrated via HPET; exposes a `Timer`.
//! - `Timer` – vtable-based timer interface (now/arm_interrupt_timer).
//! - `Tsc` – TSC frequency helper calibrated via HPET; exposes a `Timer`.
//! - `VTable` – function table used by `Timer` adapters.
//!
//! ## Constants
//! - `ONE_BILLION_NS` – 1e9 nanoseconds.
//! - `ONE_QUADRILLION_NS` – 1e15 nanoseconds.
//! - `TEN_MILLION_NS` – 10 ms in nanoseconds.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `Hpet.init` – construct an `Hpet` from a base virtual address.
//! - `Hpet.getNthTimer` – view the Nth timer triplet as an `HpetTimer`.
//! - `Hpet.timer` – expose the HPET as a generic `Timer`.
//! - `Hpet.getNthTimerConfigAndCaps` – internal pointer helper (Nth config).
//! - `Hpet.getNthTimerComparatorVal` – internal pointer helper (Nth comparator).
//! - `Hpet.getNthTimerFSBIntRoute` – internal pointer helper (Nth FSB route).
//! - `Hpet.arm_interrupt_timer` – HPET-backed arm hook for `Timer` (stub).
//! - `Hpet.now` – read HPET main counter → nanoseconds.
//! - `Lapic.init` – calibrate LAPIC timer and configure one-shot mode.
//! - `Lapic.timer` – expose the LAPIC as a generic `Timer`.
//! - `Tsc.init` – calibrate TSC frequency against HPET.
//! - `Tsc.timer` – expose the TSC as a generic `Timer`.
//! - `Tsc.arm_interrupt_timer` – compute TSC deadline and program `IA32_TSC_DEADLINE`.
//! - `Tsc.now` – read TSC → nanoseconds.
//! - `Timer.now` – return current time via vtable.
//! - `Timer.arm_interrupt_timer` – arm a deadline via vtable.
//! - `nanosFromTicksCeil` / `nanosFromTicksFloor` – ticks→ns.
//! - `ticksFromNanosCeil` / `ticksFromNanosFloor` – ns→ticks.

const apic = @import("apic.zig");
const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const paging = @import("paging.zig");

const VAddr = paging.VAddr;

/// Memory-mapped HPET device with register pointers and helpers.
pub const Hpet = struct {
    /// Capabilities/ID register layout (read-only).
    pub const GenCapsAndId = packed struct(u64) {
        revision_id: u8,
        num_timers_minus_one: u5,
        counter_64_bit: bool,
        _res: u1 = 0,
        legacy_mapping_cap: bool,
        vendor_id: u16,
        counter_clock_period: u32,
    };

    /// General configuration register layout.
    pub const GenConfig = packed struct(u64) {
        enable: bool,
        legacy_mapping: bool,
        _res: u62 = 0,
    };

    /// Interrupt status register layout.
    pub const GenIntStatus = packed struct(u64) {
        level_triggered_timer_active: bool,
        _res: u63 = 0,
    };

    /// Main counter value register layout.
    pub const MainCounterVal = packed struct(u64) {
        val: u64,
    };

    /// Per-timer configuration/capabilities register layout.
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

    /// Per-timer comparator register layout.
    pub const NthTimerComparatorVal = packed struct(u64) {
        comparator_val: u64,
    };

    /// Per-timer FSB interrupt routing register layout.
    pub const NthTimerFSBIntRoute = packed struct(u64) {
        message_address: u32,
        message_data: u32,
    };

    /// View over one HPET timer’s config/comparator/FSB route triplet.
    pub const HpetTimer = struct {
        config_and_caps: *volatile NthTimerConfigAndCaps,
        comparator_val: *volatile NthTimerComparatorVal,
        fsb_int_route: *volatile NthTimerFSBIntRoute,

        /// Summary:
        /// Construct an `HpetTimer` view from raw register pointers.
        ///
        /// Args:
        /// - `config_and_caps`: Pointer to the Nth timer config/caps register.
        /// - `comparator_val`: Pointer to the Nth timer comparator register.
        /// - `fsb_int_route`: Pointer to the Nth timer FSB route register.
        ///
        /// Returns:
        /// - `HpetTimer` newly constructed view.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
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

    /// Symbolic offsets for the HPET register block.
    pub const Register = enum(u64) {
        gen_caps_and_id = 0x0,
        gen_config = 0x10,
        gen_int_status = 0x20,
        main_counter_val = 0xF0,
        nth_timer_config_and_caps = 0x100,
        nth_timer_comparator_val = 0x108,
        nth_timer_fsb_int_route = 0x110,
    };

    /// Byte stride between adjacent Nth-timer register triplets.
    const nth_timer_offset = 0x20;

    freq_hz: u64,

    gen_caps_and_id: *const volatile GenCapsAndId,
    gen_config: *volatile GenConfig,
    gen_int_status: *volatile GenIntStatus,
    main_counter_val: *volatile MainCounterVal,

    nth_timer_config_and_caps_base: [*]volatile NthTimerConfigAndCaps,
    nth_timer_comparator_val_base: [*]volatile NthTimerComparatorVal,
    nth_timer_fsb_int_route_base: [*]volatile NthTimerFSBIntRoute,

    /// Summary:
    /// Construct an `Hpet` from a base virtual address of the HPET register block.
    ///
    /// Args:
    /// - `base_virt`: `VAddr` of the HPET MMIO base.
    ///
    /// Returns:
    /// - `Hpet` initialized with register pointers and derived frequency.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn init(base_virt: VAddr) Hpet {
        const base_addr = base_virt.addr;
        const gen_caps_and_id: *const volatile GenCapsAndId = @ptrFromInt(
            base_addr + @intFromEnum(Register.gen_caps_and_id),
        );
        return .{
            .freq_hz = ONE_QUADRILLION_NS / @as(u64, gen_caps_and_id.counter_clock_period),

            .gen_caps_and_id = gen_caps_and_id,
            .gen_config = @ptrFromInt(base_addr + @intFromEnum(Register.gen_config)),
            .gen_int_status = @ptrFromInt(base_addr + @intFromEnum(Register.gen_int_status)),
            .main_counter_val = @ptrFromInt(base_addr + @intFromEnum(Register.main_counter_val)),

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

    /// Summary:
    /// Return a view over the Nth timer’s config/comparator/FSB route registers.
    ///
    /// Args:
    /// - `n`: Zero-based timer index to select.
    ///
    /// Returns:
    /// - `HpetTimer` view for the requested timer.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Panics if `n` exceeds the implemented timer count.
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

    /// Summary:
    /// Internal helper to compute the pointer to the Nth timer’s config/caps register.
    ///
    /// Args:
    /// - `n`: Zero-based timer index.
    ///
    /// Returns:
    /// - `*volatile NthTimerConfigAndCaps` pointer.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn getNthTimerConfigAndCaps(self: *Hpet, n: u64) *volatile NthTimerConfigAndCaps {
        return @ptrFromInt(
            @intFromPtr(self.nth_timer_config_and_caps_base) + n * nth_timer_offset,
        );
    }

    /// Summary:
    /// Internal helper to compute the pointer to the Nth timer’s comparator register.
    ///
    /// Args:
    /// - `n`: Zero-based timer index.
    ///
    /// Returns:
    /// - `*volatile NthTimerComparatorVal` pointer.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn getNthTimerComparatorVal(self: *Hpet, n: u64) *volatile NthTimerComparatorVal {
        return @ptrFromInt(
            @intFromPtr(self.nth_timer_comparator_val_base) + n * nth_timer_offset,
        );
    }

    /// Summary:
    /// Internal helper to compute the pointer to the Nth timer’s FSB route register.
    ///
    /// Args:
    /// - `n`: Zero-based timer index.
    ///
    /// Returns:
    /// - `*volatile NthTimerFSBIntRoute` pointer.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn getNthTimerFSBIntRoute(self: *Hpet, n: u64) *volatile NthTimerFSBIntRoute {
        return @ptrFromInt(
            @intFromPtr(self.nth_timer_fsb_int_route_base) + n * nth_timer_offset,
        );
    }

    /// Summary:
    /// Expose this HPET device as a generic `Timer` vtable interface.
    /// Ensures the HPET main counter is enabled before returning the adapter.
    ///
    /// Args:
    /// - None.
    ///
    /// Returns:
    /// - `Timer` whose `now` reads the HPET main counter in nanoseconds.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn timer(self: *Hpet) Timer {
        if (!self.gen_config.enable) {
            self.gen_config.enable = true;
        }
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .arm_interrupt_timer = arm_interrupt_timer,
            },
        };
    }

    /// Summary:
    /// HPET-backed arm hook for the `Timer` vtable (not yet implemented).
    ///
    /// Args:
    /// - `ctx`: Opaque pointer (expects `*Hpet`).
    /// - `timer_val_ns`: Absolute deadline in nanoseconds to arm.
    ///
    /// Returns:
    /// - `void`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Panics unconditionally (`unreachable`) until implemented.
    fn arm_interrupt_timer(ctx: *anyopaque, timer_val_ns: u64) void {
        _ = ctx;
        _ = timer_val_ns;
        unreachable;
    }

    /// Summary:
    /// Read HPET main counter and convert to nanoseconds using `freq_hz`.
    ///
    /// Args:
    /// - `ctx`: Opaque pointer (expects `*Hpet`).
    ///
    /// Returns:
    /// - `u64` current time in nanoseconds (monotonic per HPET).
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn now(ctx: *anyopaque) u64 {
        const self: *Hpet = @alignCast(@ptrCast(ctx));
        return nanosFromTicksFloor(self.freq_hz, self.main_counter_val.val);
    }
};

/// Local APIC one-shot timer calibrated via HPET; exposes a `Timer`.
pub const Lapic = struct {
    freq_hz: u64,
    divider: u32,
    vector: u8,

    /// Summary:
    /// Calibrate LAPIC timer frequency using HPET and configure one-shot mode.
    ///
    /// Args:
    /// - `hpet`: Initialized HPET device used as the reference clock.
    /// - `int_vec`: Interrupt vector to deliver on timer expiry.
    ///
    /// Returns:
    /// - `Lapic` initialized with measured `freq_hz`, chosen `divider`, and `vector`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn init(hpet: *Hpet, int_vec: u8) Lapic {
        const DIV_CODE: u32 = 0b011;
        const DIVIDER: u32 = 16;

        apic.initLapicTimer(
            DIV_CODE,
            @intFromEnum(idt.IntVectors.spurious),
            true,
        );

        const hpet_iface = hpet.timer();
        var estimate: u64 = 0;

        for (0..3) |i| {
            if (apic.x2Apic) {
                cpu.wrmsr(
                    @intFromEnum(apic.X2ApicMsr.timer_initial_count_register),
                    0xFFFF_FFFF,
                );
            } else {
                apic.init_count.* = .{ .val = 0xFFFF_FFFF };
            }

            const start_ns = hpet_iface.now();
            var now_ns = start_ns;
            const target_ns = TEN_MILLION_NS;
            while ((now_ns - start_ns) < target_ns) now_ns = hpet_iface.now();

            const cur: u64 = if (apic.x2Apic)
                cpu.rdmsr(@intFromEnum(apic.X2ApicMsr.timer_current_count_register))
            else
                apic.curr_count.val;

            const elapsed: u64 = 0xFFFF_FFFF - cur;

            if (apic.x2Apic) {
                cpu.wrmsr(
                    @intFromEnum(apic.X2ApicMsr.timer_initial_count_register),
                    0,
                );
            } else {
                apic.init_count.* = .{ .val = 0 };
            }

            const delta_ns = now_ns - start_ns;
            const sample = (elapsed * @as(u64, DIVIDER) * ONE_BILLION_NS) / delta_ns;
            estimate = if (i == 0) sample else (estimate + sample) / 2;
        }

        apic.initLapicTimer(
            DIV_CODE,
            int_vec,
            false,
        );

        return .{
            .freq_hz = estimate,
            .divider = DIVIDER,
            .vector = int_vec,
        };
    }

    /// Summary:
    /// Expose the LAPIC timer as a generic `Timer` (one-shot arming).
    ///
    /// Args:
    /// - `self`: Receiver.
    ///
    /// Returns:
    /// - `Timer` whose `arm_interrupt_timer` loads LAPIC Initial Count.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn timer(self: *Lapic) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .arm_interrupt_timer = arm_interrupt_timer,
            },
        };
    }

    /// Summary:
    /// LAPIC-backed arm hook for the `Timer` vtable (one-shot mode).
    ///
    /// Args:
    /// - `ctx`: Opaque pointer (expects `*Lapic`).
    /// - `timer_val_ns`: Absolute deadline in nanoseconds to arm.
    ///
    /// Returns:
    /// - `void`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn arm_interrupt_timer(ctx: *anyopaque, timer_val_ns: u64) void {
        const self: *Lapic = @alignCast(@ptrCast(ctx));

        const eff_hz: u64 = self.freq_hz / self.divider;
        var ticks: u64 = ticksFromNanosCeil(eff_hz, timer_val_ns);
        if (ticks == 0) ticks = 1;
        if (ticks > 0xFFFF_FFFF) ticks = 0xFFFF_FFFF;

        apic.armLapicOneShot(@intCast(ticks), self.vector);
    }

    /// Summary:
    /// Not implemented for LAPIC (no monotonic readback in this adapter).
    ///
    /// Args:
    /// - `ctx`: Opaque pointer (expects `*Lapic`).
    ///
    /// Returns:
    /// - `u64` (unreachable).
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - Panics unconditionally (`unreachable`).
    fn now(ctx: *anyopaque) u64 {
        _ = ctx;
        unreachable;
    }
};

/// Vtable-based timer interface (read “now” and arm an interrupt deadline).
pub const Timer = struct {
    /// Underlying implementation pointer.
    ptr: *anyopaque,
    /// Vtable with function pointers for this timer.
    vtable: *const VTable,

    /// Summary:
    /// Return the current time in nanoseconds via the timer’s `now` vtable.
    ///
    /// Args:
    /// - `self`: Receiver.
    ///
    /// Returns:
    /// - `u64` current time in nanoseconds.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn now(self: *const Timer) u64 {
        return self.vtable.now(self.ptr);
    }

    /// Summary:
    /// Arm an interrupt/deadline via the timer’s vtable.
    ///
    /// Args:
    /// - `self`: Receiver.
    /// - `timer_val_ns`: Absolute deadline in nanoseconds.
    ///
    /// Returns:
    /// - `void`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn arm_interrupt_timer(self: *const Timer, timer_val_ns: u64) void {
        return self.vtable.arm_interrupt_timer(self.ptr, timer_val_ns);
    }
};

/// TSC frequency helper calibrated via HPET and exposed as a `Timer`.
pub const Tsc = struct {
    freq_hz: u64,

    /// Summary:
    /// Calibrate the TSC frequency against HPET by measuring TSC deltas over
    /// several ~10 ms windows and averaging.
    ///
    /// Args:
    /// - `hpet`: Pointer to an initialized `Hpet`.
    ///
    /// Returns:
    /// - `Tsc` with `freq_hz` set to the estimated TSC frequency.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
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

        return .{ .freq_hz = estimate };
    }

    /// Summary:
    /// Expose the calibrated TSC as a generic `Timer` vtable interface.
    ///
    /// Args:
    /// - `self`: Receiver.
    ///
    /// Returns:
    /// - `Timer` whose `now` converts `rdtscp()` ticks to nanoseconds.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn timer(self: *Tsc) Timer {
        return .{
            .ptr = self,
            .vtable = &.{
                .now = now,
                .arm_interrupt_timer = arm_interrupt_timer,
            },
        };
    }

    /// Summary:
    /// TSC-backed arm hook for the `Timer` vtable. Computes a TSC absolute
    /// deadline and programs x2APIC `IA32_TSC_DEADLINE` (LAPIC deadline mode).
    ///
    /// Args:
    /// - `ctx`: Opaque pointer (expects `*Tsc`).
    /// - `timer_val_ns`: Absolute deadline in nanoseconds to arm.
    ///
    /// Returns:
    /// - `void`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn arm_interrupt_timer(ctx: *anyopaque, timer_val_ns: u64) void {
        const self: *Tsc = @alignCast(@ptrCast(ctx));
        const delta_ticks: u64 = ticksFromNanosCeil(self.freq_hz, timer_val_ns);
        const now_ticks: u64 = cpu.rdtscp();
        apic.armTscDeadline(now_ticks + delta_ticks);
    }

    /// Summary:
    /// Read `rdtscp()` and convert to nanoseconds using `freq_hz`.
    ///
    /// Args:
    /// - `ctx`: Opaque pointer (expects `*Tsc`).
    ///
    /// Returns:
    /// - `u64` current time in nanoseconds derived from TSC.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn now(ctx: *anyopaque) u64 {
        const self: *Tsc = @alignCast(@ptrCast(ctx));
        return nanosFromTicksFloor(self.freq_hz, cpu.rdtscp());
    }
};

/// Function table used by `Timer` adapters.
pub const VTable = struct {
    /// Read current time in nanoseconds.
    now: *const fn (*anyopaque) u64,
    /// Arm an interrupt/deadline at an absolute nanoseconds value.
    arm_interrupt_timer: *const fn (*anyopaque, u64) void,
};

/// 1e9 nanoseconds (unit helper).
const ONE_BILLION_NS = 1_000_000_000;
/// 1e15 nanoseconds (unit helper).
const ONE_QUADRILLION_NS = 1_000_000_000_000_000;
/// 10 ms in nanoseconds (sampling window for TSC calibration).
const TEN_MILLION_NS = 10_000_000;

/// Summary:
/// Convert `ticks` at `freq_hz` to nanoseconds, rounding up (ceil).
///
/// Args:
/// - `freq_hz`: Tick frequency in Hertz.
/// - `ticks`: Number of ticks to convert.
///
/// Returns:
/// - `u64` nanoseconds, rounded up.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn nanosFromTicksCeil(freq_hz: u64, ticks: u64) u64 {
    return (ticks * ONE_BILLION_NS + freq_hz - 1) / freq_hz;
}

/// Summary:
/// Convert `ticks` at `freq_hz` to nanoseconds, truncating (floor).
///
/// Args:
/// - `freq_hz`: Tick frequency in Hertz.
/// - `ticks`: Number of ticks to convert.
///
/// Returns:
/// - `u64` nanoseconds, truncated.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn nanosFromTicksFloor(freq_hz: u64, ticks: u64) u64 {
    return (ticks * ONE_BILLION_NS) / freq_hz;
}

/// Summary:
/// Convert nanoseconds to ticks at `freq_hz`, rounding up (ceil).
///
/// Args:
/// - `freq_hz`: Tick frequency in Hertz.
/// - `ns`: Nanoseconds to convert.
///
/// Returns:
/// - `u64` ticks, rounded up.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn ticksFromNanosCeil(freq_hz: u64, ns: u64) u64 {
    return (freq_hz * ns + ONE_BILLION_NS - 1) / ONE_BILLION_NS;
}

/// Summary:
/// Convert nanoseconds to ticks at `freq_hz`, truncating (floor).
///
/// Args:
/// - `freq_hz`: Tick frequency in Hertz.
/// - `ns`: Nanoseconds to convert.
///
/// Returns:
/// - `u64` ticks, truncated.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn ticksFromNanosFloor(freq_hz: u64, ns: u64) u64 {
    return (freq_hz * ns) / ONE_BILLION_NS;
}
