const std = @import("std");
const cpu = @import("cpu.zig");
const paging = @import("paging.zig");

const VAddr = paging.VAddr;

fn addPtr(base: *align(8) volatile u8, off: u64) *align(8) volatile u8 {
    const addr = @as(usize, @intFromPtr(base)) + @as(usize, off);
    return @ptrFromInt(addr);
}

pub const HpetRegs = struct {
    base: *align(8) volatile u8,

    fn r64(self: *HpetRegs, off: u64) u64 {
        const p: *align(8) volatile u64 = @ptrCast(addPtr(self.base, off));
        return p.*;
    }

    fn w64(self: *HpetRegs, off: u64, v: u64) void {
        const p: *align(8) volatile u64 = @ptrCast(addPtr(self.base, off));
        p.* = v;
    }

    fn capId(self: *HpetRegs) u64 {
        return self.r64(0x000);
    }
    fn genCfg(self: *HpetRegs) u64 {
        return self.r64(0x010);
    }
    fn setGenCfg(self: *HpetRegs, v: u64) void {
        self.w64(0x010, v);
    }
    fn mainCounter(self: *HpetRegs) u64 {
        return self.r64(0x0F0);
    }
    fn setMainCounter(self: *HpetRegs, v: u64) void {
        self.w64(0x0F0, v);
    }
};

pub const Hpet = struct {
    regs: HpetRegs,
    period_femtos: u64,
    freq_hz: u64,
    is_64: bool,

    pub fn init(base_virt: VAddr) Hpet {
        var regs = HpetRegs{ .base = @ptrFromInt(base_virt.addr) };

        const cap = regs.capId();
        const period_femtos: u64 = cap >> 32;
        const is_64: bool = ((cap >> 13) & 1) == 1;

        const freq_hz: u64 = @divFloor(1_000_000_000_000_000, period_femtos);

        regs.setGenCfg(0);
        regs.setMainCounter(0);
        regs.setGenCfg(1);

        return .{
            .regs = regs,
            .period_femtos = period_femtos,
            .freq_hz = freq_hz,
            .is_64 = is_64,
        };
    }

    pub fn now(self: *Hpet) u64 {
        return self.regs.mainCounter();
    }
};

pub fn calibrateTscHz(hpet: *Hpet, window_ms: u32) u64 {
    const hpet_target_ticks: u64 = (hpet.freq_hz * window_ms) / 1_000;
    const start_h = hpet.now();
    const start_t = cpu.rdtscp();

    while (true) {
        const cur_h = hpet.now();
        if (cur_h - start_h >= hpet_target_ticks) break;
        asm volatile ("" ::: .{ .memory = true });
    }

    const end_t = cpu.rdtscp();
    const dt_tsc = end_t - start_t;
    return (dt_tsc * 1000) / window_ms;
}
