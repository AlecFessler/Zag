const zag = @import("zag");

const apic = zag.x86.Apic;
const cpu = zag.x86.Cpu;
const serial = zag.x86.Serial;

pub const SCHED_TIMESLICE_NS = 2_000_000; // 2ms
const ONE_BILLION_CYCLES = 1_000_000_000;

var freq_hz: u64 = undefined;

pub fn initFreqHz(freq: u64) void {
    freq_hz = freq;
}

pub fn armSchedTimer() void {
    const delta_ticks = freq_hz * SCHED_TIMESLICE_NS / ONE_BILLION_CYCLES;
    const now_ticks = cpu.rdtscp();
    apic.armTscDeadline(now_ticks + delta_ticks);
}

pub fn schedTimerHandler(ctx: *cpu.Context) void {
    _ = ctx;
    serial.print("Sched timer!\n", .{});
    armSchedTimer();
}
