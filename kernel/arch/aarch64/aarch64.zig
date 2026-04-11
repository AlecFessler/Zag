pub const pmu = @import("pmu.zig");
pub const sysinfo = @import("sysinfo.zig");

pub const vm = struct {
    pub const GuestState = struct {};
    pub const VmExitInfo = struct {};
    pub const GuestInterrupt = struct {};
    pub const GuestException = struct {};
    pub const VmPolicy = struct {};
    pub const FxsaveArea = [512]u8;

    pub fn fxsaveInit() FxsaveArea {
        return .{0} ** 512;
    }

    pub fn vmInit() void {}
    pub fn vmPerCoreInit() void {}
    pub fn vmSupported() bool {
        return false;
    }
};
