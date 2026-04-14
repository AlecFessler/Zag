const std = @import("std");
const shared = @import("shared");

const logPrint = shared.log.logPrint;
const logFmtArg = shared.log.logFmtArg;
const makeOp = shared.makeOp.makeOp;
const makeOpsTable = shared.makeOp.makeOpsTable;
const makePriorityTable = shared.makeOp.makePriorityTable;
const parseFmt = shared.log.parseFmt;
const setLogWriter = shared.log.setLogWriter;
const validateOpsCfg = shared.makeOp.validateOpsCfg;

const CollectErrorUnion = shared.makeOp.CollectErrorUnion;

const FmtErrors = shared.log.FmtErrors;
const ProfErrors = error{};

const HWReadErrors = error{
    ShortRead,
    BadEventCount,
} || std.posix.ReadError;

const HWCounter = enum(u64) {
    cycles = @intFromEnum(std.os.linux.PERF.COUNT.HW.CPU_CYCLES),
    instructions = @intFromEnum(std.os.linux.PERF.COUNT.HW.INSTRUCTIONS),
    cache_misses = @intFromEnum(std.os.linux.PERF.COUNT.HW.CACHE_MISSES),
    branch_misses = @intFromEnum(std.os.linux.PERF.COUNT.HW.BRANCH_MISSES),
    branch_instructions = @intFromEnum(std.os.linux.PERF.COUNT.HW.BRANCH_INSTRUCTIONS),
};

const Snapshot = struct {
    values: [NUM_COUNTERS]u64,
};

const NUM_COUNTERS = @typeInfo(HWCounter).@"enum".fields.len;
const PERF_FORMAT_GROUP: u64 = 1 << 3;

fn diffSnapshots(before: Snapshot, after: Snapshot) Snapshot {
    var out: Snapshot = undefined;
    for (0..NUM_COUNTERS) |i| {
        out.values[i] = after.values[i] - before.values[i];
    }
    return out;
}

fn logDiff(diff: Snapshot) void {
    logPrint(" PERF", .{});
    inline for (@typeInfo(HWCounter).@"enum".fields, 0..) |field, i| {
        logPrint(" {s}={}", .{ field.name, diff.values[i] });
    }
    logPrint("\n", .{});
}

fn openPerfEvent(
    maybe_group_fd: ?std.os.linux.fd_t,
    counter: HWCounter,
) !std.posix.fd_t {
    var attr: std.os.linux.perf_event_attr = .{
        .type = std.os.linux.PERF.TYPE.HARDWARE,
        .config = @intFromEnum(counter),
        .sample_period_or_freq = 0,
        .sample_type = 0,
        .read_format = PERF_FORMAT_GROUP,
        .flags = .{
            .disabled = false,
            .inherit = false,
            .exclude_user = false,
            .exclude_kernel = true,
            .exclude_hv = true,
        },
    };

    const pid: std.posix.pid_t = 0;
    const cpu: i32 = -1;
    const group_fd: std.posix.fd_t = maybe_group_fd orelse -1;
    const flags: usize = 0;

    return try std.posix.perf_event_open(&attr, pid, cpu, group_fd, flags);
}

pub fn Profiler(comptime DStruct: type, comptime ops_cfg: anytype) type {
    validateOpsCfg(DStruct, ops_cfg);
    return struct {
        const Self = @This();
        const ErrorUnion = CollectErrorUnion(ProfErrors || FmtErrors || HWReadErrors, ops_cfg);
        const ops_table = makeOpsTable(Self, ErrorUnion, ops_cfg);
        const priority_table = makePriorityTable(ops_cfg);

        const ops = ops_table;
        const priorities = priority_table;

        counter_fds: [NUM_COUNTERS]std.os.linux.fd_t = undefined,
        ds: *DStruct,
        rng: std.Random.DefaultPrng = undefined,
        step_idx: u64 = 0,

        pub fn init(
            ds: *DStruct,
            seed: u64,
            writer: *std.Io.Writer,
        ) !Self {
            setLogWriter(writer);
            return .{
                .counter_fds = blk: {
                    var counter_fds: [NUM_COUNTERS]std.os.linux.fd_t = undefined;
                    const counter_types = @typeInfo(HWCounter).@"enum".fields;
                    counter_fds[0] = try openPerfEvent(null, @enumFromInt(counter_types[0].value));
                    inline for (counter_types[1..], 1..) |field, i| {
                        counter_fds[i] = try openPerfEvent(counter_fds[0], @enumFromInt(field.value));
                    }
                    break :blk counter_fds;
                },
                .ds = ds,
                .rng = std.Random.DefaultPrng.init(seed),
                .step_idx = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.counter_fds) |fd| {
                std.posix.close(fd);
            }
        }

        pub fn callFn(
            self: *Self,
            comptime fmt: []const u8,
            comptime func: anytype,
            args: anytype,
        ) ErrorUnion!void {
            const fn_info = @typeInfo(@TypeOf(func)).@"fn";
            const returns_err, const returns_val = comptime blk: {
                if (fn_info.return_type) |rt| {
                    const rt_info = @typeInfo(rt);
                    switch (rt_info) {
                        .void => break :blk .{ false, false },
                        .error_union => {
                            const payload = rt_info.error_union.payload;
                            const has_val = payload != void;
                            break :blk .{ true, has_val };
                        },
                        else => break :blk .{ false, true },
                    }
                } else {
                    break :blk .{ false, false };
                }
            };

            const parsed_fmt = comptime parseFmt(fmt);

            logPrint("#{}: {s}(", .{ self.step_idx, parsed_fmt.fn_name });
            logPrint(parsed_fmt.arg_fmt, args);
            logPrint(")", .{});

            var snap_before: Snapshot = undefined;
            var snap_after: Snapshot = undefined;

            if (returns_err) {
                snap_before = try self.snapshot();
                const ret = @call(.auto, func, args) catch |err| {
                    snap_after = try self.snapshot();
                    logPrint(" = {}", .{err});
                    const diff = diffSnapshots(snap_before, snap_after);
                    logDiff(diff);
                    return err;
                };
                snap_after = try self.snapshot();

                if (returns_val) logPrint(" = " ++ parsed_fmt.ret_fmt.?, .{ret});
            } else if (returns_val) {
                snap_before = try self.snapshot();
                const ret = @call(.auto, func, args);
                snap_after = try self.snapshot();

                logPrint(" = " ++ parsed_fmt.ret_fmt.?, .{ret});
            } else {
                snap_before = try self.snapshot();
                @call(.auto, func, args);
                snap_after = try self.snapshot();
            }

            const diff = diffSnapshots(snap_before, snap_after);
            logDiff(diff);
        }

        fn snapshot(self: *Self) HWReadErrors!Snapshot {
            var raw: [1 + NUM_COUNTERS]u64 = undefined;

            const bytes = std.mem.asBytes(&raw);
            const n = try std.posix.read(self.counter_fds[0], bytes);
            if (n != bytes.len) return error.ShortRead;

            const nr = raw[0];
            if (nr != NUM_COUNTERS) return error.BadEventCount;

            return .{ .values = raw[1..].* };
        }

        pub fn step(self: *Self) ErrorUnion!void {
            self.step_idx += 1;
            const rand = self.rng.random();
            const idx = blk: {
                const u = rand.float(f32);
                var acc: f32 = 0.0;

                for (priorities, 0..) |p, i| {
                    acc += p;
                    if (u < acc) break :blk i;
                }

                break :blk priorities.len - 1;
            };
            try ops[idx](self);
        }
    };
}
