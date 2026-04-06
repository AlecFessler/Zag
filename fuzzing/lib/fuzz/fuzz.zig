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
const FuzzErrors = error{
    DetectedInvalidState,
};

pub fn Fuzzer(comptime DStruct: type, comptime ops_cfg: anytype) type {
    validateOpsCfg(DStruct, ops_cfg);
    return struct {
        const Self = @This();
        const ErrorUnion = CollectErrorUnion(FuzzErrors || FmtErrors, ops_cfg);
        const ops_table = makeOpsTable(Self, ErrorUnion, ops_cfg);
        const priority_table = makePriorityTable(ops_cfg);

        const ops = ops_table;
        const priorities = priority_table;

        ds: *DStruct,
        rng: std.Random.DefaultPrng = undefined,
        step_idx: u64 = 0,
        validate: *const fn (*DStruct) bool,

        pub fn init(
            comptime validate: *const fn (*DStruct) bool,
            ds: *DStruct,
            seed: u64,
            w: *std.Io.Writer,
        ) Self {
            setLogWriter(w);
            return .{
                .ds = ds,
                .rng = std.Random.DefaultPrng.init(seed),
                .step_idx = 0,
                .validate = validate,
            };
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

            if (returns_err) {
                const ret = @call(.auto, func, args) catch |err| {
                    logPrint(" = {}\n", .{err});
                    if (!self.validate(self.ds)) return error.DetectedInvalidState;
                    return err;
                };

                if (returns_val) logPrint(" = " ++ parsed_fmt.ret_fmt.?, .{ret});
            } else if (returns_val) {
                const ret = @call(.auto, func, args);
                logPrint(" = " ++ parsed_fmt.ret_fmt.?, .{ret});
            } else {
                @call(.auto, func, args);
            }

            logPrint("\n", .{});
            if (!self.validate(self.ds)) return error.DetectedInvalidState;
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
