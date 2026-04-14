const std = @import("std");

pub fn CollectErrorUnion(
    comptime BaseErrorSet: type,
    comptime ops_cfg: anytype,
) type {
    comptime var ErrorUnion = BaseErrorSet;
    inline for (ops_cfg) |op_cfg| {
        const func = op_cfg.func;
        const fn_info = @typeInfo(@TypeOf(func)).@"fn";
        if (fn_info.return_type) |rt| {
            const rt_info = @typeInfo(rt);
            switch (rt_info) {
                .error_union => {
                    const ErrorSet = rt_info.error_union.error_set;
                    ErrorUnion = ErrorUnion || ErrorSet;
                },
                else => {},
            }
        }
    }

    return ErrorUnion;
}

fn OpsTableType(
    comptime CtxType: type,
    comptime ErrorUnion: type,
    comptime ops_cfg: anytype,
) type {
    const struct_info = @typeInfo(@TypeOf(ops_cfg)).@"struct";
    const FnPtr = @TypeOf(makeOp(CtxType, ErrorUnion, ops_cfg[0]));
    return [struct_info.fields.len]FnPtr;
}

pub fn makeOpsTable(
    comptime CtxType: type,
    comptime ErrorUnion: type,
    comptime ops_cfg: anytype,
) OpsTableType(CtxType, ErrorUnion, ops_cfg) {
    var array: OpsTableType(CtxType, ErrorUnion, ops_cfg) = undefined;
    inline for (ops_cfg, 0..) |op_cfg, i| {
        array[i] = makeOp(CtxType, ErrorUnion, op_cfg);
    }
    return array;
}

fn PriorityTableType(comptime ops_cfg: anytype) type {
    const struct_info = @typeInfo(@TypeOf(ops_cfg)).@"struct";
    return [struct_info.fields.len]f32;
}

pub fn makePriorityTable(comptime ops_cfg: anytype) PriorityTableType(ops_cfg) {
    var weights: PriorityTableType(ops_cfg) = undefined;
    var sum: f32 = 0.0;

    inline for (ops_cfg, 0..) |op, i| {
        const w: f32 = @floatFromInt(op.priority);
        weights[i] = w;
        sum += w;
    }

    var probs: [weights.len]f32 = undefined;
    inline for (weights, 0..) |w, i| {
        probs[i] = w / sum;
    }

    return probs;
}

fn makeOp(
    comptime CtxType: type,
    comptime ErrorUnion: type,
    comptime op_cfg: anytype,
) *const fn (*CtxType) ErrorUnion!void {
    const fn_info = @typeInfo(@TypeOf(op_cfg.func)).@"fn";
    const Args = std.meta.ArgsTuple(@TypeOf(op_cfg.func));
    const Op = struct {
        fn call(
            ctx: *CtxType,
        ) ErrorUnion!void {
            var args: Args = undefined;
            args[0] = ctx.ds;

            const rand = ctx.rng.random();

            inline for (fn_info.params[1..], 1..) |param, i| {
                const ParamType = param.type.?;
                const val = if (getGenerator(ParamType, i, op_cfg)) |genInput|
                    genInput()
                else
                    genRandNum(ParamType, rand);
                if (getCallback(ParamType, i, op_cfg)) |cb| cb(val);
                args[i] = val;
            }

            try ctx.callFn(
                op_cfg.fmt,
                op_cfg.func,
                args,
            );
        }
    };

    return Op.call;
}

pub fn validateOpsCfg(comptime DStruct: type, comptime ops_cfg: anytype) void {
    const ds_info = @typeInfo(DStruct);
    if (ds_info != .@"struct") std.debug.panic(
        "Expected struct type. Invalid type: {s}\n",
        .{@typeName(DStruct)},
    );

    const cfg_info = @typeInfo(@TypeOf(ops_cfg));
    if (cfg_info != .@"struct") std.debug.panic(
        "Expected struct type. Invalid type: {s}\n",
        .{@typeName(@TypeOf(ops_cfg))},
    );

    inline for (ops_cfg) |op_cfg| {
        const CfgType = @TypeOf(op_cfg);
        if (!@hasField(CfgType, "func")) std.debug.panic("Expected Op Cfg to have a `func` field\n", .{});
        if (!@hasField(CfgType, "fmt")) std.debug.panic("Expected Op Cfg to have a `fmt` field\n", .{});

        const func = op_cfg.func;
        const fn_info = @typeInfo(@TypeOf(func)).@"fn";

        inline for (fn_info.params, 0..) |param, i| {
            const T = param.type orelse std.debug.panic("Expected typed arg in func {s}", .{
                @typeName(@TypeOf(func)),
            });
            const t_info = @typeInfo(T);
            switch (t_info) {
                .pointer => {
                    if (i != 0) std.debug.panic("Expected numerical arg type in func {s}. Invalid type: {s}\n", .{
                        @typeName(@TypeOf(func)),
                        @typeName(T),
                    });
                    if (T != *DStruct) std.debug.panic("Expected first arg of func {s} to be *{s}. Invald type: {s}\n", .{
                        @typeName(@TypeOf(func)),
                        @typeName(DStruct),
                        @typeName(T),
                    });
                },
                .int, .float => {
                    if (i == 0) std.debug.panic("Expected first arg of func {s} to be *{s}. Invald type: {s}\n", .{
                        @typeName(@TypeOf(func)),
                        @typeName(DStruct),
                        @typeName(T),
                    });
                },
                else => {
                    if (i == 0) {
                        std.debug.panic("Expected first arg of func {s} to be *{s}. Invalid type: {s}\n", .{
                            @typeName(@TypeOf(func)),
                            @typeName(DStruct),
                            @typeName(T),
                        });
                    }
                    if (getGenerator(T, i, op_cfg) == null) {
                        std.debug.panic("Expected a generator arg type {s} at index {} in func {s}\n", .{
                            @typeName(T),
                            i,
                            @typeName(@TypeOf(func)),
                        });
                    }
                },
            }
        }
    }
}

fn getCallback(
    comptime ParamType: anytype,
    comptime param_idx: u64,
    comptime op_cfg: anytype,
) ?*const fn (ParamType) void {
    const cfg_type = @TypeOf(op_cfg);
    if (!@hasField(cfg_type, "callbacks")) return null;
    const cb_info = @typeInfo(@TypeOf(op_cfg.callbacks)).@"struct";
    inline for (cb_info.fields) |field| {
        if (field.defaultValue()) |val| {
            if (val.param_idx != param_idx) continue;
            return val.callback;
        }
    }
    return null;
}

fn getGenerator(
    comptime ParamType: anytype,
    comptime param_idx: u64,
    comptime op_cfg: anytype,
) ?*const fn () ParamType {
    const cfg_type = @TypeOf(op_cfg);
    if (!@hasField(cfg_type, "generators")) return null;
    const gen_info = @typeInfo(@TypeOf(op_cfg.generators)).@"struct";
    inline for (gen_info.fields) |field| {
        if (field.defaultValue()) |val| {
            if (val.param_idx != param_idx) continue;
            return val.generator;
        }
    }
    return null;
}

fn genRandNum(comptime T: type, rand: std.Random) T {
    return switch (@typeInfo(T)) {
        .int => rand.int(T),
        .float => rand.float(T),
        else => std.debug.panic("genRandNum expects numerical input types. Invalid type {s}\n", .{@typeName(T)}),
    };
}
