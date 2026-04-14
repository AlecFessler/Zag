const std = @import("std");
const router = @import("router");
const lib = @import("lib");

const harness = @import("harness.zig");
const invariants = @import("invariants.zig");
const mutator = @import("mutator.zig");
const oracle = @import("oracle.zig");
const packet_gen = @import("packet_gen.zig");
const scenarios = @import("scenarios.zig");

const state = router.state;
const syscall = lib.syscall;

pub fn main() !void {
    const args = try parseArgs();
    var rng = std.Random.DefaultPrng.init(args.seed);
    const random = rng.random();

    harness.initRouter();

    var failures: u64 = 0;
    var step: u64 = 0;

    std.debug.print("Router fuzzer: seed={} iterations={}\n", .{ args.seed, args.iterations });

    while (step < args.iterations) : (step += 1) {
        const op = random.float(f32);

        if (op < 0.40) {
            // 40%: clean seed packet (strict oracle)
            var gen = packet_gen.generateRandom(random);
            const result = harness.injectPacket(gen.interface, &gen.buf, gen.len);
            if (!oracle.validateResult(gen, result)) {
                std.debug.print("STRICT ORACLE FAIL at step {} seed={} kind={s}\n", .{
                    step, args.seed, @tagName(gen.kind),
                });
                failures += 1;
            }
        } else if (op < 0.80) {
            // 40%: mutated packet (structural oracle)
            const seed_pkt = packet_gen.generateRandom(random);
            var gen = mutator.mutate(random, seed_pkt);
            const result = harness.injectPacket(gen.interface, &gen.buf, gen.len);
            if (!oracle.validateResult(gen, result)) {
                std.debug.print("STRUCTURAL ORACLE FAIL at step {} seed={}\n", .{
                    step, args.seed,
                });
                failures += 1;
            }
        } else if (op < 0.90) {
            // 10%: scenario step
            scenarios.runRandomScenario(random, step, args.seed);
        } else {
            // 10%: maintenance tick
            const advance_ns: u64 = random.intRangeAtMost(u64, 1_000_000, 30_000_000_000);
            harness.advanceClock(advance_ns);
            state.periodicMaintenance();
        }

        // Invariant check after every operation
        invariants.validateAll() catch |err| {
            std.debug.print("INVARIANT FAIL at step {} seed={}: {s}\n", .{
                step, args.seed, @errorName(err),
            });
            failures += 1;
        };
    }

    std.debug.print("Fuzzer complete: {} iterations, {} failures\n", .{ args.iterations, failures });
    if (failures > 0) std.process.exit(1);
}

const Args = struct {
    seed: u64,
    iterations: u64,
};

fn parseArgs() !Args {
    var seed: u64 = 0;
    var iterations: u64 = 100_000;

    var args = std.process.args();
    _ = args.skip();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-s")) {
            const val = args.next() orelse return error.MissingArg;
            seed = try std.fmt.parseInt(u64, val, 10);
        } else if (std.mem.eql(u8, arg, "-i")) {
            const val = args.next() orelse return error.MissingArg;
            iterations = try std.fmt.parseInt(u64, val, 10);
        }
    }

    return .{ .seed = seed, .iterations = iterations };
}
