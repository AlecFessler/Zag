// Fixture: kEntry calls aliveFn → marks aliveFn alive. deadFn has no
// reachable caller; deadConst has no use.
const lib = @import("lib.zig");

pub fn kEntry() void {
    aliveFn();
    _ = lib.aliveAlias;
}

fn aliveFn() void {
    lib.aliveLeaf();
}

fn deadFn() void {
    lib.deadLeaf();
}

const deadConst: u32 = 42;
