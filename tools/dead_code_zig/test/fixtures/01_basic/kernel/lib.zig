// Fixture lib: aliveAlias re-exports aliveLeaf. aliveLeaf is reached
// transitively. deadLeaf has no reachable caller.

pub const aliveAlias = aliveLeaf;

pub fn aliveLeaf() void {}

pub fn deadLeaf() void {}
