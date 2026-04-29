// Fixture: dead decl whose hash in .dead-code-skip.txt is wrong, so
// the skip entry should INVALIDATE and the decl should still be
// reported.

pub fn kEntry() void {}

const deadConst: u32 = 99;
