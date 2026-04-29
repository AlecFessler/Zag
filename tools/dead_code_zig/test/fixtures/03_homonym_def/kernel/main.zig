// Fixture: two unrelated modules each define `pub const Foo`. Neither
// has a real user. Without the self-def-token exclusion in the bare-id
// heuristic, each def's token would count as a "use" of the OTHER —
// keeping both alive falsely. Both should be flagged dead.
pub fn kEntry() void {}
