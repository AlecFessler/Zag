//! Shared protocol definitions for the tests/prof mock userspace.
//!
//! Scenarios in the prof test OS share a small name-service rooted in
//! the root service plus per-scenario message shapes. Every scenario
//! protocol lives here as a Verb enum and a fixed word layout so every
//! side of every IPC can use the same numeric constants without
//! stringly-typed lookups.

/// Stable name ids for scenarios that register with the root service.
pub const NameId = enum(u32) {
    none = 0,
    debugger = 1,
    debuggee = 2,
    _,
};

/// Debugger scenario verbs sent debuggee -> debugger over a plain
/// (non-cap) IPC call. The cap handoff that follows is a separate call
/// so that message layout stays simple and the two phases can be
/// inspected independently in a kprof trace.
pub const DbgVerb = enum(u32) {
    /// Debuggee -> debugger on startup. Payload:
    ///   word 1 = runtime address of the `debuggee_slide_anchor` symbol
    ///   word 2 = runtime address of `bp_stop_1`
    ///   word 3 = runtime address of `bp_stop_2`
    ///   word 4 = runtime address of `bp_stop_3`
    hello = 1,
    _,
};

pub inline fn header(verb: u32, flags: u32) u64 {
    return @as(u64, verb) | (@as(u64, flags) << 32);
}

pub inline fn headerVerb(word0: u64) u32 {
    return @truncate(word0);
}
