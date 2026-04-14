// Minimal zag shim for userspace fuzzing.
// Re-exports only the pure data-structure modules needed by the fuzzed code.
pub const arch = @import("arch");
pub const memory = @import("memory");
pub const perms = @import("perms");
pub const sched = @import("sched");
pub const utils = @import("utils");
