//! Top-level kernel module index.
//!
//! Importing `zag` provides access to all major kernel subsystems through stable,
//! unified namespaces. Each subsystem maintains its own internal structure, but
//! higher-level code interacts with them via `zag.*` to ensure architectural
//! consistency and to avoid hardcoding specific file paths.
//!
//! # Included Subsystems
//!
//! - `containers` – Balanced trees, free lists, and other kernel data structures
//! - `debugger`   – Kernel debugger with utilities for dumping kernel state
//! - `math`       – Range logic and low-level numeric utilities
//! - `memory`     – Physical/virtual memory managers and allocator implementations
//! - `panic`      – Kernel panic handler and symbol resolution for stack traces
//! - `sched`      – Preemptive scheduler and task dispatch infrastructure
//! - `x86`        – Architecture-specific initialization and CPU/hardware control

pub const containers = @import("containers/containers.zig");
pub const debugger = @import("debugger/debugger.zig");
pub const drivers = @import("drivers/drivers.zig");
pub const hal = @import("hal/hal.zig");
pub const math = @import("math/math.zig");
pub const memory = @import("memory/memory.zig");
pub const panic = @import("panic.zig");
pub const sched = @import("sched/sched.zig");
pub const x86 = @import("arch/x86/x86.zig");
