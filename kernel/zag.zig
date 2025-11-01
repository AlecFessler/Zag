//! Top-level module index for the Zag kernel.
//!
//! Importing `zag` provides access to all major subsystem namespaces, each
//! of which organizes its own internal modules. This file serves as the
//! central entry point for high-level kernel code to access containers,
//! math utilities, memory management, panic/symbol facilities, and the
//! architecture-specific x86 subsystem.

pub const containers = @import("containers/containers.zig");
pub const math = @import("math/math.zig");
pub const memory = @import("memory/memory.zig");
pub const panic = @import("panic.zig");
pub const x86 = @import("arch/x86/x86.zig");
