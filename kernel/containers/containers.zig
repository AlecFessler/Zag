//! Containers module entry point.
//!
//! Provides access to kernel-level container data structures such as trees,
//! lists, and maps. Intended for use in memory managers, schedulers, and other
//! subsystems that require efficient and predictable data organization.
//!
//! Serves as a unified import surface for all container types used across the kernel.

pub const RedBlackTree = @import("red_black_tree.zig");
