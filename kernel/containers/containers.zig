//! Internal container data structure module index.
//!
//! These containers are re-exported by `zag`.
//! Higher-level code should import `zag` rather than importing `containers` directly.
//!
//! This file acts as a namespace unification layer so that subsystems, memory managers,
//! schedulers, and allocators can reference container types via `zag.containers.*`
//! without needing to know where individual implementations live.
//!
//! # Included Submodules
//!
//! - `red_black_tree.zig` – Balanced binary search tree with deterministic ordering

pub const RedBlackTree = @import("red_black_tree.zig");
