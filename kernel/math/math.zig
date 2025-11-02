//! Internal math utility module index.
//!
//! These utilities are re-exported by `zag`.
//! Higher-level code should import `zag` rather than importing `math` directly.
//!
//! This file provides a unified namespace for low-level numeric helpers that are
//! used across memory management, paging, allocation, and address manipulation
//! logic. Keeping these together avoids scattering foundational math helpers
//! across unrelated subsystems.
//!
//! # Included Submodules
//!
//! - `range.zig` – Half-open range type (`[start, end)`) with helpers for overlap,
//!                 containment, and slicing logic

pub const range = @import("range.zig");
