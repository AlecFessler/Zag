//! Internal scheduler subsystem module index.
//!
//! This module is re-exported by `zag`.
//! Higher-level code should import `zag` rather than importing `scheduler` directly.
//!
//! Provides access to the kernel scheduler implementation responsible for CPU time
//! distribution, runnable thread queues, context switching, and timer-driven
//! preemption. Other subsystems interact with the scheduler through
//! `zag.scheduler.*` to avoid depending on specific scheduling strategy details.
//!
//! # Included Submodules
//!
//! - `scheduler.zig` – Core run queue management, context switching, and tick logic

pub const scheduler = @import("scheduler.zig");
