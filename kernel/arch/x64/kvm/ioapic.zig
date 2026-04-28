//! In-kernel IOAPIC emulator — placeholder for spec-v3 VM bring-up.
//!
//! The full Intel 82093AA emulator returns once vm_exit delivery and
//! the vCPU run loop are wired up.

/// IOAPIC redirection table entry count. Intel 82093AA datasheet §3.2.4.
pub const NUM_REDIR_ENTRIES: u8 = 24;
