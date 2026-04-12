//! AArch64 exception vector table and ESR_EL1 decoding.
//!
//! ARM exceptions use a vector table pointed to by VBAR_EL1. The table has
//! 16 entries (4 groups × 4 exception types), each 0x80 bytes apart.
//! This replaces x86's IDT entirely.
//!
//! Vector table layout (ARM ARM D1.10.2, Table D1-7):
//!   Offset  Source              Type
//!   0x000   Current EL, SP0     Synchronous
//!   0x080   Current EL, SP0     IRQ
//!   0x100   Current EL, SP0     FIQ
//!   0x180   Current EL, SP0     SError
//!   0x200   Current EL, SPx     Synchronous
//!   0x280   Current EL, SPx     IRQ
//!   0x300   Current EL, SPx     FIQ
//!   0x380   Current EL, SPx     SError
//!   0x400   Lower EL, AArch64   Synchronous  ← syscalls, page faults from EL0
//!   0x480   Lower EL, AArch64   IRQ          ← device interrupts from EL0
//!   0x500   Lower EL, AArch64   FIQ
//!   0x580   Lower EL, AArch64   SError
//!   0x600   Lower EL, AArch32   Synchronous  (not used — we don't run AArch32)
//!   ...
//!
//! ESR_EL1 (Exception Syndrome Register) decoding — ARM ARM D13.2.37:
//!   Bits [31:26] = EC (Exception Class):
//!     0x15 = SVC from AArch64 (syscall)
//!     0x20 = Instruction Abort from lower EL
//!     0x21 = Instruction Abort from same EL
//!     0x24 = Data Abort from lower EL (page fault)
//!     0x25 = Data Abort from same EL
//!     0x00 = Unknown reason
//!
//!   For Data/Instruction Aborts, bits [5:0] = DFSC/IFSC (Fault Status Code):
//!     0b0001xx = Translation fault (level 0-3)
//!     0b0010xx = Access flag fault (level 0-3)
//!     0b0011xx = Permission fault (level 0-3)
//!
//! FAR_EL1 holds the faulting virtual address (equivalent of x86 CR2).
//!
//! Key implementation tasks:
//! - Write the 2KB-aligned exception vector table (assembly stubs that save
//!   all 31 GPRs + SP_EL0 + ELR_EL1 + SPSR_EL1, then call Zig handlers).
//! - Install it via MSR VBAR_EL1.
//! - Decode ESR_EL1 to dispatch: SVC → syscall, Data Abort → page fault handler,
//!   IRQ → GIC handler, etc.
//! - Map fault status codes to kernel FaultReason values.
//!
//! References:
//! - ARM ARM D1.10: Exception vectors
//! - ARM ARM D13.2.37: ESR_EL1
//! - ARM ARM D13.2.40: FAR_EL1
