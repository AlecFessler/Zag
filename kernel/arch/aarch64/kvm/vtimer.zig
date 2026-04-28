//! Aarch64 virtual timer save/restore (ARM Generic Timer, virtual view).
//!
//! Reserved for future VM bring-up — when the world-switch loop is
//! wired up, per-vCPU virtual-timer state (CNTVOFF_EL2 / CNTV_CTL_EL0 /
//! CNTV_CVAL_EL0 / CNTKCTL_EL1) save/restore lives here.
//!
//! References:
//!   ARM ARM D13.11 — Generic Timer registers.
//!   ARM IHI 0069H — GICv3, virtual timer PPI (INTID 27).

pub const VtimerState = extern struct {
    cntvoff_el2: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    cntv_cval_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
};
