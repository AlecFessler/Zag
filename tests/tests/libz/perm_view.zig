pub const ENTRY_TYPE_PROCESS: u8 = 0;
pub const ENTRY_TYPE_VM_RESERVATION: u8 = 1;
pub const ENTRY_TYPE_SHARED_MEMORY: u8 = 2;
pub const ENTRY_TYPE_DEVICE_REGION: u8 = 3;
pub const ENTRY_TYPE_CORE_PIN: u8 = 4;
pub const ENTRY_TYPE_DEAD_PROCESS: u8 = 5;
pub const ENTRY_TYPE_THREAD: u8 = 6;
pub const ENTRY_TYPE_EMPTY: u8 = 0xFF;

pub const CrashReason = enum(u5) {
    none = 0,
    stack_overflow = 1,
    stack_underflow = 2,
    invalid_read = 3,
    invalid_write = 4,
    invalid_execute = 5,
    unmapped_access = 6,
    out_of_memory = 7,
    arithmetic_fault = 8,
    illegal_instruction = 9,
    alignment_fault = 10,
    protection_fault = 11,
    normal_exit = 12,
    killed = 13,
    breakpoint = 14,
    pmu_overflow = 15,
    _,
};

pub const UserViewEntry = extern struct {
    handle: u64,
    entry_type: u8,
    _reserved_byte: u8,
    rights: u16,
    _pad: [4]u8,
    field0: u64,
    field1: u64,

    pub fn processCrashReason(self: *const UserViewEntry) CrashReason {
        return @enumFromInt(@as(u5, @truncate(self.field0)));
    }

    pub fn processRestartCount(self: *const UserViewEntry) u16 {
        return @truncate(self.field0 >> 16);
    }

    pub fn deviceType(self: *const UserViewEntry) u8 {
        return @truncate(self.field0);
    }

    pub fn deviceClass(self: *const UserViewEntry) u8 {
        return @truncate(self.field0 >> 8);
    }

    pub fn deviceSizeOrPortCount(self: *const UserViewEntry) u32 {
        return @truncate(self.field0 >> 32);
    }

    pub fn pciVendor(self: *const UserViewEntry) u16 {
        return @truncate(self.field1);
    }

    pub fn pciDevice(self: *const UserViewEntry) u16 {
        return @truncate(self.field1 >> 16);
    }

    pub fn pciClassCode(self: *const UserViewEntry) u8 {
        return @truncate(self.field1 >> 32);
    }

    pub fn pciSubclass(self: *const UserViewEntry) u8 {
        return @truncate(self.field1 >> 40);
    }

    pub fn pciBus(self: *const UserViewEntry) u8 {
        return @truncate((self.field1 >> 48) & 0x1F);
    }

    pub fn pciDev(self: *const UserViewEntry) u5 {
        return @truncate((self.field1 >> 53) & 0x1F);
    }

    pub fn pciFunc(self: *const UserViewEntry) u3 {
        return @truncate((self.field1 >> 58) & 0x7);
    }

    pub fn fbWidth(self: *const UserViewEntry) u16 {
        return @truncate(self.field1);
    }

    pub fn fbHeight(self: *const UserViewEntry) u16 {
        return @truncate(self.field1 >> 16);
    }

    pub fn fbStride(self: *const UserViewEntry) u16 {
        return @truncate(self.field1 >> 32);
    }

    pub fn fbPixelFormat(self: *const UserViewEntry) u8 {
        return @truncate(self.field1 >> 48);
    }

    /// The thread's stable kernel-assigned tid. Transient scheduling state
    /// is not exposed via the user view — see `fault_recv` for `.faulted`,
    /// syscall return codes for `.suspended`, and perm entry removal for
    /// `.exited`.
    pub fn threadTid(self: *const UserViewEntry) u64 {
        return self.field0;
    }

    /// True if the perm slot for this thread has `exclude_oneshot` set.
    /// Packed in field0 bit 32.
    pub fn threadExcludeOneshot(self: *const UserViewEntry) bool {
        return (self.field0 >> 32 & 0x1) != 0;
    }

    /// True if the perm slot for this thread has `exclude_permanent` set.
    /// Packed in field0 bit 33.
    pub fn threadExcludePermanent(self: *const UserViewEntry) bool {
        return (self.field0 >> 33 & 0x1) != 0;
    }
};

pub const FaultReason = CrashReason;
