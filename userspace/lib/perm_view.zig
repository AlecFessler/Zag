pub const ENTRY_TYPE_PROCESS: u8 = 0;
pub const ENTRY_TYPE_VM_RESERVATION: u8 = 1;
pub const ENTRY_TYPE_SHARED_MEMORY: u8 = 2;
pub const ENTRY_TYPE_DEVICE_REGION: u8 = 3;
pub const ENTRY_TYPE_EMPTY: u8 = 0xFF;

pub const UserViewEntry = extern struct {
    handle: u64,
    entry_type: u8,
    _pad0: u8,
    rights: u16,
    _pad: [4]u8,
    field0: u64,
    field1: u64,

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
};
