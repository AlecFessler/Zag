pub const ENTRY_TYPE_PROCESS: u8 = 0;
pub const ENTRY_TYPE_VM_RESERVATION: u8 = 1;
pub const ENTRY_TYPE_SHARED_MEMORY: u8 = 2;
pub const ENTRY_TYPE_DEVICE_REGION: u8 = 3;
pub const ENTRY_TYPE_EMPTY: u8 = 0xFF;

pub const UserViewEntry = extern struct {
    handle: u64,
    entry_type: u8,
    rights: u8,
    _pad: [6]u8,
    field0: u64,
    field1: u64,
};
