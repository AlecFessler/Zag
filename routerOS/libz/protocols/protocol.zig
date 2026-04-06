pub const Protocol = enum(u8) {
    serial = 1,
    router = 3,
    console = 4,
    nfs_client = 6,
    ntp_client = 7,
    http_server = 8,
    root_service = 9,
};
