const zag = @import("zag");

const PrivilegePerm = zag.perms.privilege.PrivilegePerm;

pub const WritePerm = enum(u1) {
    no_write,
    write,
};

pub const ExecutePerm = enum(u1) {
    no_execute,
    execute,
};

pub const CachePerm = enum(u2) {
    not_cacheable,
    write_back,
    write_through,
};

pub const GlobalPerm = enum(u1) {
    not_global,
    global,
};

pub const MemoryPerms = packed struct(u64) {
    write_perm: WritePerm = .no_write,
    execute_perm: ExecutePerm = .no_execute,
    cache_perm: CachePerm = .write_back,
    global_perm: GlobalPerm = .not_global,
    privilege_perm: PrivilegePerm = .kernel,
    reserved: u58 = 0,
};
