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

pub const TLBFlushPersistPerm = enum(u1) {
    always_flush,
    never_flush,
};

pub const MemoryPerms = packed struct(u64) {
    write_perm: WritePerm,
    execute_perm: ExecutePerm,
    cache_perm: CachePerm,
    tlb_flush_persist_perm: TLBFlushPersistPerm,
    privilege_perm: PrivilegePerm,
    reserved: u58,
};
