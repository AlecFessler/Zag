// EXPECT: clean
// Lock + defer unlock + early return → defer covers, OK.

const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};

pub fn SlabRef(comptime T: type) type {
    return extern struct {
        ptr: *T,
        gen: u64 = 0,
        pub fn lock(_: @This()) ?*T { return null; }
        pub fn unlock(_: @This()) void {}
    };
}

pub fn sysDeferOk(ref: SlabRef(Foo), cond: u64) i64 {
    _ = ref.lock() orelse return -2;
    defer ref.unlock();
    if (cond != 0) return -1; // covered by defer
    return 0;
}
