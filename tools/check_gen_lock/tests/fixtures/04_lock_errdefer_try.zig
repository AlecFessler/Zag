// EXPECT: clean
// Lock + errdefer unlock + try → errdefer covers error path, OK.

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

fn fallible() !u64 { return 0; }

pub fn sysErrdeferOk(ref: SlabRef(Foo)) !i64 {
    _ = ref.lock() orelse return -2;
    errdefer ref.unlock();
    _ = try fallible(); // covered by errdefer
    ref.unlock();
    return 0;
}
