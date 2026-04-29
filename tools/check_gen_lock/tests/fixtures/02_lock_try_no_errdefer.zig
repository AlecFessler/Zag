// EXPECT: errors=1
// Lock + try (implicit error-path return) without errdefer → leak.

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

pub fn sysTryLeak(ref: SlabRef(Foo)) !i64 {
    _ = ref.lock() orelse return -2;
    _ = try fallible(); // <- LEAK on error: no errdefer, no defer, no unlock-before
    ref.unlock();
    return 0;
}
