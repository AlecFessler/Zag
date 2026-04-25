// EXPECT: errors=1
// Switch where one arm forgets to unlock before returning → leak.

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

pub fn sysSwitchLeak(ref: SlabRef(Foo), tag: u64) i64 {
    _ = ref.lock() orelse return -2;
    switch (tag) {
        0 => {
            ref.unlock();
            return -1;
        },
        1 => {
            return -2; // <- LEAK: no unlock in this arm
        },
        else => {
            ref.unlock();
            return 0;
        },
    }
}
