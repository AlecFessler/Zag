const lib = @import("lib");
const syscall = lib.syscall;

const futex_tests = @import("tests/futex.zig");
const misc_tests = @import("tests/misc.zig");
const perm_view_tests = @import("tests/perm_view.zig");
const shm_tests = @import("tests/shm.zig");
const thread_tests = @import("tests/thread.zig");
const vm_tests = @import("tests/vm.zig");

pub fn main(perm_view: u64) void {
    syscall.write("Hello from userspace!\n");
    syscall.write("Running kernel tests...\n");

    vm_tests.run();
    shm_tests.run();
    perm_view_tests.run(perm_view);
    thread_tests.run();
    futex_tests.run();
    misc_tests.run();

    syscall.write("\nAll test suites completed.\n");
}
