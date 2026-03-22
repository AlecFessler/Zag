const lib = @import("lib");

const syscall = lib.syscall;

const device_tests = @import("tests/device.zig");
const futex_tests = @import("tests/futex.zig");
const grant_reduced_tests = @import("tests/grant_reduced.zig");
const grant_tests = @import("tests/grant.zig");
const misc_tests = @import("tests/misc.zig");
const multithread_kill_tests = @import("tests/multithread_kill.zig");
const perm_view_tests = @import("tests/perm_view.zig");
const proc_tests = @import("tests/proc.zig");
const restart_tests = @import("tests/restart.zig");
const shm_tests = @import("tests/shm.zig");
const stack_guard_tests = @import("tests/stack_guard.zig");
const thread_tests = @import("tests/thread.zig");
const vm_error_tests = @import("tests/vm_errors.zig");
const vm_tests = @import("tests/vm.zig");
const zombie_tests = @import("tests/zombie.zig");

pub fn main(perm_view: u64) void {
    syscall.write("Hello from userspace!\n");
    syscall.write("Running kernel tests...\n");

    vm_tests.run();
    shm_tests.run();
    perm_view_tests.run(perm_view);
    thread_tests.run();
    futex_tests.run();
    vm_error_tests.run();
    device_tests.run(perm_view);
    grant_tests.run(perm_view);
    proc_tests.run();
    stack_guard_tests.run();
    multithread_kill_tests.run();
    restart_tests.run();
    zombie_tests.run();
    // TODO: grant_reduced_tests hangs in TCG - child fault cleanup path
    // grant_reduced_tests.run();
    misc_tests.run();

    syscall.write("\nAll test suites completed.\n");
    syscall.shutdown();
}
