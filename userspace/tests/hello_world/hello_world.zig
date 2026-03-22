// the purpose of this test is just to verify that a userspace thread can run, make a syscall (write), and then exit

const lib = @import("lib");

pub fn main() void {
    lib.syscall.write("Hello from userspace!\n");
}
