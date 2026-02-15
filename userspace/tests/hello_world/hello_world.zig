const lib = @import("lib");

pub fn main() void {
    lib.syscall.write("Hello from userspace!\n");
}
