const lib = @import("lib");

const syscall = lib.syscall;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr; // Avoid unused parameter warning
    syscall.write("Hello, World!\n") catch {};

    // we might have restarted, check the perms view for existing shm handles to map

    // enumerate devices in perms view, specifically we want
    // - the nic (e1000 or x550)
    // - the nvme ssd
    // - serial port access
    // the rest can be dropped

    // spawn child processes
    // - console
    // - serial service
    // - fs service
    // - router
    // - nfs client
    // - ntp client
    // - http server

    // setup shared memory for hot reloads of child process binaries from the nfs server then enter loop
    // - channel with console
    // - channel with nfs client
}
