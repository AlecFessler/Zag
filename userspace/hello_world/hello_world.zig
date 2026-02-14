fn write(msg: []const u8) void {
    asm volatile ("int $0x80"
        :
        : [_] "{rax}" (@as(u64, 0)),
          [_] "{rdi}" (@intFromPtr(msg.ptr)),
          [_] "{rsi}" (msg.len),
        : .{ .rcx = true, .r11 = true, .memory = true }
    );
}

export fn _start() noreturn {
    write("Hello from userspace!\n");
    while (true) {
        asm volatile ("pause");
    }
}
