pub const Protocol = enum(u8) {
    display = 1,
    keyboard = 2,
    mouse = 3,
    filesystem = 5,
    framebuffer = 6,
};
