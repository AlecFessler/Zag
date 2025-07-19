const console = @import("console.zig");

export fn kmain() callconv(.C) void {
    console.initialize(.LightGray, .Black);
    console.clear();
    console.print("Hello world from {s}!\n", .{"KosmOS"});
    while (true) {}
}
