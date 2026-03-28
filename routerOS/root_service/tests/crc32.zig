const lib = @import("lib");

const crc32 = lib.crc32;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("crc32 checksums");
    testKnownVector();
    testEmptyInput();
    testSingleByte();
    testIncremental();
    testDetectsCorruption();
}

fn testKnownVector() void {
    const result = crc32.compute("123456789");
    if (result == 0xCBF43926) {
        t.pass("crc32: \"123456789\" = 0xCBF43926 (standard test vector)");
    } else {
        t.fail("crc32: known vector mismatch");
    }
}

fn testEmptyInput() void {
    const result = crc32.compute("");
    if (result == 0x00000000) {
        t.pass("crc32: empty input = 0x00000000");
    } else {
        t.fail("crc32: empty input mismatch");
    }
}

fn testSingleByte() void {
    const result = crc32.compute("a");
    if (result == 0xE8B7BE43) {
        t.pass("crc32: \"a\" = 0xE8B7BE43");
    } else {
        t.fail("crc32: single byte mismatch");
    }
}

fn testIncremental() void {
    const full = crc32.compute("hello world");
    var partial = crc32.update(0xFFFFFFFF, "hello ");
    partial = crc32.update(partial, "world");
    const incremental = partial ^ 0xFFFFFFFF;
    if (full == incremental) {
        t.pass("crc32: incremental update matches full compute");
    } else {
        t.fail("crc32: incremental mismatch");
    }
}

fn testDetectsCorruption() void {
    var data = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    const original = crc32.compute(&data);
    data[2] = 'x';
    const corrupted = crc32.compute(&data);
    if (original != corrupted) {
        t.pass("crc32: detects single-byte corruption");
    } else {
        t.fail("crc32: failed to detect corruption");
    }
}
