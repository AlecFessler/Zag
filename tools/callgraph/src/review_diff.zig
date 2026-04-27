//! Run `git diff` for a commit and parse the result into the
//! `FileHunks` shape the classifier consumes.
//!
//! Same `--unified=0` parsing logic the existing /api/diff_hunks
//! handler uses, factored out so the review pipeline doesn't need to
//! reach into server.zig. Mode is always parent-vs-commit (i.e.
//! `git diff <sha>^ <sha>`) — that's the only mode reviews care about.

const std = @import("std");

const review_classifier = @import("review_classifier.zig");

pub const Hunk = review_classifier.Hunk;
pub const FileHunks = review_classifier.FileHunks;

/// Run `git diff <sha>^ <sha>` in `git_root` and return parsed hunks.
/// Returned slices and inner strings are allocated in `alloc` (typically
/// a request-scoped arena).
pub fn fetchHunksForCommit(
    alloc: std.mem.Allocator,
    git_root: []const u8,
    sha: []const u8,
) ![]FileHunks {
    const parent = try std.fmt.allocPrint(alloc, "{s}^", .{sha});

    const argv = [_][]const u8{
        "git",
        "diff",
        "--unified=0",
        "--no-color",
        parent,
        sha,
    };

    const result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 64 * 1024 * 1024,
    }) catch |err| {
        std.debug.print(
            "review_diff: git diff {s}^ {s} failed: {s}\n",
            .{ sha, sha, @errorName(err) },
        );
        return err;
    };

    if (result.term != .Exited or (result.term.Exited != 0 and result.term.Exited != 1)) {
        std.debug.print(
            "review_diff: git diff exited unexpectedly: {any}\n",
            .{result.term},
        );
        return error.GitDiffFailed;
    }

    return parse(alloc, result.stdout);
}

/// Parse `--unified=0` output into FileHunks. Public so tests can hit
/// it without spawning git. Order of files matches their appearance in
/// the diff stream.
pub fn parse(alloc: std.mem.Allocator, stdout: []const u8) ![]FileHunks {
    var files = std.ArrayList(FileHunks){};

    var current_path: ?[]const u8 = null;
    var current_hunks = std.ArrayList(Hunk){};

    var line_it = std.mem.splitScalar(u8, stdout, '\n');
    while (line_it.next()) |line| {
        if (std.mem.startsWith(u8, line, "+++ b/")) {
            try flushFile(alloc, &files, &current_path, &current_hunks);
            current_path = try alloc.dupe(u8, line["+++ b/".len..]);
        } else if (std.mem.startsWith(u8, line, "+++ /dev/null")) {
            try flushFile(alloc, &files, &current_path, &current_hunks);
        } else if (std.mem.startsWith(u8, line, "@@")) {
            const h = parseHunkLine(line) orelse continue;
            try current_hunks.append(alloc, h);
        }
    }
    try flushFile(alloc, &files, &current_path, &current_hunks);

    return files.toOwnedSlice(alloc);
}

fn flushFile(
    alloc: std.mem.Allocator,
    files: *std.ArrayList(FileHunks),
    path_opt: *?[]const u8,
    hunks: *std.ArrayList(Hunk),
) !void {
    if (path_opt.*) |p| {
        if (hunks.items.len > 0) {
            try files.append(alloc, .{
                .path = p,
                .hunks = try alloc.dupe(Hunk, hunks.items),
            });
        }
    }
    path_opt.* = null;
    hunks.clearRetainingCapacity();
}

/// Parse one `@@ -a[,b] +c[,d] @@` line. Returns null on shape mismatch.
fn parseHunkLine(line: []const u8) ?Hunk {
    const minus_idx = std.mem.indexOfScalar(u8, line, '-') orelse return null;
    const after_minus = line[minus_idx + 1 ..];
    const old_space = std.mem.indexOfScalar(u8, after_minus, ' ') orelse return null;
    const old_range = after_minus[0..old_space];
    const old_comma = std.mem.indexOfScalar(u8, old_range, ',');
    const old_start_str = if (old_comma) |i| old_range[0..i] else old_range;
    const old_count_str: []const u8 = if (old_comma) |i| old_range[i + 1 ..] else "1";
    const old_start = std.fmt.parseInt(u32, old_start_str, 10) catch return null;
    const old_count = std.fmt.parseInt(u32, old_count_str, 10) catch 1;
    const plus_rest = after_minus[old_space + 1 ..];
    if (plus_rest.len == 0 or plus_rest[0] != '+') return null;
    const after_plus = plus_rest[1..];
    const new_space = std.mem.indexOfScalar(u8, after_plus, ' ') orelse return null;
    const new_range = after_plus[0..new_space];
    const new_comma = std.mem.indexOfScalar(u8, new_range, ',');
    const new_start_str = if (new_comma) |i| new_range[0..i] else new_range;
    const new_count_str: []const u8 = if (new_comma) |i| new_range[i + 1 ..] else "1";
    const new_start = std.fmt.parseInt(u32, new_start_str, 10) catch return null;
    const new_count = std.fmt.parseInt(u32, new_count_str, 10) catch 1;
    return .{
        .old_start = old_start,
        .old_count = old_count,
        .new_start = new_start,
        .new_count = new_count,
    };
}

// ---- Tests ---------------------------------------------------------------

const testing = std.testing;

test "parse: empty input → empty file list" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const files = try parse(arena.allocator(), "");
    try testing.expectEqual(@as(usize, 0), files.len);
}

test "parse: single file with one hunk" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const diff =
        \\diff --git a/src/foo.zig b/src/foo.zig
        \\--- a/src/foo.zig
        \\+++ b/src/foo.zig
        \\@@ -10,2 +10,3 @@ pub fn bar() void {
        \\-    foo();
        \\-    bar();
        \\+    new();
        \\+    code();
        \\+    here();
    ;
    const files = try parse(a, diff);
    try testing.expectEqual(@as(usize, 1), files.len);
    try testing.expectEqualStrings("src/foo.zig", files[0].path);
    try testing.expectEqual(@as(usize, 1), files[0].hunks.len);
    try testing.expectEqual(@as(u32, 10), files[0].hunks[0].old_start);
    try testing.expectEqual(@as(u32, 2), files[0].hunks[0].old_count);
    try testing.expectEqual(@as(u32, 10), files[0].hunks[0].new_start);
    try testing.expectEqual(@as(u32, 3), files[0].hunks[0].new_count);
}

test "parse: hunk shorthand without count means count=1" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const diff =
        \\+++ b/src/x.zig
        \\@@ -42 +42 @@
        \\-old
        \\+new
    ;
    const files = try parse(a, diff);
    try testing.expectEqual(@as(usize, 1), files.len);
    try testing.expectEqual(@as(u32, 1), files[0].hunks[0].old_count);
    try testing.expectEqual(@as(u32, 1), files[0].hunks[0].new_count);
}

test "parse: pure deletion sets new_count to 0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const diff =
        \\+++ b/src/x.zig
        \\@@ -10,3 +9,0 @@
        \\-line one
        \\-line two
        \\-line three
    ;
    const files = try parse(a, diff);
    try testing.expectEqual(@as(u32, 3), files[0].hunks[0].old_count);
    try testing.expectEqual(@as(u32, 0), files[0].hunks[0].new_count);
}

test "parse: pure insertion sets old_count to 0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const diff =
        \\+++ b/src/x.zig
        \\@@ -0,0 +1,2 @@
        \\+inserted line one
        \\+inserted line two
    ;
    const files = try parse(a, diff);
    try testing.expectEqual(@as(u32, 0), files[0].hunks[0].old_count);
    try testing.expectEqual(@as(u32, 2), files[0].hunks[0].new_count);
}

test "parse: multiple hunks in one file" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const diff =
        \\+++ b/src/x.zig
        \\@@ -10,1 +10,1 @@
        \\-old
        \\+new
        \\@@ -50,2 +50,1 @@
        \\-line a
        \\-line b
        \\+merged
    ;
    const files = try parse(a, diff);
    try testing.expectEqual(@as(usize, 1), files.len);
    try testing.expectEqual(@as(usize, 2), files[0].hunks.len);
    try testing.expectEqual(@as(u32, 10), files[0].hunks[0].new_start);
    try testing.expectEqual(@as(u32, 50), files[0].hunks[1].new_start);
}

test "parse: multiple files" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const diff =
        \\+++ b/src/a.zig
        \\@@ -1,1 +1,1 @@
        \\-x
        \\+y
        \\diff --git a/src/b.zig b/src/b.zig
        \\+++ b/src/b.zig
        \\@@ -10,1 +10,1 @@
        \\-q
        \\+r
    ;
    const files = try parse(a, diff);
    try testing.expectEqual(@as(usize, 2), files.len);
    try testing.expectEqualStrings("src/a.zig", files[0].path);
    try testing.expectEqualStrings("src/b.zig", files[1].path);
}

test "parse: deleted-file marker (+++ /dev/null) flushes prior file" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const diff =
        \\+++ b/src/keep.zig
        \\@@ -1,1 +1,1 @@
        \\-old
        \\+new
        \\diff --git a/src/gone.zig b/src/gone.zig
        \\+++ /dev/null
        \\@@ -1,3 +0,0 @@
        \\-doomed
    ;
    const files = try parse(a, diff);
    try testing.expectEqual(@as(usize, 1), files.len);
    try testing.expectEqualStrings("src/keep.zig", files[0].path);
}
