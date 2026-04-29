//! Witnessing layer for the agent-review deps gate.
//!
//! When the daemon serves a `callgraph_src` (`/api/fn_source`) or
//! `callgraph_trace` (`/api/trace`) request from the MCP channel, we
//! record that the named symbol was viewed against every open mcp
//! review whose `deps_required` contains it.
//!
//! Only the MCP channel is gated — the human channel doesn't have a
//! deps_required list, so its review state is never touched here. The
//! daemon's request dispatcher decides whether a given call is "from
//! MCP" based on an `X-Cg-Channel: mcp` header set by the MCP shim.
//!
//! The witnessing pass walks every review file on every call. For v1
//! that's fine — review counts are bounded and per-call cost is tiny.
//! If it ever shows up in a profile, the obvious optimization is an
//! in-memory index keyed by qualified_name → list of (sha, item_id),
//! rebuilt on `_open` / `_complete` / restart.

const std = @import("std");

const review_store = @import("review_store.zig");

const Store = review_store.Store;
const ReviewState = review_store.ReviewState;

/// Record `qualified_name` as viewed against every in-progress mcp
/// review's items whose `deps_required` mentions it. Idempotent: a
/// repeat call for the same name is a no-op once recorded. Only
/// rewrites the JSON for reviews that actually changed.
///
/// `alloc` should be a request-scoped arena. Errors loading or saving
/// individual review files are logged but do not abort the pass — we
/// keep going so one corrupt file can't block witnessing for the rest.
pub fn recordView(
    alloc: std.mem.Allocator,
    store: *const Store,
    qualified_name: []const u8,
) !void {
    const shas = try store.listShas(alloc);
    for (shas) |sha| {
        recordViewForSha(alloc, store, sha, qualified_name) catch |err| {
            std.debug.print(
                "review witness: skip sha={s}: {s}\n",
                .{ sha, @errorName(err) },
            );
        };
    }
}

fn recordViewForSha(
    alloc: std.mem.Allocator,
    store: *const Store,
    sha: []const u8,
    qualified_name: []const u8,
) !void {
    var state = (try store.load(alloc, sha)) orelse return;
    const ch_opt = state.channels.mcp;
    if (ch_opt == null) return;
    var ch = ch_opt.?;
    if (ch.status != .in_progress) return;

    var dirty = false;

    // Append to the channel-level session log so a *future* _deps call
    // that pulls this qname into a different item's deps_required can
    // retro-fill its deps_viewed. Without this, viewing `enqueue`
    // under enqueueOnCore wouldn't satisfy the gate for
    // pickCoreForAffinity (which only learns enqueue is a dep when
    // _deps gets called for it). De-dup before appending.
    var in_session = false;
    for (ch.deps_viewed_session) |v| {
        if (std.mem.eql(u8, v, qualified_name)) {
            in_session = true;
            break;
        }
    }
    if (!in_session) {
        const new_session = try alloc.alloc([]const u8, ch.deps_viewed_session.len + 1);
        @memcpy(new_session[0..ch.deps_viewed_session.len], ch.deps_viewed_session);
        new_session[ch.deps_viewed_session.len] = try alloc.dupe(u8, qualified_name);
        ch.deps_viewed_session = new_session;
        dirty = true;
    }

    for (ch.items) |*item_ptr| {
        const required = item_ptr.deps_required orelse continue;

        var required_here = false;
        for (required) |r| {
            if (std.mem.eql(u8, r, qualified_name)) {
                required_here = true;
                break;
            }
        }
        if (!required_here) continue;

        var already_viewed = false;
        for (item_ptr.deps_viewed) |v| {
            if (std.mem.eql(u8, v, qualified_name)) {
                already_viewed = true;
                break;
            }
        }
        if (already_viewed) continue;

        // Append to deps_viewed. The deps_viewed slice is owned by the
        // load arena, so we have to allocate a new one — can't push.
        const new_viewed = try alloc.alloc([]const u8, item_ptr.deps_viewed.len + 1);
        @memcpy(new_viewed[0..item_ptr.deps_viewed.len], item_ptr.deps_viewed);
        new_viewed[item_ptr.deps_viewed.len] = try alloc.dupe(u8, qualified_name);
        item_ptr.deps_viewed = new_viewed;
        dirty = true;
    }

    if (!dirty) return;
    state.channels.mcp = ch;
    try store.save(alloc, &state);
}

// ---- Tests ---------------------------------------------------------------

const testing = std.testing;

const Item = review_store.Item;

fn tmpStore(alloc: std.mem.Allocator) !struct {
    tmp: std.testing.TmpDir,
    git_root: []u8,
    store: Store,
} {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    const git_root = try tmp.dir.realpathAlloc(alloc, ".");
    return .{ .tmp = tmp, .git_root = git_root, .store = Store.init(git_root) };
}

fn seedReview(
    alloc: std.mem.Allocator,
    store: *const Store,
    sha: []const u8,
    items: []Item,
) !void {
    const state = ReviewState{
        .sha = sha,
        .subject = "test",
        .channels = .{
            .mcp = .{
                .status = .in_progress,
                .started_at = 1700000000,
                .agent_model = "test-model",
                .items = items,
            },
        },
    };
    try store.save(alloc, &state);
}

test "recordView: no reviews → no-op" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try recordView(arena.allocator(), &ts.store, "any.symbol");
}

test "recordView: appends qname to matching item's deps_viewed" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = "abcdef000001";
    const required = try a.dupe([]const u8, &.{ "foo.callerOne", "foo.callerTwo" });
    var items = [_]Item{.{
        .id = "sym:foo.bar",
        .kind = .symbol_body,
        .deps_kind = .callers,
        .file = "src/foo.zig",
        .loc = "L10-L20",
        .qualified_name = "foo.bar",
        .deps_required = required,
        .deps_viewed = &.{},
    }};
    try seedReview(a, &ts.store, sha, &items);

    try recordView(a, &ts.store, "foo.callerOne");

    const reloaded = (try ts.store.load(a, sha)) orelse return error.MissingState;
    const ch = reloaded.channels.mcp.?;
    try testing.expectEqual(@as(usize, 1), ch.items[0].deps_viewed.len);
    try testing.expectEqualStrings("foo.callerOne", ch.items[0].deps_viewed[0]);
}

test "recordView: idempotent — repeat call doesn't double-add" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = "abcdef000002";
    const required = try a.dupe([]const u8, &.{"foo.callerOne"});
    var items = [_]Item{.{
        .id = "sym:foo.bar",
        .kind = .symbol_body,
        .deps_kind = .callers,
        .file = "src/foo.zig",
        .loc = "L10-L20",
        .qualified_name = "foo.bar",
        .deps_required = required,
        .deps_viewed = &.{},
    }};
    try seedReview(a, &ts.store, sha, &items);

    try recordView(a, &ts.store, "foo.callerOne");
    try recordView(a, &ts.store, "foo.callerOne");
    try recordView(a, &ts.store, "foo.callerOne");

    const reloaded = (try ts.store.load(a, sha)) orelse return error.MissingState;
    try testing.expectEqual(@as(usize, 1), reloaded.channels.mcp.?.items[0].deps_viewed.len);
}

test "recordView: no match → does not modify file" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = "abcdef000003";
    const required = try a.dupe([]const u8, &.{"foo.callerOne"});
    var items = [_]Item{.{
        .id = "sym:foo.bar",
        .kind = .symbol_body,
        .deps_kind = .callers,
        .file = "src/foo.zig",
        .loc = "L10-L20",
        .qualified_name = "foo.bar",
        .deps_required = required,
        .deps_viewed = &.{},
    }};
    try seedReview(a, &ts.store, sha, &items);

    try recordView(a, &ts.store, "unrelated.symbol");

    const reloaded = (try ts.store.load(a, sha)) orelse return error.MissingState;
    try testing.expectEqual(@as(usize, 0), reloaded.channels.mcp.?.items[0].deps_viewed.len);
}

test "recordView: completed channels are skipped" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = "abcdef000004";
    const required = try a.dupe([]const u8, &.{"foo.callerOne"});
    var items = [_]Item{.{
        .id = "sym:foo.bar",
        .kind = .symbol_body,
        .deps_kind = .callers,
        .file = "src/foo.zig",
        .loc = "L10-L20",
        .qualified_name = "foo.bar",
        .deps_required = required,
        .deps_viewed = &.{},
        .checked_off = true,
    }};
    const state = ReviewState{
        .sha = sha,
        .subject = "test",
        .channels = .{
            .mcp = .{
                .status = .complete,
                .started_at = 1700000000,
                .completed_at = 1700001000,
                .agent_model = "test-model",
                .items = &items,
                .summary = "done",
            },
        },
    };
    try ts.store.save(a, &state);
    try ts.store.writeSummary(a, sha, .mcp, "done");

    try recordView(a, &ts.store, "foo.callerOne");

    const reloaded = (try ts.store.load(a, sha)) orelse return error.MissingState;
    try testing.expectEqual(@as(usize, 0), reloaded.channels.mcp.?.items[0].deps_viewed.len);
}

test "recordView: items with null deps_required are skipped (deps not yet computed)" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = "abcdef000005";
    var items = [_]Item{.{
        .id = "sym:foo.bar",
        .kind = .symbol_body,
        .deps_kind = .callers,
        .file = "src/foo.zig",
        .loc = "L10-L20",
        .qualified_name = "foo.bar",
        .deps_required = null,
        .deps_viewed = &.{},
    }};
    try seedReview(a, &ts.store, sha, &items);

    try recordView(a, &ts.store, "foo.callerOne");

    const reloaded = (try ts.store.load(a, sha)) orelse return error.MissingState;
    try testing.expect(reloaded.channels.mcp.?.items[0].deps_required == null);
    try testing.expectEqual(@as(usize, 0), reloaded.channels.mcp.?.items[0].deps_viewed.len);
}

test "recordView: appends to deps_viewed_session even when no item requires it yet" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = "abcdef000007";
    var items = [_]Item{.{
        .id = "sym:foo.bar",
        .kind = .symbol_body,
        .deps_kind = .callers,
        .file = "src/foo.zig",
        .loc = "L10-L20",
        .qualified_name = "foo.bar",
        .deps_required = null,
        .deps_viewed = &.{},
    }};
    try seedReview(a, &ts.store, sha, &items);

    try recordView(a, &ts.store, "shared.dep");

    const reloaded = (try ts.store.load(a, sha)) orelse return error.MissingState;
    const ch = reloaded.channels.mcp.?;
    try testing.expectEqual(@as(usize, 1), ch.deps_viewed_session.len);
    try testing.expectEqualStrings("shared.dep", ch.deps_viewed_session[0]);
    // The item's per-item deps_viewed stays empty (deps_required is null,
    // so per-item fan-out can't apply).
    try testing.expectEqual(@as(usize, 0), ch.items[0].deps_viewed.len);
}

test "recordView: deps_viewed_session de-duplicates across calls" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = "abcdef000008";
    var items = [_]Item{.{
        .id = "sym:foo.bar",
        .kind = .symbol_body,
        .deps_kind = .callers,
        .file = "src/foo.zig",
        .loc = "L10-L20",
        .qualified_name = "foo.bar",
        .deps_required = null,
        .deps_viewed = &.{},
    }};
    try seedReview(a, &ts.store, sha, &items);

    try recordView(a, &ts.store, "x");
    try recordView(a, &ts.store, "y");
    try recordView(a, &ts.store, "x");

    const reloaded = (try ts.store.load(a, sha)) orelse return error.MissingState;
    try testing.expectEqual(@as(usize, 2), reloaded.channels.mcp.?.deps_viewed_session.len);
}

test "recordView: matches across multiple items in same review" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const sha = "abcdef000006";
    const required_a = try a.dupe([]const u8, &.{ "shared.dep", "exclusive.a" });
    const required_b = try a.dupe([]const u8, &.{ "shared.dep", "exclusive.b" });
    var items = [_]Item{
        .{
            .id = "sym:foo.a",
            .kind = .symbol_body,
            .deps_kind = .callers,
            .file = "src/foo.zig",
            .loc = "L10-L20",
            .qualified_name = "foo.a",
            .deps_required = required_a,
            .deps_viewed = &.{},
        },
        .{
            .id = "sym:foo.b",
            .kind = .symbol_body,
            .deps_kind = .callers,
            .file = "src/foo.zig",
            .loc = "L30-L40",
            .qualified_name = "foo.b",
            .deps_required = required_b,
            .deps_viewed = &.{},
        },
    };
    try seedReview(a, &ts.store, sha, &items);

    try recordView(a, &ts.store, "shared.dep");

    const reloaded = (try ts.store.load(a, sha)) orelse return error.MissingState;
    const it = reloaded.channels.mcp.?.items;
    try testing.expectEqual(@as(usize, 1), it[0].deps_viewed.len);
    try testing.expectEqual(@as(usize, 1), it[1].deps_viewed.len);
    try testing.expectEqualStrings("shared.dep", it[0].deps_viewed[0]);
    try testing.expectEqualStrings("shared.dep", it[1].deps_viewed[0]);
}
