//! Per-commit graph loading.
//!
//! Manages git worktrees, runs builds, and parses the resulting IR to
//! produce per-arch graphs for arbitrary commits. State is owned per-sha
//! in a thread-safe registry. Builds run on a dedicated worker thread so
//! the accept loop is never blocked.
//!
//! Lifecycle for a sha:
//!   1. POST /api/load_commit?sha=X transitions not_loaded → building and
//!      spawns a worker.
//!   2. Worker creates worktree, runs `zig build -Demit_ir=true` per arch,
//!      walks AST, parses IR, builds Graph, serializes JSON blobs.
//!   3. On success: ready, blobs available via /api/graph?sha=X&arch=A.
//!   4. On failure: errored, with a short error_msg.
//!
//! Per-sha entries persist for the life of the server. Worktrees on disk
//! are reused across server restarts.

const std = @import("std");

const ast = @import("ast/index.zig");
const def_deps = @import("def_deps.zig");
const entry_mod = @import("entry.zig");
const ir = @import("ir/parse.zig");
const join = @import("join.zig");
const reachability = @import("reachability.zig");
const types = @import("types.zig");

const Graph = types.Graph;

pub const ArchSpec = struct {
    /// Tag passed to root build.zig (`-Darch=`).
    build_tag: []const u8,
    /// Filename suffix produced by root build.zig.
    file_tag: []const u8,
    /// Frontend-facing tag.
    api_tag: []const u8,
    target_arch: types.TargetArch,
};

pub const Status = enum {
    not_loaded,
    building,
    ready,
    errored,

    pub fn jsonStringify(self: Status, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

/// One loaded commit. Owns its arena (graph data) and gpa-allocated
/// blobs (per-arch JSON, plus the `arches` blob).
pub const Entry = struct {
    sha: []u8,
    short_sha: []u8,
    /// Absolute worktree path (e.g. /var/tmp/cg-worktrees/<sha>).
    worktree_path: []u8,
    /// Per-arch serialized graph JSON, keyed by api_tag.
    arch_blobs: std.StringHashMap([]u8),
    /// Pre-serialized `/api/arches` payload for this commit.
    arches_blob: []u8,
    /// Loaded arches in deterministic order; backs `arches_blob`.
    arches: std.ArrayList([]const u8),
    /// Default arch tag (must be a key in `arch_blobs`).
    default_arch: []u8,
    status: Status,
    /// Short, human-readable error description on failure. Owned by gpa.
    error_msg: ?[]u8,
    /// Holds the per-commit Graph + interned strings. Boxed so the
    /// allocator can outlive the Entry's location across map reallocs.
    arena: *std.heap.ArenaAllocator,
};

pub const Registry = struct {
    gpa: std.mem.Allocator,
    git_root: []const u8,
    worktree_dir: []const u8,
    arch_specs: []const ArchSpec,

    mutex: std.Thread.Mutex = .{},
    /// sha -> *Entry. Pointers are stable: entries are never moved or
    /// freed. Map can grow under the mutex.
    entries: std.StringHashMap(*Entry),

    pub fn init(
        gpa: std.mem.Allocator,
        git_root: []const u8,
        worktree_dir: []const u8,
        arch_specs: []const ArchSpec,
    ) Registry {
        return .{
            .gpa = gpa,
            .git_root = git_root,
            .worktree_dir = worktree_dir,
            .arch_specs = arch_specs,
            .entries = std.StringHashMap(*Entry).init(gpa),
        };
    }

    /// Look up an entry by sha. Returns null if no load has been requested.
    /// Caller must NOT mutate; pointer is stable but inner status field
    /// may be racing with a worker thread. Hold `lockShared()` if you need
    /// a consistent snapshot of multiple fields.
    pub fn get(self: *Registry, sha: []const u8) ?*Entry {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.get(sha);
    }

    pub fn lockShared(self: *Registry) void {
        self.mutex.lock();
    }

    pub fn unlockShared(self: *Registry) void {
        self.mutex.unlock();
    }

    /// Triggers a load for `sha` if one isn't already in flight. Returns
    /// the entry pointer, with status reflecting current state. Does not
    /// block on the build.
    pub fn requestLoad(self: *Registry, sha: []const u8) !*Entry {
        self.mutex.lock();

        if (self.entries.get(sha)) |existing| {
            self.mutex.unlock();
            return existing;
        }

        // Reserve a slot. Allocate everything outside the mutex if we
        // need to release for any reason — but here we hold across the
        // small allocs and the put.
        const sha_owned = try self.gpa.dupe(u8, sha);
        errdefer self.gpa.free(sha_owned);

        const arena = try self.gpa.create(std.heap.ArenaAllocator);
        errdefer self.gpa.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(self.gpa);
        errdefer arena.deinit();

        const entry_ptr = try self.gpa.create(Entry);
        errdefer self.gpa.destroy(entry_ptr);

        entry_ptr.* = .{
            .sha = sha_owned,
            .short_sha = try self.gpa.dupe(u8, sha[0..@min(sha.len, 12)]),
            .worktree_path = try std.fs.path.join(self.gpa, &.{ self.worktree_dir, sha_owned }),
            .arch_blobs = std.StringHashMap([]u8).init(self.gpa),
            .arches_blob = try self.gpa.dupe(u8, "{\"arches\":[],\"default\":\"\"}"),
            .arches = std.ArrayList([]const u8){},
            .default_arch = try self.gpa.dupe(u8, ""),
            .status = .building,
            .error_msg = null,
            .arena = arena,
        };

        try self.entries.put(sha_owned, entry_ptr);
        self.mutex.unlock();

        // Spawn the worker. It owns the build pipeline; on completion it
        // updates entry_ptr fields under the mutex.
        const ctx = try self.gpa.create(WorkerCtx);
        ctx.* = .{ .registry = self, .entry = entry_ptr };
        const t = std.Thread.spawn(.{}, workerMain, .{ctx}) catch |err| {
            // Failed to spawn — record error directly. Hold the mutex
            // so observers see a consistent state.
            self.gpa.destroy(ctx);
            self.mutex.lock();
            entry_ptr.status = .errored;
            entry_ptr.error_msg = std.fmt.allocPrint(
                self.gpa,
                "failed to spawn worker: {s}",
                .{@errorName(err)},
            ) catch null;
            self.mutex.unlock();
            return entry_ptr;
        };
        t.detach();

        return entry_ptr;
    }
};

const WorkerCtx = struct {
    registry: *Registry,
    entry: *Entry,
};

fn workerMain(ctx: *WorkerCtx) void {
    const reg = ctx.registry;
    const entry = ctx.entry;
    defer reg.gpa.destroy(ctx);

    runLoad(reg, entry) catch |err| {
        reg.mutex.lock();
        defer reg.mutex.unlock();
        entry.status = .errored;
        if (entry.error_msg == null) {
            entry.error_msg = std.fmt.allocPrint(
                reg.gpa,
                "load failed: {s}",
                .{@errorName(err)},
            ) catch null;
        }
        return;
    };
}

fn runLoad(reg: *Registry, entry: *Entry) !void {
    // 1. Ensure worktree exists.
    try ensureWorktree(reg.gpa, reg.git_root, entry);

    const kernel_root_in_worktree = try std.fs.path.join(
        reg.gpa,
        &.{ entry.worktree_path, "kernel" },
    );
    defer reg.gpa.free(kernel_root_in_worktree);

    const ir_dir_in_worktree = try std.fs.path.join(
        reg.gpa,
        &.{ entry.worktree_path, "zig-out" },
    );
    defer reg.gpa.free(ir_dir_in_worktree);

    // 2. Preflight: this commit's build.zig must support -Demit_ir for us
    //    to get any IR back. Commits older than the callgraph scaffold
    //    (`207770e`) lack the option and would fail with `invalid option:
    //    -Demit_ir` — distinguish that from real compile failures so the
    //    UI can surface a clear "predates callgraph tool" message instead
    //    of the generic "no arches built successfully".
    if (!hasEmitIrOption(reg.gpa, entry.worktree_path)) {
        reg.mutex.lock();
        entry.error_msg = try reg.gpa.dupe(
            u8,
            "commit predates the -Demit_ir build option (no callgraph support)",
        );
        entry.status = .errored;
        reg.mutex.unlock();
        return;
    }

    // 2b. Pre-built userspace ELFs (root_service.elf etc.) live under
    //     `tests/tests/bin/` and `tests/prof/bin/` of the kernel repo.
    //     The top-level kernel build merely *installs* them; sub-project
    //     builds populate them. Worktrees never run sub-project builds,
    //     so the kernel build's install step would fail with
    //     `unable to update file from 'tests/tests/bin/root_service.elf'
    //     ... FileNotFound`. Copy the current main-repo binaries into
    //     the worktree before building. This is a workaround — the IR
    //     we emit reflects the worktree's *kernel* source, not these
    //     prebuilt userspace blobs, so a stale ELF doesn't poison the
    //     review. Any kernel-source change still produces accurate IR.
    seedPrebuiltElfs(reg.gpa, reg.git_root, entry.worktree_path) catch |err| {
        std.debug.print(
            "[commit {s}] seedPrebuiltElfs failed: {s} (build may install-fail)\n",
            .{ entry.short_sha, @errorName(err) },
        );
    };

    // 3. Build per arch — best effort. If at least one arch succeeds we
    //    treat the load as ready. We capture stderr to extract the first
    //    compile error for the user-facing error message.
    var first_build_err: ?[]u8 = null;
    defer if (first_build_err) |m| reg.gpa.free(m);

    for (reg.arch_specs) |spec| {
        buildOneArch(reg.gpa, entry.worktree_path, spec, &first_build_err) catch |err| {
            std.debug.print(
                "[commit {s}] build {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            // Continue to next arch — partial success is acceptable.
            continue;
        };
    }

    // 3. AST walk — once per worktree, shared across arches.
    const arena_alloc = entry.arena.allocator();
    const t_ast_start = std.time.milliTimestamp();
    const walk = ast.walkKernelFull(arena_alloc, kernel_root_in_worktree) catch |err| {
        const msg = try std.fmt.allocPrint(
            reg.gpa,
            "AST walk failed: {s}",
            .{@errorName(err)},
        );
        reg.mutex.lock();
        entry.error_msg = msg;
        entry.status = .errored;
        reg.mutex.unlock();
        return;
    };
    std.debug.print(
        "[commit {s}] phase ast_walk: {d}ms ({d} fns, {d} files)\n",
        .{ entry.short_sha, std.time.milliTimestamp() - t_ast_start, walk.fns.len, walk.asts.len },
    );

    // Shared across both arches: def_deps' setup state (qname index,
    // alias map, per-file line→node maps) is identical between arches.
    // The Cache is built ONCE here from the AST walk + a representative
    // Definition catalog, then both per-arch compute() calls reuse it.
    // The catalog is per-arch in principle, but `buildDefinitionList`
    // produces the same DefIds in the same order regardless of the
    // arch's ir_graph (it iterates `walk.definitions`), so a shared
    // catalog is fine. We build it now from the walk.
    const shared_definitions = try ast.buildDefinitionList(arena_alloc, walk.definitions);
    var def_deps_cache = try def_deps.Cache.init(
        arena_alloc, shared_definitions, walk.asts, walk.aliases,
    );
    defer def_deps_cache.deinit();

    // 4. Per-arch parse + join + reach.
    for (reg.arch_specs) |spec| {
        const ir_filename = try std.fmt.allocPrint(
            reg.gpa,
            "kernel.{s}.ll",
            .{spec.file_tag},
        );
        defer reg.gpa.free(ir_filename);

        const ir_path = try std.fs.path.join(reg.gpa, &.{ ir_dir_in_worktree, ir_filename });
        defer reg.gpa.free(ir_path);

        std.fs.cwd().access(ir_path, .{}) catch {
            std.debug.print(
                "[commit {s}] no IR at {s}; skipping arch\n",
                .{ entry.short_sha, ir_path },
            );
            continue;
        };

        // The IR parse must share the commit's arena: buildGraphWithStats
        // keeps references to mangled names and SourceLocs allocated by
        // ir.parse, so a separate arena would leave dangling slices once
        // it deinits. Memory grows with the IR size but caps at one
        // commit's worth — acceptable.
        const t_ir_start = std.time.milliTimestamp();
        const ir_graph = ir.parse(entry.arena, ir_path) catch |err| {
            std.debug.print(
                "[commit {s}] IR parse {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            continue;
        };
        std.debug.print(
            "[commit {s}] phase ir_parse({s}): {d}ms\n",
            .{ entry.short_sha, spec.api_tag, std.time.milliTimestamp() - t_ir_start },
        );

        const t_disc_start = std.time.milliTimestamp();
        const discovered = entry_mod.discover(
            arena_alloc,
            kernel_root_in_worktree,
            spec.build_tag,
            walk.fns,
            walk.asts,
        ) catch |err| {
            std.debug.print(
                "[commit {s}] entry.discover {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            continue;
        };
        std.debug.print(
            "[commit {s}] phase discover({s}): {d}ms\n",
            .{ entry.short_sha, spec.api_tag, std.time.milliTimestamp() - t_disc_start },
        );

        const t_join_start = std.time.milliTimestamp();
        var stats: join.JoinStats = undefined;
        var graph = join.buildGraphWithStats(
            arena_alloc,
            ir_graph,
            walk.fns,
            walk.asts,
            walk.struct_types,
            walk.aliases,
            discovered,
            spec.target_arch,
            &stats,
        ) catch |err| {
            std.debug.print(
                "[commit {s}] join {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            continue;
        };
        std.debug.print(
            "[commit {s}] phase join({s}): {d}ms ({d} graph fns)\n",
            .{ entry.short_sha, spec.api_tag, std.time.milliTimestamp() - t_join_start, graph.functions.len },
        );

        // Install the Definition catalog. We share the catalog built
        // up-front for the def_deps cache — fast and keeps DefIds
        // consistent across arches.
        graph.definitions = shared_definitions;

        const t_deps_start = std.time.milliTimestamp();
        def_deps.compute(arena_alloc, &graph, &def_deps_cache) catch |err| {
            std.debug.print(
                "[commit {s}] def_deps {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
        };
        std.debug.print(
            "[commit {s}] phase def_deps({s}): {d}ms\n",
            .{ entry.short_sha, spec.api_tag, std.time.milliTimestamp() - t_deps_start },
        );

        const t_reach_start = std.time.milliTimestamp();
        _ = reachability.compute(reg.gpa, &graph) catch {};
        std.debug.print(
            "[commit {s}] phase reach({s}): {d}ms\n",
            .{ entry.short_sha, spec.api_tag, std.time.milliTimestamp() - t_reach_start },
        );

        const t_serial_start = std.time.milliTimestamp();
        const blob = std.json.Stringify.valueAlloc(reg.gpa, graph, .{}) catch |err| {
            std.debug.print(
                "[commit {s}] serialize {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            continue;
        };
        std.debug.print(
            "[commit {s}] phase serialize({s}): {d}ms ({d} KB)\n",
            .{ entry.short_sha, spec.api_tag, std.time.milliTimestamp() - t_serial_start, blob.len / 1024 },
        );

        // Install under mutex.
        reg.mutex.lock();
        const dup_key = reg.gpa.dupe(u8, spec.api_tag) catch {
            reg.gpa.free(blob);
            reg.mutex.unlock();
            continue;
        };
        entry.arch_blobs.put(dup_key, blob) catch {
            reg.gpa.free(dup_key);
            reg.gpa.free(blob);
        };
        entry.arches.append(reg.gpa, dup_key) catch {};
        reg.mutex.unlock();

        std.debug.print(
            "[commit {s}] arch {s} ready ({d} fns)\n",
            .{ entry.short_sha, spec.api_tag, graph.functions.len },
        );
    }

    // 5. Finalize: build arches_blob + status.
    reg.mutex.lock();
    defer reg.mutex.unlock();

    if (entry.arches.items.len == 0) {
        entry.status = .errored;
        if (entry.error_msg == null) {
            // Prefer the first captured compile error over a generic
            // message. `first_build_err` is moved into entry.error_msg on
            // the success path; the `defer` only frees it if it remains
            // here.
            if (first_build_err) |msg| {
                entry.error_msg = msg;
                first_build_err = null;
            } else {
                entry.error_msg = try reg.gpa.dupe(u8, "no arches built successfully");
            }
        }
        return;
    }

    // Pick default: prefer x86_64.
    var default_idx: usize = 0;
    for (entry.arches.items, 0..) |a, i| {
        if (std.mem.eql(u8, a, "x86_64")) {
            default_idx = i;
            break;
        }
    }
    reg.gpa.free(entry.default_arch);
    entry.default_arch = try reg.gpa.dupe(u8, entry.arches.items[default_idx]);

    var buf = std.ArrayList(u8){};
    defer buf.deinit(reg.gpa);
    try buf.appendSlice(reg.gpa, "{\"arches\":[");
    for (entry.arches.items, 0..) |a, i| {
        if (i > 0) try buf.append(reg.gpa, ',');
        try buf.append(reg.gpa, '"');
        try buf.appendSlice(reg.gpa, a);
        try buf.append(reg.gpa, '"');
    }
    try buf.appendSlice(reg.gpa, "],\"default\":\"");
    try buf.appendSlice(reg.gpa, entry.default_arch);
    try buf.appendSlice(reg.gpa, "\"}");

    reg.gpa.free(entry.arches_blob);
    entry.arches_blob = try buf.toOwnedSlice(reg.gpa);
    entry.status = .ready;
}

fn ensureWorktree(
    gpa: std.mem.Allocator,
    git_root: []const u8,
    entry: *Entry,
) !void {
    // Make parent dir.
    const parent = std.fs.path.dirname(entry.worktree_path) orelse return error.InvalidWorktreePath;
    std.fs.cwd().makePath(parent) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // If worktree already exists with the right sha, reuse it.
    if (std.fs.cwd().access(entry.worktree_path, .{})) |_| {
        // Validate: HEAD inside this worktree should resolve to entry.sha.
        const head_ok = checkWorktreeHead(gpa, entry.worktree_path, entry.sha) catch false;
        if (head_ok) return;
        // Stale worktree — remove and recreate.
        try removeWorktree(gpa, git_root, entry.worktree_path);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    // Prune any stale worktree registrations before adding. Without this,
    // a worktree dir that was deleted out-of-band leaves a phantom entry
    // in `.git/worktrees/`, and `git worktree add` refuses to reuse the
    // same path.
    pruneWorktrees(gpa, git_root);

    // git worktree add --detach <path> <sha>
    const argv = [_][]const u8{
        "git",         "worktree", "add", "--detach",
        entry.worktree_path,
        entry.sha,
    };
    const result = try std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 256 * 1024,
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) {
            std.debug.print(
                "git worktree add failed (code {d}): {s}\n",
                .{ code, result.stderr },
            );
            return error.WorktreeAddFailed;
        },
        else => return error.WorktreeAddFailed,
    }
}

fn pruneWorktrees(gpa: std.mem.Allocator, git_root: []const u8) void {
    const argv = [_][]const u8{ "git", "worktree", "prune" };
    const result = std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 64 * 1024,
    }) catch return;
    gpa.free(result.stdout);
    gpa.free(result.stderr);
}

fn checkWorktreeHead(
    gpa: std.mem.Allocator,
    worktree_path: []const u8,
    expected_sha: []const u8,
) !bool {
    const argv = [_][]const u8{ "git", "rev-parse", "HEAD" };
    const result = std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = worktree_path,
        .max_output_bytes = 4096,
    }) catch return false;
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return false,
        else => return false,
    }
    const trimmed = std.mem.trim(u8, result.stdout, "\n\r \t");
    return std.mem.eql(u8, trimmed, expected_sha);
}

fn removeWorktree(
    gpa: std.mem.Allocator,
    git_root: []const u8,
    worktree_path: []const u8,
) !void {
    const argv = [_][]const u8{ "git", "worktree", "remove", "--force", worktree_path };
    const result = std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 64 * 1024,
    }) catch {
        // Fall back to rm -rf if git refuses (e.g. worktree was deleted
        // outside of git already and `prune` hasn't run).
        try std.fs.cwd().deleteTree(worktree_path);
        return;
    };
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    // Ignore exit code — failures are typical (e.g. already-pruned).
    _ = result.term;

    // Best-effort cleanup if dir lingered.
    std.fs.cwd().deleteTree(worktree_path) catch {};
}

fn buildOneArch(
    gpa: std.mem.Allocator,
    worktree_path: []const u8,
    spec: ArchSpec,
    first_err_msg: *?[]u8,
) !void {
    const arch_arg = try std.fmt.allocPrint(gpa, "-Darch={s}", .{spec.build_tag});
    defer gpa.free(arch_arg);

    const argv = [_][]const u8{
        "zig",
        "build",
        "-Dprofile=test",
        "-Demit_ir=true",
        arch_arg,
    };

    std.debug.print(
        "[commit] running build in {s}: zig build -Dprofile=test -Demit_ir=true {s}\n",
        .{ worktree_path, arch_arg },
    );

    // Capture stderr so we can extract the first compile error line for
    // the UI. stdout still inherits — it's mostly progress lines from the
    // zig build runner that the user might want to see in the server log.
    const result = std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = worktree_path,
        .max_output_bytes = 4 * 1024 * 1024,
    }) catch |err| {
        std.debug.print("zig build spawn failed: {s}\n", .{@errorName(err)});
        return error.BuildFailed;
    };
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);

    // Echo stderr to the server log so the operator can debug.
    if (result.stderr.len > 0) std.debug.print("{s}", .{result.stderr});

    switch (result.term) {
        .Exited => |code| if (code != 0) {
            // First arch's failure wins — keep it for the user-facing
            // error_msg. Subsequent arches' failures are still echoed to
            // the server log but don't overwrite the headline message.
            if (first_err_msg.* == null) {
                first_err_msg.* = extractFirstError(gpa, result.stderr) catch null;
            }
            return error.BuildFailed;
        },
        else => return error.BuildFailed,
    }
}

/// Pull the first useful error line out of `zig build` stderr. We prefer
/// compile errors (lines like `path/to/file.zig:LINE:COL: error: ...`)
/// over install errors (`error: unable to update file from 'X' to 'Y':
/// FileNotFound`) because the latter are usually downstream consequences
/// of an upstream compile failure, and the underlying compile error is
/// what the user can actually act on. Falls back to the first plain
/// `error:` line, then to the first non-empty stderr line. Result is
/// owned by the caller (gpa).
fn extractFirstError(gpa: std.mem.Allocator, stderr: []const u8) !?[]u8 {
    if (stderr.len == 0) return null;
    var first_compile_error: ?[]const u8 = null;
    var first_other_error: ?[]const u8 = null;
    var line_it = std.mem.splitScalar(u8, stderr, '\n');
    while (line_it.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0) continue;
        // Skip the noisy `the following command failed` summary.
        if (std.mem.indexOf(u8, line, "the following command") != null) continue;
        const err_idx = std.mem.indexOf(u8, line, "error:") orelse continue;
        // A compile error has the shape `<path>:<line>:<col>: error:`. We
        // look for two `:`s before the `error:` keyword as a quick proxy.
        const prefix = line[0..err_idx];
        var colons: u32 = 0;
        for (prefix) |c| if (c == ':') {
            colons += 1;
        };
        if (colons >= 2 and first_compile_error == null) {
            first_compile_error = line;
        } else if (first_other_error == null) {
            first_other_error = line;
        }
        if (first_compile_error != null) break;
    }
    const headline = first_compile_error orelse first_other_error orelse blk: {
        // No `error:` line — take the first non-empty stderr line.
        var it2 = std.mem.splitScalar(u8, stderr, '\n');
        while (it2.next()) |raw| {
            const line = std.mem.trimRight(u8, raw, "\r");
            if (line.len > 0) break :blk line;
        }
        break :blk null;
    };
    if (headline == null) return null;
    // Cap the message length so it fits comfortably in the UI.
    const max_len: usize = 240;
    const trimmed = if (headline.?.len > max_len) headline.?[0..max_len] else headline.?;
    return try gpa.dupe(u8, trimmed);
}

/// Copy pre-built userspace ELFs from the source repo's `tests/.../bin/`
/// directories into the same paths inside `worktree_path`. The kernel
/// build's install step expects these files to exist; without them we
/// can't reach the IR-emit step. We mirror two known directories used
/// by the test/profile profiles. Best-effort — any failure here is
/// logged but not fatal; the build will surface a clearer error if a
/// truly required file is missing.
fn seedPrebuiltElfs(
    gpa: std.mem.Allocator,
    git_root: []const u8,
    worktree_path: []const u8,
) !void {
    const subdirs = [_][]const u8{
        "tests/tests/bin",
        "tests/prof/bin",
    };
    for (subdirs) |sub| {
        const src_dir_path = try std.fs.path.join(gpa, &.{ git_root, sub });
        defer gpa.free(src_dir_path);
        const dst_dir_path = try std.fs.path.join(gpa, &.{ worktree_path, sub });
        defer gpa.free(dst_dir_path);

        var src_dir = std.fs.cwd().openDir(src_dir_path, .{ .iterate = true }) catch continue;
        defer src_dir.close();
        std.fs.cwd().makePath(dst_dir_path) catch continue;

        var it = src_dir.iterate();
        while (it.next() catch null) |item| {
            if (item.kind != .file) continue;
            // Only seed files that are clearly compiled binaries — ELFs
            // and the like. We don't want to overwrite source-controlled
            // files that exist in both src and worktree.
            if (!std.mem.endsWith(u8, item.name, ".elf") and
                !std.mem.endsWith(u8, item.name, ".bin")) continue;
            const src_file_path = try std.fs.path.join(gpa, &.{ src_dir_path, item.name });
            defer gpa.free(src_file_path);
            const dst_file_path = try std.fs.path.join(gpa, &.{ dst_dir_path, item.name });
            defer gpa.free(dst_file_path);
            std.fs.cwd().copyFile(src_file_path, std.fs.cwd(), dst_file_path, .{}) catch |err| {
                std.debug.print(
                    "  seed copy {s} -> {s} failed: {s}\n",
                    .{ src_file_path, dst_file_path, @errorName(err) },
                );
            };
        }
    }
}

/// True iff the worktree's `build.zig` declares the `-Demit_ir` option.
/// We grep by hand rather than parsing the file — the spelling of the
/// option declaration ("emit_ir") is stable across the kernel's history,
/// and a literal substring match is fast and tolerant of formatting.
fn hasEmitIrOption(gpa: std.mem.Allocator, worktree_path: []const u8) bool {
    const build_zig_path = std.fs.path.join(gpa, &.{ worktree_path, "build.zig" }) catch return false;
    defer gpa.free(build_zig_path);
    const file = std.fs.cwd().openFile(build_zig_path, .{}) catch return false;
    defer file.close();
    const contents = file.readToEndAlloc(gpa, 4 * 1024 * 1024) catch return false;
    defer gpa.free(contents);
    return std.mem.indexOf(u8, contents, "emit_ir") != null;
}
