const std = @import("std");

const sqlite = @import("sqlite.zig");
const types = @import("types.zig");
const walk_mod = @import("walk.zig");
const tokens_mod = @import("tokens.zig");
const ast_pass = @import("ast_pass.zig");
const sync_mod = @import("sync.zig");
const writer_mod = @import("writer.zig");
const ir_pass = @import("ir_pass.zig");
const bin_pass = @import("bin_pass.zig");

const SCHEMA_SQL = @embedFile("schema.sql");

const Args = struct {
    kernel_root: []const u8 = "kernel",
    out_path: []const u8 = "callgraph.db",
    arch: []const u8 = "x86_64",
    commit_sha: []const u8 = "unknown",
    ir_path: ?[]const u8 = null,
    elf_path: ?[]const u8 = null,
    n_jobs: u32 = 0, // 0 → auto-detect

    fn parse(allocator: std.mem.Allocator) !Args {
        var a: Args = .{};
        var it = try std.process.argsWithAllocator(allocator);
        defer it.deinit();
        _ = it.next(); // skip program name
        while (it.next()) |arg| {
            if (std.mem.eql(u8, arg, "--kernel-root")) {
                a.kernel_root = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
            } else if (std.mem.eql(u8, arg, "--out")) {
                a.out_path = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
            } else if (std.mem.eql(u8, arg, "--arch")) {
                a.arch = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
            } else if (std.mem.eql(u8, arg, "--commit-sha")) {
                a.commit_sha = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
            } else if (std.mem.eql(u8, arg, "--ir")) {
                a.ir_path = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
            } else if (std.mem.eql(u8, arg, "--elf")) {
                a.elf_path = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
            } else if (std.mem.eql(u8, arg, "--jobs")) {
                a.n_jobs = try std.fmt.parseInt(u32, it.next() orelse return error.MissingValue, 10);
            } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
                std.debug.print(
                    \\usage: indexer [opts]
                    \\  --kernel-root <dir>   default: kernel
                    \\  --out <path>          default: callgraph.db
                    \\  --arch <name>         default: x86_64
                    \\  --commit-sha <sha>    default: unknown
                    \\  --ir <path>           pre-opt LLVM IR file (zig-out/kernel.<arch>.ll)
                    \\  --elf <path>          final kernel ELF for DWARF + objdump (zig-out/kernel.<arch>.elf)
                    \\  --jobs <n>            default: ncpu
                    \\
                , .{});
                std.process.exit(0);
            } else {
                std.debug.print("unknown arg: {s}\n", .{arg});
                return error.UnknownArg;
            }
        }
        return a;
    }
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var arg_arena = std.heap.ArenaAllocator.init(gpa);
    defer arg_arena.deinit();
    const args = try Args.parse(arg_arena.allocator());

    const t_start = std.time.milliTimestamp();
    std.log.info("indexer starting: kernel_root={s} arch={s} sha={s}", .{ args.kernel_root, args.arch, args.commit_sha });

    // ── Stage 0: walk source tree ──────────────────────────────────────────
    var walk_result = try walk_mod.walk(gpa, args.kernel_root);
    defer walk_result.deinit();
    std.log.info("stage 0: {d} files, {d} modules", .{ walk_result.files.len, walk_result.modules.len });

    // Pipeline arena: lifetime spans the entire ingest. Wrapped for safe
    // multi-thread use by workers + writer. Deinit'd at end of main, after the
    // writer thread has joined, so any slice referenced by an in-flight job
    // remains valid until then.
    var pipeline_arena = std.heap.ArenaAllocator.init(gpa);
    defer pipeline_arena.deinit();
    var ts_arena: std.heap.ThreadSafeAllocator = .{ .child_allocator = pipeline_arena.allocator() };
    const palloc = ts_arena.allocator();

    // ── Bootstrap DB ───────────────────────────────────────────────────────
    const tmp_path = try std.fmt.allocPrintSentinel(arg_arena.allocator(), "{s}.tmp", .{args.out_path}, 0);
    std.fs.cwd().deleteFile(tmp_path) catch {}; // ignore if absent

    var db = try sqlite.Db.open(tmp_path);
    defer db.close();
    try db.exec(SCHEMA_SQL);

    // ── Spawn writer thread ────────────────────────────────────────────────
    var channel = try writer_mod.Channel.init(gpa, 256);
    defer channel.deinit();

    var w: writer_mod.Writer = .{ .db = &db, .channel = &channel };
    const writer_thread = try std.Thread.spawn(.{}, writer_mod.Writer.run, .{&w});

    // ── Send Stage 0 outputs to writer ─────────────────────────────────────
    try channel.send(.{ .modules = walk_result.modules });
    try channel.send(.{ .files = walk_result.files });
    for (walk_result.files, 0..) |f, i| {
        try channel.send(.{
            .file_line_index = .{
                .file_id = f.id,
                .byte_starts = walk_result.line_indices[i],
            },
        });
    }

    // ── Stages 1+2: parallel tokenize + AST per file ───────────────────────
    const n_jobs: u32 = if (args.n_jobs == 0)
        @intCast(@max(1, std.Thread.getCpuCount() catch 4))
    else
        args.n_jobs;

    var pool: std.Thread.Pool = undefined;
    try pool.init(.{ .allocator = gpa, .n_jobs = n_jobs });
    defer pool.deinit();

    // Per-file results (indexed by file_id) — fixed-size, no resizing.
    const per_file = try gpa.alloc(WorkerResult, walk_result.files.len);
    defer gpa.free(per_file);
    for (per_file) |*r| r.* = .empty;

    var shared: SharedState = .{ .next_node_id = std.atomic.Value(u64).init(1) };

    var wg: std.Thread.WaitGroup = .{};
    for (walk_result.files, 0..) |*file, i| {
        pool.spawnWg(&wg, processFile, .{
            palloc,
            &channel,
            file,
            walk_result.modules[file.module_id].qualified_name,
            &shared,
            &per_file[i],
        });
    }
    pool.waitAndWork(&wg);
    const total_ast_nodes = shared.next_node_id.load(.monotonic) - 1;
    std.log.info("stages 1+2: parallel pass complete ({d} ast nodes)", .{total_ast_nodes});

    // ── Stage 2.5: resolve provisional entities → final IDs ────────────────
    var total_provisional: usize = 0;
    for (per_file) |r| total_provisional += r.entities.len;
    const merged = try palloc.alloc(types.ProvisionalEntity, total_provisional);
    {
        var idx: usize = 0;
        for (per_file) |r| {
            @memcpy(merged[idx..][0..r.entities.len], r.entities);
            idx += r.entities.len;
        }
    }

    const resolve_result = try sync_mod.resolve(palloc, merged);
    std.log.info("stage 2.5: {d} provisional → {d} final entities, {d} ast backfills", .{
        total_provisional,
        resolve_result.final_entities.len,
        resolve_result.ast_backfill.len,
    });

    try channel.send(.{ .entities = resolve_result.final_entities });
    if (resolve_result.ast_backfill.len > 0) {
        try channel.send(.{ .ast_entity_backfill = resolve_result.ast_backfill });
    }

    // ── Stage 3: LLVM IR + callgraph ──────────────────────────────────────
    var ir_fns_count: usize = 0;
    var ir_calls_count: usize = 0;
    var ast_only_count: usize = 0;

    if (args.ir_path) |ir_path| {
        // Build qualified-name → entity_id lookup map for IR resolution.
        var qmap: std.StringHashMapUnmanaged(u32) = .empty;
        try qmap.ensureTotalCapacity(palloc, @intCast(resolve_result.final_entities.len * 2));
        for (resolve_result.final_entities) |e| {
            // Last write wins on dup; entity table dedups already, but defensively skip.
            try qmap.put(palloc, e.qualified_name, e.id);
            // Zig keyword-fn names appear in the AST as `@"suspend"` but
            // come out of LLVM IR as plain `suspend`. Insert an
            // unquoted alias so ir_pass lookups resolve either form.
            if (std.mem.indexOf(u8, e.qualified_name, "@\"") != null) {
                const stripped = try stripZigQuotes(palloc, e.qualified_name);
                try qmap.put(palloc, stripped, e.id);
            }
        }

        const ir_result = try ir_pass.pass(palloc, ir_path, &qmap);
        ir_fns_count = ir_result.ir_fns.len;
        ir_calls_count = ir_result.ir_calls.len;
        std.log.info("stage 3: parsed IR — {d} ir_fn, {d} ir_call rows", .{ ir_fns_count, ir_calls_count });

        if (ir_result.ir_fns.len > 0) {
            try channel.send(.{ .ir_fns = ir_result.ir_fns });
        }
        if (ir_result.ir_calls.len > 0) {
            try channel.send(.{ .ir_calls = ir_result.ir_calls });
        }

        // Mark fn-kind entities lacking an ir_fn match as is_ast_only.
        const ast_only_sql: [:0]const u8 = "UPDATE entity SET is_ast_only = 1 WHERE kind = 'fn' AND id NOT IN (SELECT entity_id FROM ir_fn)";
        try channel.send(.{ .raw_sql = ast_only_sql });

        // Count for the meta row (cheap re-walk of the map).
        for (resolve_result.final_entities) |e| {
            if (!std.mem.eql(u8, e.kind, "fn")) continue;
            if (!ir_result.has_ir_define.contains(e.id)) ast_only_count += 1;
        }
    } else {
        std.log.info("stage 3: skipped (no --ir argument)", .{});
    }

    // ── Stage 4: DWARF + objdump (if --elf given) ─────────────────────────
    var bin_symbols_count: usize = 0;
    var bin_insts_count: usize = 0;
    var dwarf_lines_count: usize = 0;
    if (args.elf_path) |elf_path| {
        // Build qmap if not already (in the no-IR path we wouldn't have one).
        var qmap_local: std.StringHashMapUnmanaged(u32) = .empty;
        try qmap_local.ensureTotalCapacity(palloc, @intCast(resolve_result.final_entities.len));
        for (resolve_result.final_entities) |e| try qmap_local.put(palloc, e.qualified_name, e.id);

        // Build basename → file_id map for DWARF line resolution.
        var basemap: std.StringHashMapUnmanaged(u32) = .empty;
        try basemap.ensureTotalCapacity(palloc, @intCast(walk_result.files.len));
        for (walk_result.files) |f| {
            const base = std.fs.path.basename(f.path);
            try basemap.put(palloc, base, f.id);
        }

        const bin_result = try bin_pass.pass(palloc, elf_path, &qmap_local, &basemap);
        bin_symbols_count = bin_result.bin_symbols.len;
        bin_insts_count = bin_result.bin_insts.len;
        dwarf_lines_count = bin_result.dwarf_lines.len;
        std.log.info("stage 4: parsed ELF — {d} bin_symbol, {d} bin_inst, {d} dwarf_line rows", .{
            bin_symbols_count, bin_insts_count, dwarf_lines_count,
        });

        if (bin_result.bin_symbols.len > 0) try channel.send(.{ .bin_symbols = bin_result.bin_symbols });
        if (bin_result.bin_insts.len > 0) try channel.send(.{ .bin_insts = bin_result.bin_insts });
        if (bin_result.dwarf_lines.len > 0) try channel.send(.{ .dwarf_lines = bin_result.dwarf_lines });
    } else {
        std.log.info("stage 4: skipped (no --elf argument)", .{});
    }

    // ── Stage 5: entry_point discovery + entry_reaches BFS ────────────────
    //
    //   - exception: fns in kernel/arch/<arch>/exceptions.zig whose short
    //     name matches the EXCEPTION_ENTRY_NAMES list (the handler set
    //     genlock and other consumers expect).
    //   - irq: fns in kernel/arch/<arch>/irq.zig named schedTimerHandler.
    //   - syscall: every fn called directly from `syscall.dispatch.dispatch`'s
    //     switch table — i.e. the actual real syscalls. Walking the
    //     dispatch arms via ir_call gives us the exact 57 handlers
    //     (one per SyscallNum enum value) instead of the older
    //     "every pub fn in syscall/*.zig" overcount that pulled in
    //     ~16 private helpers.
    //   - boot: main.kEntry.
    const entry_sql: [:0]const u8 =
        \\INSERT INTO entry_point (entity_id, kind, label)
        \\SELECT e.id, 'exception', e.qualified_name
        \\FROM entity e JOIN file f ON f.id = e.def_file_id
        \\WHERE e.kind = 'fn'
        \\  AND f.path LIKE 'arch/%/exceptions.zig'
        \\  AND (e.qualified_name LIKE '%.exceptionHandler'
        \\       OR e.qualified_name LIKE '%.pageFaultHandler'
        \\       OR e.qualified_name LIKE '%.handleSyncLowerEl'
        \\       OR e.qualified_name LIKE '%.handleIrqLowerEl'
        \\       OR e.qualified_name LIKE '%.handleSyncCurrentEl'
        \\       OR e.qualified_name LIKE '%.handleIrqCurrentEl'
        \\       OR e.qualified_name LIKE '%.handleUnexpected'
        \\       OR e.qualified_name LIKE '%.dispatchIrq'
        \\       OR e.qualified_name LIKE '%.schedTimerHandler');
        \\INSERT INTO entry_point (entity_id, kind, label)
        \\SELECT e.id, 'irq', e.qualified_name
        \\FROM entity e JOIN file f ON f.id = e.def_file_id
        \\WHERE e.kind = 'fn'
        \\  AND f.path LIKE 'arch/%/irq.zig'
        \\  AND e.qualified_name LIKE '%.schedTimerHandler';
        \\INSERT INTO entry_point (entity_id, kind, label)
        \\SELECT e.id, 'boot', e.qualified_name FROM entity e
        \\WHERE e.kind = 'fn' AND e.qualified_name = 'main.kEntry';
        \\INSERT INTO entry_point (entity_id, kind, label)
        \\SELECT DISTINCT callee.id, 'syscall', callee.qualified_name
        \\FROM ir_call ic
        \\JOIN entity caller ON caller.id = ic.caller_entity_id
        \\JOIN entity callee ON callee.id = ic.callee_entity_id
        \\WHERE caller.qualified_name = 'syscall.dispatch.dispatch'
        \\  AND callee.qualified_name LIKE 'syscall.%'
        \\  AND callee.kind = 'fn';
    ;
    try channel.send(.{ .raw_sql = entry_sql });

    // Cross-module slab-backed propagation: a `pub const X = SecureSlab(T, N)`
    // alias was marked is_slab_backed=1 in the AST pass; T may live in a
    // different module. We extract T's short name from the alias entity's
    // initializer source bytes and mark every entity whose qualified_name
    // ends with `.<T>` as slab-backed too. This is the second prong of
    // Gap #1 in the genlock plan — keeps slab-backed-type discovery
    // consistent with the legacy tokenizer-based analyzer.
    const slab_propagate_sql: [:0]const u8 =
        \\WITH alias_inits AS (
        \\    SELECT e.id AS alias_id,
        \\           CAST(substr(f.source, e.def_byte_start + 1, e.def_byte_end - e.def_byte_start) AS TEXT) AS init_text
        \\    FROM entity e
        \\    JOIN file f ON f.id = e.def_file_id
        \\    WHERE e.is_slab_backed = 1
        \\),
        \\extracted AS (
        \\    SELECT alias_id,
        \\           init_text,
        \\           instr(init_text, 'SecureSlab(') AS open_pos
        \\    FROM alias_inits
        \\    WHERE instr(init_text, 'SecureSlab(') > 0
        \\),
        \\arg_text AS (
        \\    SELECT alias_id,
        \\           substr(init_text, open_pos + length('SecureSlab(')) AS rest
        \\    FROM extracted
        \\),
        \\inner_name AS (
        \\    SELECT alias_id,
        \\           CASE
        \\               WHEN instr(rest, ',') > 0 AND instr(rest, ',') < instr(rest, ')') THEN
        \\                   trim(substr(rest, 1, instr(rest, ',') - 1))
        \\               ELSE
        \\                   trim(substr(rest, 1, instr(rest, ')') - 1))
        \\           END AS t_name
        \\    FROM arg_text
        \\)
        \\UPDATE entity
        \\   SET is_slab_backed = 1
        \\ WHERE id IN (
        \\     SELECT e2.id
        \\     FROM entity e2
        \\     JOIN inner_name ON
        \\         e2.qualified_name = inner_name.t_name
        \\         OR e2.qualified_name LIKE '%.' || inner_name.t_name
        \\     WHERE e2.kind IN ('const', 'var', 'type')
        \\ );
    ;
    try channel.send(.{ .raw_sql = slab_propagate_sql });

    // Link ir_call → ast_node by matching (caller's file, site_line) to the
    // leftmost call/builtin_call AST node on that line within the caller's
    // byte range. The trace renderer walks ast_edge upward from this node to
    // find the enclosing if/else/while/for/switch_prong/block and draws the
    // control-flow structure of each call site. Without this link the trace
    // is just a flat list of callees.
    const link_ast_sql: [:0]const u8 =
        \\CREATE TEMP TABLE ast_call_lines AS
        \\SELECT n.id AS node_id, n.file_id, n.byte_start,
        \\       (SELECT MAX(line) FROM file_line_index fli
        \\          WHERE fli.file_id = n.file_id AND fli.byte_start <= n.byte_start) AS line
        \\  FROM ast_node n
        \\ WHERE n.kind IN ('call', 'builtin_call');
        \\CREATE INDEX ast_call_lines_idx ON ast_call_lines(file_id, line, byte_start);
        \\UPDATE ir_call
        \\   SET ast_node_id = (
        \\       SELECT acl.node_id FROM ast_call_lines acl
        \\        JOIN entity e ON e.id = ir_call.caller_entity_id
        \\        WHERE acl.file_id  = e.def_file_id
        \\          AND acl.line     = ir_call.site_line
        \\          AND acl.byte_start >= e.def_byte_start
        \\          AND acl.byte_start <= e.def_byte_end
        \\        ORDER BY acl.byte_start ASC LIMIT 1)
        \\ WHERE site_line > 0;
        \\DROP TABLE ast_call_lines;
    ;
    try channel.send(.{ .raw_sql = link_ast_sql });

    // BFS reachability via recursive CTE, edge-kind-filtered (per the live
    // tool's `reaches` semantics).
    const reaches_sql: [:0]const u8 =
        \\INSERT INTO entry_reaches (entry_id, entity_id, min_depth)
        \\WITH RECURSIVE walk(entry_id, entity_id, depth) AS (
        \\    SELECT entity_id, entity_id, 0 FROM entry_point
        \\    UNION
        \\    SELECT walk.entry_id, c.callee_entity_id, walk.depth + 1
        \\    FROM ir_call c JOIN walk ON c.caller_entity_id = walk.entity_id
        \\    WHERE c.callee_entity_id IS NOT NULL
        \\      AND c.call_kind IN ('direct', 'dispatch_x64', 'dispatch_aarch64')
        \\      AND walk.depth < 64
        \\)
        \\SELECT entry_id, entity_id, MIN(depth)
        \\FROM walk
        \\GROUP BY entry_id, entity_id;
    ;
    try channel.send(.{ .raw_sql = reaches_sql });

    // ── FTS5 + meta + finalize ─────────────────────────────────────────────
    try channel.send(.{ .fts_rebuild = "entity_fts" });
    try channel.send(.{ .fts_rebuild = "token_fts" });

    const elapsed_ms_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{std.time.milliTimestamp() - t_start});
    const total_files_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{walk_result.files.len});
    const total_entities_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{resolve_result.final_entities.len});
    const total_ast_nodes_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{total_ast_nodes});
    const built_at_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{std.time.timestamp()});

    try channel.send(.{ .meta = .{ .key = "arch", .value = args.arch } });
    try channel.send(.{ .meta = .{ .key = "commit_sha", .value = args.commit_sha } });
    try channel.send(.{ .meta = .{ .key = "built_at", .value = built_at_str } });
    try channel.send(.{ .meta = .{ .key = "schema_version", .value = "1" } });
    try channel.send(.{ .meta = .{ .key = "ingest_duration_ms", .value = elapsed_ms_str } });
    try channel.send(.{ .meta = .{ .key = "total_files", .value = total_files_str } });
    try channel.send(.{ .meta = .{ .key = "total_entities", .value = total_entities_str } });
    try channel.send(.{ .meta = .{ .key = "total_ast_nodes", .value = total_ast_nodes_str } });
    const ir_fns_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{ir_fns_count});
    const ir_calls_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{ir_calls_count});
    const ast_only_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{ast_only_count});
    try channel.send(.{ .meta = .{ .key = "total_ir_fns", .value = ir_fns_str } });
    try channel.send(.{ .meta = .{ .key = "total_ir_calls", .value = ir_calls_str } });
    try channel.send(.{ .meta = .{ .key = "total_ast_only", .value = ast_only_str } });
    const bin_sym_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{bin_symbols_count});
    const bin_inst_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{bin_insts_count});
    const dwarf_line_str = try std.fmt.allocPrint(arg_arena.allocator(), "{d}", .{dwarf_lines_count});
    try channel.send(.{ .meta = .{ .key = "total_bin_symbols", .value = bin_sym_str } });
    try channel.send(.{ .meta = .{ .key = "total_bin_insts", .value = bin_inst_str } });
    try channel.send(.{ .meta = .{ .key = "total_dwarf_lines", .value = dwarf_line_str } });
    // schema_complete LAST — sentinel that frontends check.
    try channel.send(.{ .meta = .{ .key = "schema_complete", .value = "true" } });

    try channel.send(.shutdown);
    channel.close();
    writer_thread.join();
    if (w.err) |e| return e;

    // ── Atomic rename .tmp → final ─────────────────────────────────────────
    db.close();
    try std.fs.cwd().rename(tmp_path, args.out_path);
    std.log.info("indexer done: {s} ({d}ms)", .{ args.out_path, std.time.milliTimestamp() - t_start });
}

const WorkerResult = struct {
    entities: []types.ProvisionalEntity,

    const empty: WorkerResult = .{ .entities = &.{} };
};

const SharedState = struct {
    next_node_id: std.atomic.Value(u64),
};

fn processFile(
    palloc: std.mem.Allocator,
    channel: *writer_mod.Channel,
    file: *const types.FileRecord,
    module_qname: []const u8,
    shared: *SharedState,
    out: *WorkerResult,
) void {
    processFileInner(palloc, channel, file, module_qname, shared, out) catch |e| {
        std.log.err("worker failed on {s}: {s}", .{ file.path, @errorName(e) });
    };
}

/// Strip Zig's `@"keyword"` quoting from each segment of a qualified name
/// so the result matches what LLVM IR emits — e.g. `syscall.port.@"suspend"`
/// → `syscall.port.suspend`. Allocates the result in `palloc`; only called
/// for names that actually contain `@"`.
fn stripZigQuotes(palloc: std.mem.Allocator, qname: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < qname.len) {
        if (i + 1 < qname.len and qname[i] == '@' and qname[i + 1] == '"') {
            // Skip the opening @"
            i += 2;
            // Copy until closing "
            while (i < qname.len and qname[i] != '"') : (i += 1) {
                try out.append(palloc, qname[i]);
            }
            // Skip closing "
            if (i < qname.len) i += 1;
        } else {
            try out.append(palloc, qname[i]);
            i += 1;
        }
    }
    return try out.toOwnedSlice(palloc);
}

fn processFileInner(
    palloc: std.mem.Allocator,
    channel: *writer_mod.Channel,
    file: *const types.FileRecord,
    module_qname: []const u8,
    shared: *SharedState,
    out: *WorkerResult,
) !void {
    const token_rows = try tokens_mod.tokenize(palloc, file.source);
    try channel.send(.{ .tokens = .{ .file_id = file.id, .rows = token_rows } });

    const result = try ast_pass.pass(
        palloc,
        file.source,
        file.id,
        file.module_id,
        module_qname,
        &shared.next_node_id,
    );
    if (result.ast_nodes.len > 0) {
        try channel.send(.{ .ast_nodes = result.ast_nodes });
    }
    if (result.ast_edges.len > 0) {
        try channel.send(.{ .ast_edges = result.ast_edges });
    }
    out.* = .{ .entities = result.entities };
}
