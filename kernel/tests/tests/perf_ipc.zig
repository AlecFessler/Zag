const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// IPC round-trip benchmark. Spawns a server and client process,
/// cap-transfers the server handle to the client. Client measures
/// ipc_call round-trips.
///
/// Variants:
///   call + recv/reply, cross-core
///   call + recv/reply, same-core
///   call + reply_recv, cross-core
///   call + reply_recv, same-core
pub fn main(_: u64) void {
    runVariant("ipc_call_reply_cross", 1, 2, 0);
    runVariant("ipc_call_reply_same", 2, 2, 0);
    runVariant("ipc_call_replyrecv_cross", 1, 2, 1);
    runVariant("ipc_call_replyrecv_same", 2, 2, 1);
    syscall.shutdown();
}

fn runVariant(name: []const u8, client_aff: u64, server_aff: u64, use_reply_recv: u64) void {
    // Spawn server
    const srv_rights = perms.ProcessRights{ .set_affinity = true };
    const srv_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_ipc_echo.ptr),
        children.child_perf_ipc_echo.len,
        srv_rights.bits(),
    );
    if (srv_rc < 0) {
        syscall.write("[PERF] ");
        syscall.write(name);
        syscall.write(" SKIP server failed\n");
        return;
    }
    const server_handle: u64 = @bitCast(srv_rc);

    // Configure server: affinity + mode
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(server_handle, &.{ server_aff, use_reply_recv }, &reply);

    // Spawn client
    const cli_rights = perms.ProcessRights{ .mem_reserve = true, .set_affinity = true };
    const cli_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_ipc_client.ptr),
        children.child_perf_ipc_client.len,
        cli_rights.bits(),
    );
    if (cli_rc < 0) {
        syscall.write("[PERF] ");
        syscall.write(name);
        syscall.write(" SKIP client failed\n");
        _ = syscall.revoke_perm(server_handle);
        return;
    }
    const client_handle: u64 = @bitCast(cli_rc);

    // Send affinity to client
    _ = syscall.ipc_call(client_handle, &.{client_aff}, &reply);

    // Cap-transfer server handle to client
    const handle_rights: u64 = (perms.ProcessHandleRights{ .send_words = true }).bits();
    _ = syscall.ipc_call_cap(client_handle, &.{ server_handle, handle_rights }, &reply);

    // Call client to get results (client blocks on ipc_recv after benchmark)
    var results: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(client_handle, &.{}, &results);

    // Emit results: min, median, mean, p99, max
    if (results.words[1] > 0) {
        emitResult(name, "min", results.words[0]);
        emitResult(name, "median", results.words[1]);
        emitResult(name, "mean", results.words[2]);
        emitResult(name, "p99", results.words[3]);
        emitResult(name, "max", results.words[4]);
    } else {
        syscall.write("[PERF] ");
        syscall.write(name);
        syscall.write(" SKIP client failed\n");
    }

    _ = syscall.revoke_perm(server_handle);
    _ = syscall.revoke_perm(client_handle);
}

fn emitResult(name: []const u8, metric: []const u8, value: u64) void {
    syscall.write("[PERF] ");
    syscall.write(name);
    syscall.write(" ");
    syscall.write(metric);
    syscall.write("=");
    t.printDec(value);
    syscall.write(" cycles\n");
}
