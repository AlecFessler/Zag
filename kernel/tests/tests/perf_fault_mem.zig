const children = @import("embedded_children");
const lib = @import("lib");

const bench = lib.bench;
const perms = lib.perms;
const syscall = lib.syscall;

/// fault_read_mem / fault_write_mem benchmark. Measures the cross-
/// address-space memory access primitive at various sizes. These are
/// the debugger / tracer / JIT-instrumentation hot path, and their cost
/// breaks into two components: a per-call overhead (rights check +
/// process lookup + page-walk setup) and a per-byte throughput (memcpy
/// through the kernel's physmap after resolving each user VA to a
/// physical page).
///
/// Sizes: 8 bytes (single word), 64 (one cache line), 512 (half page),
/// 4096 (one full page), 16384 (four pages — tests the per-page loop).
///
/// The child only needs to exist and stay alive — it doesn't need to
/// be faulted. fault_read_mem / fault_write_mem work on any process
/// the caller holds with `fault_handler` right (kernel/syscall/
/// fault.zig:383, 426), and don't touch thread state.
pub fn main(_: u64) void {
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    };
    const ch_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_fault_int3.ptr),
        children.child_perf_fault_int3.len,
        child_rights.bits(),
    );
    if (ch_rc < 0) {
        syscall.write("[PERF] fault_mem SKIP proc_create failed\n");
        syscall.shutdown();
    }
    cached_ch = @bitCast(ch_rc);

    // Round 1: cap-transfer fault_handler so our handle gains the bit.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(cached_ch, &.{}, &reply);

    // The child is now looping on int3 and will fault repeatedly. We
    // want the child *not* running while we measure remote-mem cost —
    // otherwise fault delivery interferes with cycle counting. Let the
    // child fault once, then leave it blocked by NOT replying. The
    // child's main thread sits in .faulted; its address space stays
    // resident.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        syscall.write("[PERF] fault_mem SKIP fault_recv failed\n");
        _ = syscall.revoke_perm(cached_ch);
        syscall.shutdown();
    }

    // Use the child's text segment as our target. hotLoop's address is
    // not known here — use any readable byte in the child's vm. The
    // child ELF entry point (`main`) is loaded at a known range; we
    // just need *any* address in the child's user range. Pick the
    // token's "rip" from the FaultMessage as a guaranteed-valid child
    // address.
    const fm: *const syscall.FaultMessage = @ptrCast(@alignCast(&fault_buf));
    cached_target_addr = fm.rip & ~@as(u64, 0xFFF); // page-aligned

    // Prefault our own local buffer so measurements don't include
    // demand-paging cost on the read destination.
    local_buf = [_]u8{0} ** 16384;

    benchSize("fault_read_mem_8", 8, benchRead);
    benchSize("fault_read_mem_64", 64, benchRead);
    benchSize("fault_read_mem_512", 512, benchRead);
    benchSize("fault_read_mem_4096", 4096, benchRead);
    benchSize("fault_read_mem_16384", 16384, benchRead);

    benchSize("fault_write_mem_8", 8, benchWrite);
    benchSize("fault_write_mem_64", 64, benchWrite);
    benchSize("fault_write_mem_512", 512, benchWrite);
    benchSize("fault_write_mem_4096", 4096, benchWrite);
    benchSize("fault_write_mem_16384", 16384, benchWrite);

    // Release the child to continue (if we ever re-enable it).
    _ = syscall.fault_reply_simple(@bitCast(token), syscall.FAULT_KILL);
    _ = syscall.revoke_perm(cached_ch);
    syscall.shutdown();
}

var cached_ch: u64 = 0;
var cached_target_addr: u64 = 0;
var cached_size: u64 = 0;
var local_buf: [16384]u8 = undefined;

fn benchSize(name: []const u8, size: u64, comptime body: fn () void) void {
    cached_size = size;
    _ = bench.runBench(.{
        .name = name,
        .warmup = 100,
        .iterations = 2000,
    }, body);
}

fn benchRead() void {
    _ = syscall.fault_read_mem(cached_ch, cached_target_addr, @intFromPtr(&local_buf), cached_size);
}

fn benchWrite() void {
    // We never actually use the child for anything other than holding a
    // target address space, so writing arbitrary bytes is safe — the
    // child is .faulted and will never execute past this point anyway
    // (we FAULT_KILL it at the end).
    _ = syscall.fault_write_mem(cached_ch, cached_target_addr, @intFromPtr(&local_buf), cached_size);
}
