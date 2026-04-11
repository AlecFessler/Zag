const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;
const vcpu_mod = zag.kvm.vcpu;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const PAddr = zag.memory.address.PAddr;
const PriorityQueue = zag.containers.priority_queue.PriorityQueue;
const Process = zag.sched.process.Process;
const SpinLock = zag.sched.sync.SpinLock;
const SyscallResult = zag.arch.syscall.SyscallResult;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const VCpu = vcpu_mod.VCpu;

pub const MAX_VCPUS = 64;

pub const VmExitBoxState = enum {
    idle,
    receiving,
    pending_replies,
};

pub const VmExitBox = struct {
    state: VmExitBoxState = .idle,
    queue: PriorityQueue = .{},
    receiver: ?*Thread = null,
    pending: [MAX_VCPUS]bool = .{false} ** MAX_VCPUS,
    lock: SpinLock = .{},

    /// Check if any exits are pending resolution.
    pub fn hasPendingExits(self: *VmExitBox) bool {
        for (self.pending) |p| {
            if (p) return true;
        }
        return false;
    }

    /// Check if a receiver thread is blocked waiting.
    pub fn isReceiving(self: *VmExitBox) bool {
        return self.state == .receiving;
    }

    /// Enqueue an exited vCPU thread for delivery. Caller must hold lock.
    pub fn enqueueLocked(self: *VmExitBox, thread: *Thread) void {
        self.queue.enqueue(thread);
        if (self.state == .idle) {
            self.state = .pending_replies;
        }
    }

    /// Take the blocked receiver thread. Caller must hold lock.
    /// Transitions from receiving to pending_replies.
    pub fn takeReceiverLocked(self: *VmExitBox) *Thread {
        const r = self.receiver.?;
        self.receiver = null;
        self.state = .pending_replies;
        return r;
    }

    /// Mark a vCPU slot as having a pending exit. Caller must hold lock.
    pub fn markPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = true;
    }

    /// Clear a pending exit for a vCPU slot. Caller must hold lock.
    /// If no more pending exits remain, transitions to idle.
    pub fn clearPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = false;
        if (!self.hasPendingExits() and self.queue.dequeue() == null) {
            self.state = .idle;
        }
    }
};

/// Message written to userspace buffer on vm_recv.
pub const VmExitMessage = struct {
    thread_handle: u64,
    exit_info: zag.arch.dispatch.VmExitInfo,
    guest_state: zag.arch.dispatch.GuestState,
};

/// Action to take when replying to a VM exit.
pub const VmReplyAction = union(enum) {
    resume_guest: zag.arch.dispatch.GuestState,
    inject_interrupt: zag.arch.dispatch.GuestInterrupt,
    inject_exception: zag.arch.dispatch.GuestException,
    map_memory: struct {
        host_vaddr: u64,
        guest_addr: u64,
        size: u64,
        rights: u8,
    },
    kill: void,

};

/// Syscall implementation: dequeue from exit box, write VmExitMessage
/// to userspace buffer, return exit token (= thread handle).
pub fn vmRecv(proc: *Process, thread: *Thread, ctx: *ArchCpuContext, buf_ptr: u64, blocking: bool) SyscallResult {
    const E_INVAL: i64 = -1;
    const E_BADADDR: i64 = -7;
    const E_AGAIN: i64 = -9;

    const vm_obj = proc.vm orelse return .{ .rax = E_INVAL };
    const box = &vm_obj.exit_box;

    if (buf_ptr == 0) return .{ .rax = E_BADADDR };
    if (!zag.memory.address.AddrSpacePartition.user.contains(buf_ptr)) return .{ .rax = E_BADADDR };

    // Pre-fault all buffer pages the VmExitMessage may touch.
    const msg_size: u64 = @sizeOf(VmExitMessage);
    var prefault_va = buf_ptr;
    while (prefault_va < buf_ptr + msg_size) : (prefault_va += paging.PAGE4K) {
        proc.vmm.demandPage(VAddr.fromInt(prefault_va), true, false) catch return .{ .rax = E_BADADDR };
    }

    box.lock.lock();

    // Try to dequeue an exited vCPU
    if (box.queue.dequeue()) |exited_thread| {
        box.lock.unlock();
        const result = deliverExitMessage(proc, vm_obj, exited_thread, buf_ptr);
        return .{ .rax = result };
    }

    if (!blocking) {
        box.lock.unlock();
        return .{ .rax = E_AGAIN };
    }

    // Block: set receiver and switch away. When a vCPU exit is delivered
    // to us, the delivery path writes rax into our saved context and
    // wakes us — we resume from the syscall return frame directly.
    box.receiver = thread;
    box.state = .receiving;
    box.lock.unlock();

    thread.state = .blocked;
    thread.ctx = ctx;
    thread.on_cpu.store(false, .release);
    sched.switchToNextReady();
    unreachable;
}

/// Syscall implementation: resolve a pending exit by token.
pub fn vmReply(proc: *Process, exit_token: u64, action_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADADDR: i64 = -7;
    const E_NOENT: i64 = -10;

    const vm_obj = proc.vm orelse return E_INVAL;

    // Find the vCPU by thread handle (check exit_token validity first)
    const entry = proc.getPermByHandle(exit_token) orelse return E_NOENT;
    if (entry.object != .thread) return E_NOENT;
    const thread = entry.object.thread;

    // Find which vCPU this thread belongs to
    const vcpu_obj = vcpu_mod.vcpuFromThread(vm_obj, thread) orelse return E_NOENT;

    const box = &vm_obj.exit_box;
    box.lock.lock();

    // Check this vCPU actually has a pending exit
    const vcpu_index = vcpuIndex(vm_obj, vcpu_obj) orelse {
        box.lock.unlock();
        return E_NOENT;
    };
    if (!box.pending[vcpu_index]) {
        box.lock.unlock();
        return E_NOENT;
    }

    box.clearPendingLocked(vcpu_index);
    box.lock.unlock();

    // Validate action_ptr after confirming the exit token is valid
    if (action_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(action_ptr)) return E_BADADDR;

    // Read the action from userspace via physmap, handling cross-page boundaries.
    // Wire format: u64 tag at offset 0, payload at offset 8.
    // Max size is tag(8) + GuestState (largest payload).
    const max_action_size = 8 + @sizeOf(arch.GuestState);
    var action_buf: [max_action_size]u8 = undefined;

    // First read just the tag to determine payload size.
    if (!readUserBytes(proc, action_ptr, action_buf[0..8])) return E_BADADDR;
    const raw_tag = std.mem.readInt(u64, action_buf[0..8], .little);

    // Determine total size based on tag, then read the full action.
    const total_size: usize = switch (raw_tag) {
        0 => 8 + @sizeOf(arch.GuestState),
        1 => 8 + @sizeOf(arch.GuestInterrupt),
        2 => 8 + @sizeOf(arch.GuestException),
        3 => 8 + 25, // host_vaddr(8) + guest_addr(8) + size(8) + rights(1)
        4 => 8, // kill: tag only
        else => return E_INVAL,
    };

    if (total_size > 8) {
        if (!readUserBytes(proc, action_ptr + 8, action_buf[8..total_size])) return E_BADADDR;
    }

    switch (raw_tag) {
        0 => {
            // resume_guest: payload is GuestState at offset 8
            vcpu_obj.guest_state = std.mem.bytesAsValue(arch.GuestState, action_buf[8..][0..@sizeOf(arch.GuestState)]).*;
            vcpu_obj.state = .running;
            resumeVcpuThread(thread);
        },
        1 => {
            // inject_interrupt: payload is GuestInterrupt at offset 8
            const interrupt = std.mem.bytesAsValue(arch.GuestInterrupt, action_buf[8..][0..@sizeOf(arch.GuestInterrupt)]).*;
            arch.vmInjectInterrupt(&vcpu_obj.guest_state, interrupt);
            vcpu_obj.state = .running;
            resumeVcpuThread(thread);
        },
        2 => {
            // inject_exception: payload is GuestException at offset 8
            const exception = std.mem.bytesAsValue(arch.GuestException, action_buf[8..][0..@sizeOf(arch.GuestException)]).*;
            arch.vmInjectException(&vcpu_obj.guest_state, exception);
            vcpu_obj.state = .running;
            resumeVcpuThread(thread);
        },
        3 => {
            // map_memory: payload is {host_vaddr, guest_addr, size, rights} at offset 8
            const payload = action_buf[8..];
            const host_vaddr = std.mem.readInt(u64, payload[0..8], .little);
            const guest_addr = std.mem.readInt(u64, payload[8..16], .little);
            const map_size = std.mem.readInt(u64, payload[16..24], .little);
            const rights = payload[24];
            const result = zag.kvm.vm.guestMap(proc, host_vaddr, guest_addr, map_size, @as(u64, rights));
            if (result != 0) return result;
            vcpu_obj.state = .running;
            resumeVcpuThread(thread);
        },
        4 => {
            // kill
            vcpu_obj.state = .exited;
            thread.state = .exited;
        },
        else => return E_INVAL,
    }

    return 0; // E_OK
}

fn deliverExitMessage(proc: *Process, vm_obj: *zag.kvm.Vm, thread: *Thread, buf_ptr: u64) i64 {
    const E_BADADDR: i64 = -7;

    const vcpu_obj = vcpu_mod.vcpuFromThread(vm_obj, thread) orelse return E_BADADDR;

    // Find thread handle in caller's perm table
    const handle_id = proc.findThreadHandle(thread) orelse return E_BADADDR;

    // Mark this vCPU as pending
    const vcpu_index = vcpuIndex(vm_obj, vcpu_obj) orelse return E_BADADDR;
    vm_obj.exit_box.lock.lock();
    vm_obj.exit_box.markPendingLocked(vcpu_index);
    vm_obj.exit_box.lock.unlock();

    vcpu_obj.state = .waiting_reply;

    // Write VmExitMessage to userspace via physmap
    writeExitMessageToUser(proc, buf_ptr, handle_id, vcpu_obj);

    return @intCast(handle_id);
}

pub fn writeExitMessageToUser(proc: *Process, buf_ptr: u64, handle_id: u64, vcpu_obj: *VCpu) void {
    // Write the message fields via physmap page-walking
    const msg = VmExitMessage{
        .thread_handle = handle_id,
        .exit_info = vcpu_obj.last_exit_info,
        .guest_state = vcpu_obj.guest_state,
    };
    const msg_bytes = std.mem.asBytes(&msg);

    var remaining: usize = msg_bytes.len;
    var src_off: usize = 0;
    var dst_va: u64 = buf_ptr;
    while (remaining > 0) {
        const page_off = dst_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        // The receiver already faulted in its buffer pages in vm_recv before
        // blocking, so skip demandPage here — the pages are already present.
        const page_paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..chunk], msg_bytes[src_off..][0..chunk]);
        src_off += chunk;
        dst_va += chunk;
        remaining -= chunk;
    }
}

/// Read bytes from userspace into a kernel buffer, handling cross-page boundaries.
fn readUserBytes(proc: *Process, user_va: u64, buf: []u8) bool {
    var remaining: usize = buf.len;
    var dst_off: usize = 0;
    var src_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = src_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(src_va), false, false) catch return false;
        const page_paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
}

fn vcpuIndex(vm_obj: *zag.kvm.Vm, vcpu_obj: *VCpu) ?u32 {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus], 0..) |v, i| {
        if (v == vcpu_obj) return @intCast(i);
    }
    return null;
}

fn resumeVcpuThread(thread: *Thread) void {
    while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
    thread.state = .ready;
    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
    sched.enqueueOnCore(target_core, thread);
}
