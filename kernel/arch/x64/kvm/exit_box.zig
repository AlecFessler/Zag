const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch_paging = zag.arch.x64.paging;
const interrupts = zag.arch.x64.interrupts;
const vm_hw = zag.arch.x64.vm;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;
const kvm = zag.arch.x64.kvm;
const vcpu_mod = kvm.vcpu;
const vm_mod = kvm.vm;

const ArchCpuContext = zag.arch.x64.interrupts.ArchCpuContext;
const KernelObject = zag.perms.permissions.KernelObject;
const PAddr = zag.memory.address.PAddr;
const Process = zag.proc.process.Process;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const SyscallResult = zag.syscall.dispatch.SyscallResult;
const Thread = zag.sched.thread.Thread;
const ThreadPriorityQueue = zag.sched.thread.ThreadPriorityQueue;
const VAddr = zag.memory.address.VAddr;
const VCpu = vcpu_mod.VCpu;
const Vm = vm_mod.Vm;

const MAX_VCPUS = vm_mod.MAX_VCPUS;

pub const VmExitBoxState = enum {
    idle,
    receiving,
    pending_replies,
};

pub const VmExitBox = struct {
    state: VmExitBoxState = .idle,
    queue: ThreadPriorityQueue = .{},
    receiver: ?SlabRef(Thread) = null,
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
    /// Internal helper of queueOrDeliver — not for use across modules.
    fn enqueueLocked(self: *VmExitBox, thread: *Thread) void {
        self.queue.enqueue(thread);
        if (self.state == .idle) {
            self.state = .pending_replies;
        }
    }

    /// Take the blocked receiver thread. Caller must hold lock.
    /// Transitions from receiving to pending_replies. Returns a
    /// `SlabRef(Thread)` — the consumer must `lock()` before using
    /// the thread pointer.
    /// Internal helper of queueOrDeliver — not for use across modules.
    fn takeReceiverLocked(self: *VmExitBox) SlabRef(Thread) {
        const r = self.receiver.?;
        self.receiver = null;
        self.state = .pending_replies;
        return r;
    }

    /// Mark a vCPU slot as having a pending exit. Caller must hold lock.
    /// Internal helper — not for use across modules.
    fn markPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = true;
    }

    /// Clear a pending exit for a vCPU slot. Caller must hold lock.
    /// If no more pending exits remain and the queue is empty, transitions to idle.
    fn clearPendingLocked(self: *VmExitBox, vcpu_index: u32) void {
        self.pending[vcpu_index] = false;
        if (!self.hasPendingExits() and self.queue.isEmpty()) {
            self.state = .idle;
        }
    }
};

/// Message written to userspace buffer on vm_recv.
pub const VmExitMessage = struct {
    thread_handle: u64,
    exit_info: vm_hw.VmExitInfo,
    guest_state: vm_hw.GuestState,
};

/// Action to take when replying to a VM exit.
pub const VmReplyAction = union(enum) {
    resume_guest: vm_hw.GuestState,
    inject_interrupt: vm_hw.GuestInterrupt,
    inject_exception: vm_hw.GuestException,
    map_memory: struct {
        host_vaddr: u64,
        guest_addr: u64,
        size: u64,
        rights: u8,
    },
    kill: void,
};

/// Single home for "an exit happened, push it to userspace". Called by
/// `exit_handler.handleExit` for every VMM-bound exit. Owns the lock,
/// the queue/receiver bookkeeping, and (when a receiver is already
/// blocked) the deliverExit handoff.
pub fn queueOrDeliver(box: *VmExitBox, vm_obj: *Vm, vcpu_obj: *VCpu) void {
    box.lock.lock();
    if (box.isReceiving()) {
        const recv_ref = box.takeReceiverLocked();
        box.lock.unlock();
        if (recv_ref.lock()) |receiver| {
            deliverExit(vm_obj, vcpu_obj, receiver);
            recv_ref.unlock();
        } else |_| {
            // Receiver slot freed; exit will be picked up on the next
            // vm_recv via the pending bit set by deliverExit — but
            // without a receiver we fall back to enqueuing.
            // self-alive: caller IS vcpu_obj.thread.
            box.lock.lock();
            box.enqueueLocked(vcpu_obj.thread.ptr);
            box.lock.unlock();
        }
    } else {
        // This is the vcpu's own thread calling into the exit path —
        // the Thread slot is live by definition.
        // self-alive: caller IS vcpu_obj.thread.
        box.enqueueLocked(vcpu_obj.thread.ptr);
        box.lock.unlock();
    }
}

/// Deliver an exit to a thread that is already blocked in `vm_recv`.
/// Marks the vCPU pending, transitions it to .waiting_reply, writes the
/// exit message to the receiver's saved buffer, and wakes the receiver.
fn deliverExit(vm_obj: *Vm, vcpu_obj: *VCpu, receiver: *Thread) void {
    // Owning Process is kept alive for the life of this VM; Vm.destroy
    // clears `proc.vm` under the process's gen-lock before tearing the
    // VM down.
    // self-alive: owning Process held live by this VM.
    const owner = vm_obj.owner.ptr;
    // self-alive: vcpu_obj.thread is the caller's own vcpu thread.
    const handle_id = owner.findThreadHandle(vcpu_obj.thread.ptr) orelse return;

    // Find vCPU index and mark pending
    for (vm_obj.vcpus[0..vm_obj.num_vcpus], 0..) |v, i| {
        if (v.ptr == vcpu_obj) {
            const box = vm_obj.exitBox();
            box.lock.lock();
            box.markPendingLocked(@intCast(i));
            box.lock.unlock();
            break;
        }
    }

    vcpu_obj.storeState(.waiting_reply);

    // Wait until receiver is off CPU and has saved its context.
    while (receiver.on_cpu.load(.acquire)) std.atomic.spinLoopHint();

    // Write exit info into receiver's saved buf_ptr (syscall arg1).
    const saved_args = interrupts.getSyscallArgs(receiver.ctx);
    writeExitMessageToUser(owner, saved_args.arg1, handle_id, vcpu_obj);

    // Set return value
    interrupts.setSyscallReturn(receiver.ctx, handle_id);

    // Wake the receiver
    receiver.state = .ready;
    const target_core = if (receiver.core_affinity) |mask| @as(u64, @ctz(mask)) else apic.coreID();
    sched.enqueueOnCore(target_core, receiver);
}

/// Syscall implementation: dequeue from exit box, write VmExitMessage
/// to userspace buffer, return exit token (= thread handle).
pub fn vmRecv(proc: *Process, thread: *Thread, ctx: *ArchCpuContext, vm_handle: u64, buf_ptr: u64, blocking: bool) SyscallResult {
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;
    const E_AGAIN: i64 = -9;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return .{ .ret = E_BADCAP };

    if (buf_ptr == 0) return .{ .ret = E_BADADDR };
    if (!zag.memory.address.AddrSpacePartition.user.contains(buf_ptr)) return .{ .ret = E_BADADDR };

    // Validate the full [buf_ptr, buf_ptr + msg_size) range fits in the
    // user partition before pre-faulting. Without an end check, a
    // buf_ptr near the top of user space plus the exit message size
    // can overflow or span into the kernel half, which the pre-fault
    // loop and downstream writeExitMessageToUser would then walk
    // blindly.
    const msg_size: u64 = @sizeOf(VmExitMessage);
    const buf_end = std.math.add(u64, buf_ptr, msg_size) catch return .{ .ret = E_BADADDR };
    if (!zag.memory.address.AddrSpacePartition.user.contains(buf_end - 1)) return .{ .ret = E_BADADDR };

    // Pre-fault all buffer pages the VmExitMessage may touch.
    var prefault_va = buf_ptr;
    while (prefault_va < buf_end) {
        proc.vmm.demandPage(VAddr.fromInt(prefault_va), true, false) catch return .{ .ret = E_BADADDR };
        prefault_va += paging.PAGE4K;
    }

    vm_obj._gen_lock.lock();
    const box = vm_obj.exitBox();
    box.lock.lock();

    // Try to dequeue an exited vCPU
    if (box.queue.dequeue()) |exited_thread| {
        box.lock.unlock();
        vm_obj._gen_lock.unlock();
        const result = deliverExitMessage(proc, vm_obj, exited_thread, buf_ptr);
        return .{ .ret = result };
    }

    if (!blocking) {
        box.lock.unlock();
        vm_obj._gen_lock.unlock();
        return .{ .ret = E_AGAIN };
    }

    // Block: set receiver and switch away. When a vCPU exit is delivered
    // to us, the delivery path writes rax into our saved context and
    // wakes us — we resume from the syscall return frame directly.
    box.receiver = SlabRef(Thread).init(thread, thread._gen_lock.currentGen());
    box.state = .receiving;
    box.lock.unlock();
    vm_obj._gen_lock.unlock();

    thread._gen_lock.lock();
    thread.state = .blocked;
    thread.ctx = ctx;
    thread._gen_lock.unlock();
    thread.on_cpu.store(false, .release);
    sched.switchToNextReady();
    unreachable;
}

/// Syscall implementation: resolve a pending exit by token.
pub fn vmReply(proc: *Process, vm_handle: u64, exit_token: u64, action_ptr: u64) i64 {
    const E_INVAL: i64 = -1;
    const E_BADCAP: i64 = -3;
    const E_BADADDR: i64 = -7;
    const E_NOENT: i64 = -10;

    const vm_obj = resolveVmHandle(proc, vm_handle) orelse return E_BADCAP;

    // Find the vCPU by thread handle (check exit_token validity first)
    const entry = proc.getPermByHandle(exit_token) orelse return E_NOENT;
    if (entry.object != .thread) return E_NOENT;
    const thread = entry.object.thread.lock() catch return E_NOENT;
    defer entry.object.thread.unlock();

    vm_obj._gen_lock.lock();

    // Find which vCPU this thread belongs to
    const vcpu_obj = vcpu_mod.vcpuFromThread(vm_obj, thread) orelse {
        vm_obj._gen_lock.unlock();
        return E_NOENT;
    };

    const box = vm_obj.exitBox();
    box.lock.lock();

    // Check this vCPU actually has a pending exit
    const vcpu_index = vcpuIndex(vm_obj, vcpu_obj) orelse {
        box.lock.unlock();
        vm_obj._gen_lock.unlock();
        return E_NOENT;
    };
    if (!box.pending[vcpu_index]) {
        box.lock.unlock();
        vm_obj._gen_lock.unlock();
        return E_NOENT;
    }

    box.clearPendingLocked(vcpu_index);
    box.lock.unlock();
    vm_obj._gen_lock.unlock();

    // Validate action_ptr after confirming the exit token is valid
    if (action_ptr == 0) return E_BADADDR;
    if (!zag.memory.address.AddrSpacePartition.user.contains(action_ptr)) return E_BADADDR;

    // Read the action from userspace via physmap, handling cross-page boundaries.
    // Wire format: u64 tag at offset 0, payload at offset 8.
    // Max size is tag(8) + GuestState (largest payload).
    const max_action_size = 8 + @sizeOf(vm_hw.GuestState);
    var action_buf: [max_action_size]u8 = undefined;

    // First read just the tag to determine payload size.
    if (!readUserBytes(proc, action_ptr, action_buf[0..8])) return E_BADADDR;
    const raw_tag = std.mem.readInt(u64, action_buf[0..8], .little);

    // Determine total size based on tag, then read the full action.
    const total_size: usize = switch (raw_tag) {
        0 => 8 + @sizeOf(vm_hw.GuestState),
        1 => 8 + @sizeOf(vm_hw.GuestInterrupt),
        2 => 8 + @sizeOf(vm_hw.GuestException),
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
            vm_obj._gen_lock.lock();
            vcpu_obj.guest_state = std.mem.bytesAsValue(vm_hw.GuestState, action_buf[8..][0..@sizeOf(vm_hw.GuestState)]).*;
            vcpu_obj.storeState(.running);
            vm_obj._gen_lock.unlock();
            resumeVcpuThread(thread);
        },
        1 => {
            // inject_interrupt: payload is GuestInterrupt at offset 8
            const interrupt = std.mem.bytesAsValue(vm_hw.GuestInterrupt, action_buf[8..][0..@sizeOf(vm_hw.GuestInterrupt)]).*;
            // Reject reserved architectural exception vectors 0-31 (Intel SDM
            // Vol 3A §6.3.1 / Table 6-1). External interrupts injected via
            // VMCS VM-entry event-injection must use vectors >= 32; otherwise
            // an attacker VMM could write an illegal vector directly into
            // VM_ENTRY_INTR_INFO and corrupt guest exception handling.
            if (interrupt.vector < 32) return E_INVAL;
            vm_obj._gen_lock.lock();
            vm_hw.injectInterrupt(&vcpu_obj.guest_state, interrupt);
            vcpu_obj.storeState(.running);
            vm_obj._gen_lock.unlock();
            resumeVcpuThread(thread);
        },
        2 => {
            // inject_exception: payload is GuestException at offset 8
            const exception = std.mem.bytesAsValue(vm_hw.GuestException, action_buf[8..][0..@sizeOf(vm_hw.GuestException)]).*;
            vm_obj._gen_lock.lock();
            vm_hw.injectException(&vcpu_obj.guest_state, exception);
            vcpu_obj.storeState(.running);
            vm_obj._gen_lock.unlock();
            resumeVcpuThread(thread);
        },
        3 => {
            // map_memory: payload is {host_vaddr, guest_addr, size, rights} at offset 8.
            // This is the intentional reply→syscall bridge: vm.guestMap is the public
            // memory-mapping entry point, and the reply path forwards to it directly.
            // guestMap takes vm_obj._gen_lock itself, so we must NOT hold it here.
            const payload = action_buf[8..];
            const host_vaddr = std.mem.readInt(u64, payload[0..8], .little);
            const guest_addr = std.mem.readInt(u64, payload[8..16], .little);
            const map_size = std.mem.readInt(u64, payload[16..24], .little);
            const rights = payload[24];
            const result = vm_mod.guestMap(proc, vm_handle, host_vaddr, guest_addr, map_size, @as(u64, rights));
            if (result != 0) return result;
            vm_obj._gen_lock.lock();
            vcpu_obj.storeState(.running);
            vm_obj._gen_lock.unlock();
            resumeVcpuThread(thread);
        },
        4 => {
            // kill
            vm_obj._gen_lock.lock();
            vcpu_obj.storeState(.exited);
            vm_obj._gen_lock.unlock();
            thread._gen_lock.lock();
            thread.state = .exited;
            thread._gen_lock.unlock();
        },
        else => return E_INVAL,
    }

    return 0; // E_OK
}

fn deliverExitMessage(proc: *Process, vm_obj: *Vm, thread: *Thread, buf_ptr: u64) i64 {
    const E_BADADDR: i64 = -7;

    vm_obj._gen_lock.lock();
    defer vm_obj._gen_lock.unlock();

    const vcpu_obj = vcpu_mod.vcpuFromThread(vm_obj, thread) orelse return E_BADADDR;

    // Find thread handle in caller's perm table
    const handle_id = proc.findThreadHandle(thread) orelse return E_BADADDR;

    // Mark this vCPU as pending
    const vcpu_index = vcpuIndex(vm_obj, vcpu_obj) orelse return E_BADADDR;
    const box = vm_obj.exitBox();
    box.lock.lock();
    box.markPendingLocked(vcpu_index);
    box.lock.unlock();

    vcpu_obj.storeState(.waiting_reply);

    // Write VmExitMessage to userspace via physmap
    writeExitMessageToUser(proc, buf_ptr, handle_id, vcpu_obj);

    return @intCast(handle_id);
}

fn writeExitMessageToUser(proc: *Process, buf_ptr: u64, handle_id: u64, vcpu_obj: *VCpu) void {
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
        const page_paddr = arch_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return;
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
    // Enforce full-range user-partition membership here. Callers
    // (e.g. vmReply) only point-check the start, and the per-page
    // walk below advances `src_va` across boundaries without
    // re-checking.
    const end = std.math.add(u64, user_va, buf.len) catch return false;
    if (!zag.memory.address.AddrSpacePartition.user.contains(user_va)) return false;
    if (end != user_va and !zag.memory.address.AddrSpacePartition.user.contains(end - 1)) return false;

    var remaining: usize = buf.len;
    var dst_off: usize = 0;
    var src_va: u64 = user_va;
    while (remaining > 0) {
        const page_off = src_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        proc.vmm.demandPage(VAddr.fromInt(src_va), false, false) catch return false;
        const page_paddr = arch_paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(src_va)) orelse return false;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
        const src: [*]const u8 = @ptrFromInt(physmap_addr);
        @memcpy(buf[dst_off..][0..chunk], src[0..chunk]);
        dst_off += chunk;
        src_va += chunk;
        remaining -= chunk;
    }
    return true;
}

fn vcpuIndex(vm_obj: *Vm, vcpu_obj: *VCpu) ?u32 {
    for (vm_obj.vcpus[0..vm_obj.num_vcpus], 0..) |v, i| {
        if (v.ptr == vcpu_obj) return @intCast(i);
    }
    return null;
}

fn resumeVcpuThread(thread: *Thread) void {
    while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
    thread.state = .ready;
    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else apic.coreID();
    sched.enqueueOnCore(target_core, thread);
}

/// Resolve a VM handle from the process's perm table. Returns the *Vm or null.
fn resolveVmHandle(proc: *Process, vm_handle: u64) ?*Vm {
    const entry = proc.getPermByHandle(vm_handle) orelse return null;
    return switch (entry.object) {
        .vm => |r| r.ptr,
        else => null,
    };
}
