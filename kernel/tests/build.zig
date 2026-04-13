const std = @import("std");

fn buildChild(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    lib_mod: *std.Build.Module,
    comptime name: []const u8,
    comptime src: []const u8,
) std.Build.LazyPath {
    const child_app_mod = b.createModule(.{
        .root_source_file = b.path(src),
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    child_app_mod.addImport("lib", lib_mod);
    const child_start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/start.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });
    child_start_mod.addImport("lib", lib_mod);
    child_start_mod.addImport("app", child_app_mod);
    const child_exe = b.addExecutable(.{
        .name = name,
        .root_module = child_start_mod,
        .linkage = .static,
    });
    child_exe.pie = true;
    child_exe.entry = .{ .symbol_name = "_start" };
    child_exe.setLinkerScript(.{ .cwd_relative = "linker.ld" });
    return child_exe.getEmittedBin();
}

pub fn build(b: *std.Build) void {
    const single_test = b.option([]const u8, "test", "Build only this test (e.g. s4_3_1). Omit to build all.");
    const target_arch_str = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";

    const cpu_arch: std.Target.Cpu.Arch = blk: {
        break :blk if (std.mem.eql(u8, target_arch_str, "x64"))
            .x86_64
        else if (std.mem.eql(u8, target_arch_str, "arm"))
            .aarch64
        else
            @panic("Unsupported target architecture");
    };
    const cpu_model: std.Target.Query.CpuModel = if (cpu_arch == .aarch64)
        .{ .explicit = &std.Target.aarch64.cpu.cortex_a72 }
    else
        .determined_by_arch_os;
    const target = b.resolveTargetQuery(.{
        .cpu_arch = cpu_arch,
        .os_tag = .freestanding,
        .cpu_model = cpu_model,
    });
    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "libz/lib.zig" },
        .target = target,
        .optimize = .Debug,
        .pic = true,
    });

    const child_exit_bin = buildChild(b, target, lib_mod, "child_exit", "children/child_exit.zig");
    const child_shm_counter_bin = buildChild(b, target, lib_mod, "child_shm_counter", "children/child_shm_counter.zig");
    const child_stack_overflow_bin = buildChild(b, target, lib_mod, "child_stack_overflow", "children/child_stack_overflow.zig");
    const child_restart_counter_bin = buildChild(b, target, lib_mod, "child_restart_counter", "children/child_restart_counter.zig");
    const child_multithread_bin = buildChild(b, target, lib_mod, "child_multithread", "children/child_multithread.zig");
    const child_spawner_bin = buildChild(b, target, lib_mod, "child_spawner", "children/child_spawner.zig");
    const child_restart_verify_bin = buildChild(b, target, lib_mod, "child_restart_verify", "children/child_restart_verify.zig");
    const child_shm_writer_bin = buildChild(b, target, lib_mod, "child_shm_writer", "children/child_shm_writer.zig");
    const child_stack_overflow_restart_bin = buildChild(b, target, lib_mod, "child_stack_overflow_restart", "children/child_stack_overflow_restart.zig");
    const child_ipc_server_bin = buildChild(b, target, lib_mod, "child_ipc_server", "children/child_ipc_server.zig");
    const child_ipc_restart_server_bin = buildChild(b, target, lib_mod, "child_ipc_restart_server", "children/child_ipc_restart_server.zig");
    const child_check_self_only_bin = buildChild(b, target, lib_mod, "child_check_self_only", "children/child_check_self_only.zig");
    const child_sleep_bin = buildChild(b, target, lib_mod, "child_sleep", "children/child_sleep.zig");
    const child_null_deref_bin = buildChild(b, target, lib_mod, "child_null_deref", "children/child_null_deref.zig");
    const child_send_self_bin = buildChild(b, target, lib_mod, "child_send_self", "children/child_send_self.zig");
    const child_stack_underflow_bin = buildChild(b, target, lib_mod, "child_stack_underflow", "children/child_stack_underflow.zig");
    const child_invalid_read_bin = buildChild(b, target, lib_mod, "child_invalid_read", "children/child_invalid_read.zig");
    const child_invalid_write_bin = buildChild(b, target, lib_mod, "child_invalid_write", "children/child_invalid_write.zig");
    const child_invalid_execute_bin = buildChild(b, target, lib_mod, "child_invalid_execute", "children/child_invalid_execute.zig");
    const child_exhaust_memory_bin = buildChild(b, target, lib_mod, "child_exhaust_memory", "children/child_exhaust_memory.zig");
    const child_div_zero_bin = buildChild(b, target, lib_mod, "child_div_zero", "children/child_div_zero.zig");
    const child_illegal_insn_bin = buildChild(b, target, lib_mod, "child_illegal_insn", "children/child_illegal_insn.zig");
    const child_alignment_fault_bin = buildChild(b, target, lib_mod, "child_alignment_fault", "children/child_alignment_fault.zig");
    const child_gpf_bin = buildChild(b, target, lib_mod, "child_gpf", "children/child_gpf.zig");
    const child_shm_write_readonly_bin = buildChild(b, target, lib_mod, "child_shm_write_readonly", "children/child_shm_write_readonly.zig");
    const child_middleman_bin = buildChild(b, target, lib_mod, "child_middleman", "children/child_middleman.zig");
    const child_register_grandparent_bin = buildChild(b, target, lib_mod, "child_register_grandparent", "children/child_register_grandparent.zig");
    const child_try_affinity_bin = buildChild(b, target, lib_mod, "child_try_affinity", "children/child_try_affinity.zig");
    const child_recv_busy_bin = buildChild(b, target, lib_mod, "child_recv_busy", "children/child_recv_busy.zig");
    const child_reply_recv_noblock_bin = buildChild(b, target, lib_mod, "child_reply_recv_noblock", "children/child_reply_recv_noblock.zig");
    const child_try_vm_reserve_bin = buildChild(b, target, lib_mod, "child_try_vm_reserve", "children/child_try_vm_reserve.zig");
    const child_try_shm_create_bin = buildChild(b, target, lib_mod, "child_try_shm_create", "children/child_try_shm_create.zig");
    const child_try_thread_create_bin = buildChild(b, target, lib_mod, "child_try_thread_create", "children/child_try_thread_create.zig");
    const child_try_proc_create_bin = buildChild(b, target, lib_mod, "child_try_proc_create", "children/child_try_proc_create.zig");
    const child_try_pin_exclusive_bin = buildChild(b, target, lib_mod, "child_try_pin_exclusive", "children/child_try_pin_exclusive.zig");
    const child_sched_set_priority_bin = buildChild(b, target, lib_mod, "child_sched_set_priority", "children/child_sched_set_priority.zig");
    const child_send_self_no_words_bin = buildChild(b, target, lib_mod, "child_send_self_no_words", "children/child_send_self_no_words.zig");
    const child_recv_device_exit_bin = buildChild(b, target, lib_mod, "child_recv_device_exit", "children/child_recv_device_exit.zig");
    const child_spawner_device_bin = buildChild(b, target, lib_mod, "child_spawner_device", "children/child_spawner_device.zig");
    const child_device_restart_bin = buildChild(b, target, lib_mod, "child_device_restart", "children/child_device_restart.zig");
    const child_fill_table_spawn_bin = buildChild(b, target, lib_mod, "child_fill_table_spawn", "children/child_fill_table_spawn.zig");
    const child_recv_device_wait_bin = buildChild(b, target, lib_mod, "child_recv_device_wait", "children/child_recv_device_wait.zig");
    const child_send_self_no_kill_bin = buildChild(b, target, lib_mod, "child_send_self_no_kill", "children/child_send_self_no_kill.zig");
    const child_recv_noreply_bin = buildChild(b, target, lib_mod, "child_recv_noreply", "children/child_recv_noreply.zig");
    const child_send_self_then_recv_bin = buildChild(b, target, lib_mod, "child_send_self_then_recv", "children/child_send_self_then_recv.zig");
    const child_fill_table_recv_bin = buildChild(b, target, lib_mod, "child_fill_table_recv", "children/child_fill_table_recv.zig");
    const child_try_mmio_map_bin = buildChild(b, target, lib_mod, "child_try_mmio_map", "children/child_try_mmio_map.zig");
    const child_try_dma_map_bin = buildChild(b, target, lib_mod, "child_try_dma_map", "children/child_try_dma_map.zig");

    const child_call_parent_with_device_bin = buildChild(b, target, lib_mod, "child_call_parent_with_device", "children/child_call_parent_with_device.zig");
    const child_call_parent_with_self_bin = buildChild(b, target, lib_mod, "child_call_parent_with_self", "children/child_call_parent_with_self.zig");
    const child_check_bss_bin = buildChild(b, target, lib_mod, "child_check_bss", "children/child_check_bss.zig");
    const child_timed_sleep_bin = buildChild(b, target, lib_mod, "child_timed_sleep", "children/child_timed_sleep.zig");
    const child_threads_sleep_bin = buildChild(b, target, lib_mod, "child_threads_sleep", "children/child_threads_sleep.zig");
    const child_spawn_from_shm_bin = buildChild(b, target, lib_mod, "child_spawn_from_shm", "children/child_spawn_from_shm.zig");
    const child_verify_shm_transfer_bin = buildChild(b, target, lib_mod, "child_verify_shm_transfer", "children/child_verify_shm_transfer.zig");
    const child_ipc_metadata_echo_bin = buildChild(b, target, lib_mod, "child_ipc_metadata_echo", "children/child_ipc_metadata_echo.zig");
    const child_write_perm_view_bin = buildChild(b, target, lib_mod, "child_write_perm_view", "children/child_write_perm_view.zig");
    const child_multithread_exit_bin = buildChild(b, target, lib_mod, "child_multithread_exit", "children/child_multithread_exit.zig");
    const child_check_data_reload_bin = buildChild(b, target, lib_mod, "child_check_data_reload", "children/child_check_data_reload.zig");
    const child_ipc_counter_bin = buildChild(b, target, lib_mod, "child_ipc_counter", "children/child_ipc_counter.zig");
    const child_spawn_and_report_bin = buildChild(b, target, lib_mod, "child_spawn_and_report", "children/child_spawn_and_report.zig");
    const child_verify_proc_transfer_bin = buildChild(b, target, lib_mod, "child_verify_proc_transfer", "children/child_verify_proc_transfer.zig");
    const child_try_escalate_bin = buildChild(b, target, lib_mod, "child_try_escalate", "children/child_try_escalate.zig");
    const child_breakpoint_bin = buildChild(b, target, lib_mod, "child_breakpoint", "children/child_breakpoint.zig");
    const child_report_thread_self_bin = buildChild(b, target, lib_mod, "child_report_thread_self", "children/child_report_thread_self.zig");
    const child_report_slot1_bin = buildChild(b, target, lib_mod, "child_report_slot1", "children/child_report_slot1.zig");
    const child_check_thread_handle_bin = buildChild(b, target, lib_mod, "child_check_thread_handle", "children/child_check_thread_handle.zig");
    const child_send_self_fault_handler_bin = buildChild(b, target, lib_mod, "child_send_self_fault_handler", "children/child_send_self_fault_handler.zig");
    const child_fault_after_transfer_bin = buildChild(b, target, lib_mod, "child_fault_after_transfer", "children/child_fault_after_transfer.zig");
    const child_multithread_fault_after_transfer_bin = buildChild(b, target, lib_mod, "child_multithread_fault_after_transfer", "children/child_multithread_fault_after_transfer.zig");
    const child_try_fault_recv_bin = buildChild(b, target, lib_mod, "child_try_fault_recv", "children/child_try_fault_recv.zig");
    const child_try_fault_set_thread_mode_bin = buildChild(b, target, lib_mod, "child_try_fault_set_thread_mode", "children/child_try_fault_set_thread_mode.zig");
    const child_send_self_then_create_thread_bin = buildChild(b, target, lib_mod, "child_send_self_then_create_thread", "children/child_send_self_then_create_thread.zig");
    const child_self_handle_multithread_fault_bin = buildChild(b, target, lib_mod, "child_self_handle_multithread_fault", "children/child_self_handle_multithread_fault.zig");
    const child_transfer_then_spawn_exit_worker_bin = buildChild(b, target, lib_mod, "child_transfer_then_spawn_exit_worker", "children/child_transfer_then_spawn_exit_worker.zig");
    const child_int3_after_transfer_bin = buildChild(b, target, lib_mod, "child_int3_after_transfer", "children/child_int3_after_transfer.zig");
    const child_double_fault_after_transfer_bin = buildChild(b, target, lib_mod, "child_double_fault_after_transfer", "children/child_double_fault_after_transfer.zig");
    const child_shm_counter_then_fault_bin = buildChild(b, target, lib_mod, "child_shm_counter_then_fault", "children/child_shm_counter_then_fault.zig");
    const child_multithread_fault_on_signal_bin = buildChild(b, target, lib_mod, "child_multithread_fault_on_signal", "children/child_multithread_fault_on_signal.zig");
    const child_iter2_d_double_fault_on_signal_bin = buildChild(b, target, lib_mod, "child_iter2_d_double_fault_on_signal", "children/child_iter2_d_double_fault_on_signal.zig");
    const child_delayed_ipc_server_bin = buildChild(b, target, lib_mod, "child_delayed_ipc_server", "children/child_delayed_ipc_server.zig");
    const child_middleman_handler_bin = buildChild(b, target, lib_mod, "child_middleman_handler", "children/child_middleman_handler.zig");
    const child_fh_target_reporter_bin = buildChild(b, target, lib_mod, "child_fh_target_reporter", "children/child_fh_target_reporter.zig");
    const child_iter1_d_call_parent_bin = buildChild(b, target, lib_mod, "child_iter1_d_call_parent", "children/child_iter1_d_call_parent.zig");
    const child_iter1_d_mt_target_bin = buildChild(b, target, lib_mod, "child_iter1_d_mt_target", "children/child_iter1_d_mt_target.zig");
    const child_ipc_shm_recorder_bin = buildChild(b, target, lib_mod, "child_ipc_shm_recorder", "children/child_ipc_shm_recorder.zig");
    const child_ipc_five_word_echo_bin = buildChild(b, target, lib_mod, "child_ipc_five_word_echo", "children/child_ipc_five_word_echo.zig");
    const child_shm_no_read_bin = buildChild(b, target, lib_mod, "child_shm_no_read", "children/child_shm_no_read.zig");
    const child_shm_no_execute_bin = buildChild(b, target, lib_mod, "child_shm_no_execute", "children/child_shm_no_execute.zig");
    const child_mmio_invalid_read_bin = buildChild(b, target, lib_mod, "child_mmio_invalid_read", "children/child_mmio_invalid_read.zig");
    const child_mmio_invalid_write_bin = buildChild(b, target, lib_mod, "child_mmio_invalid_write", "children/child_mmio_invalid_write.zig");
    const child_mmio_invalid_execute_bin = buildChild(b, target, lib_mod, "child_mmio_invalid_execute", "children/child_mmio_invalid_execute.zig");
    const child_recv_then_signal_bin = buildChild(b, target, lib_mod, "child_recv_then_signal", "children/child_recv_then_signal.zig");
    const child_report_own_handle_bin = buildChild(b, target, lib_mod, "child_report_own_handle", "children/child_report_own_handle.zig");
    const child_shm_ready_no_recv_bin = buildChild(b, target, lib_mod, "child_shm_ready_no_recv", "children/child_shm_ready_no_recv.zig");
    const child_report_self_field0_bin = buildChild(b, target, lib_mod, "child_report_self_field0", "children/child_report_self_field0.zig");
    const child_report_main_addr_bin = buildChild(b, target, lib_mod, "child_report_main_addr", "children/child_report_main_addr.zig");
    const child_spawn_restartable_grandchild_bin = buildChild(b, target, lib_mod, "child_spawn_restartable_grandchild", "children/child_spawn_restartable_grandchild.zig");
    const child_restart_grandchild_counter_bin = buildChild(b, target, lib_mod, "child_restart_grandchild_counter", "children/child_restart_grandchild_counter.zig");
    const child_self_kill_bin = buildChild(b, target, lib_mod, "child_self_kill", "children/child_self_kill.zig");
    const child_shm_touch_all_pages_bin = buildChild(b, target, lib_mod, "child_shm_touch_all_pages", "children/child_shm_touch_all_pages.zig");
    const child_shm_write_magic_bin = buildChild(b, target, lib_mod, "child_shm_write_magic", "children/child_shm_write_magic.zig");
    const child_send_self_then_reply_token_bin = buildChild(b, target, lib_mod, "child_send_self_then_reply_token", "children/child_send_self_then_reply_token.zig");
    const child_grandparent_restart_bin = buildChild(b, target, lib_mod, "child_grandparent_restart", "children/child_grandparent_restart.zig");
    const child_vm_count_after_restart_bin = buildChild(b, target, lib_mod, "child_vm_count_after_restart", "children/child_vm_count_after_restart.zig");
    const child_parked_workers_then_fault_bin = buildChild(b, target, lib_mod, "child_parked_workers_then_fault", "children/child_parked_workers_then_fault.zig");
    const child_spawn_report_then_fault_bin = buildChild(b, target, lib_mod, "child_spawn_report_then_fault", "children/child_spawn_report_then_fault.zig");
    const child_fh_threads_then_fault_bin = buildChild(b, target, lib_mod, "child_fh_threads_then_fault", "children/child_fh_threads_then_fault.zig");
    const child_report_self_rights_bin = buildChild(b, target, lib_mod, "child_report_self_rights", "children/child_report_self_rights.zig");
    const child_report_rights_then_fault_bin = buildChild(b, target, lib_mod, "child_report_rights_then_fault", "children/child_report_rights_then_fault.zig");
    const child_spawn_threads_then_transfer_fh_bin = buildChild(b, target, lib_mod, "child_spawn_threads_then_transfer_fh", "children/child_spawn_threads_then_transfer_fh.zig");
    const child_selfh_all_threads_fault_bin = buildChild(b, target, lib_mod, "child_selfh_all_threads_fault", "children/child_selfh_all_threads_fault.zig");
    const child_iter1_b_restart_probe_bin = buildChild(b, target, lib_mod, "child_iter1_b_restart_probe", "children/child_iter1_b_restart_probe.zig");
    const child_iter1_b_spawn_exit_bin = buildChild(b, target, lib_mod, "child_iter1_b_spawn_exit", "children/child_iter1_b_spawn_exit.zig");
    const child_iter1_b_parked_tids_bin = buildChild(b, target, lib_mod, "child_iter1_b_parked_tids", "children/child_iter1_b_parked_tids.zig");
    const child_iter1_b_restart_loop_rights_bin = buildChild(b, target, lib_mod, "child_iter1_b_restart_loop_rights", "children/child_iter1_b_restart_loop_rights.zig");
    const child_iter1_c_delay_server_bin = buildChild(b, target, lib_mod, "child_iter1_c_delay_server", "children/child_iter1_c_delay_server.zig");
    const child_iter1_c_gated_counter_bin = buildChild(b, target, lib_mod, "child_iter1_c_gated_counter", "children/child_iter1_c_gated_counter.zig");
    const child_iter1_c_late_recv_bin = buildChild(b, target, lib_mod, "child_iter1_c_late_recv", "children/child_iter1_c_late_recv.zig");
    const child_iter1_c_reply_clears_bin = buildChild(b, target, lib_mod, "child_iter1_c_reply_clears", "children/child_iter1_c_reply_clears.zig");
    const child_iter1_c_full_table_receiver_bin = buildChild(b, target, lib_mod, "child_iter1_c_full_table_receiver", "children/child_iter1_c_full_table_receiver.zig");
    const child_try_set_priority_bin = buildChild(b, target, lib_mod, "child_try_set_priority", "children/child_try_set_priority.zig");
    const child_pin_then_restart_bin = buildChild(b, target, lib_mod, "child_pin_then_restart", "children/child_pin_then_restart.zig");
    const child_sched_try_create_with_priority_bin = buildChild(b, target, lib_mod, "child_sched_try_create_with_priority", "children/child_sched_try_create_with_priority.zig");
    const child_vm_create_exit_bin = buildChild(b, target, lib_mod, "child_vm_create_exit", "children/child_vm_create_exit.zig");
    const child_try_pmu_all_bin = buildChild(b, target, lib_mod, "child_try_pmu_all", "children/child_try_pmu_all.zig");
    const child_pmu_no_thread_right_bin = buildChild(b, target, lib_mod, "child_pmu_no_thread_right", "children/child_pmu_no_thread_right.zig");
    const child_report_pmu_right_bin = buildChild(b, target, lib_mod, "child_report_pmu_right", "children/child_report_pmu_right.zig");
    const child_try_pmu_info_bin = buildChild(b, target, lib_mod, "child_try_pmu_info", "children/child_try_pmu_info.zig");
    const child_pmu_overflow_bin = buildChild(b, target, lib_mod, "child_pmu_overflow", "children/child_pmu_overflow.zig");
    const child_pmu_overflow_self_bin = buildChild(b, target, lib_mod, "child_pmu_overflow_self", "children/child_pmu_overflow_self.zig");
    const child_try_sys_info_bin = buildChild(b, target, lib_mod, "child_try_sys_info", "children/child_try_sys_info.zig");
    const child_try_clock_getwall_bin = buildChild(b, target, lib_mod, "child_try_clock_getwall", "children/child_try_clock_getwall.zig");
    const child_try_clock_setwall_bin = buildChild(b, target, lib_mod, "child_try_clock_setwall", "children/child_try_clock_setwall.zig");
    const child_try_getrandom_bin = buildChild(b, target, lib_mod, "child_try_getrandom", "children/child_try_getrandom.zig");
    const child_try_notify_wait_bin = buildChild(b, target, lib_mod, "child_try_notify_wait", "children/child_try_notify_wait.zig");
    const child_try_sys_power_bin = buildChild(b, target, lib_mod, "child_try_sys_power", "children/child_try_sys_power.zig");
    const child_try_sys_cpu_power_bin = buildChild(b, target, lib_mod, "child_try_sys_cpu_power", "children/child_try_sys_cpu_power.zig");
    const child_vbar_non_mov_bin = buildChild(b, target, lib_mod, "child_vbar_non_mov", "children/child_vbar_non_mov.zig");
    const child_vbar_oob_read_bin = buildChild(b, target, lib_mod, "child_vbar_oob_read", "children/child_vbar_oob_read.zig");
    const child_perf_ipc_echo_bin = buildChild(b, target, lib_mod, "child_perf_ipc_echo", "children/child_perf_ipc_echo.zig");
    const child_perf_ipc_client_bin = buildChild(b, target, lib_mod, "child_perf_ipc_client", "children/child_perf_ipc_client.zig");
    const child_perf_workload_bin = buildChild(b, target, lib_mod, "child_perf_workload", "children/child_perf_workload.zig");

    const embedded_wf = b.addWriteFiles();
    _ = embedded_wf.addCopyFile(child_exit_bin, "child_exit.elf");
    _ = embedded_wf.addCopyFile(child_shm_counter_bin, "child_shm_counter.elf");
    _ = embedded_wf.addCopyFile(child_stack_overflow_bin, "child_stack_overflow.elf");
    _ = embedded_wf.addCopyFile(child_restart_counter_bin, "child_restart_counter.elf");
    _ = embedded_wf.addCopyFile(child_multithread_bin, "child_multithread.elf");
    _ = embedded_wf.addCopyFile(child_spawner_bin, "child_spawner.elf");
    _ = embedded_wf.addCopyFile(child_restart_verify_bin, "child_restart_verify.elf");
    _ = embedded_wf.addCopyFile(child_shm_writer_bin, "child_shm_writer.elf");
    _ = embedded_wf.addCopyFile(child_stack_overflow_restart_bin, "child_stack_overflow_restart.elf");
    _ = embedded_wf.addCopyFile(child_ipc_server_bin, "child_ipc_server.elf");
    _ = embedded_wf.addCopyFile(child_ipc_restart_server_bin, "child_ipc_restart_server.elf");
    _ = embedded_wf.addCopyFile(child_check_self_only_bin, "child_check_self_only.elf");
    _ = embedded_wf.addCopyFile(child_sleep_bin, "child_sleep.elf");
    _ = embedded_wf.addCopyFile(child_null_deref_bin, "child_null_deref.elf");
    _ = embedded_wf.addCopyFile(child_send_self_bin, "child_send_self.elf");
    _ = embedded_wf.addCopyFile(child_stack_underflow_bin, "child_stack_underflow.elf");
    _ = embedded_wf.addCopyFile(child_invalid_read_bin, "child_invalid_read.elf");
    _ = embedded_wf.addCopyFile(child_invalid_write_bin, "child_invalid_write.elf");
    _ = embedded_wf.addCopyFile(child_invalid_execute_bin, "child_invalid_execute.elf");
    _ = embedded_wf.addCopyFile(child_exhaust_memory_bin, "child_exhaust_memory.elf");
    _ = embedded_wf.addCopyFile(child_div_zero_bin, "child_div_zero.elf");
    _ = embedded_wf.addCopyFile(child_illegal_insn_bin, "child_illegal_insn.elf");
    _ = embedded_wf.addCopyFile(child_alignment_fault_bin, "child_alignment_fault.elf");
    _ = embedded_wf.addCopyFile(child_gpf_bin, "child_gpf.elf");
    _ = embedded_wf.addCopyFile(child_shm_write_readonly_bin, "child_shm_write_readonly.elf");
    _ = embedded_wf.addCopyFile(child_middleman_bin, "child_middleman.elf");
    _ = embedded_wf.addCopyFile(child_register_grandparent_bin, "child_register_grandparent.elf");
    _ = embedded_wf.addCopyFile(child_try_affinity_bin, "child_try_affinity.elf");
    _ = embedded_wf.addCopyFile(child_recv_busy_bin, "child_recv_busy.elf");
    _ = embedded_wf.addCopyFile(child_reply_recv_noblock_bin, "child_reply_recv_noblock.elf");
    _ = embedded_wf.addCopyFile(child_try_vm_reserve_bin, "child_try_vm_reserve.elf");
    _ = embedded_wf.addCopyFile(child_try_shm_create_bin, "child_try_shm_create.elf");
    _ = embedded_wf.addCopyFile(child_try_thread_create_bin, "child_try_thread_create.elf");
    _ = embedded_wf.addCopyFile(child_try_proc_create_bin, "child_try_proc_create.elf");
    _ = embedded_wf.addCopyFile(child_try_pin_exclusive_bin, "child_try_pin_exclusive.elf");
    _ = embedded_wf.addCopyFile(child_sched_set_priority_bin, "child_sched_set_priority.elf");
    _ = embedded_wf.addCopyFile(child_send_self_no_words_bin, "child_send_self_no_words.elf");
    _ = embedded_wf.addCopyFile(child_recv_device_exit_bin, "child_recv_device_exit.elf");
    _ = embedded_wf.addCopyFile(child_spawner_device_bin, "child_spawner_device.elf");
    _ = embedded_wf.addCopyFile(child_device_restart_bin, "child_device_restart.elf");
    _ = embedded_wf.addCopyFile(child_fill_table_spawn_bin, "child_fill_table_spawn.elf");
    _ = embedded_wf.addCopyFile(child_recv_device_wait_bin, "child_recv_device_wait.elf");
    _ = embedded_wf.addCopyFile(child_send_self_no_kill_bin, "child_send_self_no_kill.elf");
    _ = embedded_wf.addCopyFile(child_recv_noreply_bin, "child_recv_noreply.elf");
    _ = embedded_wf.addCopyFile(child_send_self_then_recv_bin, "child_send_self_then_recv.elf");
    _ = embedded_wf.addCopyFile(child_fill_table_recv_bin, "child_fill_table_recv.elf");
    _ = embedded_wf.addCopyFile(child_try_mmio_map_bin, "child_try_mmio_map.elf");
    _ = embedded_wf.addCopyFile(child_try_dma_map_bin, "child_try_dma_map.elf");

    _ = embedded_wf.addCopyFile(child_call_parent_with_device_bin, "child_call_parent_with_device.elf");
    _ = embedded_wf.addCopyFile(child_call_parent_with_self_bin, "child_call_parent_with_self.elf");
    _ = embedded_wf.addCopyFile(child_check_bss_bin, "child_check_bss.elf");
    _ = embedded_wf.addCopyFile(child_timed_sleep_bin, "child_timed_sleep.elf");
    _ = embedded_wf.addCopyFile(child_threads_sleep_bin, "child_threads_sleep.elf");
    _ = embedded_wf.addCopyFile(child_spawn_from_shm_bin, "child_spawn_from_shm.elf");
    _ = embedded_wf.addCopyFile(child_verify_shm_transfer_bin, "child_verify_shm_transfer.elf");
    _ = embedded_wf.addCopyFile(child_ipc_metadata_echo_bin, "child_ipc_metadata_echo.elf");
    _ = embedded_wf.addCopyFile(child_write_perm_view_bin, "child_write_perm_view.elf");
    _ = embedded_wf.addCopyFile(child_multithread_exit_bin, "child_multithread_exit.elf");
    _ = embedded_wf.addCopyFile(child_check_data_reload_bin, "child_check_data_reload.elf");
    _ = embedded_wf.addCopyFile(child_ipc_counter_bin, "child_ipc_counter.elf");
    _ = embedded_wf.addCopyFile(child_spawn_and_report_bin, "child_spawn_and_report.elf");
    _ = embedded_wf.addCopyFile(child_verify_proc_transfer_bin, "child_verify_proc_transfer.elf");
    _ = embedded_wf.addCopyFile(child_try_escalate_bin, "child_try_escalate.elf");
    _ = embedded_wf.addCopyFile(child_breakpoint_bin, "child_breakpoint.elf");
    _ = embedded_wf.addCopyFile(child_report_thread_self_bin, "child_report_thread_self.elf");
    _ = embedded_wf.addCopyFile(child_report_slot1_bin, "child_report_slot1.elf");
    _ = embedded_wf.addCopyFile(child_check_thread_handle_bin, "child_check_thread_handle.elf");
    _ = embedded_wf.addCopyFile(child_send_self_fault_handler_bin, "child_send_self_fault_handler.elf");
    _ = embedded_wf.addCopyFile(child_fault_after_transfer_bin, "child_fault_after_transfer.elf");
    _ = embedded_wf.addCopyFile(child_multithread_fault_after_transfer_bin, "child_multithread_fault_after_transfer.elf");
    _ = embedded_wf.addCopyFile(child_try_fault_recv_bin, "child_try_fault_recv.elf");
    _ = embedded_wf.addCopyFile(child_try_fault_set_thread_mode_bin, "child_try_fault_set_thread_mode.elf");
    _ = embedded_wf.addCopyFile(child_send_self_then_create_thread_bin, "child_send_self_then_create_thread.elf");
    _ = embedded_wf.addCopyFile(child_self_handle_multithread_fault_bin, "child_self_handle_multithread_fault.elf");
    _ = embedded_wf.addCopyFile(child_transfer_then_spawn_exit_worker_bin, "child_transfer_then_spawn_exit_worker.elf");
    _ = embedded_wf.addCopyFile(child_int3_after_transfer_bin, "child_int3_after_transfer.elf");
    _ = embedded_wf.addCopyFile(child_double_fault_after_transfer_bin, "child_double_fault_after_transfer.elf");
    _ = embedded_wf.addCopyFile(child_shm_counter_then_fault_bin, "child_shm_counter_then_fault.elf");
    _ = embedded_wf.addCopyFile(child_multithread_fault_on_signal_bin, "child_multithread_fault_on_signal.elf");
    _ = embedded_wf.addCopyFile(child_iter2_d_double_fault_on_signal_bin, "child_iter2_d_double_fault_on_signal.elf");
    _ = embedded_wf.addCopyFile(child_delayed_ipc_server_bin, "child_delayed_ipc_server.elf");
    _ = embedded_wf.addCopyFile(child_middleman_handler_bin, "child_middleman_handler.elf");
    _ = embedded_wf.addCopyFile(child_fh_target_reporter_bin, "child_fh_target_reporter.elf");
    _ = embedded_wf.addCopyFile(child_iter1_d_call_parent_bin, "child_iter1_d_call_parent.elf");
    _ = embedded_wf.addCopyFile(child_iter1_d_mt_target_bin, "child_iter1_d_mt_target.elf");
    _ = embedded_wf.addCopyFile(child_ipc_shm_recorder_bin, "child_ipc_shm_recorder.elf");
    _ = embedded_wf.addCopyFile(child_ipc_five_word_echo_bin, "child_ipc_five_word_echo.elf");
    _ = embedded_wf.addCopyFile(child_shm_no_read_bin, "child_shm_no_read.elf");
    _ = embedded_wf.addCopyFile(child_shm_no_execute_bin, "child_shm_no_execute.elf");
    _ = embedded_wf.addCopyFile(child_mmio_invalid_read_bin, "child_mmio_invalid_read.elf");
    _ = embedded_wf.addCopyFile(child_mmio_invalid_write_bin, "child_mmio_invalid_write.elf");
    _ = embedded_wf.addCopyFile(child_mmio_invalid_execute_bin, "child_mmio_invalid_execute.elf");
    _ = embedded_wf.addCopyFile(child_recv_then_signal_bin, "child_recv_then_signal.elf");
    _ = embedded_wf.addCopyFile(child_report_own_handle_bin, "child_report_own_handle.elf");
    _ = embedded_wf.addCopyFile(child_shm_ready_no_recv_bin, "child_shm_ready_no_recv.elf");
    _ = embedded_wf.addCopyFile(child_report_self_field0_bin, "child_report_self_field0.elf");
    _ = embedded_wf.addCopyFile(child_report_main_addr_bin, "child_report_main_addr.elf");
    _ = embedded_wf.addCopyFile(child_spawn_restartable_grandchild_bin, "child_spawn_restartable_grandchild.elf");
    _ = embedded_wf.addCopyFile(child_restart_grandchild_counter_bin, "child_restart_grandchild_counter.elf");
    _ = embedded_wf.addCopyFile(child_self_kill_bin, "child_self_kill.elf");
    _ = embedded_wf.addCopyFile(child_shm_touch_all_pages_bin, "child_shm_touch_all_pages.elf");
    _ = embedded_wf.addCopyFile(child_shm_write_magic_bin, "child_shm_write_magic.elf");
    _ = embedded_wf.addCopyFile(child_send_self_then_reply_token_bin, "child_send_self_then_reply_token.elf");
    _ = embedded_wf.addCopyFile(child_grandparent_restart_bin, "child_grandparent_restart.elf");
    _ = embedded_wf.addCopyFile(child_vm_count_after_restart_bin, "child_vm_count_after_restart.elf");
    _ = embedded_wf.addCopyFile(child_parked_workers_then_fault_bin, "child_parked_workers_then_fault.elf");
    _ = embedded_wf.addCopyFile(child_spawn_report_then_fault_bin, "child_spawn_report_then_fault.elf");
    _ = embedded_wf.addCopyFile(child_fh_threads_then_fault_bin, "child_fh_threads_then_fault.elf");
    _ = embedded_wf.addCopyFile(child_report_self_rights_bin, "child_report_self_rights.elf");
    _ = embedded_wf.addCopyFile(child_report_rights_then_fault_bin, "child_report_rights_then_fault.elf");
    _ = embedded_wf.addCopyFile(child_spawn_threads_then_transfer_fh_bin, "child_spawn_threads_then_transfer_fh.elf");
    _ = embedded_wf.addCopyFile(child_selfh_all_threads_fault_bin, "child_selfh_all_threads_fault.elf");
    _ = embedded_wf.addCopyFile(child_iter1_b_restart_probe_bin, "child_iter1_b_restart_probe.elf");
    _ = embedded_wf.addCopyFile(child_iter1_b_spawn_exit_bin, "child_iter1_b_spawn_exit.elf");
    _ = embedded_wf.addCopyFile(child_iter1_b_parked_tids_bin, "child_iter1_b_parked_tids.elf");
    _ = embedded_wf.addCopyFile(child_iter1_b_restart_loop_rights_bin, "child_iter1_b_restart_loop_rights.elf");
    _ = embedded_wf.addCopyFile(child_iter1_c_delay_server_bin, "child_iter1_c_delay_server.elf");
    _ = embedded_wf.addCopyFile(child_iter1_c_gated_counter_bin, "child_iter1_c_gated_counter.elf");
    _ = embedded_wf.addCopyFile(child_iter1_c_late_recv_bin, "child_iter1_c_late_recv.elf");
    _ = embedded_wf.addCopyFile(child_iter1_c_reply_clears_bin, "child_iter1_c_reply_clears.elf");
    _ = embedded_wf.addCopyFile(child_iter1_c_full_table_receiver_bin, "child_iter1_c_full_table_receiver.elf");
    _ = embedded_wf.addCopyFile(child_try_set_priority_bin, "child_try_set_priority.elf");
    _ = embedded_wf.addCopyFile(child_pin_then_restart_bin, "child_pin_then_restart.elf");
    _ = embedded_wf.addCopyFile(child_sched_try_create_with_priority_bin, "child_sched_try_create_with_priority.elf");
    _ = embedded_wf.addCopyFile(child_vm_create_exit_bin, "child_vm_create_exit.elf");
    _ = embedded_wf.addCopyFile(child_try_pmu_all_bin, "child_try_pmu_all.elf");
    _ = embedded_wf.addCopyFile(child_pmu_no_thread_right_bin, "child_pmu_no_thread_right.elf");
    _ = embedded_wf.addCopyFile(child_report_pmu_right_bin, "child_report_pmu_right.elf");
    _ = embedded_wf.addCopyFile(child_try_pmu_info_bin, "child_try_pmu_info.elf");
    _ = embedded_wf.addCopyFile(child_pmu_overflow_bin, "child_pmu_overflow.elf");
    _ = embedded_wf.addCopyFile(child_pmu_overflow_self_bin, "child_pmu_overflow_self.elf");
    _ = embedded_wf.addCopyFile(child_try_sys_info_bin, "child_try_sys_info.elf");
    _ = embedded_wf.addCopyFile(child_try_clock_getwall_bin, "child_try_clock_getwall.elf");
    _ = embedded_wf.addCopyFile(child_try_clock_setwall_bin, "child_try_clock_setwall.elf");
    _ = embedded_wf.addCopyFile(child_try_getrandom_bin, "child_try_getrandom.elf");
    _ = embedded_wf.addCopyFile(child_try_notify_wait_bin, "child_try_notify_wait.elf");
    _ = embedded_wf.addCopyFile(child_try_sys_power_bin, "child_try_sys_power.elf");
    _ = embedded_wf.addCopyFile(child_try_sys_cpu_power_bin, "child_try_sys_cpu_power.elf");
    _ = embedded_wf.addCopyFile(child_vbar_non_mov_bin, "child_vbar_non_mov.elf");
    _ = embedded_wf.addCopyFile(child_vbar_oob_read_bin, "child_vbar_oob_read.elf");
    _ = embedded_wf.addCopyFile(child_perf_ipc_echo_bin, "child_perf_ipc_echo.elf");
    _ = embedded_wf.addCopyFile(child_perf_ipc_client_bin, "child_perf_ipc_client.elf");
    _ = embedded_wf.addCopyFile(child_perf_workload_bin, "child_perf_workload.elf");
    const embed_src = embedded_wf.add("embedded_children.zig",
        \\pub const child_exit = @embedFile("child_exit.elf");
        \\pub const child_shm_counter = @embedFile("child_shm_counter.elf");
        \\pub const child_stack_overflow = @embedFile("child_stack_overflow.elf");
        \\pub const child_restart_counter = @embedFile("child_restart_counter.elf");
        \\pub const child_multithread = @embedFile("child_multithread.elf");
        \\pub const child_spawner = @embedFile("child_spawner.elf");
        \\pub const child_restart_verify = @embedFile("child_restart_verify.elf");
        \\pub const child_shm_writer = @embedFile("child_shm_writer.elf");
        \\pub const child_stack_overflow_restart = @embedFile("child_stack_overflow_restart.elf");
        \\pub const child_ipc_server = @embedFile("child_ipc_server.elf");
        \\pub const child_ipc_restart_server = @embedFile("child_ipc_restart_server.elf");
        \\pub const child_check_self_only = @embedFile("child_check_self_only.elf");
        \\pub const child_sleep = @embedFile("child_sleep.elf");
        \\pub const child_null_deref = @embedFile("child_null_deref.elf");
        \\pub const child_send_self = @embedFile("child_send_self.elf");
        \\pub const child_stack_underflow = @embedFile("child_stack_underflow.elf");
        \\pub const child_invalid_read = @embedFile("child_invalid_read.elf");
        \\pub const child_invalid_write = @embedFile("child_invalid_write.elf");
        \\pub const child_invalid_execute = @embedFile("child_invalid_execute.elf");
        \\pub const child_exhaust_memory = @embedFile("child_exhaust_memory.elf");
        \\pub const child_div_zero = @embedFile("child_div_zero.elf");
        \\pub const child_illegal_insn = @embedFile("child_illegal_insn.elf");
        \\pub const child_alignment_fault = @embedFile("child_alignment_fault.elf");
        \\pub const child_gpf = @embedFile("child_gpf.elf");
        \\pub const child_shm_write_readonly = @embedFile("child_shm_write_readonly.elf");
        \\pub const child_middleman = @embedFile("child_middleman.elf");
        \\pub const child_register_grandparent = @embedFile("child_register_grandparent.elf");
        \\pub const child_try_affinity = @embedFile("child_try_affinity.elf");
        \\pub const child_recv_busy = @embedFile("child_recv_busy.elf");
        \\pub const child_reply_recv_noblock = @embedFile("child_reply_recv_noblock.elf");
        \\pub const child_try_vm_reserve = @embedFile("child_try_vm_reserve.elf");
        \\pub const child_try_shm_create = @embedFile("child_try_shm_create.elf");
        \\pub const child_try_thread_create = @embedFile("child_try_thread_create.elf");
        \\pub const child_try_proc_create = @embedFile("child_try_proc_create.elf");
        \\pub const child_try_pin_exclusive = @embedFile("child_try_pin_exclusive.elf");
        \\pub const child_sched_set_priority = @embedFile("child_sched_set_priority.elf");
        \\pub const child_send_self_no_words = @embedFile("child_send_self_no_words.elf");
        \\pub const child_recv_device_exit = @embedFile("child_recv_device_exit.elf");
        \\pub const child_spawner_device = @embedFile("child_spawner_device.elf");
        \\pub const child_device_restart = @embedFile("child_device_restart.elf");
        \\pub const child_fill_table_spawn = @embedFile("child_fill_table_spawn.elf");
        \\pub const child_recv_device_wait = @embedFile("child_recv_device_wait.elf");
        \\pub const child_send_self_no_kill = @embedFile("child_send_self_no_kill.elf");
        \\pub const child_recv_noreply = @embedFile("child_recv_noreply.elf");
        \\pub const child_send_self_then_recv = @embedFile("child_send_self_then_recv.elf");
        \\pub const child_fill_table_recv = @embedFile("child_fill_table_recv.elf");
        \\pub const child_try_mmio_map = @embedFile("child_try_mmio_map.elf");
        \\pub const child_try_dma_map = @embedFile("child_try_dma_map.elf");

        \\pub const child_call_parent_with_device = @embedFile("child_call_parent_with_device.elf");
        \\pub const child_call_parent_with_self = @embedFile("child_call_parent_with_self.elf");
        \\pub const child_check_bss = @embedFile("child_check_bss.elf");
        \\pub const child_timed_sleep = @embedFile("child_timed_sleep.elf");
        \\pub const child_threads_sleep = @embedFile("child_threads_sleep.elf");
        \\pub const child_spawn_from_shm = @embedFile("child_spawn_from_shm.elf");
        \\pub const child_verify_shm_transfer = @embedFile("child_verify_shm_transfer.elf");
        \\pub const child_ipc_metadata_echo = @embedFile("child_ipc_metadata_echo.elf");
        \\pub const child_write_perm_view = @embedFile("child_write_perm_view.elf");
        \\pub const child_multithread_exit = @embedFile("child_multithread_exit.elf");
        \\pub const child_check_data_reload = @embedFile("child_check_data_reload.elf");
        \\pub const child_ipc_counter = @embedFile("child_ipc_counter.elf");
        \\pub const child_spawn_and_report = @embedFile("child_spawn_and_report.elf");
        \\pub const child_verify_proc_transfer = @embedFile("child_verify_proc_transfer.elf");
        \\pub const child_try_escalate = @embedFile("child_try_escalate.elf");
        \\pub const child_breakpoint = @embedFile("child_breakpoint.elf");
        \\pub const child_report_thread_self = @embedFile("child_report_thread_self.elf");
        \\pub const child_report_slot1 = @embedFile("child_report_slot1.elf");
        \\pub const child_check_thread_handle = @embedFile("child_check_thread_handle.elf");
        \\pub const child_send_self_fault_handler = @embedFile("child_send_self_fault_handler.elf");
        \\pub const child_fault_after_transfer = @embedFile("child_fault_after_transfer.elf");
        \\pub const child_multithread_fault_after_transfer = @embedFile("child_multithread_fault_after_transfer.elf");
        \\pub const child_try_fault_recv = @embedFile("child_try_fault_recv.elf");
        \\pub const child_try_fault_set_thread_mode = @embedFile("child_try_fault_set_thread_mode.elf");
        \\pub const child_send_self_then_create_thread = @embedFile("child_send_self_then_create_thread.elf");
        \\pub const child_self_handle_multithread_fault = @embedFile("child_self_handle_multithread_fault.elf");
        \\pub const child_transfer_then_spawn_exit_worker = @embedFile("child_transfer_then_spawn_exit_worker.elf");
        \\pub const child_int3_after_transfer = @embedFile("child_int3_after_transfer.elf");
        \\pub const child_double_fault_after_transfer = @embedFile("child_double_fault_after_transfer.elf");
        \\pub const child_shm_counter_then_fault = @embedFile("child_shm_counter_then_fault.elf");
        \\pub const child_multithread_fault_on_signal = @embedFile("child_multithread_fault_on_signal.elf");
        \\pub const child_iter2_d_double_fault_on_signal = @embedFile("child_iter2_d_double_fault_on_signal.elf");
        \\pub const child_delayed_ipc_server = @embedFile("child_delayed_ipc_server.elf");
        \\pub const child_middleman_handler = @embedFile("child_middleman_handler.elf");
        \\pub const child_fh_target_reporter = @embedFile("child_fh_target_reporter.elf");
        \\pub const child_iter1_d_call_parent = @embedFile("child_iter1_d_call_parent.elf");
        \\pub const child_iter1_d_mt_target = @embedFile("child_iter1_d_mt_target.elf");
        \\pub const child_ipc_shm_recorder = @embedFile("child_ipc_shm_recorder.elf");
        \\pub const child_ipc_five_word_echo = @embedFile("child_ipc_five_word_echo.elf");
        \\pub const child_shm_no_read = @embedFile("child_shm_no_read.elf");
        \\pub const child_shm_no_execute = @embedFile("child_shm_no_execute.elf");
        \\pub const child_mmio_invalid_read = @embedFile("child_mmio_invalid_read.elf");
        \\pub const child_mmio_invalid_write = @embedFile("child_mmio_invalid_write.elf");
        \\pub const child_mmio_invalid_execute = @embedFile("child_mmio_invalid_execute.elf");
        \\pub const child_recv_then_signal = @embedFile("child_recv_then_signal.elf");
        \\pub const child_report_own_handle = @embedFile("child_report_own_handle.elf");
        \\pub const child_shm_ready_no_recv = @embedFile("child_shm_ready_no_recv.elf");
        \\pub const child_report_self_field0 = @embedFile("child_report_self_field0.elf");
        \\pub const child_report_main_addr = @embedFile("child_report_main_addr.elf");
        \\pub const child_spawn_restartable_grandchild = @embedFile("child_spawn_restartable_grandchild.elf");
        \\pub const child_restart_grandchild_counter = @embedFile("child_restart_grandchild_counter.elf");
        \\pub const child_self_kill = @embedFile("child_self_kill.elf");
        \\pub const child_shm_touch_all_pages = @embedFile("child_shm_touch_all_pages.elf");
        \\pub const child_shm_write_magic = @embedFile("child_shm_write_magic.elf");
        \\pub const child_send_self_then_reply_token = @embedFile("child_send_self_then_reply_token.elf");
        \\pub const child_grandparent_restart = @embedFile("child_grandparent_restart.elf");
        \\pub const child_vm_count_after_restart = @embedFile("child_vm_count_after_restart.elf");
        \\pub const child_parked_workers_then_fault = @embedFile("child_parked_workers_then_fault.elf");
        \\pub const child_spawn_report_then_fault = @embedFile("child_spawn_report_then_fault.elf");
        \\pub const child_fh_threads_then_fault = @embedFile("child_fh_threads_then_fault.elf");
        \\pub const child_report_self_rights = @embedFile("child_report_self_rights.elf");
        \\pub const child_report_rights_then_fault = @embedFile("child_report_rights_then_fault.elf");
        \\pub const child_spawn_threads_then_transfer_fh = @embedFile("child_spawn_threads_then_transfer_fh.elf");
        \\pub const child_selfh_all_threads_fault = @embedFile("child_selfh_all_threads_fault.elf");
        \\pub const child_iter1_b_restart_probe = @embedFile("child_iter1_b_restart_probe.elf");
        \\pub const child_iter1_b_spawn_exit = @embedFile("child_iter1_b_spawn_exit.elf");
        \\pub const child_iter1_b_parked_tids = @embedFile("child_iter1_b_parked_tids.elf");
        \\pub const child_iter1_b_restart_loop_rights = @embedFile("child_iter1_b_restart_loop_rights.elf");
        \\pub const child_iter1_c_delay_server = @embedFile("child_iter1_c_delay_server.elf");
        \\pub const child_iter1_c_gated_counter = @embedFile("child_iter1_c_gated_counter.elf");
        \\pub const child_iter1_c_late_recv = @embedFile("child_iter1_c_late_recv.elf");
        \\pub const child_iter1_c_reply_clears = @embedFile("child_iter1_c_reply_clears.elf");
        \\pub const child_iter1_c_full_table_receiver = @embedFile("child_iter1_c_full_table_receiver.elf");
        \\pub const child_try_set_priority = @embedFile("child_try_set_priority.elf");
        \\pub const child_pin_then_restart = @embedFile("child_pin_then_restart.elf");
        \\pub const child_sched_try_create_with_priority = @embedFile("child_sched_try_create_with_priority.elf");
        \\pub const child_vm_create_exit = @embedFile("child_vm_create_exit.elf");
        \\pub const child_try_pmu_all = @embedFile("child_try_pmu_all.elf");
        \\pub const child_pmu_no_thread_right = @embedFile("child_pmu_no_thread_right.elf");
        \\pub const child_report_pmu_right = @embedFile("child_report_pmu_right.elf");
        \\pub const child_try_pmu_info = @embedFile("child_try_pmu_info.elf");
        \\pub const child_pmu_overflow = @embedFile("child_pmu_overflow.elf");
        \\pub const child_pmu_overflow_self = @embedFile("child_pmu_overflow_self.elf");
        \\pub const child_try_sys_info = @embedFile("child_try_sys_info.elf");
        \\pub const child_try_clock_getwall = @embedFile("child_try_clock_getwall.elf");
        \\pub const child_try_clock_setwall = @embedFile("child_try_clock_setwall.elf");
        \\pub const child_try_getrandom = @embedFile("child_try_getrandom.elf");
        \\pub const child_try_notify_wait = @embedFile("child_try_notify_wait.elf");
        \\pub const child_try_sys_power = @embedFile("child_try_sys_power.elf");
        \\pub const child_try_sys_cpu_power = @embedFile("child_try_sys_cpu_power.elf");
        \\pub const child_vbar_non_mov = @embedFile("child_vbar_non_mov.elf");
        \\pub const child_vbar_oob_read = @embedFile("child_vbar_oob_read.elf");
        \\pub const child_perf_ipc_echo = @embedFile("child_perf_ipc_echo.elf");
        \\pub const child_perf_ipc_client = @embedFile("child_perf_ipc_client.elf");
        \\pub const child_perf_workload = @embedFile("child_perf_workload.elf");
        \\
    );

    const embedded_children_mod = b.createModule(.{
        .root_source_file = embed_src,
        .target = target,
        .optimize = .Debug,
    });

    // Iterate tests/ directory, build one ELF per .zig file
    var tests_dir = std.fs.cwd().openDir("tests", .{ .iterate = true }) catch
        @panic("Cannot open tests/ directory");
    defer tests_dir.close();

    var it = tests_dir.iterate();
    while (it.next() catch @panic("Failed to iterate tests/")) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
        if (!std.mem.startsWith(u8, entry.name, "s") and
            !std.mem.startsWith(u8, entry.name, "perf_")) continue;

        const stem = entry.name[0 .. entry.name.len - 4];

        // If single test specified, skip everything else
        if (single_test) |wanted| {
            if (!std.mem.eql(u8, stem, wanted)) continue;
        }

        const app_mod = b.createModule(.{
            .root_source_file = b.path(b.fmt("tests/{s}", .{entry.name})),
            .target = target,
            .optimize = .Debug,
            .pic = true,
        });
        app_mod.addImport("lib", lib_mod);
        app_mod.addImport("embedded_children", embedded_children_mod);

        const start_mod = b.createModule(.{
            .root_source_file = .{ .cwd_relative = "libz/start.zig" },
            .target = target,
            .optimize = .Debug,
            .pic = true,
        });
        start_mod.addImport("lib", lib_mod);
        start_mod.addImport("app", app_mod);

        const exe = b.addExecutable(.{
            .name = @ptrCast(stem),
            .root_module = start_mod,
            .linkage = .static,
        });
        exe.pie = true;
        exe.entry = .{ .symbol_name = "_start" };
        exe.setLinkerScript(.{ .cwd_relative = "linker.ld" });

        const install = b.addInstallFile(exe.getEmittedBin(), b.fmt("../bin/{s}.elf", .{stem}));
        b.getInstallStep().dependOn(&install.step);
    }
}
