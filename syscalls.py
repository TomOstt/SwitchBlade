#!/usr/bin/env python3
"""Horizon OS syscall table. SVC #N → name + signature. Source: switchbrew.org/wiki/SVC"""

                                         # ID | Name | return type | args (if any) 
HORIZON_SYSCALLS = {
    0x01: "svcSetHeapSize",              # Result (uintptr_t *out_address, size_t size)
    0x02: "svcSetMemoryPermission",      # Result (uintptr_t address, size_t size, MemoryPermission perm)
    0x03: "svcSetMemoryAttribute",       # Result (uintptr_t address, size_t size, uint32_t mask, uint32_t attr)
    0x04: "svcMapMemory",                # Result (uintptr_t dst_address, uintptr_t src_address, size_t size)
    0x05: "svcUnmapMemory",              # Result (uintptr_t dst_address, uintptr_t src_address, size_t size)
    0x06: "svcQueryMemory",              # Result (MemoryInfo *out, PageInfo *out_page, uintptr_t address)
    0x07: "svcExitProcess",              # void ()
    0x08: "svcCreateThread",             # Result (Handle *out, ThreadFunc func, uintptr_t arg, uintptr_t stack_bottom, int32_t priority, int32_t core_id)
    0x09: "svcStartThread",              # Result (Handle thread_handle)
    0x0A: "svcExitThread",               # void ()
    0x0B: "svcSleepThread",              # void (int64_t ns)
    0x0C: "svcGetThreadPriority",        # Result (int32_t *out_priority, Handle thread_handle)
    0x0D: "svcSetThreadPriority",        # Result (Handle thread_handle, int32_t priority)
    0x0E: "svcGetThreadCoreMask",        # Result (int32_t *out_core_id, uint64_t *out_affinity_mask, Handle thread_handle)
    0x0F: "svcSetThreadCoreMask",        # Result (Handle thread_handle, int32_t core_id, uint64_t affinity_mask)
    0x10: "svcGetCurrentProcessorNumber", # int32_t ()
    0x11: "svcSignalEvent",              # Result (Handle event_handle)
    0x12: "svcClearEvent",               # Result (Handle event_handle)
    0x13: "svcMapSharedMemory",          # Result (Handle shmem_handle, uintptr_t address, size_t size, MemoryPermission map_perm)
    0x14: "svcUnmapSharedMemory",        # Result (Handle shmem_handle, uintptr_t address, size_t size)
    0x15: "svcCreateTransferMemory",     # Result (Handle *out, uintptr_t address, size_t size, MemoryPermission map_perm)
    0x16: "svcCloseHandle",              # Result (Handle handle)
    0x17: "svcResetSignal",              # Result (Handle handle)
    0x18: "svcWaitSynchronization",      # Result (int32_t *out_index, const Handle *handles, int32_t numHandles, int64_t timeout_ns)
    0x19: "svcCancelSynchronization",    # Result (Handle handle)
    0x1A: "svcArbitrateLock",            # Result (Handle thread_handle, uintptr_t address, uint32_t tag)
    0x1B: "svcArbitrateUnlock",          # Result (uintptr_t address)
    0x1C: "svcWaitProcessWideKeyAtomic", # Result (uintptr_t address, uintptr_t cv_key, uint32_t tag, int64_t timeout_ns)
    0x1D: "svcSignalProcessWideKey",     # void (uintptr_t cv_key, int32_t count)
    0x1E: "svcGetSystemTick",            # int64_t ()
    0x1F: "svcConnectToNamedPort",       # Result (Handle *out, const char *name)
    0x20: "svcSendSyncRequestLight",     # Result (Handle session_handle)
    0x21: "svcSendSyncRequest",          # Result (Handle session_handle)
    0x22: "svcSendSyncRequestWithUserBuffer", # Result (uintptr_t message_buffer, size_t message_buffer_size, Handle session_handle)
    0x23: "svcSendAsyncRequestWithUserBuffer", # Result (Handle *out_event, uintptr_t message_buffer, size_t message_buffer_size, Handle session_handle)
    0x24: "svcGetProcessId",             # Result (uint64_t *out, Handle process_handle)
    0x25: "svcGetThreadId",              # Result (uint64_t *out, Handle thread_handle)
    0x26: "svcBreak",                    # void (BreakReason reason, uintptr_t arg, size_t size)
    0x27: "svcOutputDebugString",        # Result (const char *debug_str, size_t len)
    0x28: "svcReturnFromException",      # void (Result result)
    0x29: "svcGetInfo",                  # Result (uint64_t *out, InfoType info_type, Handle handle, uint64_t info_subtype)
    0x2A: "svcFlushEntireDataCache",     # void ()
    0x2B: "svcFlushDataCache",           # Result (uintptr_t address, size_t size)
    0x2C: "svcMapPhysicalMemory",        # Result (uintptr_t address, size_t size) [3.0.0+]
    0x2D: "svcUnmapPhysicalMemory",      # Result (uintptr_t address, size_t size) [3.0.0+]
    0x2E: "svcGetDebugFutureThreadInfo", # Result (LastThreadContext *out, uint64_t *thread_id, Handle debug, int64_t ns) [6.0.0+]
    0x2F: "svcGetLastThreadInfo",        # Result (LastThreadContext *out, uintptr_t *out_tls, uint32_t *out_flags)
    0x30: "svcGetResourceLimitLimitValue", # Result (int64_t *out, Handle resource_limit, LimitableResource which)
    0x31: "svcGetResourceLimitCurrentValue", # Result (int64_t *out, Handle resource_limit, LimitableResource which)
    0x32: "svcSetThreadActivity",        # Result (Handle thread_handle, ThreadActivity activity)
    0x33: "svcGetThreadContext3",         # Result (ThreadContext *out, Handle thread_handle)
    0x34: "svcWaitForAddress",           # Result (uintptr_t address, ArbitrationType arb_type, int32_t value, int64_t timeout_ns) [4.0.0+]
    0x35: "svcSignalToAddress",          # Result (uintptr_t address, SignalType signal_type, int32_t value, int32_t count) [4.0.0+]
    0x36: "svcSynchronizePreemptionState", # void () [8.0.0+]
    0x37: "svcGetResourceLimitPeakValue", # Result (int64_t *out, Handle resource_limit, LimitableResource which) [11.0.0+]
    0x39: "svcCreateIoPool",             # Result (Handle *out, IoPoolType which) [13.0.0+]
    0x3A: "svcCreateIoRegion",           # Result (Handle *out, Handle io_pool, PhysicalAddress phys, size_t size, MemoryMapping mapping, MemoryPermission perm) [13.0.0+]
    0x3C: "svcKernelDebug",              # void (KernelDebugType type, uint64_t arg0, uint64_t arg1, uint64_t arg2) [4.0.0+]
    0x3D: "svcChangeKernelTraceState",   # void (KernelTraceState state)
    0x40: "svcCreateSession",            # Result (Handle *out_server, Handle *out_client, bool is_light, uintptr_t name)
    0x41: "svcAcceptSession",            # Result (Handle *out, Handle port)
    0x42: "svcReplyAndReceiveLight",     # Result (Handle handle)
    0x43: "svcReplyAndReceive",          # Result (int32_t *out_index, const Handle *handles, int32_t num_handles, Handle reply_target, int64_t timeout_ns)
    0x44: "svcReplyAndReceiveWithUserBuffer", # Result (int32_t *out_index, uintptr_t msg_buf, size_t msg_buf_size, const Handle *handles, int32_t num_handles, Handle reply_target, int64_t timeout_ns)
    0x45: "svcCreateEvent",              # Result (Handle *out_write, Handle *out_read)
    0x46: "svcMapIoRegion",              # Result (Handle io_region, uintptr_t address, size_t size, MemoryPermission perm) [13.0.0+]
    0x47: "svcUnmapIoRegion",            # Result (Handle io_region, uintptr_t address, size_t size) [13.0.0+]
    0x48: "svcMapPhysicalMemoryUnsafe",  # Result (uintptr_t address, size_t size) [5.0.0+]
    0x49: "svcUnmapPhysicalMemoryUnsafe", # Result (uintptr_t address, size_t size) [5.0.0+]
    0x4A: "svcSetUnsafeLimit",           # Result (size_t limit) [5.0.0+]
    0x4B: "svcCreateCodeMemory",         # Result (Handle *out, uintptr_t address, size_t size) [4.0.0+]
    0x4C: "svcControlCodeMemory",        # Result (Handle code_mem, CodeMemoryOperation op, uint64_t address, uint64_t size, MemoryPermission perm) [4.0.0+]
    0x4D: "svcSleepSystem",              # void ()
    0x4E: "svcReadWriteRegister",        # Result (uint32_t *out, PhysicalAddress address, uint32_t mask, uint32_t value)
    0x4F: "svcSetProcessActivity",       # Result (Handle process_handle, ProcessActivity activity)
    0x50: "svcCreateSharedMemory",       # Result (Handle *out, size_t size, MemoryPermission owner_perm, MemoryPermission remote_perm)
    0x51: "svcMapTransferMemory",        # Result (Handle trmem, uintptr_t address, size_t size, MemoryPermission perm)
    0x52: "svcUnmapTransferMemory",      # Result (Handle trmem, uintptr_t address, size_t size)
    0x53: "svcCreateInterruptEvent",     # Result (Handle *out, int32_t interrupt_id, InterruptType type)
    0x54: "svcQueryPhysicalAddress",     # Result (PhysicalMemoryInfo *out, uintptr_t address)
    0x55: "svcQueryMemoryMapping",       # Result (uintptr_t *out_address, size_t *out_size, PhysicalAddress phys, size_t size) [10.0.0+]
    0x56: "svcCreateDeviceAddressSpace", # Result (Handle *out, uint64_t das_address, uint64_t das_size)
    0x57: "svcAttachDeviceAddressSpace", # Result (DeviceName device, Handle das)
    0x58: "svcDetachDeviceAddressSpace", # Result (DeviceName device, Handle das)
    0x59: "svcMapDeviceAddressSpaceByForce", # Result (Handle das, Handle process, uint64_t process_addr, size_t size, uint64_t device_addr, uint32_t option)
    0x5A: "svcMapDeviceAddressSpaceAligned", # Result (Handle das, Handle process, uint64_t process_addr, size_t size, uint64_t device_addr, uint32_t option)
    0x5B: "svcMapDeviceAddressSpace",    # Result (size_t *out, Handle das, Handle process, uint64_t process_addr, size_t size, uint64_t device_addr, MemoryPermission perm) [1.0.0-12.1.0]
    0x5C: "svcUnmapDeviceAddressSpace",  # Result (Handle das, Handle process, uint64_t process_addr, size_t size, uint64_t device_addr)
    0x5D: "svcInvalidateProcessDataCache", # Result (Handle process, uint64_t address, uint64_t size)
    0x5E: "svcStoreProcessDataCache",    # Result (Handle process, uint64_t address, uint64_t size)
    0x5F: "svcFlushProcessDataCache",    # Result (Handle process, uint64_t address, uint64_t size)
    0x60: "svcDebugActiveProcess",       # Result (Handle *out, uint64_t process_id)
    0x61: "svcBreakDebugProcess",        # Result (Handle debug)
    0x62: "svcTerminateDebugProcess",    # Result (Handle debug)
    0x63: "svcGetDebugEvent",            # Result (DebugEventInfo *out, Handle debug)
    0x64: "svcContinueDebugEvent",       # Result (Handle debug, uint32_t flags, const uint64_t *thread_ids, int32_t num_thread_ids)
    0x65: "svcGetProcessList",           # Result (int32_t *out_num, uint64_t *out_ids, int32_t max_out)
    0x66: "svcGetThreadList",            # Result (int32_t *out_num, uint64_t *out_ids, int32_t max_out, Handle debug)
    0x67: "svcGetDebugThreadContext",    # Result (ThreadContext *out, Handle debug, uint64_t thread_id, uint32_t context_flags)
    0x68: "svcSetDebugThreadContext",    # Result (Handle debug, uint64_t thread_id, const ThreadContext *ctx, uint32_t context_flags)
    0x69: "svcQueryDebugProcessMemory", # Result (MemoryInfo *out, PageInfo *out_page, Handle process, uintptr_t address)
    0x6A: "svcReadDebugProcessMemory",   # Result (uintptr_t buffer, Handle debug, uintptr_t address, size_t size)
    0x6B: "svcWriteDebugProcessMemory",  # Result (Handle debug, uintptr_t buffer, uintptr_t address, size_t size)
    0x6C: "svcSetHardwareBreakPoint",    # Result (HardwareBreakPointRegisterName name, uint64_t flags, uint64_t value)
    0x6D: "svcGetDebugThreadParam",      # Result (uint64_t *out_64, uint32_t *out_32, Handle debug, uint64_t thread_id, DebugThreadParam param)
    0x6F: "svcGetSystemInfo",            # Result (uint64_t *out, SystemInfoType info_type, Handle handle, uint64_t info_subtype) [5.0.0+]
    0x70: "svcCreatePort",               # Result (Handle *out_server, Handle *out_client, int32_t max_sessions, bool is_light, uintptr_t name)
    0x71: "svcManageNamedPort",          # Result (Handle *out_server, const char *name, int32_t max_sessions)
    0x72: "svcConnectToPort",            # Result (Handle *out, Handle port)
    0x73: "svcSetProcessMemoryPermission", # Result (Handle process, uint64_t address, uint64_t size, MemoryPermission perm)
    0x74: "svcMapProcessMemory",         # Result (uintptr_t dst, Handle process, uint64_t src, size_t size)
    0x75: "svcUnmapProcessMemory",       # Result (uintptr_t dst, Handle process, uint64_t src, size_t size)
    0x76: "svcQueryProcessMemory",       # Result (MemoryInfo *out, PageInfo *out_page, Handle process, uint64_t address)
    0x77: "svcMapProcessCodeMemory",     # Result (Handle process, uint64_t dst, uint64_t src, uint64_t size)
    0x78: "svcUnmapProcessCodeMemory",   # Result (Handle process, uint64_t dst, uint64_t src, uint64_t size)
    0x79: "svcCreateProcess",            # Result (Handle *out, const CreateProcessParameter *params, const uint32_t *caps, int32_t num_caps)
    0x7A: "svcStartProcess",             # Result (Handle process, int32_t priority, int32_t core_id, uint64_t main_thread_stack_size)
    0x7B: "svcTerminateProcess",         # Result (Handle process)
    0x7C: "svcGetProcessInfo",           # Result (int64_t *out, Handle process, ProcessInfoType info_type)
    0x7D: "svcCreateResourceLimit",      # Result (Handle *out)
    0x7E: "svcSetResourceLimitLimitValue", # Result (Handle resource_limit, LimitableResource which, int64_t limit_value)
    0x7F: "svcCallSecureMonitor",        # void (SecureMonitorArguments *args)
    0x80: "svcUnlockGpuSharableMemory",  # Result () [17.0.0+]
    0x90: "svcMapInsecurePhysicalMemory", # Result (uintptr_t address, size_t size) [15.0.0+]
    0x91: "svcUnmapInsecurePhysicalMemory", # Result (uintptr_t address, size_t size) [15.0.0+]
}
