#pragma once
#include <stdint.h>
// Private C ABI shared by the Unix bridge and the ARM64EC notification adapter.
enum FliBridgeCall {
  FLI_SYSCALL_CALL = 0,
  FLI_RESTORE_FS_CALL = 1,
  FLI_GLIBC_EXPORTS_CALL = 2,
  FLI_THREAD_ABI_CALL = 3,
  FLI_BIND_THREAD_CALL = 4,
  FLI_EXECUTION_REGIONS_CALL = 5,
  FLI_FINISH_THREAD_ATTACH_CALL = 6,
  FLI_RESOLVE_ALIAS_CALL = 7,
  FLI_COMPLETE_ALIAS_CALL = 8,
  FLI_OBSERVE_ALIAS_CALL = 9,
  FLI_OBSERVE_THREAD_ENTRY_CALL = 10,
  FLI_ATTACH_ROOT_THREAD_CALL = 11,
  FLI_MEMORY_DRAIN_CALL = 12,
  FLI_CURRENT_THREAD_CALL = 13,
  FLI_FD_IMPORT_CALL = 14,
};
struct FliMemoryNotification {
  uint64_t address, length;
  uint32_t windows_protection, reserved;
};

// Slot in the separate FEX Unix service table, not FliBridgeCall.
enum { FLI_JIT_SERVICE_CALL = 6 };
enum FliJitOperation {
  FLI_JIT_CREATE = 0,
  FLI_JIT_RELEASE = 1,
  FLI_JIT_BEGIN_PATCH = 2,
  FLI_JIT_END_PATCH = 3,
  FLI_JIT_TRIM = 4,
};
struct FliJITAlias {
  uint64_t source, length, alias;
  uint32_t operation, reserved;
};
