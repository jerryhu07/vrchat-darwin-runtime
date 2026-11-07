#include "../platform/runtime-abi.h"
#include <atomic>
#include <cstddef>
#include <FEXCore/Core/CoreState.h>

// The native bridge accesses these fields across the PE/Unix boundary.
static_assert(offsetof(FEXCore::Core::CpuStateFrame, State.fs_cached) == 1000);
extern "C" __declspec(dllexport) uint64_t FliDispatcherLoopTop(void *frame) {
  return static_cast<FEXCore::Core::CpuStateFrame *>(frame)->Pointers.DispatcherLoopTop;
}

using Dispatch = int32_t (*)(uint64_t, unsigned, void *);
using Notify = void (*)(void *, size_t, uint32_t, int32_t, int32_t);
static std::atomic<Dispatch> OriginalDispatch{};
static std::atomic<uint32_t *> SharedSplitLock{};
extern "C" uint32_t *FliSharedSplitLock() { return SharedSplitLock.load(std::memory_order_acquire); }
static std::atomic<uint64_t> MemoryBridge{};
static std::atomic<Notify> MemoryNotify{};

extern "C" __declspec(dllexport) void FliConfigureMemoryDispatch(uint64_t original, uint64_t bridge, uint64_t notify,
                                                                 uint64_t split_lock) {
  MemoryBridge.store(bridge, std::memory_order_relaxed);
  MemoryNotify.store(reinterpret_cast<Notify>(notify), std::memory_order_relaxed);
  if (split_lock)
    SharedSplitLock.store(reinterpret_cast<uint32_t *>(split_lock), std::memory_order_release);
  if (original)
    OriginalDispatch.store(reinterpret_cast<Dispatch>(original), std::memory_order_release);
}

extern "C" __declspec(dllexport) int32_t FliMemoryDispatch(uint64_t handle, unsigned code, void *args) {
  const auto dispatch = OriginalDispatch.load(std::memory_order_acquire);
  const int32_t status = dispatch(handle, code, args);
  if (code || handle != MemoryBridge.load(std::memory_order_relaxed))
    return status;
  // This adapter is entered from Wine PE code. Unix dispatch has returned, so
  // notification callbacks cannot overwrite an active Unix syscall frame.
  uint64_t teb = 0;
  asm volatile("mov %0, x28" : "=r"(teb));
  auto area = *reinterpret_cast<uint64_t *>(teb + 0x1788);
  auto callback = reinterpret_cast<uint8_t *>(area + 1);
  const uint8_t previous = *callback;
  *callback = 1;
  FliMemoryNotification event{};
  const auto notify = MemoryNotify.load(std::memory_order_relaxed);
  while (dispatch(handle, FLI_MEMORY_DRAIN_CALL, &event) == 1) {
    notify(reinterpret_cast<void *>(event.address), event.length, event.windows_protection, 0, 0);
    notify(reinterpret_cast<void *>(event.address), event.length, event.windows_protection, 1, 0);
  }
  *callback = previous;
  return status;
}

// Reuse the single bridge binding and its existing FS restoration interface.
extern "C" int32_t FliInitializeThreadBinding(void *context) {
  const auto dispatch = OriginalDispatch.load(std::memory_order_acquire);
  const auto bridge = MemoryBridge.load(std::memory_order_relaxed);
  if (!dispatch || !bridge)
    return 0; // Initial bootstrap still uses the existing first ELF entry.
  const auto status = dispatch(bridge, FLI_ATTACH_ROOT_THREAD_CALL, context);
  if (status)
    return status;
  return dispatch(bridge, FLI_RESTORE_FS_CALL, context);
}
