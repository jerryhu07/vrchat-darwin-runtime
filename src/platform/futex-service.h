#pragma once
#include "futex-abi.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <climits>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <vector>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <os/os_sync_wait_on_address.h>

namespace FliFutexService {
struct MaskedWaiter {
  std::condition_variable cv;
  uint32_t mask;
  bool wake = false;
};
static std::mutex Lock;
static std::map<void *, std::vector<std::shared_ptr<MaskedWaiter>>> Masked;
static int64_t error(int e) {
  switch (e) {
  case EAGAIN:
    return -11;
  case ETIMEDOUT:
    return -110;
  case EFAULT:
    return -14;
  case EINTR:
    return -4;
  case EINVAL:
    return -22;
  case ENOMEM:
    return -12;
  case ENOTSUP:
    return -95;
  default:
    return -5;
  }
}
static void fork_prepare() { Lock.lock(); }
static void fork_parent() { Lock.unlock(); }
static void fork_child() {
  // Parent-only masked waiters cannot survive fork. Discard the child's copied
  // index without destroying condition variables copied while in use.
  // The discarded child-only metadata is reclaimed with its address space.
  new (&Masked) decltype(Masked)();
  Lock.unlock();
}
__attribute__((constructor)) static void initialize() { pthread_atfork(fork_prepare, fork_parent, fork_child); }
} // namespace FliFutexService

extern "C" __attribute__((visibility("default"))) int64_t fli_shared_futex(void *word, uint32_t operation,
                                                                           uint32_t value, const FliFutexTime *timeout,
                                                                           uint32_t mask) {
  using namespace FliFutexService;
  const uint32_t command = operation & 127;
  const bool private_word = operation & 128;
  if (operation & ~511u || (command != 0 && command != 1 && command != 9 && command != 10))
    return -38;
  if (!word || (reinterpret_cast<uintptr_t>(word) & 3))
    return -22;
  if (command != 9 && command != 10)
    mask = UINT32_MAX;
  if (!mask)
    return -22;
  if (command == 1 || command == 10) {
    if (value > INT32_MAX)
      return -22;
    uint32_t woken = 0;
    if (private_word) {
      std::lock_guard guard(Lock);
      if (auto queue = Masked.find(word); queue != Masked.end())
        for (auto &waiter : queue->second)
          if (woken < value && !waiter->wake && (waiter->mask & mask)) {
            waiter->wake = true;
            waiter->cv.notify_one();
            ++woken;
          }
    }
    const auto flags = private_word ? OS_SYNC_WAKE_BY_ADDRESS_NONE : OS_SYNC_WAKE_BY_ADDRESS_SHARED;
    while (woken < value) {
      if (os_sync_wake_by_address_any(word, sizeof(uint32_t), flags)) {
        if (errno == ENOENT)
          break;
        return woken ? woken : error(errno);
      }
      ++woken;
    }
    return woken;
  }
  // Shared masked waits require a process-shared waiter registry; neither
  // executor may claim support using a private condition variable.
  if (mask != UINT32_MAX && !private_word)
    return -38;
  uint64_t nanoseconds = 0;
  bool expired = false;
  if (timeout) {
    if (timeout->seconds < 0 || timeout->nanoseconds < 0 || timeout->nanoseconds >= 1000000000)
      return -22;
    __int128 ns = __int128(timeout->seconds) * 1000000000 + timeout->nanoseconds;
    if (command == 9) {
      timespec now{};
      if (clock_gettime(operation & 256 ? CLOCK_REALTIME : CLOCK_MONOTONIC, &now))
        return error(errno);
      ns -= __int128(now.tv_sec) * 1000000000 + now.tv_nsec;
    }
    if (ns <= 0)
      expired = true;
    if (ns > UINT64_MAX)
      return -22;
    if (!expired)
      nanoseconds = uint64_t(ns);
  }
  std::unique_lock guard(Lock);
  uint32_t current = 0;
  mach_vm_size_t copied = 0;
  if (mach_vm_read_overwrite(mach_task_self(), reinterpret_cast<mach_vm_address_t>(word), sizeof(current),
                             reinterpret_cast<mach_vm_address_t>(&current), &copied) != KERN_SUCCESS ||
      copied != sizeof(current))
    return -14;
  if (current != value)
    return -11;
  if (expired)
    return -110;
  if (mask != UINT32_MAX) {
    auto waiter = std::make_shared<MaskedWaiter>();
    waiter->mask = mask;
    Masked[word].push_back(waiter);
    bool woke = true;
    if (timeout)
      woke = waiter->cv.wait_for(guard, std::chrono::nanoseconds(std::min<uint64_t>(nanoseconds, INT64_MAX)),
                                 [&] { return waiter->wake; });
    else
      waiter->cv.wait(guard, [&] { return waiter->wake; });
    auto &queue = Masked.at(word);
    queue.erase(std::remove(queue.begin(), queue.end(), waiter), queue.end());
    if (queue.empty())
      Masked.erase(word);
    return woke ? 0 : -110;
  }
  guard.unlock();
  const auto flags = private_word ? OS_SYNC_WAIT_ON_ADDRESS_NONE : OS_SYNC_WAIT_ON_ADDRESS_SHARED;
  const int status = timeout ? os_sync_wait_on_address_with_timeout(word, value, sizeof(uint32_t), flags,
                                                                    OS_CLOCK_MACH_ABSOLUTE_TIME, nanoseconds)
                             : os_sync_wait_on_address(word, value, sizeof(uint32_t), flags);
  return status < 0 ? error(errno) : 0;
}
