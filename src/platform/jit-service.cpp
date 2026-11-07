// Private runtime service: one shared backing, separate non-executable RW and RX views.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <pthread.h>
#include <unistd.h>
#include "runtime-abi.h"
struct View {
  uint64_t alias, length, trimmed;
};
static std::mutex lock;
static std::unordered_map<uint64_t, View> views;
struct PatchView {
  uint64_t base, length, source, requested, owner;
};
static std::unordered_map<uint64_t, PatchView> patches;
static pid_t patch_pid;
static int trim_view(View &view, uint64_t used) {
  const uint64_t end = used & ~uint64_t(16383);
  if (end > view.length - 16384)
    return -1;
  if (end <= view.trimmed)
    return 0;
  // Keep the virtual range reserved while dropping the redundant resident
  // alias. No backing bytes are discarded; the RX view remains its owner.
  mach_vm_address_t address = view.alias + view.trimmed;
  if (mach_vm_map(mach_task_self(), &address, end - view.trimmed, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                  MACH_PORT_NULL, 0, FALSE, VM_PROT_NONE, VM_PROT_NONE, VM_INHERIT_COPY))
    return -1;
  view.trimmed = end;
  return 0;
}

// Fork snapshots must keep the child's two aliases coherent while separating
// them from the parent. A plain COPY inheritance splits the two COW views.
static void child_views() {
  for (auto &[source, v] : views) {
    mach_vm_address_t temporary = 0;
    vm_prot_t current = 0, maximum = 0;
    if (mach_vm_remap(mach_task_self(), &temporary, v.length, 0, VM_FLAGS_ANYWHERE, mach_task_self(), source, TRUE,
                      &current, &maximum, VM_INHERIT_COPY))
      _exit(71);
    if (mach_vm_protect(mach_task_self(), temporary, v.length, FALSE, VM_PROT_READ | VM_PROT_WRITE))
      _exit(71);
    for (auto address : {v.alias, source}) {
      mach_vm_address_t target = address;
      if (mach_vm_remap(mach_task_self(), &target, v.length, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(),
                        temporary, FALSE, &current, &maximum, VM_INHERIT_COPY))
        _exit(71);
    }
    if (mach_vm_protect(mach_task_self(), source, v.length, FALSE, VM_PROT_READ | VM_PROT_EXECUTE) ||
        mach_vm_protect(mach_task_self(), source + v.length - 16384, 16384, FALSE, VM_PROT_NONE))
      _exit(71);
    mach_vm_deallocate(mach_task_self(), temporary, v.length);
    const auto published = v.trimmed;
    v.trimmed = 0;
    if (trim_view(v, published))
      _exit(71);
  }
  lock.unlock();
}
__attribute__((constructor)) static void install_fork_views() {
  if (pthread_atfork([] { lock.lock(); }, [] { lock.unlock(); }, child_views))
    _exit(71);
}
static int32_t unsupported(void *) { return int32_t(0xc00000bb); }
static int32_t alias(void *opaque) {
  if (!opaque)
    return int32_t(0xc000000d);
  auto &r = *static_cast<FliJITAlias *>(opaque);
  std::lock_guard guard(lock);
  // Temporary patch windows are not inherited; clear only their metadata
  // on the first ordinary service call after a fork, outside the atfork hook.
  if (patch_pid != getpid()) {
    patches.clear();
    patch_pid = getpid();
  }
  if (r.operation == FLI_JIT_BEGIN_PATCH) {
    if (!r.source || !r.length || r.length > 16384 || r.alias)
      return int32_t(0xc000000d);
    for (const auto &[owner, v] : views)
      if (r.source >= owner && r.source - owner < v.length - 16384 &&
          r.length <= v.length - 16384 - (r.source - owner)) {
        const uint64_t begin = r.source & ~uint64_t(16383), offset = r.source - begin,
                       span = (offset + r.length + 16383) & ~uint64_t(16383);
        mach_vm_address_t mapped = 0;
        vm_prot_t current = 0, maximum = 0;
        if (mach_vm_remap(mach_task_self(), &mapped, span, 0, VM_FLAGS_ANYWHERE, mach_task_self(), begin, FALSE,
                          &current, &maximum, VM_INHERIT_NONE))
          return int32_t(0xc0000017);
        if (mach_vm_protect(mach_task_self(), mapped, span, FALSE, VM_PROT_READ | VM_PROT_WRITE)) {
          mach_vm_deallocate(mach_task_self(), mapped, span);
          return int32_t(0xc0000022);
        }
        r.alias = mapped + offset;
        patches.emplace(r.alias, PatchView{mapped, span, r.source, r.length, owner});
        return 0;
      }
    return int32_t(0xc000000d);
  }
  if (r.operation == FLI_JIT_END_PATCH) {
    auto it = patches.find(r.alias);
    if (it == patches.end() || it->second.source != r.source || it->second.requested != r.length)
      return int32_t(0xc000000d);
    if (mach_vm_deallocate(mach_task_self(), it->second.base, it->second.length))
      return int32_t(0xc0000001);
    patches.erase(it);
    return 0;
  }
  if (r.operation == FLI_JIT_TRIM) {
    auto it = views.find(r.source);
    return it != views.end() && !trim_view(it->second, r.length) ? 0 : int32_t(0xc000000d);
  }
  if (!r.source || !r.length || r.length > 2ULL * 1024 * 1024 * 1024 || ((r.source | r.length) & 16383) ||
      r.operation > FLI_JIT_RELEASE)
    return int32_t(0xc000000d);
  if (r.operation == FLI_JIT_RELEASE) {
    auto it = views.find(r.source);
    if (it == views.end() || it->second.alias != r.alias || it->second.length != r.length)
      return int32_t(0xc000000d);
    for (const auto &[key, p] : patches)
      if (p.owner == r.source)
        return int32_t(0xc00000aa);
    if (mach_vm_deallocate(mach_task_self(), r.alias, r.length))
      return int32_t(0xc0000001);
    views.erase(it);
    return 0;
  }
  if (views.contains(r.source) || r.alias)
    return int32_t(0xc000000d);
  mach_vm_address_t result = 0;
  vm_prot_t current = 0, maximum = 0;
  auto status = mach_vm_remap(mach_task_self(), &result, r.length, 0, VM_FLAGS_ANYWHERE, mach_task_self(), r.source,
                              FALSE, &current, &maximum, VM_INHERIT_COPY);
  if (status)
    return int32_t(0xc0000017);
  if (mach_vm_protect(mach_task_self(), result, r.length, FALSE, VM_PROT_READ | VM_PROT_WRITE)) {
    mach_vm_deallocate(mach_task_self(), result, r.length);
    return int32_t(0xc0000022);
  }
  views.emplace(r.source, View{result, r.length, 0});
  r.alias = result;
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t (*const __wine_unix_call_funcs[])(void *) = {
  unsupported,
  unsupported,
  unsupported,
  unsupported,
  unsupported,
  unsupported,
  alias
};
