#include "runtime-env.h"
#include "generated-abi.h"
#include "paths.h"
#include "linux-thread-owner.h"
#include "file-identity.h"
#include "cwd-service.h"
#include "sleep-service.h"
#include "memory-owner-abi.h"
// Private, opt-in Linux syscall carrier for anonymous x64 Unix trampolines.
// It performs real file operations. Unsupported operations return Linux errors;
// file seals, module validation and EAC authentication are never fabricated.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/arm/thread_status.h>
#include <libproc.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <pthread.h>
#include <condition_variable>
#include <memory>
#include <optional>
#include <atomic>
#include <codecvt>
#include <crt_externs.h>
#include <locale>
#include <signal.h>
#include <sched.h>
#include <sys/ucontext.h>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <map>
#include "futex-service.h"
#include "runtime-abi.h"
#include <unistd.h>
#include "fli_darwin_pci_inventory.h"
#include "fli_elf_thread_abi.h"


static std::mutex Lock;
static std::unordered_set<uint64_t> LinuxPages;
static std::unordered_set<uint64_t> NativeExecutionPages;
static pid_t NativeExecutionPid;
static std::unordered_set<int> Descriptors;
// Only virtual proc reopens and directory cookies need a userspace cursor.
// Ordinary file descriptions share the kernel cursor across owners, dup and fork.
static std::unordered_map<int, uint64_t> FilePositions;
static std::unordered_map<int, DIR *> DirectoryStreams;
static std::unordered_set<int> ReadonlyDescriptors;
struct MemfdState {
  std::atomic_flag mutation = ATOMIC_FLAG_INIT;
  std::atomic<uint32_t> seals{0};
  int readonly = -1;
};
static_assert(std::atomic<uint32_t>::is_always_lock_free);
static std::unordered_map<int, MemfdState *> Memfds;
struct MemfdGuard {
  MemfdState *state;
  explicit MemfdGuard(MemfdState *value) : state(value) {
    if (state)
      while (state->mutation.test_and_set(std::memory_order_acquire))
        sched_yield();
  }
  ~MemfdGuard() {
    if (state)
      state->mutation.clear(std::memory_order_release);
  }
};
static int32_t query_root_memory(uint64_t, uint64_t *);
static uint64_t current_wine_ntdll();
static uint64_t current_wine_module(const char *expected);
static bool accessible_process(int pid);
static int64_t linux_error(int error);
static bool read_name(uint64_t address, std::string &name, unsigned limit);
static int64_t cmdline_snapshot(int pid);
static void snapshot_loaded_elf(int fd, const char *path = nullptr);
static void *wine_unix_symbol(const char *name) {
  const char *root = getenv("WINEBUILDDIR");
  if (!root)
    return nullptr;
  void *library = dlopen((std::string(root) + "/dlls/ntdll/ntdll.so").c_str(), RTLD_NOW | RTLD_NOLOAD);
  if (!library)
    return nullptr;
  void *symbol = dlsym(library, name);
  dlclose(library);
  return symbol;
}
static int wine_protect(void *address, size_t size, uint32_t prot) {
  using function = int32_t (*)(void *, void **, size_t *, uint32_t, uint32_t *);
  auto call = reinterpret_cast<function>(wine_unix_symbol("NtProtectVirtualMemory"));
  if (!call)
    return -1;
  uint32_t old = 0;
  int32_t status = call(reinterpret_cast<void *>(-1), &address, &size, prot, &old);
  if (status)
    dprintf(2, "FLI_WINE_PROTECT status=%x address=%p size=%zx prot=%x\n", uint32_t(status), address, size, prot);
  return status;
}
static bool owned_mapping(uint64_t address, uint64_t size) {
  if (!size || address > UINT64_MAX - size)
    return false;
  for (uint64_t page = address; page < address + size;) {
    uint64_t region[4]{};
    if (query_root_memory(page, region) || region[0] > page || page - region[0] >= region[1])
      return false;
    page = std::min(address + size, region[0] + region[1]);
  }
  return true;
}
static std::mutex MemoryMutationLock;
static thread_local std::unique_lock<std::mutex> PendingMemoryMutation;
static thread_local std::vector<FliMemoryNotification> PendingMemoryNotifications;
static thread_local size_t PendingMemoryCursor;
extern "C" int32_t (*const __wine_unix_call_funcs[])(void *);
static bool install_memory_dispatch() {
  const uint64_t wine = current_wine_ntdll(), provider = current_wine_module("xtajit64.dll");
  if (!wine || !provider)
    return false;
  auto slot = reinterpret_cast<uint64_t *>(wine + VRCHAT_WINE_UNIX_DISPATCH_RVA);
  const uint64_t wrapper = provider + VRCHAT_FEX_MEMORY_DISPATCH_RVA;
  static uint64_t installed_split_lock;
  uint64_t split_lock = installed_split_lock;
  if (!split_lock) {
    auto get = reinterpret_cast<uint64_t (*)()>(dlsym(RTLD_DEFAULT, "fli_root_split_lock_address"));
    if (get)
      split_lock = get();
  }
  if (*slot == wrapper && installed_split_lock == split_lock)
    return true;
  const uint64_t notify = *reinterpret_cast<uint64_t *>(wine + REGRESSION_WINE_NOTIFY_PROTECT_RVA);
  if (!*slot || !notify)
    return false;
  using configure = void (*)(uint64_t, uint64_t, uint64_t, uint64_t);
  reinterpret_cast<configure>(provider + VRCHAT_FEX_CONFIGURE_MEMORY_RVA)(
      *slot == wrapper ? 0 : *slot, reinterpret_cast<uint64_t>(__wine_unix_call_funcs), notify, split_lock);
  *slot = wrapper;
  installed_split_lock = split_lock;
  if (split_lock)
    dprintf(2, "FLI_SHARED_SPLIT_LOCK_READY pid=%d one-root-and-native-mutex=1 address=%llx\n", getpid(),
            (unsigned long long)split_lock);
  dprintf(2, "FLI_MEMORY_DISPATCH_READY pid=%d user-stack-notification=1\n", getpid());
  return true;
}
static void notify_execution(uint64_t address, uint64_t size, uint64_t prot) {
  const uint32_t windows = (prot & 4) ? ((prot & 2) ? 0x40 : 0x20) : ((prot & 2) ? 4 : (prot & 1) ? 2 : 1);
  PendingMemoryNotifications.push_back({address, size, windows, 0});
}
static int32_t drain_memory_notification(void *opaque) {
  if (!opaque)
    return -22;
  if (PendingMemoryCursor < PendingMemoryNotifications.size()) {
    *static_cast<FliMemoryNotification *>(opaque) = PendingMemoryNotifications[PendingMemoryCursor++];
    return 1;
  }
  PendingMemoryNotifications.clear();
  PendingMemoryCursor = 0;
  if (PendingMemoryMutation.owns_lock())
    PendingMemoryMutation.unlock();
  return 0;
}
static int64_t protect_wine_pages(uint64_t address, uint64_t size, uint32_t prot) {
  using query = int32_t (*)(void *, const void *, uint32_t, void *, size_t, size_t *);
  const auto read = reinterpret_cast<query>(wine_unix_symbol("NtQueryVirtualMemory"));
  if (!read)
    return -12;
  struct Basic {
    uint64_t base, allocation;
    uint32_t allocation_protect, pad;
    uint64_t size;
    uint32_t state, protect, type, pad2;
  };
  static_assert(sizeof(Basic) == 48);
  const uint32_t windows = (prot & 4) ? ((prot & 2) ? 0x40 : 0x20) : ((prot & 2) ? 4 : (prot & 1) ? 2 : 1);
  for (uint64_t cursor = address; cursor < address + size;) {
    Basic info{};
    const int32_t queried =
        read(reinterpret_cast<void *>(-1), reinterpret_cast<void *>(cursor), 0, &info, sizeof(info), nullptr);
    if (queried || info.state != 0x1000 || info.base > cursor || cursor - info.base >= info.size)
      return -12;
    const uint64_t length = std::min<uint64_t>(address + size - cursor, info.size - (cursor - info.base));
    // Wine owns this committed VMA. Its existing page table and host projection
    // preserve 4 KiB guest permissions and neighboring pages on Darwin.
    const int32_t status = wine_protect(reinterpret_cast<void *>(cursor), length, windows);
    if (status)
      return uint32_t(status) == 0xc0000022u || uint32_t(status) == 0xc0000045u ? -13 : -12;
    // Do not register Windows pages as Linux syscall sources or create a
    // second protection table. Publish only the span Wine actually committed.
    notify_execution(cursor, length, prot);
    if (fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
      dprintf(2, "FLI_MEMORY_OWNER_PROTECT pid=%d owner=wine address=%llx length=%llx prot=%x type=%x result=0\n",
              getpid(), (unsigned long long)cursor, (unsigned long long)length, prot, info.type);
    cursor += length;
  }
  return 0;
}
static int64_t protect_root_pages(uint64_t address, uint64_t size, uint32_t prot) {
  const auto protect = reinterpret_cast<FliRootProtect>(dlsym(RTLD_DEFAULT, "fli_root_guest_protect_memory"));
  if (!protect)
    return protect_wine_pages(address, size, prot);
  FliMemoryProtectionRequest request{address, size, prot, -12};
  int32_t handled = 0;
  {
    // Root can call back into the bridge while holding its state lock.
    // Preserve the existing memory transaction gate, release only bridge state.
    struct UnlockForRoot {
      UnlockForRoot() { Lock.unlock(); }
      ~UnlockForRoot() { Lock.lock(); }
    } unlocked;
    handled = protect(&request);
  }
  if (handled != 1)
    return handled < 0 ? handled : protect_wine_pages(address, size, prot);
  if (!request.result) {
    for (uint64_t page = address; page < address + size; page += 4096) {
      NativeExecutionPages.erase(page);
      if (prot & 4)
        LinuxPages.insert(page);
      else
        LinuxPages.erase(page);
    }
    notify_execution(address, size, prot);
  }
  if (fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
    dprintf(2, "FLI_MEMORY_OWNER_PROTECT pid=%d owner=root address=%llx length=%llx prot=%x result=%lld\n", getpid(),
            (unsigned long long)address, (unsigned long long)size, prot, (long long)request.result);
  return request.result;
}
static int64_t protect_pages(uint64_t address, size_t size, uint32_t prot) {
  if ((address & 4095) || !size || (prot & ~7u) || size > UINT64_MAX - 4095)
    return -22;
  size = (size + 4095) & ~uint64_t(4095);
  if (address > UINT64_MAX - size)
    return -22;
  return protect_root_pages(address, size, prot);
}
struct ElfRegion {
  uint64_t start, end, offset;
  uint32_t flags;
  std::string name;
};
static std::vector<ElfRegion> ElfRegions;
static bool GlibcStarted;
static uint64_t GlibcFSBase;
static uint64_t GlibcBase;
static uint64_t GlibcLoaderBase;
static thread_local uint64_t ThreadLinuxFS;
static thread_local bool LinuxFSExplicit;
static thread_local bool LinuxTLSAttachPending;
struct AdoptedLinuxThread {
  uint64_t tcb = 0;
  ~AdoptedLinuxThread();
};
static thread_local AdoptedLinuxThread AdoptedThread;
static thread_local uint64_t ChildClearTID;
static bool ForkChild;
static std::unordered_set<pid_t> ChildProcesses;
#include "native-trace-state.h"
using NativeTrace::LinuxRegisters;
using NativeTrace::RootAliasMetadata;
using NativeTrace::TraceState;
static std::vector<RootAliasMetadata> RootAliases;
static size_t trace_bytes() { return (sizeof(TraceState) + getpagesize() - 1) & ~size_t(getpagesize() - 1); }
static TraceState *CurrentTrace;
struct TraceELFHeader {
  unsigned char ident[16];
  uint16_t type, machine;
  uint32_t version;
  uint64_t entry, phoff, shoff;
  uint32_t flags;
  uint16_t size, phsize, phnum, shsize, shnum, shstr;
};
struct TraceELFSegment {
  uint32_t type, flags;
  uint64_t offset, vaddr, paddr, filesz, memsz, align;
};
template <class T> static bool read_trace_metadata(uint64_t address, T &value) {
  mach_vm_size_t copied = 0;
  return mach_vm_read_overwrite(mach_task_self(), address, sizeof(value), reinterpret_cast<mach_vm_address_t>(&value),
                                &copied) == KERN_SUCCESS &&
         copied == sizeof(value);
}
// The adopted descriptor owns Linux thread identity. Fork writes its child TID
// there; Root callbacks borrow this same value rather than the Darwin thread ID.
static int current_linux_tid(uint64_t &tid) {
  if (AdoptedThread.tcb) {
    uint32_t stored = 0;
    if (ThreadLinuxFS != AdoptedThread.tcb || !read_trace_metadata(AdoptedThread.tcb + 720, stored) || !stored)
      return ESRCH;
    tid = stored;
    return 0;
  }
  return pthread_threadid_np(nullptr, &tid);
}

static bool append_trace_elf(uint64_t base, const char *name, unsigned &count) {
  TraceELFHeader header{};
  if (!read_trace_metadata(base, header)) {
    dprintf(2, "FLI_ROOT_ELF_HEADER_ERROR base=%llx step=read\n", (unsigned long long)base);
    return false;
  }
  if (memcmp(header.ident, "\177ELF", 4) || header.machine != 62 || header.phsize != sizeof(TraceELFSegment) ||
      header.phnum > 1024) {
    dprintf(2, "FLI_ROOT_ELF_HEADER_ERROR base=%llx step=metadata machine=%u phsize=%u phnum=%u\n",
            (unsigned long long)base, header.machine, header.phsize, header.phnum);
    return false;
  }
  for (unsigned i = 0; i < header.phnum && count < 64; ++i) {
    TraceELFSegment ph{};
    if (!read_trace_metadata(base + header.phoff + i * sizeof(ph), ph)) {
      dprintf(2, "FLI_ROOT_ELF_HEADER_ERROR base=%llx step=segment index=%u\n", (unsigned long long)base, i);
      return false;
    }
    if (ph.type != 1 || !ph.memsz)
      continue;
    auto &record = CurrentTrace->elf[count++];
    record.start = base + (ph.vaddr & ~uint64_t(4095));
    record.end = base + ((ph.vaddr + ph.memsz + 4095) & ~uint64_t(4095));
    record.offset = ph.offset & ~uint64_t(4095);
    record.flags = ph.flags;
    snprintf(record.name, sizeof(record.name), "%s", name);
  }
  return true;
}
static void refresh_trace_link_map() {
  if (!CurrentTrace || !CurrentTrace->elf_count.load())
    return;
  const uint64_t base = CurrentTrace->elf[0].start;
  TraceELFHeader header{};
  if (!read_trace_metadata(base, header) || header.phnum > 1024)
    return;
  uint64_t debug = 0;
  for (unsigned i = 0; i < header.phnum; ++i) {
    TraceELFSegment ph{};
    if (!read_trace_metadata(base + header.phoff + i * sizeof(ph), ph))
      return;
    if (ph.type != 2)
      continue;
    for (uint64_t n = 0; n < ph.memsz / 16 && n < 4096; ++n) {
      struct {
        uint64_t tag, value;
      } dynamic{};
      if (!read_trace_metadata(base + ph.vaddr + n * 16, dynamic) || !dynamic.tag)
        break;
      if (dynamic.tag == 21) {
        debug = dynamic.value;
        break;
      }
    }
  }
  struct Debug {
    uint32_t version, pad;
    uint64_t map, brk;
    uint32_t state, pad2;
    uint64_t loader;
  };
  Debug state{};
  if (!debug || !read_trace_metadata(debug, state) || state.state)
    return;
  unsigned count = 0, modules = 0;
  uint64_t next = state.map;
  while (next && modules++ < 16) {
    struct {
      uint64_t base, name, dynamic, next, previous;
    } map{};
    if (!read_trace_metadata(next, map))
      return;
    std::string name;
    if (map.name && !read_name(map.name, name, 511))
      return;
    if (name.empty())
      name = CurrentTrace->guest_program;
    if (!append_trace_elf(map.base, name.c_str(), count))
      return;
    next = map.next;
  }
  if (count) {
    CurrentTrace->elf_count.store(count, std::memory_order_release);
    dprintf(2, "FLI_ROOT_LINK_MAP pid=%d modules=%u regions=%u\n", getpid(), modules, count);
  }
}
static std::unordered_map<pid_t, TraceState *> TracedChildren;
static struct sigaction OriginalChildBus;
static uint64_t NativeUnalignedHandler;
static uint64_t NativeResetState;
static uint64_t NativeCallRetHandler;
static void *NativeMemoryQuery;
static bool import_current_trace() {
  if (CurrentTrace)
    return true;
  const char *fd_text = getenv("REGRESSION_LINUX_TRACE_FD"), *pid_text = getenv("REGRESSION_LINUX_TRACE_PID");
  if (!fd_text || !pid_text)
    return false;
  char *end = nullptr;
  long pid = strtol(pid_text, &end, 10);
  if (!end || *end || pid != getpid())
    return false;
  long fd = strtol(fd_text, &end, 10);
  if (!end || *end || fd < 3 || fd > 65535)
    return false;
  struct stat info{};
  if (fstat(int(fd), &info) || !S_ISREG(info.st_mode) || info.st_nlink || info.st_uid != geteuid() ||
      uint64_t(info.st_size) != trace_bytes())
    return false;
  void *memory = mmap(nullptr, trace_bytes(), PROT_READ | PROT_WRITE, MAP_SHARED, int(fd), 0);
  if (memory == MAP_FAILED)
    return false;
  auto *trace = static_cast<TraceState *>(memory);
  if (trace->magic != 0x464c495452414331ULL) {
    munmap(memory, trace_bytes());
    return false;
  }
  CurrentTrace = trace;
  ForkChild = true;
  dprintf(2, "FLI_LINUX_TRACE_IMPORTED pid=%d fd=%ld\n", getpid(), fd);
  return true;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_register_owner(uint64_t base, uint64_t frame) {
  if (!CurrentTrace && !import_current_trace())
    return 0;
  TraceELFHeader header{};
  uint64_t word = 0;
  if (!read_trace_metadata(base, header) || memcmp(header.ident, "\177ELF", 4) || header.machine != 62 || !frame ||
      !read_trace_metadata(frame, word))
    return -22;
  CurrentTrace->frame.store(frame);
  CurrentTrace->cpu_area.store(0);
  CurrentTrace->alignment_routing.store(false);
  CurrentTrace->root_owner.store(true, std::memory_order_release);
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_elf_exec_start(const char *program, uint64_t main,
                                                                                   uint64_t interpreter,
                                                                                   const uint64_t *registers,
                                                                                   uint64_t frame) {
  if (!import_current_trace())
    return -1;
  unsigned count = 0;
  for (auto [base, name] :
       {std::pair<uint64_t, const char *>{main, program}, {interpreter, "/lib64/ld-linux-x86-64.so.2"}}) {
    if (!base)
      continue;
    if (!append_trace_elf(base, name, count))
      return -8;
  }
  snprintf(CurrentTrace->guest_program, sizeof(CurrentTrace->guest_program), "%s", program);
  memcpy(&CurrentTrace->registers, registers, sizeof(LinuxRegisters));
  CurrentTrace->frame.store(frame);
  CurrentTrace->cpu_area.store(0);
  CurrentTrace->registers_valid.store(true);
  CurrentTrace->alignment_routing.store(false);
  CurrentTrace->elf_count.store(count);
  CurrentTrace->frontend_ready.store(true, std::memory_order_release);
  dprintf(2, "FLI_LINUX_ELF_EXEC_READY pid=%d regions=%u program=%s\n", getpid(), count, program);
  kill(getpid(), SIGSTOP);
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_set_smc_page(uint64_t base, uint64_t page,
                                                                                      int active) {
  if (!CurrentTrace)
    return 0; // Standalone controls have no external native tracer.
  const uint64_t size = getpagesize();
  if (page < base || (page - base) % size)
    return -22;
  const uint64_t index = (page - base) / size;
  if (index >= 4096 * 64)
    return -22;
  uint64_t expected = 0;
  if (!CurrentTrace->smc_base.compare_exchange_strong(expected, base) && expected != base)
    return -22;
  const uint64_t mask = uint64_t(1) << (index % 64);
  if (active)
    CurrentTrace->smc_pages[index / 64].fetch_or(mask, std::memory_order_release);
  else
    CurrentTrace->smc_pages[index / 64].fetch_and(~mask, std::memory_order_release);
  return 0;
}
extern "C" __attribute__((visibility("default"))) uint64_t fli_linux_root_take_changes(uint64_t *begin,
                                                                                       uint64_t *length) {
  if (!CurrentTrace)
    return 0;
  const uint64_t end = CurrentTrace->dirty_end.exchange(0), start = CurrentTrace->dirty_begin.exchange(UINT64_MAX);
  if (!end || start >= end)
    return 0;
  *begin = start;
  *length = end - start;
  return 1;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_publish_memory_fault(uint64_t address) {
  if (!CurrentTrace || !CurrentTrace->frontend_ready.load() || !CurrentTrace->traced.load())
    return -95;
  CurrentTrace->root_siginfo_address.store(address);
  CurrentTrace->root_siginfo_address_valid.store(true, std::memory_order_release);
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_take_delivery_signal() {
  return CurrentTrace ? CurrentTrace->root_delivery_signal.exchange(0, std::memory_order_acquire) : 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_trap(uint64_t *registers, void *floating,
                                                                              int signal, int code) {
  if (!CurrentTrace || !CurrentTrace->frontend_ready.load() || !CurrentTrace->traced.load())
    return -95;
  // SIGURG is intercepted by ptrace, but its native default disposition is
  // harmless when Darwin redelivers it during PT_DETACH (which ignores data).
  struct sigaction transport_action{};
  if (sigaction(SIGURG, nullptr, &transport_action))
    return linux_error(errno);
  if (transport_action.sa_handler != SIG_DFL && transport_action.sa_handler != SIG_IGN)
    return -95;
  refresh_trace_link_map();
  memcpy(&CurrentTrace->registers, registers, sizeof(LinuxRegisters));
  memcpy(CurrentTrace->floating, floating, sizeof(CurrentTrace->floating));
  CurrentTrace->floating_valid.store(true);
  CurrentTrace->registers_valid.store(true);
  CurrentTrace->root_trap_code.store(code);
  CurrentTrace->root_trap_stop.store(true);
  CurrentTrace->root_signal.store(signal);
  CurrentTrace->pending_signal.store(signal);
  dprintf(2, "FLI_ROOT_GUEST_TRAP pid=%d signal=%d code=%d rip=%llx rax=%llx\n", getpid(), signal, code,
          static_cast<unsigned long long>(CurrentTrace->registers.rip),
          static_cast<unsigned long long>(CurrentTrace->registers.rax));
  sigset_t trap_mask, previous_mask;
  sigemptyset(&trap_mask);
  sigaddset(&trap_mask, SIGURG);
  int status = pthread_sigmask(SIG_UNBLOCK, &trap_mask, &previous_mask);
  if (status) {
    CurrentTrace->root_trap_stop.store(false);
    return linux_error(status);
  }
  status = pthread_kill(pthread_self(), SIGURG);
  if (status) {
    pthread_sigmask(SIG_SETMASK, &previous_mask, nullptr);
    CurrentTrace->root_trap_stop.store(false);
    return linux_error(status);
  }
  while (CurrentTrace->root_trap_stop.load(std::memory_order_acquire))
    sched_yield();
  pthread_sigmask(SIG_SETMASK, &previous_mask, nullptr);
  dprintf(2, "FLI_ROOT_GUEST_TRAP_RESUMED pid=%d\n", getpid());
  memcpy(registers, &CurrentTrace->registers, sizeof(LinuxRegisters));
  memcpy(floating, CurrentTrace->floating, sizeof(CurrentTrace->floating));
  CurrentTrace->registers_valid.store(false);
  CurrentTrace->floating_valid.store(false);
  CurrentTrace->root_siginfo_address_valid.store(false, std::memory_order_release);
  return 0;
}
static void child_bus_observer(int signal, siginfo_t *info, void *opaque) {
  static const char marker[] = "FLI_CHILD_BUS_HANDLER_ENTER\n";
  write(2, marker, sizeof(marker) - 1);
  auto *context = static_cast<ucontext_t *>(opaque);
  if (CurrentTrace && CurrentTrace->probe_bus.exchange(false)) {
    const auto &native = context->uc_mcontext->__ss;
    const uint32_t esr = context->uc_mcontext->__es.__esr;
    CurrentTrace->fault_code.store(info->si_code);
    CurrentTrace->fault_esr.store(esr);
    CurrentTrace->fault_pc.store(native.__pc);
    CurrentTrace->fault_frame.store(native.__x[24]);
    CurrentTrace->fault_address.store(context->uc_mcontext->__es.__far);
    CurrentTrace->fault_guest_prot.store(UINT32_MAX);
    CurrentTrace->fault_wine_prot.store(0);
    CurrentTrace->fault_wine_type.store(0);
    CurrentTrace->fault_allocation.store(0);
    // User-raised signals can interrupt a bridge syscall while Lock is held.
    // Their saved ESR/FAR may be stale; query memory only for hardware faults.
    if (info->si_code == BUS_ADRALN && (esr >> 26) == 0x24) {
      {
        std::lock_guard guard(Lock); // query_root_memory releases this gate before entering Root.
        uint64_t region[4]{};
        CurrentTrace->fault_guest_prot.store(
            query_root_memory(context->uc_mcontext->__es.__far, region) ? UINT32_MAX : uint32_t(region[3]));
      }
      if (NativeMemoryQuery) {
        struct basic {
          uint64_t base, allocation;
          uint32_t allocation_protect, pad;
          uint64_t size;
          uint32_t state, protect, type, pad2;
        } memory{};
        using query = int32_t (*)(void *, const void *, uint32_t, void *, size_t, size_t *);
        if (!reinterpret_cast<query>(NativeMemoryQuery)(reinterpret_cast<void *>(-1),
                                                        reinterpret_cast<void *>(context->uc_mcontext->__es.__far), 0,
                                                        &memory, sizeof(memory), nullptr)) {
          CurrentTrace->fault_wine_prot.store(memory.protect);
          CurrentTrace->fault_wine_type.store(memory.type);
          CurrentTrace->fault_allocation.store(memory.allocation);
        }
      }
    }
    // ARM alignment traps in the FEX execution frame are host implementation
    // exceptions. Let the existing Wine/FEX handler execute the x64 operation.
    if (info->si_code == BUS_ADRALN && (esr & 0x3f) == 0x21 && native.__x[24] == CurrentTrace->frame.load()) {
      const uint64_t frame = CurrentTrace->frame.load(), area = CurrentTrace->cpu_area.load();
      const uint64_t header = *reinterpret_cast<uint64_t *>(frame);
      const uint32_t tail = header ? *reinterpret_cast<uint32_t *>(header) : 0;
      if (NativeUnalignedHandler && area && tail >= 4 && tail < 64 * 1024 * 1024 && native.__pc >= header + 4 &&
          native.__pc < header + tail) {
        // Invoke the exact running FOSS provider with its own ThreadState.
        // The helper performs the atomic operation or backpatch; it is not a
        // skipped instruction or a replacement value for guest computation.
        using handler = std::optional<int32_t> (*)(void *, uint32_t, uint64_t, uint64_t *, bool);
        auto thread = *reinterpret_cast<void **>(area + 0x38);
        auto advance = reinterpret_cast<handler>(NativeUnalignedHandler)(thread, 0, native.__pc,
                                                                         context->uc_mcontext->__ss.__x, true);
        if (advance) {
          context->uc_mcontext->__ss.__pc += *advance;
          CurrentTrace->alignments.fetch_add(1);
          return;
        }
      }
    }
    const uint64_t area = CurrentTrace->cpu_area.load(), frame = CurrentTrace->frame.load();
    const uint32_t guest_prot = CurrentTrace->fault_guest_prot.load();
    if (NativeResetState && area && native.__x[24] == frame && guest_prot != UINT32_MAX && (guest_prot & 6) == 6 &&
        (esr & 0x40) && (((esr & 0x3c) == 0x04) || ((esr & 0x3c) == 0x0c)) &&
        CurrentTrace->fault_wine_prot.load() == 0x20) {
      struct alignas(16) ArmContext {
        uint32_t flags, cpsr;
        uint64_t x[31], sp, pc;
        __uint128_t vectors[32];
        uint32_t fpcr, fpsr;
        unsigned char debug[120];
      } arm{};
      static_assert(offsetof(ArmContext, pc) == 0x108 && offsetof(ArmContext, vectors) == 0x110);
      struct ExceptionRecord {
        uint32_t code, flags;
        uint64_t record, address;
        uint32_t count, pad;
        uint64_t info[15];
      } record{};
      arm.flags = 0x400007;
      arm.cpsr = native.__cpsr;
      memcpy(arm.x, native.__x, sizeof(arm.x));
      arm.sp = native.__sp;
      arm.pc = native.__pc;
      memcpy(arm.vectors, context->uc_mcontext->__ns.__v, sizeof(arm.vectors));
      arm.fpcr = context->uc_mcontext->__ns.__fpcr;
      arm.fpsr = context->uc_mcontext->__ns.__fpsr;
      record.code = 0xc0000005;
      record.address = native.__pc;
      record.count = 2;
      record.info[0] = 1;
      record.info[1] = CurrentTrace->fault_address.load();
      // Match the running provider's ScopedCallbackDisable, avoiding Wine's
      // process-debug event path for a Linux-only fork child.
      auto *callback = reinterpret_cast<uint8_t *>(area + 1);
      const uint8_t previous = *callback;
      *callback = 1;
      using reset = bool (*)(void *, void *, void *, void *);
      const bool handled =
          reinterpret_cast<reset>(NativeResetState)(reinterpret_cast<void *>(area), &record, nullptr, &arm);
      *callback = previous;
      if (handled) {
        arm.x[24] = frame;
        memcpy(context->uc_mcontext->__ss.__x, arm.x, sizeof(arm.x));
        context->uc_mcontext->__ss.__sp = arm.sp;
        context->uc_mcontext->__ss.__pc = arm.pc;
        context->uc_mcontext->__ss.__cpsr = arm.cpsr;
        memcpy(context->uc_mcontext->__ns.__v, arm.vectors, sizeof(arm.vectors));
        context->uc_mcontext->__ns.__fpcr = arm.fpcr;
        context->uc_mcontext->__ns.__fpsr = arm.fpsr;
        CurrentTrace->code_writes.fetch_add(1);
        return;
      }
    }
    if (NativeCallRetHandler && info->si_code == BUS_ADRALN && (esr >> 26) == 0x24 &&
        (((esr & 0x3c) == 0x04) || ((esr & 0x3c) == 0x0c)) && frame && native.__x[24] == frame) {
      using recover = int32_t (*)(void *, uint64_t, uint64_t, uint64_t *);
      if (reinterpret_cast<recover>(NativeCallRetHandler)(reinterpret_cast<void *>(frame), native.__pc,
                                                          context->uc_mcontext->__es.__far,
                                                          &context->uc_mcontext->__ss.__x[17]))
        return;
    }
    // Preserve other SIGBUS events for the guest tracer, before delivering or
    // suppressing them as it requests. Do not expose stale syscall registers.
    CurrentTrace->registers_valid.store(false);
    CurrentTrace->pending_signal.store(SIGBUS);
    kill(getpid(), SIGSTOP);
    if (CurrentTrace->delivery_signal.exchange(0) != SIGBUS)
      return;
  }
  OriginalChildBus.sa_sigaction(signal, info, opaque);
}
static void install_child_bus_observer() {
  if (!fli_env_enabled("REGRESSION_ROUTE_CHILD_ALIGNMENT"))
    return;
  if (sigaction(SIGBUS, nullptr, &OriginalChildBus) || !(OriginalChildBus.sa_flags & SA_SIGINFO) ||
      !OriginalChildBus.sa_sigaction)
    return;
  const uint64_t provider = current_wine_module("xtajit64.dll");
  if (!provider)
    return;
  // Pinned public FEX provider SHA-256 0dde3c54...3fc14330.
  NativeUnalignedHandler = provider + REGRESSION_FEX_UNALIGNED_RVA;
  NativeResetState = provider + REGRESSION_FEX_RESET_RVA;
  NativeCallRetHandler = REGRESSION_FEX_CALLRET_RVA ? provider + REGRESSION_FEX_CALLRET_RVA : 0;
  NativeMemoryQuery = wine_unix_symbol("NtQueryVirtualMemory");
  auto action = OriginalChildBus;
  action.sa_sigaction = child_bus_observer;
  if (!sigaction(SIGBUS, &action, nullptr))
    CurrentTrace->alignment_routing.store(true);
  sigset_t mask{};
  pthread_sigmask(SIG_SETMASK, nullptr, &mask);
  stack_t stack{};
  sigaltstack(nullptr, &stack);
  dprintf(2, "FLI_CHILD_SIGNAL_STATE bus-blocked=%d segv-blocked=%d trap-blocked=%d alt-flags=%x\n",
          sigismember(&mask, SIGBUS), sigismember(&mask, SIGSEGV), sigismember(&mask, SIGTRAP), stack.ss_flags);
}
// The parent waits on one traced ELF at a time. Keep its actual Mach task port
// across stops; XNU task_for_pid otherwise dominates the hot SIGBUS route.
static thread_local pid_t RootFaultTaskPID = -1;
static thread_local mach_port_t RootFaultTask = MACH_PORT_NULL;
static bool root_internal_bus_fault(pid_t child, const TraceState *trace) {
  if (RootFaultTaskPID != child) {
    if (RootFaultTask != MACH_PORT_NULL)
      mach_port_deallocate(mach_task_self(), RootFaultTask);
    RootFaultTask = MACH_PORT_NULL;
    RootFaultTaskPID = child;
  }
  if (RootFaultTask == MACH_PORT_NULL && task_for_pid(mach_task_self(), child, &RootFaultTask) != KERN_SUCCESS)
    return false;
  thread_act_array_t threads = nullptr;
  mach_msg_type_number_t count = 0;
  bool alignment = false;
  kern_return_t status = task_threads(RootFaultTask, &threads, &count);
  if (status != KERN_SUCCESS) {
    mach_port_deallocate(mach_task_self(), RootFaultTask);
    RootFaultTask = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), child, &RootFaultTask) != KERN_SUCCESS)
      return false;
    status = task_threads(RootFaultTask, &threads, &count);
  }
  if (status == KERN_SUCCESS) {
    for (unsigned i = 0; i < count; ++i) {
      arm_exception_state64_t exception{};
      mach_msg_type_number_t n = ARM_EXCEPTION_STATE64_COUNT;
      if (thread_get_state(threads[i], ARM_EXCEPTION_STATE64, reinterpret_cast<thread_state_t>(&exception), &n) ==
              KERN_SUCCESS &&
          (exception.__esr >> 26) == 0x24) {
        if ((exception.__esr & 0x3f) == 0x21)
          alignment = true;
        const uint64_t base = trace->smc_base.load(), size = getpagesize();
        if (base && exception.__far >= base && (exception.__esr & 0x40) && ((exception.__esr & 0x3c) == 0x0c)) {
          const uint64_t index = (exception.__far - base) / size;
          if (index < 4096 * 64 &&
              (trace->smc_pages[index / 64].load(std::memory_order_acquire) & (uint64_t(1) << (index % 64))))
            alignment = true;
        }
      }
      mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(threads), count * sizeof(thread_t));
  }
  return alignment;
}
static int deliver_host_fault(pid_t child, int signal) {
  return ptrace(PT_CONTINUE, child, reinterpret_cast<caddr_t>(1), signal);
}
static pid_t wait_guest_child(pid_t target, int *status, int options) {
  unsigned observed = 0;
  for (;;) {
    pid_t child = waitpid(target, status, options);
    if (child > 0 && !WIFSTOPPED(*status) && child == RootFaultTaskPID) {
      if (RootFaultTask != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), RootFaultTask);
      RootFaultTask = MACH_PORT_NULL;
      RootFaultTaskPID = -1;
    }
    if (child <= 0 || !WIFSTOPPED(*status) || !TracedChildren.contains(child))
      return child;
    auto *trace = TracedChildren[child];
    // Internal SIGBUS fault recovery is frequent; the handled branch below stays observable
    // through SMC counters, while genuine guest stops still appear in wait outcomes.
    if (trace->frontend_ready.load() && WSTOPSIG(*status) != SIGBUS)
      dprintf(2, "FLI_ROOT_NATIVE_STOP pid=%d signal=%d pending=%d trap=%d\n", child, WSTOPSIG(*status),
              trace->pending_signal.load(), trace->root_trap_stop.load());
    if (WSTOPSIG(*status) == SIGTRAP && trace->exec_pending.load() && trace->deferred_exec.load()) {
      if (ptrace(PT_CONTINUE, child, reinterpret_cast<caddr_t>(1), 0) < 0)
        return child;
      continue;
    }
    if (WSTOPSIG(*status) == SIGSTOP && trace->exec_pending.load() &&
        trace->frontend_ready.load(std::memory_order_acquire)) {
      trace->exec_pending.store(false);
      trace->exec_completed.store(true);
      *status = 0x57f | ((trace->options.load() & 0x10) ? 4 << 16 : 0);
      dprintf(2, "FLI_LINUX_EXEC_EVENT pid=%d status=%x source=real-ELF-entry\n", child, *status);
      return child;
    }
    if (WSTOPSIG(*status) == SIGTRAP && trace->exec_pending.exchange(false)) {
      trace->exec_completed.store(true);
      trace->registers_valid.store(false);
      if (trace->options.load() & 0x10)
        *status |= 4 << 16;
      dprintf(2, "FLI_LINUX_EXEC_EVENT pid=%d status=%x\n", child, *status);
      return child;
    }
    if (WSTOPSIG(*status) == SIGURG && trace->root_trap_stop.load(std::memory_order_acquire)) {
      *status = (trace->root_signal.load() << 8) | 0x7f;
      return child;
    }
    if ((WSTOPSIG(*status) == SIGTRAP || WSTOPSIG(*status) == SIGSEGV) && trace->frontend_ready.load()) {
      if (trace->root_trap_stop.load())
        return child;
      // Let the real FEX synchronous-exception handler publish x86 state.
      if (deliver_host_fault(child, WSTOPSIG(*status)) < 0)
        return child;
      continue;
    }
    if (WSTOPSIG(*status) == SIGBUS &&
        (trace->root_owner.load() || trace->frontend_ready.load() || trace->smc_base.load()) &&
        root_internal_bus_fault(child, trace)) {
      if (deliver_host_fault(child, SIGBUS) < 0)
        return child;
      continue;
    }
    if (observed++ < 4)
      dprintf(2, "FLI_CHILD_WAIT_ROUTE pid=%d status=%x code=%d esr=%x handled=%llu\n", child, *status,
              trace->fault_code.load(), trace->fault_esr.load(),
              static_cast<unsigned long long>(trace->alignments.load()));
    if (WSTOPSIG(*status) == SIGSTOP && trace->pending_signal.load()) {
      *status = (trace->pending_signal.load() << 8) | 0x7f;
      if (trace->root_trap_stop.load())
        return child;
      dprintf(2,
              "FLI_CHILD_GUEST_BUS pid=%d code=%d esr=%x pc=%llx far=%llx frame-match=%d guest-prot=%x wine-prot=%x "
              "wine-type=%x allocation=%llx\n",
              child, trace->fault_code.load(), trace->fault_esr.load(),
              static_cast<unsigned long long>(trace->fault_pc.load()),
              static_cast<unsigned long long>(trace->fault_address.load()),
              trace->fault_frame.load() == trace->frame.load(), trace->fault_guest_prot.load(),
              trace->fault_wine_prot.load(), trace->fault_wine_type.load(),
              static_cast<unsigned long long>(trace->fault_allocation.load()));
      return child;
    }
    if (WSTOPSIG(*status) != SIGBUS || !trace->alignment_routing.load())
      return child;
    trace->probe_bus.store(true);
    if (ptrace(PT_CONTINUE, child, reinterpret_cast<caddr_t>(1), SIGBUS) < 0) {
      trace->probe_bus.store(false);
      return child;
    }
  }
}
extern "C" __attribute__((visibility("default"))) int32_t fli_probe_root_trace_fork() {
  if (CurrentTrace)
    return -95;
  void *memory = mmap(nullptr, trace_bytes(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (memory == MAP_FAILED)
    return linux_error(errno);
  auto *trace = new (memory) TraceState;
  pid_t child = fork();
  if (child == 0) {
    CurrentTrace = trace;
    ForkChild = true;
    TracedChildren.clear();
    ChildProcesses.clear();
    if (ptrace(PT_TRACE_ME, 0, nullptr, 0))
      _exit(126);
    trace->traced.store(true);
  } else if (child > 0) {
    TracedChildren[child] = trace;
    ChildProcesses.insert(child);
  }
  return child < 0 ? int32_t(linux_error(errno)) : int32_t(child);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_probe_root_trace_wait(int32_t child, int32_t *status) {
  return wait_guest_child(child, status, 0);
}
static int continue_guest_child(int child, TraceState *trace, int signal) {
  const bool pending = trace->pending_signal.load() != 0;
  const bool guest_fault =
      pending && trace->root_trap_stop.load() && trace->root_siginfo_address_valid.load() && signal == SIGSEGV;
  if (guest_fault)
    trace->root_delivery_signal.store(signal, std::memory_order_release);
  else if (pending)
    trace->delivery_signal.store(signal);
  const int delivered = pending && (signal == 0 || signal == SIGBUS || guest_fault) ? 0 : signal;
  const int status = ptrace(PT_CONTINUE, child, reinterpret_cast<caddr_t>(1), delivered);
  if (status < 0) {
    if (guest_fault)
      trace->root_delivery_signal.store(0);
    return linux_error(errno);
  }
  if (pending)
    trace->pending_signal.store(0);
  trace->stopped = false;
  trace->root_trap_stop.store(false, std::memory_order_release);
  return status;
}
static int detach_guest_child(int child, TraceState *trace, int signal) {
  const bool internal_stop = trace->root_trap_stop.load(std::memory_order_acquire);
  const int status = ptrace(PT_DETACH, child, reinterpret_cast<caddr_t>(1), signal);
  if (status < 0)
    return linux_error(errno);
  trace->traced.store(false);
  trace->stopped = false;
  trace->root_trap_stop.store(false, std::memory_order_release);
  if (internal_stop)
    trace->pending_signal.store(0);
  dprintf(2, "FLI_LINUX_DETACH pid=%d internal_trap=%d signal=%d\n", child, internal_stop, signal);
  return status;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_probe_root_trace_detach(int32_t child) {
  if (!TracedChildren.contains(child))
    return -3;
  return detach_guest_child(child, TracedChildren[child], 0);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_probe_root_trace_continue(int32_t child, int32_t signal) {
  if (!TracedChildren.contains(child))
    return -3;
  if (signal == SIGKILL) {
    const int result = ptrace(PT_KILL, child, reinterpret_cast<caddr_t>(1), 0);
    if (!result)
      TracedChildren[child]->root_trap_stop.store(false, std::memory_order_release);
    return result < 0 ? linux_error(errno) : result;
  }
  return continue_guest_child(child, TracedChildren[child], signal);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_probe_root_trace_guest_stop(int32_t child,
                                                                                          int32_t *signal,
                                                                                          uint64_t *rip) {
  auto it = TracedChildren.find(child);
  if (it == TracedChildren.end() || !it->second->root_trap_stop.load())
    return -95;
  *signal = it->second->root_signal.load();
  *rip = it->second->registers.rip;
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_probe_root_trace_guest_fault(int32_t child, uint64_t *rip,
                                                                                           uint64_t *address,
                                                                                           int32_t *code) {
  auto it = TracedChildren.find(child);
  if (it == TracedChildren.end() || !it->second->root_trap_stop.load() || it->second->root_signal.load() != SIGSEGV ||
      !it->second->root_siginfo_address_valid.load())
    return -95;
  *rip = it->second->registers.rip;
  *address = it->second->root_siginfo_address.load();
  *code = it->second->root_trap_code.load();
  return 0;
}
static void capture_registers(void *context, uint64_t original);
static bool stop_for_syscall(void *context, uint64_t original, bool entry) {
  if (!CurrentTrace || !CurrentTrace->traced.load() || !CurrentTrace->syscalls.load())
    return false;
  // Linux reserves the return slot as -ENOSYS at syscall entry; orig_rax
  // retains the actual requested operation. The provider later writes its result.
  if (entry)
    *reinterpret_cast<uint64_t *>(static_cast<char *>(context) + 0x48) = uint64_t(-38);
  capture_registers(context, original);
  CurrentTrace->syscall_stop.store(true);
  // This is an actual kernel ptrace stop, observed and resumed by the parent.
  kill(getpid(), SIGTRAP);
  CurrentTrace->syscall_stop.store(false);
  return true;
}
static int host_signal(unsigned signal) {
  static constexpr int signals[]{0,       SIGHUP,  SIGINT,    SIGQUIT, SIGILL,   SIGTRAP, SIGABRT, SIGBUS,
                                 SIGFPE,  SIGKILL, SIGUSR1,   SIGSEGV, SIGUSR2,  SIGPIPE, SIGALRM, SIGTERM,
                                 0,       SIGCHLD, SIGCONT,   SIGSTOP, SIGTSTP,  SIGTTIN, SIGTTOU, SIGURG,
                                 SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH, SIGIO,   0,       SIGSYS};
  return signal < std::size(signals) ? signals[signal] : 0;
}
static struct sigaction OriginalDiagSignal;
static int DiagCodeFD = -1;
static volatile sig_atomic_t DiagCaptured;
static uint64_t current_wine_teb() {
  uint64_t teb = 0, self = 0;
  asm volatile("mov %0,x28" : "=r"(teb));
  // Root ELF workers reserve x28 for their own state, not a Windows TEB.
  // Inspect only safe metadata before following any Windows pointer chain.
  return teb && teb <= UINT64_MAX - 0x30 && read_trace_metadata(teb + 0x30, self) && self == teb ? teb : 0;
}
static uint64_t current_wine_module(const char *expected) {
  const uint64_t teb = current_wine_teb();
  if (!teb)
    return 0;
  uint64_t peb = *reinterpret_cast<uint64_t *>(teb + 0x60);
  uint64_t ldr = peb ? *reinterpret_cast<uint64_t *>(peb + 0x18) : 0;
  if (!ldr)
    return 0;
  const uint64_t head = ldr + 0x20;
  uint64_t link = *reinterpret_cast<uint64_t *>(head);
  for (unsigned i = 0; link && link != head && i < 128; ++i) {
    uint64_t entry = link - 0x10;
    auto length = *reinterpret_cast<uint16_t *>(entry + 0x58);
    auto name = *reinterpret_cast<const uint16_t **>(entry + 0x60);
    const size_t characters = strlen(expected);
    bool match = length == 2 * characters && name;
    for (unsigned j = 0; match && j < characters; ++j)
      match = (name[j] | 32) == expected[j];
    if (match)
      return *reinterpret_cast<uint64_t *>(entry + 0x30);
    link = *reinterpret_cast<uint64_t *>(link);
  }
  return 0;
}
static uint64_t current_wine_ntdll() { return current_wine_module("ntdll.dll"); }
static const char *carrier_path() {
  const char *path = getenv("REGRESSION_FLI_CARRIER");
  return path ? path : fli_host_path("REGRESSION_FLI_CARRIER");
}
static const char *running_wine_elf() {
  void *module = dlopen(carrier_path(), RTLD_NOW | RTLD_NOLOAD);
  if (!module)
    return nullptr;
  using Get = const char *(*)();
  auto get = reinterpret_cast<Get>(dlsym(module, "fli_wine_guest_executable"));
  const char *path = get ? get() : nullptr;
  dlclose(module);
  return path;
}
static std::string guest_executable() {
  if (const char *path = running_wine_elf())
    return path;
  if (fli_env_enabled("REGRESSION_PROC_EXE_HOST")) {
    char path[PROC_PIDPATHINFO_MAXSIZE]{};
    return proc_pidpath(getpid(), path, sizeof(path)) > 0 ? std::string(path) : std::string{};
  }
  const uint64_t teb = current_wine_teb();
  if (!teb)
    return {};
  uint64_t peb = *reinterpret_cast<uint64_t *>(teb + 0x60);
  if (!peb)
    return {};
  uint64_t image = *reinterpret_cast<uint64_t *>(peb + 0x10), ldr = *reinterpret_cast<uint64_t *>(peb + 0x18);
  if (!ldr)
    return {};
  uint64_t head = ldr + 0x20, link = *reinterpret_cast<uint64_t *>(head);
  for (unsigned i = 0; link && link != head && i < 128; ++i) {
    uint64_t entry = link - 0x10;
    if (*reinterpret_cast<uint64_t *>(entry + 0x30) == image) {
      uint16_t length = *reinterpret_cast<uint16_t *>(entry + 0x48);
      auto data = *reinterpret_cast<const char16_t **>(entry + 0x50);
      if (!data || length > 8192)
        return {};
      std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
      std::string path = converter.to_bytes(data, data + length / 2);
      std::replace(path.begin(), path.end(), '\\', '/');
      if (path.starts_with("Z:/") || path.starts_with("z:/"))
        path = path.substr(2);
      else if (path.starts_with("C:/") || path.starts_with("c:/")) {
        const char *prefix = getenv("WINEPREFIX");
        if (!prefix)
          return {};
        path = std::string(prefix) + "/drive_c" + path.substr(2);
      }
      return path;
    }
    link = *reinterpret_cast<uint64_t *>(link);
  }
  return {};
}
static bool register_elf_execution() {
  const uint64_t base = current_wine_ntdll();
  if (!base)
    return false;
  // Actual initialized provider pointer in the pinned public Wine build.
  using notify = void (*)(void *, size_t, uint32_t, uint32_t, int32_t, int32_t);
  auto function = *reinterpret_cast<notify *>(base + REGRESSION_WINE_NOTIFY_ALLOC_RVA);
  if (!function)
    return false;
  uint64_t teb;
  asm volatile("mov %0, x28" : "=r"(teb));
  const uint64_t area = teb ? *reinterpret_cast<uint64_t *>(teb + 0x1788) : 0;
  dprintf(2, "FLI_ELF_NOTIFY_STATE callback=%u simulation=%u tid=%llu\n",
          area ? *reinterpret_cast<uint8_t *>(area + 1) : 255, area ? *reinterpret_cast<uint8_t *>(area) : 255,
          static_cast<unsigned long long>(teb ? *reinterpret_cast<uint64_t *>(teb + 0x48) : 0));
  if (!area)
    return false;
  struct CallbackScope {
    uint8_t *state;
    uint8_t previous;
    explicit CallbackScope(uint64_t area) : state(reinterpret_cast<uint8_t *>(area + 1)), previous(*state) {
      *state = 1;
    }
    ~CallbackScope() { *state = previous; }
  } callback_scope(area);
  dprintf(2, "FLI_ELF_CALLBACK_SCOPE area=%llx active=%u\n", static_cast<unsigned long long>(area),
          *reinterpret_cast<uint8_t *>(area + 1));
  unsigned count = 0;
  for (const auto &region : ElfRegions) {
    if (!(region.flags & 1))
      continue;
    void *address = reinterpret_cast<void *>(region.start);
    size_t length = region.end - region.start;
    dprintf(2, "FLI_ELF_NOTIFY_ENTRY callback=%p provider=%llx address=%p length=%zx\n",
            reinterpret_cast<void *>(function), static_cast<unsigned long long>(current_wine_module("xtajit64.dll")),
            address, length);
    const uint64_t tracker = current_wine_module("xtajit64.dll") + VRCHAT_FEX_INVALIDATION_TRACKER_RVA;
    // Read-only diagnostic of the exact FOSS provider's interval lock. Symbol
    // RVA and libc++ field offsets are recorded by nm/layout control v582.
    dprintf(2, "FLI_ELF_INTERVAL_STATE before=%08x\n", *reinterpret_cast<uint32_t *>(tracker + 72));
    function(address, length, 0x1000, 0x20, 0, 0);
    dprintf(2, "FLI_ELF_NOTIFY_PRE_DONE state=%08x\n", *reinterpret_cast<uint32_t *>(tracker + 72));
    function(address, length, 0x1000, 0x20, 1, 0);
    dprintf(2, "FLI_ELF_NOTIFY_POST_DONE state=%08x\n", *reinterpret_cast<uint32_t *>(tracker + 72));
    ++count;
  }
  dprintf(2, "FLI_GLIBC_FEX_EXECUTION ntdll=%llx regions=%u\n", static_cast<unsigned long long>(base), count);
  return count != 0;
}
static void capture_owned_probe_fault(int signal, siginfo_t *info, void *opaque) {
  auto *context = static_cast<ucontext_t *>(opaque);
  auto &state = context->uc_mcontext->__ss;
  if (!DiagCaptured && DiagCodeFD >= 0) {
    DiagCaptured = 1;
    uint64_t values[]{state.__pc,
                      state.__x[8],
                      state.__x[9],
                      state.__x[16],
                      state.__x[17],
                      state.__x[24],
                      state.__x[24] ? *reinterpret_cast<uint64_t *>(state.__x[24] + 24) : 0};
    write(DiagCodeFD, values, sizeof(values));
    // Enabled only for our own PE probe plus FOSS GLIBC, never for EAC runs.
    write(DiagCodeFD, reinterpret_cast<void *>(state.__pc & ~uint64_t(4095)), 4096);
  }
  if (OriginalDiagSignal.sa_flags & SA_SIGINFO)
    OriginalDiagSignal.sa_sigaction(signal, info, opaque);
  else if (OriginalDiagSignal.sa_handler != SIG_IGN && OriginalDiagSignal.sa_handler != SIG_DFL)
    OriginalDiagSignal.sa_handler(signal);
}
static bool ensure_glibc(bool defer_notification = false) {
  if (GlibcStarted)
    return true;
  if (!fli_env_enabled("REGRESSION_HOST_GLIBC"))
    return false;
  void *library = dlopen(carrier_path(), RTLD_NOW | RTLD_GLOBAL);
  if (!library) {
    dprintf(2, "FLI_GLIBC_LOAD_ERROR %s\n", dlerror());
    return false;
  }
  using start = int32_t (*)(uint64_t *);
  auto function = reinterpret_cast<start>(dlsym(library, "fli_start_glibc"));
  uint64_t data[4]{};
  int32_t status = function ? function(data) : -1;
  if (status) {
    dprintf(2, "FLI_GLIBC_START_ERROR %d\n", status);
    return false;
  }
  struct link_map {
    uint64_t base;
    const char *name;
    void *dynamic;
    link_map *next, *previous;
  };
  struct ehdr {
    unsigned char ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t size, phsize, phnum, shsize, shnum, shstr;
  };
  struct phdr {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
  };
  unsigned modules = 0;
  for (auto *map = reinterpret_cast<link_map *>(data[0]); map && modules < 16; map = map->next, ++modules) {
    const char *name = map->name && *map->name ? map->name : running_wine_elf();
    if (!name)
      continue;
    if (strstr(name, "libc.so.6"))
      GlibcBase = map->base;
    if (strstr(name, "ld-linux-x86-64.so.2"))
      GlibcLoaderBase = map->base;
    auto *header = reinterpret_cast<const ehdr *>(map->base);
    if (memcmp(header->ident, "\177ELF", 4) || header->ident[4] != 2 || header->machine != 62 ||
        header->phsize != sizeof(phdr))
      continue;
    auto *segments = reinterpret_cast<const phdr *>(map->base + header->phoff);
    for (unsigned i = 0; i < header->phnum; ++i) {
      const auto &segment = segments[i];
      if (segment.type != 1 || !segment.memsz)
        continue;
      ElfRegions.push_back({map->base + (segment.vaddr & ~uint64_t(4095)),
                            map->base + ((segment.vaddr + segment.memsz + 4095) & ~uint64_t(4095)),
                            segment.offset & ~uint64_t(4095), segment.flags, name});
      if (segment.flags & 1)
        for (uint64_t page = ElfRegions.back().start; page < ElfRegions.back().end; page += 4096)
          LinuxPages.insert(page);
    }
    dprintf(2, "FLI_GLIBC_REAL_ELF base=%llx name=%s\n", static_cast<unsigned long long>(map->base), name);
  }
  GlibcFSBase = data[1];
  GlibcStarted = !ElfRegions.empty();
  if (GlibcStarted && !defer_notification && !register_elf_execution()) {
    dprintf(2, "FLI_GLIBC_FEX_EXECUTION unavailable\n");
    GlibcStarted = false;
  }
  if (GlibcStarted && fli_env_enabled("REGRESSION_DIAG_GLIBC_EXPORTS")) {
    DiagCodeFD = open((std::string(fli_host_path("VRCHAT_STATE_DIR")) + "/fault-code.bin").c_str(),
                      O_CREAT | O_TRUNC | O_WRONLY, 0600);
    struct sigaction action{};
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = capture_owned_probe_fault;
    sigaction(SIGSEGV, &action, &OriginalDiagSignal);
  }
  dprintf(2, "FLI_GLIBC_HOSTED pid=%d modules=%u regions=%zu fs=%llx\n", getpid(), modules, ElfRegions.size(),
          static_cast<unsigned long long>(GlibcFSBase));
  return GlibcStarted;
}
static bool anonymous_code(uint64_t pc) {
  const char *root = getenv("WINEBUILDDIR");
  if (!root)
    return false;
  const std::string path = std::string(root) + "/dlls/ntdll/ntdll.so";
  void *library = dlopen(path.c_str(), RTLD_NOW | RTLD_NOLOAD);
  if (!library)
    return false;
  using query = int32_t (*)(void *, const void *, uint32_t, void *, size_t, size_t *);
  auto function = reinterpret_cast<query>(dlsym(library, "NtQueryVirtualMemory"));
  struct basic {
    uint64_t base, allocation;
    uint32_t allocation_protect, pad;
    uint64_t size;
    uint32_t state, protect, type, pad2;
  } info{};
  int32_t status =
      function ? function(reinterpret_cast<void *>(-1), reinterpret_cast<void *>(pc), 0, &info, sizeof(info), nullptr)
               : -1;
  dlclose(library);
  return status == 0 && info.type == 0x20000 && info.state == 0x1000;
}
static uint64_t &word(void *context, size_t offset) {
  return *reinterpret_cast<uint64_t *>(static_cast<char *>(context) + offset);
}
static bool read_linux_context(void *context, uint64_t original, LinuxRegisters &r, void *floating = nullptr,
                               void *ymm = nullptr, uint32_t *has_ymm = nullptr) {
  const uint64_t base = current_wine_ntdll();
  if (!base)
    return false;
  // The pinned FOSS Wine converter is also used by dispatch_emulation.
  using convert = void (*)(void *, const void *);
  alignas(16) unsigned char x64[0x4d0]{};
  reinterpret_cast<convert>(base + REGRESSION_WINE_CONTEXT_RVA)(x64, context);
  r.r15 = word(x64, 0xf0);
  r.r14 = word(x64, 0xe8);
  r.r13 = word(x64, 0xe0);
  r.r12 = word(x64, 0xd8);
  r.rbp = word(x64, 0xa0);
  r.rbx = word(x64, 0x90);
  r.r11 = word(x64, 0xd0);
  r.r10 = word(x64, 0xc8);
  r.r9 = word(x64, 0xc0);
  r.r8 = word(x64, 0xb8);
  r.rax = word(x64, 0x78);
  r.rcx = word(x64, 0x80);
  r.rdx = word(x64, 0x88);
  r.rsi = word(x64, 0xa8);
  r.rdi = word(x64, 0xb0);
  r.orig_rax = original;
  r.rip = word(x64, 0xf8);
  r.rsp = word(x64, 0x98);
  r.eflags = *reinterpret_cast<uint32_t *>(x64 + 0x44);
  r.cs = *reinterpret_cast<uint16_t *>(x64 + 0x38);
  r.ss = *reinterpret_cast<uint16_t *>(x64 + 0x42);
  r.ds = *reinterpret_cast<uint16_t *>(x64 + 0x3a);
  r.es = *reinterpret_cast<uint16_t *>(x64 + 0x3c);
  r.fs = *reinterpret_cast<uint16_t *>(x64 + 0x3e);
  r.gs = *reinterpret_cast<uint16_t *>(x64 + 0x40);
  uint64_t teb;
  asm volatile("mov %0,x28" : "=r"(teb));
  auto area = *reinterpret_cast<uint64_t *>(teb + 0x1788), frame = *reinterpret_cast<uint64_t *>(area + 0x30);
  r.fs_base = ThreadLinuxFS;
  r.gs_base = *reinterpret_cast<uint64_t *>(frame + 992);
  if (floating)
    memcpy(floating, x64 + 0x100, 512);
  if (has_ymm) {
    *has_ymm = (*static_cast<uint32_t *>(context) & 0x40) ? 1 : 0;
    if (*has_ymm && ymm)
      memcpy(ymm, static_cast<unsigned char *>(context) + 0x210, 256);
  }
  return true;
}
static void capture_registers(void *context, uint64_t original) {
  if (!CurrentTrace || !read_linux_context(context, original, CurrentTrace->registers))
    return;
  uint64_t teb;
  asm volatile("mov %0,x28" : "=r"(teb));
  auto area = *reinterpret_cast<uint64_t *>(teb + 0x1788), frame = *reinterpret_cast<uint64_t *>(area + 0x30);
  CurrentTrace->frame.store(frame);
  CurrentTrace->cpu_area.store(area);
  CurrentTrace->registers_valid.store(true);
}
static bool read_name(uint64_t address, std::string &name, unsigned limit = 250) {
  for (size_t offset = 0; offset < limit;) {
    if (address > UINT64_MAX - offset)
      return false;
    char bytes[256];
    size_t length = std::min<size_t>(sizeof(bytes), limit - offset);
    length = std::min<size_t>(length, 4096 - ((address + offset) & 4095));
    const auto read = [&](size_t size) {
      mach_vm_size_t copied = 0;
      return mach_vm_read_overwrite(mach_task_self(), address + offset, size,
                                    reinterpret_cast<mach_vm_address_t>(bytes), &copied) == KERN_SUCCESS &&
             copied == size;
    };
    if (!read(length)) {
      length = 1;
      if (!read(length))
        return false;
    }
    const auto *end = static_cast<const char *>(std::memchr(bytes, 0, length));
    name.append(bytes, end ? size_t(end - bytes) : length);
    if (end)
      return true;
    offset += length;
  }
  return false;
}
static bool read_vector(uint64_t address, std::vector<std::string> &values) {
  size_t bytes = 0;
  for (unsigned i = 0; i < 1024; ++i) {
    uint64_t pointer = 0;
    mach_vm_size_t copied = 0;
    if (mach_vm_read_overwrite(mach_task_self(), address + i * 8, 8, reinterpret_cast<mach_vm_address_t>(&pointer),
                               &copied) != KERN_SUCCESS)
      return false;
    if (!pointer)
      return true;
    std::string value;
    if (!read_name(pointer, value, 32768) || (bytes += value.size() + 1) > 1024 * 1024)
      return false;
    values.push_back(std::move(value));
  }
  return false;
}
static void import_memfds() {
  static bool imported = false;
  if (imported)
    return;
  imported = true;
  const char *data = getenv("REGRESSION_INHERITED_MEMFDS");
  if (!data)
    return;
  std::string records = data;
  size_t begin = 0;
  while (begin < records.size()) {
    size_t end = records.find(';', begin);
    if (end == std::string::npos)
      break;
    int fd = -1, readonly = 0;
    unsigned seals = 0;
    char extra;
    std::string record = records.substr(begin, end - begin);
    begin = end + 1;
    if (sscanf(record.c_str(), "%d,%u,%d%c", &fd, &seals, &readonly, &extra) != 3 || fd < 3 || fd > 65535 ||
        (seals != 0 && seals != 1 && seals != 15))
      continue;
    struct stat st{};
    int mode = fcntl(fd, F_GETFL);
    if (mode < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 0 || st.st_uid != geteuid() ||
        (seals == 15 && (mode & O_ACCMODE) != O_RDONLY))
      continue;
    void *shared = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (shared == MAP_FAILED)
      continue;
    auto *state = new (shared) MemfdState;
    state->seals.store(seals);
    state->readonly = dup(fd);
    if (state->readonly >= 0)
      fcntl(state->readonly, F_SETFD, FD_CLOEXEC);
    // Writable inherited memfds cannot acquire a new immutable seal without
    // their original read-only backing. Keep them unavailable for new seals.
    if ((mode & O_ACCMODE) != O_RDONLY) {
      if (state->readonly >= 0)
        close(state->readonly);
      state->readonly = -1;
    }
    Memfds[fd] = state;
    Descriptors.insert(fd);
    if (readonly)
      ReadonlyDescriptors.insert(fd);
    dprintf(2, "FLI_LINUX_FD_INHERITED fd=%d seals=%u\n", fd, seals);
  }
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_open_inherited(int source) {
  std::lock_guard guard(Lock);
  import_memfds();
  auto found = Memfds.find(source);
  if (found == Memfds.end() || found->second->seals.load() != 15)
    return -9;
  int mode = fcntl(source, F_GETFL);
  if (mode < 0)
    return linux_error(errno);
  if ((mode & O_ACCMODE) != O_RDONLY)
    return -95;
  int alias = fcntl(source, F_DUPFD_CLOEXEC, 3);
  if (alias < 0)
    return linux_error(errno);
  if (const char *path = getenv("REGRESSION_DIAG_INHERITED_ELF")) {
    const int saved = errno;
    snapshot_loaded_elf(source, path);
    errno = saved;
  }
  dprintf(2, "FLI_ROOT_INHERITED_OPEN source=%d alias=%d\n", source, alias);
  return alias; // The ELF provider owns this alias and its independent offset.
}
static int64_t exec_native_wine(const std::string &executable, uint64_t argv_address, uint64_t env_address) {
  if (!fli_env_enabled("REGRESSION_NATIVE_WINE_EXEC"))
    return -38;
  char current[PROC_PIDPATHINFO_MAXSIZE]{};
  const char *guest = running_wine_elf();
  if (proc_pidpath(getpid(), current, sizeof(current)) <= 0 ||
      (executable != current && (!guest || executable != guest)))
    return -95;
  std::vector<std::string> arguments, environment;
  if (!read_vector(argv_address, arguments) || !read_vector(env_address, environment) || arguments.empty())
    return -14;
  // The Linux Wine Unix-entry convention can put the PE image in argv[0].
  // The native macOS wine command takes that same image in argv[1].
  if (fli_owned_host_path(arguments[0]) && arguments[0].ends_with(".exe"))
    arguments.insert(arguments.begin(), current);
  else if (guest && arguments[0] == guest)
    arguments[0] = current;
  std::map<std::string, std::string> merged;
  for (char **p = *_NSGetEnviron(); p && *p; ++p) {
    std::string entry = *p;
    size_t equal = entry.find('=');
    if (equal == std::string::npos)
      continue;
    std::string key = entry.substr(0, equal);
    if (key == "PATH" || key == "HOME" || key == "USER" || key == "LOGNAME" || key == "TMPDIR" ||
        key == "WINEBUILDDIR" || key == "WINEPREFIX" || key == "WINELOADER" || key == "WINEDEBUG" ||
        key == "WINEDEBUGGER" || key == "WINEDLLPATH" || key == "HTTP_PROXY" || key == "HTTPS_PROXY" ||
        key == "ALL_PROXY" || key == "NO_PROXY" || key == "http_proxy" || key == "https_proxy" || key == "all_proxy" ||
        key == "no_proxy" || key.starts_with("DYLD_") || key.starts_with("GST_") || key.starts_with("GI_") ||
        key.starts_with("VKMT_") || key.starts_with("FEX_") || key.starts_with("DXMT_") || key.starts_with("MVK_") ||
        key.starts_with("MTL_") || key.starts_with("REGRESSION_"))
      merged[key] = entry.substr(equal + 1);
  }
  for (const auto &entry : environment) {
    size_t equal = entry.find('=');
    if (equal == std::string::npos)
      return -22;
    std::string key = entry.substr(0, equal), value = entry.substr(equal + 1);
    if (key == "LD_PRELOAD" && !value.empty())
      return -95;
    if (key == "HOME" && value == "/home/regression")
      continue; // Native Wine keeps its existing host home.
    if (key == "WINEDLLPATH" && merged.contains(key))
      continue; // Host DLL paths belong to the native namespace.
    merged[key] = value;
  }
  std::string descriptors;
  for (auto [fd, state] : Memfds)
    if (fcntl(fd, F_GETFD) == 0) {
      MemfdGuard mutation(state);
      const off_t position = FilePositions.contains(fd) ? off_t(FilePositions.at(fd)) : lseek(fd, 0, SEEK_CUR);
      if (position < 0)
        return linux_error(errno);
      if (state->seals.load() == 15 && (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY) {
        if (state->readonly < 0)
          return -95;
        if (dup2(state->readonly, fd) < 0)
          return linux_error(errno);
      }
      if (lseek(fd, position, SEEK_SET) < 0)
        return linux_error(errno);
      descriptors += std::to_string(fd) + "," + std::to_string(state->seals.load()) + "," +
                     (ReadonlyDescriptors.contains(fd) ? "1;" : "0;");
    }
  merged["REGRESSION_INHERITED_MEMFDS"] = descriptors;
  if (CurrentTrace && guest && CurrentTrace->traced.load()) {
    merged["REGRESSION_LINUX_TRACE_FD"] = std::to_string(CurrentTrace->relay_fd);
    merged["REGRESSION_LINUX_TRACE_PID"] = std::to_string(getpid());
    merged["REGRESSION_NATIVE_ELF_EXEC_GATE"] = "1";
    CurrentTrace->deferred_exec.store(true);
    CurrentTrace->frontend_ready.store(false);
    CurrentTrace->elf_count.store(0);
  }
  std::vector<std::string> text;
  for (const auto &[key, value] : merged)
    text.push_back(key + "=" + value);
  std::vector<char *> args, env;
  for (auto &s : arguments)
    args.push_back(s.data());
  for (auto &s : text)
    env.push_back(s.data());
  args.push_back(nullptr);
  env.push_back(nullptr);
  if (CurrentTrace) {
    uint64_t tid = 0;
    current_linux_tid(tid);
    CurrentTrace->exec_old_tid.store(tid);
    CurrentTrace->exec_pending.store(true);
  }
  dprintf(2, "FLI_NATIVE_WINE_EXEC pid=%d argc=%zu inherited-memfds=%zu\n", getpid(), arguments.size(), Memfds.size());
  execve(current, args.data(), env.data());
  int error = errno;
  if (CurrentTrace)
    CurrentTrace->exec_pending.store(false);
  return linux_error(error);
}
static int64_t linux_error(int error) {
  // Darwin errno numbers differ from Linux for these file-operation errors.
  switch (error) {
  case EAGAIN:
    return -11;
  case ENOSYS:
    return -38;
  case EOPNOTSUPP:
    return -95;
  case EOVERFLOW:
    return -75;
  default:
    return -error;
  }
}
static int64_t add_memfd_seals(MemfdState *state, uint64_t requested) {
  if (!state)
    return -22;
  if (requested & ~uint64_t(15))
    return -22;
  if (state->seals.load() & 1)
    return -1;
  if (!requested)
    return 0;
  // The minimum supported combinations are SEAL_SEAL alone or the complete
  // immutable set. Partial resize/write seals need separate VM semantics.
  if (requested != 1 && requested != 15)
    return -95;
  if (requested == 15 && state->readonly < 0)
    return -95;
  if (requested == 15) {
    struct Saved {
      int fd, backup, flags;
    };
    std::vector<Saved> saved;
    for (auto [fd, object] : Memfds)
      if (object == state) {
        int backup = dup(fd);
        if (backup < 0) {
          int error = errno;
          for (auto &s : saved)
            close(s.backup);
          return linux_error(error);
        }
        saved.push_back({fd, backup, fcntl(fd, F_GETFD)});
      }
    // Replacing the writable host backing must preserve the ordinary open
    // description's cursor. Virtual proc reopens keep their independent cursor.
    for (const auto &s : saved)
      if (!FilePositions.contains(s.fd)) {
        const off_t position = lseek(s.fd, 0, SEEK_CUR);
        if (position < 0 || lseek(state->readonly, position, SEEK_SET) < 0) {
          int error = errno;
          for (const auto &old : saved)
            close(old.backup);
          return linux_error(error);
        }
        break;
      }
    for (auto &s : saved) {
      if (dup2(state->readonly, s.fd) < 0) {
        int error = errno;
        for (auto &old : saved) {
          dup2(old.backup, old.fd);
          fcntl(old.fd, F_SETFD, old.flags);
          close(old.backup);
        }
        return linux_error(error);
      }
      fcntl(s.fd, F_SETFD, s.flags);
    }
    for (auto &s : saved)
      close(s.backup);
  }
  // Shared across fork: every mutation takes the same object lock. Inherited
  // writable host descriptors cannot bypass these guest-kernel operations.
  state->seals.store(uint32_t(requested), std::memory_order_release);
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_set_aliases(const RootAliasMetadata *aliases,
                                                                                     uint64_t count) {
  if (count > 4 || (!aliases && count))
    return -22;
  std::lock_guard guard(Lock);
  RootAliases.clear();
  if (count)
    RootAliases.assign(aliases, aliases + count);
  if (CurrentTrace) {
    for (unsigned i = 0; i < count; ++i)
      CurrentTrace->aliases[i] = aliases[i];
    CurrentTrace->alias_count.store(unsigned(count), std::memory_order_release);
  }
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_alias_snapshot(void *opaque, size_t length) {
  struct Snapshot {
    uint32_t size, count;
    RootAliasMetadata rows[4];
  };
  if (!opaque || length != sizeof(Snapshot))
    return int32_t(0xc0000004);
  auto &out = *static_cast<Snapshot *>(opaque);
  if (out.size != sizeof(Snapshot))
    return int32_t(0xc0000004);
  std::lock_guard guard(Lock);
  if (RootAliases.size() > 4)
    return int32_t(0xc0000023);
  out.count = uint32_t(RootAliases.size());
  std::copy(RootAliases.begin(), RootAliases.end(), out.rows);
  return 0;
}
#include "fli_native_maps_view.h"
// XNU COW shadows reset vm_region's object offset. Retain the real PE source
// offset from the matching loaded image's unmodified section metadata.
static unsigned normalize_pe_source_offsets(std::vector<NativeMapsRow> &rows) {
  unsigned changed = 0;
  for (const auto &header : rows) {
    if (header.offset || header.end - header.start < 64 || header.permissions[0] != 'r' ||
        !fli_owned_host_path(header.name))
      continue;
    if (!header.name.ends_with(".dll") && !header.name.ends_with(".exe"))
      continue;
    uint16_t mz = 0;
    uint32_t at = 0, sig = 0;
    uint16_t sections = 0, optional = 0;
    if (!read_trace_metadata(header.start, mz) || mz != 0x5a4d || !read_trace_metadata(header.start + 60, at) ||
        at < 64 || at > 65536 || !read_trace_metadata(header.start + at, sig) || sig != 0x4550 ||
        !read_trace_metadata(header.start + at + 6, sections) || !sections || sections > 96 ||
        !read_trace_metadata(header.start + at + 20, optional) || optional < 64 || optional > 4096)
      continue;
    uint32_t image_size = 0, header_size = 0;
    if (!read_trace_metadata(header.start + at + 24 + 56, image_size) ||
        !read_trace_metadata(header.start + at + 24 + 60, header_size) || !image_size || header_size > image_size)
      continue;
    const uint64_t table = uint64_t(at) + 24 + optional;
    const size_t bytes = size_t(sections) * 40;
    std::vector<unsigned char> disk(bytes), live(bytes);
    int fd = open(header.name.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
      continue;
    struct stat st{};
    uint32_t disk_sig = 0;
    uint16_t disk_count = 0;
    bool matched = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && pread(fd, &disk_sig, 4, at) == 4 && disk_sig == sig &&
                   pread(fd, &disk_count, 2, at + 6) == 2 && disk_count == sections &&
                   pread(fd, disk.data(), bytes, table) == ssize_t(bytes);
    close(fd);
    mach_vm_size_t copied = 0;
    matched = matched &&
              mach_vm_read_overwrite(mach_task_self(), header.start + table, bytes,
                                     reinterpret_cast<mach_vm_address_t>(live.data()), &copied) == KERN_SUCCESS &&
              copied == bytes && disk == live;
    if (!matched)
      continue;
    for (auto &row : rows) {
      if (row.name != header.name || row.start < header.start || row.end - header.start > image_size)
        continue;
      const uint64_t begin = row.start - header.start, end = row.end - header.start;
      std::optional<uint64_t> source;
      if (end <= header_size)
        source = begin;
      else
        for (unsigned i = 0; i < sections; ++i) {
          uint32_t va = 0, size = 0, raw = 0;
          memcpy(&va, disk.data() + i * 40 + 12, 4);
          memcpy(&size, disk.data() + i * 40 + 16, 4);
          memcpy(&raw, disk.data() + i * 40 + 20, 4);
          if (begin >= va && end <= uint64_t(va) + size && uint64_t(raw) + end - va <= uint64_t(st.st_size)) {
            source = uint64_t(raw) + begin - va;
            break;
          }
        }
      if (source && row.offset != *source) {
        row.offset = *source;
        ++changed;
      }
    }
  }
  return changed;
}
// All callers hold the bridge lock. Root callbacks take it in the opposite
// direction, so never hold it while acquiring the Root memory-state lock.
static int32_t query_root_memory(uint64_t address, uint64_t *out) {
  using query = int32_t (*)(uint64_t, uint64_t *);
  const auto read = reinterpret_cast<query>(dlsym(RTLD_DEFAULT, "fli_root_guest_query_memory"));
  if (!read)
    return -38;
  struct UnlockForRoot {
    UnlockForRoot() { Lock.unlock(); }
    ~UnlockForRoot() { Lock.lock(); }
  } unlocked;
  return read(address, out);
}
static int64_t maps_snapshot(int pid = getpid(), bool wine_calls = true) {
  if (pid != getpid() && !accessible_process(pid))
    return -13;
  const char *directory = getenv("REGRESSION_LINUX_SYSCALL_TMPDIR");
  if (!directory)
    return -22;
  std::string path = std::string(directory) + "/linux-proc-maps-XXXXXX";
  int writable = mkstemp(path.data());
  if (writable < 0)
    return linux_error(errno);
  std::vector<NativeElfOrigin> origins;
  std::vector<NativeMapsRow> native_rows, canonical_rows;
  if (pid == getpid())
    for (const auto &region : ElfRegions)
      origins.push_back({region.start, region.end, region.offset, region.name});
  auto *trace = pid == getpid() ? CurrentTrace : TracedChildren.contains(pid) ? TracedChildren[pid] : nullptr;
  if (trace && trace->frontend_ready.load(std::memory_order_acquire) && (pid != getpid() || ElfRegions.empty()))
    for (unsigned i = 0; i < trace->elf_count.load() && i < 64; ++i) {
      const auto &region = trace->elf[i];
      origins.push_back({region.start, region.end, region.offset, region.name});
    }
  const unsigned alias_count = pid == getpid() ? unsigned(RootAliases.size())
                               : trace         ? trace->alias_count.load(std::memory_order_acquire)
                                               : 0;
  if (alias_count > 4) {
    unlink(path.c_str());
    close(writable);
    return -95;
  }
  std::vector<RootAliasMetadata> aliases;
  if (alias_count) {
    const auto *data = pid == getpid() ? RootAliases.data() : trace->aliases;
    aliases.assign(data, data + alias_count);
  }
  mach_vm_address_t address = 0;
  natural_t native_depth = 0;
  unsigned submaps = 0;
  unsigned regions = 0;
  for (; regions < 65536; ++regions) {
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info{};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    if (pid == getpid()) {
      vm_region_submap_info_data_64_t leaf{};
      count = VM_REGION_SUBMAP_INFO_COUNT_64;
      const auto status = mach_vm_region_recurse(mach_task_self(), &address, &size, &native_depth,
                                                 reinterpret_cast<vm_region_recurse_info_t>(&leaf), &count);
      if (status != KERN_SUCCESS)
        break;
      if (leaf.is_submap) {
        if (native_depth >= 32) {
          unlink(path.c_str());
          close(writable);
          return -95;
        }
        ++native_depth;
        ++submaps;
        continue;
      }
      info.protection = leaf.protection;
      info.max_protection = leaf.max_protection;
      info.offset = leaf.offset;
      info.shared =
          leaf.share_mode == SM_SHARED || leaf.share_mode == SM_TRUESHARED || leaf.share_mode == SM_SHARED_ALIASED;
    } else {
      struct proc_regioninfo region{};
      if (proc_pidinfo(pid, PROC_PIDREGIONINFO, address, &region, sizeof(region)) != sizeof(region)) {
        if (!regions) {
          int error = errno;
          unlink(path.c_str());
          close(writable);
          return linux_error(error ? error : EACCES);
        }
        break;
      }
      address = region.pri_address;
      size = region.pri_size;
      info.protection = region.pri_protection;
      info.offset = region.pri_offset;
      info.shared = region.pri_share_mode == SM_SHARED;
    }
    if (object != MACH_PORT_NULL)
      mach_port_deallocate(mach_task_self(), object);
    char filename[PROC_PIDPATHINFO_MAXSIZE]{};
    struct proc_regionwithpathinfo backing{};
    if (proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, address, &backing, sizeof(backing)) == sizeof(backing) &&
        backing.prp_prinfo.pri_address <= address &&
        address - backing.prp_prinfo.pri_address < backing.prp_prinfo.pri_size)
      snprintf(filename, sizeof(filename), "%s", backing.prp_vip.vip_path);
    // Wine maps PE images through temporary section files. Query the actual
    // section object's name rather than exposing the implementation temp name.
    if (wine_calls && pid == getpid() && (!*filename || strstr(filename, "/tmpmap-"))) {
      // Only initialized Wine callers may query the TEB. Before __wine_main,
      // Wine's pthread key is not initialized and can belong to another library.
      using teb_query = void *(*)();
      static const auto current = reinterpret_cast<teb_query>(wine_unix_symbol("NtCurrentTeb"));
      const bool wine_thread = current && current();
      static bool reported_missing_teb = false;
      if (!wine_thread && !reported_missing_teb) {
        reported_missing_teb = true;
        dprintf(2, "FLI_PROC_MAPS_NO_WINE_TEB pid=%d source=actual-Darwin-mapping\n", getpid());
      }
      using query = int32_t (*)(void *, const void *, uint32_t, void *, size_t, size_t *);
      auto call = wine_thread ? reinterpret_cast<query>(wine_unix_symbol("NtQueryVirtualMemory")) : nullptr;
      alignas(8) char storage[16384]{};
      struct memory_basic {
        uint64_t base, allocation;
        uint32_t allocation_protect, pad;
        uint64_t size;
        uint32_t state, protect, type, pad2;
      } basic{};
      if (call &&
          !call(reinterpret_cast<void *>(-1), reinterpret_cast<void *>(address), 0, &basic, sizeof(basic), nullptr) &&
          basic.state != 0x10000 && basic.base <= address && address - basic.base < basic.size &&
          (*filename || basic.type == 0x1000000) &&
          !call(reinterpret_cast<void *>(-1), reinterpret_cast<void *>(address), 2, storage, sizeof(storage),
                nullptr)) {
        struct unicode {
          uint16_t length, capacity;
          uint32_t pad;
          const char16_t *data;
        };
        auto &name = *reinterpret_cast<const unicode *>(storage);
        if (name.data && name.length <= 8192) {
          std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
          std::string path = converter.to_bytes(name.data, name.data + name.length / 2);
          std::replace(path.begin(), path.end(), '\\', '/');
          if (path.starts_with("/??/"))
            path = path.substr(4);
          if (path.starts_with("Z:/") || path.starts_with("z:/"))
            path = path.substr(2);
          else if ((path.starts_with("C:/") || path.starts_with("c:/")) && getenv("WINEPREFIX"))
            path = std::string(getenv("WINEPREFIX")) + "/drive_c" + path.substr(2);
          if (fli_owned_host_path(path)) {
            snprintf(filename, sizeof(filename), "%s", path.c_str());
            if (getenv("REGRESSION_DIAG_PROC_MAPS"))
              dprintf(2, "FLI_WINE_SECTION_NAME address=%llx path=%s\n", static_cast<unsigned long long>(address),
                      filename);
          }
        }
      }
    }
    struct stat st{};
    if (*filename)
      stat(filename, &st);
    std::string permissions;
    permissions += (info.protection & VM_PROT_READ) ? 'r' : '-';
    permissions += (info.protection & VM_PROT_WRITE) ? 'w' : '-';
    permissions += (info.protection & VM_PROT_EXECUTE) ? 'x' : '-';
    permissions += info.shared ? 's' : 'p';
    native_rows.push_back({address, address + size, info.offset, uint64_t(fli_guest_device_major(uint64_t(st.st_dev))),
                           uint64_t(fli_guest_device_minor(uint64_t(st.st_dev))), uint64_t(st.st_ino), permissions,
                           filename});
    if (!size || address + size < address)
      break;
    address += size;
  }
  if (wine_calls && fli_env_enabled("REGRESSION_DIAG_MAP_PROTECTIONS") && pid == getpid()) {
    using query = int32_t (*)(void *, const void *, uint32_t, void *, size_t, size_t *);
    auto basic = reinterpret_cast<query>(wine_unix_symbol("NtQueryVirtualMemory"));
    struct basic_info {
      uint64_t base, allocation;
      uint32_t allocation_protect, pad;
      uint64_t size;
      uint32_t state, protect, type, pad2;
    };
    static_assert(sizeof(basic_info) == 48);
    for (const auto &origin : origins) {
      mach_vm_address_t start = origin.start;
      mach_vm_size_t size = 0;
      natural_t depth = 0;
      vm_region_submap_info_data_64_t info{};
      kern_return_t status;
      do {
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        status = mach_vm_region_recurse(mach_task_self(), &start, &size, &depth,
                                        reinterpret_cast<vm_region_recurse_info_t>(&info), &count);
        if (status != KERN_SUCCESS || !info.is_submap)
          break;
        ++depth;
      } while (depth < 32);
      basic_info win{};
      int32_t win_status = basic ? basic(reinterpret_cast<void *>(-1), reinterpret_cast<void *>(origin.start), 0, &win,
                                         sizeof(win), nullptr)
                                 : int32_t(0xc00000bb);
      dprintf(2,
              "OWNED_ELF_MAP_LAYER address=%llx length=%llx mach_status=%d mach_start=%llx mach_size=%llx mach_prot=%x "
              "wine_status=%x wine_base=%llx wine_size=%llx wine_protect=%x wine_state=%x\n",
              (unsigned long long)origin.start, (unsigned long long)(origin.end - origin.start), status,
              (unsigned long long)start, (unsigned long long)size, info.protection, unsigned(win_status),
              (unsigned long long)win.base, (unsigned long long)win.size, win.protect, win.state);
    }
  }
  if (pid == getpid()) {
    const unsigned corrected = normalize_pe_source_offsets(native_rows);
    if (corrected)
      dprintf(2, "FLI_PE_SOURCE_OFFSETS corrected=%u source=matched-loaded-and-file-section-metadata\n", corrected);
  }
  if (!normalize_native_maps(native_rows, origins, canonical_rows)) {
    unlink(path.c_str());
    close(writable);
    return -11;
  }

  // Linux applications query guest mmap/mprotect permissions. The host stores
  // x86 bytes as data; its JIT write guards and W^X state are a separate layer.
  if (pid == getpid() && fli_env_enabled("REGRESSION_GUEST_MAP_PERMISSIONS")) {
    using query = int32_t (*)(uint64_t, uint64_t *);
    const auto read = query_root_memory;
    std::vector<NativeMapsRow> guest_rows;
    unsigned changed = 0;
    for (const auto &row : canonical_rows) {
      const bool elf = std::any_of(origins.begin(), origins.end(), [&](const auto &origin) {
        return origin.start <= row.start && row.end <= origin.end;
      });
      if (!read || !elf) {
        guest_rows.push_back(row);
        continue;
      }
      for (uint64_t address = row.start; address < row.end;) {
        const uint64_t end = std::min(row.end, (address & ~uint64_t(4095)) + 4096);
        auto part = row;
        part.start = address;
        part.end = end;
        part.offset += address - row.start;
        uint64_t memory[4]{};
        if (!read(address, memory) && memory[0] <= address && end <= memory[0] + memory[1] && memory[2] == memory[0]) {
          part.permissions[0] = (memory[3] & PROT_READ) ? 'r' : '-';
          part.permissions[1] = (memory[3] & PROT_WRITE) ? 'w' : '-';
          part.permissions[2] = (memory[3] & PROT_EXEC) ? 'x' : '-';
          if (part.permissions != row.permissions)
            ++changed;
        }
        if (!guest_rows.empty()) {
          auto &previous = guest_rows.back();
          if (previous.end == part.start && previous.permissions == part.permissions && previous.name == part.name &&
              previous.major == part.major && previous.minor == part.minor && previous.inode == part.inode &&
              previous.offset + previous.end - previous.start == part.offset) {
            previous.end = part.end;
            address = end;
            continue;
          }
        }
        guest_rows.push_back(std::move(part));
        address = end;
      }
    }
    canonical_rows = std::move(guest_rows);
    dprintf(
        2,
        "LAB_GUEST_MAP_PERMISSIONS pid=%d corrected-pages=%u native-regions-retained=1 source=tracked-mmap-mprotect\n",
        getpid(), changed);
  }
  if (!aliases.empty()) {
    std::vector<NativeMapsRow> logical_rows;
    if (!translate_native_alias_maps(canonical_rows, aliases, logical_rows)) {
      unlink(path.c_str());
      close(writable);
      return -11;
    }
    canonical_rows = std::move(logical_rows);
  }
  for (const auto &row : canonical_rows)
    dprintf(writable, "%llx-%llx %s %08llx %02llx:%02llx %llu %s\n", (unsigned long long)row.start,
            (unsigned long long)row.end, row.permissions.c_str(), (unsigned long long)row.offset,
            (unsigned long long)row.major, (unsigned long long)row.minor, (unsigned long long)row.inode,
            row.name.c_str());
  dprintf(2, "FLI_NATIVE_MAPS_NORMALIZED native=%zu origins=%zu rows=%zu native-backing-retained=1 aliases=%zu\n",
          native_rows.size(), origins.size(), canonical_rows.size(), aliases.size());
  if (pid == getpid()) {
    uint64_t readable = 0, largest = 0;
    for (const auto &row : native_rows)
      if (row.permissions[0] == 'r') {
        readable += row.end - row.start;
        largest = std::max(largest, row.end - row.start);
      }
    dprintf(2, "FLI_NATIVE_MAPS_LEAF pid=%d submaps=%u leaves=%zu readable-bytes=%llu largest-readable=%llu\n", pid,
            submaps, native_rows.size(), (unsigned long long)readable, (unsigned long long)largest);
  }
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  const int error = errno;
  // Diagnostic text metadata only, never guest module contents.
  if (const char *report = getenv("REGRESSION_DIAG_PROC_MAPS")) {
    int out = open(report, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (out >= 0) {
      char data[8192];
      ssize_t count;
      while ((count = read(fd, data, sizeof(data))) > 0)
        write(out, data, size_t(count));
      lseek(fd, 0, SEEK_SET);
      close(out);
    }
    dprintf(2, "FLI_GUEST_EXECUTABLE path=%s\n", guest_executable().c_str());
  }
  unlink(path.c_str());
  close(writable);
  if (fd < 0)
    return linux_error(error);
  Descriptors.insert(fd);
  ReadonlyDescriptors.insert(fd);
  dprintf(2, "FLI_LINUX_PROC_MAPS pid=%d regions=%u fd=%d source=actual-Darwin-mappings\n", pid, regions, fd);
  return fd;
}
static std::string guest_file(const std::string &original) {
  std::string path = original;
  std::replace(path.begin(), path.end(), '\\', '/');
  const std::string root = fli_host_path("VRCHAT_ROOTFS");
  const std::string game = fli_host_path("VRCHAT_GAME_DIR");
  if (path.starts_with(root + "/"))
    path.erase(0, root.size());
  if (path.empty() || path[0] != '/' || path.find("..") != std::string::npos)
    return {};
  char real[PATH_MAX];
  if (fli_shared_host_path(path))
    return fli_shared_host_object(path).value_or(std::string{});
  if (fli_shared_host_root().empty() && path.starts_with(game + "/") && realpath(path.c_str(), real))
    return real;
  if (!realpath((root + path).c_str(), real))
    return {};
  std::string result = real;
  return fli_guest_host_path_visible(result, root) ? result : std::string{};
}
static bool accessible_process(int pid) {
  struct proc_bsdinfo info{};
  return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == sizeof(info) && info.pbi_uid == geteuid();
}
static std::string other_process_executable(const std::string &path) {
  if (!path.starts_with("/proc/"))
    return {};
  char *end = nullptr;
  long pid = strtol(path.c_str() + 6, &end, 10);
  if (pid <= 0 || pid > INT32_MAX || !end || strcmp(end, "/exe") || !accessible_process(int(pid)))
    return {};
  if (TracedChildren.contains(int(pid)) && TracedChildren[int(pid)]->frontend_ready.load(std::memory_order_acquire))
    return TracedChildren[int(pid)]->guest_program;
  char native[PROC_PIDPATHINFO_MAXSIZE]{};
  return proc_pidpath(int(pid), native, sizeof(native)) > 0 ? std::string(native) : std::string{};
}
static int64_t status_snapshot(int pid) {
  if (pid <= 0)
    return -3;
  struct kinfo_proc info{};
  size_t length = sizeof(info);
  int query[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
  if (sysctl(query, 4, &info, &length, nullptr, 0))
    return linux_error(errno);
  if (length != sizeof(info) || info.kp_proc.p_pid != pid)
    return -3;
  struct proc_taskinfo task{};
  const bool have_task = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task, sizeof(task)) == sizeof(task);
  struct proc_bsdinfo bsd{};
  const bool have_bsd = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) == sizeof(bsd);
  // Public kinfo is available even when libproc denies broader cross-UID data.
  // Never turn unavailable task statistics into fabricated zero values.
  const int ppid = have_bsd ? int(bsd.pbi_ppid) : int(info.kp_eproc.e_ppid);
  const unsigned uid = have_bsd ? bsd.pbi_uid : info.kp_eproc.e_ucred.cr_uid;
  const unsigned ruid = have_bsd ? bsd.pbi_ruid : info.kp_eproc.e_pcred.p_ruid;
  const unsigned svuid = have_bsd ? bsd.pbi_svuid : info.kp_eproc.e_pcred.p_svuid;
  const unsigned gid = have_bsd ? bsd.pbi_gid : info.kp_eproc.e_ucred.cr_groups[0];
  const unsigned rgid = have_bsd ? bsd.pbi_rgid : info.kp_eproc.e_pcred.p_rgid;
  const unsigned svgid = have_bsd ? bsd.pbi_svgid : info.kp_eproc.e_pcred.p_svgid;
  const char *directory = getenv("REGRESSION_LINUX_SYSCALL_TMPDIR");
  if (!directory)
    return -22;
  std::string path = std::string(directory) + "/linux-proc-status-XXXXXX";
  int writable = mkstemp(path.data());
  if (writable < 0)
    return linux_error(errno);
  const int tracer = (info.kp_proc.p_flag & P_TRACED) ? ppid : 0;
  const char state = info.kp_proc.p_stat == SSTOP   ? 'T'
                     : info.kp_proc.p_stat == SZOMB ? 'Z'
                     : info.kp_proc.p_stat == SRUN  ? 'R'
                                                    : 'S';
  const char *description = state == 'T' ? "stopped" : state == 'Z' ? "zombie" : state == 'R' ? "running" : "sleeping";
  dprintf(writable, "Name:\t%s\nState:\t%c (%s)\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\nTracerPid:\t%d\n", info.kp_proc.p_comm,
          state, description, pid, pid, ppid, tracer);
  dprintf(writable, "Uid:\t%u\t%u\t%u\t%u\nGid:\t%u\t%u\t%u\t%u\n", ruid, uid, svuid, uid, rgid, gid, svgid, gid);
  if (have_task)
    dprintf(writable, "Threads:\t%d\nVmSize:\t%llu kB\nVmRSS:\t%llu kB\n", task.pti_threadnum,
            static_cast<unsigned long long>(task.pti_virtual_size / 1024),
            static_cast<unsigned long long>(task.pti_resident_size / 1024));
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  int error = errno;
  unlink(path.c_str());
  close(writable);
  if (fd < 0)
    return linux_error(error);
  Descriptors.insert(fd);
  ReadonlyDescriptors.insert(fd);
  dprintf(2,
          "FLI_LINUX_PROC_STATUS pid=%d tracer=%d source=actual-Darwin-process public-fallback=%d task-statistics=%d\n",
          pid, tracer, !have_bsd, have_task);
  return fd;
}
static int64_t comm_snapshot(int pid) {
  if (pid <= 0)
    return -3;
  char name[128]{};
  if (proc_name(pid, name, sizeof(name)) <= 0) {
    // Darwin exposes the public short name through KERN_PROC_PID even when
    // libproc restricts its broader BSD-info query to the process owner.
    struct kinfo_proc info{};
    size_t length = sizeof(info);
    int query[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    if (sysctl(query, 4, &info, &length, nullptr, 0))
      return linux_error(errno);
    if (length != sizeof(info) || info.kp_proc.p_pid != pid)
      return -3;
    snprintf(name, sizeof(name), "%s", info.kp_proc.p_comm);
  }
  const char *directory = getenv("REGRESSION_LINUX_SYSCALL_TMPDIR");
  if (!directory)
    return -22;
  std::string path = std::string(directory) + "/linux-proc-comm-XXXXXX";
  int writer = mkstemp(path.data());
  if (writer < 0)
    return linux_error(errno);
  dprintf(writer, "%.15s\n", name);
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  int error = errno;
  unlink(path.c_str());
  close(writer);
  if (fd < 0)
    return linux_error(error);
  Descriptors.insert(fd);
  ReadonlyDescriptors.insert(fd);
  dprintf(2, "FLI_LINUX_PROC_COMM pid=%d name=%.15s source=actual-Darwin-process\n", pid, name);
  return fd;
}
struct NativeProcDirectorySnapshot {
  std::string path;
  dev_t device;
  ino_t inode;
  std::vector<pid_t> pids;
};
static std::vector<NativeProcDirectorySnapshot> NativeProcDirectories;
static bool remove_proc_directory(const NativeProcDirectorySnapshot &snapshot) {
  for (pid_t pid : snapshot.pids)
    if (rmdir((snapshot.path + "/" + std::to_string(pid)).c_str()) && errno != ENOENT)
      return false;
  return rmdir(snapshot.path.c_str()) == 0 || errno == ENOENT;
}
static int64_t proc_directory_snapshot() {
  std::vector<pid_t> pids(2048);
  int count;
  for (;;) {
    count = proc_listallpids(pids.data(), int(pids.size() * sizeof(pid_t)));
    if (count <= 0)
      return linux_error(errno ? errno : EIO);
    if (size_t(count) < pids.size())
      break;
    if (pids.size() >= 65536)
      return -75;
    pids.resize(pids.size() * 2);
  }
  pids.resize(count);
  std::sort(pids.begin(), pids.end());
  pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
  pids.erase(std::remove_if(pids.begin(), pids.end(), [](pid_t pid) { return pid <= 0; }), pids.end());
  NativeProcDirectorySnapshot snapshot{};
  snapshot.pids = pids;
  snapshot.path =
      (std::string(fli_host_path("VRCHAT_ROOTFS")) + "/tmp/native-proc-") + std::to_string(getpid()) + "-XXXXXX";
  if (!mkdtemp(snapshot.path.data()))
    return linux_error(errno);
  for (pid_t pid : pids)
    if (mkdir((snapshot.path + "/" + std::to_string(pid)).c_str(), 0500)) {
      const int error = errno;
      remove_proc_directory(snapshot);
      return linux_error(error);
    }
  int fd = open(snapshot.path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  struct stat st{};
  if (fd < 0 || fstat(fd, &st)) {
    const int error = errno;
    if (fd >= 0)
      close(fd);
    remove_proc_directory(snapshot);
    return linux_error(error);
  }
  snapshot.device = st.st_dev;
  snapshot.inode = st.st_ino;
  NativeProcDirectories.push_back(std::move(snapshot));
  static const bool cleanup_registered = [] {
    atexit([] {
      for (const auto &entry : NativeProcDirectories)
        remove_proc_directory(entry);
    });
    return true;
  }();
  (void)cleanup_registered;
  dprintf(2, "FLI_NATIVE_PROC_DIRECTORY count=%zu own-pid-present=%d source=proc_listallpids\n", pids.size(),
          std::binary_search(pids.begin(), pids.end(), getpid()));
  return fd;
}
extern "C" __attribute__((visibility("default"))) void fli_linux_root_release_proc_snapshot(int closing_fd) {
  std::lock_guard guard(Lock);
  if (NativeProcDirectories.empty())
    return;
  struct stat closed{};
  if (fstat(closing_fd, &closed) || !S_ISDIR(closed.st_mode))
    return;
  auto entry = std::find_if(NativeProcDirectories.begin(), NativeProcDirectories.end(),
                            [&](const auto &s) { return s.device == closed.st_dev && s.inode == closed.st_ino; });
  if (entry == NativeProcDirectories.end())
    return;
  int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, nullptr, 0);
  if (bytes <= 0)
    return;
  std::vector<proc_fdinfo> fds(size_t(bytes) / sizeof(proc_fdinfo) + 64);
  bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds.data(), int(fds.size() * sizeof(proc_fdinfo)));
  if (bytes <= 0 || size_t(bytes) >= fds.size() * sizeof(proc_fdinfo))
    return;
  for (size_t i = 0; i < size_t(bytes) / sizeof(proc_fdinfo); ++i)
    if (fds[i].proc_fd != closing_fd) {
      struct stat other{};
      if (!fstat(fds[i].proc_fd, &other) && other.st_dev == entry->device && other.st_ino == entry->inode)
        return;
    }
  if (remove_proc_directory(*entry))
    NativeProcDirectories.erase(entry);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_root_open_proc(int pid, int kind) {
  std::lock_guard guard(Lock);
  if (kind == 3 && pid == getpid())
    refresh_trace_link_map();
  int64_t result = kind == 0                      ? comm_snapshot(pid)
                   : kind == 1                    ? cmdline_snapshot(pid)
                   : kind == 2                    ? status_snapshot(pid)
                   : kind == 3                    ? maps_snapshot(pid, false)
                   : kind == 4 && pid == getpid() ? proc_directory_snapshot()
                                                  : -95;
  if (result < 0)
    return int32_t(result);
  // Transfer this actual read-only snapshot to the ELF descriptor namespace.
  Descriptors.erase(int(result));
  ReadonlyDescriptors.erase(int(result));
  FilePositions.erase(int(result));
  return int32_t(result);
}
#include "fli_native_procargs_snapshot.h"
static int64_t cmdline_snapshot(int pid) {
  if (pid <= 0)
    return -3;
  int argmax = 0;
  size_t size = sizeof(argmax);
  int maxquery[] = {CTL_KERN, KERN_ARGMAX};
  if (sysctl(maxquery, 2, &argmax, &size, nullptr, 0) || argmax <= 0 || argmax > 4 * 1024 * 1024)
    return -95;
  std::vector<char> data(size_t(argmax), 0), arguments;
  size = data.size();
  int query[] = {CTL_KERN, KERN_PROCARGS2, pid};
  int argc = 0;
  if (sysctl(query, 3, data.data(), &size, nullptr, 0)) {
    const int original_error = errno;
    const char *snapshot = pid == 1 ? getenv("REGRESSION_NATIVE_PROC1_SNAPSHOT") : nullptr;
    if (!read_native_procargs_snapshot(snapshot, pid, arguments, argc))
      return linux_error(original_error);
    dprintf(2, "FLI_NATIVE_PROCARGS_SNAPSHOT pid=%d argc=%d current-boot=1 environment-excluded=1\n", pid, argc);
  } else {
    if (size < sizeof(argc))
      return -22;
    memcpy(&argc, data.data(), sizeof(argc));
    if (argc < 0 || argc > 65536)
      return -22;
    size_t start = sizeof(argc);
    while (start < size && data[start])
      ++start;
    while (start < size && !data[start])
      ++start;
    size_t end = start;
    int count = 0;
    while (end < size && count < argc) {
      while (end < size && data[end])
        ++end;
      if (end < size) {
        ++end;
        ++count;
      }
    }
    if (count != argc)
      return -22;
    arguments.assign(data.begin() + start, data.begin() + end);
  }
  const char *directory = getenv("REGRESSION_LINUX_SYSCALL_TMPDIR");
  if (!directory)
    return -22;
  std::string path = std::string(directory) + "/linux-proc-cmdline-XXXXXX";
  int writer = mkstemp(path.data());
  if (writer < 0)
    return linux_error(errno);
  if (write(writer, arguments.data(), arguments.size()) != ssize_t(arguments.size())) {
    int error = errno;
    unlink(path.c_str());
    close(writer);
    return linux_error(error);
  }
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  int error = errno;
  unlink(path.c_str());
  close(writer);
  if (fd < 0)
    return linux_error(error);
  Descriptors.insert(fd);
  ReadonlyDescriptors.insert(fd);
  dprintf(2, "FLI_LINUX_PROC_CMDLINE pid=%d argc=%d environment-excluded=1\n", pid, argc);
  return fd;
}
static int64_t readonly_text_snapshot(const std::string &label, const std::string &text, uint64_t flags) {
  if (flags & ~uint64_t(0x80000))
    return -95;
  const char *directory = getenv("REGRESSION_LINUX_SYSCALL_TMPDIR");
  if (!directory)
    return -22;
  std::string path = std::string(directory) + "/" + label + "-XXXXXX";
  int writer = mkstemp(path.data());
  if (writer < 0)
    return linux_error(errno);
  int error = fcntl(writer, F_SETFD, FD_CLOEXEC) < 0 ? errno : 0;
  size_t offset = 0;
  while (!error && offset < text.size()) {
    ssize_t count = write(writer, text.data() + offset, text.size() - offset);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0) {
      error = count < 0 ? errno : EIO;
      break;
    }
    offset += size_t(count);
  }
  if (!error && fchmod(writer, 0444))
    error = errno;
  int fd = error ? -1 : open(path.c_str(), O_RDONLY | ((flags & 0x80000) ? O_CLOEXEC : 0));
  if (fd < 0 && !error)
    error = errno;
  unlink(path.c_str());
  close(writer);
  if (error) {
    if (fd >= 0)
      close(fd);
    return linux_error(error);
  }
  Descriptors.insert(fd);
  ReadonlyDescriptors.insert(fd);
  return fd;
}
static std::string escape_mount_field(const char *value) {
  std::string result;
  for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value); *p; ++p) {
    if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\\') {
      char escaped[5];
      snprintf(escaped, sizeof(escaped), "\\%03o", unsigned(*p));
      result += escaped;
    } else
      result += char(*p);
  }
  return result;
}
static int64_t mounts_snapshot(uint64_t flags) {
  if (flags & ~uint64_t(0x80000))
    return -95;
  struct statfs *mounts = nullptr;
  errno = 0;
  const int count = getmntinfo_r_np(&mounts, MNT_NOWAIT);
  if (count <= 0) {
    int error = errno;
    free(mounts);
    return linux_error(error ? error : EIO);
  }
  std::string text;
  for (int i = 0; i < count; ++i) {
    const auto &mount = mounts[i];
    std::string options = (mount.f_flags & MNT_RDONLY) ? "ro" : "rw";
    if (mount.f_flags & MNT_NOSUID)
      options += ",nosuid";
    if (mount.f_flags & MNT_NODEV)
      options += ",nodev";
    if (mount.f_flags & MNT_NOEXEC)
      options += ",noexec";
    if (mount.f_flags & MNT_SYNCHRONOUS)
      options += ",sync";
    if (mount.f_flags & MNT_NOATIME)
      options += ",noatime";
    text += escape_mount_field(mount.f_mntfromname) + " " + escape_mount_field(mount.f_mntonname) + " ";
    text += escape_mount_field(mount.f_fstypename) + " " + options + " 0 0\n";
  }
  free(mounts);
  int64_t fd = readonly_text_snapshot("linux-proc-mounts", text, flags);
  if (fd >= 0)
    dprintf(2, "FLI_NATIVE_MOUNTS count=%d source=Darwin-getmntinfo_r_np\n", count);
  return fd;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_mounts_snapshot() {
  std::lock_guard guard(Lock);
  int64_t fd = mounts_snapshot(0x80000);
  if (fd >= 0) {
    Descriptors.erase(int(fd));
    ReadonlyDescriptors.erase(int(fd));
    FilePositions.erase(int(fd));
  }
  return int32_t(fd);
}
static int64_t pci_devices_snapshot(uint64_t flags) {
  std::string text;
  int status = darwin_pci_inventory(text);
  if (status)
    return status;
  int64_t fd = readonly_text_snapshot("linux-pci-devices", text, flags);
  if (fd >= 0)
    dprintf(2, "FLI_LINUX_PCI_INVENTORY rows=%zu source=actual-IOKit-devices\n",
            size_t(std::count(text.begin(), text.end(), '\n')));
  return fd;
}
static bool platform_identity_path(const std::string &path) {
  return path == "/sys/devices/virtual/dmi/id/product_name" || path == "/sys/devices/virtual/dmi/id/board_name";
}
static int64_t platform_identity_snapshot(const std::string &path, uint64_t flags) {
  std::string text;
  int status = darwin_platform_identity(path, text);
  if (status)
    return status;
  int64_t fd = readonly_text_snapshot("linux-platform-text", text, flags);
  if (fd >= 0)
    dprintf(2, "FLI_NATIVE_PLATFORM_TEXT path=%s source=IOPlatformExpert-existing-property\n", path.c_str());
  return fd;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_pci_devices_snapshot() {
  std::lock_guard guard(Lock);
  int64_t fd = pci_devices_snapshot(0x80000);
  if (fd >= 0) {
    Descriptors.erase(int(fd));
    ReadonlyDescriptors.erase(int(fd));
    FilePositions.erase(int(fd));
  }
  return int32_t(fd);
}
static int64_t write_linux_stat(const struct stat &host, uint64_t address) {
  struct linux_stat {
    uint64_t dev, ino, nlink;
    uint32_t mode, uid, gid, pad;
    uint64_t rdev;
    int64_t size, blksize, blocks, atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns, reserved[3];
  } value{};
  static_assert(sizeof(value) == 144);
  value.dev = host.st_dev;
  value.ino = host.st_ino;
  value.nlink = host.st_nlink;
  value.mode = host.st_mode;
  value.uid = host.st_uid;
  value.gid = host.st_gid;
  value.rdev = host.st_rdev;
  value.size = host.st_size;
  value.blksize = host.st_blksize;
  value.blocks = host.st_blocks;
  value.atime = host.st_atimespec.tv_sec;
  value.atime_ns = host.st_atimespec.tv_nsec;
  value.mtime = host.st_mtimespec.tv_sec;
  value.mtime_ns = host.st_mtimespec.tv_nsec;
  value.ctime = host.st_ctimespec.tv_sec;
  value.ctime_ns = host.st_ctimespec.tv_nsec;
  return mach_vm_write(mach_task_self(), address, reinterpret_cast<vm_offset_t>(&value), sizeof(value)) == KERN_SUCCESS
             ? 0
             : -14;
}
static int64_t stat_guest_path(int dirfd, const std::string &path, uint64_t buffer, uint64_t flags) {
  if (flags & ~uint64_t(0x1900))
    return -22; // NOFOLLOW, NO_AUTOMOUNT, EMPTY_PATH.
  struct stat host{};
  if (path.empty()) {
    if (!(flags & 0x1000))
      return -2;
    if (dirfd == -100) {
      if (stat(".", &host))
        return linux_error(errno);
    } else if (!Descriptors.contains(dirfd))
      return -9;
    else if (fstat(dirfd, &host))
      return linux_error(errno);
    return write_linux_stat(host, buffer);
  }
  int64_t snapshot = -2;
  const std::string self = "/proc/" + std::to_string(getpid());
  if (path == "/proc/self/maps" || path == self + "/maps")
    snapshot = maps_snapshot();
  else if (path == "/proc/self/status" || path == self + "/status")
    snapshot = status_snapshot(getpid());
  else if (path == "/proc/mounts" || path == "/proc/self/mounts")
    snapshot = mounts_snapshot(0x80000);
  else if (path == "/proc/bus/pci/devices")
    snapshot = pci_devices_snapshot(0x80000);
  else if (platform_identity_path(path))
    snapshot = platform_identity_snapshot(path, 0x80000);
  else if (path.starts_with("/proc/")) {
    char *end = nullptr;
    long pid = strtol(path.c_str() + 6, &end, 10);
    if (pid > 0 && pid <= INT32_MAX && end) {
      if (!strcmp(end, "/status"))
        snapshot = status_snapshot(int(pid));
      else if (!strcmp(end, "/maps"))
        snapshot = maps_snapshot(int(pid));
      else if (!strcmp(end, "/comm"))
        snapshot = comm_snapshot(int(pid));
      else if (!strcmp(end, "/cmdline"))
        snapshot = cmdline_snapshot(int(pid));
    }
  }
  if (snapshot >= 0) {
    const int fd = int(snapshot);
    int status = fstat(fd, &host), error = errno;
    close(fd);
    Descriptors.erase(fd);
    FilePositions.erase(fd);
    ReadonlyDescriptors.erase(fd);
    return status ? linux_error(error) : write_linux_stat(host, buffer);
  }
  if (platform_identity_path(path) || (path.starts_with("/proc/") && path != "/proc/self/exe" && path != self + "/exe"))
    return snapshot;
  std::string physical;
  if (path == "/proc/self/exe" || path == self + "/exe") {
    if (flags & 0x100)
      return -95; // Virtual symlink lstat is not implemented.
    physical = guest_executable();
    if (auto resolved = guest_file(physical); !resolved.empty())
      physical = std::move(resolved);
  } else if (path[0] == '/')
    physical = guest_file(path);
  else {
    if (path.find("..") != std::string::npos)
      return -13;
    if (dirfd != -100 && !Descriptors.contains(dirfd))
      return -9;
    int native_flags = (flags & 0x100) ? AT_SYMLINK_NOFOLLOW : 0;
    if (fstatat(dirfd == -100 ? AT_FDCWD : dirfd, path.c_str(), &host, native_flags))
      return linux_error(errno);
    return write_linux_stat(host, buffer);
  }
  if (physical.empty())
    return -2;
  if (flags & 0x100)
    return -95; // guest_file currently resolves symlinks.
  if (stat(physical.c_str(), &host))
    return linux_error(errno);
  return write_linux_stat(host, buffer);
}
// User-requested read-only diagnostic of the exact image supplied to the loader.
static void snapshot_loaded_elf(int fd, const char *path) {
  if (!path)
    path = getenv("REGRESSION_DIAG_LOADED_ELF");
  if (!path || !fli_path_within(path, fli_host_path("VRCHAT_STATE_DIR")))
    return;
  unsigned char header[20]{};
  struct stat info{};
  if (pread(fd, header, sizeof(header), 0) != sizeof(header) || memcmp(header, "\177ELF", 4) || header[4] != 2 ||
      header[5] != 1 || header[18] != 62 || header[19] || fstat(fd, &info) || info.st_size < 64 ||
      info.st_size > 64 * 1024 * 1024)
    return;
  int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (out < 0)
    return;
  char buffer[65536];
  off_t offset = 0;
  bool ok = true;
  while (offset < info.st_size) {
    ssize_t n = pread(fd, buffer, std::min<off_t>(sizeof(buffer), info.st_size - offset), offset);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      ok = false;
      break;
    }
    ssize_t used = 0;
    while (used < n) {
      ssize_t written = write(out, buffer + used, size_t(n - used));
      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0) {
        ok = false;
        break;
      }
      used += written;
    }
    if (!ok)
      break;
    offset += n;
  }
  if (close(out))
    ok = false;
  if (!ok)
    unlink(path);
  dprintf(2, "FLI_LOADED_ELF_SNAPSHOT complete=%d bytes=%lld source-offset-unchanged=1\n", ok, (long long)offset);
}
// Conservative code-address candidates only: no stack payload or strings.
// These are not unwind-verified frames and must not be reported as a call chain.
static void trace_syscall_code_stack(void *context, uint64_t number, uint64_t pc) {
  if (!fli_env_enabled("REGRESSION_DIAG_SYSCALL_CODE_STACK") || (number != 39 && number != 110 && number != 257))
    return;
  const uint64_t stack = word(context, 0x100); // Public ARM64 CONTEXT.Sp layout.
  unsigned candidates = 0;
  for (unsigned i = 0; i < 128 && candidates < 16; ++i) {
    uint64_t value = 0;
    if (stack > UINT64_MAX - i * 8 || !read_trace_metadata(stack + i * 8, value))
      break;
    if (!LinuxPages.contains(value & ~uint64_t(4095)))
      continue;
    dprintf(2, "FLI_SYSCALL_CODE_STACK number=%llu pc=%llx slot=%u candidate=%llx unwind-verified=0\n",
            (unsigned long long)number, (unsigned long long)pc, i, (unsigned long long)value);
    ++candidates;
  }
  dprintf(2, "FLI_SYSCALL_CODE_STACK_DONE number=%llu pc=%llx candidates=%u\n", (unsigned long long)number,
          (unsigned long long)pc, candidates);
}
static void trace_cpuid_boundary(uint64_t number, uint64_t pc) {
  if (!REGRESSION_FEX_CPUID_OBSERVATION_RVA || !fli_env_enabled("REGRESSION_DIAG_CPUID_BOUNDARY") ||
      (number != 319 && number != 39 && number != 110 && number != 257))
    return;
  const uint64_t base = current_wine_module("xtajit64.dll");
  uint64_t values[3]{};
  mach_vm_size_t bytes = 0;
  if (base &&
      mach_vm_read_overwrite(mach_task_self(), base + REGRESSION_FEX_CPUID_OBSERVATION_RVA, sizeof(values),
                             reinterpret_cast<mach_vm_address_t>(values), &bytes) == KERN_SUCCESS &&
      bytes == sizeof(values))
    dprintf(2, "FLI_CPUID_BOUNDARY number=%llu pc=%llx leaf1=%llu vendor=%llu compiled=%llu unchanged=1\n",
            (unsigned long long)number, (unsigned long long)pc, (unsigned long long)values[0],
            (unsigned long long)values[1], (unsigned long long)values[2]);
}
static void arm_managed_elf_branch_trace(int fd, uint64_t base, uint64_t length) {
  if (!REGRESSION_FEX_GUEST_BRANCH_RVA || !fli_env_enabled("REGRESSION_DIAG_MANAGED_ELF_TRACE") || !Memfds.contains(fd) ||
      !ReadonlyDescriptors.contains(fd))
    return;
  TraceELFHeader header{};
  struct stat file{};
  if (pread(fd, &header, sizeof(header), 0) != sizeof(header) || memcmp(header.ident, "\177ELF", 4) ||
      header.ident[4] != 2 || header.ident[5] != 1 || header.machine != 62 || header.type != 3 ||
      header.phsize != sizeof(TraceELFSegment) || !header.phnum || header.phnum > 64 || fstat(fd, &file) ||
      header.phoff > uint64_t(file.st_size) ||
      uint64_t(header.phnum) * header.phsize > uint64_t(file.st_size) - header.phoff)
    return;
  uint64_t begin = UINT64_MAX, end = 0;
  for (unsigned i = 0; i < header.phnum; ++i) {
    TraceELFSegment segment{};
    if (pread(fd, &segment, sizeof(segment), off_t(header.phoff + i * sizeof(segment))) != sizeof(segment))
      return;
    if (segment.type != 1 || !(segment.flags & 1) || !segment.memsz)
      continue;
    if (segment.vaddr > length || segment.memsz > length - segment.vaddr)
      return;
    begin = std::min(begin, segment.vaddr);
    end = std::max(end, segment.vaddr + segment.memsz);
  }
  if (begin >= end || base > UINT64_MAX - end)
    return;
  const uint64_t module = current_wine_module("xtajit64.dll");
  if (!module)
    return;
  uint64_t teb = 0;
  asm volatile("mov %0,x28" : "=r"(teb));
  const uint64_t values[4] = {base + begin, base + end, teb, 0};
  if (mach_vm_write(mach_task_self(), module + REGRESSION_FEX_GUEST_BRANCH_RVA, reinterpret_cast<vm_offset_t>(values),
                    sizeof(values)) == KERN_SUCCESS)
    dprintf(2, "FLI_MANAGED_ELF_BRANCH_TRACE begin=%llx end=%llx owner-teb=%llx metadata-only=1\n",
            (unsigned long long)values[0], (unsigned long long)values[1], (unsigned long long)teb);
}
static void trace_guest_branch_boundary(uint64_t number, uint64_t pc) {
  if (!REGRESSION_FEX_GUEST_BRANCH_RVA || !fli_env_enabled("REGRESSION_DIAG_MANAGED_ELF_TRACE") ||
      (number != 39 && number != 110 && number != 257))
    return;
  const auto module = current_wine_module("xtajit64.dll");
  uint64_t data[4]{};
  mach_vm_size_t bytes = 0;
  if (module &&
      mach_vm_read_overwrite(mach_task_self(), module + REGRESSION_FEX_GUEST_BRANCH_RVA, sizeof(data),
                             reinterpret_cast<mach_vm_address_t>(data), &bytes) == KERN_SUCCESS &&
      bytes == sizeof(data) && pc >= data[0] && pc < data[1])
    dprintf(2, "FLI_GUEST_BRANCH_BOUNDARY number=%llu pc=%llx entries=%llu\n", (unsigned long long)number,
            (unsigned long long)pc, (unsigned long long)data[3]);
}
static int64_t read_linux_directory(int fd, uint64_t address, uint64_t capacity) {
  if (!Descriptors.contains(fd))
    return -9;
  if (capacity < 24)
    return -22;
  auto stream = DirectoryStreams.find(fd);
  if (stream == DirectoryStreams.end()) {
    struct stat info{};
    if (fstat(fd, &info))
      return linux_error(errno);
    if (!S_ISDIR(info.st_mode))
      return -20;
    int copy = dup(fd);
    if (copy < 0)
      return linux_error(errno);
    fcntl(copy, F_SETFD, FD_CLOEXEC);
    DIR *directory = fdopendir(copy);
    if (!directory) {
      int error = errno;
      close(copy);
      return linux_error(error);
    }
    stream = DirectoryStreams.emplace(fd, directory).first;
  }
  DIR *directory = stream->second;
  const long initial = telldir(directory);
  std::vector<unsigned char> output(size_t(std::min<uint64_t>(capacity, 65536)), 0);
  size_t used = 0;
  while (used < output.size()) {
    const long position = telldir(directory);
    errno = 0;
    dirent *entry = readdir(directory);
    if (!entry) {
      if (errno && !used)
        return linux_error(errno);
      break;
    }
    if (!entry->d_ino)
      continue;
    const size_t length = (19 + entry->d_namlen + 1 + 7) & ~size_t(7);
    if (length > output.size() - used) {
      seekdir(directory, position);
      if (!used)
        return -22;
      break;
    }
    const uint64_t inode = entry->d_ino;
    const int64_t next = telldir(directory);
    const uint16_t record = uint16_t(length);
    memcpy(output.data() + used, &inode, 8);
    memcpy(output.data() + used + 8, &next, 8);
    memcpy(output.data() + used + 16, &record, 2);
    output[used + 18] = entry->d_type;
    memcpy(output.data() + used + 19, entry->d_name, entry->d_namlen);
    used += length;
  }
  if (used &&
      mach_vm_write(mach_task_self(), address, reinterpret_cast<vm_offset_t>(output.data()), used) != KERN_SUCCESS) {
    seekdir(directory, initial);
    return -14;
  }
  FilePositions[fd] = uint64_t(telldir(directory));
  dprintf(2, "FLI_LINUX_GETDENTS fd=%d bytes=%zu source=actual-Darwin-directory\n", fd, used);
  return int64_t(used);
}
static int64_t native_ptrace_request(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
  int64_t result = linux_error(ENOSYS);
  if (a == 0 && ForkChild) {
    int status = ptrace(PT_TRACE_ME, 0, nullptr, 0);
    result = status < 0 ? linux_error(errno) : status;
    if (!status && CurrentTrace)
      CurrentTrace->traced.store(true);
  } else if ((a == 1 || a == 2) && TracedChildren.contains(int(b))) {
    auto *trace = TracedChildren[int(b)];
    if (!trace->traced.load() || !trace->stopped)
      result = -3;
    else {
      mach_port_t task = MACH_PORT_NULL;
      kern_return_t status = task_for_pid(mach_task_self(), int(b), &task);
      if (status != KERN_SUCCESS) {
        dprintf(2, "FLI_PTRACE_TASK_ACCESS pid=%d status=%d\n", int(b), status);
        result = -1;
      } else {
        uint64_t value = 0;
        mach_vm_size_t copied = 0;
        status = mach_vm_read_overwrite(task, c, sizeof(value), reinterpret_cast<mach_vm_address_t>(&value), &copied);
        mach_port_deallocate(mach_task_self(), task);
        if (status != KERN_SUCCESS || copied != sizeof(value))
          result = -5;
        else {
          struct proc_regioninfo region{};
          if (proc_pidinfo(int(b), PROC_PIDREGIONINFO, c, &region, sizeof(region)) == sizeof(region) &&
              region.pri_address == c && region.pri_offset == 0) {
            char filename[PROC_PIDPATHINFO_MAXSIZE]{};
            proc_regionfilename(int(b), c, filename, sizeof(filename));
            const uint32_t magic = uint32_t(value);
            const char *format = magic == 0x464c457f ? "ELF" : magic == 0xfeedfacf ? "Mach-O-64" : "other";
            dprintf(2, "FLI_PTRACE_IMAGE_HEADER pid=%d format=%s image=%s\n", int(b), format, filename);
          }
          result =
              mach_vm_write(mach_task_self(), d, reinterpret_cast<vm_offset_t>(&value), sizeof(value)) == KERN_SUCCESS
                  ? 0
                  : -14;
        }
      }
    }
  } else if ((a == 4 || a == 5) && TracedChildren.contains(int(b))) {
    auto *trace = TracedChildren[int(b)];
    if (!trace->traced.load() || !trace->stopped)
      result = -3;
    else {
      mach_port_t task = MACH_PORT_NULL;
      kern_return_t status = task_for_pid(mach_task_self(), int(b), &task);
      if (status != KERN_SUCCESS)
        result = -1;
      else {
        const uint64_t host = getpagesize(), first = c & ~(host - 1),
                       last = (c + sizeof(uint64_t) + host - 1) & ~(host - 1);
        struct Saved {
          uint64_t address;
          vm_prot_t protection;
        };
        std::vector<Saved> saved;
        result = 0;
        for (uint64_t page = first; page < last; page += host) {
          mach_vm_address_t address = page;
          mach_vm_size_t size = 0;
          vm_region_basic_info_data_64_t info{};
          mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
          mach_port_t object = MACH_PORT_NULL;
          status = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO_64,
                                  reinterpret_cast<vm_region_info_t>(&info), &count, &object);
          if (object != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), object);
          if (status != KERN_SUCCESS || address > page) {
            result = -5;
            break;
          }
          status = mach_vm_protect(task, page, host, false,
                                   (info.protection | VM_PROT_READ | VM_PROT_WRITE) & ~VM_PROT_EXECUTE);
          if (status != KERN_SUCCESS) {
            result = -5;
            break;
          }
          saved.push_back({page, info.protection});
        }
        if (!result) {
          uint64_t value = d;
          status = mach_vm_write(task, c, reinterpret_cast<vm_offset_t>(&value), sizeof(value));
          if (status != KERN_SUCCESS)
            result = -5;
        }
        for (const auto &page : saved)
          if (mach_vm_protect(task, page.address, host, false, page.protection) != KERN_SUCCESS)
            result = -5;
        mach_port_deallocate(mach_task_self(), task);
        if (!result && trace->frontend_ready.load()) {
          trace->dirty_begin.store(std::min(trace->dirty_begin.load(), c));
          trace->dirty_end.store(std::max(trace->dirty_end.load(), c + 8));
        }
        dprintf(2, "FLI_PTRACE_WRITE pid=%d address=%llx size=8 result=%lld\n", int(b),
                static_cast<unsigned long long>(c), static_cast<long long>(result));
      }
    }
  } else if (a == 0x4200 && TracedChildren.contains(int(b))) {
    auto *trace = TracedChildren[int(b)];
    if (!trace->traced.load() || !trace->stopped)
      result = -3;
    else if (d & ~uint64_t(0x11))
      result = -95;
    else {
      // TRACESYSGOOD annotates genuine stops generated by this syscall
      // provider. TRACEEXEC reports the native execution replacement.
      trace->options.store(d);
      result = 0;
    }
  } else if (a == 0x4204 && TracedChildren.contains(int(b))) {
    auto *trace = TracedChildren[int(b)];
    struct iovec output{};
    mach_vm_size_t copied = 0;
    const void *data =
        c == 1 ? static_cast<const void *>(&trace->registers) : static_cast<const void *>(trace->floating);
    const size_t bytes = c == 1 ? sizeof(LinuxRegisters) : sizeof(trace->floating);
    if (!trace->traced.load() || !trace->stopped)
      result = -3;
    else if ((c != 1 && c != 2) || (c == 1 && !trace->registers_valid.load()) ||
             (c == 2 && !trace->floating_valid.load()))
      result = -95;
    else if (mach_vm_read_overwrite(mach_task_self(), d, sizeof(output), reinterpret_cast<mach_vm_address_t>(&output),
                                    &copied) != KERN_SUCCESS)
      result = -14;
    else {
      output.iov_len = std::min(output.iov_len, bytes);
      if (mach_vm_write(mach_task_self(), reinterpret_cast<uint64_t>(output.iov_base),
                        reinterpret_cast<vm_offset_t>(data), mach_msg_type_number_t(output.iov_len)) != KERN_SUCCESS)
        result = -14;
      else
        result =
            mach_vm_write(mach_task_self(), d, reinterpret_cast<vm_offset_t>(&output), sizeof(output)) == KERN_SUCCESS
                ? 0
                : -14;
    }
  } else if (a == 0x4205 && c == 2 && TracedChildren.contains(int(b))) {
    auto *trace = TracedChildren[int(b)];
    struct iovec input{};
    mach_vm_size_t copied = 0;
    alignas(16) unsigned char floating[512]{};
    if (!trace->traced.load() || !trace->stopped)
      result = -3;
    else if (!trace->root_trap_stop.load() || !trace->floating_valid.load())
      result = -95;
    else if (mach_vm_read_overwrite(mach_task_self(), d, sizeof(input), reinterpret_cast<mach_vm_address_t>(&input),
                                    &copied) != KERN_SUCCESS)
      result = -14;
    else if (input.iov_len != sizeof(floating))
      result = -95;
    else if (mach_vm_read_overwrite(mach_task_self(), reinterpret_cast<uint64_t>(input.iov_base), sizeof(floating),
                                    reinterpret_cast<mach_vm_address_t>(floating), &copied) != KERN_SUCCESS)
      result = -14;
    else if (*reinterpret_cast<uint32_t *>(floating + 24) & ~uint32_t(0xffc0))
      result = -5;
    // Public FEX CPUState does not maintain x87 FOP/FIP/FDP.
    else if (*reinterpret_cast<uint16_t *>(floating + 6) || *reinterpret_cast<uint64_t *>(floating + 8) ||
             *reinterpret_cast<uint64_t *>(floating + 16))
      result = -95;
    else {
      memcpy(trace->floating, floating, sizeof(floating));
      result = 0;
    }
  } else if (a == 0x4205 && TracedChildren.contains(int(b))) {
    auto *trace = TracedChildren[int(b)];
    struct iovec input{};
    mach_vm_size_t copied = 0;
    LinuxRegisters registers{};
    if (!trace->traced.load() || !trace->stopped)
      result = -3;
    else if (c != 1 || !trace->root_trap_stop.load() || !trace->registers_valid.load())
      result = -95;
    else if (mach_vm_read_overwrite(mach_task_self(), d, sizeof(input), reinterpret_cast<mach_vm_address_t>(&input),
                                    &copied) != KERN_SUCCESS)
      result = -14;
    else if (input.iov_len != sizeof(registers))
      result = -95;
    else if (mach_vm_read_overwrite(mach_task_self(), reinterpret_cast<uint64_t>(input.iov_base), sizeof(registers),
                                    reinterpret_cast<mach_vm_address_t>(&registers), &copied) != KERN_SUCCESS)
      result = -14;
    else if (registers.cs != 0x33 || registers.ss != 0x2b || registers.fs || registers.gs ||
             (registers.eflags & 0x3000))
      result = -5;
    else {
      trace->registers = registers;
      result = 0;
      dprintf(2, "FLI_ROOT_SET_REGISTERS pid=%d rip=%llx rsp=%llx arg0=%llx arg1=%llx\n", int(b),
              static_cast<unsigned long long>(registers.rip), static_cast<unsigned long long>(registers.rsp),
              static_cast<unsigned long long>(registers.rdi), static_cast<unsigned long long>(registers.rsi));
    }
  } else if (a == 0x4201 && TracedChildren.contains(int(b)) && TracedChildren[int(b)]->exec_completed.load()) {
    uint64_t tid = TracedChildren[int(b)]->exec_old_tid.load();
    result = mach_vm_write(mach_task_self(), d, reinterpret_cast<vm_offset_t>(&tid), sizeof(tid)) == KERN_SUCCESS
                 ? 0
                 : -14;
  } else if (a == 0x4202 && TracedChildren.contains(int(b))) {
    auto *trace = TracedChildren[int(b)];
    const uint32_t stop = trace->last_stop_status;
    if (!trace->stopped)
      result = -3;
    else if (trace->root_trap_stop.load()) {
      alignas(8) unsigned char info[128]{};
      int32_t signo = trace->root_signal.load(), code = trace->root_trap_code.load();
      memcpy(info, &signo, 4);
      memcpy(info + 8, &code, 4);
      const uint64_t address = trace->root_siginfo_address_valid.load(std::memory_order_acquire)
                                   ? trace->root_siginfo_address.load()
                                   : trace->registers.rip;
      memcpy(info + 16, &address, 8);
      result = mach_vm_write(mach_task_self(), d, reinterpret_cast<vm_offset_t>(info), sizeof(info)) == KERN_SUCCESS
                   ? 0
                   : -14;
    } else if (stop != 0x4057f && stop != 0x857f)
      result = -95;
    else {
      // Linux kernel ptrace_do_notify: actual stop kind, tracee PID and UID.
      alignas(8) unsigned char info[128]{};
      int32_t signo = 5, code = int32_t(stop >> 8), pid = int32_t(b);
      struct proc_bsdinfo process{};
      if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &process, sizeof(process)) != sizeof(process))
        result = -3;
      else {
        memcpy(info, &signo, 4);
        memcpy(info + 8, &code, 4);
        memcpy(info + 16, &pid, 4);
        memcpy(info + 20, &process.pbi_ruid, 4);
        result = mach_vm_write(mach_task_self(), d, reinterpret_cast<vm_offset_t>(info), sizeof(info)) == KERN_SUCCESS
                     ? 0
                     : -14;
      }
    }
  } else if (a == 17 && TracedChildren.contains(int(b))) {
    int signal = host_signal(unsigned(d));
    if (d && !signal)
      result = -95;
    else
      result = detach_guest_child(int(b), TracedChildren[int(b)], signal);
  } else if ((a == 7 || a == 24) && TracedChildren.contains(int(b))) {
    int signal = host_signal(unsigned(d));
    if ((d && !signal) || (a == 24 && TracedChildren[int(b)]->exec_completed.load()))
      result = -95;
    else {
      auto *trace = TracedChildren[int(b)];
      trace->syscalls.store(a == 24);
      result = continue_guest_child(int(b), trace, signal);
    }
  } else
    result = -95;
  return result;
}

static int32_t dispatch(void *context) {
  const char *enabled = getenv("REGRESSION_LINUX_SYSCALL_BRIDGE");
  if (!context || !enabled || strcmp(enabled, "1"))
    return 0;
  std::unique_lock guard(Lock);
  import_memfds();
  const uint64_t number = word(context, 0x48), pc = word(context, 0x108);
  const uint64_t page = pc & ~uint64_t(0xfff);
  const uint64_t a = word(context, 0xd8), b = word(context, 0xd0);
  const uint64_t c = word(context, 0x10), d = word(context, 0x28);
  const bool unmap_owned = number == 11 && owned_mapping(a, b);
  std::unique_lock<std::mutex> memory_change(MemoryMutationLock, std::defer_lock);
  int64_t result = -38;
  if (number != 319 && !LinuxPages.contains(page)) {
    static thread_local unsigned boundary_count;
    if (ThreadLinuxFS && fli_env_enabled("REGRESSION_DIAG_SYSCALL_BOUNDARY") && boundary_count++ < 64)
      dprintf(2, "FLI_WINDOWS_SYSCALL_BOUNDARY number=%llu pc=%llx pid=%d linux-fs-active=1\n",
              (unsigned long long)number, (unsigned long long)pc, getpid());
    return 0;
  }
  // Bootstrap before any memory call. The first anonymous Linux gate call
  // installs this adapter; subsequent PE calls enter it before Unix dispatch.
  const uint64_t wine = current_wine_ntdll(), provider = current_wine_module("xtajit64.dll");
  const bool was_ready =
      wine && provider &&
      *reinterpret_cast<uint64_t *>(wine + VRCHAT_WINE_UNIX_DISPATCH_RVA) == provider + VRCHAT_FEX_MEMORY_DISPATCH_RVA;
  if (!install_memory_dispatch() || (!was_ready && (number == 9 || number == 10 || number == 11))) {
    word(context, 0x48) = uint64_t(-38);
    return 1;
  }
  if (number == 9 || number == 10 || number == 11 || number == 56 || number == 57 || number == 58) {
    guard.unlock();
    memory_change.lock();
    guard.lock();
  }
  trace_guest_branch_boundary(number, pc);
  trace_cpuid_boundary(number, pc);
  trace_syscall_code_stack(context, number, pc);
  if (CurrentTrace && CurrentTrace->traced.load())
    capture_registers(context, number);
  const bool trace_entry = stop_for_syscall(context, number, true);
  // A Linux-only service outside this pinned Wine's Windows service table
  // opts an anonymous Unix trampoline page into Linux register/error semantics.
  // The mode is restricted to this research runtime, never a default Wine path.
  if (number == 319) {
    if (!LinuxPages.contains(page) && !anonymous_code(pc))
      return 0;
    if (!LinuxFSExplicit && !AdoptedThread.tcb && ensure_glibc())
      ThreadLinuxFS = GlibcFSBase;
    std::string name;
    LinuxPages.insert(page);
    if (GlibcStarted && !LinuxFSExplicit && !AdoptedThread.tcb && !LinuxTLSAttachPending &&
        fli_env_enabled("REGRESSION_LAZY_LINUX_TLS")) {
      LinuxTLSAttachPending = true;
      dprintf(2, "FLI_LINUX_THREAD_ATTACH_REQUEST pc=%llx\n", (unsigned long long)pc);
      return 2; // Resume through Wine's user-stack TLS initializer, then retry this syscall.
    }
    if (!read_name(a, name))
      result = -14;
    else if (b & ~uint64_t(3))
      result = -95;
    else {
      const char *directory = getenv("REGRESSION_LINUX_SYSCALL_TMPDIR");
      if (!directory || directory[0] != '/')
        result = -22;
      else {
        std::string path = std::string(directory) + "/linux-memfd-XXXXXX";
        int fd = mkstemp(path.data());
        if (fd < 0)
          result = linux_error(errno);
        else {
          int readonly = open(path.c_str(), O_RDONLY | O_CLOEXEC), error = readonly < 0 ? errno : 0;
          if (unlink(path.c_str()) && !error)
            error = errno;
          void *shared =
              error ? MAP_FAILED : mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
          if (shared == MAP_FAILED) {
            if (!error)
              error = errno;
            if (readonly >= 0)
              close(readonly);
            close(fd);
            result = linux_error(error);
          } else {
            auto *state = new (shared) MemfdState;
            state->readonly = readonly;
            state->seals.store((b & 2) ? 0 : 1);
            if (b & 1)
              fcntl(fd, F_SETFD, FD_CLOEXEC);
            Memfds[fd] = state;
            Descriptors.insert(fd);
            result = fd;
          }
        }
      }
    }
  } else if (number == 0xf102 && fli_env_enabled("REGRESSION_DIAG_GLIBC_EXPORTS"))
    result = static_cast<int64_t>(GlibcBase + 0x6e800); // Pinned public GLIBC dlopen symbol.
  else if (number == 0xf105 && fli_env_enabled("REGRESSION_DIAG_HOST_GUARD")) {
    const uint64_t host = getpagesize(), begin = a & ~(host - 1), end = (a + b + host - 1) & ~(host - 1);
    result = owned_mapping(a, b) ? wine_protect(reinterpret_cast<void *>(begin), end - begin, 0x20) : -22;
    mach_vm_address_t base = a;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info{};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    if (mach_vm_region(mach_task_self(), &base, &size, VM_REGION_BASIC_INFO_64,
                       reinterpret_cast<vm_region_info_t>(&info), &count, &object) == KERN_SUCCESS)
      dprintf(2, "FLI_DIAG_GUARD address=%llx host-prot=%x base=%llx size=%llx\n", static_cast<unsigned long long>(a),
              info.protection, static_cast<unsigned long long>(base), static_cast<unsigned long long>(size));
    if (object != MACH_PORT_NULL)
      mach_port_deallocate(mach_task_self(), object);
  } else if (number == 0xf107 && fli_env_enabled("REGRESSION_DIAG_WINE_ENTRY")) {
    void *Module = dlopen(carrier_path(), RTLD_NOW | RTLD_GLOBAL);
    using Check = int32_t (*)(uint64_t *);
    auto Function = Module ? reinterpret_cast<Check>(dlsym(Module, "fli_check_wine_elf_entry")) : nullptr;
    uint64_t value = 0;
    int32_t status = Function ? Function(&value) : -1;
    result = status ? -5 : int64_t(value);
  } else if (number == 12) {
    using service = int32_t (*)(uint64_t, uint64_t *);
    const auto owner = reinterpret_cast<service>(dlsym(RTLD_DEFAULT, "fli_root_program_break"));
    uint64_t actual = 0;
    const int32_t status = owner ? owner(a, &actual) : -38;
    result = status ? status : int64_t(actual);
  } else if (number == 9 || number == 11) {
    using service = int32_t (*)(uint64_t, const uint64_t *, uint64_t *);
    const auto owner = reinterpret_cast<service>(dlsym(RTLD_DEFAULT, "fli_root_memory_operation"));
    const uint64_t args[6] = {a, b, c, d, word(context, 0x18), word(context, 0x20)};
    uint64_t actual = uint64_t(-38);
    int32_t status = -38;
    if (number == 9 && !(d & 0x20) && !Descriptors.contains(int(args[4])))
      result = -9;
    else {
      guard.unlock();
      if (owner)
        status = owner(number, args, &actual);
      guard.lock();
      result = status ? status : int64_t(actual);
      if (result >= 0) {
        const uint64_t begin = number == 9 ? actual : a, length = (b + 4095) & ~uint64_t(4095),
                       prot = number == 9 ? c : 0;
        for (uint64_t page = begin; page < begin + length; page += 4096) {
          NativeExecutionPages.erase(page);
          if (prot & 4)
            LinuxPages.insert(page);
          else
            LinuxPages.erase(page);
        }
        notify_execution(begin, length, prot);
      }
    }
  } else if (number == 10)
    result = protect_pages(a, b, uint32_t(c));
  else if (number == 79) {
    if (!b)
      result = -22;
    else {
      std::string path;
      const int error = fli_current_directory(fli_host_path("VRCHAT_ROOTFS"), path);
      if (error)
        result = linux_error(error);
      else if (b < path.size() + 1)
        result = -34;
      else
        result = mach_vm_write(mach_task_self(), a, reinterpret_cast<vm_offset_t>(path.c_str()), path.size() + 1) ==
                         KERN_SUCCESS
                     ? int64_t(path.size() + 1)
                     : -14;
    }
  } else if (number == 39)
    result = getpid();
  else if (number == 59) {
    std::string executable;
    if (!read_name(a, executable, 4096))
      result = -14;
    else {
      dprintf(2, "FLI_LINUX_EXEC_REQUEST path=%s\n", executable.c_str());
      for (unsigned i = 0; i < 64; ++i) {
        uint64_t pointer = 0;
        mach_vm_size_t copied = 0;
        if (mach_vm_read_overwrite(mach_task_self(), b + i * 8, 8, reinterpret_cast<mach_vm_address_t>(&pointer),
                                   &copied) != KERN_SUCCESS ||
            !pointer)
          break;
        std::string value;
        if (!read_name(pointer, value, 8192))
          break;
        bool path = fli_owned_host_path(value) || value.starts_with("/proc/self/fd/") || value == "VRChat.exe";
        dprintf(2, "FLI_LINUX_EXEC_ARG index=%u length=%zu%s%s\n", i, value.size(), path ? " path=" : "",
                path ? value.c_str() : "");
        if (value.starts_with("/proc/self/fd/")) {
          int fd = atoi(value.c_str() + 14);
          unsigned char magic[4]{};
          if (Descriptors.contains(fd) && pread(fd, magic, sizeof(magic), 0) == 4)
            dprintf(2, "FLI_LINUX_EXEC_FD fd=%d format=%s\n", fd,
                    !memcmp(magic, "\177ELF", 4)         ? "ELF"
                    : magic[0] == 'M' && magic[1] == 'Z' ? "PE"
                                                         : "other");
        }
      }
      for (unsigned i = 0; i < 128; ++i) {
        uint64_t pointer = 0;
        mach_vm_size_t copied = 0;
        if (mach_vm_read_overwrite(mach_task_self(), c + i * 8, 8, reinterpret_cast<mach_vm_address_t>(&pointer),
                                   &copied) != KERN_SUCCESS ||
            !pointer)
          break;
        std::string value;
        if (!read_name(pointer, value, 8192))
          break;
        const auto equal = value.find('=');
        if (equal != std::string::npos)
          dprintf(2, "FLI_LINUX_EXEC_ENV_KEY %.*s\n", int(equal), value.c_str());
      }
      result = exec_native_wine(executable, b, c);
    }
  } else if (number == 14) {
    uint64_t mask = 0, previous = 0;
    bool writable = true;
    if (c) {
      mach_vm_address_t base = c;
      mach_vm_size_t span = 0;
      vm_region_basic_info_data_64_t info{};
      mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
      mach_port_t object = 0;
      writable = c <= UINT64_MAX - 8 &&
                 mach_vm_region(mach_task_self(), &base, &span, VM_REGION_BASIC_INFO_64,
                                reinterpret_cast<vm_region_info_t>(&info), &count, &object) == KERN_SUCCESS &&
                 base <= c && c - base <= span && span - (c - base) >= 8 && (info.protection & VM_PROT_WRITE);
      if (object)
        mach_port_deallocate(mach_task_self(), object);
    }
    if (d != 8 || (b && a > 2))
      result = -22;
    else if ((b && !read_trace_metadata(b, mask)) || !writable)
      result = -14;
    else {
      using service = int32_t (*)(uint64_t, uint32_t, uint64_t, uint64_t *);
      auto owner = reinterpret_cast<service>(dlsym(RTLD_DEFAULT, "fli_root_signal_mask"));
      guard.unlock();
      result = owner ? owner(a, b != 0, mask, &previous) : -38;
      guard.lock();
      if (!result && c &&
          mach_vm_write(mach_task_self(), c, reinterpret_cast<vm_offset_t>(&previous), 8) != KERN_SUCCESS)
        result = -14;
    }
  } else if (number == 56 && a == 0x3d0f00) {
    FliLinuxThreadState state{};
    state.size = sizeof(state);
    state.version = 1;
    LinuxRegisters registers{};
    if (!read_linux_context(context, number, registers, state.floating, state.ymm, &state.has_ymm))
      result = -22;
    else {
      memcpy(state.regs, &registers, sizeof(registers));
      // SYSCALL stores the complete architectural flags in R11, including
      // PF/AF bits that the ARM64EC exception-context format cannot carry.
      state.regs[18] = registers.r11;
      const uint64_t args[6] = {a, b, c, d, word(context, 0x18), word(context, 0x20)};
      memcpy(state.args, args, sizeof(args));
      using service = int32_t (*)(const FliLinuxThreadState *, uint64_t *);
      auto owner = reinterpret_cast<service>(dlsym(RTLD_DEFAULT, "fli_root_clone_thread"));
      uint64_t actual = uint64_t(-38);
      guard.unlock();
      const int32_t status = owner ? owner(&state, &actual) : -38;
      guard.lock();
      result = status ? status : int64_t(actual);
    }
  } else if (number == 56 && fli_env_enabled("REGRESSION_LINUX_FORK")) {
    // Linux fork(), not CLONE_VM or a pthread. Preserve genuine process
    // separation; other clone flag combinations remain unsupported.
    if (a != 0x1200011 || b || c || word(context, 0x18))
      result = -95;
    else {
      const char *directory = getenv("REGRESSION_LINUX_SYSCALL_TMPDIR");
      std::string path = std::string(directory ? directory : fli_host_path("VRCHAT_STATE_DIR")) + "/linux-trace-XXXXXX";
      int relay = mkstemp(path.data());
      if (relay < 0) {
        word(context, 0x48) = uint64_t(linux_error(errno));
        return 1;
      }
      if (unlink(path.c_str()) || ftruncate(relay, off_t(trace_bytes()))) {
        int error = errno;
        close(relay);
        word(context, 0x48) = uint64_t(linux_error(error));
        return 1;
      }
      void *shared = mmap(nullptr, trace_bytes(), PROT_READ | PROT_WRITE, MAP_SHARED, relay, 0);
      if (shared == MAP_FAILED) {
        word(context, 0x48) = uint64_t(linux_error(errno));
        return 1;
      }
      auto *trace = new (shared) TraceState;
      trace->relay_fd = relay;
      stack_t inherited_signal_stack{};
      if (sigaltstack(nullptr, &inherited_signal_stack)) {
        word(context, 0x48) = uint64_t(linux_error(errno));
        return 1;
      }
      pid_t child = fork();
      result = child < 0 ? linux_error(errno) : child;
      if (child == 0) {
        // Darwin disables the alternate signal stack after fork. The Linux
        // child inherits the caller's stack; Wine/FEX fault delivery needs it.
        if (!(inherited_signal_stack.ss_flags & SS_DISABLE)) {
          inherited_signal_stack.ss_flags = 0;
          if (sigaltstack(&inherited_signal_stack, nullptr))
            _exit(127);
        }
        ForkChild = true;
        ChildProcesses.clear();
        TracedChildren.clear();
        CurrentTrace = trace;
        install_child_bus_observer();
        const uint32_t tid = uint32_t(getpid());
        ChildClearTID = d;
        if (d && mach_vm_write(mach_task_self(), d, reinterpret_cast<vm_offset_t>(&tid), sizeof(tid)) != KERN_SUCCESS)
          _exit(127);
      } else if (child > 0) {
        ChildProcesses.insert(child);
        TracedChildren[child] = trace;
      } else {
        munmap(shared, trace_bytes());
        close(relay);
      }
      dprintf(2, "FLI_LINUX_FORK pid=%d child=%d source=Darwin-fork\n", getpid(), child);
    }
  } else if ((number == 60 || number == 231) && fli_env_enabled("REGRESSION_LINUX_FORK")) {
    if (ChildClearTID) {
      uint32_t zero = 0;
      if (mach_vm_write(mach_task_self(), ChildClearTID, reinterpret_cast<vm_offset_t>(&zero), sizeof(zero)) ==
          KERN_SUCCESS)
        fli_shared_futex(reinterpret_cast<void *>(ChildClearTID), 1, 1, nullptr, UINT32_MAX);
    }
    // There is one Linux execution thread in this fork-only experiment.
    _exit(int(a));
  } else if (number == 61 && fli_env_enabled("REGRESSION_LINUX_FORK")) {
    if (c & ~uint64_t(3) || d)
      result = -95;
    else {
      int status = 0;
      pid_t child = wait_guest_child(int(a), &status, int(c));
      if (child > 0)
        dprintf(2, "FLI_LINUX_WAIT observer=%d child=%d native-status=%x options=%llx\n", getpid(), child, status,
                static_cast<unsigned long long>(c));
      if (child > 0 && TracedChildren.contains(child) && TracedChildren[child]->alignments.load())
        dprintf(2, "FLI_CHILD_ALIGNMENT pid=%d handled=%llu esr=%x\n", child,
                static_cast<unsigned long long>(TracedChildren[child]->alignments.load()),
                TracedChildren[child]->fault_esr.load());
      if (child > 0 && TracedChildren.contains(child) && TracedChildren[child]->code_writes.load())
        dprintf(2, "FLI_CHILD_CODE_WRITE pid=%d handled=%llu\n", child,
                static_cast<unsigned long long>(TracedChildren[child]->code_writes.load()));
      if (child > 0 && WIFSTOPPED(status) && (WSTOPSIG(status) == SIGBUS || WSTOPSIG(status) == SIGSEGV)) {
        mach_port_t task = MACH_PORT_NULL;
        kern_return_t kr = task_for_pid(mach_task_self(), child, &task);
        dprintf(2, "FLI_CHILD_EXCEPTION_TASK pid=%d status=%d\n", child, kr);
        if (kr == KERN_SUCCESS) {
          thread_act_array_t threads = nullptr;
          mach_msg_type_number_t count = 0;
          if (task_threads(task, &threads, &count) == KERN_SUCCESS) {
            for (unsigned i = 0; i < count; ++i) {
              arm_exception_state64_t exception{};
              arm_thread_state64_t registers{};
              mach_msg_type_number_t en = ARM_EXCEPTION_STATE64_COUNT, rn = ARM_THREAD_STATE64_COUNT;
              auto er = thread_get_state(threads[i], ARM_EXCEPTION_STATE64,
                                         reinterpret_cast<thread_state_t>(&exception), &en);
              auto rr =
                  thread_get_state(threads[i], ARM_THREAD_STATE64, reinterpret_cast<thread_state_t>(&registers), &rn);
              dprintf(2, "FLI_CHILD_EXCEPTION thread=%u es=%d rs=%d esr=%x far=%llx pc=%llx frame=%llx\n", i, er, rr,
                      exception.__esr, static_cast<unsigned long long>(exception.__far),
                      static_cast<unsigned long long>(arm_thread_state64_get_pc(registers)),
                      static_cast<unsigned long long>(registers.__x[24]));
              mach_port_deallocate(mach_task_self(), threads[i]);
            }
            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(threads), count * sizeof(thread_t));
          }
          mach_port_deallocate(mach_task_self(), task);
        }
      }
      result = child < 0 ? linux_error(errno) : child;
      if (child > 0 && WIFSTOPPED(status)) {
        int guest = 0;
        for (unsigned i = 1; i < 32; ++i)
          if (host_signal(i) == WSTOPSIG(status)) {
            guest = int(i);
            break;
          }
        auto found = TracedChildren.find(child);
        if (found != TracedChildren.end()) {
          found->second->stopped = true;
          if (guest == 5 && found->second->syscall_stop.load() && (found->second->options.load() & 1))
            guest |= 0x80;
        }
        if (guest)
          status = (status & 0xffff0000) | (guest << 8) | 0x7f;
        if (found != TracedChildren.end())
          found->second->last_stop_status = uint32_t(status);
      }
      if (child > 0 && fli_env_enabled("REGRESSION_FLI_TRACE_WAIT_RESULTS")) {
        dprintf(2,
                "FLI_WAIT_OUTCOME child=%d result=%lld status=%x exited=%d exit=%d signaled=%d signal=%d stopped=%d\n",
                child, (long long)result, status, WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0, WIFSTOPPED(status));
        const uint64_t ntdll = current_wine_ntdll();
        if (ntdll) {
          using convert = void (*)(void *, const void *);
          alignas(16) unsigned char x64[0x4d0]{};
          reinterpret_cast<convert>(ntdll + REGRESSION_WINE_CONTEXT_RVA)(x64, context);
          const uint64_t stack = word(x64, 0x98);
          dprintf(2, "FLI_WAIT_CALL pc=%llx stack=%llx\n", (unsigned long long)word(x64, 0xf8),
                  (unsigned long long)stack);
          for (unsigned slot = 0; slot < 24; ++slot) {
            uint64_t candidate = 0;
            if (!read_trace_metadata(stack + slot * 8, candidate))
              break;
            uint64_t region[4]{};
            const bool executable = !query_root_memory(candidate, region) && (region[3] & 4);
            if (executable)
              dprintf(2, "FLI_WAIT_STACK_CODE_CANDIDATE slot=%u pc=%llx\n", slot, (unsigned long long)candidate);
          }
        }
      }
      if (child > 0 && b &&
          mach_vm_write(mach_task_self(), b, reinterpret_cast<vm_offset_t>(&status), sizeof(status)) != KERN_SUCCESS)
        result = -14;
    }
  } else if (number == 101 && fli_env_enabled("REGRESSION_LINUX_FORK")) {
    result = native_ptrace_request(a, b, c, d);
  } else if (number == 62 && fli_env_enabled("REGRESSION_LINUX_FORK")) {
    const int pid = int(a), signal = host_signal(unsigned(b));
    if (pid != getpid() && !ChildProcesses.contains(pid))
      result = -13;
    else if (b && !signal)
      result = -95;
    else {
      // Darwin keeps a traced child in its debugger stop after kill(). Linux
      // SIGKILL must also release that stop so waitpid can reap the real child.
      int status = signal == SIGKILL && TracedChildren.contains(pid) && TracedChildren[pid]->stopped
                       ? ptrace(PT_KILL, pid, reinterpret_cast<caddr_t>(1), 0)
                       : kill(pid, signal);
      result = status < 0 ? linux_error(errno) : status;
    }
  } else if (number == 110)
    result = getppid();
  else if (number == 201) {
    int64_t now = int64_t(time(nullptr));
    result = now;
    if (a && mach_vm_write(mach_task_self(), a, reinterpret_cast<vm_offset_t>(&now), sizeof(now)) != KERN_SUCCESS)
      result = -14;
  } else if (number == 35 || number == 230) {
    const bool relative = number == 35;
    const int32_t clock = relative ? 1 : int32_t(a);
    const uint64_t flags = relative ? 0 : b, input = relative ? a : c, output = relative ? b : d;
    FliSleepTime request{}, remaining{};
    mach_vm_size_t copied = 0;
    if (mach_vm_read_overwrite(mach_task_self(), input, sizeof(request), reinterpret_cast<mach_vm_address_t>(&request),
                               &copied) != KERN_SUCCESS ||
        copied != sizeof(request))
      result = -14;
    else {
      guard.unlock();
      result = fli_sleep(clock, flags, request, remaining);
      guard.lock();
      if (result == -4 && !flags && output &&
          mach_vm_write(mach_task_self(), output, reinterpret_cast<vm_offset_t>(&remaining), sizeof(remaining)) !=
              KERN_SUCCESS)
        result = -14;
    }
  } else if (number == 228) {
    clockid_t clock;
    switch (a) {
    case 0:
      clock = CLOCK_REALTIME;
      break;
    case 1:
      clock = CLOCK_MONOTONIC;
      break;
    case 2:
      clock = CLOCK_PROCESS_CPUTIME_ID;
      break;
    case 3:
      clock = CLOCK_THREAD_CPUTIME_ID;
      break;
    case 4:
      clock = CLOCK_MONOTONIC_RAW;
      break;
    default:
      word(context, 0x48) = uint64_t(-95);
      return 1;
    }
    struct timespec value{};
    if (clock_gettime(clock, &value))
      result = linux_error(errno);
    else
      result = mach_vm_write(mach_task_self(), b, reinterpret_cast<vm_offset_t>(&value), sizeof(value)) == KERN_SUCCESS
                   ? 0
                   : -14;
  } else if (number == 234 && fli_env_enabled("REGRESSION_LINUX_FORK")) {
    uint64_t tid = 0;
    current_linux_tid(tid);
    int signal = host_signal(unsigned(c));
    if (int(a) != getpid() || b != tid)
      result = -3;
    else if (c && !signal)
      result = -95;
    else {
      int status = pthread_kill(pthread_self(), signal);
      result = status ? linux_error(status) : 0;
    }
  } else if (number == 158) {
    if (a == 0x1002) {
      if (b >= 0x800000000000ULL)
        result = -1;
      else {
        ThreadLinuxFS = b;
        LinuxFSExplicit = true;
        result = 0;
      }
    } else if (a == 0x1003) {
      result = mach_vm_write(mach_task_self(), b, reinterpret_cast<vm_offset_t>(&ThreadLinuxFS),
                             sizeof(ThreadLinuxFS)) == KERN_SUCCESS
                   ? 0
                   : -14;
    } else
      result = -95;
  } else if (number == 217)
    result = read_linux_directory(int(a), b, c);
  else if (number == 186) {
    uint64_t tid = 0;
    result = current_linux_tid(tid) ? -3 : int64_t(tid);
  } else if (number == 8) {
    int fd = int(a);
    int64_t offset = int64_t(b), base = 0;
    if (!Descriptors.contains(fd))
      result = -9;
    else if (c > 2)
      result = -22;
    else if (DirectoryStreams.contains(fd)) {
      if (c == 0 && offset >= 0) {
        seekdir(DirectoryStreams[fd], long(offset));
        FilePositions[fd] = uint64_t(offset);
        result = offset;
      } else if (c == 1 && !offset)
        result = telldir(DirectoryStreams[fd]);
      else
        result = -22;
    } else if (FilePositions.contains(fd)) {
      if (c == 1)
        base = int64_t(FilePositions.at(fd));
      if (c == 2) {
        struct stat info{};
        if (fstat(fd, &info)) {
          word(context, 0x48) = uint64_t(linux_error(errno));
          return 1;
        }
        base = info.st_size;
      }
      if ((offset > 0 && base > INT64_MAX - offset) || (offset < 0 && base < INT64_MIN - offset) || base + offset < 0)
        result = -22;
      else {
        FilePositions[fd] = uint64_t(base + offset);
        result = base + offset;
      }
    } else {
      const off_t position = lseek(fd, off_t(offset), int(c));
      result = position < 0 ? linux_error(errno) : int64_t(position);
    }
  } else if (number == 20) {
    if (a != 1 && a != 2)
      result = -9;
    else if (c > 1024)
      result = -22;
    else {
      ssize_t count = writev(int(a), reinterpret_cast<const iovec *>(b), int(c));
      result = count < 0 ? linux_error(errno) : count;
    }
  } else if (number == 202) {
    const uint32_t command = uint32_t(b) & 127;
    void *host = reinterpret_cast<void *>(a);
    for (const auto &alias : RootAliases) {
      if (a >= alias.guest && a - alias.guest < alias.length) {
        if (alias.length - (a - alias.guest) < 4 || !(alias.protection & PROT_READ))
          host = nullptr;
        else
          host = reinterpret_cast<void *>(alias.host + a - alias.guest);
        break;
      }
    }
    FliFutexTime timeout{};
    const FliFutexTime *limit = nullptr;
    bool valid = host != nullptr;
    if ((command == 0 || command == 9) && d) {
      mach_vm_size_t copied = 0;
      valid = valid &&
              mach_vm_read_overwrite(mach_task_self(), d, sizeof(timeout),
                                     reinterpret_cast<mach_vm_address_t>(&timeout), &copied) == KERN_SUCCESS &&
              copied == sizeof(timeout);
      limit = &timeout;
    }
    if (!valid)
      result = -14;
    else {
      static bool announced;
      if (!announced) {
        announced = true;
        dprintf(2, "FLI_NATIVE_SHARED_FUTEX_SERVICE pid=%d kernel-key=actual-backing\n", getpid());
      }
      const uint32_t mask = uint32_t(word(context, 0x20));
      guard.unlock();
      result = fli_shared_futex(host, uint32_t(b), uint32_t(c), limit, mask);
      guard.lock();
    }
  } else if (number == 89) {
    std::string path;
    if (!read_name(a, path, 4096))
      result = -14;
    else {
      dprintf(2, "FLI_LINUX_READLINK path=%s capacity=%llu\n", path.c_str(), static_cast<unsigned long long>(c));
      if (path == "/proc/self/exe" || path == "/proc/" + std::to_string(getpid()) + "/exe") {
        std::string target = guest_executable();
        if (target.empty())
          result = -3;
        else {
          size_t length = std::min<size_t>(target.size(), c);
          result = mach_vm_write(mach_task_self(), b, reinterpret_cast<vm_offset_t>(target.data()),
                                 mach_msg_type_number_t(length)) == KERN_SUCCESS
                       ? int64_t(length)
                       : -14;
        }
      } else if (path.starts_with("/proc/self/fd/") || path.starts_with("/proc/" + std::to_string(getpid()) + "/fd/")) {
        char *end = nullptr;
        const long fd = strtol(path.c_str() + path.rfind('/') + 1, &end, 10);
        char actual[PATH_MAX]{};
        if (!c)
          result = -22;
        else if (!end || *end || fd < 0 || fd > INT32_MAX || !Descriptors.contains(int(fd)))
          result = -2;
        else if (fcntl(int(fd), F_GETPATH, actual))
          result = linux_error(errno);
        else {
          const std::string target = fli_guest_path_view(actual, fli_host_path("VRCHAT_ROOTFS"));
          const size_t length = std::min<uint64_t>(target.size(), c);
          result = mach_vm_write(mach_task_self(), b, reinterpret_cast<vm_offset_t>(target.data()),
                                 mach_msg_type_number_t(length)) == KERN_SUCCESS
                       ? int64_t(length)
                       : -14;
        }
      } else if (path.starts_with("/proc/")) {
        std::string target = other_process_executable(path);
        if (target.empty())
          result = -2;
        else {
          size_t length = std::min<size_t>(target.size(), c);
          result = mach_vm_write(mach_task_self(), b, reinterpret_cast<vm_offset_t>(target.data()),
                                 mach_msg_type_number_t(length)) == KERN_SUCCESS
                       ? int64_t(length)
                       : -14;
        }
      } else if (fli_owned_host_ancestor(path) || fli_owned_host_path(path)) {
        std::vector<char> target(std::min<uint64_t>(c, 4096));
        ssize_t length = readlink(path.c_str(), target.data(), target.size());
        if (length < 0)
          result = linux_error(errno);
        else
          result = mach_vm_write(mach_task_self(), b, reinterpret_cast<vm_offset_t>(target.data()),
                                 mach_msg_type_number_t(length)) == KERN_SUCCESS
                       ? length
                       : -14;
      } else if (!path.empty() && path[0] == '/' && path.find("..") == std::string::npos) {
        const std::string root = fli_host_path("VRCHAT_ROOTFS");
        const std::string physical = root + path, parent = physical.substr(0, physical.rfind('/'));
        char canonical[PATH_MAX]{};
        if (!realpath(parent.c_str(), canonical))
          result = linux_error(errno);
        else if (std::string(canonical) != root && !std::string(canonical).starts_with(root + "/"))
          result = -13;
        else {
          std::vector<char> target(std::min<uint64_t>(c, 4096));
          ssize_t length = readlink(physical.c_str(), target.data(), target.size());
          result = length < 0 ? linux_error(errno)
                   : mach_vm_write(mach_task_self(), b, reinterpret_cast<vm_offset_t>(target.data()),
                                   mach_msg_type_number_t(length)) == KERN_SUCCESS
                       ? length
                       : -14;
        }
      } else
        result = -2;
    }
  } else if (number == 262 || number == 267) {
    std::string path;
    if (!read_name(b, path, 4096))
      result = -14;
    else {
      dprintf(2, "FLI_LINUX_PATH_QUERY number=%llu path=%s dirfd=%lld flags-or-size=%llx\n",
              static_cast<unsigned long long>(number), path.c_str(), static_cast<long long>(a),
              static_cast<unsigned long long>(d));
      if (number == 262)
        result = stat_guest_path(int(a), path, c, d);
      else if (number == 267 && (path == "/proc/self/exe" || path == "/proc/" + std::to_string(getpid()) + "/exe")) {
        std::string target = guest_executable();
        if (target.empty())
          result = -3;
        else {
          size_t length = std::min<size_t>(target.size(), d);
          result = mach_vm_write(mach_task_self(), c, reinterpret_cast<vm_offset_t>(target.data()),
                                 mach_msg_type_number_t(length)) == KERN_SUCCESS
                       ? int64_t(length)
                       : -14;
        }
      } else if (number == 267 && path.starts_with("/proc/")) {
        std::string target = other_process_executable(path);
        if (target.empty())
          result = -2;
        else {
          size_t length = std::min<size_t>(target.size(), d);
          result = mach_vm_write(mach_task_self(), c, reinterpret_cast<vm_offset_t>(target.data()),
                                 mach_msg_type_number_t(length)) == KERN_SUCCESS
                       ? int64_t(length)
                       : -14;
        }
      }
    }
  } else if (number == 5) {
    const int fd = int(a);
    struct stat host{};
    if (!Descriptors.contains(fd))
      result = -9;
    else if (fstat(fd, &host))
      result = linux_error(errno);
    else
      result = write_linux_stat(host, b);
  } else if (number == 2 || number == 257) {
    std::string path;
    const uint64_t pathname = number == 2 ? a : b, flags = number == 2 ? b : c;
    if (!read_name(pathname, path, 4096))
      result = -14;
    else {
      if (path.starts_with("/proc/") || path.starts_with("/dev/fd/"))
        dprintf(2, "FLI_LINUX_OPEN path=%s flags=%llx\n", path.c_str(), static_cast<unsigned long long>(flags));
      else if (path.starts_with("/usr/lib") || path.starts_with("/lib") || path.starts_with("/etc/") ||
               path.starts_with("/dev/") || path.starts_with("/sys/"))
        dprintf(2, "FLI_LINUX_OPEN path=%s flags=%llx\n", path.c_str(), static_cast<unsigned long long>(flags));
      else
        dprintf(2, "FLI_LINUX_OPEN path=%s flags=%llx\n", path.c_str(), static_cast<unsigned long long>(flags));
      if ((flags & 3) == 0 && (path == "/proc/self/maps" || path == "/proc/" + std::to_string(getpid()) + "/maps"))
        result = maps_snapshot();
      else if ((flags & 3) == 0 &&
               (path == "/proc/self/status" || path == "/proc/" + std::to_string(getpid()) + "/status"))
        result = status_snapshot(getpid());
      else if ((flags & 3) == 0 && (path == "/proc/mounts" || path == "/proc/self/mounts"))
        result = mounts_snapshot(flags);
      else if ((flags & 3) == 0 && path == "/proc/bus/pci/devices")
        result = pci_devices_snapshot(flags);
      else if ((flags & 3) == 0 && platform_identity_path(path))
        result = platform_identity_snapshot(path, flags);
      else if ((flags & 3) == 0 && path.starts_with("/proc/")) {
        char *end = nullptr;
        long pid = strtol(path.c_str() + 6, &end, 10);
        if (pid > 0 && pid <= INT32_MAX && end) {
          if (!strcmp(end, "/status"))
            result = status_snapshot(int(pid));
          else if (!strcmp(end, "/maps"))
            result = maps_snapshot(int(pid));
          else if (!strcmp(end, "/comm"))
            result = comm_snapshot(int(pid));
          else if (!strcmp(end, "/cmdline"))
            result = cmdline_snapshot(int(pid));
        }
      } else if ((flags & 3) == 0 && path == "/proc/" + std::to_string(getppid()) + "/comm")
        result = comm_snapshot(getppid());
      else if ((flags & 3) == 0 && path == "/proc/" + std::to_string(getppid()) + "/cmdline")
        result = cmdline_snapshot(getppid());
      else if (path[0] == '/' && !path.starts_with("/proc/")) {
        std::string physical = guest_file(path);
        if (physical.empty())
          result = -2;
        else if ((flags & 3) != 0)
          result = -95;
        else {
          int fd = open(physical.c_str(), O_RDONLY | ((flags & 0x80000) ? O_CLOEXEC : 0));
          if (fd < 0)
            result = linux_error(errno);
          else {
            Descriptors.insert(fd);
            ReadonlyDescriptors.insert(fd);
            result = fd;
          }
        }
      }
      for (const std::string prefix : {std::string("/proc/self/fd/"), "/proc/" + std::to_string(getpid()) + "/fd/"}) {
        if (!path.starts_with(prefix))
          continue;
        char *end = nullptr;
        long original = strtol(path.c_str() + prefix.size(), &end, 10);
        if (!end || *end || original < 0 || original > INT32_MAX || !Descriptors.contains(int(original)))
          result = -9;
        else if ((flags & 3) != 0 || (flags & ~uint64_t(0x88000)))
          result = -95;
        else {
          int fd = dup(int(original));
          if (fd < 0)
            result = linux_error(errno);
          else {
            if (flags & 0x80000)
              fcntl(fd, F_SETFD, FD_CLOEXEC);
            Descriptors.insert(fd);
            ReadonlyDescriptors.insert(fd);
            FilePositions[fd] = 0;
            result = fd;
            if (Memfds.contains(int(original))) {
              Memfds[fd] = Memfds[int(original)];
              int saved_errno = errno;
              snapshot_loaded_elf(int(original));
              errno = saved_errno;
            }
          }
        }
      }
    }
  } else if (number == 0 || number == 3 || number == 1 || number == 17 || number == 18 || number == 77 ||
             number == 72) {
    const int fd = static_cast<int>(a);
    MemfdState *memfd = Memfds.contains(fd) ? Memfds[fd] : nullptr;
    MemfdGuard mutation(memfd);
    if (!Descriptors.contains(fd))
      result = -9;
    else if (number == 3) {
      int status = close(fd);
      if (status < 0)
        result = linux_error(errno);
      else {
        if (DirectoryStreams.contains(fd)) {
          closedir(DirectoryStreams[fd]);
          DirectoryStreams.erase(fd);
        }
        Descriptors.erase(fd);
        FilePositions.erase(fd);
        ReadonlyDescriptors.erase(fd);
        Memfds.erase(fd);
        result = 0;
      }
    } else if ((number == 1 || number == 18 || number == 77) && ReadonlyDescriptors.contains(fd))
      result = -9;
    else if ((number == 1 || number == 18 || number == 77) && memfd && (memfd->seals.load() & 14))
      result = -1;
    else if (number == 77) {
      if (b > uint64_t(std::numeric_limits<off_t>::max()))
        result = -22;
      else {
        int status = ftruncate(fd, static_cast<off_t>(b));
        result = status < 0 ? linux_error(errno) : status;
      }
    } else if (number == 72) {
      if (b == 1033)
        result = ReadonlyDescriptors.contains(fd) ? -1 : add_memfd_seals(memfd, c);
      else if (b == 1034)
        result = memfd ? int64_t(memfd->seals.load()) : -22;
      else if (b == 1 || b == 2) {
        int status = fcntl(fd, b == 1 ? F_GETFD : F_SETFD, int(c));
        result = status < 0 ? linux_error(errno) : status;
      }
    } else if (c > uint64_t(std::numeric_limits<ssize_t>::max()) ||
               ((number == 17 || number == 18) && d > uint64_t(std::numeric_limits<off_t>::max())))
      result = -22;
    else {
      const auto independent = FilePositions.find(fd);
      ssize_t status;
      if (number == 17)
        status = pread(fd, reinterpret_cast<void *>(b), c, static_cast<off_t>(d));
      else if (number == 18)
        status = pwrite(fd, reinterpret_cast<const void *>(b), c, static_cast<off_t>(d));
      else if (independent != FilePositions.end()) {
        status = number == 0 ? pread(fd, reinterpret_cast<void *>(b), c, off_t(independent->second))
                             : pwrite(fd, reinterpret_cast<const void *>(b), c, off_t(independent->second));
        if (status > 0)
          independent->second += uint64_t(status);
      } else
        status =
            number == 0 ? read(fd, reinterpret_cast<void *>(b), c) : write(fd, reinterpret_cast<const void *>(b), c);
      result = status < 0 ? linux_error(errno) : status;
    }
  }
  if (number == 11 && fli_env_enabled("REGRESSION_DIAG_MUNMAP"))
    dprintf(2, "FLI_MUNMAP_REQUEST address=%llx size=%llx tracked-before=%d host-page=%d\n", (unsigned long long)a,
            (unsigned long long)b, unmap_owned, getpagesize());
  if (number == 56 || number == 14 || number == 231 || number == 101 || number == 157 || number == 62 ||
      number == 234 || number == 228 || number == 72)
    dprintf(2, "FLI_LINUX_THREAD_CALL number=%llu a=%llx b=%llx c=%llx d=%llx e=%llx pc=%llx\n",
            static_cast<unsigned long long>(number), static_cast<unsigned long long>(a),
            static_cast<unsigned long long>(b), static_cast<unsigned long long>(c),
            static_cast<unsigned long long>(number == 101 && (a == 4 || a == 5 || a == 6) ? 0 : d),
            static_cast<unsigned long long>(number == 101 ? 0 : word(context, 0x18)),
            static_cast<unsigned long long>(pc));
  if (ThreadLinuxFS && fli_env_enabled("REGRESSION_DIAG_THREAD_IDENTITY")) {
    static thread_local uint64_t reported_fs;
    if (reported_fs != ThreadLinuxFS) {
      uint64_t tid = 0;
      uint32_t stored_tid = 0;
      int native_status = pthread_threadid_np(nullptr, &tid);
      bool readable = read_trace_metadata(ThreadLinuxFS + 720, stored_tid);
      dprintf(2,
              "FLI_THREAD_IDENTITY native_status=%d native_tid=%llu tls_readable=%d tls_tid=%u root_tls=%d "
              "independent_tls=%d\n",
              native_status, (unsigned long long)tid, readable, stored_tid, ThreadLinuxFS == GlibcFSBase,
              AdoptedThread.tcb == ThreadLinuxFS);
      reported_fs = ThreadLinuxFS;
    }
  }
  if (!PendingMemoryNotifications.empty() && memory_change.owns_lock())
    PendingMemoryMutation = std::move(memory_change);
  word(context, 0x48) = static_cast<uint64_t>(result);
  if (trace_entry)
    stop_for_syscall(context, number, false);
  dprintf(2, "FLI_LINUX_SYSCALL number=%llu pc=%llx result=%lld pid=%d\n", static_cast<unsigned long long>(number),
          static_cast<unsigned long long>(pc), static_cast<long long>(result), getpid());
  return 1;
}
static int32_t restore_linux_fs(void *amd64_context) {
  if ((!ThreadLinuxFS && !LinuxFSExplicit) || !amd64_context)
    return 0;
  uint64_t teb;
  asm volatile("mov %0, x28" : "=r"(teb));
  auto area = *reinterpret_cast<uint64_t *>(teb + 0x1788);
  if (!area)
    return 0;
  auto frame = *reinterpret_cast<uint64_t *>(area + 0x30);
  if (!frame)
    return 0;
  // Pinned public FEX a4128 CPUState layout: fs_cached at byte 1000.
  *reinterpret_cast<uint64_t *>(frame + 1000) = ThreadLinuxFS;
  // Preserve the composite thread's Linux FS and Windows GS on this restore.
  // Integer/control/floating-point state is still restored by the real FEX path.
  auto *flags = reinterpret_cast<uint32_t *>(static_cast<char *>(amd64_context) + 0x30);
  *flags &= ~uint32_t(4); // CONTEXT_SEGMENTS
  const uint64_t native_teb = teb;
  const uint64_t peb = native_teb ? *reinterpret_cast<uint64_t *>(native_teb + 0x60) : 0;
  const uint64_t bitmap = peb ? *reinterpret_cast<uint64_t *>(peb + 0x368) : 0;
  static thread_local unsigned restoration_count;
  if (++restoration_count <= 16 || !(restoration_count & (restoration_count - 1))) {
    dprintf(2, "FLI_GLIBC_FS_RESTORE frame=%llx fs=%llx\n", static_cast<unsigned long long>(frame),
            static_cast<unsigned long long>(ThreadLinuxFS));
    dprintf(2, "FLI_FEX_CONTEXT native-teb=%llx caller-teb=%llx peb=%llx bitmap=%llx\n",
            static_cast<unsigned long long>(native_teb), static_cast<unsigned long long>(teb),
            static_cast<unsigned long long>(peb), static_cast<unsigned long long>(bitmap));
  }
  using dispatcher_query = uint64_t (*)(void *);
  const uint64_t provider = current_wine_module("xtajit64.dll");
  const uint64_t loop = provider ? reinterpret_cast<dispatcher_query>(provider + VRCHAT_FEX_DISPATCHER_QUERY_RVA)(
                                       reinterpret_cast<void *>(frame))
                                 : 0;
  static bool DumpedDispatcher;
  if (!DumpedDispatcher && loop) {
    DumpedDispatcher = true;
    // Only the provider's generic dispatcher, never translated guest blocks.
    const uint64_t base = loop & ~uint64_t(4095);
    const char *path = getenv("REGRESSION_FEX_DISPATCHER_CAPTURE");
    if (path) {
      FILE *file = fopen(path, "wb");
      if (file) {
        fwrite(reinterpret_cast<void *>(base), 1, 4096, file);
        fclose(file);
      }
    }
    dprintf(2, "FLI_FEX_DISPATCHER loop=%llx page=%llx\n", static_cast<unsigned long long>(loop),
            static_cast<unsigned long long>(base));
  }
  return 0;
}
static int32_t glibc_exports(void *opaque) {
  if (!opaque)
    return int32_t(0xc000000d);
  std::lock_guard guard(Lock);
  if (!ensure_glibc())
    return int32_t(0xc0000135);
  auto *out = static_cast<uint64_t *>(opaque);
  // Public symbols of the retained glibc 2.42 image, verified by its ELF dynsym.
  out[0] = GlibcBase + 0x6e800;
  out[1] = GlibcBase + 0x6e8c0;
  out[2] = GlibcBase + 0x6dfb0;
  return 0;
}
static int32_t glibc_thread_abi(void *opaque) {
  if (!opaque)
    return int32_t(0xc000000d);
  std::lock_guard guard(Lock);
  auto *out = static_cast<fli_elf_thread_abi *>(opaque);
  if (out->size != sizeof(*out))
    return int32_t(0xc0000004);
  const char *user_notify = getenv("REGRESSION_ELF_NOTIFY_ON_USER_STACK");
  if (!ensure_glibc(user_notify && !strcmp(user_notify, "1")) || !GlibcLoaderBase)
    return int32_t(0xc0000135);
  // Exact exported debug ABI and build IDs are recorded in glibc-tls-v561.
  const auto *tid = reinterpret_cast<const uint32_t *>(GlibcBase + 0x1acd40);
  if (tid[0] != 32 || tid[1] != 1 || tid[2] != 720 || *reinterpret_cast<const uint32_t *>(GlibcBase + 0x1bd15c) != 2368)
    return int32_t(0xc00000bb);
  *out = {sizeof(*out),
          1,
          GlibcBase + 0x6e800,
          GlibcBase + 0x6e8c0,
          GlibcBase + 0x6dfb0,
          GlibcLoaderBase + 0x12ab0,
          GlibcLoaderBase + 0x12ae0,
          GlibcFSBase};
  return 0;
}
static uint32_t *glibc_stack_lock() { return reinterpret_cast<uint32_t *>(GlibcLoaderBase + 0x37000 + 2112); }
static void lock_glibc_stacks() {
  uint32_t expected = 0;
  while (!__atomic_compare_exchange_n(glibc_stack_lock(), &expected, 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
    expected = 0;
    sched_yield();
  }
}
static void unlock_glibc_stacks() {
  uint32_t previous = __atomic_exchange_n(glibc_stack_lock(), 0, __ATOMIC_RELEASE);
  if (previous > 1) {
    fli_shared_futex(glibc_stack_lock(), 129, 1, nullptr, UINT32_MAX);
  }
}
AdoptedLinuxThread::~AdoptedLinuxThread() {
  if (!tcb || !GlibcLoaderBase)
    return;
  std::lock_guard guard(Lock);
  lock_glibc_stacks();
  auto *node = reinterpret_cast<uint64_t *>(tcb + 704);
  auto *next = reinterpret_cast<uint64_t *>(node[0]), *previous = reinterpret_cast<uint64_t *>(node[1]);
  previous[0] = node[0];
  next[1] = node[1];
  node[0] = node[1] = reinterpret_cast<uint64_t>(node);
  *reinterpret_cast<uint32_t *>(tcb + 720) = 0;
  unlock_glibc_stacks();
  // ponytail: retain detached TLS allocations until process exit; deallocation must run with live ELF execution state.
}
static int32_t glibc_bind_thread(void *opaque) {
  if (!opaque)
    return int32_t(0xc000000d);
  std::lock_guard guard(Lock);
  auto &input = *static_cast<fli_elf_thread_binding *>(opaque);
  if (AdoptedThread.tcb)
    return AdoptedThread.tcb == input.tcb ? 0 : int32_t(0xc000000d);
  if (!GlibcStarted || !GlibcLoaderBase || !input.tcb || input.tcb == GlibcFSBase || (input.tcb & 31) ||
      !input.stack_low || input.stack_high <= input.stack_low)
    return int32_t(0xc000000d);
  uint64_t dtv = 0, process_header[7]{};
  if (!read_trace_metadata(input.tcb + 8, dtv) || !dtv)
    return int32_t(0xc0000005);
  for (unsigned i = 0; i < 7; ++i)
    if (!read_trace_metadata(GlibcFSBase + i * 8, process_header[i]))
      return int32_t(0xc0000005);
  uint32_t features = 0;
  if (!read_trace_metadata(GlibcFSBase + 72, features) || features)
    return int32_t(0xc00000bb);
  uint64_t tid = 0;
  if (pthread_threadid_np(nullptr, &tid) || !tid || tid > INT32_MAX)
    return int32_t(0xc00000bb);
  alignas(32) unsigned char descriptor[2368]{};
  auto qword = [&](unsigned offset, uint64_t value) { memcpy(descriptor + offset, &value, 8); };
  auto dword = [&](unsigned offset, uint32_t value) { memcpy(descriptor + offset, &value, 4); };
  qword(0, input.tcb);
  qword(8, dtv);
  qword(16, input.tcb);
  dword(24, 1);
  qword(32, process_header[4]);
  qword(40, process_header[5]);
  qword(48, process_header[6]);
  dword(720, uint32_t(tid));
  qword(736, input.tcb + 736);
  qword(744, uint64_t(int64_t(-32)));
  qword(1296, input.tcb + 784);
  dword(1556, 2);
  qword(1576, input.tcb);
  qword(1680, input.stack_low);
  qword(1688, input.stack_high - input.stack_low);
  if (mach_vm_write(mach_task_self(), input.tcb, reinterpret_cast<vm_offset_t>(descriptor), sizeof(descriptor)) !=
      KERN_SUCCESS)
    return int32_t(0xc0000005);
  // _dl_allocate_tls allocates TLS but does not perform kernel thread
  // registration. Carry the real unsupported rseq state of our Root thread;
  // zero is a CPU ID and would falsely request rseq in every child pthread.
  int64_t rseq_offset = 0;
  int32_t root_cpu = 0, initial_cpu = 0;
  if (!read_trace_metadata(GlibcLoaderBase + 0x36a20, rseq_offset) || rseq_offset <= -1048576 ||
      rseq_offset >= 1048576 || !read_trace_metadata(GlibcFSBase + rseq_offset + 4, root_cpu) || root_cpu >= 0 ||
      !read_trace_metadata(input.tcb + rseq_offset + 4, initial_cpu))
    return int32_t(0xc00000bb);
  if (mach_vm_write(mach_task_self(), input.tcb + rseq_offset + 4, reinterpret_cast<vm_offset_t>(&root_cpu), 4) !=
      KERN_SUCCESS)
    return int32_t(0xc0000005);
  dprintf(2, "FLI_THREAD_KERNEL_STATE rseq-before=%d rseq-after=%d actual-root-state=1\n", initial_cpu, root_cpu);
  lock_glibc_stacks();
  auto *head = reinterpret_cast<uint64_t *>(GlibcLoaderBase + 0x37000 + 2064);
  auto *node = reinterpret_cast<uint64_t *>(input.tcb + 704), *next = reinterpret_cast<uint64_t *>(head[0]);
  node[0] = head[0];
  node[1] = reinterpret_cast<uint64_t>(head);
  next[1] = reinterpret_cast<uint64_t>(node);
  head[0] = reinterpret_cast<uint64_t>(node);
  unlock_glibc_stacks();
  *reinterpret_cast<uint32_t *>(GlibcFSBase + 24) = 1;
  *reinterpret_cast<unsigned char *>(GlibcBase + 0x1f2100) = 0;
  AdoptedThread.tcb = input.tcb;
  dprintf(2, "FLI_GLIBC_THREAD_REGISTERED tid=%llu independent-tls=1\n", static_cast<unsigned long long>(tid));
  return 0;
}
extern "C" {
static int32_t glibc_execution_regions(void *opaque) {
  if (!opaque)
    return int32_t(0xc000000d);
  std::lock_guard guard(Lock);
  auto *out = static_cast<fli_elf_execution_regions *>(opaque);
  if (out->size != sizeof(*out))
    return int32_t(0xc0000004);
  if (!ensure_glibc(true))
    return int32_t(0xc0000135);
  out->count = 0;
  for (const auto &region : ElfRegions)
    if (region.flags & 1) {
      if (out->count == 16)
        return int32_t(0xc0000023);
      out->regions[out->count++] = {region.start, region.end - region.start, (region.flags & 2) ? 0x40u : 0x20u, 0};
    }
  return out->count ? 0 : int32_t(0xc0000135);
}
static int32_t glibc_finish_thread_attach(void *opaque) {
  if (!opaque)
    return int32_t(0xc000000d);
  LinuxTLSAttachPending = false;
  const int32_t status = *static_cast<const int32_t *>(opaque);
  dprintf(2, "FLI_LINUX_THREAD_ATTACH_DONE status=%08x independent-tls=%d\n", uint32_t(status),
          AdoptedThread.tcb && ThreadLinuxFS == AdoptedThread.tcb);
  return 0;
}
// Execute only an original, decoded indirect JMP from a real executable alias.
// Other instructions and inaccessible targets retain Wine's normal exception path.
struct NativeInstructionAliasSnapshot {
  uint32_t size, count;
  RootAliasMetadata rows[4];
};
// ponytail: immutable alias snapshots live until process exit; reclaim only after
// a synchronized mapping lifecycle is implemented. No copied code or fake backing.
static std::vector<std::unique_ptr<NativeInstructionAliasSnapshot>> NativeAliasSnapshots;
static bool publish_native_instruction_aliases() {
  if (RootAliases.size() > 4)
    return false;
  const auto provider = current_wine_module("xtajit64.dll");
  if (!provider)
    return false;
  if (NativeAliasSnapshots.empty() || NativeAliasSnapshots.back()->count != RootAliases.size() ||
      memcmp(NativeAliasSnapshots.back()->rows, RootAliases.data(), RootAliases.size() * sizeof(RootAliasMetadata))) {
    auto snapshot = std::make_unique<NativeInstructionAliasSnapshot>();
    snapshot->size = sizeof(*snapshot);
    snapshot->count = uint32_t(RootAliases.size());
    std::copy(RootAliases.begin(), RootAliases.end(), snapshot->rows);
    NativeAliasSnapshots.push_back(std::move(snapshot));
  }
  using install = void (*)(const NativeInstructionAliasSnapshot *);
  reinterpret_cast<install>(provider + VRCHAT_FEX_INSTALL_ALIASES_RVA)(NativeAliasSnapshots.back().get());
  dprintf(2, "LAB_ALIAS_FETCH_PUBLISHED pid=%d aliases=%zu actual-shared-backing=1\n", getpid(), RootAliases.size());
  return true;
}
static int32_t query_execution_mapping(uint64_t address, uint64_t *out) {
  for (const auto &alias : RootAliases) {
    const uint64_t page = address & ~uint64_t(4095);
    if (page < alias.guest || page - alias.guest > alias.length || alias.length - (page - alias.guest) < 4096)
      continue;
    uint8_t byte = 0;
    if (!(alias.protection & PROT_READ) || !read_trace_metadata(alias.host + page - alias.guest, byte))
      return -14;
    out[0] = page;
    out[1] = 4096;
    out[2] = alias.host + page - alias.guest;
    out[3] = alias.protection;
    return 0;
  }
  using query = int32_t (*)(uint64_t, uint64_t *);
  const auto read = query_root_memory;
  return read ? read(address, out) : -38;
}
static thread_local uint64_t PendingExecutionPage, PendingExecutionLength;
static int32_t resolve_aliased_execution(void *opaque) {
  if (!opaque || !fli_env_enabled("REGRESSION_FLI_NATIVE_ALIAS_EXECUTION"))
    return 0;
  struct Request {
    void *context;
    uint64_t fault, page, length;
    uint32_t windows, reserved;
  };
  const auto &request = *static_cast<Request *>(opaque);
  void *context = request.context;
  if (!context)
    return 0;
  std::lock_guard guard(Lock);
  const uint64_t pc = word(context, 0x108);
  static thread_local unsigned observations;
  if (++observations <= 32 || !(observations & (observations - 1)))
    dprintf(2, "FLI_NATIVE_ALIAS_GATE pid=%d pc=%llx fault=%llx aliases=%zu\n", getpid(), (unsigned long long)pc,
            (unsigned long long)request.fault, RootAliases.size());
  if (!NativeAliasSnapshots.empty() && NativeAliasSnapshots.back()->count) {
    static thread_local unsigned observations;
    if (++observations <= 32 || !(observations & (observations - 1)))
      dprintf(2, "LAB_POST_ALIAS_EXCEPTION pid=%d count=%u pc=%llx fault=%llx executable-fault=%d\n", getpid(),
              observations, (unsigned long long)pc, (unsigned long long)request.fault, pc == request.fault);
  }
  if (pc != request.fault)
    return 0;
  for (const auto &alias : RootAliases) {
    if (!(alias.protection & PROT_EXEC) || pc < alias.guest || pc - alias.guest >= alias.length)
      continue;
    const size_t size = std::min<uint64_t>(32, alias.length - (pc - alias.guest));
    unsigned char code[32]{};
    mach_vm_size_t copied = 0;
    if (mach_vm_read_overwrite(mach_task_self(), alias.host + pc - alias.guest, size,
                               reinterpret_cast<mach_vm_address_t>(code), &copied) != KERN_SUCCESS ||
        copied != size)
      return 0;
    dprintf(2, "FLI_NATIVE_ALIAS_EXECUTION pid=%d pc=%llx backing=%llx\n", getpid(), (unsigned long long)pc,
            (unsigned long long)(alias.host + pc - alias.guest));
    if (size < 6 || code[0] != 0xff || code[1] != 0x25) {
      const uint64_t page = pc & ~uint64_t(4095);
      if (NativeExecutionPid != getpid()) {
        NativeExecutionPages.clear();
        NativeExecutionPid = getpid();
      }
      if (NativeExecutionPages.contains(page))
        return 0;
      if (!publish_native_instruction_aliases())
        return 0;
      auto &output = *static_cast<Request *>(opaque);
      output.page = page;
      output.length = 4096;
      output.windows = (alias.protection & PROT_WRITE) ? 0x40u : 0x20u;
      output.reserved = 0;
      PendingExecutionPage = page;
      PendingExecutionLength = 4096;
      dprintf(2, "LAB_ALIAS_FETCH_REGISTER pid=%d pc=%llx guest-page=%llx actual-backing=%llx\n", getpid(),
              (unsigned long long)pc, (unsigned long long)page, (unsigned long long)(alias.host + page - alias.guest));
      return 2;
    }
    int32_t displacement;
    memcpy(&displacement, code + 2, 4);
    const uint64_t pointer = pc + 6 + int64_t(displacement);
    if (alias.length < 8 || !(alias.protection & PROT_READ) || pointer < alias.guest ||
        pointer - alias.guest > alias.length - 8)
      return 0;
    uint64_t target = 0;
    if (!read_trace_metadata(alias.host + pointer - alias.guest, target))
      return 0;
    memcpy(static_cast<unsigned char *>(context) + 0x108, &target, 8);
    dprintf(2, "FLI_NATIVE_ALIAS_JMP pid=%d source=%llx target=%llx original-indirect-jump=1 registers-unchanged=1\n",
            getpid(), (unsigned long long)pc, (unsigned long long)target);
    return 1;
  }
  using query = int32_t (*)(uint64_t, uint64_t *);
  auto read = query_root_memory;
  uint64_t region[4]{};
  const int32_t mapped = read ? read(pc, region) : -38;
  if (mapped || region[2] != region[0] || !(region[3] & PROT_EXEC)) {
    static thread_local unsigned misses;
    if (misses++ < 8)
      dprintf(2, "FLI_NATIVE_ROOT_EXECUTION_QUERY_FAIL pid=%d pc=%llx query=%d page=%llx host=%llx prot=%llx\n",
              getpid(), (unsigned long long)pc, mapped, (unsigned long long)region[0], (unsigned long long)region[2],
              (unsigned long long)region[3]);
    return 0;
  }
  // Linux syscall ownership does not imply native FEX execution registration.
  if (NativeExecutionPid != getpid()) {
    NativeExecutionPages.clear();
    NativeExecutionPid = getpid();
  }

  // Native FEX can decode forward from any entry in this page into the next.
  // Re-notify the current page with a verified adjacent page so any cached
  // failed decode at the boundary is invalidated as well.
  uint64_t execution_length = region[1];
  bool adjacent_unregistered = false;
  if (region[1] == 4096) {
    uint64_t adjacent[4]{};
    if (!read(region[0] + region[1], adjacent) && adjacent[0] == region[0] + region[1] && adjacent[1] == 4096 &&
        adjacent[2] == adjacent[0] && adjacent[3] == region[3]) {
      execution_length += adjacent[1];
      adjacent_unregistered = !NativeExecutionPages.contains(adjacent[0]);
    }
  }
  if (NativeExecutionPages.contains(region[0]) && !adjacent_unregistered)
    return 0;
  const auto base = current_wine_ntdll();
  if (!base || !*reinterpret_cast<void **>(base + REGRESSION_WINE_NOTIFY_ALLOC_RVA))
    return 0;
  auto &output = *static_cast<Request *>(opaque);
  output.page = region[0];
  output.length = execution_length;
  PendingExecutionPage = region[0];
  PendingExecutionLength = execution_length;
  dprintf(2, "LAB_EXECUTION_SPAN pid=%d pc=%llx page=%llx length=%llx cross-page=%d\n", getpid(),
          (unsigned long long)pc, (unsigned long long)region[0], (unsigned long long)execution_length,
          execution_length > 4096);
  output.windows = (region[3] & PROT_WRITE) ? 0x40u : 0x20u;
  output.reserved = 0;
  dprintf(2,
          "FLI_NATIVE_ROOT_EXECUTION_READY pid=%d pc=%llx page=%llx protection=%llx actual-root-map=1 "
          "native-notification-deferred=1\n",
          getpid(), (unsigned long long)pc, (unsigned long long)region[0], (unsigned long long)region[3]);
  return 2;
}
static int32_t complete_aliased_execution(void *opaque) {
  if (!opaque || !fli_env_enabled("REGRESSION_FLI_NATIVE_ALIAS_EXECUTION"))
    return -22;
  const uint64_t page = *static_cast<const uint64_t *>(opaque);
  std::lock_guard guard(Lock);
  using query = int32_t (*)(uint64_t, uint64_t *);
  auto read = query_execution_mapping;
  uint64_t region[4]{};
  const int32_t status = read ? read(page, region) : -38;
  if (status || region[0] != page || !(region[3] & PROT_EXEC)) {
    dprintf(2, "FLI_NATIVE_ROOT_EXECUTION_FINISH_REJECT pid=%d page=%llx query=%d mapped=%llx host=%llx prot=%llx\n",
            getpid(), (unsigned long long)page, status, (unsigned long long)region[0], (unsigned long long)region[2],
            (unsigned long long)region[3]);
    return -14;
  }
  if (PendingExecutionPage != page || (PendingExecutionLength != 4096 && PendingExecutionLength != 8192))
    return -22;
  for (uint64_t cursor = page; cursor < page + PendingExecutionLength; cursor += 4096) {
    uint64_t verified[4]{};
    if (read(cursor, verified) || verified[0] != cursor || verified[2] != region[2] + cursor - page ||
        verified[3] != region[3])
      return -14;
  }
  if (NativeExecutionPid != getpid()) {
    NativeExecutionPages.clear();
    NativeExecutionPid = getpid();
  }
  for (uint64_t cursor = page; cursor < page + PendingExecutionLength; cursor += 4096) {
    LinuxPages.insert(cursor);
    NativeExecutionPages.insert(cursor);
  }
  PendingExecutionPage = PendingExecutionLength = 0;
  dprintf(2, "FLI_NATIVE_ROOT_EXECUTION_SYNC pid=%d page=%llx native-notification-complete=1 original-pc-retried=1\n",
          getpid(), (unsigned long long)page);
  return 0;
}
static int32_t observe_aliased_execution(void *opaque) {
  if (!opaque || !fli_env_enabled("REGRESSION_FLI_NATIVE_ALIAS_EXECUTION"))
    return -22;
  struct Observation {
    uint64_t page;
    uint32_t status, callback;
    uint64_t pc;
  };
  const auto &value = *static_cast<const Observation *>(opaque);
  dprintf(
      2,
      "FLI_NATIVE_ROOT_NOTIFY_RESULT pid=%d pc=%llx page=%llx wine-status=%08x in-syscall-callback=%u user-stack=1\n",
      getpid(), (unsigned long long)value.pc, (unsigned long long)value.page, value.status, value.callback);
  return 0;
}
static int32_t observe_elf_thread_entry(void *opaque) {
  if (!opaque || !fli_env_enabled("REGRESSION_FLI_NATIVE_ALIAS_EXECUTION"))
    return -22;
  struct Observation {
    uint64_t page;
    uint32_t status, callback;
    uint64_t pc;
  };
  const auto &value = *static_cast<const Observation *>(opaque);
  dprintf(
      2,
      "FLI_NATIVE_ELF_THREAD_ENTRY pid=%d pc=%llx status=%08x callback=%u fs=%llx actual-tcb=%llx independent-tls=%d\n",
      getpid(), (unsigned long long)value.pc, value.status, value.callback, (unsigned long long)ThreadLinuxFS,
      (unsigned long long)AdoptedThread.tcb, AdoptedThread.tcb && AdoptedThread.tcb == ThreadLinuxFS);
  return 0;
}
static int32_t attach_elf_thread_for_teb(uint64_t teb) {
  if (!teb || !fli_env_enabled("REGRESSION_FLI_NATIVE_ALIAS_EXECUTION"))
    return int32_t(0xc000000d);
  {
    std::lock_guard guard(Lock);
    if (AdoptedThread.tcb)
      return AdoptedThread.tcb == ThreadLinuxFS ? 0 : int32_t(0xc000000d);
    if (!ensure_glibc(true) || !GlibcLoaderBase)
      return int32_t(0xc0000135);
  }
  using allocate = int32_t (*)(uint64_t *);
  auto root = reinterpret_cast<allocate>(dlsym(RTLD_DEFAULT, "fli_root_allocate_glibc_tls"));
  if (!root)
    return int32_t(0xc0000135);
  uint64_t tcb = 0;
  const int32_t allocated = root(&tcb);
  if (allocated || !tcb)
    return int32_t(0xc0000017);
  if (!teb)
    return int32_t(0xc0000005);
  uint64_t low = 0, high = 0;
  if (!read_trace_metadata(teb + 0x10, low) || !read_trace_metadata(teb + 8, high) || !low || high <= low)
    return int32_t(0xc0000005);
  fli_elf_thread_binding binding{tcb, low, high};
  const int32_t bound = glibc_bind_thread(&binding);
  if (bound)
    return bound;
  ThreadLinuxFS = tcb;
  LinuxFSExplicit = true;
  uint64_t self = 0;
  uint32_t stored_tid = 0;
  uint64_t tid = 0;
  if (!read_trace_metadata(tcb, self) || self != tcb || !read_trace_metadata(tcb + 720, stored_tid) ||
      pthread_threadid_np(nullptr, &tid) || stored_tid != tid)
    return int32_t(0xc00000bb);
  dprintf(2, "FLI_NATIVE_ROOT_TLS_READY pid=%d tid=%llu tcb=%llx actual-glibc-allocation=1 independent-tls=1\n",
          getpid(), (unsigned long long)tid, (unsigned long long)tcb);
  return 0;
}
static int32_t attach_root_elf_thread(void *opaque) {
  if (!opaque)
    return int32_t(0xc000000d);
  uint64_t teb = 0;
  asm volatile("mov %0,x28" : "=r"(teb));
  return attach_elf_thread_for_teb(teb);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_linux_caller_thread_context(uint64_t teb, uint64_t *out) {
  if (!teb || !out)
    return -22;
  const int32_t status = attach_elf_thread_for_teb(teb);
  if (status)
    return -12;
  uint64_t tid = 0;
  if (current_linux_tid(tid) || !AdoptedThread.tcb || ThreadLinuxFS != AdoptedThread.tcb)
    return -22;
  uint64_t area = 0, frame = 0;
  if (read_trace_metadata(teb + 0x1788, area) && area && read_trace_metadata(area + 0x30, frame) && frame) {
    const uint64_t fs = ThreadLinuxFS;
    if (mach_vm_write(mach_task_self(), frame + 1000, reinterpret_cast<vm_offset_t>(&fs), sizeof(fs)) != KERN_SUCCESS)
      return -14;
  }
  out[0] = ThreadLinuxFS;
  out[1] = tid;
  return 0;
}
static int32_t current_thread_binding(void *opaque) {
  if (!opaque)
    return int32_t(0xc000000d);
  *static_cast<uint64_t *>(opaque) = AdoptedThread.tcb;
  return 0;
}
static int32_t adopt_wine_descriptor(void *opaque) {
  int32_t fd = -1;
  if (!opaque || !read_trace_metadata(uint64_t(opaque), fd))
    return int32_t(0xc0000005);
  std::lock_guard guard(Lock);
  const int flags = fd < 0 ? -1 : fcntl(fd, F_GETFL);
  if (flags < 0)
    return int32_t(0xc0000008);
  if (Descriptors.contains(fd))
    return 0;
  MemfdState *shared = nullptr;
  struct stat imported{};
  if (fstat(fd, &imported))
    return int32_t(0xc0000008);
  // ponytail: exports are infrequent; scan existing memfds until an inode index is measured necessary.
  for (const auto &[existing, state] : Memfds) {
    struct stat object{};
    if (!fstat(existing, &object) && object.st_dev == imported.st_dev && object.st_ino == imported.st_ino) {
      shared = state;
      break;
    }
  }
  Descriptors.insert(fd);
  if ((flags & O_ACCMODE) == O_RDONLY)
    ReadonlyDescriptors.insert(fd);
  if (shared)
    Memfds[fd] = shared;
  dprintf(2, "FLI_WINE_FD_IMPORTED pid=%d fd=%d actual-wine-export=1 shared-memfd=%d\n", getpid(), fd,
          shared != nullptr);
  return 0;
}
__attribute__((visibility("default"))) extern int32_t (*const __wine_unix_call_funcs[])(void *) = {
    dispatch, // FLI_SYSCALL_CALL
    restore_linux_fs, // FLI_RESTORE_FS_CALL
    glibc_exports, // FLI_GLIBC_EXPORTS_CALL
    glibc_thread_abi, // FLI_THREAD_ABI_CALL
    glibc_bind_thread, // FLI_BIND_THREAD_CALL
    glibc_execution_regions, // FLI_EXECUTION_REGIONS_CALL
    glibc_finish_thread_attach, // FLI_FINISH_THREAD_ATTACH_CALL
    resolve_aliased_execution, // FLI_RESOLVE_ALIAS_CALL
    complete_aliased_execution, // FLI_COMPLETE_ALIAS_CALL
    observe_aliased_execution, // FLI_OBSERVE_ALIAS_CALL
    observe_elf_thread_entry, // FLI_OBSERVE_THREAD_ENTRY_CALL
    attach_root_elf_thread, // FLI_ATTACH_ROOT_THREAD_CALL
    drain_memory_notification, // FLI_MEMORY_DRAIN_CALL
    current_thread_binding, // FLI_CURRENT_THREAD_CALL
    adopt_wine_descriptor}; // FLI_FD_IMPORT_CALL
static_assert(std::size(__wine_unix_call_funcs) == FLI_FD_IMPORT_CALL + 1);
}

// The Root caller owns the relay mapping and supplies translated local buffers.
extern "C" __attribute__((visibility("default")))
int32_t fli_native_trace_adopt(int32_t child, TraceState *trace) {
  if (!trace || trace->magic != 0x464c495452414331ULL) return -22;
  struct proc_bsdinfo process {};
  if (proc_pidinfo(child, PROC_PIDTBSDINFO, 0, &process, sizeof(process)) != sizeof(process)) return -3;
  if (process.pbi_ppid != uint32_t(getpid()) || process.pbi_uid != getuid()) return -13;
  std::lock_guard guard(Lock);
  TracedChildren[child] = trace;
  ChildProcesses.insert(child);
  return 0;
}
extern "C" __attribute__((visibility("default")))
int64_t fli_native_trace_request(uint64_t request, int32_t child, uint64_t address, uint64_t data) {
  std::lock_guard guard(Lock);
  if (!TracedChildren.contains(child)) return -3;
  return native_ptrace_request(request, uint64_t(child), address, data);
}
extern "C" __attribute__((visibility("default")))
int32_t fli_native_trace_wait(int32_t child, int32_t *status, int32_t options) {
  if (!TracedChildren.contains(child)) { errno = ECHILD; return -1; }
  return wait_guest_child(child, status, options);
}
extern "C" __attribute__((visibility("default")))
void fli_native_trace_release(int32_t child) {
  std::lock_guard guard(Lock);
  TracedChildren.erase(child);
  ChildProcesses.erase(child);
}

extern "C" __attribute__((visibility("default")))
int64_t fli_native_trace_readlink(int32_t child, void *buffer, uint64_t length) {
  if (!buffer || !length) return -22;
  std::lock_guard guard(Lock);
  if (!TracedChildren.contains(child)) return -3;
  const std::string target = other_process_executable("/proc/" + std::to_string(child) + "/exe");
  if (target.empty()) return -2;
  const size_t count = std::min<uint64_t>(length, target.size());
  std::memcpy(buffer, target.data(), count);
  return static_cast<int64_t>(count);
}
