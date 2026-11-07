#include "runtime-abi.h"
/* Private ABI transport: all library results come from the actual ELF functions. */
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#ifdef REGRESSION_ELF_THREAD_CONTEXT
#include "fli_elf_thread_abi.h"
static struct fli_elf_thread_abi thread_abi;
static uint64_t native_bridge_table;
static LONG(WINAPI *native_unix_call)(uint64_t, unsigned, void *);
#endif
static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
static uint64_t functions[3];
#ifndef REGRESSION_ELF_THREAD_CONTEXT
static void *gate;
#endif
struct loaded {
  uint64_t module, table;
  struct loaded *next;
};
static struct loaded *libraries;
static SRWLOCK libraries_lock = SRWLOCK_INIT;
__declspec(dllexport) BOOL WINAPI fli_elf_owns(uint64_t value, BOOL module) {
  BOOL found = FALSE;
  AcquireSRWLockShared(&libraries_lock);
  for (struct loaded *p = libraries; p; p = p->next)
    if ((module ? p->module : p->table) == value) {
      found = TRUE;
      break;
    }
  ReleaseSRWLockShared(&libraries_lock);
  return found;
}
extern uint64_t fli_elf_sysv_call(void *, uint64_t, uint64_t, uint64_t);
typedef LONG(WINAPI *query_t)(HANDLE, const void *, unsigned, void *, SIZE_T, SIZE_T *);
typedef LONG(WINAPI *unix_t)(uint64_t, unsigned, void *);
static BOOL CALLBACK initialize(INIT_ONCE *o, void *arg, void **ctx) {
  (void)o;
  (void)arg;
  (void)ctx;
#ifndef REGRESSION_ELF_THREAD_CONTEXT
  static const unsigned char code[] = {0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x0f, 0x05, 0xc3};
#endif
  WCHAR provider_root[1024];
  DWORD root_length = GetEnvironmentVariableW(L"VRCHAT_RUNTIME_ROOT", provider_root, ARRAYSIZE(provider_root));
  if (!root_length || root_length >= ARRAYSIZE(provider_root) - 1 || provider_root[0] != '/')
    return FALSE;
  provider_root[root_length++] = '/';
  provider_root[root_length] = 0;
  WCHAR path[1024] = L"\\??\\Z:";
  DWORD length = GetEnvironmentVariableW(L"REGRESSION_LINUX_BRIDGE_PATH", path + 6, ARRAYSIZE(path) - 6);
  if (!length || length >= ARRAYSIZE(path) - 6 || path[6] != '/' || wcsncmp(path + 6, provider_root, root_length))
    return FALSE;
  for (DWORD i = 6; i < length + 6; ++i)
    if (path[i] == '/')
      path[i] = '\\';
  UNICODE_STRING name = {(USHORT)((length + 6) * sizeof(WCHAR)), sizeof(path), path};
  uint64_t handles[2];
  DWORD old;
  HMODULE n = GetModuleHandleW(L"ntdll.dll");
  query_t query = (query_t)GetProcAddress(n, "NtQueryVirtualMemory");
  unix_t *call = (unix_t *)GetProcAddress(n, "__wine_unix_call_dispatcher");
  if (!query || !call)
    return FALSE;
#ifndef REGRESSION_ELF_THREAD_CONTEXT
  if (!gate) {
    gate = VirtualAlloc(0, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!gate)
      return FALSE;
    memcpy(gate, code, sizeof(code));
    if (!VirtualProtect(gate, 4096, PAGE_EXECUTE_READ, &old))
      return FALSE;
    FlushInstructionCache(GetCurrentProcess(), gate, sizeof(code));
  }
#endif
#ifdef REGRESSION_ELF_THREAD_CONTEXT
  if (query(GetCurrentProcess(), &name, 1002, handles, sizeof(handles), 0))
    return FALSE;
  native_bridge_table = handles[1];
  native_unix_call = *call;
  thread_abi.size = sizeof(thread_abi);
  if (native_unix_call(native_bridge_table, FLI_THREAD_ABI_CALL, &thread_abi) || thread_abi.version != 1)
    return FALSE;
  functions[0] = thread_abi.dlopen_function;
  functions[1] = thread_abi.dlsym_function;
  functions[2] = thread_abi.dlclose_function;
  char user_notify[2];
  if (GetEnvironmentVariableA("REGRESSION_ELF_NOTIFY_ON_USER_STACK", user_notify, sizeof(user_notify)) == 1 &&
      user_notify[0] == '1') {
    struct fli_elf_execution_regions ranges = {sizeof(ranges), 0};
    LONG(WINAPI * notify)(void *) = (void *)GetProcAddress(n, "__wine_register_elf_regions");
    if (!notify || native_unix_call(native_bridge_table, FLI_EXECUTION_REGIONS_CALL, &ranges))
      return FALSE;
    fprintf(stderr, "ELF_EXECUTION_USER_STACK_BEGIN regions=%u\n", ranges.count);
    if (notify(&ranges))
      return FALSE;
    fprintf(stderr, "ELF_EXECUTION_USER_STACK_REGISTERED regions=%u\n", ranges.count);
  }
  return TRUE;
#else
  int64_t fd = fli_elf_sysv_call(gate, 319, (uint64_t)"elf-transport", 2);
  if (fd < 0)
    return FALSE;
  if ((int64_t)fli_elf_sysv_call(gate, 3, fd, 0) < 0)
    return FALSE;
  if (query(GetCurrentProcess(), &name, 1002, handles, sizeof(handles), 0))
    return FALSE;
  return (*call)(handles[1], FLI_GLIBC_EXPORTS_CALL, functions) == 0;
#endif
}
#ifdef REGRESSION_ELF_THREAD_CONTEXT
__declspec(dllexport) LONG WINAPI fli_elf_attach_thread(void) {
  if (!InitOnceExecuteOnce(&once, initialize, 0, 0))
    return 0xc0000135;
  CONTEXT context = {0};
  LONG status = native_unix_call(native_bridge_table, FLI_ATTACH_ROOT_THREAD_CALL, &context);
  return status ? status : native_unix_call(native_bridge_table, FLI_RESTORE_FS_CALL, &context);
}
static LONG ensure_linux_thread(void) { return fli_elf_attach_thread(); }
__declspec(dllexport) LONG WINAPI fli_elf_prepare_thread(void) { return ensure_linux_thread(); }
__declspec(dllexport) DWORD WINAPI fli_elf_thread_entry(void *opaque) {
  uint64_t *startup = opaque;
  DWORD(WINAPI * entry)(void *) = (void *)startup[0];
  void *argument = (void *)startup[1];
  HeapFree(GetProcessHeap(), 0, startup);
  LONG status = ensure_linux_thread();
  if (status)
    return (DWORD)status;
  return entry(argument);
}

#else
static LONG ensure_linux_thread(void) { return InitOnceExecuteOnce(&once, initialize, 0, 0) ? 0 : 0xc0000135; }
#endif
__declspec(dllexport) LONG WINAPI fli_elf_load(const char *path, uint64_t *module, uint64_t *table) {
  if (!path || !module || !table)
    return 0xc000000d;
  *module = *table = 0;
  LONG ready = ensure_linux_thread();
  if (ready)
    return ready;
  uint64_t m = fli_elf_sysv_call((void *)functions[0], (uint64_t)path, 2, 0);
  if (!m)
    return 0xc0000135;
  uint64_t t = fli_elf_sysv_call((void *)functions[1], m, (uint64_t)"__wine_unix_call_funcs", 0);
  if (!t) {
    fli_elf_sysv_call((void *)functions[2], m, 0, 0);
    return 0xc0000139;
  }
  struct loaded *entry = HeapAlloc(GetProcessHeap(), 0, sizeof(*entry));
  if (!entry) {
    fli_elf_sysv_call((void *)functions[2], m, 0, 0);
    return 0xc0000017;
  }
  entry->module = m;
  entry->table = t;
  AcquireSRWLockExclusive(&libraries_lock);
  entry->next = libraries;
  libraries = entry;
  ReleaseSRWLockExclusive(&libraries_lock);
  fprintf(stderr, "ELF_TRANSPORT_TABLE_LOADED\n");
  *module = m;
  *table = t;
  return 0;
}
__declspec(dllexport) LONG WINAPI fli_elf_call(uint64_t table, unsigned index, void *args) {
  LONG ready = ensure_linux_thread();
  if (ready)
    return ready;
  LONG status = (LONG)fli_elf_sysv_call((void *)((uint64_t *)table)[index], (uint64_t)args, 0, 0);
  char flag[2];
  if (GetEnvironmentVariableA("REGRESSION_ELF_TRACE", flag, sizeof(flag)) == 1 && flag[0] == '1')
    fprintf(stderr, "ELF_TRANSPORT_CALL index=%u result=%08lx\n", index, (unsigned long)status);
  return status;
}
__declspec(dllexport) LONG WINAPI fli_elf_close(uint64_t module) {
  LONG ready = ensure_linux_thread();
  if (ready)
    return ready;
  LONG status = (LONG)fli_elf_sysv_call((void *)functions[2], module, 0, 0);
  if (!status) {
    AcquireSRWLockExclusive(&libraries_lock);
    struct loaded **p = &libraries;
    while (*p && (*p)->module != module)
      p = &(*p)->next;
    if (*p) {
      struct loaded *old = *p;
      *p = old->next;
      HeapFree(GetProcessHeap(), 0, old);
    }
    ReleaseSRWLockExclusive(&libraries_lock);
  }
  return status;
}
