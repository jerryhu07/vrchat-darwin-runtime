#include "runtime-env.h"
// SPDX-License-Identifier: MIT
// Native host for the real Wine ELF frontend and the unchanged macOS Wine backend.
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
__attribute__((used, visibility("default"))) const void *wine_main_preload_info;
struct preload_region {
  void *address;
  size_t size;
};
static struct preload_region image_reservation[2];
static int open_pe_path(const char *path) {
  size_t length = strlen(path);
  if (length >= 4 && path[0] == '\\' && path[3] == '\\' &&
      ((path[1] == '\\' && path[2] == '?') || (path[1] == '?' && path[2] == '?')))
    path += 4;
  char native[PATH_MAX];
  if (strlen(path) >= 3 && isalpha((unsigned char)path[0]) && path[1] == ':') {
    const char *prefix = getenv("WINEPREFIX");
    if (!prefix)
      return -1;
    int count =
        snprintf(native, sizeof(native), "%s/dosdevices/%c:%s", prefix, tolower((unsigned char)path[0]), path + 2);
    if (count < 0 || (size_t)count >= sizeof(native))
      return -1;
  } else {
    if (strlen(path) >= sizeof(native))
      return -1;
    strcpy(native, path);
  }
  for (char *p = native; *p; ++p)
    if (*p == '\\')
      *p = '/';
  return open(native, O_RDONLY);
}
static int reserve_pe_image(const char *path) {
  int fd = open_pe_path(path);
  if (fd < 0)
    return 0;
  uint16_t mz = 0;
  uint32_t offset = 0, signature = 0, size = 0;
  uint64_t base = 0;
  uint16_t machine = 0, magic = 0;
  int valid = pread(fd, &mz, 2, 0) == 2 && mz == 0x5a4d && pread(fd, &offset, 4, 60) == 4 && offset >= 64 &&
              offset < 0x400000 && pread(fd, &signature, 4, offset) == 4 && signature == 0x4550 &&
              pread(fd, &machine, 2, offset + 4) == 2 && machine == 0x8664 && pread(fd, &magic, 2, offset + 24) == 2 &&
              magic == 0x20b && pread(fd, &base, 8, offset + 48) == 8 && pread(fd, &size, 4, offset + 80) == 4;
  close(fd);
  if (!valid || base < 0x100000000ULL || (base & 0xffff) || !size || size > 0x80000000U)
    return 0;
  size_t span = ((size_t)size + 0xffff) & ~(size_t)0xffff;
  mach_vm_address_t address = base;
  kern_return_t status = mach_vm_allocate(mach_task_self(), &address, span, VM_FLAGS_FIXED);
  if (status != KERN_SUCCESS) {
    fprintf(stderr, "FLI_PE_RESERVE unavailable=%d base=%llx size=%zx\n", status, (unsigned long long)base, span);
    return 0;
  }
  status = mach_vm_protect(mach_task_self(), address, span, FALSE, VM_PROT_NONE);
  if (status != KERN_SUCCESS) {
    mach_vm_deallocate(mach_task_self(), address, span);
    return 0;
  }
  image_reservation[0] = (struct preload_region){(void *)base, span};
  wine_main_preload_info = image_reservation;
  char range[64];
  snprintf(range, sizeof(range), "%llx-%llx", (unsigned long long)base, (unsigned long long)(base + span));
  setenv("WINEPRELOADRESERVE", range, 1);
  fprintf(stderr, "FLI_PE_RESERVE pid=%d base=%llx size=%zx\n", getpid(), (unsigned long long)base, span);
  return 1;
}
static void (*native_wine_main)(int, char **);
static void enter_native_wine(int argc, char **argv) {
  /* The configured frontend has already completed the loader handoff. */
  if (argc > 1 && argv[1][0] != '-')
    setenv("WINELOADERNOEXEC", "1", 1);
  unsetenv("REGRESSION_NATIVE_ELF_EXEC_GATE");
  native_wine_main(argc, argv);
}
int main(int argc, char **argv) {
  if (argc > 1 && fli_env_enabled("REGRESSION_FLI_RESERVE_PE_IMAGE"))
    reserve_pe_image(argv[1]);
  const char *root = getenv("WINEBUILDDIR");
  if (!root) {
    fputs("WINEBUILDDIR is required\n", stderr);
    return 64;
  }
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/dlls/ntdll/ntdll.so", root);
  void *native = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
  if (!native) {
    fprintf(stderr, "%s\n", dlerror());
    return 70;
  }
  void (*start)(int, char **) = dlsym(native, "__wine_main");
  const char *syscalls = getenv("REGRESSION_LINUX_BRIDGE_PATH");
  if (fli_env_enabled("REGRESSION_NATIVE_ELF_EXEC_GATE") && (!syscalls || !dlopen(syscalls, RTLD_NOW | RTLD_GLOBAL))) {
    fprintf(stderr, "ELF execution bridge: %s\n", dlerror());
    return 70;
  }
  const char *carrier = getenv("REGRESSION_FLI_CARRIER");
  if (!carrier || carrier[0] != '/') {
    fputs("REGRESSION_FLI_CARRIER must name an absolute file\n", stderr);
    return 64;
  }
  void *bridge = dlopen(carrier, RTLD_NOW | RTLD_GLOBAL);
  if (!start || !bridge) {
    fputs("Wine ELF/native backend unavailable\n", stderr);
    return 70;
  }
  int (*run)(int, char **, void (*)(int, char **)) = dlsym(bridge, "fli_run_wine_elf_host");
  native_wine_main = start;
  return run ? run(argc, argv, enter_native_wine) : 70;
}
