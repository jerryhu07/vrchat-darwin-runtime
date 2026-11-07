// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>
struct fli_elf_thread_abi {
  uint32_t size, version;
  uint64_t dlopen_function, dlsym_function, dlclose_function;
  uint64_t allocate_tls_function, deallocate_tls_function, root_fs;
};
struct fli_elf_thread_binding {
  uint64_t tcb, stack_low, stack_high;
};

struct fli_elf_execution_regions {
  uint32_t size, count;
  struct {
    uint64_t address, length;
    uint32_t protect, reserved;
  } regions[16];
};
