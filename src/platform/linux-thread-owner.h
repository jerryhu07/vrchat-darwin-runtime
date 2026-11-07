#pragma once
#include <stdint.h>
// Public x86-64 Linux register order plus FXSAVE and upper YMM state.
// RIP is the continuation after SYSCALL; the source adapter normalizes it.
struct FliLinuxThreadState {
  uint32_t size, version, has_ymm, reserved;
  uint64_t regs[27], args[6];
  alignas(16) unsigned char floating[512], ymm[256];
};
static_assert(sizeof(FliLinuxThreadState) == 1056);
