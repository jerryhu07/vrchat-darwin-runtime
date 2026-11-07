#pragma once
#include <stdint.h>
typedef struct FliMemoryProtectionRequest {
  uint64_t address, length, protection;
  int64_t result;
} FliMemoryProtectionRequest;
// 1: the authoritative Root owner handled the range (result is Linux errno).
// 0: this owner has no mapping for the requested range.
typedef int32_t (*FliRootProtect)(FliMemoryProtectionRequest *);
