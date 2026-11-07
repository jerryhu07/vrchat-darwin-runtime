#pragma once
#include <stdint.h>
typedef struct FliMemoryPeer {
  uint64_t address,length,protection;
  int64_t result;
} FliMemoryPeer;
