#pragma once
#include <stdint.h>
typedef struct FliFutexTime {
  int64_t seconds, nanoseconds;
} FliFutexTime;
typedef int64_t (*FliFutexCall)(void *, uint32_t, uint32_t, const struct FliFutexTime *, uint32_t);
