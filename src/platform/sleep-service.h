#pragma once
#include <cerrno>
#include <cstdint>
#include <ctime>

struct FliSleepTime {
  int64_t seconds, nanoseconds;
};
// Buffers are resolved by the caller; both executors use the same host wait.
static inline int64_t fli_sleep(int32_t clock, uint64_t flags, const FliSleepTime &request, FliSleepTime &remaining) {
  if (flags > 1 || request.seconds < 0 || request.nanoseconds < 0 || request.nanoseconds >= 1000000000)
    return -22;
  clockid_t host;
  switch (clock) {
  case 0:
    host = CLOCK_REALTIME;
    break;
  case 1:
    host = CLOCK_MONOTONIC;
    break;
  default:
    return -22;
  }
  timespec delay{request.seconds, request.nanoseconds}, left{};
  if (flags) {
    timespec now{};
    if (clock_gettime(host, &now))
      return -errno;
    if (delay.tv_sec < now.tv_sec || (delay.tv_sec == now.tv_sec && delay.tv_nsec <= now.tv_nsec))
      return 0;
    delay.tv_sec -= now.tv_sec;
    delay.tv_nsec -= now.tv_nsec;
    if (delay.tv_nsec < 0) {
      --delay.tv_sec;
      delay.tv_nsec += 1000000000;
    }
  }
  if (!nanosleep(&delay, &left))
    return 0;
  const int error = errno;
  if (error == EINTR && !flags)
    remaining = {left.tv_sec, left.tv_nsec};
  return -error;
}
