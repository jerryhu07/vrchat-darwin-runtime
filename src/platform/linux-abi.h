#pragma once
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>

struct LinuxPeerCredentials {
  int32_t ProcessID {};
  uint32_t UserID {};
  uint32_t GroupID {};
};

struct LinuxX86_64Stat {
  uint64_t Device {};
  uint64_t Inode {};
  uint64_t LinkCount {};
  uint32_t Mode {};
  uint32_t UserID {};
  uint32_t GroupID {};
  int32_t Padding {};
  uint64_t SpecialDevice {};
  int64_t Size {};
  int64_t BlockSize {};
  int64_t BlockCount {};
  int64_t AccessSeconds {};
  int64_t AccessNanoseconds {};
  int64_t ModificationSeconds {};
  int64_t ModificationNanoseconds {};
  int64_t ChangeSeconds {};
  int64_t ChangeNanoseconds {};
  std::array<int64_t, 3> Reserved {};
};

struct __attribute__((packed)) LinuxDirent64Header {
  uint64_t Inode {};
  int64_t Offset {};
  uint16_t RecordLength {};
  uint8_t Type {};
};

struct LinuxRLimit64 {
  uint64_t Current {};
  uint64_t Maximum {};
};

struct LinuxX86_64StackT {
  uint64_t StackPointer {};
  int32_t Flags {};
  uint32_t Padding {};
  uint64_t Size {};
};

struct LinuxIOVector64 {
  uint64_t Base {};
  uint64_t Length {};
};

struct LinuxMessageHeader64 {
  uint64_t Name {};
  uint32_t NameLength {};
  uint32_t NamePadding {};
  uint64_t IOVectors {};
  uint64_t IOVectorCount {};
  uint64_t Control {};
  uint64_t ControlLength {};
  int32_t Flags {};
  uint32_t FlagsPadding {};
};

struct LinuxControlMessageHeader64 {
  uint64_t Length {};
  int32_t Level {};
  int32_t Type {};
};

struct LinuxTimespec64 {
  int64_t Seconds {};
  int64_t Nanoseconds {};
};

struct LinuxTimeval64 {
  int64_t Seconds {};
  int64_t Microseconds {};
};

struct LinuxTimezone {
  int32_t MinutesWest {};
  int32_t DestinationTime {};
};

struct LinuxX86_64Sysinfo {
  int64_t Uptime {};
  std::array<uint64_t, 3> Loads {};
  uint64_t TotalRAM {};
  uint64_t FreeRAM {};
  uint64_t SharedRAM {};
  uint64_t BufferRAM {};
  uint64_t TotalSwap {};
  uint64_t FreeSwap {};
  uint16_t Processes {};
  uint16_t Padding {};
  uint64_t TotalHigh {};
  uint64_t FreeHigh {};
  uint32_t MemoryUnit {};
};

struct LinuxX86_64StatFS {
  int64_t Type {};
  int64_t BlockSize {};
  uint64_t Blocks {};
  uint64_t BlocksFree {};
  uint64_t BlocksAvailable {};
  uint64_t Files {};
  uint64_t FilesFree {};
  std::array<int32_t, 2> FileSystemID {};
  int64_t NameLength {};
  int64_t FragmentSize {};
  int64_t Flags {};
  std::array<int64_t, 4> Spare {};
};

struct LinuxPollFD {
  int32_t Descriptor {};
  int16_t Events {};
  int16_t ReturnedEvents {};
};

struct LinuxFlock64 {
  int16_t Type {};
  int16_t Whence {};
  int32_t Padding {};
  int64_t Start {};
  int64_t Length {};
  int32_t ProcessID {};
  int32_t FinalPadding {};
};

struct LinuxFutexWaitV {
  uint64_t Value {};
  uint64_t Address {};
  uint32_t Flags {};
  uint32_t Reserved {};
};

struct __attribute__((packed)) LinuxEpollEvent {
  uint32_t Events {};
  uint64_t Data {};
};

struct LinuxClone3Args {
  uint64_t Flags {};
  uint64_t PIDFD {};
  uint64_t ChildTID {};
  uint64_t ParentTID {};
  uint64_t ExitSignal {};
  uint64_t Stack {};
  uint64_t StackSize {};
  uint64_t TLS {};
  uint64_t SetTID {};
  uint64_t SetTIDSize {};
  uint64_t CGroup {};
};

struct LinuxGuestSigAction {
  uint64_t Handler {};
  uint64_t Flags {};
  uint64_t Restorer {};
  uint64_t Mask {};
};

inline std::optional<clockid_t> TranslateLinuxClockID(int32_t LinuxClock) {
  switch (LinuxClock) {
  case 0: return CLOCK_REALTIME;
  case 1: return CLOCK_MONOTONIC;
  case 2: return CLOCK_PROCESS_CPUTIME_ID;
  case 3: return CLOCK_THREAD_CPUTIME_ID;
#ifdef CLOCK_MONOTONIC_RAW
  case 4: return CLOCK_MONOTONIC_RAW;
#endif
  case 5: return CLOCK_REALTIME;
  case 6: return CLOCK_MONOTONIC;
  case 7: return CLOCK_MONOTONIC;
  default: return std::nullopt;
  }
}

inline int TranslateHostSocketErrorToLinux(int HostError) {
  switch (HostError) {
  case EAGAIN: return 11;
  case EINPROGRESS: return 115;
  case EALREADY: return 114;
  case ENOTSOCK: return 88;
  case EDESTADDRREQ: return 89;
  case EMSGSIZE: return 90;
  case EPROTOTYPE: return 91;
  case ENOPROTOOPT: return 92;
  case EPROTONOSUPPORT: return 93;
  case ESOCKTNOSUPPORT: return 94;
  case EOPNOTSUPP: return 95;
  case EPFNOSUPPORT: return 96;
  case EAFNOSUPPORT: return 97;
  case EADDRINUSE: return 98;
  case EADDRNOTAVAIL: return 99;
  case ENETDOWN: return 100;
  case ENETUNREACH: return 101;
  case ENETRESET: return 102;
  case ECONNABORTED: return 103;
  case ECONNRESET: return 104;
  case ENOBUFS: return 105;
  case EISCONN: return 106;
  case ENOTCONN: return 107;
  case ESHUTDOWN: return 108;
  case ETOOMANYREFS: return 109;
  case ETIMEDOUT: return 110;
  case ECONNREFUSED: return 111;
  case EHOSTDOWN: return 112;
  case EHOSTUNREACH: return 113;
  default: return HostError;
  }
}

inline int TranslateHostFileLockErrorToLinux(int HostError) {
  switch (HostError) {
  case EAGAIN: return 11;
  case EDEADLK: return 35;
  case ENOLCK: return 37;
  case EOVERFLOW: return 75;
  default: return HostError;
  }
}

inline int TranslateHostDupErrorToLinux(int HostError) {
  switch (HostError) {
  case EBADF: return 9;
  case EINTR: return 4;
  case EMFILE: return 24;
  case ENFILE: return 23;
  case ENOMEM: return 12;
  default: return 5;
  }
}

inline int TranslateHostFileOpenErrorToLinux(int HostError) {
  switch (HostError) {
  case EACCES: return 13;
  case EEXIST: return 17;
  case EINTR: return 4;
  case EISDIR: return 21;
  case ELOOP: return 40;
  case EMFILE: return 24;
  case ENAMETOOLONG: return 36;
  case ENFILE: return 23;
  case ENOENT: return 2;
  case ENOMEM: return 12;
  case ENOSPC: return 28;
  case ENOTDIR: return 20;
  case EROFS: return 30;
  default: return 5;
  }
}

inline int TranslateHostFcntlGetFlagsErrorToLinux(int HostError) {
  switch (HostError) {
  case EBADF: return 9;
  case EINTR: return 4;
  case EINVAL: return 22;
  default: return 5;
  }
}

inline int TranslateHostRegularWriteErrorToLinux(int HostError) {
  switch (HostError) {
  case EBADF: return 9;
  case EFBIG: return 27;
  case EINTR: return 4;
  case EINVAL: return 22;
  case EIO: return 5;
  case ENOSPC: return 28;
  case EPIPE: return 32;
  default: return 5;
  }
}

inline int TranslateHostRenameErrorToLinux(int HostError) {
  switch (HostError) {
  case EACCES: return 13;
  case EBUSY: return 16;
  case EEXIST: return 17;
  case EINVAL: return 22;
  case EIO: return 5;
  case EISDIR: return 21;
  case ELOOP: return 40;
  case ENAMETOOLONG: return 36;
  case ENOENT: return 2;
  case ENOSPC: return 28;
  case ENOTDIR: return 20;
  case ENOTEMPTY: return 39;
  case EPERM: return 1;
  case EROFS: return 30;
  case EXDEV: return 18;
  default: return 5;
  }
}

inline bool IsValidLinuxTimespec(const LinuxTimespec64& Time) {
  return Time.Seconds >= 0 && Time.Nanoseconds >= 0 && Time.Nanoseconds < 1'000'000'000;
}
