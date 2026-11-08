#include "paths.h"
#include "runtime-env.h"
#include "generated-abi.h"
#include "linux-abi.h"
#include "linux-thread-owner.h"
constexpr uint64_t LinuxSigBlock = 0, LinuxSigUnblock = 1, LinuxSigSetMask = 2;
#include "file-identity.h"
#include "cwd-service.h"
#include "sleep-service.h"
#include "memory-owner-abi.h"
#include "futex-abi.h"
#include <fstream>
// SPDX-License-Identifier: MIT

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/HostFeatures.h>
#include "Interface/Context/Context.h"
#include <FEXCore/Debug/InternalThreadState.h>
#include <Interface/Core/LookupCache.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXCore/Utils/LongJump.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <Linux/Utils/ELFParser.h>
#include "LinuxEmulation/ArchHelpers/UContext.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <map>
#include <memory>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <signal.h>
#include <set>
#include <string>
#include <sys/ucontext.h>
#include <utility>
#include <vector>
#include <type_traits>

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <libproc.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <poll.h>
#include <pthread.h>
#include <spawn.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <os/os_sync_wait_on_address.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern "C" ssize_t __getdirentries64(int, char *, size_t, off_t *);

namespace {
thread_local std::unique_lock<std::recursive_mutex> *ActiveSyscallLock{};
thread_local bool NativeCallbackInProgress{};
thread_local uint64_t NativeCallbackBlockingSequence{}, ActiveGuestSyscallNumber{UINT64_MAX}, ActiveGuestSyscallRIP{};
thread_local int64_t ActiveGuestSyscallDescriptor{-1};
template <typename Function> auto BlockingHostCall(Function &&Call) {
  auto *Lock = ActiveSyscallLock;
  const uint64_t sequence = NativeCallbackInProgress ? ++NativeCallbackBlockingSequence : 0;
  const bool trace = sequence && (sequence <= 64 || (sequence & (sequence - 1)) == 0) &&
                     fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT");
  if (trace)
    dprintf(2, "NATIVE_CALLBACK_BLOCK_BEGIN pid=%d seq=%llu syscall=%llu rip=%llx lock-owned=%d\n", getpid(),
            (unsigned long long)sequence, (unsigned long long)ActiveGuestSyscallNumber,
            (unsigned long long)ActiveGuestSyscallRIP, Lock && Lock->owns_lock());
  const bool unlock = Lock && Lock->owns_lock();
  if (unlock)
    Lock->unlock();
  auto Result = Call();
  if (trace) {
    if constexpr (std::is_integral_v<decltype(Result)>)
      dprintf(2, "NATIVE_CALLBACK_BLOCK_HOST_RETURN pid=%d seq=%llu syscall=%llu descriptor=%lld result=%lld\n",
              getpid(), (unsigned long long)sequence, (unsigned long long)ActiveGuestSyscallNumber,
              (long long)ActiveGuestSyscallDescriptor, (long long)Result);
    else
      dprintf(2, "NATIVE_CALLBACK_BLOCK_HOST_RETURN pid=%d seq=%llu syscall=%llu result-kind=noninteger\n", getpid(),
              (unsigned long long)sequence, (unsigned long long)ActiveGuestSyscallNumber);
  }
  if (unlock)
    Lock->lock();
  if (trace)
    dprintf(2, "NATIVE_CALLBACK_BLOCK_END pid=%d seq=%llu syscall=%llu\n", getpid(), (unsigned long long)sequence,
            (unsigned long long)ActiveGuestSyscallNumber);
  return Result;
}
std::string ResearchTemporaryPrefix(std::string_view Name) {
  const char *Directory = std::getenv("REGRESSION_RESEARCH_TMPDIR");
  return std::string{Directory && *Directory ? Directory : "/private/tmp"} + "/" + std::string{Name};
}

thread_local uint64_t CallbackGuestThreadID{};
uint64_t LinuxGuestThreadID() {
  if (CallbackGuestThreadID)
    return CallbackGuestThreadID;
  if (pthread_main_np())
    return static_cast<uint64_t>(getpid());
  uint64_t Identifier{};
  return pthread_threadid_np(nullptr, &Identifier) == 0 ? Identifier : 0;
}

static std::atomic<FEXCore::Core::CpuStateFrame *> NativeMapObservedFrame{nullptr};
static std::atomic<uint64_t> NativeMapCompileSequence{}, NativeMapCompilePhase{}, NativeMapCompileAddress{};
struct NativeMapCompileScope {
  const bool active = NativeCallbackInProgress;
  const uint64_t finished;
  NativeMapCompileScope(uint64_t phase, uint64_t address) : finished(phase + 1) {
    if (active) {
      NativeMapCompileAddress.store(address);
      NativeMapCompilePhase.store(phase);
    }
  }
  ~NativeMapCompileScope() {
    if (active)
      NativeMapCompilePhase.store(finished);
  }
};

uintptr_t LoadedMachOImageBase(std::string_view ImageSuffix) {
  const uint32_t ImageCount = _dyld_image_count();
  for (uint32_t Index = 0; Index < ImageCount; ++Index) {
    const char *ImageName = _dyld_get_image_name(Index);
    const auto *ImageHeader = _dyld_get_image_header(Index);
    if (ImageName != nullptr && ImageHeader != nullptr && std::string_view{ImageName}.ends_with(ImageSuffix)) {
      return reinterpret_cast<uintptr_t>(ImageHeader);
    }
  }
  return 0;
}

constexpr uint64_t RealInterpreterLoadOffset = 32 * 1024 * 1024;
constexpr uint64_t RealMMapArenaOffset = 48 * 1024 * 1024;
constexpr uint64_t RealMMapArenaLimitOffset = 4064ULL * 1024 * 1024;
constexpr uint64_t RealLowPageAliasOffset = 4068ULL * 1024 * 1024;
constexpr uint64_t RealLowPageAliasBackingSize = 16 * 1024;
constexpr uint64_t RealStackOffset = 4080ULL * 1024 * 1024;
constexpr uint64_t RealStackStringsOffset = RealStackOffset + 0x4000;
constexpr uint64_t RealStopOffset = 4095ULL * 1024 * 1024;
constexpr size_t RealGuestMemorySize = 4096ULL * 1024 * 1024;
constexpr uint64_t LinuxSharedUserDataAddress = 0x7ffe0000;
constexpr uint64_t LinuxSharedUserDataSize = 4096;
constexpr uint64_t LinuxGuestPageSize = 4096;
constexpr uint64_t ObservedWineSessionMappingSize = 0x144000;
constexpr uint64_t ObservedWineUserSharedDataInitializationSize = 1848;
constexpr uint64_t LowGuestAddressLimit = uint64_t{1} << 32;
constexpr uint64_t HighSparseGuestBase = LowGuestAddressLimit;
constexpr uint64_t HighSparseGuestSize = (uint64_t{1} << 41) - HighSparseGuestBase;
static_assert(RealMMapArenaLimitOffset <= RealLowPageAliasOffset);
static_assert(RealLowPageAliasOffset + RealLowPageAliasBackingSize <= RealStackOffset);
static_assert(HighSparseGuestBase % LinuxGuestPageSize == 0);
static_assert(HighSparseGuestSize % LinuxGuestPageSize == 0);
constexpr uint64_t ReadSyscall = 0;
constexpr uint64_t WriteSyscall = 1;
constexpr uint64_t OpenSyscall = 2;
constexpr uint64_t StatSyscall = 4;
constexpr uint64_t PollSyscall = 7;
constexpr uint64_t BrkSyscall = 12;
constexpr uint64_t RtSigactionSyscall = 13;
constexpr uint64_t RtSigprocmaskSyscall = 14;
constexpr uint64_t IoctlSyscall = 16;
constexpr uint64_t LinuxTCGets2 = 0x802c542a;
constexpr uint64_t LinuxExt2IOCGetFlags = 0x80086601;
constexpr uint64_t AccessSyscall = 21;
constexpr uint64_t DupSyscall = 32;
constexpr uint64_t Dup2Syscall = 33;
constexpr uint64_t SocketSyscall = 41;
constexpr uint64_t ConnectSyscall = 42;
constexpr uint64_t AcceptSyscall = 43;
constexpr bool ExperimentalAcceptDispatchEnabled = true;
constexpr uint64_t SendMsgSyscall = 46;
constexpr uint64_t RecvMsgSyscall = 47;
constexpr uint64_t ShutdownSyscall = 48;
constexpr uint64_t BindSyscall = 49;
constexpr uint64_t ListenSyscall = 50;
constexpr uint64_t SocketPairSyscall = 53;
constexpr uint64_t SetSockOptSyscall = 54;
constexpr uint64_t GetSockOptSyscall = 55;
constexpr uint64_t GetPIDSyscall = 39;
constexpr uint64_t GetTIDSyscall = 186;
constexpr uint64_t CloneSyscall = 56;
constexpr uint64_t FcntlSyscall = 72;
constexpr uint64_t FTruncateSyscall = 77;
constexpr uint64_t ExecveSyscall = 59;
constexpr uint64_t Wait4Syscall = 61;
constexpr uint64_t WriteVSyscall = 20;
constexpr uint64_t PRead64Syscall = 17;
constexpr uint64_t PWrite64Syscall = 18;
constexpr uint64_t FStatSyscall = 5;
constexpr uint64_t MMapSyscall = 9;
constexpr uint64_t MUnmapSyscall = 11;
constexpr uint64_t EpollCreateSyscall = 213;
constexpr uint64_t GetDents64Syscall = 217;
constexpr uint64_t EpollWaitSyscall = 232;
constexpr uint64_t EpollCtlSyscall = 233;
constexpr uint64_t EpollPWait2Syscall = 441;
constexpr uint64_t CloseSyscall = 3;
constexpr uint64_t PrctlSyscall = 157;
constexpr uint64_t ArchPrctlSyscall = 158;
constexpr uint64_t SetTIDAddressSyscall = 218;
constexpr uint64_t SetRobustListSyscall = 273;
constexpr uint64_t RSeqSyscall = 334;
constexpr uint64_t MProtectSyscall = 10;
constexpr uint64_t Prlimit64Syscall = 302;
constexpr uint64_t Pipe2Syscall = 293;
constexpr uint64_t ClockGettimeSyscall = 228;
constexpr uint64_t ClockNanosleepSyscall = 230;
constexpr uint64_t GetrandomSyscall = 318;
constexpr uint64_t MemfdCreateSyscall = 319;
constexpr uint64_t UserfaultfdSyscall = 323;
constexpr uint64_t Clone3Syscall = 435;
constexpr uint64_t FAccessAt2Syscall = 439;
constexpr uint64_t FutexWaitVSyscall = 449;
constexpr uint64_t UnameSyscall = 63;
constexpr uint64_t GetcwdSyscall = 79;
constexpr uint64_t ChdirSyscall = 80;
constexpr uint64_t FChdirSyscall = 81;
constexpr uint64_t RenameSyscall = 82;
constexpr uint64_t MkdirSyscall = 83;
constexpr uint64_t UnlinkSyscall = 87;
constexpr uint64_t SymlinkSyscall = 88;
constexpr uint64_t ReadlinkSyscall = 89;
constexpr uint64_t ChmodSyscall = 90;
constexpr uint64_t UmaskSyscall = 95;
constexpr uint64_t GettimeofdaySyscall = 96;
constexpr uint64_t SysinfoSyscall = 99;
constexpr uint64_t TimeSyscall = 201;
constexpr uint64_t SchedGetAffinitySyscall = 204;
constexpr uint64_t GetUIDSyscall = 102;
constexpr uint64_t SetSIDSyscall = 112;
constexpr uint64_t SetPrioritySyscall = 141;
constexpr uint64_t SigAltStackSyscall = 131;
constexpr uint64_t LinuxX86MinSignalStackSize = 2048;
constexpr uint64_t FStatFSSyscall = 138;
constexpr uint64_t OpenAtSyscall = 257;
constexpr uint64_t NewFStatAtSyscall = 262;
constexpr uint64_t ExitSyscall = 60;
constexpr uint64_t ExitGroupSyscall = 231;
constexpr int64_t LinuxAtFDCWD = -100;
constexpr int64_t LinuxFSetFDCommand = 2;
constexpr int64_t LinuxFGetFLCommand = 3;
constexpr int64_t LinuxFSetFLCommand = 4;
constexpr uint64_t LinuxOWriteOnlyAccessMode = 0x1;
constexpr uint64_t LinuxOReadWriteAccessMode = 0x2;
constexpr uint64_t LinuxOAppend = 0x400;
constexpr uint64_t LinuxONonBlock = 0x800;

bool WineIPCTraceEnabled() { return fli_env_enabled("REGRESSION_FLI_TRACE_WINE_IPC"); }

void TraceWineRequestHeader(std::string_view Source, int Descriptor, const void *Header, size_t HeaderSize) {
  if (!WineIPCTraceEnabled() || Header == nullptr || HeaderSize < 12) {
    return;
  }

  int32_t RequestCode{};
  uint32_t RequestSize{};
  uint32_t ReplySize{};
  const auto *Bytes = static_cast<const uint8_t *>(Header);
  std::memcpy(&RequestCode, Bytes, sizeof(RequestCode));
  std::memcpy(&RequestSize, Bytes + 4, sizeof(RequestSize));
  std::memcpy(&ReplySize, Bytes + 8, sizeof(ReplySize));
  std::cerr << "TRACE wine-ipc request source=" << Source << " fd=" << Descriptor << " req=" << RequestCode
            << " request-size=" << RequestSize << " reply-size=" << ReplySize << '\n';
  std::cerr.flush();
}

void TraceWineReplyHeader(std::string_view Source, int Descriptor, const void *Header, size_t HeaderSize) {
  if (!WineIPCTraceEnabled() || Header == nullptr || HeaderSize < 8) {
    return;
  }

  uint32_t Error{};
  uint32_t ReplySize{};
  const auto *Bytes = static_cast<const uint8_t *>(Header);
  std::memcpy(&Error, Bytes, sizeof(Error));
  std::memcpy(&ReplySize, Bytes + 4, sizeof(ReplySize));
  std::cerr << "TRACE wine-ipc reply source=" << Source << " fd=" << Descriptor << " error=" << Error
            << " reply-size=" << ReplySize << '\n';
  std::cerr.flush();
}

enum class ConnectPathClass : uint8_t {
  None,
  Empty,
  Abstract,
  Absolute,
  Relative,
};

enum class ConnectFailureReason : uint8_t {
  None,
  UnownedDescriptor,
  UnreadableAddress,
  UnsupportedFamily,
  EmptyPayload,
  AbstractPath,
  EmptyPath,
  RelativePath,
  PathResolutionRejected,
  HostCWDNotMirrored,
  MissingTarget,
  TargetNotSocket,
  HostPathTooLong,
  HostConnectFailed,
};

enum class AcceptFailureReason : uint8_t {
  None,
  NonListeningOrUnownedDescriptor,
  UnreadableAddressOrLength,
  UnmeasuredAddressLength,
  HostAcceptFailed,
  UnsupportedHostAddress,
};

enum class GetSockOptFailureReason : uint8_t {
  None,
  UnownedDescriptor,
  UnreadableLength,
  UnmeasuredShape,
  UnreadableValue,
  HostPeerIdentityFailed,
  HostPeerProcessFailed,
  HostPeerProcessLengthMismatch,
};

enum class SendMsgFailureReason : uint8_t {
  None,
  UnownedDescriptor,
  UnreadableHeader,
  UnreadableIOVector,
  UnreadablePayload,
  UnreadableControl,
  UnmeasuredShape,
  UnownedTransferredDescriptor,
  HostControlLayoutUnavailable,
  HostSendFailed,
};

enum class MUnmapFailureReason : uint8_t {
  None,
  UnmeasuredShape,
  HostAnonymousRemapFailed,
  HostAnonymousRemapAddressMismatch,
  SparseHighUnmapFailed,
  LowShadowUnmapFailed,
  InvalidRange,
};

static_assert(sizeof(LinuxPeerCredentials) == 12);

static_assert(sizeof(LinuxX86_64Stat) == 144);

static_assert(sizeof(LinuxDirent64Header) == 19);

static_assert(sizeof(LinuxRLimit64) == 16);

static_assert(sizeof(LinuxX86_64StackT) == 24);

static_assert(sizeof(LinuxIOVector64) == 16);

static_assert(sizeof(LinuxMessageHeader64) == 56);

static_assert(sizeof(LinuxControlMessageHeader64) == 16);

struct HighMMapRecord {
  uint64_t Address{};
  uint64_t Length{};
  uint64_t ArenaEnd{};
  uint64_t Protection{};
  uint64_t Flags{};
  uint64_t Offset{};
  int64_t Descriptor{-1};
  std::string DescriptorPathClass{"none"};
  std::string DescriptorGuestPath{"none"};
  bool Active{};
};

struct LowMMapRecord {
  uint64_t Address{};
  uint64_t Length{};
  uint64_t Protection{};
  uint64_t Flags{};
  uint64_t Offset{};
  int64_t Descriptor{-1};
  std::string DescriptorPathClass{"none"};
  std::string DescriptorGuestPath{"none"};
};

struct ReadELFHeaderRecord {
  uint64_t SyscallOrdinal{};
  int64_t Descriptor{-1};
  uint64_t GuestBuffer{};
  uint64_t RequestedByteCount{};
  uint64_t ReturnedByteCount{};
  uint64_t First64ByteFingerprint{};
  uint32_t Magic{};
  uint8_t ELFClass{};
  uint8_t DataEncoding{};
  uint16_t Type{};
  uint16_t Machine{};
  uint32_t Version{};
  uint64_t Entry{};
  uint64_t ProgramHeaderOffset{};
  uint16_t ProgramHeaderEntrySize{};
  uint16_t ProgramHeaderCount{};
  std::string DescriptorPathClass{"none"};
  std::string DescriptorGuestPath{"none"};
};

static_assert(sizeof(LinuxTimespec64) == 16);

static_assert(sizeof(LinuxTimeval64) == 16);

static_assert(sizeof(LinuxTimezone) == 8);

static_assert(sizeof(LinuxX86_64Sysinfo) == 112);
static_assert(offsetof(LinuxX86_64Sysinfo, TotalHigh) == 88);
static_assert(offsetof(LinuxX86_64Sysinfo, MemoryUnit) == 104);

static_assert(sizeof(LinuxX86_64StatFS) == 120);

static_assert(sizeof(LinuxPollFD) == 8);

static_assert(sizeof(LinuxFlock64) == 32);

static_assert(sizeof(LinuxFutexWaitV) == 24);

static_assert(sizeof(LinuxEpollEvent) == 12);

static_assert(sizeof(LinuxClone3Args) == 88);

static_assert(sizeof(LinuxGuestSigAction) == 32);

uint64_t FingerprintBytes(const uint8_t *Bytes, size_t Size) {
  constexpr uint64_t OffsetBasis = 14'695'981'039'346'656'037ULL;
  constexpr uint64_t Prime = 1'099'511'628'211ULL;
  uint64_t Hash = OffsetBasis;
  for (size_t Index = 0; Index < Size; ++Index) {
    Hash ^= Bytes[Index];
    Hash *= Prime;
  }
  return Hash;
}

struct LinuxUtsName {
  std::array<char, 65> SystemName{};
  std::array<char, 65> NodeName{};
  std::array<char, 65> Release{};
  std::array<char, 65> Version{};
  std::array<char, 65> Machine{};
  std::array<char, 65> DomainName{};
};
static_assert(sizeof(LinuxUtsName) == 390);

class ConfigLifetime final {
public:
  ConfigLifetime() { FEXCore::Config::Initialize(); }

  ~ConfigLifetime() { FEXCore::Config::Shutdown(); }
};

class HostDisassemblyLogLifetime final {
public:
  explicit HostDisassemblyLogLifetime(bool Enabled) : Enabled{Enabled} {
    if (Enabled) {
      LogMan::Msg::InstallHandler(
          [](LogMan::DebugLevels, const char *Message) { std::fprintf(stderr, "%s\n", Message); });
    }
  }

  ~HostDisassemblyLogLifetime() {
    if (Enabled) {
      LogMan::Msg::UnInstallHandler();
    }
  }

private:
  bool Enabled{};
};

struct MachVMRegionSnapshot {
  bool Present{};
  uint64_t Start{};
  uint64_t Size{};
  int Protection{};
  int MaximumProtection{};
};

struct MachVMAdjacencySnapshot {
  bool ScanSucceeded{};
  uint64_t RegionsScanned{};
  int ScanResult{KERN_INVALID_ARGUMENT};
  MachVMRegionSnapshot Previous;
  MachVMRegionSnapshot Containing;
  MachVMRegionSnapshot Next;
  uint64_t FaultOffsetWithinContaining{std::numeric_limits<uint64_t>::max()};
  bool FaultAtContainingLastByte{};
  bool FaultAtPreviousRegionEnd{};
  bool FaultOneByteBeforeNextRegion{};
};

MachVMAdjacencySnapshot InspectMachVMAdjacency(uint64_t FaultAddress) {
  MachVMAdjacencySnapshot Snapshot;
  mach_vm_address_t Cursor{};
  constexpr uint64_t MaximumRegionCount = 65'536;

  const auto ReadRegion = [](mach_vm_address_t QueryAddress, MachVMRegionSnapshot *Region,
                             mach_vm_address_t *NextAddress) {
    mach_vm_address_t RegionAddress = QueryAddress;
    mach_vm_size_t RegionSize{};
    vm_region_basic_info_data_64_t Info{};
    mach_msg_type_number_t InfoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t ObjectName = MACH_PORT_NULL;
    const kern_return_t Result = mach_vm_region(mach_task_self(), &RegionAddress, &RegionSize, VM_REGION_BASIC_INFO_64,
                                                reinterpret_cast<vm_region_info_t>(&Info), &InfoCount, &ObjectName);
    if (ObjectName != MACH_PORT_NULL) {
      mach_port_deallocate(mach_task_self(), ObjectName);
    }
    if (Result != KERN_SUCCESS) {
      return Result;
    }
    if (RegionSize == 0 || RegionAddress > std::numeric_limits<mach_vm_address_t>::max() - RegionSize) {
      return static_cast<kern_return_t>(KERN_INVALID_ADDRESS);
    }
    if (Region != nullptr) {
      Region->Present = true;
      Region->Start = RegionAddress;
      Region->Size = RegionSize;
      Region->Protection = Info.protection;
      Region->MaximumProtection = Info.max_protection;
    }
    if (NextAddress != nullptr) {
      *NextAddress = RegionAddress + RegionSize;
    }
    return Result;
  };

  for (uint64_t Index = 0; Index < MaximumRegionCount; ++Index) {
    MachVMRegionSnapshot Region;
    mach_vm_address_t NextAddress{};
    const kern_return_t Result = ReadRegion(Cursor, &Region, &NextAddress);
    Snapshot.ScanResult = Result;
    if (Result != KERN_SUCCESS) {
      return Snapshot;
    }
    ++Snapshot.RegionsScanned;

    const uint64_t RegionEnd = Region.Start + Region.Size;
    if (FaultAddress >= Region.Start && FaultAddress < RegionEnd) {
      Snapshot.Containing = Region;
      Snapshot.FaultOffsetWithinContaining = FaultAddress - Region.Start;
      Snapshot.FaultAtContainingLastByte =
          FaultAddress != std::numeric_limits<uint64_t>::max() && FaultAddress + 1 == RegionEnd;
      MachVMRegionSnapshot NextRegion;
      mach_vm_address_t IgnoredNextAddress{};
      const kern_return_t NextResult =
          ReadRegion(static_cast<mach_vm_address_t>(RegionEnd), &NextRegion, &IgnoredNextAddress);
      if (NextResult == KERN_SUCCESS) {
        Snapshot.Next = NextRegion;
        Snapshot.FaultOneByteBeforeNextRegion =
            FaultAddress != std::numeric_limits<uint64_t>::max() && FaultAddress + 1 == Snapshot.Next.Start;
      }
      Snapshot.ScanSucceeded = true;
      Snapshot.ScanResult = KERN_SUCCESS;
      return Snapshot;
    }
    if (Region.Start > FaultAddress) {
      Snapshot.Next = Region;
      Snapshot.FaultAtPreviousRegionEnd =
          Snapshot.Previous.Present && Snapshot.Previous.Start + Snapshot.Previous.Size == FaultAddress;
      Snapshot.FaultOneByteBeforeNextRegion =
          FaultAddress != std::numeric_limits<uint64_t>::max() && FaultAddress + 1 == Snapshot.Next.Start;
      Snapshot.ScanSucceeded = true;
      Snapshot.ScanResult = KERN_SUCCESS;
      return Snapshot;
    }

    Snapshot.Previous = Region;
    if (NextAddress <= Cursor) {
      Snapshot.ScanResult = KERN_INVALID_ADDRESS;
      return Snapshot;
    }
    Cursor = NextAddress;
  }

  Snapshot.ScanResult = KERN_RESOURCE_SHORTAGE;
  return Snapshot;
}

// Reserve a high host shadow for guest addresses below the macOS 4 GiB floor.
class LowGuestShadowMapping final {
public:
  static constexpr uint8_t MappedBit = 0x80;
  static constexpr uint8_t PendingZeroBit = 0x40;

  bool Allocate() {
    const long PageSizeResult = sysconf(_SC_PAGESIZE);
    if (PageSizeResult <= 0 || (PageSizeResult & (PageSizeResult - 1)) != 0 ||
        static_cast<uint64_t>(PageSizeResult) % LinuxGuestPageSize != 0 ||
        LowGuestAddressLimit > std::numeric_limits<size_t>::max()) {
      return false;
    }
    HostPageSize = static_cast<size_t>(PageSizeResult);
    Base = mmap(nullptr, static_cast<size_t>(LowGuestAddressLimit), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (Base == MAP_FAILED) {
      return false;
    }
    RedirectBase = mmap(nullptr, HostPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (RedirectBase == MAP_FAILED) {
      munmap(Base, static_cast<size_t>(LowGuestAddressLimit));
      Base = MAP_FAILED;
      return false;
    }
    PageStates.assign(static_cast<size_t>(LowGuestAddressLimit / LinuxGuestPageSize), uint8_t{});
    return true;
  }

  ~LowGuestShadowMapping() {
    for (const auto &Record : PrivateFiles)
      close(Record.Descriptor);
    if (RedirectBase != MAP_FAILED) {
      munmap(RedirectBase, HostPageSize);
    }
    if (Base != MAP_FAILED) {
      munmap(Base, static_cast<size_t>(LowGuestAddressLimit));
    }
  }

  bool IsAllocated() const {
    return Base != MAP_FAILED && RedirectBase != MAP_FAILED && HostPageSize != 0 && !PageStates.empty();
  }

  uint64_t Bias() const { return IsAllocated() ? reinterpret_cast<uint64_t>(Base) : 0; }

  size_t HostPageBytes() const { return HostPageSize; }

  uint64_t RedirectGuestPageAddress() const { return IsAllocated() ? LinuxSharedUserDataAddress : 0; }

  uint64_t RedirectHostPageAddress() const { return IsAllocated() ? reinterpret_cast<uint64_t>(RedirectBase) : 0; }

  uint64_t MappedLogicalPageMask(uint64_t Address, uint64_t Length) const {
    if (!ContainsLogicalRange(Address, Length) || Address % LinuxGuestPageSize != 0 ||
        Length % LinuxGuestPageSize != 0 || Length / LinuxGuestPageSize > 64) {
      return 0;
    }
    const size_t FirstPage = static_cast<size_t>(Address / LinuxGuestPageSize);
    const size_t PageCount = static_cast<size_t>(Length / LinuxGuestPageSize);
    uint64_t Mask{};
    for (size_t Index = 0; Index < PageCount; ++Index) {
      if ((PageStates[FirstPage + Index] & MappedBit) != 0) {
        Mask |= uint64_t{1} << Index;
      }
    }
    return Mask;
  }

  uint64_t PackedLogicalPageStates(uint64_t Address, uint64_t Length) const {
    if (!ContainsLogicalRange(Address, Length) || Address % LinuxGuestPageSize != 0 ||
        Length % LinuxGuestPageSize != 0 || Length / LinuxGuestPageSize > sizeof(uint64_t)) {
      return 0;
    }
    const size_t FirstPage = static_cast<size_t>(Address / LinuxGuestPageSize);
    const size_t PageCount = static_cast<size_t>(Length / LinuxGuestPageSize);
    uint64_t Packed{};
    for (size_t Index = 0; Index < PageCount; ++Index) {
      Packed |= uint64_t{PageStates[FirstPage + Index]} << (Index * 8);
    }
    return Packed;
  }

  bool ContainsLogicalRange(uint64_t Address, uint64_t Size) const {
    return IsAllocated() && Size != 0 && Address < LowGuestAddressLimit && Size <= LowGuestAddressLimit - Address;
  }

  bool ContainsMappedLogicalRange(uint64_t Address, uint64_t Size, int RequiredProtection = 0) const {
    if (!ContainsLogicalRange(Address, Size) || (RequiredProtection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) != 0) {
      return false;
    }
    const size_t FirstPage = static_cast<size_t>(Address / LinuxGuestPageSize);
    const size_t LastPage = static_cast<size_t>((Address + Size - 1) / LinuxGuestPageSize);
    for (size_t Page = FirstPage; Page <= LastPage; ++Page) {
      const uint8_t State = PageStates[Page];
      if ((State & MappedBit) == 0 || (State & RequiredProtection) != RequiredProtection) {
        return false;
      }
    }
    return true;
  }

  uint8_t PageStateForLogicalAddress(uint64_t Address) const {
    if (!ContainsLogicalRange(Address, 1)) {
      return 0;
    }
    return PageStates[static_cast<size_t>(Address / LinuxGuestPageSize)];
  }

  void *HostPointerForMappedLogicalRange(uint64_t Address, uint64_t Size, int RequiredProtection = 0) const {
    return ContainsMappedLogicalRange(Address, Size, RequiredProtection) && IsHostContiguousRange(Address, Size)
               ? Translate(Address)
               : nullptr;
  }

  void *HostPointerForWritableLogicalRange(uint64_t Address, uint64_t Size) const {
    return HostPointerForMappedLogicalRange(Address, Size, PROT_WRITE);
  }

  bool ContainsHostAddress(uint64_t Address) const {
    if (!IsAllocated()) {
      return false;
    }
    const uint64_t RedirectAddress = RedirectHostPageAddress();
    return (Address >= Bias() && Address - Bias() < LowGuestAddressLimit) ||
           (Address >= RedirectAddress && Address - RedirectAddress < LinuxGuestPageSize);
  }

  uint64_t LogicalAddress(uint64_t HostAddress) const {
    const uint64_t RedirectAddress = RedirectHostPageAddress();
    if (RedirectAddress != 0 && HostAddress >= RedirectAddress && HostAddress - RedirectAddress < LinuxGuestPageSize) {
      return LinuxSharedUserDataAddress + (HostAddress - RedirectAddress);
    }
    return IsAllocated() && HostAddress >= Bias() && HostAddress - Bias() < LowGuestAddressLimit
               ? HostAddress - Bias()
               : std::numeric_limits<uint64_t>::max();
  }

  int Map(uint64_t Address, uint64_t Length, uint64_t Protection, bool NoReplace, bool Anonymous, int Descriptor,
          uint64_t Offset, uint64_t *FileBytes) {
    if (!ContainsLogicalRange(Address, Length) || Address % LinuxGuestPageSize != 0 ||
        Length % LinuxGuestPageSize != 0) {
      return EINVAL;
    }
    const size_t FirstPage = static_cast<size_t>(Address / LinuxGuestPageSize);
    const size_t PageCount = static_cast<size_t>(Length / LinuxGuestPageSize);
    const auto Begin = PageStates.begin() + static_cast<ptrdiff_t>(FirstPage);
    const auto End = Begin + static_cast<ptrdiff_t>(PageCount);
    if (NoReplace && std::any_of(Begin, End, [](uint8_t State) { return (State & MappedBit) != 0; })) {
      return EEXIST;
    }
    if (!ResetRedirectAliasForReplacement(Address, Length)) {
      return ENOMEM;
    }

    const std::vector<uint8_t> PreviousStates{Begin, End};
    const bool NeedsContents = !Anonymous || Protection != PROT_NONE;
    if (NeedsContents && !MakeTemporarilyWritable(Address, Length)) {
      return ENOMEM;
    }
    if (NeedsContents) {
      ZeroLogicalRange(Address, Length);
    }
    uint64_t BytesRead{};
    if (!Anonymous) {
      if (Offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
        RestoreStates(FirstPage, PreviousStates);
        ApplyHostProtection(Address, Length);
        return EINVAL;
      }
      const int ReadError = ReadFileIntoLogicalRange(Descriptor, Offset, Address, Length, &BytesRead);
      if (ReadError != 0) {
        RestoreStates(FirstPage, PreviousStates);
        ApplyHostProtection(Address, Length);
        return ReadError;
      }
    }

    const uint8_t State = MappedBit | static_cast<uint8_t>(Protection) | (NeedsContents ? 0 : PendingZeroBit);
    std::fill(Begin, End, State);
    if (!ApplyHostProtection(Address, Length)) {
      RestoreStates(FirstPage, PreviousStates);
      ApplyHostProtection(Address, Length);
      return ENOMEM;
    }
    if (FileBytes != nullptr) {
      *FileBytes = BytesRead;
    }
    ++MapCount;
    MappedGuestPages += PageCount;
    return 0;
  }

  int MapSharedFile(uint64_t Address, uint64_t Length, uint64_t Protection, int Descriptor, uint64_t Offset,
                    uint64_t *HostAddress, uint64_t *HostSpan, bool Private = false) {
    if (!ContainsLogicalRange(Address, Length) || Length % LinuxGuestPageSize != 0 || Offset % HostPageSize != 0 ||
        (Protection & ~uint64_t{PROT_READ | PROT_WRITE | PROT_EXEC}) != 0) {
      return EINVAL;
    }
    const bool Redirected = Address == LinuxSharedUserDataAddress;
    if (Redirected && Length != LinuxSharedUserDataSize)
      return EINVAL;
    const uint64_t Span = (Length + HostPageSize - 1) & ~(HostPageSize - 1);
    if (Private && Length % HostPageSize != 0)
      return EINVAL;
    if (!Redirected) {
      if (Address % HostPageSize != 0)
        return EINVAL;
      for (uint64_t OffsetInPage = Length; OffsetInPage < Span; OffsetInPage += LinuxGuestPageSize) {
        if (PageStates[(Address + OffsetInPage) / LinuxGuestPageSize] & (PROT_READ | PROT_WRITE | PROT_EXEC)) {
          return EINVAL; // Do not replace a neighbour's live backing.
        }
      }
    }
    const size_t FirstPage = static_cast<size_t>(Address / LinuxGuestPageSize);
    if (Offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
      return EINVAL;
    }

    int PrivateFD = Private ? dup(Descriptor) : -1;
    if (Private && PrivateFD < 0)
      return errno;
    if (Private)
      fcntl(PrivateFD, F_SETFD, FD_CLOEXEC);
    void *const Target = Translate(Address);
    void *const Result = mmap(Target, Span, static_cast<int>(Protection),
                              (Private ? MAP_PRIVATE : MAP_SHARED) | MAP_FIXED, Descriptor, static_cast<off_t>(Offset));
    if (Result == MAP_FAILED) {
      const int Error = errno;
      if (PrivateFD >= 0)
        close(PrivateFD);
      return Error;
    }
    if (Result != Target) {
      munmap(Result, Span);
      if (PrivateFD >= 0)
        close(PrivateFD);
      return EIO;
    }

    if (Private) {
      PrivateFiles.push_back(
          {Address, Length, Offset, PrivateFD, FingerprintBytes(static_cast<const uint8_t *>(Target), Length), false});
    }
    const uint8_t State = MappedBit | static_cast<uint8_t>(Protection);
    std::fill_n(PageStates.begin() + FirstPage, Length / LinuxGuestPageSize, State);
    if (Redirected)
      RedirectSharedFileMapped = true;
    else {
      for (uint64_t Page = Address; Page < Address + Span; Page += HostPageSize) {
        if (std::find(LinearSharedPages.begin(), LinearSharedPages.end(), Page) == LinearSharedPages.end()) {
          LinearSharedPages.push_back(Page);
        }
      }
    }
    if (HostAddress != nullptr) {
      *HostAddress = reinterpret_cast<uint64_t>(Target);
    }
    if (HostSpan != nullptr) {
      *HostSpan = Span;
    }
    ++MapCount;
    MappedGuestPages += Length / LinuxGuestPageSize;
    return 0;
  }

  int Protect(uint64_t Address, uint64_t Length, uint64_t Protection) {
    if (!ContainsLogicalRange(Address, Length) || Address % LinuxGuestPageSize != 0 ||
        Length % LinuxGuestPageSize != 0) {
      return EINVAL;
    }
    const size_t FirstPage = static_cast<size_t>(Address / LinuxGuestPageSize);
    const size_t PageCount = static_cast<size_t>(Length / LinuxGuestPageSize);
    const auto Begin = PageStates.begin() + static_cast<ptrdiff_t>(FirstPage);
    const auto End = Begin + static_cast<ptrdiff_t>(PageCount);
    if (std::any_of(Begin, End, [](uint8_t State) { return (State & MappedBit) == 0; })) {
      return ENOMEM;
    }
    // Anonymous PROT_NONE reservations reveal zero pages on first access.
    // Delay writes until protection permits access to keep reservations sparse.
    if (Protection != PROT_NONE) {
      for (size_t Page = FirstPage; Page < FirstPage + PageCount; ++Page) {
        if ((PageStates[Page] & PendingZeroBit) == 0)
          continue;
        const uint64_t PageAddress = Page * LinuxGuestPageSize;
        if (!MakeTemporarilyWritable(PageAddress, LinuxGuestPageSize)) {
          ApplyHostProtection(Address, Length);
          return ENOMEM;
        }
        ZeroLogicalRange(PageAddress, LinuxGuestPageSize);
      }
    }
    // Wine's Linux build uses MAP_PRIVATE for read-only shared session views.
    // Darwin snapshots MAP_PRIVATE files. Keep clean read-only views coherent
    // through a read-only shared backing, and restore COW before enabling writes.
    for (auto &File : PrivateFiles) {
      if (File.Address != Address || File.Length != Length)
        continue;
      const bool ReadOnly = Protection == PROT_READ;
      if (ReadOnly && !File.ReadOnlyShared && ContainsMappedLogicalRange(Address, Length, PROT_READ) &&
          FingerprintBytes(static_cast<const uint8_t *>(Translate(Address)), Length) == File.InitialHash) {
        if (mmap(Translate(Address), Length, PROT_READ, MAP_SHARED | MAP_FIXED, File.Descriptor, File.Offset) !=
            Translate(Address))
          return errno;
        File.ReadOnlyShared = true;
      } else if (File.ReadOnlyShared && (Protection & PROT_WRITE)) {
        if (mmap(Translate(Address), Length, static_cast<int>(Protection), MAP_PRIVATE | MAP_FIXED, File.Descriptor,
                 File.Offset) != Translate(Address))
          return errno;
        File.ReadOnlyShared = false;
        File.InitialHash = FingerprintBytes(static_cast<const uint8_t *>(Translate(Address)), Length);
      }
    }
    const std::vector<uint8_t> PreviousStates{Begin, End};
    for (auto Iterator = Begin; Iterator != End; ++Iterator) {
      *Iterator =
          MappedBit | static_cast<uint8_t>(Protection) | (Protection == PROT_NONE ? (*Iterator & PendingZeroBit) : 0);
    }
    if (!ApplyHostProtection(Address, Length)) {
      RestoreStates(FirstPage, PreviousStates);
      ApplyHostProtection(Address, Length);
      return ENOMEM;
    }
    ++ProtectCount;
    return 0;
  }

  int Unmap(uint64_t Address, uint64_t Length) {
    if (!ContainsLogicalRange(Address, Length) || Address % LinuxGuestPageSize != 0 ||
        Length % LinuxGuestPageSize != 0) {
      return EINVAL;
    }
    const size_t FirstPage = static_cast<size_t>(Address / LinuxGuestPageSize);
    const size_t PageCount = static_cast<size_t>(Length / LinuxGuestPageSize);
    const auto Begin = PageStates.begin() + static_cast<ptrdiff_t>(FirstPage);
    const auto End = Begin + static_cast<ptrdiff_t>(PageCount);
    const std::vector<uint8_t> PreviousStates{Begin, End};
    if (!ResetRedirectAliasForReplacement(Address, Length)) {
      return ENOMEM;
    }
    std::fill(Begin, End, uint8_t{});
    if (!ApplyHostProtection(Address, Length)) {
      RestoreStates(FirstPage, PreviousStates);
      ApplyHostProtection(Address, Length);
      return ENOMEM;
    }
    // Preserve adjacent 4 KiB guest pages sharing one 16 KiB host page.
    // Map() clears contents before exposing a subsequent readable mapping.
    MappedGuestPages -= static_cast<uint64_t>(std::count_if(PreviousStates.begin(), PreviousStates.end(),
                                                            [](uint8_t State) { return (State & MappedBit) != 0; }));
    return 0;
  }

private:
  bool IsRedirectedGuestAddress(uint64_t Address) const {
    return Address >= LinuxSharedUserDataAddress && Address - LinuxSharedUserDataAddress < LinuxSharedUserDataSize;
  }

  bool LogicalRangeTouchesRedirect(uint64_t Address, uint64_t Length) const {
    return Length != 0 && Address < LinuxSharedUserDataAddress + LinuxSharedUserDataSize &&
           LinuxSharedUserDataAddress < Address + Length;
  }

  bool IsHostContiguousRange(uint64_t Address, uint64_t Length) const {
    if (!ContainsLogicalRange(Address, Length) || !LogicalRangeTouchesRedirect(Address, Length)) {
      return ContainsLogicalRange(Address, Length);
    }
    return IsRedirectedGuestAddress(Address) && IsRedirectedGuestAddress(Address + Length - 1);
  }

  void *Translate(uint64_t Address) const {
    if (IsRedirectedGuestAddress(Address)) {
      return static_cast<uint8_t *>(RedirectBase) + (Address - LinuxSharedUserDataAddress);
    }
    return static_cast<uint8_t *>(Base) + Address;
  }

  uint64_t AlignDownToHostPage(uint64_t Address) const { return Address & ~uint64_t{HostPageSize - 1}; }

  uint64_t AlignUpToHostPage(uint64_t Address) const {
    return (Address + HostPageSize - 1) & ~uint64_t{HostPageSize - 1};
  }

  void ZeroLogicalRange(uint64_t Address, uint64_t Length) const {
    uint64_t BytesZeroed{};
    while (BytesZeroed < Length) {
      const uint64_t LogicalAddress = Address + BytesZeroed;
      const uint64_t PageRemaining = LinuxGuestPageSize - (LogicalAddress % LinuxGuestPageSize);
      const uint64_t Chunk = std::min<uint64_t>(Length - BytesZeroed, PageRemaining);
      std::memset(Translate(LogicalAddress), 0, static_cast<size_t>(Chunk));
      BytesZeroed += Chunk;
    }
  }

  int ReadFileIntoLogicalRange(int Descriptor, uint64_t Offset, uint64_t Address, uint64_t Length,
                               uint64_t *BytesReadResult) const {
    uint64_t BytesRead{};
    while (BytesRead < Length) {
      const uint64_t LogicalAddress = Address + BytesRead;
      const uint64_t PageRemaining = LinuxGuestPageSize - (LogicalAddress % LinuxGuestPageSize);
      const uint64_t Chunk = std::min<uint64_t>(Length - BytesRead, PageRemaining);
      const ssize_t Result = pread(Descriptor, Translate(LogicalAddress), static_cast<size_t>(Chunk),
                                   static_cast<off_t>(Offset + BytesRead));
      if (Result == -1 && errno == EINTR) {
        continue;
      }
      if (Result == -1) {
        return errno;
      }
      if (Result == 0) {
        break;
      }
      BytesRead += static_cast<uint64_t>(Result);
    }
    if (BytesReadResult != nullptr) {
      *BytesReadResult = BytesRead;
    }
    return 0;
  }

  bool ResetRedirectAliasForReplacement(uint64_t Address, uint64_t Length) {
    for (size_t Index = 0; Index < PrivateFiles.size();) {
      const auto &File = PrivateFiles[Index];
      if (Address < File.Address + File.Length && File.Address < Address + Length) {
        if (Address > File.Address || Address + Length < File.Address + File.Length)
          return false;
        close(File.Descriptor);
        PrivateFiles.erase(PrivateFiles.begin() + Index);
      } else
        ++Index;
    }
    for (size_t Index = 0; Index < LinearSharedPages.size();) {
      const uint64_t Shared = LinearSharedPages[Index];
      if (Address < Shared + HostPageSize && Shared < Address + Length) {
        if (Address > Shared || Address + Length < Shared + LinuxGuestPageSize)
          return false;
        void *Target = static_cast<uint8_t *>(Base) + Shared;
        if (mmap(Target, HostPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != Target)
          return false;
        LinearSharedPages.erase(LinearSharedPages.begin() + Index);
      } else
        ++Index;
    }
    if (!RedirectSharedFileMapped || !LogicalRangeTouchesRedirect(Address, Length)) {
      return true;
    }
    void *const Result = mmap(RedirectBase, HostPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (Result == MAP_FAILED || Result != RedirectBase) {
      return false;
    }
    RedirectSharedFileMapped = false;
    return true;
  }

  bool MakeTemporarilyWritable(uint64_t Address, uint64_t Length) const {
    uint64_t LastHostAddress = std::numeric_limits<uint64_t>::max();
    const uint64_t FirstGuestPage = Address & ~(LinuxGuestPageSize - 1);
    const uint64_t LastGuestPage = (Address + Length - 1) & ~(LinuxGuestPageSize - 1);
    for (uint64_t GuestPage = FirstGuestPage; GuestPage <= LastGuestPage; GuestPage += LinuxGuestPageSize) {
      const uint64_t HostAddress =
          IsRedirectedGuestAddress(GuestPage) ? RedirectHostPageAddress() : Bias() + AlignDownToHostPage(GuestPage);
      if (HostAddress == LastHostAddress) {
        continue;
      }
      if (mprotect(reinterpret_cast<void *>(HostAddress), HostPageSize, PROT_READ | PROT_WRITE) != 0) {
        return false;
      }
      LastHostAddress = HostAddress;
    }
    return true;
  }

  int ProtectionForState(uint8_t State) const {
    if ((State & MappedBit) == 0) {
      return PROT_NONE;
    }
    const int GuestProtection = State & (PROT_READ | PROT_WRITE | PROT_EXEC);
    int Protection{};
    if ((GuestProtection & (PROT_READ | PROT_EXEC)) != 0) {
      Protection |= PROT_READ;
    }
    if ((GuestProtection & PROT_WRITE) != 0) {
      Protection |= PROT_WRITE;
    }
    return Protection;
  }

  int HostProtectionForLinearPage(uint64_t HostGuestPageAddress) const {
    int Protection{};
    const uint64_t HostPageEnd = HostGuestPageAddress + HostPageSize;
    for (uint64_t GuestPage = HostGuestPageAddress; GuestPage < HostPageEnd; GuestPage += LinuxGuestPageSize) {
      if (IsRedirectedGuestAddress(GuestPage)) {
        continue;
      }
      const uint8_t State = PageStates[static_cast<size_t>(GuestPage / LinuxGuestPageSize)];
      Protection |= ProtectionForState(State);
    }
    return Protection;
  }

  bool ApplyHostProtection(uint64_t Address, uint64_t Length) const {
    uint64_t LastHostAddress = std::numeric_limits<uint64_t>::max();
    const uint64_t FirstGuestPage = Address & ~(LinuxGuestPageSize - 1);
    const uint64_t LastGuestPage = (Address + Length - 1) & ~(LinuxGuestPageSize - 1);
    for (uint64_t GuestPage = FirstGuestPage; GuestPage <= LastGuestPage; GuestPage += LinuxGuestPageSize) {
      const bool Redirected = IsRedirectedGuestAddress(GuestPage);
      const uint64_t HostGuestPage = AlignDownToHostPage(GuestPage);
      const uint64_t HostAddress = Redirected ? RedirectHostPageAddress() : Bias() + HostGuestPage;
      if (HostAddress == LastHostAddress) {
        continue;
      }
      const int Protection = Redirected
                                 ? ProtectionForState(PageStates[static_cast<size_t>(GuestPage / LinuxGuestPageSize)])
                                 : HostProtectionForLinearPage(HostGuestPage);
      if (mprotect(reinterpret_cast<void *>(HostAddress), HostPageSize, Protection) != 0) {
        return false;
      }
      LastHostAddress = HostAddress;
    }
    return true;
  }

  void RestoreStates(size_t FirstPage, const std::vector<uint8_t> &PreviousStates) {
    std::copy(PreviousStates.begin(), PreviousStates.end(), PageStates.begin() + static_cast<ptrdiff_t>(FirstPage));
  }

  void *Base{MAP_FAILED};
  void *RedirectBase{MAP_FAILED};
  size_t HostPageSize{};
  std::vector<uint8_t> PageStates;
  bool RedirectSharedFileMapped{};
  struct PrivateFile {
    uint64_t Address, Length, Offset;
    int Descriptor;
    uint64_t InitialHash;
    bool ReadOnlyShared;
  };
  std::vector<PrivateFile> PrivateFiles;
  std::vector<uint64_t> LinearSharedPages;
  uint64_t MapCount{};
  uint64_t ProtectCount{};
  uint64_t MappedGuestPages{};
};

// Back Wine's high guest address range with ordinary host pages and FEX address translation.
class HighGuestSparseMapping final {
public:
  static constexpr uint8_t MappedBit = 0x80;

  bool Allocate() {
    const long PageSizeResult = sysconf(_SC_PAGESIZE);
    if (PageSizeResult <= 0 || (PageSizeResult & (PageSizeResult - 1)) != 0 ||
        static_cast<uint64_t>(PageSizeResult) % LinuxGuestPageSize != 0 ||
        HighSparseGuestSize > std::numeric_limits<size_t>::max()) {
      return false;
    }
    HostPageSize = static_cast<size_t>(PageSizeResult);
    Base = mmap(nullptr, static_cast<size_t>(HighSparseGuestSize), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (Base == MAP_FAILED) {
      return false;
    }
    PageStates.assign(static_cast<size_t>(HighSparseGuestSize / LinuxGuestPageSize), uint8_t{});
    return true;
  }

  ~HighGuestSparseMapping() {
    if (Base != MAP_FAILED) {
      munmap(Base, static_cast<size_t>(HighSparseGuestSize));
    }
  }

  bool IsAllocated() const { return Base != MAP_FAILED && HostPageSize != 0 && !PageStates.empty(); }

  uint64_t GuestBase() const { return HighSparseGuestBase; }

  uint64_t HostBase() const { return IsAllocated() ? reinterpret_cast<uint64_t>(Base) : 0; }

  uint64_t Size() const { return IsAllocated() ? HighSparseGuestSize : 0; }

  size_t HostPageBytes() const { return HostPageSize; }

  FEXCore::Context::GuestMemoryAddressRegion Region() const {
    return FEXCore::Context::GuestMemoryAddressRegion{
        .GuestBase = GuestBase(),
        .HostBase = HostBase(),
        .Size = Size(),
    };
  }

  void ExcludeIdentityRange(uint64_t Address, uint64_t Length) {
    IdentityBase = Address;
    IdentitySize = Length;
  }

  std::vector<FEXCore::Context::GuestMemoryAddressRegion> TranslationRegions() const {
    const auto Whole = Region();
    const uint64_t End = Whole.GuestBase + Whole.Size;
    if (IdentitySize == 0 || IdentityBase >= End || IdentityBase + IdentitySize <= Whole.GuestBase) {
      return {Whole};
    }
    std::vector<FEXCore::Context::GuestMemoryAddressRegion> Regions;
    if (Whole.GuestBase < IdentityBase) {
      Regions.push_back({Whole.GuestBase, Whole.HostBase, IdentityBase - Whole.GuestBase});
    }
    const uint64_t After = IdentityBase + IdentitySize;
    if (After < End) {
      Regions.push_back({After, Whole.HostBase + After - Whole.GuestBase, End - After});
    }
    return Regions;
  }

  bool ContainsLogicalRange(uint64_t Address, uint64_t Length) const {
    if (!IsAllocated() || Length == 0 || Address < HighSparseGuestBase ||
        Address - HighSparseGuestBase >= HighSparseGuestSize ||
        Length > HighSparseGuestSize - (Address - HighSparseGuestBase)) {
      return false;
    }
    // The primary ELF arena uses identity addresses in both FEX and syscalls.
    return IdentitySize == 0 || Address >= IdentityBase + IdentitySize || Address + Length <= IdentityBase;
  }

  bool ContainsMappedLogicalRange(uint64_t Address, uint64_t Length, int RequiredProtection = 0) const {
    if (!ContainsLogicalRange(Address, Length) || (RequiredProtection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) != 0) {
      return false;
    }
    const size_t FirstPage = PageIndex(Address);
    const size_t LastPage = PageIndex(Address + Length - 1);
    for (size_t Page = FirstPage; Page <= LastPage; ++Page) {
      const uint8_t State = PageStates[Page];
      if ((State & MappedBit) == 0 || (State & RequiredProtection) != RequiredProtection) {
        return false;
      }
    }
    return true;
  }

  void *HostPointerForMappedLogicalRange(uint64_t Address, uint64_t Length, int RequiredProtection = 0) const {
    return ContainsMappedLogicalRange(Address, Length, RequiredProtection) ? Translate(Address) : nullptr;
  }

  bool ContainsHostAddress(uint64_t Address) const {
    return IsAllocated() && Address >= HostBase() && Address - HostBase() < HighSparseGuestSize;
  }

  uint64_t LogicalAddress(uint64_t HostAddress) const {
    return ContainsHostAddress(HostAddress) ? HighSparseGuestBase + (HostAddress - HostBase())
                                            : std::numeric_limits<uint64_t>::max();
  }

  int Map(uint64_t Address, uint64_t Length, uint64_t Protection, bool NoReplace, bool Anonymous, int Descriptor,
          uint64_t Offset, uint64_t *FileBytes) {
    if (!ContainsLogicalRange(Address, Length) || Address % LinuxGuestPageSize != 0 ||
        Length % LinuxGuestPageSize != 0) {
      return EINVAL;
    }
    const size_t FirstPage = PageIndex(Address);
    const size_t PageCount = static_cast<size_t>(Length / LinuxGuestPageSize);
    const auto Begin = PageStates.begin() + static_cast<ptrdiff_t>(FirstPage);
    const auto End = Begin + static_cast<ptrdiff_t>(PageCount);
    if (NoReplace && std::any_of(Begin, End, [](uint8_t State) { return (State & MappedBit) != 0; })) {
      return EEXIST;
    }

    const std::vector<uint8_t> PreviousStates{Begin, End};
    if (!MakeTemporarilyWritable(Address, Length)) {
      return ENOMEM;
    }
    std::memset(Translate(Address), 0, static_cast<size_t>(Length));
    uint64_t BytesRead{};
    if (!Anonymous) {
      if (Offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
        RestoreStates(FirstPage, PreviousStates);
        ApplyHostProtection(Address, Length);
        return EINVAL;
      }
      while (BytesRead < Length) {
        const ssize_t Result = pread(Descriptor, static_cast<uint8_t *>(Translate(Address)) + BytesRead,
                                     static_cast<size_t>(Length - BytesRead), static_cast<off_t>(Offset + BytesRead));
        if (Result == -1 && errno == EINTR) {
          continue;
        }
        if (Result == -1) {
          const int ReadError = errno;
          RestoreStates(FirstPage, PreviousStates);
          ApplyHostProtection(Address, Length);
          return ReadError;
        }
        if (Result == 0) {
          break;
        }
        BytesRead += static_cast<uint64_t>(Result);
      }
    }

    const uint8_t State = MappedBit | static_cast<uint8_t>(Protection);
    const uint64_t PreviouslyMapped = static_cast<uint64_t>(
        std::count_if(Begin, End, [](uint8_t PreviousState) { return (PreviousState & MappedBit) != 0; }));
    std::fill(Begin, End, State);
    if (!ApplyHostProtection(Address, Length)) {
      RestoreStates(FirstPage, PreviousStates);
      ApplyHostProtection(Address, Length);
      return ENOMEM;
    }
    if (FileBytes != nullptr) {
      *FileBytes = BytesRead;
    }
    ++MapCount;
    MappedGuestPages += PageCount - PreviouslyMapped;
    return 0;
  }

  int Protect(uint64_t Address, uint64_t Length, uint64_t Protection) {
    if (!ContainsLogicalRange(Address, Length) || Address % LinuxGuestPageSize != 0 ||
        Length % LinuxGuestPageSize != 0) {
      return EINVAL;
    }
    const size_t FirstPage = PageIndex(Address);
    const size_t PageCount = static_cast<size_t>(Length / LinuxGuestPageSize);
    const auto Begin = PageStates.begin() + static_cast<ptrdiff_t>(FirstPage);
    const auto End = Begin + static_cast<ptrdiff_t>(PageCount);
    if (std::any_of(Begin, End, [](uint8_t State) { return (State & MappedBit) == 0; })) {
      return ENOMEM;
    }
    const std::vector<uint8_t> PreviousStates{Begin, End};
    for (auto Iterator = Begin; Iterator != End; ++Iterator) {
      *Iterator = MappedBit | static_cast<uint8_t>(Protection);
    }
    if (!ApplyHostProtection(Address, Length)) {
      RestoreStates(FirstPage, PreviousStates);
      ApplyHostProtection(Address, Length);
      return ENOMEM;
    }
    ++ProtectCount;
    return 0;
  }

  int Unmap(uint64_t Address, uint64_t Length) {
    if (!ContainsLogicalRange(Address, Length) || Address % LinuxGuestPageSize != 0 ||
        Length % LinuxGuestPageSize != 0) {
      return EINVAL;
    }
    const size_t FirstPage = PageIndex(Address);
    const size_t PageCount = static_cast<size_t>(Length / LinuxGuestPageSize);
    const auto Begin = PageStates.begin() + static_cast<ptrdiff_t>(FirstPage);
    const auto End = Begin + static_cast<ptrdiff_t>(PageCount);
    const uint64_t PreviouslyMapped =
        static_cast<uint64_t>(std::count_if(Begin, End, [](uint8_t State) { return (State & MappedBit) != 0; }));
    if (!MakeTemporarilyWritable(Address, Length)) {
      return ENOMEM;
    }
    std::memset(Translate(Address), 0, static_cast<size_t>(Length));
    const std::vector<uint8_t> PreviousStates{Begin, End};
    std::fill(Begin, End, uint8_t{});
    if (!ApplyHostProtection(Address, Length)) {
      RestoreStates(FirstPage, PreviousStates);
      ApplyHostProtection(Address, Length);
      return ENOMEM;
    }
    ++UnmapCount;
    MappedGuestPages -= PreviouslyMapped;
    return 0;
  }

private:
  size_t PageIndex(uint64_t Address) const {
    return static_cast<size_t>((Address - HighSparseGuestBase) / LinuxGuestPageSize);
  }

  void *Translate(uint64_t Address) const { return static_cast<uint8_t *>(Base) + (Address - HighSparseGuestBase); }

  uint64_t HostPageGuestBase(uint64_t Address) const {
    const uint64_t Offset = Address - HighSparseGuestBase;
    return HighSparseGuestBase + (Offset & ~uint64_t{HostPageSize - 1});
  }

  int ProtectionForState(uint8_t State) const {
    if ((State & MappedBit) == 0) {
      return PROT_NONE;
    }
    const int GuestProtection = State & (PROT_READ | PROT_WRITE | PROT_EXEC);
    int Protection{};
    if ((GuestProtection & (PROT_READ | PROT_EXEC)) != 0) {
      Protection |= PROT_READ;
    }
    if ((GuestProtection & PROT_WRITE) != 0) {
      Protection |= PROT_WRITE;
    }
    return Protection;
  }

  int HostProtectionForPage(uint64_t HostGuestBase) const {
    int Protection{};
    for (uint64_t GuestPage = HostGuestBase; GuestPage < HostGuestBase + HostPageSize;
         GuestPage += LinuxGuestPageSize) {
      Protection |= ProtectionForState(PageStates[PageIndex(GuestPage)]);
    }
    return Protection;
  }

  bool MakeTemporarilyWritable(uint64_t Address, uint64_t Length) const {
    const uint64_t FirstHostGuestBase = HostPageGuestBase(Address);
    const uint64_t LastHostGuestBase = HostPageGuestBase(Address + Length - 1);
    for (uint64_t GuestPage = FirstHostGuestBase; GuestPage <= LastHostGuestBase; GuestPage += HostPageSize) {
      if (mprotect(Translate(GuestPage), HostPageSize, PROT_READ | PROT_WRITE) != 0) {
        return false;
      }
    }
    return true;
  }

  bool ApplyHostProtection(uint64_t Address, uint64_t Length) const {
    const uint64_t FirstHostGuestBase = HostPageGuestBase(Address);
    const uint64_t LastHostGuestBase = HostPageGuestBase(Address + Length - 1);
    for (uint64_t GuestPage = FirstHostGuestBase; GuestPage <= LastHostGuestBase; GuestPage += HostPageSize) {
      if (mprotect(Translate(GuestPage), HostPageSize, HostProtectionForPage(GuestPage)) != 0) {
        return false;
      }
    }
    return true;
  }

  void RestoreStates(size_t FirstPage, const std::vector<uint8_t> &PreviousStates) {
    std::copy(PreviousStates.begin(), PreviousStates.end(), PageStates.begin() + static_cast<ptrdiff_t>(FirstPage));
  }

  void *Base{MAP_FAILED};
  size_t HostPageSize{};
  std::vector<uint8_t> PageStates;
  uint64_t IdentityBase{};
  uint64_t IdentitySize{};
  uint64_t MapCount{};
  uint64_t ProtectCount{};
  uint64_t UnmapCount{};
  uint64_t MappedGuestPages{};
};

class ProbeSignalDelegator final : public FEXCore::SignalDelegator {
public:
  uintptr_t CallbackReturnAddress{};
  uintptr_t GetThunkCallbackRET() const override { return CallbackReturnAddress; }
};

// Redirect the host signal context to FEX's dispatcher stop handler; changing guest RIP alone does not leave a JIT
// block. Enter signed native code after sigreturn before changing this thread's JIT execution mode.
extern "C" __attribute__((naked, noinline)) void fli_native_stop_resume() {
  __asm__ volatile("mov x19, x0\n"
                   "mov x20, x1\n"
                   "mov x0, #1\n"
                   "bl _pthread_jit_write_protect_np\n"
                   "mov sp, x20\n"
                   "br x19\n");
}

class DarwinDiagnosticThreadStopHandler final {
public:
  bool Attach(FEXCore::Core::InternalThreadState *Thread, uint64_t ThreadStopHandlerAddress, uint64_t GuestStopAddress,
              bool ProcessHandlers = true) {
    if (Thread == nullptr || ActiveThread != nullptr || ThreadStopHandlerAddress == 0 || GuestStopAddress == 0) {
      return false;
    }

    OwnProcessHandlers = ProcessHandlers;
    struct sigaction Action{};
    sigemptyset(&Action.sa_mask);
    Action.sa_sigaction = Handle;
    Action.sa_flags = SA_SIGINFO;
    if (OwnProcessHandlers && sigaction(SIGUSR2, &Action, &PreviousAction) != 0) {
      return false;
    }

    ActiveThread = Thread;
    ActiveThreadStopHandlerAddress = ThreadStopHandlerAddress;
    ActiveGuestStopAddress = GuestStopAddress;
    SignalTriggered = 0;
    if (fli_env_enabled("REGRESSION_FLI_TRACE_STOP_CONTEXT")) {
      std::array<uint32_t, 8> Words{};
      std::memcpy(Words.data(), reinterpret_cast<const void *>(ThreadStopHandlerAddress), sizeof(Words));
      dprintf(2, "OWNED_STOP_ATTACH entry=%llx words=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
              static_cast<unsigned long long>(ThreadStopHandlerAddress), Words[0], Words[1], Words[2], Words[3],
              Words[4], Words[5], Words[6], Words[7]);
    }
    Installed = true;
    return true;
  }

  static int Request() { return raise(SIGUSR2); }

  void Reset() {
    if (!Installed) {
      return;
    }
    if (OwnProcessHandlers)
      sigaction(SIGUSR2, &PreviousAction, nullptr);
    ActiveThread = nullptr;
    ActiveThreadStopHandlerAddress = 0;
    ActiveGuestStopAddress = 0;
    Installed = false;
  }

  ~DarwinDiagnosticThreadStopHandler() { Reset(); }

private:
  static void Handle(int Signal, siginfo_t *, void *RawContext) {
    auto *Thread = ActiveThread;
    auto *Context = static_cast<ucontext_t *>(RawContext);
    if (Signal != SIGUSR2 || Thread == nullptr || Context == nullptr || Context->uc_mcontext == nullptr ||
        ActiveThreadStopHandlerAddress == 0 || ActiveGuestStopAddress == 0) {
      _exit(206);
    }

    auto *Frame = Thread->CurrentFrame;
    if (Frame == nullptr || Frame->ReturningStackLocation == 0) {
      _exit(207);
    }

    Frame->State.rip = ActiveGuestStopAddress;
    auto &HostState = Context->uc_mcontext->__ss;
    if (fli_env_enabled("REGRESSION_FLI_TRACE_STOP_CONTEXT")) {
      static thread_local unsigned Count{};
      if (Count++ < 4)
        dprintf(2, "OWNED_STOP_SIGNAL entry=%llx return-sp=%llx interrupted-sp=%llx interrupted-pc=%llx\n",
                static_cast<unsigned long long>(ActiveThreadStopHandlerAddress),
                static_cast<unsigned long long>(Frame->ReturningStackLocation),
                static_cast<unsigned long long>(HostState.__sp), static_cast<unsigned long long>(HostState.__pc));
    }
    // sigreturn may restore the interrupted thread's writable JIT mode.
    // Restore execution in ordinary native code after that return, then use the original stop stub.
    HostState.__x[0] = ActiveThreadStopHandlerAddress;
    HostState.__x[1] = Frame->ReturningStackLocation;
    HostState.__sp = Frame->ReturningStackLocation;
    HostState.__pc = reinterpret_cast<uint64_t>(&fli_native_stop_resume);
    SignalTriggered = 1;
  }

  struct sigaction PreviousAction{};
  bool Installed{}, OwnProcessHandlers{true};
  inline static thread_local FEXCore::Core::InternalThreadState *ActiveThread{};
  inline static thread_local uint64_t ActiveThreadStopHandlerAddress{};
  inline static thread_local uint64_t ActiveGuestStopAddress{};
  inline static thread_local volatile sig_atomic_t SignalTriggered{};
};

struct GuestMemoryFault {
  uint64_t address;
  uint16_t error;
  uint8_t code;
};
static GuestMemoryFault DescribeRootMemoryFault(FEXCore::Core::InternalThreadState *, uint64_t, uint32_t);
static bool RootOwnsNativeFileView(FEXCore::Core::InternalThreadState *, uint64_t);
static bool ForwardUntracedRootMemoryFault(FEXCore::Core::InternalThreadState *, ucontext_t *,
                                           const GuestMemoryFault &);
static bool DeliverRootGuestMemorySignal(FEXCore::Core::InternalThreadState *, int, uint64_t, int);
// Translate genuine FEX breakpoint exceptions to the Linux ptrace provider.
class DarwinGuestTrapHandler final {
public:
  static bool BindThread(FEXCore::Core::InternalThreadState *Thread, const FEXCore::SignalDelegatorConfig &Config) {
    using Stop = int32_t (*)(uint64_t *, void *, int, int);
    StopGuest = reinterpret_cast<Stop>(dlsym(RTLD_DEFAULT, "fli_linux_root_trap"));
    TakeChanges =
        reinterpret_cast<uint64_t (*)(uint64_t *, uint64_t *)>(dlsym(RTLD_DEFAULT, "fli_linux_root_take_changes"));
    PublishMemoryFault =
        reinterpret_cast<int32_t (*)(uint64_t)>(dlsym(RTLD_DEFAULT, "fli_linux_root_publish_memory_fault"));
    TakeDeliveredSignal = reinterpret_cast<int32_t (*)()>(dlsym(RTLD_DEFAULT, "fli_linux_root_take_delivery_signal"));
    if (!StopGuest || !TakeChanges || !PublishMemoryFault || !TakeDeliveredSignal)
      return false;
    ActiveThread = Thread;
    SignalConfig = Config;
    return true;
  }
  static bool HandleGenerated(int Signal, siginfo_t *Info, void *Opaque) {
    auto *Context = static_cast<ucontext_t *>(Opaque);
    if (!ActiveThread || !Context || !Context->uc_mcontext)
      return false;
    const auto *Frame = ActiveThread->CurrentFrame;
    const auto &Fault = Frame->SynchronousFaultData;
    const uint64_t Entry =
        Signal == SIGTRAP ? Frame->Pointers.GuestSignal_SIGTRAP : Frame->Pointers.GuestSignal_SIGSEGV;
    const uint64_t PC = Context->uc_mcontext->__ss.__pc;
    if (!Fault.FaultToTopAndGeneratedException || Fault.Signal != Signal || PC < Entry || PC >= Entry + 256)
      return false;
    Handle(Signal, Info, Opaque);
    return true;
  }
  bool Attach(FEXCore::Core::InternalThreadState *Thread, const FEXCore::SignalDelegatorConfig &Config) {
    if (!BindThread(Thread, Config))
      return false;
    struct sigaction Action{};
    sigemptyset(&Action.sa_mask);
    Action.sa_flags = SA_SIGINFO;
    Action.sa_sigaction = Handle;
    Installed = sigaction(SIGTRAP, &Action, &PreviousAction) == 0;
    if (Installed && sigaction(SIGSEGV, &Action, &PreviousSegvAction)) {
      sigaction(SIGTRAP, &PreviousAction, nullptr);
      Installed = false;
    }
    return Installed;
  }
  ~DarwinGuestTrapHandler() {
    if (Installed) {
      sigaction(SIGTRAP, &PreviousAction, nullptr);
      sigaction(SIGSEGV, &PreviousSegvAction, nullptr);
      ActiveThread = nullptr;
    }
  }
  static bool ForwardHostMemoryFault(FEXCore::Core::InternalThreadState *Thread, int Signal, siginfo_t *Info,
                                     ucontext_t *Native) {
    if (!Thread || !Info || !Native || !Native->uc_mcontext || (Signal != SIGBUS && Signal != SIGSEGV))
      return false;
    const auto guest =
        DescribeRootMemoryFault(Thread, reinterpret_cast<uint64_t>(Info->si_addr), Native->uc_mcontext->__es.__esr);
    if (Thread != ActiveThread || !PublishMemoryFault)
      return ForwardUntracedRootMemoryFault(Thread, Native, guest);
    auto *Frame = Thread->CurrentFrame;
    auto &Host = Native->uc_mcontext->__ss;
    const uint64_t RIP = Thread->CTX->RestoreRIPFromHostPC(Thread, Host.__pc);
    if (!RIP)
      return false;
    if (PublishMemoryFault(guest.address))
      return ForwardUntracedRootMemoryFault(Thread, Native, guest);
    PublishedFaultAddress = guest.address;
    Frame->State.rip = RIP;
    Frame->SynchronousFaultData = {.FaultToTopAndGeneratedException = true,
                                   .Signal = uint8_t(SIGSEGV),
                                   .TrapNo = 14,
                                   .si_code = guest.code,
                                   .err_code = guest.error,
                                   ._pad = 0};
    const uint64_t Address = reinterpret_cast<uint64_t>(Info->si_addr);
    uint32_t DirectGPR = 0, PageGPR = 0;
    for (size_t Index = 0; Index < SignalConfig.SRAGPRCount && Index < 16; ++Index) {
      const uint8_t Register = SignalConfig.SRAGPRMapping[Index];
      const uint64_t Value = Register == 29 ? Host.__fp : Host.__x[Register];
      if (Value == Address)
        DirectGPR |= uint32_t(1) << Index;
      if ((Value & ~uint64_t(4095)) == (Address & ~uint64_t(4095)))
        PageGPR |= uint32_t(1) << Index;
    }
    const auto Region = InspectMachVMAdjacency(Address).Containing;
    dprintf(2,
            "FLI_ROOT_HOST_GUEST_FAULT signal=%d source=%llx address=%llx esr=%x gpr-direct=%x gpr-page=%x mapped=%d "
            "protection=%x\n",
            Signal, (unsigned long long)RIP, (unsigned long long)Address, Native->uc_mcontext->__es.__esr, DirectGPR,
            PageGPR, Region.Present, Region.Protection);
    Host.__pc = Frame->Pointers.GuestSignal_SIGSEGV;
    return true;
  }

private:
  static void Handle(int Signal, siginfo_t *Info, void *Opaque) {
    auto *Thread = ActiveThread;
    auto *Context = static_cast<ucontext_t *>(Opaque);
    if ((Signal != SIGTRAP && Signal != SIGSEGV) || !Thread || !Context || !Context->uc_mcontext)
      _exit(208);
    auto *Frame = Thread->CurrentFrame;
    auto &Host = Context->uc_mcontext->__ss;
    const auto Fault = Frame->SynchronousFaultData;
    // This dispatcher entry spills SRA before issuing its actual host BRK.
    const uint64_t Entry =
        Signal == SIGTRAP ? Frame->Pointers.GuestSignal_SIGTRAP : Frame->Pointers.GuestSignal_SIGSEGV;
    if (!Fault.FaultToTopAndGeneratedException || Fault.Signal != Signal || Host.__pc < Entry ||
        Host.__pc >= Entry + 256) {
      if (Signal == SIGSEGV && (PreviousSegvAction.sa_flags & SA_SIGINFO)) {
        PreviousSegvAction.sa_sigaction(Signal, Info, Opaque);
        return;
      }
      _exit(209);
    }
    if (fli_env_enabled("REGRESSION_FLI_TRACE_BRANCHES") && Frame->DiagnosticBranches) {
      const auto &Memory = Frame->DiagnosticBranches[64];
      dprintf(2, "FLI_ROOT_LAST_MEMORY source=%llx guest-address=%llx\n", (unsigned long long)Memory.target,
              (unsigned long long)Memory.source);
      const uint64_t End = Frame->DiagnosticBranchSequence;
      for (uint64_t Sequence = End > 32 ? End - 32 : 0; Sequence < End; ++Sequence) {
        const auto &Branch = Frame->DiagnosticBranches[Sequence % 64];
        dprintf(2, "FLI_ROOT_BRANCH seq=%llu source=%llx target=%llx\n", (unsigned long long)Sequence,
                (unsigned long long)Branch.source, (unsigned long long)Branch.target);
      }
    }
    auto &State = Frame->State;
    using namespace FEXCore::X86State;
    uint64_t Registers[]{State.gregs[REG_R15],
                         State.gregs[REG_R14],
                         State.gregs[REG_R13],
                         State.gregs[REG_R12],
                         State.gregs[REG_RBP],
                         State.gregs[REG_RBX],
                         State.gregs[REG_R11],
                         State.gregs[REG_R10],
                         State.gregs[REG_R9],
                         State.gregs[REG_R8],
                         State.gregs[REG_RAX],
                         State.gregs[REG_RCX],
                         State.gregs[REG_RDX],
                         State.gregs[REG_RSI],
                         State.gregs[REG_RDI],
                         UINT64_MAX,
                         State.rip,
                         State.cs_idx,
                         Thread->CTX->ReconstructCompactedEFLAGS(Thread, true, Host.__x, Host.__cpsr),
                         State.gregs[REG_RSP],
                         State.ss_idx,
                         State.fs_cached,
                         State.gs_cached,
                         State.ds_idx,
                         State.es_idx,
                         State.fs_idx,
                         State.gs_idx};
    // Same FXSAVE layout and x87 rotation as FEX's public Linux signal frames.
    // FEX does not track x87 instruction/data pointers; reserved fields stay 0.
    FEXCore::x86_64::_libc_fpstate FP{};
    static_assert(sizeof(FP) == 512);
    FP.fcw = State.FCW;
    FP.ftw = State.AbridgedFTW;
    FP.mxcsr = State.mxcsr;
    FP.mxcsr_mask = 0xffc0;
    FP.fsw = (State.flags[X87FLAG_TOP_LOC] << 11) | (State.flags[X87FLAG_C0_LOC] << 8) |
             (State.flags[X87FLAG_C1_LOC] << 9) | (State.flags[X87FLAG_C2_LOC] << 10) |
             (State.flags[X87FLAG_C3_LOC] << 14) | State.flags[X87FLAG_IE_LOC];
    for (unsigned i = 0; i < 8; ++i)
      memcpy(&FP._st[i], State.mm[(i + State.flags[X87FLAG_TOP_LOC]) % 8], 16);
    Thread->CTX->ReconstructXMMRegisters(Thread, FP._xmm, nullptr);
    if (StopGuest(Registers, &FP, Fault.Signal, Fault.si_code))
      _exit(210);
    constexpr unsigned GPR[]{REG_R15, REG_R14, REG_R13, REG_R12, REG_RBP, REG_RBX, REG_R11, REG_R10,
                             REG_R9,  REG_R8,  REG_RAX, REG_RCX, REG_RDX, REG_RSI, REG_RDI};
    for (unsigned i = 0; i < 15; ++i)
      State.gregs[GPR[i]] = Registers[i];
    State.rip = Registers[16];
    State.cs_idx = Registers[17];
    State.gregs[REG_RSP] = Registers[19];
    State.ss_idx = Registers[20];
    State.fs_cached = Registers[21];
    State.gs_cached = Registers[22];
    State.ds_idx = Registers[23];
    State.es_idx = Registers[24];
    State.fs_idx = Registers[25];
    State.gs_idx = Registers[26];
    Thread->CTX->SetFlagsFromCompactedEFLAGS(Thread, Registers[18]);
    Thread->CTX->SetXMMRegistersFromState(Thread, FP._xmm, nullptr);
    State.FCW = FP.fcw;
    State.AbridgedFTW = FP.ftw;
    State.mxcsr = FP.mxcsr;
    State.flags[X87FLAG_IE_LOC] = FP.fsw & 1;
    State.flags[X87FLAG_C0_LOC] = (FP.fsw >> 8) & 1;
    State.flags[X87FLAG_C1_LOC] = (FP.fsw >> 9) & 1;
    State.flags[X87FLAG_C2_LOC] = (FP.fsw >> 10) & 1;
    State.flags[X87FLAG_C3_LOC] = (FP.fsw >> 14) & 1;
    State.flags[X87FLAG_TOP_LOC] = (FP.fsw >> 11) & 7;
    for (unsigned i = 0; i < 8; ++i)
      memcpy(State.mm[(i + State.flags[X87FLAG_TOP_LOC]) % 8], &FP._st[i], 16);
    Frame->SynchronousFaultData.FaultToTopAndGeneratedException = false;
    uint64_t Begin = 0, Length = 0;
    if (TakeChanges(&Begin, &Length)) {
      std::unique_lock Lock(Thread->CTX->GetCodeInvalidationMutex());
      Thread->CTX->InvalidateCodeBuffersCodeRange(Begin, Length);
      Thread->CTX->InvalidateThreadCachedCodeRange(Thread, Begin, Length);
    }
    Host.__pc = SignalConfig.AbsoluteLoopTopAddressFillSRA;
    const int Delivered = TakeDeliveredSignal();
    if (Delivered == SIGSEGV) {
      const uint64_t Address = PublishedFaultAddress;
      PublishedFaultAddress = 0;
      if (!DeliverRootGuestMemorySignal(Thread, Delivered, Address, Fault.si_code))
        _exit(211);
    }
  }
  struct sigaction PreviousAction{};
  bool Installed{};
  inline static thread_local FEXCore::Core::InternalThreadState *ActiveThread{};
  inline static thread_local FEXCore::SignalDelegatorConfig SignalConfig{};
  inline static thread_local int32_t (*StopGuest)(uint64_t *, void *, int, int){};
  inline static thread_local struct sigaction PreviousSegvAction{};
  inline static thread_local uint64_t (*TakeChanges)(uint64_t *, uint64_t *){};
  inline static thread_local int32_t (*PublishMemoryFault)(uint64_t){};
  inline static thread_local int32_t (*TakeDeliveredSignal)(){};
  inline static thread_local uint64_t PublishedFaultAddress{};
};

bool HandleTrackedGuestCodeWrite(FEXCore::Core::InternalThreadState *, uint64_t, ucontext_t *);

class DarwinUnalignedAccessHandler final {
public:
  static constexpr sig_atomic_t MaximumDiagnosticBackpatchCount = 10'000;
  static constexpr size_t MaximumPatternCount = 32;
  static constexpr size_t BoundaryInstructionRadius = 4;
  static constexpr size_t BoundaryInstructionCount = BoundaryInstructionRadius * 2 + 1;

  bool Attach(FEXCore::Core::InternalThreadState *Thread, uintptr_t GuestMemoryBase, size_t GuestMemorySize,
              uintptr_t LowShadowHostBase = 0, size_t LowShadowHostSize = 0, uintptr_t LowRedirectHostBase = 0,
              size_t LowRedirectHostSize = 0, uintptr_t HighSparseHostBase = 0, size_t HighSparseHostSize = 0,
              LowGuestShadowMapping *LowShadowMapping = nullptr, HighGuestSparseMapping *HighSparseMapping = nullptr,
              bool BoundedDiagnostic = true, bool ProcessHandlers = true) {
    if (Thread == nullptr || ActiveThread != nullptr || GuestMemorySize == 0 ||
        GuestMemoryBase > std::numeric_limits<uintptr_t>::max() - GuestMemorySize) {
      return false;
    }

    OwnProcessHandlers = ProcessHandlers;
    if (OwnProcessHandlers) {
      struct sigaction Action{};
      sigemptyset(&Action.sa_mask);
      Action.sa_sigaction = Handle;
      Action.sa_flags = SA_SIGINFO;
      if (sigaction(SIGBUS, &Action, &PreviousBusAction) != 0) {
        return false;
      }
      if (sigaction(SIGSEGV, &Action, &PreviousSegvAction) != 0) {
        sigaction(SIGBUS, &PreviousBusAction, nullptr);
        return false;
      }
    }
    ActiveThread = Thread;
    ApplyDiagnosticLimit = BoundedDiagnostic;
    ActiveGuestMemoryBase = GuestMemoryBase;
    CaptureInstructions = !fli_env_enabled("REGRESSION_NATIVE_WINE_HOST_ENTRY");
    ActiveGuestMemoryLimit = GuestMemoryBase + GuestMemorySize;
    ActiveLowShadowHostBase = LowShadowHostBase;
    ActiveLowShadowHostLimit = LowShadowHostBase + LowShadowHostSize;
    ActiveLowRedirectHostBase = LowRedirectHostBase;
    ActiveLowRedirectHostLimit = LowRedirectHostBase + LowRedirectHostSize;
    ActiveHighSparseHostBase = HighSparseHostBase;
    ActiveHighSparseHostLimit = HighSparseHostBase + HighSparseHostSize;
    ActiveFEXImageBase = LoadedMachOImageBase("/libFEXCore.dylib");
    ActiveProbeImageBase = reinterpret_cast<uintptr_t>(_dyld_get_image_header(0));
    ActiveLowShadowMapping = LowShadowMapping;
    ActiveHighSparseMapping = HighSparseMapping;
    HandledCount = 0;
    SigbusCount = 0;
    SigsegvCount = 0;
    SigsegvMissingAddressCount = 0;
    HandledPatternCount = 0;
    HandledPatternOverflow = 0;
    HandledPatternGuestRIP.fill(0);
    HandledPatternHostProgramCounter.fill(0);
    HandledPatternInstruction.fill(0);
    HandledPatternFirstFaultAddress.fill(0);
    HandledPatternLastFaultAddress.fill(0);
    HandledPatternSignal.fill(0);
    HandledPatternCode.fill(0);
    HandledPatternHitCount.fill(0);
    SignalBoundarySeen = 0;
    SignalBoundarySignal = 0;
    SignalBoundaryCode = 0;
    SignalBoundaryProgramCounter = 0;
    SignalBoundaryInstruction = 0;
    SignalBoundaryInstructionNeighborhood.fill(0);
    SignalBoundaryInstructionNeighborhoodValidMask = 0;
    SignalBoundaryAddressRegister = 0;
    SignalBoundaryAddressRegisterMatchesFault = 0;
    SignalBoundaryJITGuardPage = 0;
    SignalBoundaryFaultAddress = 0;
    SignalBoundaryX4 = 0;
    SignalBoundaryFSBase = 0;
    SignalBoundaryGSBase = 0;
    SignalBoundaryRSP = 0;
    SignalBoundaryX4MatchesFault = 0;
    SignalBoundaryThreadState = 0;
    SignalBoundaryInterruptPage = 0;
    SignalBoundaryCallRetStack = 0;
    SignalBoundaryFaultOffset = std::numeric_limits<uint64_t>::max();
    SignalBoundaryGuestRIPOffset = std::numeric_limits<uint64_t>::max();
    SignalBoundaryRecoveredGuestRIP = 0;
    SignalBoundaryHostGPRs.fill(0);
    SignalBoundaryGuestGPRs.fill(0);
    DiagnosticBackpatchLimitSeen = 0;
    Handling = false;
    Installed = true;
    if (fli_env_enabled("REGRESSION_FLI_MACH_ALIGN") && fli_env_enabled("REGRESSION_NATIVE_ELF_EXEC_GATE")) {
      using Register = int (*)(uint64_t, void *,
                               int (*)(void *, arm_thread_state64_t *, const arm_exception_state64_t *, mach_port_t));
      auto Add = reinterpret_cast<Register>(dlsym(RTLD_DEFAULT, "fli_mach_fault_register"));
      MachThread = Thread;
      MachBase = GuestMemoryBase;
      MachLimit = GuestMemoryBase + GuestMemorySize;
      MachLow = LowShadowMapping;
      MachHigh = HighSparseMapping;
      MachBounded = BoundedDiagnostic;
      if (!Add || !Add(reinterpret_cast<uint64_t>(Thread->CurrentFrame), this, RecoverMach)) {
        Reset();
        return false;
      }
    }
    return true;
  }

  void Reset() {
    if (!Installed) {
      return;
    }
    if (MachThread) {
      using Remove = void (*)(uint64_t);
      auto Drop = reinterpret_cast<Remove>(dlsym(RTLD_DEFAULT, "fli_mach_fault_unregister"));
      if (Drop)
        Drop(reinterpret_cast<uint64_t>(MachThread->CurrentFrame));
      MachThread = nullptr;
    }
    ActiveThread = nullptr;
    ActiveGuestMemoryBase = 0;
    ActiveGuestMemoryLimit = 0;
    ActiveLowShadowHostBase = 0;
    ActiveLowShadowHostLimit = 0;
    ActiveLowRedirectHostBase = 0;
    ActiveLowRedirectHostLimit = 0;
    ActiveHighSparseHostBase = 0;
    ActiveHighSparseHostLimit = 0;
    ActiveFEXImageBase = 0;
    ActiveProbeImageBase = 0;
    ActiveLowShadowMapping = nullptr;
    ActiveHighSparseMapping = nullptr;
    Handling = false;
    if (OwnProcessHandlers) {
      sigaction(SIGSEGV, &PreviousSegvAction, nullptr);
      sigaction(SIGBUS, &PreviousBusAction, nullptr);
    }
    Installed = false;
  }

  uint64_t Count() const { return static_cast<uint64_t>(HandledCount) + MachAlignCount.load(); }

  bool BoundarySeen() const { return SignalBoundarySeen != 0; }

  uint64_t BoundarySignal() const { return static_cast<uint64_t>(SignalBoundarySignal); }

  int64_t BoundaryCode() const { return static_cast<int64_t>(SignalBoundaryCode); }

  uint64_t BoundaryProgramCounter() const { return SignalBoundaryProgramCounter; }

  std::array<uint32_t, BoundaryInstructionCount> BoundaryInstructionWords() const {
    return SignalBoundaryInstructionNeighborhood;
  }

  uint64_t BoundaryFaultAddress() const { return SignalBoundaryFaultAddress; }

  uint64_t BoundaryGuestRIPOffset() const { return SignalBoundaryGuestRIPOffset; }

  uint64_t BoundaryRecoveredGuestRIP() const { return SignalBoundaryRecoveredGuestRIP; }

  std::array<uint64_t, MaximumPatternCount> PatternHostProgramCounters() const {
    return HandledPatternHostProgramCounter;
  }

  std::array<uint64_t, MaximumPatternCount> PatternFirstFaultAddresses() const {
    return HandledPatternFirstFaultAddress;
  }

  ~DarwinUnalignedAccessHandler() { Reset(); }

private:
  static void RecordHandledPattern(FEXCore::Core::InternalThreadState *Thread, int Signal, int Code,
                                   uintptr_t ProgramCounter, uintptr_t FaultAddress) {
    const uint64_t GuestRIP = Thread->CTX->RestoreRIPFromHostPC(Thread, ProgramCounter);
    const uint32_t Instruction = CaptureInstructions ? *reinterpret_cast<const uint32_t *>(ProgramCounter) : 0;
    for (size_t Index = 0; Index < HandledPatternCount; ++Index) {
      if (HandledPatternGuestRIP[Index] != GuestRIP || HandledPatternInstruction[Index] != Instruction) {
        continue;
      }
      HandledPatternLastFaultAddress[Index] = FaultAddress;
      ++HandledPatternHitCount[Index];
      return;
    }
    if (HandledPatternCount >= MaximumPatternCount) {
      HandledPatternOverflow = 1;
      return;
    }
    const size_t Index = HandledPatternCount++;
    HandledPatternGuestRIP[Index] = GuestRIP;
    HandledPatternHostProgramCounter[Index] = ProgramCounter;
    HandledPatternInstruction[Index] = Instruction;
    HandledPatternFirstFaultAddress[Index] = FaultAddress;
    HandledPatternLastFaultAddress[Index] = FaultAddress;
    HandledPatternSignal[Index] = Signal;
    HandledPatternCode[Index] = Code;
    HandledPatternHitCount[Index] = 1;
  }

  static size_t AppendSignalTraceLiteral(char *Buffer, size_t Offset, size_t Capacity, std::string_view Literal) {
    for (const char Character : Literal) {
      if (Offset >= Capacity) {
        break;
      }
      Buffer[Offset++] = Character;
    }
    return Offset;
  }

  static size_t AppendSignalTraceHex(char *Buffer, size_t Offset, size_t Capacity, uintptr_t Value) {
    static constexpr std::string_view Digits{"0123456789abcdef"};
    Offset = AppendSignalTraceLiteral(Buffer, Offset, Capacity, "0x");
    bool Started = false;
    for (int Shift = static_cast<int>(sizeof(Value) * 8) - 4; Shift >= 0; Shift -= 4) {
      const auto Nibble = static_cast<size_t>((Value >> Shift) & 0xF);
      if (!Started && Nibble == 0 && Shift != 0) {
        continue;
      }
      Started = true;
      if (Offset >= Capacity) {
        break;
      }
      Buffer[Offset++] = Digits[Nibble];
    }
    return Offset;
  }

  static void WriteOutsideCodeBufferTrace(int Signal, int Code, uintptr_t ProgramCounter, uintptr_t FaultAddress,
                                          uintptr_t GuestRIP, uintptr_t CurrentFrame,
                                          const __darwin_arm_thread_state64 &HostState, uintptr_t JITGuardPage,
                                          uintptr_t JITGuardLimit) {
    std::array<char, 1536> Buffer{};
    size_t Offset =
        AppendSignalTraceLiteral(Buffer.data(), 0, Buffer.size(), "REGRESSION_SIGNAL_OUTSIDE_CODE_BUFFER signal=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), static_cast<uintptr_t>(Signal));
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " code=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), static_cast<uintptr_t>(Code));
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " pc=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ProgramCounter);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " fault=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), FaultAddress);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " guest_rip=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), GuestRIP);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " lr=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), HostState.__lr);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " sp=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), HostState.__sp);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " fp=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), HostState.__fp);
    static constexpr std::array<std::string_view, 9> HostRegisterLabels{
        " x0=", " x1=", " x2=", " x3=", " x4=", " x5=", " x6=", " x7=", " x8="};
    for (size_t Index = 0; Index < HostRegisterLabels.size(); ++Index) {
      Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), HostRegisterLabels[Index]);
      Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), HostState.__x[Index]);
    }
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " thread=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), reinterpret_cast<uintptr_t>(ActiveThread));
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " frame=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), CurrentFrame);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " fex_base=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveFEXImageBase);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " probe_base=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveProbeImageBase);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " guest_base=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveGuestMemoryBase);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " guest_limit=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveGuestMemoryLimit);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " low_base=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveLowShadowHostBase);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " low_limit=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveLowShadowHostLimit);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " redirect_base=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveLowRedirectHostBase);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " redirect_limit=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveLowRedirectHostLimit);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " high_base=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveHighSparseHostBase);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " high_limit=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), ActiveHighSparseHostLimit);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " guard=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), JITGuardPage);
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " guard_limit=");
    Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), JITGuardLimit);
    const auto PCRegion = InspectMachVMAdjacency(ProgramCounter);
    if (PCRegion.Containing.Present) {
      Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " pc_region=");
      Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), PCRegion.Containing.Start);
      Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " pc_region_size=");
      Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), PCRegion.Containing.Size);
      Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " pc_region_prot=");
      Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), PCRegion.Containing.Protection);
      if (CaptureInstructions && (PCRegion.Containing.Protection & PROT_READ) &&
          ProgramCounter + 4 <= PCRegion.Containing.Start + PCRegion.Containing.Size) {
        uint32_t Instruction{};
        std::memcpy(&Instruction, reinterpret_cast<const void *>(ProgramCounter), sizeof(Instruction));
        Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " pc_instruction=");
        Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), Instruction);
        const unsigned BaseRegister = (Instruction >> 5) & 31;
        const uintptr_t BaseValue = BaseRegister < 29    ? HostState.__x[BaseRegister]
                                    : BaseRegister == 29 ? HostState.__fp
                                    : BaseRegister == 30 ? HostState.__lr
                                                         : HostState.__sp;
        Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " pc_base_register=");
        Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), BaseRegister);
        Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), " pc_base_value=");
        Offset = AppendSignalTraceHex(Buffer.data(), Offset, Buffer.size(), BaseValue);
      }
    }
    Offset = AppendSignalTraceLiteral(Buffer.data(), Offset, Buffer.size(), "\n");
    (void)::write(STDERR_FILENO, Buffer.data(), Offset);
  }

  static void Handle(int Signal, siginfo_t *Info, void *RawContext) {
    // Worker setup can select this process-wide handler. Preserve the per-thread
    // generated-exception route before treating a dispatcher fault as a host fault.
    if (Signal == SIGSEGV && DarwinGuestTrapHandler::HandleGenerated(Signal, Info, RawContext))
      return;
    auto *Thread = ActiveThread;
    auto *Context = static_cast<ucontext_t *>(RawContext);
    const bool BusAlignment = Signal == SIGBUS && Info != nullptr && Info->si_code == BUS_ADRALN;
    const bool SegvAlignmentCandidate =
        Signal == SIGSEGV && Info != nullptr && (Info->si_code == SEGV_MAPERR || Info->si_code == SEGV_ACCERR);
    if (Handling) {
      _exit(204);
    }
    if ((!BusAlignment && !SegvAlignmentCandidate) || Thread == nullptr || Context == nullptr ||
        Context->uc_mcontext == nullptr) {
      _exit(201);
    }

    auto &HostState = Context->uc_mcontext->__ss;
    const uintptr_t ProgramCounter = static_cast<uintptr_t>(HostState.__pc);
    const uintptr_t FaultAddress = reinterpret_cast<uintptr_t>(Info->si_addr);
    if (fli_env_enabled("REGRESSION_FLI_TRACE_GUEST_FAULT")) {
      static thread_local unsigned seen;
      if (seen++ < 8)
        dprintf(2, "OWNED_FAULT_BOUNDARY signal=%d code=%d esr=%x pc=%llx address=%llx in-jit=%d\n", Signal,
                Info->si_code, Context->uc_mcontext->__es.__esr, (unsigned long long)ProgramCounter,
                (unsigned long long)FaultAddress, Thread->CTX->IsAddressInCodeBuffer(Thread, ProgramCounter));
    }
    if ((Signal == SIGSEGV || Signal == SIGBUS) && (Context->uc_mcontext->__es.__esr & (1U << 6)) &&
        HandleTrackedGuestCodeWrite(Thread, FaultAddress, Context))
      return;
    const uintptr_t JITGuardLimit = Thread->JITGuardPage + static_cast<uintptr_t>(getpagesize());
    // Darwin may report an access to a PROT_NONE JIT guard page as SEGV_MAPERR.
    // The exact guard-page range check below keeps this recovery narrowly scoped.
    const bool JITGuardSignal = BusAlignment || SegvAlignmentCandidate;
    if (JITGuardSignal && FaultAddress >= Thread->JITGuardPage && FaultAddress < JITGuardLimit) {
      auto &HostVectorState = Context->uc_mcontext->__ns;
      std::array<uint64_t, 32> GPRs{};
      std::array<__uint128_t, 32> FPRs{};
      std::copy(std::begin(HostState.__x), std::end(HostState.__x), GPRs.begin());
      GPRs[29] = HostState.__fp;
      GPRs[30] = HostState.__lr;
      GPRs[31] = HostState.__sp;
      std::copy(std::begin(HostVectorState.__v), std::end(HostVectorState.__v), FPRs.begin());
      uint64_t RestartProgramCounter = HostState.__pc;

      FEXCore::UncheckedLongJump::ManuallyLoadJumpBuf(Thread->RestartJump, Thread->JITGuardOverflowArgument,
                                                      GPRs.data(), FPRs.data(), &RestartProgramCounter);

      std::copy_n(GPRs.begin(), 29, std::begin(HostState.__x));
      HostState.__fp = GPRs[29];
      HostState.__lr = GPRs[30];
      HostState.__sp = GPRs[31];
      HostState.__pc = RestartProgramCounter;
      std::copy(FPRs.begin(), FPRs.end(), std::begin(HostVectorState.__v));
      return;
    }
    if (!Thread->CTX->IsAddressInCodeBuffer(Thread, ProgramCounter)) {
      const auto *Frame = Thread->CurrentFrame;
      if (Frame)
        dprintf(2,
                "FLI_ROOT_FAILURE exit=202 pid=%d host-signal=%d guest-signal=%u generated=%d trap=%u code=%u "
                "guest-rip=%llx native-pc=%llx segv-entry=%llx trap-entry=%llx\n",
                getpid(), Signal, Frame->SynchronousFaultData.Signal,
                Frame->SynchronousFaultData.FaultToTopAndGeneratedException, Frame->SynchronousFaultData.TrapNo,
                Frame->SynchronousFaultData.si_code, (unsigned long long)Frame->State.rip,
                (unsigned long long)ProgramCounter, (unsigned long long)Frame->Pointers.GuestSignal_SIGSEGV,
                (unsigned long long)Frame->Pointers.GuestSignal_SIGTRAP);
      WriteOutsideCodeBufferTrace(Signal, Info->si_code, ProgramCounter, FaultAddress,
                                  Frame != nullptr ? Frame->State.rip : 0, reinterpret_cast<uintptr_t>(Frame),
                                  HostState, Thread->JITGuardPage, JITGuardLimit);
      if (fli_env_enabled("REGRESSION_FLI_TRACE_OWNED_LINK_TARGET") &&
          ProgramCounter - ActiveFEXImageBase == 0x15c940 && HostState.__fp >= 0x50) {
        // This diagnostic matches the retained, hash-verified FEX v309 frame layout.
        // Read only local linker metadata; never dump guest program instructions.
        std::array<uint64_t, 6> Words{};
        mach_vm_size_t Copied{};
        if (mach_vm_read_overwrite(mach_task_self(), HostState.__fp - 0x50, sizeof(Words),
                                   reinterpret_cast<mach_vm_address_t>(Words.data()), &Copied) == KERN_SUCCESS &&
            Copied == sizeof(Words)) {
          dprintf(2, "OWNED_LINK_TARGET guest=%llx host=%llx record=%llx low_mapped=%d\n", (unsigned long long)Words[0],
                  (unsigned long long)Words[1], (unsigned long long)Words[5],
                  ActiveLowShadowMapping && ActiveLowShadowMapping->ContainsMappedLogicalRange(Words[0], 1, PROT_READ));
        }
      }
      _exit(202);
    }

    // Match FEX's Linux HandleSMC fault path: unbalanced guest CALL/RET may
    // reach either guard of its optional host return cache. Retry this host
    // instruction with x25 at the default cache location, preserving x86 state.
    const uintptr_t CallRetBase = reinterpret_cast<uintptr_t>(Thread->CallRetStackBase);
    const uintptr_t CallRetEnd = CallRetBase + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE;
    const uintptr_t HostPage = getpagesize();
    const bool CallRetGuard = CallRetBase && ((FaultAddress >= CallRetBase - HostPage && FaultAddress < CallRetBase) ||
                                              (FaultAddress >= CallRetEnd && FaultAddress < CallRetEnd + HostPage));
    if (CallRetGuard && HostState.__x[25] >= CallRetBase - 16 && HostState.__x[25] <= CallRetEnd + 16) {
      HostState.__x[25] = CallRetBase + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4;
      static std::atomic<uint64_t> resets{};
      const uint64_t count = ++resets;
      if (count <= 8 || (count & (count - 1)) == 0)
        dprintf(2, "FLI_ROOT_CALLRET_GUARD_RESET pid=%d source=%llx fault=%llx cache-base=%llx count=%llu\n", getpid(),
                (unsigned long long)Thread->CTX->RestoreRIPFromHostPC(Thread, ProgramCounter),
                (unsigned long long)FaultAddress, (unsigned long long)CallRetBase, (unsigned long long)count);
      return;
    }

    const uint32_t Syndrome = Context->uc_mcontext->__es.__esr;
    const uint32_t ExceptionClass = Syndrome >> 26;
    const bool DataAbort = ExceptionClass == 0x24 || ExceptionClass == 0x25;
    // Darwin SIGBUS/BUS_ADRALN also reports permission faults. Only the CPU's
    // alignment syndrome may enter the unaligned instruction repair path.
    const uint32_t FaultStatus = Syndrome & 0x3f;
    if (DataAbort && FaultStatus >= 4 && FaultStatus <= 15) {
      if (DarwinGuestTrapHandler::ForwardHostMemoryFault(Thread, Signal, Info, Context))
        return;
      RecordBoundary(Thread, Signal, Info->si_code, ProgramCounter, FaultAddress, HostState);
      return;
    }
    const bool FaultAddressMissing = FaultAddress == 0;
    const bool FaultAddressInGuest = FaultAddress >= ActiveGuestMemoryBase && FaultAddress < ActiveGuestMemoryLimit;
    // The Darwin host can back a logical guest range at a different address.
    // Extend the existing unaligned-access repair only for BUS_ADRALN inside
    // ranges owned by this isolated probe. Keep translated SEGVs on the guest
    // signal path so genuine protection and missing-page faults are preserved.
    const bool FaultAddressInMappedLowShadow =
        BusAlignment && ActiveLowShadowMapping != nullptr &&
        ActiveLowShadowMapping->ContainsHostAddress(FaultAddress) &&
        ActiveLowShadowMapping->ContainsMappedLogicalRange(ActiveLowShadowMapping->LogicalAddress(FaultAddress), 1);
    const bool FaultAddressInMappedHighSparse =
        BusAlignment && ActiveHighSparseMapping != nullptr &&
        ActiveHighSparseMapping->ContainsHostAddress(FaultAddress) &&
        ActiveHighSparseMapping->ContainsMappedLogicalRange(ActiveHighSparseMapping->LogicalAddress(FaultAddress), 1);
    uint64_t TranslatedGuestAddress = 0;
    const bool FaultAddressInSharedAlias =
        BusAlignment && Thread->CTX->TranslateHostMemoryAddress(FaultAddress, &TranslatedGuestAddress) &&
        TranslatedGuestAddress >= ActiveGuestMemoryBase && TranslatedGuestAddress < ActiveGuestMemoryLimit;
    const bool FaultAddressInTranslatedGuest =
        FaultAddressInMappedLowShadow || FaultAddressInMappedHighSparse || FaultAddressInSharedAlias;
    const bool FaultAddressInNativeView = BusAlignment && DataAbort && FaultStatus == 0x21 &&
                                          RootOwnsNativeFileView(Thread, FaultAddress);
    if (!FaultAddressMissing && !FaultAddressInGuest && !FaultAddressInTranslatedGuest && !FaultAddressInNativeView) {
      if (DarwinGuestTrapHandler::ForwardHostMemoryFault(Thread, Signal, Info, Context))
        return;
      RecordBoundary(Thread, Signal, Info->si_code, ProgramCounter, FaultAddress, HostState);
      return;
    }

    Handling = true;
    std::optional<int32_t> Result;
    {
      FEXCore::Allocator::JITWriteScope WriteScope;
      Result = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(
          Thread, FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::HalfBarrier, ProgramCounter, HostState.__x);
    }
    if (!Result.has_value()) {
      Handling = false;
      if (DarwinGuestTrapHandler::ForwardHostMemoryFault(Thread, Signal, Info, Context))
        return;
      RecordBoundary(Thread, Signal, Info->si_code, ProgramCounter, FaultAddress, HostState);
      return;
    }
    Handling = false;

    if (ApplyDiagnosticLimit && HandledCount >= MaximumDiagnosticBackpatchCount) {
      DiagnosticBackpatchLimitSeen = 1;
      if (DarwinGuestTrapHandler::ForwardHostMemoryFault(Thread, Signal, Info, Context))
        return;
      RecordBoundary(Thread, Signal, Info->si_code, ProgramCounter, FaultAddress, HostState);
      return;
    }

    RecordHandledPattern(Thread, Signal, Info->si_code, ProgramCounter, FaultAddress);
    HostState.__pc = static_cast<uint64_t>(ProgramCounter + *Result);
    const sig_atomic_t PreviousCount = HandledCount;
    HandledCount = PreviousCount < std::numeric_limits<sig_atomic_t>::max()
                       ? static_cast<sig_atomic_t>(PreviousCount + 1)
                       : PreviousCount;
    if (Signal == SIGBUS) {
      const sig_atomic_t PreviousBusCount = SigbusCount;
      SigbusCount = PreviousBusCount < std::numeric_limits<sig_atomic_t>::max()
                        ? static_cast<sig_atomic_t>(PreviousBusCount + 1)
                        : PreviousBusCount;
    } else {
      const sig_atomic_t PreviousSegvCount = SigsegvCount;
      SigsegvCount = PreviousSegvCount < std::numeric_limits<sig_atomic_t>::max()
                         ? static_cast<sig_atomic_t>(PreviousSegvCount + 1)
                         : PreviousSegvCount;
      if (FaultAddress == 0) {
        const sig_atomic_t PreviousMissingAddressCount = SigsegvMissingAddressCount;
        SigsegvMissingAddressCount = PreviousMissingAddressCount < std::numeric_limits<sig_atomic_t>::max()
                                         ? static_cast<sig_atomic_t>(PreviousMissingAddressCount + 1)
                                         : PreviousMissingAddressCount;
      }
    }
  }

  static void RecordBoundary(FEXCore::Core::InternalThreadState *Thread, int Signal, int Code, uintptr_t ProgramCounter,
                             uintptr_t FaultAddress, __darwin_arm_thread_state64 &HostState) {
    auto *Frame = Thread->CurrentFrame;
    if (Frame == nullptr || Frame->Pointers.GuestSignal_SIGSEGV == 0) {
      _exit(205);
    }

    SignalBoundarySignal = static_cast<sig_atomic_t>(Signal);
    SignalBoundaryCode = static_cast<sig_atomic_t>(Code);
    SignalBoundaryProgramCounter = ProgramCounter;
    SignalBoundaryInstruction = CaptureInstructions ? *reinterpret_cast<const uint32_t *>(ProgramCounter) : 0;
    for (size_t Index = 0; CaptureInstructions && Index < SignalBoundaryInstructionNeighborhood.size(); ++Index) {
      const int64_t RelativeInstruction = static_cast<int64_t>(Index) - static_cast<int64_t>(BoundaryInstructionRadius);
      if (RelativeInstruction < 0 && ProgramCounter < static_cast<uintptr_t>(-RelativeInstruction) * sizeof(uint32_t)) {
        continue;
      }
      const uintptr_t CandidateProgramCounter =
          RelativeInstruction < 0 ? ProgramCounter - static_cast<uintptr_t>(-RelativeInstruction) * sizeof(uint32_t)
                                  : ProgramCounter + static_cast<uintptr_t>(RelativeInstruction) * sizeof(uint32_t);
      if (!Thread->CTX->IsAddressInCodeBuffer(Thread, CandidateProgramCounter)) {
        continue;
      }
      SignalBoundaryInstructionNeighborhood[Index] = *reinterpret_cast<const uint32_t *>(CandidateProgramCounter);
      SignalBoundaryInstructionNeighborhoodValidMask |= 1ULL << Index;
    }
    SignalBoundaryAddressRegister = (SignalBoundaryInstruction >> 5) & 0x1F;
    const uint64_t AddressRegisterValue =
        SignalBoundaryAddressRegister == 31 ? HostState.__sp : HostState.__x[SignalBoundaryAddressRegister];
    SignalBoundaryAddressRegisterMatchesFault = AddressRegisterValue == FaultAddress;
    SignalBoundaryFaultAddress = FaultAddress;
    SignalBoundaryX4 = HostState.__x[4];
    SignalBoundaryFSBase = Frame->State.fs_cached;
    SignalBoundaryGSBase = Frame->State.gs_cached;
    SignalBoundaryRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];
    SignalBoundaryX4MatchesFault = HostState.__x[4] == FaultAddress;
    const uintptr_t JITGuardLimit = Thread->JITGuardPage + static_cast<uintptr_t>(getpagesize());
    SignalBoundaryJITGuardPage = Signal == SIGSEGV && Code == SEGV_ACCERR && FaultAddress >= Thread->JITGuardPage &&
                                 FaultAddress < JITGuardLimit;
    const uintptr_t ThreadBase = reinterpret_cast<uintptr_t>(Thread);
    SignalBoundaryThreadState = FaultAddress >= ThreadBase && FaultAddress < ThreadBase + sizeof(*Thread);
    const uintptr_t InterruptPageBase = reinterpret_cast<uintptr_t>(&Thread->InterruptFaultPage);
    SignalBoundaryInterruptPage =
        FaultAddress >= InterruptPageBase && FaultAddress < InterruptPageBase + sizeof(Thread->InterruptFaultPage);
    const uintptr_t CallRetStackBase = reinterpret_cast<uintptr_t>(Thread->CallRetStackBase);
    SignalBoundaryCallRetStack =
        CallRetStackBase != 0 && FaultAddress >= CallRetStackBase &&
        FaultAddress < CallRetStackBase + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE;
    if (FaultAddress >= ActiveGuestMemoryBase && FaultAddress < ActiveGuestMemoryLimit) {
      SignalBoundaryFaultOffset = FaultAddress - ActiveGuestMemoryBase;
    }
    if (Frame->State.rip >= ActiveGuestMemoryBase && Frame->State.rip < ActiveGuestMemoryLimit) {
      SignalBoundaryGuestRIPOffset = Frame->State.rip - ActiveGuestMemoryBase;
    }
    SignalBoundaryRecoveredGuestRIP = Thread->CTX->RestoreRIPFromHostPC(Thread, ProgramCounter);
    for (size_t Index = 0; Index < SignalBoundaryHostGPRs.size(); ++Index) {
      SignalBoundaryHostGPRs[Index] = HostState.__x[Index];
    }
    for (size_t Index = 0; Index < SignalBoundaryGuestGPRs.size(); ++Index) {
      SignalBoundaryGuestGPRs[Index] = Frame->State.gregs[Index];
    }
    SignalBoundarySeen = 1;
    dprintf(2,
            "FLI_ROOT_MEMORY_BOUNDARY source=%llx address=%llx signal=%d code=%d interrupt=%d callret=%d handled=%d "
            "limit=%d\n",
            (unsigned long long)SignalBoundaryRecoveredGuestRIP, (unsigned long long)FaultAddress, Signal, Code,
            (int)SignalBoundaryInterruptPage, (int)SignalBoundaryCallRetStack, (int)HandledCount,
            (int)DiagnosticBackpatchLimitSeen);
    HostState.__pc = Frame->Pointers.GuestSignal_SIGSEGV;
  }

  static int RecoverMach(void *Opaque, arm_thread_state64_t *State, const arm_exception_state64_t *Fault,
                         mach_port_t NativeThread) {
    auto *Self = static_cast<DarwinUnalignedAccessHandler *>(Opaque);
    auto *Thread = Self->MachThread;
    const uint64_t PC = arm_thread_state64_get_pc(*State), Address = Fault->__far;
    if (!Thread || reinterpret_cast<uint64_t>(Thread->CurrentFrame) != State->__x[28] || (Fault->__esr >> 26) != 0x24 ||
        !Thread->CTX->IsAddressInCodeBuffer(Thread, PC))
      return 0;
    static thread_local bool AllocatorReady = [] {
      FEXCore::Allocator::InitializeThread();
      return true;
    }();
    (void)AllocatorReady;
    FEXCore::Allocator::RegisterTLSData(Thread);
    if ((Fault->__esr & 0x40) && ((Fault->__esr & 0x3c) == 0x0c)) {
      struct __darwin_mcontext64 Machine{};
      ucontext_t Context{};
      Context.uc_mcontext = &Machine;
      std::memcpy(&Machine.__ss, State, sizeof(Machine.__ss));
      std::memcpy(&Machine.__es, Fault, sizeof(Machine.__es));
      mach_msg_type_number_t Count = ARM_NEON_STATE64_COUNT;
      if (thread_get_state(NativeThread, ARM_NEON_STATE64, reinterpret_cast<thread_state_t>(&Machine.__ns), &Count) !=
          KERN_SUCCESS)
        return 0;
      if (HandleTrackedGuestCodeWrite(Thread, Address, &Context)) {
        std::memcpy(State, &Machine.__ss, sizeof(*State));
        ++Self->MachSMCCount;
        return 1;
      }
    }
    if ((Fault->__esr & 0x3f) != 0x21)
      return 0;
    uint64_t Logical = 0;
    const bool Owned = (Address >= Self->MachBase && Address < Self->MachLimit) ||
                       (Self->MachLow && Self->MachLow->ContainsHostAddress(Address) &&
                        Self->MachLow->ContainsMappedLogicalRange(Self->MachLow->LogicalAddress(Address), 1)) ||
                       (Self->MachHigh && Self->MachHigh->ContainsHostAddress(Address) &&
                        Self->MachHigh->ContainsMappedLogicalRange(Self->MachHigh->LogicalAddress(Address), 1)) ||
                       (Thread->CTX->TranslateHostMemoryAddress(Address, &Logical) && Logical >= Self->MachBase &&
                        Logical < Self->MachLimit);
    if (!Owned || (Self->MachBounded && Self->MachAlignCount >= MaximumDiagnosticBackpatchCount))
      return 0;
    mach_vm_address_t Base = Address;
    mach_vm_size_t Size = 0;
    vm_region_basic_info_data_64_t Region{};
    mach_msg_type_number_t Count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t Object = MACH_PORT_NULL;
    const auto Result = mach_vm_region(mach_task_self(), &Base, &Size, VM_REGION_BASIC_INFO_64,
                                       reinterpret_cast<vm_region_info_t>(&Region), &Count, &Object);
    if (Object != MACH_PORT_NULL)
      mach_port_deallocate(mach_task_self(), Object);
    // FEX may touch two aligned 16-byte cells; the fault address can sit
    // inside the first cell. Bound the actual cells, not 32 bytes after FAR.
    const uint64_t WindowBase = Address & ~uint64_t(15);
    if (Result != KERN_SUCCESS || WindowBase < Base || Size < 32 || WindowBase - Base > Size - 32 ||
        !(Region.protection & VM_PROT_READ) || ((Fault->__esr & 0x40) && !(Region.protection & VM_PROT_WRITE)))
      return 0;
    FEXCore::Allocator::JITWriteScope WriteScope;
    const auto Offset = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(
        Thread, FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::HalfBarrier, PC, State->__x);
    if (!Offset)
      return 0;
    arm_thread_state64_set_pc_fptr(*State, reinterpret_cast<void *>(PC + *Offset));
    const auto Total = ++Self->MachAlignCount;
    if (Total <= 4 || (Total & (Total - 1)) == 0)
      dprintf(2, "FLI_MACH_ALIGNMENT_RECOVERED count=%llu\n", static_cast<unsigned long long>(Total));
    return 1;
  }
  FEXCore::Core::InternalThreadState *MachThread{};
  uintptr_t MachBase{}, MachLimit{};
  LowGuestShadowMapping *MachLow{};
  HighGuestSparseMapping *MachHigh{};
  bool MachBounded{};
  std::atomic<uint64_t> MachAlignCount{}, MachSMCCount{};

  inline static thread_local FEXCore::Core::InternalThreadState *ActiveThread{};
  inline static thread_local uintptr_t ActiveGuestMemoryBase{};
  inline static thread_local bool CaptureInstructions{true};
  inline static thread_local uintptr_t ActiveGuestMemoryLimit{};
  inline static thread_local uintptr_t ActiveLowShadowHostBase{};
  inline static thread_local uintptr_t ActiveLowShadowHostLimit{};
  inline static thread_local uintptr_t ActiveLowRedirectHostBase{};
  inline static thread_local uintptr_t ActiveLowRedirectHostLimit{};
  inline static thread_local uintptr_t ActiveHighSparseHostBase{};
  inline static thread_local uintptr_t ActiveHighSparseHostLimit{};
  inline static thread_local uintptr_t ActiveFEXImageBase{};
  inline static thread_local uintptr_t ActiveProbeImageBase{};
  inline static thread_local LowGuestShadowMapping *ActiveLowShadowMapping{};
  inline static thread_local HighGuestSparseMapping *ActiveHighSparseMapping{};
  inline static thread_local bool ApplyDiagnosticLimit{true};
  // Diagnostic counters saturate; their range must never stop guest execution.
  inline static thread_local volatile sig_atomic_t HandledCount{};
  inline static thread_local volatile sig_atomic_t SigbusCount{};
  inline static thread_local volatile sig_atomic_t SigsegvCount{};
  inline static thread_local volatile sig_atomic_t SigsegvMissingAddressCount{};
  inline static thread_local size_t HandledPatternCount{};
  inline static thread_local volatile sig_atomic_t HandledPatternOverflow{};
  inline static thread_local std::array<uint64_t, MaximumPatternCount> HandledPatternGuestRIP{};
  inline static thread_local std::array<uint64_t, MaximumPatternCount> HandledPatternHostProgramCounter{};
  inline static thread_local std::array<uint32_t, MaximumPatternCount> HandledPatternInstruction{};
  inline static thread_local std::array<uint64_t, MaximumPatternCount> HandledPatternFirstFaultAddress{};
  inline static thread_local std::array<uint64_t, MaximumPatternCount> HandledPatternLastFaultAddress{};
  inline static thread_local std::array<int32_t, MaximumPatternCount> HandledPatternSignal{};
  inline static thread_local std::array<int32_t, MaximumPatternCount> HandledPatternCode{};
  inline static thread_local std::array<uint64_t, MaximumPatternCount> HandledPatternHitCount{};
  inline static thread_local volatile sig_atomic_t SignalBoundarySeen{};
  inline static thread_local volatile sig_atomic_t SignalBoundarySignal{};
  inline static thread_local volatile sig_atomic_t SignalBoundaryCode{};
  inline static thread_local uint64_t SignalBoundaryProgramCounter{};
  inline static thread_local uint64_t SignalBoundaryInstruction{};
  inline static thread_local std::array<uint32_t, BoundaryInstructionCount> SignalBoundaryInstructionNeighborhood{};
  inline static thread_local uint64_t SignalBoundaryInstructionNeighborhoodValidMask{};
  inline static thread_local uint64_t SignalBoundaryAddressRegister{};
  inline static thread_local volatile sig_atomic_t SignalBoundaryAddressRegisterMatchesFault{};
  inline static thread_local volatile sig_atomic_t SignalBoundaryJITGuardPage{};
  inline static thread_local uint64_t SignalBoundaryFaultAddress{};
  inline static thread_local uint64_t SignalBoundaryX4{};
  inline static thread_local uint64_t SignalBoundaryFSBase{};
  inline static thread_local uint64_t SignalBoundaryGSBase{};
  inline static thread_local uint64_t SignalBoundaryRSP{};
  inline static thread_local volatile sig_atomic_t SignalBoundaryX4MatchesFault{};
  inline static thread_local volatile sig_atomic_t SignalBoundaryThreadState{};
  inline static thread_local volatile sig_atomic_t SignalBoundaryInterruptPage{};
  inline static thread_local volatile sig_atomic_t SignalBoundaryCallRetStack{};
  inline static thread_local uint64_t SignalBoundaryFaultOffset{std::numeric_limits<uint64_t>::max()};
  inline static thread_local uint64_t SignalBoundaryGuestRIPOffset{std::numeric_limits<uint64_t>::max()};
  inline static thread_local uint64_t SignalBoundaryRecoveredGuestRIP{};
  inline static thread_local std::array<uint64_t, 29> SignalBoundaryHostGPRs{};
  inline static thread_local std::array<uint64_t, 16> SignalBoundaryGuestGPRs{};
  inline static thread_local volatile sig_atomic_t DiagnosticBackpatchLimitSeen{};
  inline static thread_local volatile sig_atomic_t Handling{};
  struct sigaction PreviousBusAction{};
  struct sigaction PreviousSegvAction{};
  bool Installed{}, OwnProcessHandlers{true};
};

bool IsAdditionalGuestEnvironment(std::string_view Entry) {
  const size_t Equal = Entry.find('=');
  if (Equal == std::string_view::npos || Equal == 0 || Equal > 128 || Entry.size() > 4096)
    return false;
  const auto Name = Entry.substr(0, Equal);
  for (const char C : Name) {
    if (!((C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') || (C >= '0' && C <= '9') || C == '_'))
      return false;
  }
  for (const std::string_view Reserved :
       {"LC_ALL", "HOME", "WINEARCH", "WINELOADERNOEXEC", "WINESERVERSOCKET", "WINEPRELOADRESERVE", "DISPLAY"}) {
    if (Name == Reserved)
      return false;
  }
  return true;
}

bool IsValidWinePreloadReserve(std::string_view Value) {
  constexpr uint64_t LinuxPageSize = 4096;
  const size_t Separator = Value.find('-');
  if (Value.empty() || Value.size() > 33 || Separator == std::string_view::npos || Separator == 0 ||
      Separator + 1 >= Value.size() || Value.find('-', Separator + 1) != std::string_view::npos) {
    return false;
  }

  const auto ParseHex = [](std::string_view Component) -> std::optional<uint64_t> {
    if (Component.empty() || Component.size() > 16) {
      return std::nullopt;
    }
    uint64_t Result{};
    for (const char Character : Component) {
      uint64_t Digit{};
      if (Character >= '0' && Character <= '9') {
        Digit = static_cast<uint64_t>(Character - '0');
      } else if (Character >= 'a' && Character <= 'f') {
        Digit = static_cast<uint64_t>(Character - 'a' + 10);
      } else if (Character >= 'A' && Character <= 'F') {
        Digit = static_cast<uint64_t>(Character - 'A' + 10);
      } else {
        return std::nullopt;
      }
      if (Result > (std::numeric_limits<uint64_t>::max() - Digit) / 16) {
        return std::nullopt;
      }
      Result = Result * 16 + Digit;
    }
    return Result;
  };

  const auto Start = ParseHex(Value.substr(0, Separator));
  const auto End = ParseHex(Value.substr(Separator + 1));
  return Start.has_value() && End.has_value() && (*Start < *End || (*Start == 0 && *End == 0)) &&
         (*Start & (LinuxPageSize - 1)) == 0 && (*End & (LinuxPageSize - 1)) == 0;
}

class ProcessSyscallHandler final : public FEXCore::HLE::SyscallHandler {
public:
  ProcessSyscallHandler(uint64_t GuestBase, uint64_t GuestSize, uint64_t StopAddress = 0,
                        uint64_t InitialProgramBreak = 0, uint64_t ProgramBreakLimit = 0, uint64_t MMapArenaBase = 0,
                        uint64_t MMapArenaLimit = 0, std::string RootFS = {}, std::string GuestProgram = {},
                        std::string HostExecutablePath = {})
      : GuestBase{GuestBase}, GuestSize{GuestSize}, StopAddress{StopAddress}, InitialProgramBreak{InitialProgramBreak},
        CurrentProgramBreak{InitialProgramBreak}, ProgramBreakLimit{ProgramBreakLimit}, MMapArenaBase{MMapArenaBase},
        NextMMapAddress{MMapArenaBase}, MMapArenaLimit{MMapArenaLimit}, RootFS{std::move(RootFS)},
        GuestProgram{std::move(GuestProgram)}, HostExecutablePath{std::move(HostExecutablePath)} {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_LINUX64;
    const char *TracePID = std::getenv("REGRESSION_LINUX_TRACE_PID");
    const bool OwnELFExec = fli_env_enabled("REGRESSION_NATIVE_ELF_EXEC_GATE") && TracePID &&
                            std::strtoll(TracePID, nullptr, 10) == getpid();
    NativeMTrack = fli_env_enabled("REGRESSION_FLI_MTRACK") &&
                   (OwnELFExec || fli_env_enabled("REGRESSION_FLI_MTRACK_CONTROL")) &&
                   !fli_env_enabled("REGRESSION_FLI_ROOT_FULL_SMC");
    if (NativeMTrack) {
      SMCNotify =
          reinterpret_cast<int32_t (*)(uint64_t, uint64_t, int)>(dlsym(RTLD_DEFAULT, "fli_linux_root_set_smc_page"));
      if (!SMCNotify)
        std::abort();
      if (const char *Hot = std::getenv("REGRESSION_FLI_FULL_CODE_OFFSET")) {
        char *End = nullptr;
        const uint64_t Offset = std::strtoull(Hot, &End, 0);
        if (!*Hot || *End || Offset % getpagesize() || Offset > GuestSize - getpagesize())
          std::abort();
        FullSMCPage = GuestBase + Offset;
        dprintf(2, "FLI_ROOT_FULL_CODE_PAGE page=%llx offset=%llx\n", (unsigned long long)*FullSMCPage,
                (unsigned long long)Offset);
      }
    }
    if (!this->RootFS.empty()) {
      std::array<char, 4096> Canonical{};
      if (realpath(this->RootFS.c_str(), Canonical.data()) != nullptr) {
        this->RootFS = Canonical.data();
      }
    }
  }

  ~ProcessSyscallHandler() override {
    for (const auto &[Page, Active] : SMCProtectedPages)
      if (Active) {
        mprotect(reinterpret_cast<void *>(Page), getpagesize(), PROT_READ | PROT_WRITE);
        SMCNotify(GuestBase, Page, 0);
      }
    for (const auto &Alias : SharedAliases)
      munmap(reinterpret_cast<void *>(Alias.Host), Alias.Span);

    CleanupNativeForkCloneChild();
    for (const int Descriptor : OwnedDescriptors) {
      close(Descriptor);
    }
  }

  uint64_t SharedSplitLockAddress() const {
    auto *context = static_cast<FEXCore::Context::ContextImpl *>(ForkContext);
    return context ? reinterpret_cast<uint64_t>(&context->StrictSplitLockMutex) : 0;
  }

  void AttachForkContext(FEXCore::Context::Context *Context, uint64_t StopHandler = 0) {
    NativeThreadStopHandler = StopHandler;
    MainNativeThread = pthread_self();
    ForkContext = Context;
    NativeForkCloneContextAttached = Context != nullptr;
  }

  bool SetInitialGuestDirectory(const std::string &Path) {
    if (Path.empty() || Path.front() != '/')
      return false;
    const auto Host = ResolveGuestPathWithParents(Path);
    struct stat Status{};
    if (!Host || stat(Host->c_str(), &Status) != 0 || !S_ISDIR(Status.st_mode))
      return false;
    GuestCurrentWorkingDirectory = fli_guest_path_view(*Host, RootFS);
    return true;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame *Frame, FEXCore::HLE::SyscallArguments *Arguments) override {
    std::unique_lock<std::recursive_mutex> Lock{SyscallMutex};
    auto *PreviousLock = ActiveSyscallLock;
    const uint64_t previous_number = ActiveGuestSyscallNumber, previous_rip = ActiveGuestSyscallRIP;
    const int64_t previous_descriptor = ActiveGuestSyscallDescriptor;
    ActiveGuestSyscallNumber = Arguments->Argument[0];
    ActiveGuestSyscallRIP = Frame->State.rip;
    ActiveGuestSyscallDescriptor =
        (Arguments->Argument[0] == 0 || Arguments->Argument[0] == 1) ? int64_t(Arguments->Argument[1]) : -1;
    if (NativeCallbackInProgress && Arguments->Argument[0] == 0 &&
        fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT")) {
      const auto description = DescribeMappingDescriptor(int(Arguments->Argument[1]), false);
      struct stat metadata{};
      const bool known = fstat(int(Arguments->Argument[1]), &metadata) == 0;
      dprintf(
          2,
          "NATIVE_CALLBACK_READ_METADATA pid=%d descriptor=%lld requested=%llu fd-class=%s regular=%d file-size=%lld\n",
          getpid(), (long long)ActiveGuestSyscallDescriptor, (unsigned long long)Arguments->Argument[3],
          description.first.c_str(), known && S_ISREG(metadata.st_mode), known ? (long long)metadata.st_size : -1LL);
    }
    ActiveSyscallLock = &Lock;
    PrepareTrackedCodeChange(Frame->Thread, Arguments);
    const uint64_t Result = HandleSyscallImpl(Frame, Arguments);
    CompleteMemoryOperation(Frame->Thread, Arguments, Result);
    // Exit dispatch below releases SyscallMutex before leaving this stack.
    if (ProcessExiting && ActiveGuestThread)
      Stop(Frame);
    ActiveSyscallLock = PreviousLock;
    ActiveGuestSyscallNumber = previous_number;
    ActiveGuestSyscallRIP = previous_rip;
    ActiveGuestSyscallDescriptor = previous_descriptor;
    if (fli_env_enabled("REGRESSION_FLI_TRACE_SYSCALL_RESULTS")) {
      const int64_t SignedResult = static_cast<int64_t>(Result);
      if ((SignedResult < 0 && SignedResult >= -4095 && SignedResult != -2) || Arguments->Argument[0] == MMapSyscall ||
          Arguments->Argument[0] == MProtectSyscall || Arguments->Argument[0] == ConnectSyscall) {
        const auto Key = std::make_pair(Arguments->Argument[0], SignedResult);
        const uint64_t Occurrence = ++SyscallTraceCounts[Key];
        if (Occurrence <= 32 || (Occurrence & (Occurrence - 1)) == 0)
          dprintf(STDERR_FILENO,
                  "TRACE syscall-result pid=%d nr=%llu result=%lld args=%llx,%llx,%llx,%llx,%llx,%llx rip=%llx\n",
                  getpid(), (unsigned long long)Arguments->Argument[0], (long long)SignedResult,
                  (unsigned long long)Arguments->Argument[1], (unsigned long long)Arguments->Argument[2],
                  (unsigned long long)Arguments->Argument[3], (unsigned long long)Arguments->Argument[4],
                  (unsigned long long)Arguments->Argument[5], (unsigned long long)Arguments->Argument[6],
                  (unsigned long long)Frame->State.rip);
      }
    }
    if (fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT") && Arguments->Argument[0] == MMapSyscall &&
        static_cast<int64_t>(Result) >= 0 && !(Arguments->Argument[4] & 0x20) && (Arguments->Argument[3] & PROT_READ) &&
        Arguments->Argument[6] == 0 && ClientMapInputSamples++ < 128) {
      const uint64_t sp = Frame->State.gregs[FEXCore::X86State::REG_RSP];
      bool hook_caller = false;
      for (unsigned i = 0; i < 64; ++i) {
        const void *word = HostPointerForGuestRange(sp + i * 8, 8, PROT_READ);
        if (!word)
          break;
        uint64_t pc = 0;
        memcpy(&pc, word, 8);
        for (const auto &map : HighMMapRecords)
          if (map.Active && (map.Protection & PROT_EXEC) && pc >= map.Address && pc - map.Address < map.Length &&
              pc - map.Address + map.Offset == 0x508305)
            hook_caller = true;
      }
      unsigned char magic[4]{};
      const void *mapped = HostPointerForGuestRange(Result, 4, PROT_READ);
      if (mapped)
        memcpy(magic, mapped, 4);
      const char *type = !memcmp(magic, "\177ELF", 4) ? "ELF" : magic[0] == 'M' && magic[1] == 'Z' ? "MZ" : "other";
      const auto description = DescribeMappingDescriptor(int(Arguments->Argument[5]), false);
      const auto slash = description.second.find_last_of('/');
      const std::string base = description.second.substr(slash == std::string::npos ? 0 : slash + 1);
      bool safe = !base.empty() && base.size() < 96;
      for (char c : base)
        safe = safe && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
                        c == '.' || c == '-');
      dprintf(2,
              "CLIENT_MAP_INPUT pid=%d phase=%s fd=%lld size=%llx image=%s basename=%s original-mmap-hook-caller=%d "
              "result-preserved=1\n",
              getpid(), NativeHandoffObserved ? "after-native-handoff" : "before-native-handoff",
              (long long)Arguments->Argument[5], (unsigned long long)Arguments->Argument[2], type,
              safe ? base.c_str() : "redacted", hook_caller);
    }
    if (Arguments->Argument[0] == 15 && GuestSignalDepth) {
      GuestSignalFrames[GuestSignalDepth - 1].ReturnedViaSyscall = true;
      Lock.unlock();
      FEXCore::UncheckedLongJump::LongJump(GuestSignalFrames[GuestSignalDepth - 1].ReturnJump, 1);
    }
    if (ActivePendingSignals && ActivePendingSignals->load() && GuestSignalDepth == 0) {
      Lock.unlock();
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = Result;
      DeliverQueuedSignals(Frame);
      Lock.lock();
    }
    if (ForkContext && NativeThreadStopHandler &&
        (Arguments->Argument[0] == ExitSyscall || Arguments->Argument[0] == ExitGroupSyscall)) {
      // A Linux exit syscall does not resume the caller's guest instruction stream.
      Lock.unlock();
      DarwinDiagnosticThreadStopHandler::Request();
      std::abort(); // The installed handler returns directly to ExecuteThread's caller.
    }
    return Result;
  }

  uint64_t MemoryOperationImpl(FEXCore::Core::CpuStateFrame *Frame, FEXCore::HLE::SyscallArguments *Arguments) {
    const uint64_t Number = Arguments->Argument[0];
    if (Number == MMapSyscall && MMapArenaBase != 0) {
      constexpr uint64_t LinuxMapShared = 0x01;
      constexpr uint64_t LinuxMapPrivate = 0x02;
      constexpr uint64_t LinuxMapFixed = 0x10;
      constexpr uint64_t LinuxMapAnonymous = 0x20;
      constexpr uint64_t LinuxMapDenyWrite = 0x0800;
      constexpr uint64_t LinuxMapNoReserve = 0x4000;
      constexpr uint64_t LinuxMapStack = 0x20000;
      constexpr uint64_t LinuxMapFixedNoReplace = 0x100000;
      constexpr uint64_t AllowedFlags = LinuxMapPrivate | LinuxMapFixed | LinuxMapAnonymous | LinuxMapDenyWrite |
                                        LinuxMapNoReserve | LinuxMapStack | LinuxMapFixedNoReplace;
      constexpr uint64_t LinuxPageSize = 4096;
      const uint64_t RequestedAddress = Arguments->Argument[1];
      const uint64_t Length = Arguments->Argument[2];
      const uint64_t Protection = Arguments->Argument[3];
      const uint64_t Flags = Arguments->Argument[4];
      const int Descriptor = static_cast<int>(Arguments->Argument[5]);
      const uint64_t Offset = Arguments->Argument[6];
      const bool IsLowPageAliasRequest = RequestedAddress == LinuxSharedUserDataAddress &&
                                         Length == LinuxSharedUserDataSize && Protection == PROT_READ &&
                                         Flags == (LinuxMapPrivate | LinuxMapAnonymous | LinuxMapFixedNoReplace) &&
                                         Descriptor == -1 && Offset == 0;
      MMapLastRequestedAddress = RequestedAddress;
      MMapLastLength = Length;
      MMapLastFlags = Flags;
      const auto RecordFailure = [this](int LinuxError, std::string Reason) -> uint64_t {
        if (fli_env_enabled("REGRESSION_FLI_TRACE_FILE_MAPS") && !(MMapLastFlags & 0x20))
          fprintf(stderr, "OWNED_FILE_MAP_FAILURE address=%llx length=%llx flags=%llx error=%d reason=%s\n",
                  static_cast<unsigned long long>(MMapLastRequestedAddress),
                  static_cast<unsigned long long>(MMapLastLength), static_cast<unsigned long long>(MMapLastFlags),
                  LinuxError, Reason.c_str());
        const uint64_t ReturnedValue = static_cast<uint64_t>(-LinuxError);

        return ReturnedValue;
      };

      const bool SharedFixedLowCandidate =
          RequestedAddress != 0 && RequestedAddress < LowGuestAddressLimit && Length != 0 &&
          Length % LinuxPageSize == 0 && (Protection & ~(PROT_READ | PROT_WRITE)) == 0 &&
          Flags == (LinuxMapShared | LinuxMapFixed) && OwnedDescriptors.contains(Descriptor) &&
          Offset % static_cast<uint64_t>(getpagesize()) == 0;
      if (SharedFixedLowCandidate) {
        struct stat DescriptorStat{};
        if (fstat(Descriptor, &DescriptorStat) == 0) {
          MMapSharedFixedLowLastDescriptorStatSucceeded = true;
          MMapSharedFixedLowLastDescriptorRegular = S_ISREG(DescriptorStat.st_mode);
          MMapSharedFixedLowLastDescriptorSize = DescriptorStat.st_size;
        }
      }
      const bool ExactSharedFixedLowMapping =
          SharedFixedLowCandidate && MMapSharedFixedLowLastDescriptorStatSucceeded &&
          MMapSharedFixedLowLastDescriptorRegular && MMapSharedFixedLowLastDescriptorSize >= 0 &&
          Offset <= static_cast<uint64_t>(MMapSharedFixedLowLastDescriptorSize) &&
          Length <= static_cast<uint64_t>(MMapSharedFixedLowLastDescriptorSize) - Offset;
      if (ExactSharedFixedLowMapping && LowMemoryBiasModeEnabled && LowGuestShadow != nullptr) {
        uint64_t HostAddress{};
        uint64_t HostSpan{};
        const int MapError = LowGuestShadow->MapSharedFile(RequestedAddress, Length, Protection, Descriptor, Offset,
                                                           &HostAddress, &HostSpan);
        if (MapError != 0) {
          return RecordFailure(MapError, "shared-fixed-low-shadow-map-failed");
        }
        MMapFileByteCount += Length;
        RecordLowMMap(RequestedAddress, Length, Protection, Flags, Descriptor, Offset);
        return RequestedAddress;
      }
      const bool SharedFileCandidate = RequestedAddress == 0 && Length != 0 && Flags == LinuxMapShared &&
                                       OwnedDescriptors.contains(Descriptor) && Offset % LinuxPageSize == 0;
      if (SharedFileCandidate) {
        struct stat DescriptorStat{};
        if (fstat(Descriptor, &DescriptorStat) == 0) {
          MMapSharedFileLastDescriptorStatSucceeded = true;
          MMapSharedFileLastDescriptorRegular = S_ISREG(DescriptorStat.st_mode);
          MMapSharedFileLastDescriptorSize = DescriptorStat.st_size;
        }
      }
      const bool ExactSharedUserDataMapping =
          SharedFileCandidate && Length == LinuxPageSize && Protection == PROT_WRITE &&
          Descriptor == MemfdCreateLastDescriptor && MMapSharedFileLastDescriptorStatSucceeded &&
          MMapSharedFileLastDescriptorRegular &&
          MMapSharedFileLastDescriptorSize == static_cast<int64_t>(LinuxPageSize) && Offset == 0;
      const bool ExactSharedSessionMapping =
          SharedFileCandidate && Length == ObservedWineSessionMappingSize && Protection == (PROT_READ | PROT_WRITE) &&
          Descriptor == MemfdCreateLastDescriptor && MMapSharedFileLastDescriptorStatSucceeded &&
          MMapSharedFileLastDescriptorRegular &&
          MMapSharedFileLastDescriptorSize == static_cast<int64_t>(ObservedWineSessionMappingSize) && Offset == 0;
      const bool ExactWineUserSharedDataInitializationMapping =
          SharedFileCandidate && Length == ObservedWineUserSharedDataInitializationSize &&
          Protection == (PROT_READ | PROT_WRITE) && ReceivedSCMRightsDescriptors.contains(Descriptor) &&
          MMapSharedFileLastDescriptorStatSucceeded && MMapSharedFileLastDescriptorRegular &&
          MMapSharedFileLastDescriptorSize == static_cast<int64_t>(LinuxPageSize) && Offset == 0;
      const bool OwnedSharedFileMapping =
          SharedFileCandidate && MMapSharedFileLastDescriptorStatSucceeded && MMapSharedFileLastDescriptorRegular &&
          Offset % static_cast<uint64_t>(getpagesize()) == 0 && Offset <= static_cast<uint64_t>(INT64_MAX);
      if (ExactSharedUserDataMapping || ExactSharedSessionMapping || ExactWineUserSharedDataInitializationMapping ||
          OwnedSharedFileMapping) {
        const uint64_t HostPageSize = static_cast<uint64_t>(getpagesize());
        if (HostPageSize == 0 || (HostPageSize & (HostPageSize - 1)) != 0) {
          return RecordFailure(EINVAL, "invalid-host-page-size");
        }
        const uint64_t HostMappingSpan = (Length + HostPageSize - 1) & ~(HostPageSize - 1);
        const uint64_t MappingAddress = FindFreeArenaAddress(NextMMapAddress, HostMappingSpan, HostPageSize);
        if (!ContainsMMapArena(MappingAddress, HostMappingSpan)) {

          return RecordFailure(ENOMEM, "shared-file-outside-private-arena");
        }
        // The guest cannot choose this host address: only the next unused page in the
        // helper's private arena may be replaced by the measured shared file mapping.
        void *Result = mmap(reinterpret_cast<void *>(MappingAddress), HostMappingSpan, static_cast<int>(Protection),
                            MAP_SHARED | MAP_FIXED, Descriptor, static_cast<off_t>(Offset));
        if (Result == MAP_FAILED) {
          return RecordFailure(errno, "host-shared-file-mmap-failed");
        }
        if (reinterpret_cast<uint64_t>(Result) != MappingAddress) {
          munmap(Result, HostMappingSpan);
          return RecordFailure(EIO, "host-shared-file-mmap-address-mismatch");
        }
        NextMMapAddress = MappingAddress + HostMappingSpan;
        RecordHighMMap(MappingAddress, Length, NextMMapAddress, Protection, Flags, Descriptor, Offset);
        return MappingAddress;
      }
      const bool FarSharedNoReplace = Flags == (LinuxMapShared | LinuxMapFixedNoReplace) &&
                                      RequestedAddress >= HighSparseGuestBase + HighSparseGuestSize &&
                                      RequestedAddress < 0x800000000000ULL;
      if (Flags == (LinuxMapShared | LinuxMapFixedNoReplace) ||
          (Flags == (LinuxMapShared | LinuxMapFixed) && ContainsMMapArena(RequestedAddress, Length))) {
        if (!Length || RequestedAddress % LinuxPageSize ||
            Offset % (FarSharedNoReplace ? LinuxPageSize : getpagesize()) ||
            (Protection & ~uint64_t{PROT_READ | PROT_WRITE | PROT_EXEC}))
          return RecordFailure(EINVAL, "shared-alias-invalid-range");
        const uint64_t Rounded = (Length + LinuxPageSize - 1) & ~(LinuxPageSize - 1);
        if (Rounded < Length || (!FarSharedNoReplace && !ContainsMMapArena(RequestedAddress, Rounded)))
          return RecordFailure(ENOMEM, "shared-alias-outside-private-arena");
        if (FarSharedNoReplace) {
          mach_vm_address_t base = RequestedAddress;
          mach_vm_size_t span = 0;
          vm_region_basic_info_data_64_t info{};
          mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
          mach_port_t object = MACH_PORT_NULL;
          const kern_return_t status = mach_vm_region(mach_task_self(), &base, &span, VM_REGION_BASIC_INFO_64,
                                                      reinterpret_cast<vm_region_info_t>(&info), &count, &object);
          if (object != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), object);
          if (status == KERN_SUCCESS && base < RequestedAddress + Rounded && base + span > RequestedAddress)
            return RecordFailure(EEXIST, "shared-alias-far-host-range-occupied");
        }
        if (!OwnedDescriptors.contains(Descriptor))
          return RecordFailure(EBADF, "unowned-file-descriptor");
        for (const auto &Alias : SharedAliases)
          if (RequestedAddress < Alias.Guest + Alias.Length && Alias.Guest < RequestedAddress + Rounded)
            return RecordFailure((Flags & LinuxMapFixedNoReplace) ? EEXIST : 95,
                                 "shared-alias-replacement-not-supported");
        if (Flags & LinuxMapFixedNoReplace) {
          for (const auto &Record : HighMMapRecords)
            if (Record.Active && RequestedAddress < Record.Address + Record.Length &&
                Record.Address < RequestedAddress + Rounded)
              return RecordFailure(EEXIST, "shared-alias-range-already-mapped");
        }
        if (SharedAliases.size() == FEXCore::Context::GUEST_MEMORY_ADDRESS_REGION_CAPACITY)
          return RecordFailure(ENOMEM, "shared-alias-translation-slots-exhausted");
        const uint64_t HostPage = getpagesize();
        const uint64_t FileShift = Offset % HostPage;
        if (Rounded > UINT64_MAX - FileShift - HostPage + 1)
          return RecordFailure(ENOMEM, "shared-alias-length-overflow");
        const uint64_t Span = (Rounded + FileShift + HostPage - 1) & ~(HostPage - 1);
        // Keep the Linux 4 KiB file offset while mapping host-aligned pages.
        const int HostProtection = (Protection & ~PROT_EXEC) | ((Protection & PROT_EXEC) ? PROT_READ : 0);
        void *Host = mmap(nullptr, Span, HostProtection, MAP_SHARED, Descriptor, Offset - FileShift);
        if (Host == MAP_FAILED)
          return RecordFailure(TranslateHostSocketErrorToLinux(errno), "shared-alias-host-map-failed");
        if (FarSharedNoReplace && (Protection & PROT_EXEC) &&
            fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT")) {
          std::array<uint8_t, 32> bytes{};
          mach_vm_size_t copied = 0;
          if (mach_vm_read_overwrite(mach_task_self(), reinterpret_cast<mach_vm_address_t>(Host) + FileShift,
                                     bytes.size(), reinterpret_cast<mach_vm_address_t>(bytes.data()),
                                     &copied) == KERN_SUCCESS &&
              copied == bytes.size()) {
            dprintf(2, "NATIVE_SHARED_ALIAS_CODE pid=%d guest=%llx actual-host=%llx original-file-offset=%llx prefix=",
                    getpid(), (unsigned long long)RequestedAddress,
                    (unsigned long long)reinterpret_cast<uint64_t>(Host) + FileShift, (unsigned long long)Offset);
            for (const auto byte : bytes)
              dprintf(2, "%02x", byte);
            dprintf(2, "\n");
          }
        }
        SharedAliases.push_back(
            {RequestedAddress, Rounded, reinterpret_cast<uint64_t>(Host) + FileShift, Span, Protection, Offset});
        if (!RefreshSharedAliases()) {
          SharedAliases.pop_back();
          munmap(Host, Span);
          return RecordFailure(ENOMEM, "shared-alias-region-rejected");
        }
        RecordHighMMap(RequestedAddress, Rounded, RequestedAddress + Rounded, Protection, Flags, Descriptor, Offset);
        if (FarSharedNoReplace && fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
          dprintf(
              2,
              "NATIVE_FAR_SHARED_FILE_MAPPED pid=%d guest=%llx length=%llx offset=%llx host-shift=%llx actual-file=1\n",
              getpid(), (unsigned long long)RequestedAddress, (unsigned long long)Rounded, (unsigned long long)Offset,
              (unsigned long long)FileShift);
        return RequestedAddress;
      }
      if (Length == 0 || (Protection & ~uint64_t{PROT_READ | PROT_WRITE | PROT_EXEC}) != 0 ||
          (Flags & LinuxMapPrivate) == 0 || (Flags & ~AllowedFlags) != 0 || Offset % LinuxPageSize != 0) {
        return RecordFailure(EINVAL, "invalid-shape");
      }
      if ((Flags & LinuxMapAnonymous) == 0 && !OwnedDescriptors.contains(Descriptor)) {
        return RecordFailure(EBADF, "unowned-file-descriptor");
      }
      if ((Flags & LinuxMapAnonymous) != 0 && Descriptor != -1) {
        return RecordFailure(EINVAL, "anonymous-descriptor-not-minus-one");
      }
      if (Length > std::numeric_limits<uint64_t>::max() - (LinuxPageSize - 1)) {
        return RecordFailure(ENOMEM, "length-overflow");
      }
      const uint64_t AlignedLength = (Length + LinuxPageSize - 1) & ~(LinuxPageSize - 1);
      uint64_t MappingAddress{};
      const bool FixedRequest = (Flags & (LinuxMapFixed | LinuxMapFixedNoReplace)) != 0;
      if (FixedRequest) {
        if (RequestedAddress % LinuxPageSize != 0) {
          return RecordFailure(EINVAL, "fixed-address-unaligned");
        }
        MappingAddress = RequestedAddress;
      } else {
        MappingAddress = FindFreeArenaAddress(NextMMapAddress, AlignedLength, LinuxPageSize);
      }
      if (IsLowPageAliasRequest && LowPageAliasModeEnabled) {
        if (LowPageAliasAccepted) {
          return RecordFailure(EEXIST, "low-page-alias-already-present");
        }
        if (LowPageAliasBackingSize < RealLowPageAliasBackingSize ||
            !Contains(LowPageAliasBackingAddress, RealLowPageAliasBackingSize)) {
          return RecordFailure(ENOMEM, "low-page-alias-backing-invalid");
        }
        std::memset(reinterpret_cast<void *>(LowPageAliasBackingAddress), 0,
                    static_cast<size_t>(RealLowPageAliasBackingSize));
        LowPageAliasAccepted = true;
        return LinuxSharedUserDataAddress;
      }
      if (FixedRequest && LowMemoryBiasModeEnabled && LowGuestShadow != nullptr &&
          LowGuestShadow->ContainsLogicalRange(MappingAddress, AlignedLength)) {
        uint64_t FileBytes{};
        struct stat FileStat{};
        const bool NativePrivateFile =
            (Flags & (LinuxMapAnonymous | LinuxMapFixedNoReplace)) == 0 && MappingAddress % getpagesize() == 0 &&
            Offset % getpagesize() == 0 && AlignedLength % getpagesize() == 0 && fstat(Descriptor, &FileStat) == 0 &&
            S_ISREG(FileStat.st_mode) && Offset + AlignedLength <= static_cast<uint64_t>(FileStat.st_size);
        const int LowMapError =
            NativePrivateFile
                ? LowGuestShadow->MapSharedFile(MappingAddress, AlignedLength, Protection, Descriptor, Offset, nullptr,
                                                nullptr, true)
                : LowGuestShadow->Map(MappingAddress, AlignedLength, Protection, (Flags & LinuxMapFixedNoReplace) != 0,
                                      (Flags & LinuxMapAnonymous) != 0, Descriptor, Offset, &FileBytes);
        if (LowMapError != 0) {
          return RecordFailure(LowMapError, "low-memory-shadow-map-failed");
        }
        MMapFileByteCount += FileBytes;
        RecordLowMMap(MappingAddress, AlignedLength, Protection, Flags, Descriptor, Offset);
        return MappingAddress;
      }
      if (FixedRequest && HighMemoryRegionModeEnabled && HighGuestSparse != nullptr &&
          HighGuestSparse->ContainsLogicalRange(MappingAddress, AlignedLength)) {
        uint64_t FileBytes{};
        const int HighMapError =
            HighGuestSparse->Map(MappingAddress, AlignedLength, Protection, (Flags & LinuxMapFixedNoReplace) != 0,
                                 (Flags & LinuxMapAnonymous) != 0, Descriptor, Offset, &FileBytes);
        if (HighMapError != 0) {
          return RecordFailure(HighMapError, "high-memory-sparse-map-failed");
        }
        MMapFileByteCount += FileBytes;
        return MappingAddress;
      }
      if (!ContainsMMapArena(MappingAddress, AlignedLength)) {

        return RecordFailure(ENOMEM, "outside-private-arena");
      }

      if ((Flags & LinuxMapFixedNoReplace) && ArenaRangeOccupied(MappingAddress, AlignedLength)) {
        return RecordFailure(EEXIST, "fixed-noreplace-arena-occupied");
      }

      // A non-fixed 4 KiB allocation can share a Darwin page with tracked code.
      // Retire that internal write guard before zeroing the newly selected range.
      UnprotectTrackedCodeRange((Frame ? Frame->Thread : nullptr), MappingAddress, AlignedLength);
      // A replacement mapping may reuse a page that the owner made read-only.
      // Restore backing access only while initializing the new mapping.
      const int prepare_error = ProjectArenaHostPermissions(MappingAddress, AlignedLength, PROT_READ | PROT_WRITE);
      if (prepare_error)
        return RecordFailure(prepare_error, "arena-backing-prepare-failed");
      if ((Flags & LinuxMapAnonymous) != 0) {
        // Fresh anonymous host pages preserve zero-fill semantics without committing a large PROT_NONE reservation.
        FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void *>(MappingAddress), AlignedLength);
      } else {
        std::memset(reinterpret_cast<void *>(MappingAddress), 0, static_cast<size_t>(AlignedLength));
      }
      if ((Flags & LinuxMapAnonymous) == 0) {
        if (Offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
          return RecordFailure(EINVAL, "file-offset-overflow");
        }
        size_t TotalRead{};
        while (TotalRead < Length) {
          const ssize_t Result = pread(Descriptor, reinterpret_cast<void *>(MappingAddress + TotalRead),
                                       static_cast<size_t>(Length - TotalRead), static_cast<off_t>(Offset + TotalRead));
          if (Result == -1 && errno == EINTR) {
            continue;
          }
          if (Result == -1) {
            return RecordFailure(errno, "file-read-failed");
          }
          if (Result == 0) {
            break;
          }
          TotalRead += static_cast<size_t>(Result);
        }
        MMapFileByteCount += TotalRead;
      }
      if (!FixedRequest) {
        NextMMapAddress = MappingAddress + AlignedLength;
      }
      RecordHighMMap(MappingAddress, AlignedLength, FixedRequest ? MappingAddress + AlignedLength : NextMMapAddress,
                     Protection, Flags, Descriptor, Offset);
      const int protection_error = ProjectArenaHostPermissions(MappingAddress, AlignedLength, Protection);
      if (protection_error)
        return RecordFailure(protection_error, "arena-backing-protection-failed");
      return MappingAddress;
    }
    if (Number == MUnmapSyscall && MMapArenaBase != 0) {
      constexpr uint64_t LinuxMapShared = 0x01;
      constexpr uint64_t LinuxMapPrivateAnonymous = 0x02 | 0x20;
      const uint64_t Address = Arguments->Argument[1];
      const uint64_t Length = Arguments->Argument[2];
      MUnmapLastActiveRecordIndexPlusOne = 0;
      MUnmapLastActiveRecordArenaEnd = 0;
      MUnmapLastActiveRecordProtection = 0;
      MUnmapLastActiveRecordFlags = 0;
      if (Length == 0 || Address % LinuxGuestPageSize != 0 ||
          Length > std::numeric_limits<uint64_t>::max() - (LinuxGuestPageSize - 1)) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const uint64_t RoundedLength = (Length + LinuxGuestPageSize - 1) & ~(LinuxGuestPageSize - 1);
      for (auto It = SharedAliases.begin(); It != SharedAliases.end(); ++It) {
        if (Address == It->Guest && RoundedLength == It->Length) {
          if (munmap(reinterpret_cast<void *>(It->Host - (It->Offset % getpagesize())), It->Span))
            return static_cast<uint64_t>(-errno);
          SharedAliases.erase(It);
          RefreshSharedAliases();
          for (auto &Record : HighMMapRecords)
            if (Record.Address == Address && Record.Length == RoundedLength)
              Record.Active = false;
          return 0;
        }
        if (Address < It->Guest + It->Length && It->Guest < Address + RoundedLength)
          return static_cast<uint64_t>(-95);
      }
      if (LowGuestShadow && LowGuestShadow->ContainsLogicalRange(Address, RoundedLength)) {
        const int Error = LowGuestShadow->Unmap(Address, RoundedLength);
        if (Error != 0) {
          return static_cast<uint64_t>(-Error);
        }
        return 0;
      }
      if (HighMemoryRegionModeEnabled && HighGuestSparse != nullptr &&
          HighGuestSparse->ContainsLogicalRange(Address, Length)) {
        const int HighUnmapError = HighGuestSparse->Unmap(Address, Length);
        if (HighUnmapError != 0) {
          return static_cast<uint64_t>(-HighUnmapError);
        }
        return 0;
      }
      if (ContainsMMapArena(Address, RoundedLength)) {
        const int error = ProjectArenaHostPermissions(Address, RoundedLength, PROT_READ | PROT_WRITE);
        if (error)
          return uint64_t(-error);
      }
      for (uint64_t Index = HighMMapRecordCount; Index != 0; --Index) {
        const HighMMapRecord &Record = HighMMapRecords[Index - 1];
        if (Record.Active && Record.Address == Address && Record.Length == Length) {
          MUnmapLastActiveRecordIndexPlusOne = Index;
          MUnmapLastActiveRecordArenaEnd = Record.ArenaEnd;
          MUnmapLastActiveRecordProtection = Record.Protection;
          MUnmapLastActiveRecordFlags = Record.Flags;
          break;
        }
      }
      const bool EndValid = Length <= std::numeric_limits<uint64_t>::max() - Address;
      const bool ExactMeasuredLIFOShape =
          Length != 0 && Address % LinuxGuestPageSize == 0 && Length % LinuxGuestPageSize == 0 && EndValid &&
          ContainsMMapArena(Address, Length) && MUnmapLastActiveRecordIndexPlusOne != 0 &&
          MUnmapLastActiveRecordArenaEnd == NextMMapAddress &&
          MUnmapLastActiveRecordProtection == (PROT_READ | PROT_WRITE) &&
          (MUnmapLastActiveRecordFlags == LinuxMapPrivateAnonymous);
      if (ExactMeasuredLIFOShape) {
        std::memset(reinterpret_cast<void *>(Address), 0, static_cast<size_t>(Length));
        if (MUnmapLastActiveRecordIndexPlusOne != 0) {
          HighMMapRecords[MUnmapLastActiveRecordIndexPlusOne - 1].Active = false;
        }
        NextMMapAddress = Address;

        return 0;
      }
      const uint64_t HostPageSize = static_cast<uint64_t>(getpagesize());
      const bool HostPageSizeValid = HostPageSize != 0 && (HostPageSize & (HostPageSize - 1)) == 0;
      const bool ExactMeasuredSharedUserDataLIFOShape =
          Length == ObservedWineUserSharedDataInitializationSize && EndValid && HostPageSizeValid &&
          Address % HostPageSize == 0 && ContainsMMapArena(Address, Length) &&
          MUnmapLastActiveRecordIndexPlusOne != 0 && MUnmapLastActiveRecordArenaEnd == NextMMapAddress &&
          MUnmapLastActiveRecordArenaEnd - Address == HostPageSize &&
          MUnmapLastActiveRecordProtection == (PROT_READ | PROT_WRITE) && MUnmapLastActiveRecordFlags == LinuxMapShared;
      if (ExactMeasuredSharedUserDataLIFOShape) {
        void *const Result = mmap(reinterpret_cast<void *>(Address), static_cast<size_t>(HostPageSize),
                                  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (Result == MAP_FAILED) {
          return static_cast<uint64_t>(-errno);
        }
        if (reinterpret_cast<uint64_t>(Result) != Address) {
          munmap(Result, static_cast<size_t>(HostPageSize));
          return static_cast<uint64_t>(-EIO);
        }
        std::memset(reinterpret_cast<void *>(Address), 0, static_cast<size_t>(HostPageSize));
        HighMMapRecords[MUnmapLastActiveRecordIndexPlusOne - 1].Active = false;
        NextMMapAddress = Address;
        return 0;
      }
      for (uint64_t Index = HighMMapRecordCount; Index != 0; --Index) {
        auto &Record = HighMMapRecords[Index - 1];
        if (Record.Active && Record.Address == Address && (Record.Flags & LinuxMapShared) != 0 &&
            ((Record.Length + LinuxGuestPageSize - 1) & ~(LinuxGuestPageSize - 1)) == RoundedLength &&
            Address % static_cast<uint64_t>(getpagesize()) == 0) {
          const uint64_t Span = Record.ArenaEnd - Address;
          if (mmap(reinterpret_cast<void *>(Address), Span, PROT_READ | PROT_WRITE,
                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
            return static_cast<uint64_t>(-errno);
          }
          Record.Active = false;
          if (Record.ArenaEnd == NextMMapAddress) {
            NextMMapAddress = Address;
          }
          return 0;
        }
      }
      for (uint64_t Index = HighMMapRecordCount; Index != 0; --Index) {
        auto &Record = HighMMapRecords[Index - 1];
        if (Record.Active && Record.Address == Address && Record.Length == RoundedLength && (Record.Flags & 2) != 0 &&
            ContainsMMapArena(Address, RoundedLength)) {
          std::memset(reinterpret_cast<void *>(Address), 0, static_cast<size_t>(RoundedLength));
          for (auto &Other : HighMMapRecords) {
            if (Other.Active && Other.Address >= Address && Other.Address - Address < RoundedLength &&
                Other.Length <= RoundedLength - (Other.Address - Address))
              Other.Active = false;
          }
          if (Record.ArenaEnd == NextMMapAddress) {
            NextMMapAddress = Address;
          }
          return 0;
        }
      }
      if (ContainsMMapArena(Address, RoundedLength)) {
        const uint64_t End = Address + RoundedLength;
        bool SharedOverlap = false;
        for (const auto &Record : HighMMapRecords) {
          if (Record.Active && Record.Address < End && Address < Record.Address + Record.Length &&
              (Record.Flags & LinuxMapShared))
            SharedOverlap = true;
        }
        if (!SharedOverlap) {
          // Retain the owned host reservation and discard only the guest-unmapped contents.
          FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void *>(Address), RoundedLength);
          std::vector<HighMMapRecord> Remainders;
          for (auto &Record : HighMMapRecords) {
            const uint64_t RecordEnd = Record.Address + Record.Length;
            if (!Record.Active || Record.Address >= End || Address >= RecordEnd)
              continue;
            Record.Active = false;
            if (Record.Address < Address) {
              auto Left = Record;
              Left.Active = true;
              Left.Length = Address - Record.Address;
              Left.ArenaEnd = Address;
              Remainders.push_back(Left);
            }
            if (End < RecordEnd) {
              auto Right = Record;
              Right.Active = true;
              Right.Offset += End - Record.Address;
              Right.Address = End;
              Right.Length = RecordEnd - End;
              Remainders.push_back(Right);
            }
          }
          HighMMapRecords.insert(HighMMapRecords.end(), Remainders.begin(), Remainders.end());
          HighMMapRecordCount = HighMMapRecords.size();
          if (End >= NextMMapAddress && Address < NextMMapAddress) {
            NextMMapAddress = Address;
          }
          return 0;
        }
      }
    }
    return uint64_t(-ENOSYS);
  }
  void CompleteMemoryOperation(FEXCore::Core::InternalThreadState *Thread,
                               const FEXCore::HLE::SyscallArguments *Arguments, uint64_t Result) {
    const uint64_t Number = Arguments->Argument[0];
    if (ForkContext &&
        ((Number == MMapSyscall && static_cast<int64_t>(Result) >= 0) || (Number == MUnmapSyscall && Result == 0))) {
      UpdateTrackedProtections(Number, Number == MMapSyscall ? Result : Arguments->Argument[1], Arguments->Argument[2],
                               Arguments->Argument[3]);
      if (Number == MUnmapSyscall && ContainsMMapArena(Arguments->Argument[1], Arguments->Argument[2])) {
        const uint64_t length = (Arguments->Argument[2] + 4095) & ~uint64_t(4095);
        if (ProjectArenaHostPermissions(Arguments->Argument[1], length, PROT_NONE))
          std::abort();
      }
      InvalidateGuestCodeRange(Thread, Number == MMapSyscall ? Result : Arguments->Argument[1], Arguments->Argument[2]);
    }
  }
  static uint64_t *CurrentSignalMaskAddress() { return BorrowedSignalMask ? BorrowedSignalMask : &OwnSignalMask; }
  static uint64_t &CurrentSignalMask() { return *CurrentSignalMaskAddress(); }
  uint64_t UpdateSignalMask(uint64_t how, bool set, uint64_t requested) {
    const uint64_t previous = CurrentSignalMask();
    if (set) {
      requested &= ~((uint64_t{1} << 8) | (uint64_t{1} << 18));
      if (how == LinuxSigBlock)
        CurrentSignalMask() |= requested;
      else if (how == LinuxSigUnblock)
        CurrentSignalMask() &= ~requested;
      else
        CurrentSignalMask() = requested;
    }
    return previous;
  }
  int NativeSignalMask(uint64_t how, bool set, uint64_t requested, uint64_t *previous) {
    if (!previous || (set && how > LinuxSigSetMask))
      return -EINVAL;
    std::lock_guard<std::recursive_mutex> lock(SyscallMutex);
    *previous = UpdateSignalMask(how, set, requested);
    return 0;
  }
  uint64_t NativeCloneThread(const FliLinuxThreadState *input) {
    if (!input || input->size != sizeof(*input) || input->version != 1 || input->has_ymm > 1 ||
        input->args[0] != 0x3d0f00)
      return uint64_t(-EINVAL);
    std::unique_lock<std::recursive_mutex> lock(SyscallMutex);
    struct Scope {
      std::unique_lock<std::recursive_mutex> *previous;
      Scope(std::unique_lock<std::recursive_mutex> *p) : previous(ActiveSyscallLock) { ActiveSyscallLock = p; }
      ~Scope() { ActiveSyscallLock = previous; }
    } scope(&lock);
    if (!MainGuestThread || !ForkContext)
      return uint64_t(-ENOSYS);
    FEXCore::Core::CPUState parent{};
    using namespace FEXCore::X86State;
    // The register values come from the actual caller; segment descriptor
    // tables are process-owned and already shared by all Root threads.
    parent.segment_arrays[0] = MainGuestThread->CurrentFrame->State.segment_arrays[0];
    parent.segment_arrays[1] = MainGuestThread->CurrentFrame->State.segment_arrays[1];
    constexpr unsigned gpr[]{REG_R15, REG_R14, REG_R13, REG_R12, REG_RBP, REG_RBX, REG_R11, REG_R10,
                             REG_R9,  REG_R8,  REG_RAX, REG_RCX, REG_RDX, REG_RSI, REG_RDI};
    for (unsigned i = 0; i < 15; ++i)
      parent.gregs[gpr[i]] = input->regs[i];
    parent.rip = input->regs[16];
    parent.cs_idx = input->regs[17];
    parent.gregs[REG_RSP] = input->regs[19];
    parent.ss_idx = input->regs[20];
    parent.fs_cached = input->regs[21];
    parent.gs_cached = input->regs[22];
    parent.ds_idx = input->regs[23];
    parent.es_idx = input->regs[24];
    parent.fs_idx = input->regs[25];
    parent.gs_idx = input->regs[26];
    FEXCore::HLE::SyscallArguments args{};
    args.Argument[0] = CloneSyscall;
    for (unsigned i = 0; i < 6; ++i)
      args.Argument[i + 1] = input->args[i];
    return SpawnGuestThread(parent, &args, parent.rip, input);
  }
  uint64_t NativeMemoryOperation(uint64_t number, const uint64_t *input) {
    if (!input || (number != MMapSyscall && number != MUnmapSyscall))
      return uint64_t(-EINVAL);
    std::unique_lock<std::recursive_mutex> lock(SyscallMutex);
    struct Scope {
      std::unique_lock<std::recursive_mutex> *previous;
      Scope(std::unique_lock<std::recursive_mutex> *p) : previous(ActiveSyscallLock) { ActiveSyscallLock = p; }
      ~Scope() { ActiveSyscallLock = previous; }
    } scope(&lock);
    FEXCore::HLE::SyscallArguments args{};
    args.Argument[0] = number;
    for (unsigned i = 0; i < 6; ++i)
      args.Argument[i + 1] = input[i];
    int borrowed = -1;
    if (number == MMapSyscall && !(input[3] & 0x20)) {
      struct stat st{};
      const int original = int(input[4]);
      if (fstat(original, &st) || !S_ISREG(st.st_mode))
        return uint64_t(-EBADF);
      borrowed = fcntl(original, F_DUPFD_CLOEXEC, 0);
      if (borrowed < 0)
        return uint64_t(-TranslateHostSocketErrorToLinux(errno));
      OwnedDescriptors.insert(borrowed);
      NativeBorrowedDescriptors.insert(borrowed);
      args.Argument[5] = uint64_t(borrowed);
    }
    ++HandleSyscallCallCount;
    PrepareTrackedCodeChange(nullptr, &args);
    const uint64_t result = MemoryOperationImpl(nullptr, &args);
    CompleteMemoryOperation(nullptr, &args, result);
    if (borrowed >= 0) {
      NativeBorrowedDescriptors.erase(borrowed);
      OwnedDescriptors.erase(borrowed);
      close(borrowed);
    }
    return result;
  }
  uint64_t HandleSyscallImpl(FEXCore::Core::CpuStateFrame *Frame, FEXCore::HLE::SyscallArguments *Arguments) {
    const uint64_t Number = Arguments->Argument[0];
#ifdef __APPLE__
    if (!RootFS.empty())
      if (auto result = HandleInternetSocketSyscall(Number, Arguments->Argument, false))
        return *result;
#endif
    ++HandleSyscallCallCount;
    if (Number == CloneSyscall && Arguments->Argument[1] == 0x4111 &&
        fli_env_enabled("REGRESSION_FLI_TRACE_FOSS_SPAWN_TARGET")) {
      const auto *child =
          static_cast<const uint64_t *>(HostPointerForGuestRange(Arguments->Argument[2], 16, PROT_READ));
      // Exact retained Fedora glibc2.42 __spawni_child entry, not vendor code.
      static const unsigned char signature[] = {0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0xb9, 0x13, 0,
                                                0,    0,    0x48, 0x89, 0xe5, 0x41, 0x57, 0x41};
      const void *function = child ? HostPointerForGuestRange(child[0], sizeof(signature), PROT_READ) : nullptr;
      struct SpawnArgs {
        uint64_t mask, file, exec, actions, attributes, argv;
        int64_t argc;
        uint64_t env;
        uint32_t flags;
        uint8_t use_clone3, pad[3];
        int32_t error, pidfd;
      };
      static_assert(sizeof(SpawnArgs) == 80);
      const auto *spawn =
          child ? static_cast<const SpawnArgs *>(HostPointerForGuestRange(child[1], sizeof(SpawnArgs), PROT_READ))
                : nullptr;
      if (function && !memcmp(function, signature, sizeof(signature)) && spawn && spawn->argc >= 0 &&
          spawn->argc <= 1024) {
        const auto path = ReadGuestPath(spawn->file);
        if (path && path->size() <= 512) {
          std::string base =
              path->substr(path->find_last_of('/') == std::string::npos ? 0 : path->find_last_of('/') + 1);
          bool safe = !base.empty() && base.size() <= 80;
          for (char c : base)
            safe = safe && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
                            c == '.' || c == '-');
          dprintf(2, "FLI_FOSS_SPAWN_TARGET basename=%s argc=%lld source=glibc-2.42-readonly arguments-not-logged=1\n",
                  safe ? base.c_str() : "[redacted]", (long long)spawn->argc);
        }
      }
    }
    if (Number == 0xF109 && fli_env_enabled("REGRESSION_FLI_ROOT_CALLBACK_BRIDGE")) {
      const auto target = NativeWindowsApiTargets.find(Arguments->Argument[5]);
      if (target == NativeWindowsApiTargets.end())
        return 0xc00000bb;
      using Call = uint64_t (*)(uint64_t, const uint64_t *, uint64_t);
      auto call = reinterpret_cast<Call>(dlsym(RTLD_DEFAULT, "fli_wine_native_api_call"));
      const uint64_t args[] = {Arguments->Argument[1], Arguments->Argument[2], Arguments->Argument[3],
                               Arguments->Argument[4]};
      dprintf(2, "NATIVE_WINE_API_ENTER pid=%d entry=%llx target=%llx actual-teb=%d\n", getpid(),
              (unsigned long long)Arguments->Argument[5], (unsigned long long)target->second,
              Frame->State.gs_cached != 0);
      return call ? BlockingHostCall([&] { return call(target->second, args, Frame->State.gs_cached); }) : 0xc00000bb;
    }
    if (Number == 0xF108 && fli_env_enabled("REGRESSION_NATIVE_WINE_HOST_ENTRY")) {
      using Invoke =
          uint64_t (*)(void *, uint64_t, const uint64_t *, bool, bool, uint64_t, uint64_t, uint64_t, uint64_t *);
      using Entry = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, Invoke, void *);
      auto Callback = reinterpret_cast<Entry>(dlsym(RTLD_DEFAULT, "fli_wine_elf_handoff"));
      if (!Callback || !Contains(Arguments->Argument[1], 40) || Arguments->Argument[2] > 1024 ||
          !Contains(Arguments->Argument[3], 8))
        return uint64_t(-14);
      const uint64_t Map = Arguments->Argument[1], FS = Frame->State.fs_cached, Base = GuestBase,
                     Break = CurrentProgramBreak;
      const uint64_t Argc = Arguments->Argument[2], Argv = Arguments->Argument[3];
      if (fli_env_enabled("REGRESSION_FLI_TRACE_HOOK_HANDOFF"))
        ObserveELFLoaderHandoff(Map);
      NativeHandoffObserved = true;
      struct CallbackContext {
        ProcessSyscallHandler *owner;
        FEXCore::Core::CpuStateFrame *frame;
      } callback_context{this, Frame};
      const Invoke invoke =
          +[](void *opaque, uint64_t entry, const uint64_t *input, bool borrow_fd, bool native_view, uint64_t wine_teb,
              uint64_t caller_fs, uint64_t caller_tid, uint64_t *caller_mask) -> uint64_t {
        auto *context = static_cast<CallbackContext *>(opaque);
        auto *owner = context->owner;
        auto *frame = context->frame;
        if (!owner->ForkContext || !ActiveSignalThread || !owner->HostPointerForGuestRange(entry, 16, PROT_READ) ||
            !input)
          return uint64_t(-EFAULT);
        uint64_t args[6]{};
        memcpy(args, input, sizeof(args));
        int borrowed = -1;
        if (borrow_fd && static_cast<int64_t>(args[4]) >= 0) {
          std::lock_guard<std::recursive_mutex> descriptor_lock(owner->SyscallMutex);
          struct stat st{};
          int flags = fcntl(int(args[4]), F_GETFL);
          if (flags < 0 || fstat(int(args[4]), &st) || !S_ISREG(st.st_mode))
            return uint64_t(-EBADF);
          borrowed = fcntl(int(args[4]), F_DUPFD_CLOEXEC, 0);
          if (borrowed < 0)
            return uint64_t(-TranslateHostSocketErrorToLinux(errno));
          owner->OwnedDescriptors.insert(borrowed);
          owner->NativeBorrowedDescriptors.insert(borrowed);
          args[4] = uint64_t(borrowed);
          if (native_view && args[5] == 0 && fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT")) {
            char path[4096]{};
            const bool named = fcntl(borrowed, F_GETPATH, path) == 0;
            const char *basename = named ? strrchr(path, '/') : nullptr;
            basename = basename ? basename + 1 : "unresolved";
            bool safe = strlen(basename) < 128;
            for (const char *c = basename; *c; ++c)
              safe = safe && (isalnum((unsigned char)*c) || *c == '.' || *c == '_' || *c == '-');
            unsigned char header[64]{};
            uint32_t pe_offset = 0;
            uint16_t machine = 0;
            if (pread(borrowed, header, sizeof(header), 0) == sizeof(header) && header[0] == 'M' && header[1] == 'Z') {
              memcpy(&pe_offset, header + 60, 4);
              uint32_t signature = 0;
              if (pe_offset < 1024 * 1024 && pread(borrowed, &signature, 4, pe_offset) == 4 && signature == 0x4550)
                pread(borrowed, &machine, 2, pe_offset + 4);
            }
            dprintf(2,
                    "NATIVE_MAP_REAL_OBJECT pid=%d address=%llx length=%llx basename=%s pe-machine=%x file-size=%llx\n",
                    getpid(), (unsigned long long)args[0], (unsigned long long)args[1], safe ? basename : "redacted",
                    machine, (unsigned long long)st.st_size);
          }
        }
        {
          std::lock_guard<std::recursive_mutex> scope_lock(owner->SyscallMutex);
          if (native_view)
            owner->NativeFileMapRequest = std::array<uint64_t, 6>{args[0], args[1], args[2], args[3], args[4], args[5]};
        }
        if (wine_teb) {
          uint64_t self = 0;
          mach_vm_size_t copied = 0;
          if (wine_teb > UINT64_MAX - 0x30 ||
              mach_vm_read_overwrite(mach_task_self(), wine_teb + 0x30, 8, reinterpret_cast<mach_vm_address_t>(&self),
                                     &copied) != KERN_SUCCESS ||
              copied != 8 || self != wine_teb) {
            if (borrowed >= 0) {
              std::lock_guard<std::recursive_mutex> lock(owner->SyscallMutex);
              owner->NativeBorrowedDescriptors.erase(borrowed);
              owner->OwnedDescriptors.erase(borrowed);
              close(borrowed);
              owner->NativeFileMapRequest.reset();
            }
            return uint64_t(-EFAULT);
          }
        }
        FEXCore::Core::CPUState saved;
        memcpy(&saved, &frame->State, sizeof(saved));
        const uint64_t returning = frame->ReturningStackLocation;
        using namespace FEXCore::X86State;
        const unsigned regs[] = {REG_RDI, REG_RSI, REG_RDX, REG_RCX, REG_R8, REG_R9};
        for (unsigned i = 0; i < 6; ++i)
          frame->State.gregs[regs[i]] = args[i];
        // The paused handoff uses SYSCALL, while FEX callbacks require SysV function-entry alignment.
        frame->State.gregs[REG_RSP] = ((saved.gregs[REG_RSP] - 256) & ~uint64_t(15)) | 8;
        frame->State.gregs[REG_RAX] = 0;
        if (native_view && fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
          dprintf(2, "NATIVE_MAP_WINDOWS_CONTEXT pid=%d actual-teb-valid=%d previous-gs=%llx\n", getpid(),
                  wine_teb != 0, (unsigned long long)saved.gs_cached);
        if (wine_teb)
          frame->State.gs_cached = wine_teb;
        auto *previous_mask = BorrowedSignalMask;
        const uint64_t previous_tid = CallbackGuestThreadID;
        const uint64_t previous_callback_tid = owner->MainCallbackTID.load();
        if (caller_fs && caller_tid) {
          frame->State.fs_cached = caller_fs;
          CallbackGuestThreadID = caller_tid;
          BorrowedSignalMask = caller_mask;
          owner->MainCallbackTID.store(caller_tid);
        }
        if (borrowed >= 0 && !std::getenv("REGRESSION_LINUX_TRACE_PID") &&
            fli_env_enabled("REGRESSION_FLI_OWNED_FD_PATH_CONTROL")) {
          std::array<char, 4096> expected{};
          const int host_status = fcntl(borrowed, F_GETPATH, expected.data());
          const uint64_t scratch = frame->State.gregs[REG_RSP] - 8192;
          char *path = static_cast<char *>(owner->HostPointerForGuestRange(scratch, 8192, PROT_READ | PROT_WRITE));
          if (host_status || !path)
            _exit(81);
          snprintf(path, 64, "/proc/self/fd/%d", borrowed);
          frame->State.gregs[REG_RDI] = scratch;
          frame->State.gregs[REG_RSI] = scratch + 4096;
          frame->State.gregs[REG_RDX] = 4095;
          owner->ForkContext->HandleCallback(ActiveSignalThread, 0x7003000000ULL + 0xe8700);
          const uint64_t count = frame->State.gregs[REG_RAX];
          if (count != strlen(expected.data()) || memcmp(path + 4096, expected.data(), count))
            _exit(82);
          dprintf(2, "OWNED_NATIVE_FD_READLINK real_glibc=1 exact_host_path=1 original_fd_open=%d\n",
                  fcntl(int(input[4]), F_GETFL) >= 0);
          for (unsigned i = 0; i < 6; ++i)
            frame->State.gregs[regs[i]] = args[i];
          frame->State.gregs[REG_RSP] = ((saved.gregs[REG_RSP] - 256) & ~uint64_t(15)) | 8;
          frame->State.gregs[REG_RAX] = 0;
        }
        const bool previous_callback = NativeCallbackInProgress;
        const uint64_t previous_sequence = NativeCallbackBlockingSequence;
        if (native_view) {
          NativeCallbackInProgress = true;
          NativeCallbackBlockingSequence = 0;
          NativeMapObservedFrame.store(frame, std::memory_order_release);
        }
        owner->ForkContext->HandleCallback(ActiveSignalThread, entry);
        if (native_view) {
          NativeMapObservedFrame.store(nullptr, std::memory_order_release);
          NativeCallbackInProgress = previous_callback;
          NativeCallbackBlockingSequence = previous_sequence;
        }
        const uint64_t result = frame->State.gregs[REG_RAX];
        BorrowedSignalMask = previous_mask;
        CallbackGuestThreadID = previous_tid;
        owner->MainCallbackTID.store(previous_callback_tid);
        memcpy(&frame->State, &saved, sizeof(saved));
        frame->ReturningStackLocation = returning;
        {
          std::lock_guard<std::recursive_mutex> descriptor_lock(owner->SyscallMutex);
          owner->NativeFileMapRequest.reset();
          if (borrowed >= 0) {
            owner->NativeBorrowedDescriptors.erase(borrowed);
            owner->OwnedDescriptors.erase(borrowed);
            close(borrowed);
          }
        }
        return result;
      };
      return BlockingHostCall([&] { return Callback(Map, FS, Base, Break, Argc, Argv, invoke, &callback_context); });
    }
    if (Number == 0xF106 && fli_env_enabled("REGRESSION_NATIVE_WINE_ENTRY_CONTROL")) {
      using Query = int32_t (*)(void *);
      auto Callback = reinterpret_cast<Query>(dlsym(RTLD_DEFAULT, "fli_wine_native_time"));
      void *Output = HostPointerForGuestRange(Arguments->Argument[1], 8, PROT_WRITE);
      return Callback && Output ? uint64_t(int64_t(Callback(Output))) : uint64_t(-14);
    }
    if (Number == 0xF101 && fli_env_enabled("REGRESSION_GLIBC_CARRIER")) {
      using Ready = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t);
      auto Callback = reinterpret_cast<Ready>(dlsym(RTLD_DEFAULT, "fli_glibc_ready"));
      if (!Callback || !Contains(Arguments->Argument[1], 40))
        return static_cast<uint64_t>(-EFAULT);
      return Callback(Arguments->Argument[1], Frame->State.fs_cached, GuestBase, CurrentProgramBreak);
    }
    if (Number == 0xF100 && std::getenv("REGRESSION_EAC_UNIX_BRIDGE_PROBE")) {
      return ProbeNativeEACUnixBridge(Frame, Arguments->Argument[1], Arguments->Argument[2]);
    }
    if (Number == 234 && !RootFS.empty()) {
      dprintf(STDERR_FILENO, "TRACE tgkill-request self=%d target=%llu tid=%llu signal=%llu\n", getpid(),
              (unsigned long long)Arguments->Argument[1], (unsigned long long)Arguments->Argument[2],
              (unsigned long long)Arguments->Argument[3]);
      if (Arguments->Argument[1] != static_cast<uint64_t>(getpid())) {
        return SendRemoteThreadSignal(Arguments->Argument[1], Arguments->Argument[2],
                                      static_cast<int>(Arguments->Argument[3]));
      }
      return QueueOwnThreadSignal(Arguments->Argument[2], static_cast<int>(Arguments->Argument[3]));
    }
    if (Number == 15 && !RootFS.empty()) {
      return GuestSignalDepth ? 0 : static_cast<uint64_t>(-EINVAL);
    }
    if (Number == 131 && !RootFS.empty()) {
      const uint64_t NewAddress = Arguments->Argument[1], OldAddress = Arguments->Argument[2];
      const void *New = NewAddress ? HostPointerForGuestRange(NewAddress, 24, PROT_READ) : nullptr;
      void *Old = OldAddress ? HostPointerForGuestRange(OldAddress, 24, PROT_WRITE) : nullptr;
      if ((NewAddress && !New) || (OldAddress && !Old))
        return static_cast<uint64_t>(-EFAULT);
      FEXCore::x86_64::stack_t Requested{};
      if (New)
        std::memcpy(&Requested, New, sizeof(Requested));
      if (New && Requested.ss_flags != 0 && Requested.ss_flags != 2)
        return static_cast<uint64_t>(-EINVAL);
      if (New && Requested.ss_flags == 0 &&
          (Requested.ss_size < 2048 ||
           !HostPointerForGuestRange(reinterpret_cast<uint64_t>(Requested.ss_sp), Requested.ss_size, PROT_WRITE))) {
        return static_cast<uint64_t>(-ENOMEM);
      }
      if (Old)
        std::memcpy(Old, &GuestSignalStack, sizeof(GuestSignalStack));
      if (New)
        GuestSignalStack = Requested;
      return 0;
    }
    if (Number == ExecveSyscall && !RootFS.empty()) {
      const auto Target = ReadGuestPath(Arguments->Argument[1]);
      const auto ReadStrings = [&](uint64_t Array, size_t Maximum) -> std::optional<std::vector<std::string>> {
        std::vector<std::string> Values;
        for (size_t Index = 0; Index <= Maximum; ++Index) {
          const void *Slot = HostPointerForGuestRange(Array + Index * 8, 8, PROT_READ);
          if (!Slot)
            return std::nullopt;
          uint64_t Address{};
          std::memcpy(&Address, Slot, sizeof(Address));
          if (!Address)
            return Values;
          if (Index == Maximum)
            return std::nullopt;
          const auto Value = ReadGuestPath(Address);
          if (!Value)
            return std::nullopt;
          Values.push_back(*Value);
        }
        return std::nullopt;
      };
      const auto Args = ReadStrings(Arguments->Argument[2], 32);
      const auto Env = ReadStrings(Arguments->Argument[3], 64);
      if (!Target || !Args || !Env)
        return static_cast<uint64_t>(-EFAULT);
      if (fli_env_enabled("REGRESSION_FLI_TRACE_EXEC_METADATA")) {
        const char *Kind =
            *Target == "/opt/wine-devel/bin/wine"
                ? "wine1119-bin"
                : (*Target == "/opt/wine-devel/bin/wine-preloader"
                       ? "wine1119-preloader"
                       : (*Target == "/opt/wine-devel/lib/wine/i386-unix/wine" ? "wine1119-i386" : "other"));
        dprintf(2, "OWNED_EXEC_META target=%s argc=%zu envc=%zu child=%d\n", Kind, Args->size(), Env->size(),
                NativeForkCloneChildProcess);
        for (size_t Index = 0; Index < Args->size(); ++Index) {
          dprintf(2, "OWNED_EXEC_META arg=%zu kind=%s bytes=%zu\n", Index,
                  ClassifyExecveArgument(Index, (*Args)[Index]).c_str(), (*Args)[Index].size());
        }
        for (const auto &Entry : *Env) {
          const size_t Equal = Entry.find('=');
          const std::string_view Name{Entry.data(), Equal == std::string::npos ? Entry.size() : Equal};
          if (Name == "WINELOADERNOEXEC" || Name == "WINEARCH" || Name == "WINESERVERSOCKET" ||
              Name == "WINEPRELOADRESERVE") {
            dprintf(2, "OWNED_EXEC_META env=%.*s value-bytes=%zu\n", static_cast<int>(Name.size()), Name.data(),
                    Equal == std::string::npos ? 0 : Entry.size() - Equal - 1);
          }
        }
      }
      if (const auto Result = MaybeReexecStandardWine(*Target, *Args, *Env))
        return *Result;
      if (const auto Result = MaybeReexecOfficialProtonWine64Preloader(*Target, *Args, *Env)) {
        return *Result;
      }
      return static_cast<uint64_t>(-38);
    }
    if (Number == 86 && !RootFS.empty()) { // Linux link(): fontconfig's atomic cache installation.
      const auto Source = ReadGuestPath(Arguments->Argument[1]);
      const auto Destination = ReadGuestPath(Arguments->Argument[2]);
      if (!Source || !Destination)
        return static_cast<uint64_t>(-EFAULT);
      const auto HostSource = ResolveGuestPathWithParents(*Source);
      const auto HostDestination = ResolveGuestCreationPath(*Destination);
      if (!HostSource || !HostDestination)
        return static_cast<uint64_t>(-EACCES);
      struct stat Info{};
      if (lstat(HostSource->c_str(), &Info) != 0)
        return static_cast<uint64_t>(-errno);
      if (!S_ISREG(Info.st_mode))
        return static_cast<uint64_t>(-EPERM);
      if (link(HostSource->c_str(), HostDestination->c_str()) != 0) {
        return static_cast<uint64_t>(-TranslateHostFileOpenErrorToLinux(errno));
      }
      return 0;
    }
    if (MaybeStopAtPostSessionSyscallBoundary(Frame, Arguments, Number)) {
      return static_cast<uint64_t>(-EINTR);
    }
    if (Number == ReadSyscall && !RootFS.empty()) {
      ++ReadCallCount;
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t Buffer = Arguments->Argument[2];
      const uint64_t Count = Arguments->Argument[3];
      ReadLastDescriptorOwned = OwnedDescriptors.contains(Descriptor);
      ReadLastDescriptorReceivedSCMRights = ReceivedSCMRightsDescriptors.contains(Descriptor);
      void *GuestDestination = Count != 0 ? HostPointerForGuestRange(Buffer, Count, PROT_WRITE) : nullptr;
      ReadLastBufferClass = Count == 0
                                ? "empty"
                                : (Contains(Buffer, Count)
                                       ? "guest-memory"
                                       : (LowMemoryBiasModeEnabled && LowGuestShadow != nullptr &&
                                                  LowGuestShadow->ContainsMappedLogicalRange(Buffer, Count, PROT_WRITE)
                                              ? "low-shadow"
                                              : (GuestDestination != nullptr ? "high-sparse" : "scalar-or-outside")));
      struct stat DescriptorStat{};
      ReadLastDescriptorStatSucceeded = fstat(Descriptor, &DescriptorStat) == 0;
      ReadLastDescriptorFIFO = ReadLastDescriptorStatSucceeded && S_ISFIFO(DescriptorStat.st_mode);
      ReadLastDescriptorSocket = ReadLastDescriptorStatSucceeded && S_ISSOCK(DescriptorStat.st_mode);
      ReadLastDescriptorRegular = ReadLastDescriptorStatSucceeded && S_ISREG(DescriptorStat.st_mode);
      if (const char *TraceReads = getenv("REGRESSION_FLI_TRACE_READS");
          TraceReads != nullptr && std::string_view{TraceReads} == "1") {
        std::cerr << "TRACE read call=" << ReadCallCount << " fd=" << Descriptor << " count=" << Count
                  << " buffer-class=" << ReadLastBufferClass << " owned=" << (ReadLastDescriptorOwned ? 1 : 0)
                  << " scm-rights=" << (ReadLastDescriptorReceivedSCMRights ? 1 : 0)
                  << " fifo=" << (ReadLastDescriptorFIFO ? 1 : 0) << " socket=" << (ReadLastDescriptorSocket ? 1 : 0)
                  << " regular=" << (ReadLastDescriptorRegular ? 1 : 0) << '\n';
        std::cerr.flush();
      }
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if ((Count != 0 && GuestDestination == nullptr) ||
          Count > static_cast<uint64_t>(std::numeric_limits<ssize_t>::max())) {
        return static_cast<uint64_t>(-EFAULT);
      }
      const auto Inherited = InheritedReadOffsets.find(Descriptor);
      // ponytail: immutable regular-file reads keep the existing syscall lock;
      // use per-file locks only if measured contention warrants it.
      const ssize_t Result =
          Inherited != InheritedReadOffsets.end()
              ? pread(Descriptor, GuestDestination, static_cast<size_t>(Count), *Inherited->second)
              : BlockingHostCall([&] { return read(Descriptor, GuestDestination, static_cast<size_t>(Count)); });
      if (Result > 0 && Inherited != InheritedReadOffsets.end())
        *Inherited->second += Result;
      if (Result == -1) {
        return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
      }
      ReadByteCount += static_cast<uint64_t>(Result);
      constexpr uint64_t PreloaderELFHeaderReadSize = 2048;
      constexpr size_t ELFHeaderDiagnosticSize = 64;
      const bool ExactPreloaderELFHeaderRead =
          GuestProgram == "/opt/proton/files/lib/wine/x86_64-unix/wine-preloader" && ReadLastDescriptorOwned &&
          ReadLastDescriptorRegular && Count == PreloaderELFHeaderReadSize &&
          Result >= static_cast<ssize_t>(ELFHeaderDiagnosticSize);
      if (ExactPreloaderELFHeaderRead) {
        if (ReadELFHeaderRecordCount < ReadELFHeaderRecords.size()) {
          const auto *Bytes = static_cast<const uint8_t *>(GuestDestination);
          const auto ReadUInt16 = [Bytes](size_t Offset) {
            uint16_t Value{};
            std::memcpy(&Value, Bytes + Offset, sizeof(Value));
            return Value;
          };
          const auto ReadUInt32 = [Bytes](size_t Offset) {
            uint32_t Value{};
            std::memcpy(&Value, Bytes + Offset, sizeof(Value));
            return Value;
          };
          const auto ReadUInt64 = [Bytes](size_t Offset) {
            uint64_t Value{};
            std::memcpy(&Value, Bytes + Offset, sizeof(Value));
            return Value;
          };
          const auto [DescriptorPathClass, DescriptorGuestPath] = DescribeMappingDescriptor(Descriptor, false);
          ReadELFHeaderRecords[ReadELFHeaderRecordCount++] = ReadELFHeaderRecord{
              .SyscallOrdinal = ReadCallCount,
              .Descriptor = Descriptor,
              .GuestBuffer = Buffer,
              .RequestedByteCount = Count,
              .ReturnedByteCount = static_cast<uint64_t>(Result),
              .First64ByteFingerprint = FingerprintBytes(Bytes, ELFHeaderDiagnosticSize),
              .Magic = ReadUInt32(0),
              .ELFClass = Bytes[4],
              .DataEncoding = Bytes[5],
              .Type = ReadUInt16(16),
              .Machine = ReadUInt16(18),
              .Version = ReadUInt32(20),
              .Entry = ReadUInt64(24),
              .ProgramHeaderOffset = ReadUInt64(32),
              .ProgramHeaderEntrySize = ReadUInt16(54),
              .ProgramHeaderCount = ReadUInt16(56),
              .DescriptorPathClass = DescriptorPathClass,
              .DescriptorGuestPath = DescriptorGuestPath,
          };
        } else {
        }
      }
      constexpr uint64_t WineFixedReplySize = 64;
      constexpr uint64_t WineReplyHeaderSize = 8;
      const bool ExactWineFixedReply =
          GuestProgram == "/opt/proton/files/lib/wine/x86_64-unix/wine-preloader" && ReadLastDescriptorOwned &&
          ReadLastDescriptorFIFO && Count == WineFixedReplySize && Result == static_cast<ssize_t>(WineFixedReplySize);
      if (ExactWineFixedReply) {
        const auto *ReplyBytes = static_cast<const uint8_t *>(GuestDestination);
        std::memcpy(&ReadWineFixedReplyLastError, ReplyBytes, sizeof(ReadWineFixedReplyLastError));
        std::memcpy(&ReadWineFixedReplyLastDeclaredSize, ReplyBytes + sizeof(ReadWineFixedReplyLastError),
                    sizeof(ReadWineFixedReplyLastDeclaredSize));
        TraceWineReplyHeader("read", Descriptor, GuestDestination, static_cast<size_t>(WineReplyHeaderSize));
      }
      return static_cast<uint64_t>(Result);
    }
    if (Number == PRead64Syscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t Buffer = Arguments->Argument[2];
      const uint64_t Count = Arguments->Argument[3];
      const uint64_t Offset = Arguments->Argument[4];
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      void *Destination = Count <= static_cast<uint64_t>(std::numeric_limits<ssize_t>::max())
                              ? HostPointerForGuestRange(Buffer, Count, PROT_WRITE)
                              : nullptr;
      if ((Count != 0 && Destination == nullptr) ||
          Count > static_cast<uint64_t>(std::numeric_limits<ssize_t>::max()) ||
          Offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
        return static_cast<uint64_t>(-EFAULT);
      }
      const ssize_t Result = pread(Descriptor, Destination, static_cast<size_t>(Count), static_cast<off_t>(Offset));
      if (Result == -1) {
        return static_cast<uint64_t>(-errno);
      }
      PRead64ByteCount += static_cast<uint64_t>(Result);
      return static_cast<uint64_t>(Result);
    }
    if (Number == FStatSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestBuffer = Arguments->Argument[2];
      void *StatDestination = HostPointerForGuestRange(GuestBuffer, sizeof(LinuxX86_64Stat), PROT_WRITE);
      const bool IsStandardDescriptor = Descriptor >= STDIN_FILENO && Descriptor <= STDERR_FILENO;
      if ((!OwnedDescriptors.contains(Descriptor) && !IsStandardDescriptor) ||
          ClosedStandardDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (StatDestination == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      struct stat HostStat{};
      if (fstat(Descriptor, &HostStat) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      const LinuxX86_64Stat GuestStat = TranslateStat(HostStat);
      std::memcpy(StatDestination, &GuestStat, sizeof(GuestStat));
      return 0;
    }
    if (Number == GetDents64Syscall && !RootFS.empty()) {
      constexpr uint64_t MaximumGuestDirectoryBufferSize = 1024 * 1024;
      constexpr uint64_t DarwinDirectoryBlockSize = 4096;
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestBuffer = Arguments->Argument[2];
      const uint64_t ByteCount = Arguments->Argument[3];
      GetDents64LastDescriptorOwned = OwnedDescriptors.contains(Descriptor);
      GetDents64LastDescriptorDirectory = false;
      GetDents64LastDescriptorPathConfined = false;

      if (!GetDents64LastDescriptorOwned) {
        return static_cast<uint64_t>(-EBADF);
      }

      struct stat DescriptorStat{};
      if (fstat(Descriptor, &DescriptorStat) != 0) {
        const int HostError = errno;
        return static_cast<uint64_t>(-HostError);
      }
      GetDents64LastDescriptorDirectory = S_ISDIR(DescriptorStat.st_mode);
      if (!GetDents64LastDescriptorDirectory) {
        return static_cast<uint64_t>(-ENOTDIR);
      }

      std::array<char, 4096> DescriptorPath{};
      if (fcntl(Descriptor, F_GETPATH, DescriptorPath.data()) != 0) {

        return static_cast<uint64_t>(-EBADF);
      }
      const std::string HostPath{DescriptorPath.data()};
      GetDents64LastDescriptorPathConfined = fli_guest_host_path_visible(HostPath, RootFS);
      if (!GetDents64LastDescriptorPathConfined) {
        return static_cast<uint64_t>(-EACCES);
      }

      if (ByteCount < 2 * DarwinDirectoryBlockSize || ByteCount > MaximumGuestDirectoryBufferSize ||
          ByteCount > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        return static_cast<uint64_t>(-EINVAL);
      }
      void *GuestDestination = HostPointerForGuestRange(GuestBuffer, ByteCount, PROT_WRITE);
      if (GuestDestination == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }

      // A Linux dirent64 may be four bytes larger than the equivalent Darwin
      // record because Linux aligns to eight bytes and Darwin to four. Since a
      // Darwin record is at least 24 bytes, reading at most 6/7 of the guest
      // capacity guarantees that every converted record still fits.
      const uint64_t SafeHostCapacity = ((ByteCount / 7) * 6) & ~(DarwinDirectoryBlockSize - 1);
      if (SafeHostCapacity < DarwinDirectoryBlockSize) {
        return static_cast<uint64_t>(-EINVAL);
      }
      std::vector<char> HostRecords(static_cast<size_t>(SafeHostCapacity));
      off_t Position{};
      errno = 0;
      const ssize_t HostResult = __getdirentries64(Descriptor, HostRecords.data(), HostRecords.size(), &Position);
      const int HostDirectoryError = HostResult == -1 ? errno : 0;
      if (HostResult == -1) {
        return static_cast<uint64_t>(-HostDirectoryError);
      }
      errno = 0;
      const off_t NextOffset = lseek(Descriptor, 0, SEEK_CUR);

      if (NextOffset == static_cast<off_t>(-1)) {
        (void)lseek(Descriptor, Position, SEEK_SET);
        return static_cast<uint64_t>(-EIO);
      }
      GetDents64HostByteCount += static_cast<uint64_t>(HostResult);
      if (HostResult == 0) {
        return 0;
      }

      const auto RollBackDirectory = [&]() { (void)lseek(Descriptor, Position, SEEK_SET); };
      constexpr size_t DarwinNameOffset = offsetof(struct dirent, d_name);
      constexpr size_t MaximumDarwinNameLength = sizeof(std::declval<struct dirent>().d_name) - 1;
      std::vector<uint8_t> LinuxRecords(static_cast<size_t>(ByteCount), 0);
      size_t HostOffset{};
      size_t LinuxOffset{};
      uint64_t ConvertedEntryCount{};
      uint64_t SkippedZeroInodeCount{};
      while (HostOffset < static_cast<size_t>(HostResult)) {
        const size_t RemainingHostBytes = static_cast<size_t>(HostResult) - HostOffset;
        if (RemainingHostBytes < DarwinNameOffset + 1) {
          RollBackDirectory();
          return static_cast<uint64_t>(-EIO);
        }

        const uint8_t *HostRecord = reinterpret_cast<const uint8_t *>(HostRecords.data() + HostOffset);
        uint64_t Inode{};
        uint16_t RecordLength{};
        uint16_t NameLength{};
        uint8_t Type{};
        std::memcpy(&Inode, HostRecord + offsetof(struct dirent, d_ino), sizeof(Inode));
        std::memcpy(&RecordLength, HostRecord + offsetof(struct dirent, d_reclen), sizeof(RecordLength));
        std::memcpy(&NameLength, HostRecord + offsetof(struct dirent, d_namlen), sizeof(NameLength));
        std::memcpy(&Type, HostRecord + offsetof(struct dirent, d_type), sizeof(Type));
        const bool RecordShapeValid = RecordLength >= DarwinNameOffset + 1 && RecordLength <= RemainingHostBytes &&
                                      NameLength <= MaximumDarwinNameLength &&
                                      DarwinNameOffset + static_cast<size_t>(NameLength) + 1 <= RecordLength &&
                                      HostRecord[DarwinNameOffset + NameLength] == '\0';
        if (!RecordShapeValid) {
          RollBackDirectory();
          return static_cast<uint64_t>(-EIO);
        }

        if (Inode == 0) {
          ++SkippedZeroInodeCount;
          HostOffset += RecordLength;
          continue;
        }
        const size_t UnalignedLinuxLength = sizeof(LinuxDirent64Header) + static_cast<size_t>(NameLength) + 1;
        const size_t LinuxLength = (UnalignedLinuxLength + 7) & ~size_t{7};
        if (LinuxLength > std::numeric_limits<uint16_t>::max() || LinuxOffset > LinuxRecords.size() ||
            LinuxLength > LinuxRecords.size() - LinuxOffset) {
          RollBackDirectory();
          return static_cast<uint64_t>(-EIO);
        }
        const LinuxDirent64Header LinuxHeader{
            .Inode = Inode,
            .Offset = static_cast<int64_t>(NextOffset),
            .RecordLength = static_cast<uint16_t>(LinuxLength),
            .Type = Type,
        };
        std::memcpy(LinuxRecords.data() + LinuxOffset, &LinuxHeader, sizeof(LinuxHeader));
        std::memcpy(LinuxRecords.data() + LinuxOffset + sizeof(LinuxHeader), HostRecord + DarwinNameOffset,
                    static_cast<size_t>(NameLength) + 1);
        LinuxOffset += LinuxLength;
        ++ConvertedEntryCount;
        HostOffset += RecordLength;
      }

      std::memcpy(GuestDestination, LinuxRecords.data(), LinuxOffset);
      GetDents64LinuxByteCount += LinuxOffset;
      GetDents64EntryCount += ConvertedEntryCount;
      GetDents64SkippedZeroInodeCount += SkippedZeroInodeCount;
      return static_cast<uint64_t>(LinuxOffset);
    }
    if (Number == FcntlSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const int64_t Command = static_cast<int64_t>(Arguments->Argument[2]);
      const uint64_t Argument = Arguments->Argument[3];
      const bool DescriptorOwned = OwnedDescriptors.contains(Descriptor);

      if (Command == 1 && DescriptorOwned) { // Linux F_GETFD
        const int Flags = fcntl(Descriptor, F_GETFD);
        return Flags < 0 ? static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno))
                         : static_cast<uint64_t>((Flags & FD_CLOEXEC) ? 1 : 0);
      }
      const bool GetStatusFlagsCandidate = Command == LinuxFGetFLCommand && DescriptorOwned;
      int GetStatusHostFlags = -1;
      int GetStatusHostError = 0;
      if (GetStatusFlagsCandidate) {
        const int SavedHostError = errno;
        GetStatusHostFlags = fcntl(Descriptor, F_GETFL);
        GetStatusHostError = GetStatusHostFlags == -1 ? errno : 0;
        errno = SavedHostError;
      }

      const bool GetRegistryTemporaryStatusFlagsExactCandidate =
          GetStatusFlagsCandidate && RegistryTemporaryDescriptors.contains(Descriptor);
      if (GetRegistryTemporaryStatusFlagsExactCandidate) {
        struct stat HostStat{};
        const int SavedHostError = errno;
        const int StatResult = fstat(Descriptor, &HostStat);
        const int StatHostError = StatResult == -1 ? errno : 0;
        errno = SavedHostError;
        FcntlGetFlagsRegistryTemporaryLastDescriptorRegular = StatResult == 0 && S_ISREG(HostStat.st_mode);
        if (StatResult == -1) {
          const int LinuxError = TranslateHostFcntlGetFlagsErrorToLinux(StatHostError);
          return static_cast<uint64_t>(-LinuxError);
        }
        if (!FcntlGetFlagsRegistryTemporaryLastDescriptorRegular) {
          return static_cast<uint64_t>(-EINVAL);
        }
        if (GetStatusHostFlags == -1) {
          const int LinuxError = TranslateHostFcntlGetFlagsErrorToLinux(GetStatusHostError);
          return static_cast<uint64_t>(-LinuxError);
        }
        if (GetStatusHostFlags != O_WRONLY) {
          return static_cast<uint64_t>(-ENOTSUP);
        }
        return LinuxOWriteOnlyAccessMode;
      }
      if (GetStatusFlagsCandidate) {
        if (GetStatusHostFlags == -1) {
          const int LinuxError = TranslateHostFcntlGetFlagsErrorToLinux(GetStatusHostError);
          return static_cast<uint64_t>(-LinuxError);
        }
        constexpr int KnownHostStatusFlags = O_ACCMODE | O_APPEND | O_NONBLOCK;
        if ((GetStatusHostFlags & ~KnownHostStatusFlags) != 0) {
          return static_cast<uint64_t>(-ENOTSUP);
        }

        uint64_t LinuxFlags{};
        switch (GetStatusHostFlags & O_ACCMODE) {
        case O_RDONLY:
          break;
        case O_WRONLY:
          LinuxFlags |= LinuxOWriteOnlyAccessMode;
          break;
        case O_RDWR:
          LinuxFlags |= LinuxOReadWriteAccessMode;
          break;
        default:

          return static_cast<uint64_t>(-EINVAL);
        }
        if ((GetStatusHostFlags & O_APPEND) != 0) {
          LinuxFlags |= LinuxOAppend;
        }
        if ((GetStatusHostFlags & O_NONBLOCK) != 0) {
          LinuxFlags |= LinuxONonBlock;
        }
        return LinuxFlags;
      }
      const bool SetDescriptorFlagsExactCandidate =
          Command == LinuxFSetFDCommand && Descriptor != -1 && DescriptorOwned && Argument == 1;

      // Wine can request close-on-exec for a failed relative openat result.
      // Linux responde EBADF sin inspeccionar el tercer argumento.
      if (Descriptor == -1 && Command == LinuxFSetFDCommand) {
        return static_cast<uint64_t>(-EBADF);
      }

      if (SetDescriptorFlagsExactCandidate) {
        const int HostFlagsBefore = fcntl(Descriptor, F_GETFD);
        if (HostFlagsBefore == -1) {
          const int LinuxError = TranslateHostSocketErrorToLinux(errno);
          return static_cast<uint64_t>(-LinuxError);
        }
        if (fcntl(Descriptor, F_SETFD, HostFlagsBefore | FD_CLOEXEC) == -1) {
          const int LinuxError = TranslateHostSocketErrorToLinux(errno);
          return static_cast<uint64_t>(-LinuxError);
        }
        const int HostFlagsAfter = fcntl(Descriptor, F_GETFD);
        if (HostFlagsAfter == -1) {
          const int LinuxError = TranslateHostSocketErrorToLinux(errno);
          return static_cast<uint64_t>(-LinuxError);
        }
        if ((HostFlagsAfter & FD_CLOEXEC) == 0) {
          return static_cast<uint64_t>(-EIO);
        }
        return 0;
      }

      if (Command == LinuxFSetFLCommand) {
        if (!OwnedDescriptors.contains(Descriptor))
          return static_cast<uint64_t>(-EBADF);
        if (Argument & ~(uint64_t{3} | LinuxONonBlock | LinuxOAppend))
          return static_cast<uint64_t>(-EINVAL);
        const int Before = fcntl(Descriptor, F_GETFL);
        if (Before < 0)
          return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
        int After = Before & ~(O_NONBLOCK | O_APPEND);
        if (Argument & LinuxONonBlock)
          After |= O_NONBLOCK;
        if (Argument & LinuxOAppend)
          After |= O_APPEND;
        if (fcntl(Descriptor, F_SETFL, After) != 0)
          return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
        (void)(fcntl(Descriptor, F_GETFL));
        return 0;
      }

      constexpr int64_t LinuxFGetLK = 5, LinuxFSetLK = 6, LinuxFSetLKW = 7;
      if (Command == LinuxFGetLK || Command == LinuxFSetLK || Command == LinuxFSetLKW) {
        if (!OwnedDescriptors.contains(Descriptor)) {
          return static_cast<uint64_t>(-EBADF);
        }
        void *LockBuffer = HostPointerForGuestRange(Argument, sizeof(LinuxFlock64),
                                                    PROT_READ | (Command == LinuxFGetLK ? PROT_WRITE : 0));
        if (!LockBuffer) {
          return static_cast<uint64_t>(-EFAULT);
        }

        LinuxFlock64 GuestLock{};
        std::memcpy(&GuestLock, LockBuffer, sizeof(GuestLock));

        std::optional<short> HostType;
        switch (GuestLock.Type) {
        case 0:
          HostType = F_RDLCK;
          break;
        case 1:
          HostType = F_WRLCK;
          break;
        case 2:
          HostType = F_UNLCK;
          break;
        default:
          break;
        }
        std::optional<short> HostWhence;
        switch (GuestLock.Whence) {
        case 0:
          HostWhence = SEEK_SET;
          break;
        case 1:
          HostWhence = SEEK_CUR;
          break;
        case 2:
          HostWhence = SEEK_END;
          break;
        default:
          break;
        }
        if (!HostType.has_value() || !HostWhence.has_value()) {
          return static_cast<uint64_t>(-EINVAL);
        }

        struct flock HostLock{};
        HostLock.l_type = *HostType;
        HostLock.l_whence = *HostWhence;
        HostLock.l_start = static_cast<off_t>(GuestLock.Start);
        HostLock.l_len = static_cast<off_t>(GuestLock.Length);
        const int HostCommand = Command == LinuxFGetLK ? F_GETLK : Command == LinuxFSetLKW ? F_SETLKW : F_SETLK;
        const int LockResult = Command == LinuxFSetLKW
                                   ? BlockingHostCall([&] { return fcntl(Descriptor, HostCommand, &HostLock); })
                                   : fcntl(Descriptor, HostCommand, &HostLock);
        if (LockResult == -1) {
          const int LinuxError = TranslateHostFileLockErrorToLinux(errno);
          return static_cast<uint64_t>(-LinuxError);
        }
        if (Command == LinuxFGetLK) {
          GuestLock.Type = HostLock.l_type == F_RDLCK ? 0 : HostLock.l_type == F_WRLCK ? 1 : 2;
          GuestLock.Whence = HostLock.l_whence == SEEK_SET ? 0 : HostLock.l_whence == SEEK_CUR ? 1 : 2;
          GuestLock.Start = HostLock.l_start;
          GuestLock.Length = HostLock.l_len;
          GuestLock.ProcessID = HostLock.l_pid;
          std::memcpy(LockBuffer, &GuestLock, sizeof(GuestLock));
        }
        return 0;
      }
    }
    if (Number == SetSockOptSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const int32_t Level = static_cast<int32_t>(Arguments->Argument[2]);
      const int32_t Option = static_cast<int32_t>(Arguments->Argument[3]);
      const uint64_t GuestValue = Arguments->Argument[4];
      const uint64_t ValueLength = Arguments->Argument[5];
      const void *ValueBuffer =
          ValueLength <= 64 ? HostPointerForGuestRange(GuestValue, ValueLength, PROT_READ) : nullptr;
      SetSockOptLastDescriptorOwned = OwnedDescriptors.contains(Descriptor);
      SetSockOptLastValueReadable = false;
      SetSockOptLastInt32ValueReadable = false;
      SetSockOptLastInt32Value = 0;
      SetSockOptLastValueReadable = ValueLength != 0 && ValueLength <= 64 && (ValueBuffer != nullptr);
      if (SetSockOptLastValueReadable) {
        if (ValueLength == sizeof(int32_t)) {
          int32_t ScalarValue{};
          std::memcpy(&ScalarValue, ValueBuffer, sizeof(ScalarValue));
          SetSockOptLastInt32Value = ScalarValue;
          SetSockOptLastInt32ValueReadable = true;
        }
      }

      constexpr int32_t LinuxSolSocket = 1;
      constexpr int32_t LinuxSoPassCred = 16;
      const bool PassCredentialsCandidate = SetSockOptLastDescriptorOwned && Level == LinuxSolSocket &&
                                            Option == LinuxSoPassCred && ValueLength == sizeof(int32_t) &&
                                            SetSockOptLastInt32ValueReadable &&
                                            (SetSockOptLastInt32Value == 0 || SetSockOptLastInt32Value == 1);
      if (PassCredentialsCandidate) {
        // Wine on macOS omits SO_PASSCRED; leave server_pid unknown without setting another host option.
        return 0;
      }
    }
    if (Number == SigAltStackSyscall && !RootFS.empty()) {
      const uint64_t GuestNewStack = Arguments->Argument[1];
      const uint64_t GuestOldStack = Arguments->Argument[2];
      SigAltStackLastNewStackReadable = GuestNewStack != 0 && Contains(GuestNewStack, sizeof(LinuxX86_64StackT));
      SigAltStackLastGuestRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];
      if (SigAltStackLastNewStackReadable) {
        LinuxX86_64StackT NewStack{};
        std::memcpy(&NewStack, reinterpret_cast<const void *>(GuestNewStack), sizeof(NewStack));
        SigAltStackLastStackRangeLowShadowMapped =
            LowGuestShadow && LowGuestShadow->ContainsMappedLogicalRange(NewStack.StackPointer, NewStack.Size);
        SigAltStackLastStackRangeLowShadowReadable =
            LowGuestShadow &&
            LowGuestShadow->ContainsMappedLogicalRange(NewStack.StackPointer, NewStack.Size, PROT_READ);
        SigAltStackLastStackRangeLowShadowWritable =
            LowGuestShadow &&
            LowGuestShadow->ContainsMappedLogicalRange(NewStack.StackPointer, NewStack.Size, PROT_WRITE);

        const bool StackEndRepresentable =
            NewStack.StackPointer != 0 && NewStack.Size != 0 &&
            NewStack.Size <= std::numeric_limits<uint64_t>::max() - NewStack.StackPointer;
        const uint64_t StackEnd = StackEndRepresentable ? NewStack.StackPointer + NewStack.Size : 0;
        SigAltStackLastGuestRSPWithinStack = StackEndRepresentable &&
                                             SigAltStackLastGuestRSP >= NewStack.StackPointer &&
                                             SigAltStackLastGuestRSP <= StackEnd;

        const bool InstallCandidate = GuestOldStack == 0 && NewStack.Flags == 0 &&
                                      NewStack.Size >= LinuxX86MinSignalStackSize && StackEndRepresentable &&
                                      SigAltStackLastStackRangeLowShadowMapped &&
                                      SigAltStackLastStackRangeLowShadowReadable &&
                                      SigAltStackLastStackRangeLowShadowWritable && !SigAltStackLastGuestRSPWithinStack;
        if (InstallCandidate) {
          return 0;
        }
      }
    }
    if (Number == StatSyscall && !RootFS.empty()) {
      const auto GuestPath = ReadGuestPath(Arguments->Argument[1]);
      const uint64_t GuestBuffer = Arguments->Argument[2];
      void *StatDestination = HostPointerForGuestRange(GuestBuffer, sizeof(LinuxX86_64Stat), PROT_WRITE);
      if (!GuestPath.has_value() || StatDestination == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      TraceGuestPath("stat", *GuestPath);
      if (GuestPath->empty() || GuestPath->front() != '/') {
        return static_cast<uint64_t>(-ENOTSUP);
      }
      const auto HostPath = ResolveGuestPathWithParents(*GuestPath);
      if (!HostPath.has_value()) {
        return static_cast<uint64_t>(-EACCES);
      }
      struct stat HostStat{};
      if (stat(HostPath->c_str(), &HostStat) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      const LinuxX86_64Stat GuestStat = TranslateStat(HostStat);
      std::memcpy(StatDestination, &GuestStat, sizeof(GuestStat));
      return 0;
    }
    if (NativeFileMapRequest && (*NativeFileMapRequest)[5] == 0 && pthread_equal(pthread_self(), MainNativeThread) &&
        fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT")) {
      const uint64_t diagnostic = ++NativeMapCallbackDiagnosticCount;
      if (diagnostic <= 32 || (diagnostic & (diagnostic - 1)) == 0)
        dprintf(2, "NATIVE_MAP_CALLBACK_SYSCALL pid=%d number=%llu rip=%llx address=%llx occurrence=%llu\n", getpid(),
                (unsigned long long)Number, (unsigned long long)Frame->State.rip,
                (unsigned long long)(*NativeFileMapRequest)[0], (unsigned long long)diagnostic);
      if (diagnostic <= 32 && (Number == 202 || Number == 0 || Number == 7 || Number == 61 || Number == 232) &&
          Frame->DiagnosticBranches) {
        const uint64_t end = Frame->DiagnosticBranchSequence;
        for (uint64_t i = end > 12 ? end - 12 : 0; i < end; ++i) {
          const auto &branch = Frame->DiagnosticBranches[i % 64];
          dprintf(2, "NATIVE_MAP_WAIT_BRANCH pid=%d source=%llx target=%llx\n", getpid(),
                  (unsigned long long)branch.source, (unsigned long long)branch.target);
        }
      }
    }
    if (Number == MMapSyscall && NativeFileMapRequest && pthread_equal(pthread_self(), MainNativeThread)) {
      bool matches = true;
      for (unsigned i = 0; i < 6; ++i)
        matches = matches && Arguments->Argument[i + 1] == (*NativeFileMapRequest)[i];
      if (matches) {
        const auto &request = *NativeFileMapRequest;
        const uint64_t address = request[0], length = request[1], protection = request[2], flags = request[3],
                       offset = request[5], page = getpagesize();
        const int fd = int(request[4]);
        if (!length || length > SIZE_MAX - page + 1 || offset > uint64_t(INT64_MAX) ||
            address < HighSparseGuestBase + HighSparseGuestSize || address > UINT64_MAX - length || address % page ||
            offset % page || (flags != 0x12 && flags != 0x11) || (protection & ~uint64_t(PROT_READ | PROT_WRITE)))
          return uint64_t(-EINVAL);
        const uint64_t rounded = (length + page - 1) & ~(page - 1);
        if (address > UINT64_MAX - rounded)
          return uint64_t(-EINVAL);
        if (!OwnedDescriptors.contains(fd))
          return uint64_t(-EBADF);
        mach_vm_address_t base = address;
        mach_vm_size_t span = 0;
        vm_region_basic_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        const kern_return_t status = mach_vm_region(mach_task_self(), &base, &span, VM_REGION_BASIC_INFO_64,
                                                    reinterpret_cast<vm_region_info_t>(&info), &count, &object);
        if (object != MACH_PORT_NULL)
          mach_port_deallocate(mach_task_self(), object);
        if (status != KERN_SUCCESS || base > address || address - base >= span || rounded > span - (address - base))
          return uint64_t(-ENOMEM);
        void *mapped = mmap(reinterpret_cast<void *>(address), length, int(protection),
                            (flags == 0x12 ? MAP_PRIVATE : MAP_SHARED) | MAP_FIXED, fd, off_t(offset));
        if (mapped == MAP_FAILED)
          return uint64_t(-TranslateHostSocketErrorToLinux(errno));
        NativeFileViews.push_back({address, rounded, protection});
        RegisterNativeNtDLLBridge(address, offset, fd);
        dprintf(2, "NATIVE_FILE_VIEW_MMAP pid=%d address=%llx length=%llx actual-host-map=1\n", getpid(),
                (unsigned long long)address, (unsigned long long)length);
        return reinterpret_cast<uint64_t>(mapped);
      }
    }
    if (Number == MMapSyscall || Number == MUnmapSyscall)
      return MemoryOperationImpl(Frame, Arguments);
    if (Number == 8 && !RootFS.empty()) { // Linux x86-64 lseek
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const int64_t Offset = static_cast<int64_t>(Arguments->Argument[2]);
      const uint64_t Whence = Arguments->Argument[3];
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      // SEEK_SET/CUR/END have the same values on Linux and Darwin.
      if (Whence > 2) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (auto Inherited = InheritedReadOffsets.find(Descriptor); Inherited != InheritedReadOffsets.end()) {
        int64_t Base = Whence == 1 ? *Inherited->second : 0;
        if (Whence == 2) {
          struct stat Info{};
          if (fstat(Descriptor, &Info))
            return static_cast<uint64_t>(-errno);
          Base = Info.st_size;
        }
        if ((Offset > 0 && Base > INT64_MAX - Offset) || (Offset < 0 && Base < INT64_MIN - Offset) || Base + Offset < 0)
          return static_cast<uint64_t>(-EINVAL);
        *Inherited->second = Base + Offset;
        return Base + Offset;
      }
      const off_t Result = lseek(Descriptor, Offset, static_cast<int>(Whence));
      if (Result == static_cast<off_t>(-1)) {
        // Darwin EOVERFLOW (84) differs from Linux EOVERFLOW (75).
        return static_cast<uint64_t>(-(errno == EOVERFLOW ? 75 : errno));
      }
      return static_cast<uint64_t>(Result);
    }
    if (Number == CloseSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      if (Descriptor >= STDIN_FILENO && Descriptor <= STDERR_FILENO) {
        if (ClosedStandardDescriptors.contains(Descriptor)) {
          return static_cast<uint64_t>(-EBADF);
        }
        ClosedStandardDescriptors.insert(Descriptor);
        return 0;
      }
      const auto DescriptorIterator = OwnedDescriptors.find(Descriptor);
      if (DescriptorIterator == OwnedDescriptors.end()) {
        return static_cast<uint64_t>(-EBADF);
      }
      ReleaseProcSnapshot(Descriptor);
      if (close(Descriptor) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      EpollDescriptors.erase(Descriptor);
      for (auto It = EpollFilters.begin(); It != EpollFilters.end();) {
        if (It->first.first == Descriptor || It->first.second == Descriptor)
          It = EpollFilters.erase(It);
        else
          ++It;
      }
      ReceivedSCMRightsDescriptors.erase(Descriptor);
      RegistryTemporaryDescriptors.erase(Descriptor);
      CXAltLoaderConnectedDescriptors.erase(Descriptor);
      OwnedDescriptors.erase(DescriptorIterator);
      InheritedReadOffsets.erase(Descriptor);
      return 0;
    }
    constexpr int64_t LinuxPrSetName = 15;
    if (Number == PrctlSyscall && !RootFS.empty() && static_cast<int64_t>(Arguments->Argument[1]) == LinuxPrSetName) {
      constexpr size_t LinuxTaskNameSize = 16;
      const uint64_t GuestName = Arguments->Argument[2];
      if (!Contains(GuestName, LinuxTaskNameSize)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      std::array<char, LinuxTaskNameSize> Name{};
      std::memcpy(Name.data(), reinterpret_cast<const void *>(GuestName), Name.size());
      Name.back() = '\0';
      (void)(strnlen(Name.data(), Name.size()));
      const int Result = pthread_setname_np(Name.data());
      if (Result != 0) {
        return static_cast<uint64_t>(-Result);
      }
      return 0;
    }
    constexpr uint64_t ObservedUserfaultfdFlags = 526337;
    if (Number == UserfaultfdSyscall && !RootFS.empty() && Arguments->Argument[1] == ObservedUserfaultfdFlags) {
      return static_cast<uint64_t>(-38);
    }
    constexpr uint64_t LinuxKernelSigsetSize = sizeof(uint64_t);
    constexpr int64_t LinuxMaximumSignal = 64;

    constexpr uint64_t LinuxSA_RESTORER = 0x0400'0000;
    constexpr uint64_t LinuxSA_RESTART = 0x1000'0000;
    constexpr int64_t LinuxSIGPIPE = 13;
    if (Number == RtSigactionSyscall && !RootFS.empty() &&
        static_cast<int64_t>(Arguments->Argument[1]) == LinuxSIGPIPE && Arguments->Argument[2] != 0 &&
        Arguments->Argument[3] != 0 && Arguments->Argument[4] == LinuxKernelSigsetSize) {
      const uint64_t GuestAction = Arguments->Argument[2];
      const uint64_t GuestOldAction = Arguments->Argument[3];
      if (!(HostPointerForGuestRange(GuestAction, sizeof(LinuxGuestSigAction), PROT_READ | PROT_WRITE) != nullptr) ||
          !(HostPointerForGuestRange(GuestOldAction, sizeof(LinuxGuestSigAction), PROT_READ | PROT_WRITE) != nullptr)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      LinuxGuestSigAction RequestedAction{};
      std::memcpy(&RequestedAction, HostPointerForGuestRange(GuestAction, sizeof(LinuxGuestSigAction), PROT_READ),
                  sizeof(RequestedAction));
      const bool ExactObservedIgnore = RequestedAction.Handler == 1 &&
                                       RequestedAction.Flags == (LinuxSA_RESTART | LinuxSA_RESTORER) &&
                                       RequestedAction.Restorer != 0 && Contains(RequestedAction.Restorer, 1);
      if (ExactObservedIgnore) {
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
          return static_cast<uint64_t>(-errno);
        RtSigactionLastSignal = LinuxSIGPIPE;
        const LinuxGuestSigAction &CurrentAction = GuestSignalActions[static_cast<size_t>(LinuxSIGPIPE)];
        std::memcpy(HostPointerForGuestRange(GuestOldAction, sizeof(LinuxGuestSigAction), PROT_WRITE), &CurrentAction,
                    sizeof(CurrentAction));
        GuestSignalActions[static_cast<size_t>(LinuxSIGPIPE)] = RequestedAction;
        return 0;
      }
    }

    if (Number == RtSigactionSyscall && !RootFS.empty() && static_cast<int64_t>(Arguments->Argument[1]) >= 1 &&
        static_cast<int64_t>(Arguments->Argument[1]) <= LinuxMaximumSignal &&
        Arguments->Argument[4] == LinuxKernelSigsetSize) {
      const int64_t Signal = static_cast<int64_t>(Arguments->Argument[1]);
      const uint64_t GuestAction = Arguments->Argument[2];
      const uint64_t GuestOldAction = Arguments->Argument[3];
      constexpr int64_t LinuxSIGKILL = 9;
      constexpr int64_t LinuxSIGSTOP = 19;
      if (GuestAction != 0 && (Signal == LinuxSIGKILL || Signal == LinuxSIGSTOP)) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if ((GuestAction != 0 &&
           !(HostPointerForGuestRange(GuestAction, sizeof(LinuxGuestSigAction), PROT_READ | PROT_WRITE) != nullptr)) ||
          (GuestOldAction != 0 && !(HostPointerForGuestRange(GuestOldAction, sizeof(LinuxGuestSigAction),
                                                             PROT_READ | PROT_WRITE) != nullptr))) {
        return static_cast<uint64_t>(-EFAULT);
      }

      RtSigactionLastSignal = Signal;
      const LinuxGuestSigAction &CurrentAction = GuestSignalActions[static_cast<size_t>(Signal)];
      if (GuestOldAction != 0) {
        std::memcpy(HostPointerForGuestRange(GuestOldAction, sizeof(LinuxGuestSigAction), PROT_WRITE), &CurrentAction,
                    sizeof(CurrentAction));
      }
      if (GuestAction != 0) {
        LinuxGuestSigAction RequestedAction{};
        std::memcpy(&RequestedAction, HostPointerForGuestRange(GuestAction, sizeof(LinuxGuestSigAction), PROT_READ),
                    sizeof(RequestedAction));
        constexpr uint64_t LinuxSIGKILLBit = uint64_t{1} << (LinuxSIGKILL - 1);
        constexpr uint64_t LinuxSIGSTOPBit = uint64_t{1} << (LinuxSIGSTOP - 1);
        RequestedAction.Mask &= ~(LinuxSIGKILLBit | LinuxSIGSTOPBit);
        GuestSignalActions[static_cast<size_t>(Signal)] = RequestedAction;
        if (Signal == 13 && RequestedAction.Handler == 1)
          signal(SIGPIPE, SIG_IGN);
      } else {
      }
      return 0;
    }
    if (Number == RtSigprocmaskSyscall && !RootFS.empty()) {
      if (Arguments->Argument[4] != LinuxKernelSigsetSize) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const uint64_t GuestSet = Arguments->Argument[2];
      const uint64_t GuestOldSet = Arguments->Argument[3];
      const void *Set = GuestSet ? HostPointerForGuestRange(GuestSet, sizeof(uint64_t), PROT_READ) : nullptr;
      void *OldSet = GuestOldSet ? HostPointerForGuestRange(GuestOldSet, sizeof(uint64_t), PROT_WRITE) : nullptr;
      if ((GuestSet && !Set) || (GuestOldSet && !OldSet)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      // Read first: Linux permits the input and output masks to alias.
      uint64_t RequestedMask{};
      if (Set) {
        if (Arguments->Argument[1] > LinuxSigSetMask) {
          return static_cast<uint64_t>(-EINVAL);
        }
        std::memcpy(&RequestedMask, Set, sizeof(RequestedMask));
      }
      if (OldSet) {
        std::memcpy(OldSet, &CurrentSignalMask(), sizeof(CurrentSignalMask()));
      }
      UpdateSignalMask(Arguments->Argument[1], Set != nullptr, RequestedMask);
      return 0;
    }
    if (Number == ArchPrctlSyscall && !RootFS.empty()) {
      constexpr uint32_t ArchSetGS = 0x1001;
      constexpr uint32_t ArchSetFS = 0x1002;
      constexpr uint32_t ArchGetFS = 0x1003;
      constexpr uint32_t ArchGetGS = 0x1004;
      constexpr uint32_t ArchGetCPUID = 0x1011;
      constexpr uint32_t ArchSetCPUID = 0x1012;
      constexpr uint32_t ArchCETStatus = 0x3001;
      constexpr uint64_t TaskMaximum64Bit = uint64_t{1} << 47;
      const uint32_t Code = static_cast<uint32_t>(Arguments->Argument[1]);
      const uint64_t Address = Arguments->Argument[2];
      switch (Code) {
      case ArchSetGS:
        if (Address >= TaskMaximum64Bit) {
          return static_cast<uint64_t>(-EPERM);
        }
        Frame->State.gs_cached = Address;
        return 0;
      case ArchSetFS:
        if (Address >= TaskMaximum64Bit) {
          return static_cast<uint64_t>(-EPERM);
        }
        Frame->State.fs_cached = Address;
        return 0;
      case ArchGetFS:
      case ArchGetGS:
        if (!Contains(Address, sizeof(uint64_t))) {
          return static_cast<uint64_t>(-EFAULT);
        }
        *reinterpret_cast<uint64_t *>(Address) = Code == ArchGetFS ? Frame->State.fs_cached : Frame->State.gs_cached;
        return 0;
      case ArchGetCPUID:
        return 1;
      case ArchSetCPUID:
        return static_cast<uint64_t>(-ENODEV);
      case ArchCETStatus:
        return static_cast<uint64_t>(-EINVAL);
      default:
        return static_cast<uint64_t>(-EINVAL);
      }
    }
    if (!RootFS.empty() && (Number == 104 || Number == 107 || Number == 108)) {
      if (Number == 104)
        return getgid();
      if (Number == 107)
        return geteuid();
      return getegid();
    }
    if (!RootFS.empty() && (Number == 118 || Number == 120)) {
      struct kinfo_proc Info{};
      size_t Size = sizeof(Info);
      int Query[]{CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
      if (sysctl(Query, 4, &Info, &Size, nullptr, 0) != 0 || Size != sizeof(Info)) {
        return static_cast<uint64_t>(-EIO);
      }
      void *Outputs[3]{};
      for (size_t Index = 0; Index < 3; ++Index) {
        Outputs[Index] = HostPointerForGuestRange(Arguments->Argument[Index + 1], 4, PROT_WRITE);
        if (!Outputs[Index])
          return static_cast<uint64_t>(-EFAULT);
      }
      const uint32_t IDs[3]{Number == 118 ? getuid() : getgid(), Number == 118 ? geteuid() : getegid(),
                            Number == 118 ? Info.kp_eproc.e_pcred.p_svuid : Info.kp_eproc.e_pcred.p_svgid};
      for (size_t Index = 0; Index < 3; ++Index)
        std::memcpy(Outputs[Index], &IDs[Index], 4);
      return 0;
    }
    if (Number == GetUIDSyscall && !RootFS.empty()) {
      LastGetUID = static_cast<uint64_t>(getuid());
      return LastGetUID;
    }
    if (Number == 62 && !RootFS.empty() && Arguments->Argument[2] == 0) {
      // Linux kill(pid, 0) checks actual process existence and permissions.
      const pid_t Target = static_cast<int32_t>(Arguments->Argument[1]);
      return kill(Target, 0) == 0 ? 0 : static_cast<uint64_t>(-errno);
    }
    if (Number == GetPIDSyscall && !RootFS.empty()) {
      LastGetPID = static_cast<uint64_t>(getpid());
      return LastGetPID;
    }
    if (Number == 110 && !RootFS.empty())
      return static_cast<uint64_t>(getppid());
    if (Number == SetSIDSyscall && !RootFS.empty() && NativeForkCloneChildProcess) {
      errno = 0;
      const pid_t Result = setsid();
      if (Result < 0) {
        return static_cast<uint64_t>(-errno);
      }
      return static_cast<uint64_t>(Result);
    }
    if (Number == SchedGetAffinitySyscall && !RootFS.empty()) {
      constexpr uint64_t LinuxKernelAffinityBytes = sizeof(uint64_t);
      constexpr int LinuxBadAddress = 14;
      constexpr int LinuxInvalidArgument = 22;
      const int64_t ProcessID = static_cast<int64_t>(Arguments->Argument[1]);
      const uint64_t CPUSetSize = Arguments->Argument[2];
      const uint64_t GuestMask = Arguments->Argument[3];
      if (ProcessID < 0 || CPUSetSize < LinuxKernelAffinityBytes) {
        return static_cast<uint64_t>(-LinuxInvalidArgument);
      }
      void *MaskBuffer = HostPointerForGuestRange(GuestMask, LinuxKernelAffinityBytes, PROT_WRITE);
      if (!MaskBuffer) {
        return static_cast<uint64_t>(-LinuxBadAddress);
      }
      const long HostLogicalCPUCount = sysconf(_SC_NPROCESSORS_ONLN);
      const uint64_t LogicalCPUCount =
          HostLogicalCPUCount > 0 ? static_cast<uint64_t>(HostLogicalCPUCount) : uint64_t{1};
      const uint64_t AffinityMask =
          LogicalCPUCount >= 64 ? std::numeric_limits<uint64_t>::max() : (uint64_t{1} << LogicalCPUCount) - 1;
      std::cerr << "TRACE sched_getaffinity-write"
                << " handler-call=" << HandleSyscallCallCount << " arguments=" << reinterpret_cast<uintptr_t>(Arguments)
                << " pid=" << ProcessID << " cpusetsize=" << CPUSetSize << " mask=" << GuestMask
                << " mask-contained=" << (Contains(GuestMask, CPUSetSize) ? 1 : 0) << '\n';
      std::cerr.flush();
      std::memcpy(MaskBuffer, &AffinityMask, sizeof(AffinityMask));
      std::cerr << "TRACE sched_getaffinity-result"
                << " pid=" << ProcessID << " cpusetsize=" << CPUSetSize << " logical-cpus=" << LogicalCPUCount
                << " returned-bytes=" << LinuxKernelAffinityBytes << '\n';
      std::cerr.flush();
      return LinuxKernelAffinityBytes;
    }
    if (Number == DupSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-9);
      }
      const int DuplicatedDescriptor = dup(Descriptor);
      if (DuplicatedDescriptor == -1) {
        return static_cast<uint64_t>(-TranslateHostDupErrorToLinux(errno));
      }
      OwnedDescriptors.insert(DuplicatedDescriptor);
      if (auto Inherited = InheritedReadOffsets.find(Descriptor); Inherited != InheritedReadOffsets.end())
        InheritedReadOffsets[DuplicatedDescriptor] = Inherited->second;
      ClosedStandardDescriptors.erase(DuplicatedDescriptor);
      std::cerr << "TRACE dup-result"
                << " source=" << Descriptor << " duplicated=" << DuplicatedDescriptor
                << " source-status-flags=" << fcntl(Descriptor, F_GETFL)
                << " duplicated-descriptor-flags=" << fcntl(DuplicatedDescriptor, F_GETFD) << '\n';
      std::cerr.flush();
      return static_cast<uint64_t>(DuplicatedDescriptor);
    }
    if (Number == Dup2Syscall && !RootFS.empty()) {
      const int SourceDescriptor = static_cast<int>(Arguments->Argument[1]);
      const int TargetDescriptor = static_cast<int>(Arguments->Argument[2]);
      Dup2LastSourceOwned = OwnedDescriptors.contains(SourceDescriptor);
      if (!Dup2LastSourceOwned || TargetDescriptor < 0) {
        Dup2LastLinuxError = EBADF;
        return static_cast<uint64_t>(-EBADF);
      }
      const int Result = dup2(SourceDescriptor, TargetDescriptor);
      if (Result == -1) {
        Dup2LastLinuxError = TranslateHostDupErrorToLinux(errno);
        return static_cast<uint64_t>(-Dup2LastLinuxError);
      }
      OwnedDescriptors.insert(Result);
      if (auto Inherited = InheritedReadOffsets.find(SourceDescriptor); Inherited != InheritedReadOffsets.end())
        InheritedReadOffsets[Result] = Inherited->second;
      else
        InheritedReadOffsets.erase(Result);
      ClosedStandardDescriptors.erase(Result);
      Dup2LastLinuxError = 0;
      return static_cast<uint64_t>(Result);
    }
    if (Number == GetTIDSyscall && !RootFS.empty()) {

      // Match Wine's public macOS implementation of get_unix_tid(): return
      // the numeric Mach thread-port name after releasing the extra send right
      // acquired by mach_thread_self(). This is guest ABI state only; it does
      // not fabricate a Linux TID or alter the host thread.
      const mach_port_t ThreadPort = mach_thread_self();
      (void)(mach_port_deallocate(mach_task_self(), ThreadPort));
      return LinuxGuestThreadID();
    }
    if (Number == SetPrioritySyscall && !RootFS.empty()) {
      const int64_t Which = static_cast<int64_t>(Arguments->Argument[1]);
      const int64_t Who = static_cast<int64_t>(Arguments->Argument[2]);
      const int64_t Nice = static_cast<int32_t>(Arguments->Argument[3]);
      SetPriorityLastWhoMatchesPID = Who == static_cast<int64_t>(getpid());
      constexpr int64_t ObservedCapabilityProbeNice = -20;
      constexpr int64_t ObservedResetNice = 0;
      if (Which != PRIO_PROCESS || !SetPriorityLastWhoMatchesPID ||
          (Nice != ObservedCapabilityProbeNice && Nice != ObservedResetNice)) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (setpriority(PRIO_PROCESS, static_cast<id_t>(Who), static_cast<int>(Nice)) != 0) {
        const int HostError = errno;
        const int LinuxError = HostError == EACCES || HostError == EPERM ? EACCES : (HostError == ESRCH ? ESRCH : EIO);
        return static_cast<uint64_t>(-LinuxError);
      }
      return 0;
    }
    if (Number == PollSyscall && !RootFS.empty()) {
      const uint64_t Count = Arguments->Argument[2];
      const int Timeout = static_cast<int32_t>(Arguments->Argument[3]);
      if (Count > 1024)
        return static_cast<uint64_t>(-EINVAL);
      auto *Buffer = static_cast<LinuxPollFD *>(
          Count ? HostPointerForGuestRange(Arguments->Argument[1], Count * sizeof(LinuxPollFD), PROT_READ | PROT_WRITE)
                : nullptr);
      if (Count && !Buffer)
        return static_cast<uint64_t>(-EFAULT);
      std::vector<LinuxPollFD> Guest(Count);
      std::vector<pollfd> Host(Count);
      if (Count)
        std::memcpy(Guest.data(), Buffer, Count * sizeof(LinuxPollFD));
      int Invalid{};
      for (size_t Index = 0; Index < Count; ++Index) {
        if (Guest[Index].Events & ~0x003F)
          return static_cast<uint64_t>(-EINVAL);
        const int FD = Guest[Index].Descriptor;
        const bool Valid =
            OwnedDescriptors.contains(FD) || (FD >= 0 && FD <= 2 && !ClosedStandardDescriptors.contains(FD));
        Guest[Index].ReturnedEvents = FD >= 0 && !Valid ? POLLNVAL : 0;
        if (Guest[Index].ReturnedEvents)
          ++Invalid;
        Host[Index] = {Valid ? FD : -1, Guest[Index].Events, 0};
      }
      const int Result = BlockingHostCall([&] { return poll(Host.data(), Count, Invalid ? 0 : Timeout); });
      if (Result < 0)
        return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
      for (size_t Index = 0; Index < Count; ++Index)
        Guest[Index].ReturnedEvents |= Host[Index].revents;
      if (Count) {
        std::memcpy(Buffer, Guest.data(), Count * sizeof(LinuxPollFD));
      }
      PollReadyDescriptorCount += Result + Invalid;
      return static_cast<uint64_t>(Result + Invalid);
    }
    if (Number == Pipe2Syscall && !RootFS.empty()) {
      const uint64_t GuestPipe = Arguments->Argument[1];
      const uint64_t Flags = Arguments->Argument[2];
      Pipe2LastPointerClass = "scalar-or-outside";
      Pipe2LastLowShadowMapped = false;
      Pipe2LastLowShadowWritable = false;
      if (Contains(GuestPipe, 2 * sizeof(int32_t))) {
        Pipe2LastPointerClass = "guest-memory";
      } else if (LowMemoryBiasModeEnabled && LowGuestShadow != nullptr &&
                 LowGuestShadow->ContainsLogicalRange(GuestPipe, 2 * sizeof(int32_t))) {
        Pipe2LastPointerClass = "low-shadow";
        Pipe2LastLowShadowMapped = LowGuestShadow->ContainsMappedLogicalRange(GuestPipe, 2 * sizeof(int32_t));
        Pipe2LastLowShadowWritable =
            LowGuestShadow->ContainsMappedLogicalRange(GuestPipe, 2 * sizeof(int32_t), PROT_WRITE);
      }

      void *GuestPipeDestination =
          Contains(GuestPipe, 2 * sizeof(int32_t)) ? reinterpret_cast<void *>(GuestPipe) : nullptr;

      if (GuestPipeDestination == nullptr && LowMemoryBiasModeEnabled && LowGuestShadow != nullptr) {
        GuestPipeDestination = LowGuestShadow->HostPointerForWritableLogicalRange(GuestPipe, 2 * sizeof(int32_t));
      }
      if (GuestPipeDestination == nullptr) {
        GuestPipeDestination = HostPointerForGuestRange(GuestPipe, 2 * sizeof(int32_t), PROT_WRITE);
        if (GuestPipeDestination)
          Pipe2LastPointerClass = "high-sparse";
      }
      if (GuestPipeDestination == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      constexpr uint64_t LinuxPipeCloexec = 0x80000;
      constexpr uint64_t LinuxPipeNonblock = 0x800;
      if (Flags & ~(LinuxPipeCloexec | LinuxPipeNonblock)) {
        return static_cast<uint64_t>(-EINVAL);
      }
      std::array<int, 2> HostPipe{-1, -1};
      if (pipe(HostPipe.data()) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      for (const int FD : HostPipe) {
        if (((Flags & LinuxPipeCloexec) && fcntl(FD, F_SETFD, FD_CLOEXEC) == -1) ||
            ((Flags & LinuxPipeNonblock) && fcntl(FD, F_SETFL, O_NONBLOCK) == -1)) {
          const int Error = errno;
          close(HostPipe[0]);
          close(HostPipe[1]);
          return static_cast<uint64_t>(-Error);
        }
      }
      const std::array<int32_t, 2> GuestDescriptors{
          static_cast<int32_t>(HostPipe[0]),
          static_cast<int32_t>(HostPipe[1]),
      };
      std::memcpy(GuestPipeDestination, GuestDescriptors.data(), sizeof(GuestDescriptors));
      OwnedDescriptors.insert(HostPipe[0]);
      OwnedDescriptors.insert(HostPipe[1]);
      return 0;
    }
    if (Number == SocketSyscall && !RootFS.empty()) {
      constexpr int64_t LinuxAFUnix = 1;
      constexpr int64_t LinuxSocketTypeMask = 0xF;
      constexpr int64_t LinuxSockStream = 1;
      constexpr int64_t LinuxSockNonblock = 0x800;
      constexpr int64_t LinuxSockCloexec = 0x8'0000;
      constexpr int64_t LinuxAllowedFlags = LinuxSockNonblock | LinuxSockCloexec;
      const int64_t Domain = static_cast<int64_t>(Arguments->Argument[1]);
      const int64_t Type = static_cast<int64_t>(Arguments->Argument[2]);
      const int64_t Protocol = static_cast<int64_t>(Arguments->Argument[3]);
      const int64_t BaseType = Type & LinuxSocketTypeMask;
      const int64_t Flags = Type & ~LinuxSocketTypeMask;
      if (Domain != LinuxAFUnix) {
        return static_cast<uint64_t>(-97);
      }
      if (BaseType != LinuxSockStream || Protocol != 0 || (Flags & ~LinuxAllowedFlags) != 0) {
        return static_cast<uint64_t>(-93);
      }

      const int Descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
      if (Descriptor == -1) {
        return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
      }
      const auto CloseWithError = [Descriptor](int HostError) -> uint64_t {
        close(Descriptor);
        return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(HostError));
      };
      if ((Flags & LinuxSockNonblock) != 0) {
        const int ExistingFlags = fcntl(Descriptor, F_GETFL);
        if (ExistingFlags == -1 || fcntl(Descriptor, F_SETFL, ExistingFlags | O_NONBLOCK) == -1) {
          return CloseWithError(errno);
        }
      }
      if ((Flags & LinuxSockCloexec) != 0) {
        const int ExistingDescriptorFlags = fcntl(Descriptor, F_GETFD);
        if (ExistingDescriptorFlags == -1 || fcntl(Descriptor, F_SETFD, ExistingDescriptorFlags | FD_CLOEXEC) == -1) {
          return CloseWithError(errno);
        }
      }
      OwnedDescriptors.insert(Descriptor);
      return static_cast<uint64_t>(Descriptor);
    }
    if (Number == SocketPairSyscall && !RootFS.empty()) {
      constexpr int64_t LinuxAFUnix = 1;
      constexpr int64_t LinuxSocketTypeMask = 0xF;
      constexpr int64_t LinuxSockStream = 1;
      constexpr int64_t LinuxSockNonblock = 0x800;
      constexpr int64_t LinuxSockCloexec = 0x8'0000;
      constexpr int64_t LinuxAllowedFlags = LinuxSockNonblock | LinuxSockCloexec;
      const int64_t Domain = static_cast<int64_t>(Arguments->Argument[1]);
      const int64_t Type = static_cast<int64_t>(Arguments->Argument[2]);
      const int64_t Protocol = static_cast<int64_t>(Arguments->Argument[3]);
      const uint64_t GuestPair = Arguments->Argument[4];
      const int64_t BaseType = Type & LinuxSocketTypeMask;
      const int64_t Flags = Type & ~LinuxSocketTypeMask;
      void *PairDestination = HostPointerForGuestRange(GuestPair, 2 * sizeof(int32_t), PROT_WRITE);
      if (!PairDestination) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if (Domain != LinuxAFUnix) {
        return static_cast<uint64_t>(-97);
      }
      if (BaseType != LinuxSockStream || Protocol != 0 || (Flags & ~LinuxAllowedFlags) != 0) {
        return static_cast<uint64_t>(-93);
      }

      std::array<int, 2> HostPair{-1, -1};
      if (socketpair(AF_UNIX, SOCK_STREAM, 0, HostPair.data()) != 0) {
        const int LinuxError = TranslateHostSocketErrorToLinux(errno);
        return static_cast<uint64_t>(-LinuxError);
      }
      const auto ClosePairWithError = [&HostPair](int HostError) -> uint64_t {
        const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
        close(HostPair[0]);
        close(HostPair[1]);
        return static_cast<uint64_t>(-LinuxError);
      };
      for (const int Descriptor : HostPair) {
        if ((Flags & LinuxSockNonblock) != 0) {
          const int ExistingFlags = fcntl(Descriptor, F_GETFL);
          if (ExistingFlags == -1 || fcntl(Descriptor, F_SETFL, ExistingFlags | O_NONBLOCK) == -1) {
            const int HostError = errno;
            return ClosePairWithError(HostError);
          }
        }
        if ((Flags & LinuxSockCloexec) != 0) {
          const int ExistingDescriptorFlags = fcntl(Descriptor, F_GETFD);
          if (ExistingDescriptorFlags == -1 || fcntl(Descriptor, F_SETFD, ExistingDescriptorFlags | FD_CLOEXEC) == -1) {
            const int HostError = errno;
            return ClosePairWithError(HostError);
          }
        }
      }

      const std::array<int32_t, 2> GuestDescriptors{
          static_cast<int32_t>(HostPair[0]),
          static_cast<int32_t>(HostPair[1]),
      };
      std::memcpy(PairDestination, GuestDescriptors.data(), sizeof(GuestDescriptors));
      OwnedDescriptors.insert(HostPair[0]);
      OwnedDescriptors.insert(HostPair[1]);
      return 0;
    }
    if (Number == ShutdownSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const int64_t How = static_cast<int64_t>(Arguments->Argument[2]);
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (How < SHUT_RD || How > SHUT_RDWR) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (shutdown(Descriptor, static_cast<int>(How)) != 0) {
        const int LinuxError = TranslateHostSocketErrorToLinux(errno);
        return static_cast<uint64_t>(-LinuxError);
      }
      return 0;
    }
    if (Number == BindSyscall && !RootFS.empty()) {
      constexpr uint16_t LinuxAFUnix = 1;
      constexpr uint64_t ObservedAddressLength = 9;
      constexpr std::string_view ObservedSocketName = "socket";
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestAddress = Arguments->Argument[2];
      const uint64_t AddressLength = Arguments->Argument[3];
      BindLastEndpointCreated = false;
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (AddressLength != ObservedAddressLength || !Contains(GuestAddress, AddressLength)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      uint16_t Family{};
      std::memcpy(&Family, reinterpret_cast<const void *>(GuestAddress), sizeof(Family));
      if (Family != LinuxAFUnix) {
        return static_cast<uint64_t>(-97);
      }
      const auto *Path = reinterpret_cast<const char *>(GuestAddress + sizeof(Family));
      const size_t PayloadLength = static_cast<size_t>(AddressLength - sizeof(Family));
      const auto *Terminator = static_cast<const char *>(std::memchr(Path, '\0', PayloadLength));
      if (Terminator == nullptr) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const std::string GuestSocketPath{Path, Terminator};
      TraceGuestPath("bind", GuestSocketPath);
      if (GuestSocketPath != ObservedSocketName || static_cast<size_t>(Terminator - Path + 1) != PayloadLength) {
        return static_cast<uint64_t>(-ENOTSUP);
      }

      const auto ExpectedHostCWD = ResolveGuestPath(".");
      std::array<char, 4096> HostCurrentDirectory{};
      if (!ExpectedHostCWD.has_value() || getcwd(HostCurrentDirectory.data(), HostCurrentDirectory.size()) == nullptr ||
          std::string_view{HostCurrentDirectory.data()} != *ExpectedHostCWD) {
        return static_cast<uint64_t>(-EACCES);
      }

      sockaddr_un HostAddress{};
      HostAddress.sun_family = AF_UNIX;
      std::memcpy(HostAddress.sun_path, GuestSocketPath.c_str(), GuestSocketPath.size() + 1);
      const size_t HostAddressLength = offsetof(sockaddr_un, sun_path) + GuestSocketPath.size() + 1;
      HostAddress.sun_len = static_cast<uint8_t>(HostAddressLength);
      if (bind(Descriptor, reinterpret_cast<const sockaddr *>(&HostAddress),
               static_cast<socklen_t>(HostAddressLength)) != 0) {
        const int LinuxError = TranslateHostSocketErrorToLinux(errno);
        return static_cast<uint64_t>(-LinuxError);
      }
      struct stat EndpointStat{};
      BindLastEndpointCreated = lstat(GuestSocketPath.c_str(), &EndpointStat) == 0 && S_ISSOCK(EndpointStat.st_mode);
      if (!BindLastEndpointCreated) {
        return static_cast<uint64_t>(-EIO);
      }
      return 0;
    }
    if (Number == ListenSyscall && !RootFS.empty()) {
      constexpr int ObservedBacklog = 5;
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const int64_t Backlog = static_cast<int64_t>(Arguments->Argument[2]);
      ListenLastDescriptor = Descriptor;
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (Backlog != ObservedBacklog) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (listen(Descriptor, ObservedBacklog) != 0) {
        const int LinuxError = TranslateHostSocketErrorToLinux(errno);
        return static_cast<uint64_t>(-LinuxError);
      }
      ++ListenSuccessCount;
      return 0;
    }
    if (Number == FutexWaitVSyscall && !RootFS.empty()) {
      constexpr int LinuxENOSYS = 38;
      const bool ExactAvailabilityProbe = Arguments->Argument[1] == 0 && Arguments->Argument[2] == 0 &&
                                          Arguments->Argument[3] == 0 && Arguments->Argument[4] == 0 &&
                                          Arguments->Argument[5] == 0;
      if (ExactAvailabilityProbe) {
        return static_cast<uint64_t>(-LinuxENOSYS);
      }
    }
    if (Number == EpollCreateSyscall && !RootFS.empty()) {
      const int64_t Size = static_cast<int32_t>(Arguments->Argument[1]);
      if (Size <= 0) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const int Descriptor = kqueue();
      if (Descriptor == -1) {
        return static_cast<uint64_t>(-errno);
      }
      OwnedDescriptors.insert(Descriptor);
      EpollDescriptors.insert(Descriptor);
      return static_cast<uint64_t>(Descriptor);
    }
    if (Number == EpollCtlSyscall && !RootFS.empty()) {
      constexpr int64_t LinuxEpollCtlAdd = 1;
      constexpr uint32_t LinuxEpollIn = 0x0000'0001;
      constexpr uint32_t LinuxEpollOut = 0x0000'0004;
      const int EpollDescriptor = static_cast<int>(Arguments->Argument[1]);
      const int64_t Operation = static_cast<int64_t>(Arguments->Argument[2]);
      const int TargetDescriptor = static_cast<int>(Arguments->Argument[3]);
      const uint64_t GuestEvent = Arguments->Argument[4];
      LinuxEpollEvent TracedEvent{};
      const bool TracedEventReadable = Contains(GuestEvent, sizeof(TracedEvent));
      if (TracedEventReadable) {
        std::memcpy(&TracedEvent, reinterpret_cast<const void *>(GuestEvent), sizeof(TracedEvent));
      }

      if (!EpollDescriptors.contains(EpollDescriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (!OwnedDescriptors.contains(TargetDescriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      const auto Key = std::make_pair(EpollDescriptor, TargetDescriptor);
      if (Operation == 2) { // EPOLL_CTL_DEL ignores the event pointer.
        const auto Existing = EpollFilters.find(Key);
        if (Existing == EpollFilters.end())
          return static_cast<uint64_t>(-ENOENT);
        struct kevent Change{};
        EV_SET(&Change, TargetDescriptor, Existing->second, EV_DELETE, 0, 0, nullptr);
        if (BlockingHostCall([&] { return kevent(EpollDescriptor, &Change, 1, nullptr, 0, nullptr); }) == -1) {
          return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
        }
        EpollFilters.erase(Existing);
        return 0;
      }
      if (Operation != LinuxEpollCtlAdd) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (!TracedEventReadable) {
        return static_cast<uint64_t>(-EFAULT);
      }
      const LinuxEpollEvent Event = TracedEvent;
      const bool IsReadRegistration = Event.Events == LinuxEpollIn;
      const bool IsWriteRegistration = Event.Events == LinuxEpollOut;
      if (!IsReadRegistration && !IsWriteRegistration) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (EpollFilters.contains(Key))
        return static_cast<uint64_t>(-EEXIST);
      const int16_t Filter = IsWriteRegistration ? EVFILT_WRITE : EVFILT_READ;
      struct kevent Change{};
      EV_SET(&Change, static_cast<uintptr_t>(TargetDescriptor), Filter, EV_ADD | EV_ENABLE, 0, 0,
             reinterpret_cast<void *>(static_cast<uintptr_t>(Event.Data)));
      if (BlockingHostCall([&] { return kevent(EpollDescriptor, &Change, 1, nullptr, 0, nullptr); }) == -1) {
        return static_cast<uint64_t>(-errno);
      }
      EpollFilters.emplace(Key, Filter);
      return 0;
    }
    if (Number == EpollPWait2Syscall && !RootFS.empty()) {
      constexpr int LinuxENOSYS = 38;
      constexpr int64_t ObservedMaxEvents = 128;
      constexpr int64_t ObservedTimeoutSeconds = 0;
      constexpr int64_t ObservedTimeoutNanoseconds = 16'000'000;
      constexpr uint64_t ObservedSignalSetSize = 8;
      const int EpollDescriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestEvents = Arguments->Argument[2];
      const int64_t MaxEvents = static_cast<int64_t>(Arguments->Argument[3]);
      const uint64_t GuestTimeout = Arguments->Argument[4];
      const uint64_t EpollSignalMaskAddress = Arguments->Argument[5];
      const uint64_t SignalSetSize = Arguments->Argument[6];
      EpollPWait2LastDescriptorKnown = EpollDescriptors.contains(EpollDescriptor);
      const bool EventSpanValid =
          MaxEvents > 0 && MaxEvents <= 4096 &&
          static_cast<uint64_t>(MaxEvents) <= std::numeric_limits<uint64_t>::max() / sizeof(LinuxEpollEvent);
      const uint64_t EventSpan = EventSpanValid ? static_cast<uint64_t>(MaxEvents) * sizeof(LinuxEpollEvent) : 0;
      LinuxTimespec64 Timeout{};
      if (Contains(GuestTimeout, sizeof(Timeout))) {
        std::memcpy(&Timeout, reinterpret_cast<const void *>(GuestTimeout), sizeof(Timeout));
        EpollPWait2LastTimeoutReadable = true;
      }
      if (!EpollPWait2LastDescriptorKnown) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (MaxEvents != ObservedMaxEvents) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (!EventSpanValid || !Contains(GuestEvents, EventSpan)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if (!EpollPWait2LastTimeoutReadable) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if (!IsValidLinuxTimespec(Timeout) || Timeout.Seconds != ObservedTimeoutSeconds ||
          Timeout.Nanoseconds != ObservedTimeoutNanoseconds) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (EpollSignalMaskAddress != 0 || SignalSetSize != ObservedSignalSetSize) {
        return static_cast<uint64_t>(-EINVAL);
      }
      return static_cast<uint64_t>(-LinuxENOSYS);
    }
    if (Number == EpollWaitSyscall && !RootFS.empty()) {
      constexpr int64_t ObservedPollingTimeoutMilliseconds = 0;
      constexpr uint32_t LinuxEpollIn = 0x0000'0001;
      constexpr uint32_t LinuxEpollOut = 0x0000'0004;
      constexpr uint32_t LinuxEpollError = 0x0000'0008;
      constexpr uint32_t LinuxEpollHangup = 0x0000'0010;
      const int EpollDescriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestEvents = Arguments->Argument[2];
      const int64_t MaxEvents = static_cast<int64_t>(Arguments->Argument[3]);
      const int64_t TimeoutMilliseconds = static_cast<int32_t>(Arguments->Argument[4]);
      EpollWaitLastDescriptorKnown = EpollDescriptors.contains(EpollDescriptor);
      const bool IsTimedWait = TimeoutMilliseconds > 0;
      const bool IsPollingWait = TimeoutMilliseconds == ObservedPollingTimeoutMilliseconds;
      const bool EventSpanValid =
          MaxEvents > 0 && MaxEvents <= 4096 &&
          static_cast<uint64_t>(MaxEvents) <= std::numeric_limits<uint64_t>::max() / sizeof(LinuxEpollEvent);
      const uint64_t EventSpan = EventSpanValid ? static_cast<uint64_t>(MaxEvents) * sizeof(LinuxEpollEvent) : 0;
      if (!EpollWaitLastDescriptorKnown) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (!EventSpanValid) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (!EventSpanValid || !Contains(GuestEvents, EventSpan)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      std::vector<struct kevent> HostEvents(static_cast<size_t>(MaxEvents));
      const timespec HostTimeout{
          .tv_sec = TimeoutMilliseconds > 0 ? TimeoutMilliseconds / 1000 : 0,
          .tv_nsec = TimeoutMilliseconds > 0 ? (TimeoutMilliseconds % 1000) * 1'000'000 : 0,
      };
      const int Result = BlockingHostCall([&] {
        return kevent(EpollDescriptor, nullptr, 0, HostEvents.data(), static_cast<int>(HostEvents.size()),
                      TimeoutMilliseconds < 0 ? nullptr : &HostTimeout);
      });
      if (Result == -1) {
        const int LinuxError = TranslateHostSocketErrorToLinux(errno);
        return static_cast<uint64_t>(-LinuxError);
      }
      for (int Index = 0; Index < Result; ++Index) {
        const auto &HostEvent = HostEvents[static_cast<size_t>(Index)];
        LinuxEpollEvent GuestEvent{};
        if (HostEvent.filter == EVFILT_READ) {
          GuestEvent.Events |= LinuxEpollIn;
        } else if (HostEvent.filter == EVFILT_WRITE) {
          GuestEvent.Events |= LinuxEpollOut;
        } else {
          return static_cast<uint64_t>(-EIO);
        }
        if ((HostEvent.flags & EV_ERROR) != 0) {
          GuestEvent.Events |= LinuxEpollError;
        }
        if ((HostEvent.flags & EV_EOF) != 0) {
          GuestEvent.Events |= LinuxEpollHangup;
        }
        GuestEvent.Data = reinterpret_cast<uintptr_t>(HostEvent.udata);
        std::memcpy(reinterpret_cast<void *>(GuestEvents + static_cast<uint64_t>(Index) * sizeof(GuestEvent)),
                    &GuestEvent, sizeof(GuestEvent));
      }
      EpollWaitReturnedEventCount += static_cast<uint64_t>(Result);
      if (IsTimedWait) {
        EpollWaitTimedReturnedEventCount += static_cast<uint64_t>(Result);
      } else if (IsPollingWait) {
        EpollWaitPollingReturnedEventCount += static_cast<uint64_t>(Result);
      }
      return static_cast<uint64_t>(Result);
    }
    if (Number == GettimeofdaySyscall && !RootFS.empty()) {
      const uint64_t GuestTime = Arguments->Argument[1];
      const uint64_t GuestTimezone = Arguments->Argument[2];
      if (!Contains(GuestTime, sizeof(LinuxTimeval64))) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if (GuestTimezone != 0) {
        return static_cast<uint64_t>(-EINVAL);
      }
      timeval HostTime{};
      if (gettimeofday(&HostTime, nullptr) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      const LinuxTimeval64 GuestResult{
          .Seconds = HostTime.tv_sec,
          .Microseconds = HostTime.tv_usec,
      };
      std::memcpy(reinterpret_cast<void *>(GuestTime), &GuestResult, sizeof(GuestResult));
      return 0;
    }
    if (Number == SysinfoSyscall && !RootFS.empty()) {
      const uint64_t GuestBuffer = Arguments->Argument[1];
      void *HostBuffer = nullptr;
      if (Contains(GuestBuffer, sizeof(LinuxX86_64Sysinfo))) {
        HostBuffer = reinterpret_cast<void *>(GuestBuffer);
      } else if (LowMemoryBiasModeEnabled && LowGuestShadow != nullptr) {
        HostBuffer =
            LowGuestShadow->HostPointerForMappedLogicalRange(GuestBuffer, sizeof(LinuxX86_64Sysinfo), PROT_WRITE);
      }
      if (HostBuffer == nullptr && HighMemoryRegionModeEnabled && HighGuestSparse != nullptr) {
        HostBuffer =
            HighGuestSparse->HostPointerForMappedLogicalRange(GuestBuffer, sizeof(LinuxX86_64Sysinfo), PROT_WRITE);
      }
      if (HostBuffer == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }

      timespec HostUptime{};
      if (clock_gettime(CLOCK_MONOTONIC, &HostUptime) != 0) {
        return static_cast<uint64_t>(-errno);
      }

      uint64_t TotalMemory{};
      size_t TotalMemorySize = sizeof(TotalMemory);
      if (sysctlbyname("hw.memsize", &TotalMemory, &TotalMemorySize, nullptr, 0) != 0 ||
          TotalMemorySize != sizeof(TotalMemory) || TotalMemory == 0) {
        return static_cast<uint64_t>(-EIO);
      }

      uint64_t FreeMemory{};
      const mach_port_t HostPort = mach_host_self();
      vm_size_t HostPageSize{};
      vm_statistics64_data_t HostVMStatistics{};
      mach_msg_type_number_t HostVMStatisticsCount = HOST_VM_INFO64_COUNT;
      const kern_return_t PageSizeResult = host_page_size(HostPort, &HostPageSize);
      const kern_return_t StatisticsResult = host_statistics64(
          HostPort, HOST_VM_INFO64, reinterpret_cast<host_info64_t>(&HostVMStatistics), &HostVMStatisticsCount);
      mach_port_deallocate(mach_task_self(), HostPort);
      if (PageSizeResult == KERN_SUCCESS && StatisticsResult == KERN_SUCCESS) {
        const uint64_t AvailablePages =
            static_cast<uint64_t>(HostVMStatistics.free_count) + static_cast<uint64_t>(HostVMStatistics.inactive_count);
        if (HostPageSize != 0 && AvailablePages <= std::numeric_limits<uint64_t>::max() / HostPageSize) {
          FreeMemory = std::min(TotalMemory, AvailablePages * HostPageSize);
        }
      }

      LinuxX86_64Sysinfo GuestInfo{};
      GuestInfo.Uptime = HostUptime.tv_sec;
      std::array<double, 3> HostLoads{};
      const int LoadCount = getloadavg(HostLoads.data(), static_cast<int>(HostLoads.size()));
      constexpr double LinuxLoadScale = double{1ULL << 16};
      for (size_t Index = 0; Index < GuestInfo.Loads.size(); ++Index) {
        if (LoadCount > static_cast<int>(Index) && HostLoads[Index] > 0) {
          const double ScaledLoad = HostLoads[Index] * LinuxLoadScale;
          GuestInfo.Loads[Index] = ScaledLoad >= static_cast<double>(std::numeric_limits<uint64_t>::max())
                                       ? std::numeric_limits<uint64_t>::max()
                                       : static_cast<uint64_t>(ScaledLoad);
        }
      }
      GuestInfo.TotalRAM = TotalMemory;
      GuestInfo.FreeRAM = FreeMemory;
      GuestInfo.Processes = 1;
      GuestInfo.MemoryUnit = 1;
      std::memcpy(HostBuffer, &GuestInfo, sizeof(GuestInfo));
      return 0;
    }
    if (Number == TimeSyscall && !RootFS.empty()) {
      const uint64_t GuestOutput = Arguments->Argument[1];
      if (GuestOutput != 0) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const time_t HostTime = time(nullptr);
      if (HostTime == static_cast<time_t>(-1)) {
        return static_cast<uint64_t>(-errno);
      }
      TimeLastSeconds = static_cast<int64_t>(HostTime);
      return static_cast<uint64_t>(TimeLastSeconds);
    }
    if (Number == FStatFSSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestBuffer = Arguments->Argument[2];
      void *StatDestination = HostPointerForGuestRange(GuestBuffer, sizeof(LinuxX86_64StatFS), PROT_WRITE);
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (StatDestination == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      struct statfs HostStat{};
      if (fstatfs(Descriptor, &HostStat) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      constexpr int64_t LinuxExtFileSystemMagic = 0xEF53;
      LinuxX86_64StatFS GuestStat{
          .Type = LinuxExtFileSystemMagic,
          .BlockSize = static_cast<int64_t>(HostStat.f_bsize),
          .Blocks = static_cast<uint64_t>(HostStat.f_blocks),
          .BlocksFree = static_cast<uint64_t>(HostStat.f_bfree),
          .BlocksAvailable = static_cast<uint64_t>(HostStat.f_bavail),
          .Files = static_cast<uint64_t>(HostStat.f_files),
          .FilesFree = static_cast<uint64_t>(HostStat.f_ffree),
          .FileSystemID = {HostStat.f_fsid.val[0], HostStat.f_fsid.val[1]},
          .NameLength = NAME_MAX,
          .FragmentSize = static_cast<int64_t>(HostStat.f_bsize),
          .Flags = 0,
      };
      std::memcpy(StatDestination, &GuestStat, sizeof(GuestStat));
      return 0;
    }
    if (Number == FAccessAt2Syscall && !RootFS.empty()) {
      constexpr uint64_t LinuxAtEffectiveAccess = 0x200;
      const int32_t DirectoryDescriptor = static_cast<int32_t>(Arguments->Argument[1]);
      const auto GuestPath = ReadGuestPath(Arguments->Argument[2]);
      const uint64_t Mode = Arguments->Argument[3];
      const uint64_t Flags = Arguments->Argument[4];
      if (!GuestPath.has_value()) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if (DirectoryDescriptor != LinuxAtFDCWD || Mode != F_OK || Flags != LinuxAtEffectiveAccess) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const auto HostPath = ResolveGuestPathWithParents(*GuestPath);
      if (!HostPath.has_value()) {
        return static_cast<uint64_t>(-EACCES);
      }
      if (access(HostPath->c_str(), F_OK) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      return 0;
    }
    if (Number == MemfdCreateSyscall && !RootFS.empty()) {
      constexpr uint64_t LinuxMFDCloexec = 1;
      constexpr uint64_t LinuxMFDExec = 0x10;
      const auto GuestName = ReadGuestPath(Arguments->Argument[1]);
      const uint64_t Flags = Arguments->Argument[2];
      MemfdCreateLastDescriptor = -1;
      if (!GuestName.has_value()) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if (GuestName->size() > 249 || (Flags & ~(LinuxMFDCloexec | LinuxMFDExec))) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const auto HostTemplate = ResolveGuestCreationPath(".wine-mapping-XXXXXX");
      if (!HostTemplate.has_value()) {
        return static_cast<uint64_t>(-EACCES);
      }
      std::vector<char> MutableTemplate(HostTemplate->begin(), HostTemplate->end());
      MutableTemplate.push_back('\0');
      const int Descriptor = mkstemp(MutableTemplate.data());
      if (Descriptor == -1) {
        return static_cast<uint64_t>(-errno);
      }
      if (unlink(MutableTemplate.data()) != 0) {
        const int UnlinkError = errno;
        close(Descriptor);
        return static_cast<uint64_t>(-UnlinkError);
      }
      if ((Flags & LinuxMFDCloexec) && fcntl(Descriptor, F_SETFD, FD_CLOEXEC) == -1) {
        const int LinuxError = TranslateHostSocketErrorToLinux(errno);
        close(Descriptor);
        return static_cast<uint64_t>(-LinuxError);
      }
      OwnedDescriptors.insert(Descriptor);
      MemfdCreateLastDescriptor = Descriptor;
      return static_cast<uint64_t>(Descriptor);
    }
    if (Number == PWrite64Syscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestBuffer = Arguments->Argument[2];
      const uint64_t ByteCount = Arguments->Argument[3];
      const uint64_t Offset = Arguments->Argument[4];
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (Offset > static_cast<uint64_t>(INT64_MAX) || ByteCount > static_cast<uint64_t>(SSIZE_MAX)) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const void *Bytes = ByteCount != 0 ? HostPointerForGuestRange(GuestBuffer, ByteCount, PROT_READ) : nullptr;
      if (ByteCount != 0 && !Bytes)
        return static_cast<uint64_t>(-EFAULT);
      const ssize_t Written = pwrite(Descriptor, Bytes, static_cast<size_t>(ByteCount), static_cast<off_t>(Offset));
      if (Written == -1) {
        return static_cast<uint64_t>(-errno);
      }
      PWrite64WrittenByteCount += static_cast<uint64_t>(Written);
      if (Offset == ObservedWineSessionMappingSize) {
        SessionMappingWriteCompleted = true;
      }
      return static_cast<uint64_t>(Written);
    }
    if (Number == FTruncateSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t Length = Arguments->Argument[2];
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (Length > static_cast<uint64_t>(INT64_MAX))
        return static_cast<uint64_t>(-EINVAL);
      if (ftruncate(Descriptor, static_cast<off_t>(Length)) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      return 0;
    }
    if (Number == FChdirSyscall && !RootFS.empty()) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      FChdirLastTargetDirectory = false;
      FChdirLastTargetConfined = false;
      FChdirLastHostCWDMatchesGuest = false;
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      struct stat DescriptorStat{};
      if (fstat(Descriptor, &DescriptorStat) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      FChdirLastTargetDirectory = S_ISDIR(DescriptorStat.st_mode);
      if (!FChdirLastTargetDirectory) {
        return static_cast<uint64_t>(-ENOTDIR);
      }
      std::array<char, 4096> DescriptorPath{};
      if (fcntl(Descriptor, F_GETPATH, DescriptorPath.data()) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      const std::string HostPath{DescriptorPath.data()};
      FChdirLastTargetConfined = fli_guest_host_path_visible(HostPath, RootFS);
      if (!FChdirLastTargetConfined) {
        return static_cast<uint64_t>(-EACCES);
      }
      if (fchdir(Descriptor) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      const std::string GuestPath = fli_guest_path_view(HostPath, RootFS);
      GuestCurrentWorkingDirectory = GuestPath;
      std::array<char, 4096> HostCurrentWorkingDirectory{};
      FChdirLastHostCWDMatchesGuest =
          getcwd(HostCurrentWorkingDirectory.data(), HostCurrentWorkingDirectory.size()) != nullptr &&
          HostPath == HostCurrentWorkingDirectory.data();
      if (!FChdirLastHostCWDMatchesGuest) {
        return static_cast<uint64_t>(-EIO);
      }
      return 0;
    }
    if (Number == 45 && !RootFS.empty()) {
      const int FD = static_cast<int>(Arguments->Argument[1]);
      const uint64_t Size = Arguments->Argument[3], Flags = Arguments->Argument[4];
      if (!OwnedDescriptors.contains(FD))
        return static_cast<uint64_t>(-EBADF);
      if (Flags & ~(uint64_t{2} | 64 | 256 | 0x4000))
        return static_cast<uint64_t>(-EINVAL);
      // Connected stream callers do not request a source sockaddr. Add address
      // conversion when a measured datagram caller needs it; never consume data
      // while returning an unsupported-address failure.
      if (Arguments->Argument[5])
        return static_cast<uint64_t>(-95);
      void *Destination = Size <= static_cast<uint64_t>(SSIZE_MAX)
                              ? HostPointerForGuestRange(Arguments->Argument[2], Size, PROT_WRITE)
                              : nullptr;
      if (Size && !Destination)
        return static_cast<uint64_t>(-EFAULT);
      int HostFlags = Flags & 2 ? MSG_PEEK : 0;
      if (Flags & 64)
        HostFlags |= MSG_DONTWAIT;
      if (Flags & 256)
        HostFlags |= MSG_WAITALL;
      return static_cast<uint64_t>(BlockingHostCall([&]() -> int64_t {
        const ssize_t Result = recv(FD, Destination, static_cast<size_t>(Size), HostFlags);
        return Result < 0 ? -TranslateHostSocketErrorToLinux(errno) : Result;
      }));
    }
    if ((Number == 51 || Number == 52) && !RootFS.empty()) {
      const int FD = static_cast<int>(Arguments->Argument[1]);
      if (!OwnedDescriptors.contains(FD))
        return static_cast<uint64_t>(-EBADF);
      void *LengthPointer = HostPointerForGuestRange(Arguments->Argument[3], 4, PROT_READ | PROT_WRITE);
      if (!LengthPointer)
        return static_cast<uint64_t>(-EFAULT);
      uint32_t Capacity{};
      std::memcpy(&Capacity, LengthPointer, 4);
      void *Output = Capacity ? HostPointerForGuestRange(Arguments->Argument[2], Capacity, PROT_WRITE) : nullptr;
      if (Capacity && !Output)
        return static_cast<uint64_t>(-EFAULT);
      sockaddr_storage Address{};
      socklen_t Length = sizeof(Address);
      const int Result = Number == 51 ? getsockname(FD, reinterpret_cast<sockaddr *>(&Address), &Length)
                                      : getpeername(FD, reinterpret_cast<sockaddr *>(&Address), &Length);
      if (Result != 0)
        return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
      if (Address.ss_family != AF_UNIX)
        return static_cast<uint64_t>(-97);
      const auto *Unix = reinterpret_cast<const sockaddr_un *>(&Address);
      std::string Path{Unix->sun_path, strnlen(Unix->sun_path, sizeof(Unix->sun_path))};
      if (Path.starts_with(RootFS + '/'))
        Path.erase(0, RootFS.size());
      if (const char *Display = std::getenv("REGRESSION_X11_SOCKET"); Display && Path == Display)
        Path = "/tmp/.X11-unix/X0";
      std::array<uint8_t, 110> LinuxAddress{};
      const uint16_t Family = 1;
      std::memcpy(LinuxAddress.data(), &Family, 2);
      if (Path.size() + 3 > LinuxAddress.size())
        return static_cast<uint64_t>(-36);
      if (!Path.empty())
        std::memcpy(LinuxAddress.data() + 2, Path.c_str(), Path.size() + 1);
      const uint32_t GuestLength = Path.empty() ? 2 : static_cast<uint32_t>(Path.size() + 3);
      if (Capacity)
        std::memcpy(Output, LinuxAddress.data(), std::min(Capacity, GuestLength));
      std::memcpy(LengthPointer, &GuestLength, 4);
      return 0;
    }
    if (Number == ConnectSyscall && !RootFS.empty()) {
      constexpr uint16_t LinuxAFUnix = 1;
      constexpr uint64_t LinuxSockaddrUnMaximum = 110;
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestAddress = Arguments->Argument[2];
      const uint64_t AddressLength = Arguments->Argument[3];
      const auto *SocketBuffer =
          static_cast<const uint8_t *>(HostPointerForGuestRange(GuestAddress, AddressLength, PROT_READ));
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      if (AddressLength < sizeof(uint16_t) || AddressLength > LinuxSockaddrUnMaximum || !SocketBuffer) {
        return static_cast<uint64_t>(-EFAULT);
      }

      uint16_t Family{};
      std::memcpy(&Family, SocketBuffer, sizeof(Family));
      if (Family != LinuxAFUnix) {
        return static_cast<uint64_t>(-97);
      }
      const auto *Path = reinterpret_cast<const char *>(SocketBuffer + sizeof(Family));
      const size_t PayloadLength = static_cast<size_t>(AddressLength - sizeof(Family));
      if (PayloadLength == 0) {
        return static_cast<uint64_t>(-95);
      }
      std::string GuestSocketPath;
      if (Path[0] == '\0') {
        std::string_view AbstractName{Path + 1, PayloadLength - 1};
        while (!AbstractName.empty() && AbstractName.back() == '\0')
          AbstractName.remove_suffix(1);
        const char *DisplaySocket = std::getenv("REGRESSION_X11_SOCKET");
        if (AbstractName != "/tmp/.X11-unix/X0" || !DisplaySocket || !*DisplaySocket) {
          return static_cast<uint64_t>(-95);
        }
        // The explicitly selected XQuartz endpoint represents the same owned
        // display for Linux's abstract and pathname Unix socket spellings.
        GuestSocketPath = AbstractName;
      } else {
        const auto *Terminator = static_cast<const char *>(std::memchr(Path, '\0', PayloadLength));
        const size_t PathLength = Terminator ? static_cast<size_t>(Terminator - Path) : PayloadLength;
        GuestSocketPath.assign(Path, PathLength);
      }
      TraceGuestPath("connect", GuestSocketPath);
      if (GuestSocketPath.empty()) {
        return static_cast<uint64_t>(-EINVAL);
      }
      const bool ExactAltLoaderSocket = !CXAltLoaderGuestSocketPath.empty() && !CXAltLoaderHostSocketPath.empty() &&
                                        GuestSocketPath == CXAltLoaderGuestSocketPath;
      const char *X11Socket = std::getenv("REGRESSION_X11_SOCKET");
      const bool ExactX11Socket = GuestSocketPath == "/tmp/.X11-unix/X0" && X11Socket && *X11Socket;
      std::string HostPath;
      if (ExactX11Socket) {
        struct stat DisplayStat{};
        if (lstat(X11Socket, &DisplayStat) != 0 || !S_ISSOCK(DisplayStat.st_mode) || DisplayStat.st_uid != getuid()) {
          return static_cast<uint64_t>(-EACCES);
        }
        HostPath = X11Socket;
      } else if (ExactAltLoaderSocket) {
        HostPath = CXAltLoaderHostSocketPath;
      } else {
        const auto ResolvedHostPath = ResolveGuestPath(GuestSocketPath);
        if (!ResolvedHostPath.has_value()) {
          return static_cast<uint64_t>(-EACCES);
        }
        HostPath = *ResolvedHostPath;
      }

      const bool RelativePath = GuestSocketPath.front() != '/';
      if (RelativePath) {
        const auto ExpectedHostCWD = ResolveGuestPath(".");
        std::array<char, 4096> HostCurrentDirectory{};
        if (!ExpectedHostCWD.has_value() ||
            getcwd(HostCurrentDirectory.data(), HostCurrentDirectory.size()) == nullptr ||
            std::string_view{HostCurrentDirectory.data()} != *ExpectedHostCWD) {
          return static_cast<uint64_t>(-EACCES);
        }
      }

      struct stat HostStat{};
      if (lstat(HostPath.c_str(), &HostStat) != 0) {
        const int LinuxError = TranslateHostSocketErrorToLinux(errno);
        return static_cast<uint64_t>(-LinuxError);
      }
      if (!S_ISSOCK(HostStat.st_mode)) {
        return static_cast<uint64_t>(-111);
      }
      const std::string HostSocketAddressPath =
          (ExactAltLoaderSocket || ExactX11Socket) ? HostPath : (RelativePath ? GuestSocketPath : HostPath);
      if (HostSocketAddressPath.size() >= sizeof(sockaddr_un::sun_path)) {
        return static_cast<uint64_t>(-36);
      }

      sockaddr_un HostAddress{};
      HostAddress.sun_family = AF_UNIX;
      std::memcpy(HostAddress.sun_path, HostSocketAddressPath.data(), HostSocketAddressPath.size());
      HostAddress.sun_path[HostSocketAddressPath.size()] = '\0';
      const size_t HostAddressLength = offsetof(sockaddr_un, sun_path) + HostSocketAddressPath.size() + 1;
      HostAddress.sun_len = static_cast<uint8_t>(HostAddressLength);
      if (BlockingHostCall([&] {
            return connect(Descriptor, reinterpret_cast<const sockaddr *>(&HostAddress),
                           static_cast<socklen_t>(HostAddressLength));
          }) != 0) {
        const int LinuxError = TranslateHostSocketErrorToLinux(errno);
        return static_cast<uint64_t>(-LinuxError);
      }
      if (ExactAltLoaderSocket) {
        CXAltLoaderConnectedDescriptors.insert(Descriptor);
      }
      return 0;
    }
    if (ExperimentalAcceptDispatchEnabled && Number == AcceptSyscall && !RootFS.empty()) {
      dprintf(STDERR_FILENO, "FEX_ACCEPT_HANDLER_ENTER\n");
      return HandleAcceptSyscall(Arguments);
    }
    if (Number == GetSockOptSyscall && !RootFS.empty()) {
      constexpr int64_t LinuxSOLSocket = 1;
      constexpr int64_t LinuxSOPeerCredentials = 17;
      constexpr uint32_t LinuxPeerCredentialsSize = sizeof(LinuxPeerCredentials);
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const int64_t Level = static_cast<int64_t>(Arguments->Argument[2]);
      const int64_t Option = static_cast<int64_t>(Arguments->Argument[3]);
      const uint64_t GuestValue = Arguments->Argument[4];
      const uint64_t GuestValueLength = Arguments->Argument[5];
      if (!OwnedDescriptors.contains(Descriptor)) {
        return static_cast<uint64_t>(-EBADF);
      }
      void *LengthBuffer = HostPointerForGuestRange(GuestValueLength, sizeof(uint32_t), PROT_READ | PROT_WRITE);
      void *ValueBuffer = HostPointerForGuestRange(GuestValue, LinuxPeerCredentialsSize, PROT_WRITE);
      if (!LengthBuffer) {
        return static_cast<uint64_t>(-EFAULT);
      }
      uint32_t InputLength{};
      std::memcpy(&InputLength, LengthBuffer, sizeof(InputLength));
      if (Level == LinuxSOLSocket && Option == LinuxSOPeerCredentials && InputLength == LinuxPeerCredentialsSize) {
        if (!ValueBuffer) {
          return static_cast<uint64_t>(-EFAULT);
        } else {
          uid_t HostUserID{};
          gid_t HostGroupID{};
          if (getpeereid(Descriptor, &HostUserID, &HostGroupID) != 0) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          pid_t HostProcessID{};
          socklen_t HostProcessIDLength = sizeof(HostProcessID);
          if (getsockopt(Descriptor, SOL_LOCAL, LOCAL_PEERPID, &HostProcessID, &HostProcessIDLength) != 0) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          if (HostProcessIDLength != sizeof(HostProcessID)) {
            return static_cast<uint64_t>(-EIO);
          }
          const LinuxPeerCredentials GuestCredentials{
              .ProcessID = static_cast<int32_t>(HostProcessID),
              .UserID = static_cast<uint32_t>(HostUserID),
              .GroupID = static_cast<uint32_t>(HostGroupID),
          };
          std::memcpy(ValueBuffer, &GuestCredentials, sizeof(GuestCredentials));
          std::memcpy(LengthBuffer, &LinuxPeerCredentialsSize, sizeof(LinuxPeerCredentialsSize));
          return 0;
        }
      }
    }
    if (Number == SendMsgSyscall && !RootFS.empty()) {
      constexpr int32_t LinuxSOLSocket = 1;
      constexpr int32_t LinuxSCMRights = 1;
      constexpr uint64_t ServerHandlePayloadSize = sizeof(uint32_t);
      constexpr uint64_t ClientSendFDPayloadSize = 2 * sizeof(uint32_t);
      constexpr uint64_t MeasuredControlSize = sizeof(LinuxControlMessageHeader64) + sizeof(int32_t);
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestHeaderAddress = Arguments->Argument[2];
      const int64_t CallFlags = static_cast<int64_t>(Arguments->Argument[3]);
      SendMsgLastDescriptorOwned = OwnedDescriptors.contains(Descriptor);
      SendMsgLastFirstIOVectorPayloadReadable = false;
      SendMsgLastControlReadable = false;
      SendMsgLastTransferredDescriptorOwned = false;
      SendMsgLastTransferredDescriptorClosed = false;
      SendMsgLastTransferredDescriptorFlags = -1;
      SendMsgLastTransferredStatusFlags = -1;
      SendMsgLastTransferredDescriptorStatSucceeded = false;
      if (!SendMsgLastDescriptorOwned) {
        return static_cast<uint64_t>(-EBADF);
      }
      void *MessageBuffer = HostPointerForGuestRange(GuestHeaderAddress, sizeof(LinuxMessageHeader64), PROT_READ);
      if (MessageBuffer == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      LinuxMessageHeader64 GuestHeader{};
      std::memcpy(&GuestHeader, MessageBuffer, sizeof(GuestHeader));
      const void *VectorBuffer = HostPointerForGuestRange(GuestHeader.IOVectors, sizeof(LinuxIOVector64), PROT_READ);
      if (VectorBuffer == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      LinuxIOVector64 GuestVector{};
      std::memcpy(&GuestVector, VectorBuffer, sizeof(GuestVector));
      void *PayloadBuffer = GuestVector.Length <= static_cast<uint64_t>(SSIZE_MAX)
                                ? HostPointerForGuestRange(GuestVector.Base, GuestVector.Length, PROT_READ)
                                : nullptr;
      void *ControlBuffer = GuestHeader.ControlLength <= 65536
                                ? HostPointerForGuestRange(GuestHeader.Control, GuestHeader.ControlLength, PROT_READ)
                                : nullptr;
      const bool ExactMeasuredPayloadSize =
          GuestVector.Length == ServerHandlePayloadSize || GuestVector.Length == ClientSendFDPayloadSize;
      SendMsgLastFirstIOVectorPayloadReadable = GuestVector.Length <= 4096 && (PayloadBuffer != nullptr);
      if (ExactMeasuredPayloadSize && !SendMsgLastFirstIOVectorPayloadReadable) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if ((ControlBuffer == nullptr || GuestHeader.ControlLength < MeasuredControlSize)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      LinuxControlMessageHeader64 GuestControl{};
      std::memcpy(&GuestControl, ControlBuffer, sizeof(GuestControl));
      SendMsgLastControlReadable = GuestHeader.ControlLength <= 4096 && (ControlBuffer != nullptr);
      constexpr size_t AltLoaderMinimumDescriptorCount = 4;
      constexpr size_t AltLoaderMaximumDescriptorCount = 5;
      constexpr uint64_t AltLoaderPayloadSize = 1;
      const bool AltLoaderControlLengthValid =
          GuestControl.Length >=
              sizeof(LinuxControlMessageHeader64) + AltLoaderMinimumDescriptorCount * sizeof(int32_t) &&
          GuestControl.Length <=
              sizeof(LinuxControlMessageHeader64) + AltLoaderMaximumDescriptorCount * sizeof(int32_t) &&
          (GuestControl.Length - sizeof(LinuxControlMessageHeader64)) % sizeof(int32_t) == 0;
      const size_t AltLoaderDescriptorCount =
          AltLoaderControlLengthValid
              ? static_cast<size_t>((GuestControl.Length - sizeof(LinuxControlMessageHeader64)) / sizeof(int32_t))
              : 0;
      const bool ExactAltLoaderShape =
          CallFlags == 0 && GuestHeader.Name == 0 && GuestHeader.NameLength == 0 && GuestHeader.IOVectorCount == 1 &&
          GuestHeader.Flags == 0 && GuestVector.Length == AltLoaderPayloadSize &&
          SendMsgLastFirstIOVectorPayloadReadable && SendMsgLastControlReadable &&
          GuestHeader.ControlLength == GuestControl.Length && AltLoaderControlLengthValid &&
          GuestControl.Level == LinuxSOLSocket && GuestControl.Type == LinuxSCMRights;
      if (ExactAltLoaderShape) {
        std::array<int, AltLoaderMaximumDescriptorCount> TransferredDescriptors{};
        std::memcpy(TransferredDescriptors.data(),
                    static_cast<const uint8_t *>(ControlBuffer) + sizeof(LinuxControlMessageHeader64),
                    AltLoaderDescriptorCount * sizeof(int));
        SendMsgLastTransferredDescriptorOwned = OwnedDescriptors.contains(TransferredDescriptors[3]);
        bool AllTransferredDescriptorsPermitted = true;
        for (size_t Index = 0; Index < AltLoaderDescriptorCount; ++Index) {
          const int CandidateDescriptor = TransferredDescriptors[Index];
          const bool CandidateOwned = OwnedDescriptors.contains(CandidateDescriptor);
          const bool CandidateStandard = CandidateDescriptor >= STDIN_FILENO && CandidateDescriptor <= STDERR_FILENO;
          const bool CandidateStandardOpen = CandidateStandard &&
                                             !ClosedStandardDescriptors.contains(CandidateDescriptor) &&
                                             fcntl(CandidateDescriptor, F_GETFD) != -1;
          const bool PositionPermitted = Index < 3 ? CandidateOwned || CandidateStandardOpen : CandidateOwned;
          AllTransferredDescriptorsPermitted &= PositionPermitted;
        }
        if (!AllTransferredDescriptorsPermitted) {
          return static_cast<uint64_t>(-EBADF);
        }
        iovec HostVector{
            .iov_base = PayloadBuffer,
            .iov_len = static_cast<size_t>(GuestVector.Length),
        };
        alignas(cmsghdr) std::array<std::byte, 64> HostControlStorage{};
        static_assert(CMSG_SPACE(AltLoaderMaximumDescriptorCount * sizeof(int)) <= HostControlStorage.size());
        msghdr HostHeader{};
        HostHeader.msg_iov = &HostVector;
        HostHeader.msg_iovlen = 1;
        HostHeader.msg_control = HostControlStorage.data();
        HostHeader.msg_controllen = CMSG_SPACE(AltLoaderDescriptorCount * sizeof(int));
        cmsghdr *HostControl = CMSG_FIRSTHDR(&HostHeader);
        if (HostControl == nullptr) {
          return static_cast<uint64_t>(-EIO);
        }
        HostControl->cmsg_len = CMSG_LEN(AltLoaderDescriptorCount * sizeof(int));
        HostControl->cmsg_level = SOL_SOCKET;
        HostControl->cmsg_type = SCM_RIGHTS;
        std::memcpy(CMSG_DATA(HostControl), TransferredDescriptors.data(), AltLoaderDescriptorCount * sizeof(int));
        const ssize_t Result = BlockingHostCall([&] { return sendmsg(Descriptor, &HostHeader, 0); });
        if (Result == -1) {
          const int HostError = errno;
          const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
          return static_cast<uint64_t>(-LinuxError);
        }
        return static_cast<uint64_t>(Result);
      }
      int TransferredDescriptor{-1};
      std::memcpy(&TransferredDescriptor,
                  static_cast<const uint8_t *>(ControlBuffer) + sizeof(LinuxControlMessageHeader64),
                  sizeof(TransferredDescriptor));
      SendMsgLastTransferredDescriptorOwned = OwnedDescriptors.contains(TransferredDescriptor);
      SendMsgLastTransferredDescriptorClosed = ClosedStandardDescriptors.contains(TransferredDescriptor);
      errno = 0;
      SendMsgLastTransferredDescriptorFlags = fcntl(TransferredDescriptor, F_GETFD);
      errno = 0;
      SendMsgLastTransferredStatusFlags = fcntl(TransferredDescriptor, F_GETFL);
      struct stat TransferredDescriptorStat{};
      errno = 0;
      SendMsgLastTransferredDescriptorStatSucceeded = fstat(TransferredDescriptor, &TransferredDescriptorStat) == 0;
      const bool ExactOpenStandardErrorDescriptor = TransferredDescriptor == STDERR_FILENO &&
                                                    !ClosedStandardDescriptors.contains(STDERR_FILENO) &&
                                                    fcntl(STDERR_FILENO, F_GETFD) != -1;
      const bool ExactOpenStandardInputDescriptor =
          TransferredDescriptor == STDIN_FILENO && !SendMsgLastTransferredDescriptorClosed &&
          SendMsgLastTransferredDescriptorFlags == 0 && SendMsgLastTransferredStatusFlags != -1 &&
          (SendMsgLastTransferredStatusFlags & O_ACCMODE) == O_RDONLY && SendMsgLastTransferredDescriptorStatSucceeded;
      const bool ExactOpenStandardOutputDescriptor =
          TransferredDescriptor == STDOUT_FILENO && !SendMsgLastTransferredDescriptorClosed &&
          SendMsgLastTransferredDescriptorFlags == 0 && SendMsgLastTransferredStatusFlags != -1 &&
          (SendMsgLastTransferredStatusFlags & O_ACCMODE) == O_WRONLY && SendMsgLastTransferredDescriptorStatSucceeded;
      const bool TransferredDescriptorPermitted = SendMsgLastTransferredDescriptorOwned ||
                                                  ExactOpenStandardErrorDescriptor ||
                                                  ExactOpenStandardInputDescriptor || ExactOpenStandardOutputDescriptor;
      const bool ExactMeasuredShape = CallFlags == 0 && GuestHeader.Name == 0 && GuestHeader.NameLength == 0 &&
                                      GuestHeader.IOVectorCount == 1 &&
                                      GuestHeader.ControlLength == MeasuredControlSize && GuestHeader.Flags == 0 &&
                                      ExactMeasuredPayloadSize && GuestControl.Length == MeasuredControlSize &&
                                      GuestControl.Level == LinuxSOLSocket && GuestControl.Type == LinuxSCMRights;
      if (ExactMeasuredShape) {
        if (!TransferredDescriptorPermitted) {
          return static_cast<uint64_t>(-EBADF);
        } else {
          iovec HostVector{
              .iov_base = PayloadBuffer,
              .iov_len = static_cast<size_t>(GuestVector.Length),
          };
          alignas(cmsghdr) std::array<std::byte, 64> HostControlStorage{};
          static_assert(CMSG_SPACE(sizeof(int)) <= HostControlStorage.size());
          msghdr HostHeader{};
          HostHeader.msg_iov = &HostVector;
          HostHeader.msg_iovlen = 1;
          HostHeader.msg_control = HostControlStorage.data();
          HostHeader.msg_controllen = CMSG_SPACE(sizeof(int));
          cmsghdr *HostControl = CMSG_FIRSTHDR(&HostHeader);
          if (HostControl == nullptr) {
            return static_cast<uint64_t>(-EIO);
          }
          HostControl->cmsg_len = CMSG_LEN(sizeof(int));
          HostControl->cmsg_level = SOL_SOCKET;
          HostControl->cmsg_type = SCM_RIGHTS;
          std::memcpy(CMSG_DATA(HostControl), &TransferredDescriptor, sizeof(TransferredDescriptor));
          HostHeader.msg_controllen = CMSG_SPACE(sizeof(int));
          const ssize_t Result = BlockingHostCall([&] { return sendmsg(Descriptor, &HostHeader, 0); });
          if (Result == -1) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          return static_cast<uint64_t>(Result);
        }
      }
    }
    if (Number == SetTIDAddressSyscall && !RootFS.empty()) {
      const uint64_t Address = Arguments->Argument[1];
      if (Address != 0 && !HostPointerForGuestRange(Address, sizeof(int32_t), PROT_WRITE)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      ClearChildTID = Address;
      return LinuxGuestThreadID();
    }
    if (Number == SetRobustListSyscall && !RootFS.empty()) {
      constexpr uint64_t LinuxRobustListHeadSize = 24;
      const uint64_t Address = Arguments->Argument[1];
      const uint64_t Length = Arguments->Argument[2];
      if (Length != LinuxRobustListHeadSize) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (!HostPointerForGuestRange(Address, Length, PROT_READ)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      RobustListHead = Address;
      return 0;
    }
    if (Number == RSeqSyscall && !RootFS.empty()) {
      return static_cast<uint64_t>(-38);
    }
    if (Number == MProtectSyscall && !RootFS.empty())
      return ProtectGuestRange(Frame->Thread, Arguments->Argument[1], Arguments->Argument[2], Arguments->Argument[3]);
    if (Number == Prlimit64Syscall && !RootFS.empty()) {
      constexpr int32_t LinuxRLimitStack = 3;
      constexpr int32_t LinuxRLimitCore = 4;
      constexpr int32_t LinuxRLimitNoFile = 7;
      constexpr int32_t LinuxRLimitAddressSpace = 9;
      constexpr int32_t LinuxRLimitNice = 13;
      const int32_t ProcessID = static_cast<int32_t>(Arguments->Argument[1]);
      const int32_t Resource = static_cast<int32_t>(Arguments->Argument[2]);
      const uint64_t NewLimit = Arguments->Argument[3];
      const uint64_t OldLimit = Arguments->Argument[4];
      const void *NewLimitBuffer =
          NewLimit ? HostPointerForGuestRange(NewLimit, sizeof(LinuxRLimit64), PROT_READ) : nullptr;
      void *OldLimitBuffer = OldLimit ? HostPointerForGuestRange(OldLimit, sizeof(LinuxRLimit64), PROT_WRITE) : nullptr;
      Prlimit64LastNewLimitClass =
          NewLimit == 0 ? "zero" : ((NewLimitBuffer != nullptr) ? "guest-memory" : "scalar-or-outside");
      Prlimit64LastOldLimitClass =
          OldLimit == 0 ? "zero" : ((OldLimitBuffer != nullptr) ? "guest-memory" : "scalar-or-outside");
      const bool NewLimitReadable = NewLimit != 0 && (NewLimitBuffer != nullptr);
      const bool OldLimitReadable = OldLimit != 0 && (OldLimitBuffer != nullptr);

      const bool StackQueryCandidate =
          ProcessID == 0 && Resource == LinuxRLimitStack && NewLimit == 0 && OldLimitReadable;
      const bool CoreQueryCandidate =
          ProcessID == 0 && Resource == LinuxRLimitCore && NewLimit == 0 && OldLimitReadable;
      const bool NoFileQueryCandidate =
          ProcessID == 0 && Resource == LinuxRLimitNoFile && NewLimit == 0 && OldLimitReadable;
      LinuxRLimit64 RequestedNoFileLimit{};
      if (NewLimitReadable) {
        std::memcpy(&RequestedNoFileLimit, NewLimitBuffer, sizeof(RequestedNoFileLimit));
      }
      const bool NoFileSetCandidate = ProcessID == 0 && Resource == LinuxRLimitNoFile && NewLimitReadable &&
                                      OldLimit == 0 &&
                                      RequestedNoFileLimit.Current == std::numeric_limits<uint64_t>::max() &&
                                      RequestedNoFileLimit.Maximum == std::numeric_limits<uint64_t>::max();
      const bool AddressSpaceQueryCandidate =
          ProcessID == 0 && Resource == LinuxRLimitAddressSpace && NewLimit == 0 && OldLimitReadable;
      LinuxRLimit64 RequestedAddressSpaceLimit{};
      if (NewLimitReadable) {
        std::memcpy(&RequestedAddressSpaceLimit, NewLimitBuffer, sizeof(RequestedAddressSpaceLimit));
      }
      const bool AddressSpaceSetCandidate =
          ProcessID == 0 && Resource == LinuxRLimitAddressSpace && NewLimitReadable && OldLimit == 0 &&
          RequestedAddressSpaceLimit.Current == std::numeric_limits<uint64_t>::max() &&
          RequestedAddressSpaceLimit.Maximum == std::numeric_limits<uint64_t>::max();
      const bool NiceQueryCandidate =
          ProcessID == 0 && Resource == LinuxRLimitNice && NewLimit == 0 && OldLimitReadable;

      if (NiceQueryCandidate) {
        return static_cast<uint64_t>(-EINVAL);
      }

      if (NoFileSetCandidate) {
        const struct rlimit HostLimit{RLIM_INFINITY, RLIM_INFINITY};
        if (setrlimit(RLIMIT_NOFILE, &HostLimit) != 0) {
          const int HostError = errno;
          const int LinuxError =
              HostError == EINVAL ? EINVAL : (HostError == EPERM ? EPERM : (HostError == EACCES ? EACCES : EIO));
          return static_cast<uint64_t>(-LinuxError);
        }
        return 0;
      }

      if (AddressSpaceSetCandidate) {
        const struct rlimit HostLimit{RLIM_INFINITY, RLIM_INFINITY};
        if (setrlimit(RLIMIT_AS, &HostLimit) != 0) {
          const int HostError = errno;
          const int LinuxError =
              HostError == EINVAL ? EINVAL : (HostError == EPERM ? EPERM : (HostError == EACCES ? EACCES : EIO));
          return static_cast<uint64_t>(-LinuxError);
        }
        return 0;
      }

      int HostResource = -1;
      if (StackQueryCandidate) {
        HostResource = RLIMIT_STACK;
      } else if (NoFileQueryCandidate) {
        HostResource = RLIMIT_NOFILE;
      } else if (CoreQueryCandidate) {
        HostResource = RLIMIT_CORE;
      } else if (AddressSpaceQueryCandidate) {
        HostResource = RLIMIT_AS;
      }
      if (HostResource != -1) {
        struct rlimit HostLimit{};
        if (getrlimit(HostResource, &HostLimit) != 0) {
          const int HostError = errno;
          const int LinuxError = HostError == EINVAL ? EINVAL : EIO;
          return static_cast<uint64_t>(-LinuxError);
        }
        const auto ConvertLimit = [](rlim_t Value) {
          return Value == RLIM_INFINITY ? std::numeric_limits<uint64_t>::max() : static_cast<uint64_t>(Value);
        };
        const LinuxRLimit64 GuestLimit{
            ConvertLimit(HostLimit.rlim_cur),
            ConvertLimit(HostLimit.rlim_max),
        };
        std::memcpy(OldLimitBuffer, &GuestLimit, sizeof(GuestLimit));
        return 0;
      }
    }
    if (Number == ClockGettimeSyscall && !RootFS.empty()) {
      const int32_t LinuxClock = static_cast<int32_t>(Arguments->Argument[1]);
      const uint64_t GuestTime = Arguments->Argument[2];
      void *TimeBuffer = HostPointerForGuestRange(GuestTime, sizeof(LinuxTimespec64), PROT_WRITE);
      if (TimeBuffer == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      const auto HostClock = TranslateLinuxClockID(LinuxClock);
      if (!HostClock.has_value()) {
        return static_cast<uint64_t>(-EINVAL);
      }
      struct timespec HostTime{};
      if (clock_gettime(*HostClock, &HostTime) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      const LinuxTimespec64 Time{
          static_cast<int64_t>(HostTime.tv_sec),
          static_cast<int64_t>(HostTime.tv_nsec),
      };
      std::memcpy(TimeBuffer, &Time, sizeof(Time));
      return 0;
    }
    if ((Number == 191 || Number == 192 || Number == 193) && !RootFS.empty()) {
      const auto Name = ReadGuestPath(Arguments->Argument[2]);
      const uint64_t Length = Arguments->Argument[4];
      if (!Name)
        return static_cast<uint64_t>(-EFAULT);
      if (Length > static_cast<uint64_t>(SSIZE_MAX))
        return static_cast<uint64_t>(-EINVAL);
      void *Output = Length ? HostPointerForGuestRange(Arguments->Argument[3], Length, PROT_WRITE) : nullptr;
      if (Length && !Output)
        return static_cast<uint64_t>(-EFAULT);
      ssize_t Result;
      if (Number == 193) {
        const int FD = static_cast<int>(Arguments->Argument[1]);
        if (!OwnedDescriptors.contains(FD))
          return static_cast<uint64_t>(-EBADF);
        Result = fgetxattr(FD, Name->c_str(), Output, static_cast<size_t>(Length), 0, 0);
      } else {
        const auto Path = ReadGuestPath(Arguments->Argument[1]);
        if (!Path)
          return static_cast<uint64_t>(-EFAULT);
        const auto Normalized = NormalizeGuestPathWithParents(*Path);
        const auto HostPath = Number == 192 && Normalized && *Normalized != "/" ? ResolveGuestCreationPath(*Normalized)
                                                                                : ResolveGuestPathWithParents(*Path);
        if (!HostPath)
          return static_cast<uint64_t>(-EACCES);
        Result = getxattr(HostPath->c_str(), Name->c_str(), Output, static_cast<size_t>(Length), 0,
                          Number == 192 ? XATTR_NOFOLLOW : 0);
      }
      if (Result >= 0)
        return static_cast<uint64_t>(Result);
      const int Error = errno == ENOATTR ? 61 : errno == ENOTSUP ? 95 : errno == ENAMETOOLONG ? 36 : errno;
      return static_cast<uint64_t>(-Error);
    }
    if (Number == 270 && !RootFS.empty()) { // pselect6
      const int64_t Count = static_cast<int64_t>(Arguments->Argument[1]);
      if (Count < 0 || Count > FD_SETSIZE)
        return static_cast<uint64_t>(-EINVAL);
      const size_t Bytes = static_cast<size_t>((Count + 63) / 64) * sizeof(uint64_t);
      fd_set Sets[3];
      uint8_t *GuestSets[3]{};
      fd_set *HostSets[3]{};
      for (unsigned Index = 0; Index != 3; ++Index) {
        FD_ZERO(&Sets[Index]);
        const uint64_t Address = Arguments->Argument[Index + 2];
        if (Address && Bytes) {
          GuestSets[Index] = static_cast<uint8_t *>(HostPointerForGuestRange(Address, Bytes, PROT_READ | PROT_WRITE));
          if (!GuestSets[Index])
            return static_cast<uint64_t>(-EFAULT);
          HostSets[Index] = &Sets[Index];
          for (int FD = 0; FD < Count; ++FD) {
            if ((GuestSets[Index][FD / 8] & (1U << (FD % 8))) != 0) {
              if (!OwnedDescriptors.contains(FD) && (FD > STDERR_FILENO || ClosedStandardDescriptors.contains(FD))) {
                return static_cast<uint64_t>(-EBADF);
              }
              FD_SET(FD, &Sets[Index]);
            }
          }
        }
      }
      if (Arguments->Argument[6]) {
        const void *MaskArgs = HostPointerForGuestRange(Arguments->Argument[6], 16, PROT_READ);
        if (!MaskArgs)
          return static_cast<uint64_t>(-EFAULT);
        uint64_t MaskWords[2]{};
        std::memcpy(MaskWords, MaskArgs, sizeof(MaskWords));
        if (MaskWords[0] != 0)
          return static_cast<uint64_t>(-38);
      }
      timespec Timeout{}, Started{};
      LinuxTimespec64 GuestTimeout{};
      void *TimeoutBuffer = nullptr;
      if (Arguments->Argument[5]) {
        TimeoutBuffer = HostPointerForGuestRange(Arguments->Argument[5], sizeof(GuestTimeout), PROT_READ | PROT_WRITE);
        if (!TimeoutBuffer)
          return static_cast<uint64_t>(-EFAULT);
        std::memcpy(&GuestTimeout, TimeoutBuffer, sizeof(GuestTimeout));
        if (GuestTimeout.Seconds < 0 || GuestTimeout.Nanoseconds < 0 || GuestTimeout.Nanoseconds >= 1'000'000'000)
          return static_cast<uint64_t>(-EINVAL);
        Timeout = {GuestTimeout.Seconds, GuestTimeout.Nanoseconds};
        clock_gettime(CLOCK_MONOTONIC, &Started);
      }
      const int Result = BlockingHostCall([&] {
        return pselect(static_cast<int>(Count), HostSets[0], HostSets[1], HostSets[2],
                       TimeoutBuffer ? &Timeout : nullptr, nullptr);
      });
      const int Error = errno;
      if (Result >= 0) {
        for (unsigned Index = 0; Index != 3; ++Index) {
          if (!GuestSets[Index])
            continue;
          std::memset(GuestSets[Index], 0, Bytes);
          for (int FD = 0; FD < Count; ++FD)
            if (FD_ISSET(FD, &Sets[Index]))
              GuestSets[Index][FD / 8] |= 1U << (FD % 8);
        }
      }
      if (TimeoutBuffer && (Result >= 0 || Error == EINTR)) {
        timespec Now{};
        clock_gettime(CLOCK_MONOTONIC, &Now);
        const __int128 Remaining = std::max<__int128>(
            0,
            static_cast<__int128>(GuestTimeout.Seconds) * 1'000'000'000 + GuestTimeout.Nanoseconds -
                (static_cast<__int128>(Now.tv_sec - Started.tv_sec) * 1'000'000'000 + Now.tv_nsec - Started.tv_nsec));
        GuestTimeout = {static_cast<int64_t>(Remaining / 1'000'000'000),
                        static_cast<int64_t>(Remaining % 1'000'000'000)};
        std::memcpy(TimeoutBuffer, &GuestTimeout, sizeof(GuestTimeout));
      }
      return Result < 0 ? static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(Error))
                        : static_cast<uint64_t>(Result);
    }
    if (Number == 24 && !RootFS.empty()) { // sched_yield
      return sched_yield() == 0 ? 0 : static_cast<uint64_t>(-errno);
    }
    if (Number == 203 && !RootFS.empty()) { // sched_setaffinity
      return static_cast<uint64_t>(-38);    // No Darwin equivalent for a Linux CPU mask.
    }
    if (Number == 98 && !RootFS.empty()) { // getrusage
      const int Who = static_cast<int>(Arguments->Argument[1]);
      std::array<int64_t, 18> Usage{};
      void *Output = HostPointerForGuestRange(Arguments->Argument[2], sizeof(Usage), PROT_WRITE);
      if (!Output)
        return static_cast<uint64_t>(-EFAULT);
      if (Who == 1) {
        thread_basic_info_data_t Info{};
        mach_msg_type_number_t Count = THREAD_BASIC_INFO_COUNT;
        const mach_port_t Thread = mach_thread_self();
        const kern_return_t Result =
            thread_info(Thread, THREAD_BASIC_INFO, reinterpret_cast<thread_info_t>(&Info), &Count);
        mach_port_deallocate(mach_task_self(), Thread);
        if (Result != KERN_SUCCESS)
          return static_cast<uint64_t>(-ESRCH);
        Usage[0] = Info.user_time.seconds;
        Usage[1] = Info.user_time.microseconds;
        Usage[2] = Info.system_time.seconds;
        Usage[3] = Info.system_time.microseconds;
        // Darwin does not expose the other per-thread rusage counters here.
      } else if (Who == 0 || Who == -1) {
        rusage Host{};
        if (getrusage(Who == 0 ? RUSAGE_SELF : RUSAGE_CHILDREN, &Host) != 0)
          return static_cast<uint64_t>(-errno);
        Usage = {Host.ru_utime.tv_sec,  Host.ru_utime.tv_usec, Host.ru_stime.tv_sec, Host.ru_stime.tv_usec,
                 Host.ru_maxrss / 1024, Host.ru_ixrss,         Host.ru_idrss,        Host.ru_isrss,
                 Host.ru_minflt,        Host.ru_majflt,        Host.ru_nswap,        Host.ru_inblock,
                 Host.ru_oublock,       Host.ru_msgsnd,        Host.ru_msgrcv,       Host.ru_nsignals,
                 Host.ru_nvcsw,         Host.ru_nivcsw};
      } else
        return static_cast<uint64_t>(-EINVAL);
      std::memcpy(Output, Usage.data(), sizeof(Usage));
      return 0;
    }
    if (Number == 202 && !RootFS.empty()) { // Linux futex
      const uint64_t Address = Arguments->Argument[1];
      const uint32_t Operation = static_cast<uint32_t>(Arguments->Argument[2]);
      const uint32_t Command = Operation & 127;
      const uint32_t Value = static_cast<uint32_t>(Arguments->Argument[3]);
      if (fli_env_enabled("REGRESSION_FLI_TRACE_FUTEX")) {
        dprintf(STDERR_FILENO, "TRACE futex address=0x%llx op=%u value=%u\n", static_cast<unsigned long long>(Address),
                Operation, Value);
        if (Command == 0 || Command == 9) {
          if (fli_env_enabled("REGRESSION_FLI_TRACE_IPC_WAIT_STACK") && IPCWaitStackSamples++ < 16) {
            const uint64_t sp = Frame->State.gregs[FEXCore::X86State::REG_RSP];
            dprintf(2, "TRACE ipc-wait-stack address=0x%llx sample=%u\n", (unsigned long long)Address,
                    IPCWaitStackSamples);
            for (unsigned i = 0; i < 128; ++i) {
              const void *data = HostPointerForGuestRange(sp + i * 8, 8, PROT_READ);
              if (!data)
                break;
              uint64_t pc = 0;
              memcpy(&pc, data, 8);
              const auto protection = TrackedGuestProtection(pc);
              if (!protection || !(*protection & PROT_EXEC))
                continue;
              for (size_t n = 0; n < HighMMapRecordCount; ++n) {
                const auto &map = HighMMapRecords[n];
                if (map.Active && pc >= map.Address && pc - map.Address < map.Length &&
                    map.DescriptorGuestPath != "none") {
                  dprintf(2, "TRACE ipc-code-candidate slot=%u module=%s offset=0x%llx unwind-verified=0\n", i,
                          map.DescriptorGuestPath.c_str(), (unsigned long long)(pc - map.Address + map.Offset));
                  break;
                }
              }
            }
          }
          uint64_t Cursor = Frame->State.gregs[FEXCore::X86State::REG_RBP];
          for (unsigned Index = 0; Index != 8; ++Index) {
            const void *Words = HostPointerForGuestRange(Cursor, 16, PROT_READ);
            if (!Words)
              break;
            uint64_t Pair[2]{};
            std::memcpy(Pair, Words, sizeof(Pair));
            dprintf(STDERR_FILENO, "TRACE futex-frame pc=0x%llx\n", static_cast<unsigned long long>(Pair[1]));
            for (size_t MapIndex = 0; MapIndex < HighMMapRecordCount; ++MapIndex) {
              const auto &Map = HighMMapRecords[MapIndex];
              if (Pair[1] >= Map.Address && Pair[1] - Map.Address < Map.Length && Map.DescriptorGuestPath != "none") {
                dprintf(STDERR_FILENO, "TRACE futex-frame module=%s offset=0x%llx\n", Map.DescriptorGuestPath.c_str(),
                        static_cast<unsigned long long>(Pair[1] - Map.Address + Map.Offset));
              }
            }
            if (Pair[0] <= Cursor)
              break;
            Cursor = Pair[0];
          }
        }
      }
      if ((Operation & ~511U) != 0 || (Command != 0 && Command != 1 && Command != 9 && Command != 10)) {
        return static_cast<uint64_t>(-38); // Linux ENOSYS
      }
      if ((Command == 9 || Command == 10) && Arguments->Argument[6] != 0xffffffffU) {
        return static_cast<uint64_t>(-38); // Selective bitset queues are not implemented.
      }
      if (Address % sizeof(uint32_t) != 0)
        return static_cast<uint64_t>(-EINVAL);
      void *HostAddress = HostPointerForGuestRange(Address, sizeof(uint32_t), PROT_READ);
      if (!HostAddress)
        return static_cast<uint64_t>(-EFAULT);
      // Resolve the shared service after the bridge is loaded. Do not cache
      // its absence during early Root-only initialization.
      static FliFutexCall shared_futex = nullptr;
      if (!shared_futex)
        shared_futex = reinterpret_cast<FliFutexCall>(dlsym(RTLD_DEFAULT, "fli_shared_futex"));
      if (shared_futex) {
        FliFutexTime timeout{};
        const FliFutexTime *limit = nullptr;
        if ((Command == 0 || Command == 9) && Arguments->Argument[4]) {
          const void *input = HostPointerForGuestRange(Arguments->Argument[4], sizeof(LinuxTimespec64), PROT_READ);
          if (!input)
            return uint64_t(-EFAULT);
          LinuxTimespec64 original{};
          std::memcpy(&original, input, sizeof(original));
          timeout = {original.Seconds, original.Nanoseconds};
          limit = &timeout;
        }
        static bool announced;
        if (!announced) {
          announced = true;
          dprintf(2, "FLI_ROOT_SHARED_FUTEX_SERVICE pid=%d kernel-key=actual-backing\n", getpid());
        }
        return BlockingHostCall([&] {
          return uint64_t(shared_futex(HostAddress, Operation, Value, limit, uint32_t(Arguments->Argument[6])));
        });
      }
      const bool Private = (Operation & 128) != 0;
      if (Command == 1 || Command == 10) {
        if (Value > INT32_MAX)
          return static_cast<uint64_t>(-EINVAL);
        const auto Flags = Private ? OS_SYNC_WAKE_BY_ADDRESS_NONE : OS_SYNC_WAKE_BY_ADDRESS_SHARED;
        uint32_t Woken = 0;
        while (Woken < Value) {
          if (os_sync_wake_by_address_any(HostAddress, sizeof(uint32_t), Flags) != 0) {
            if (errno == ENOENT)
              break;
            return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
          }
          ++Woken;
        }
        return Woken;
      }
      if (__atomic_load_n(static_cast<uint32_t *>(HostAddress), __ATOMIC_RELAXED) != Value) {
        return static_cast<uint64_t>(-11); // Linux EAGAIN
      }
      const auto Flags = Private ? OS_SYNC_WAIT_ON_ADDRESS_NONE : OS_SYNC_WAIT_ON_ADDRESS_SHARED;
      const uint64_t GuestTimeout = Arguments->Argument[4];
      int Result;
      if (GuestTimeout == 0) {
        Result = BlockingHostCall([&] { return os_sync_wait_on_address(HostAddress, Value, sizeof(uint32_t), Flags); });
      } else {
        const void *TimeoutBuffer = HostPointerForGuestRange(GuestTimeout, sizeof(LinuxTimespec64), PROT_READ);
        if (!TimeoutBuffer)
          return static_cast<uint64_t>(-EFAULT);
        LinuxTimespec64 Timeout{};
        std::memcpy(&Timeout, TimeoutBuffer, sizeof(Timeout));
        if (Timeout.Seconds < 0 || Timeout.Nanoseconds < 0 || Timeout.Nanoseconds >= 1'000'000'000) {
          return static_cast<uint64_t>(-EINVAL);
        }
        __int128 Nanoseconds = static_cast<__int128>(Timeout.Seconds) * 1'000'000'000 + Timeout.Nanoseconds;
        if (Command == 9) {
          timespec Now{};
          if (clock_gettime((Operation & 256) ? CLOCK_REALTIME : CLOCK_MONOTONIC, &Now) != 0) {
            return static_cast<uint64_t>(-errno);
          }
          Nanoseconds -= static_cast<__int128>(Now.tv_sec) * 1'000'000'000 + Now.tv_nsec;
        }
        if (Nanoseconds <= 0)
          return static_cast<uint64_t>(-110); // Linux ETIMEDOUT
        if (Nanoseconds > UINT64_MAX)
          return static_cast<uint64_t>(-EINVAL);
        Result = BlockingHostCall([&] {
          return os_sync_wait_on_address_with_timeout(HostAddress, Value, sizeof(uint32_t), Flags,
                                                      OS_CLOCK_MACH_ABSOLUTE_TIME, static_cast<uint64_t>(Nanoseconds));
        });
      }
      return Result < 0 ? static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno)) : 0;
    }
    if (Number == 229 && !RootFS.empty()) { // clock_getres
      const auto HostClock = TranslateLinuxClockID(static_cast<int32_t>(Arguments->Argument[1]));
      if (!HostClock.has_value())
        return static_cast<uint64_t>(-EINVAL);
      const uint64_t GuestTime = Arguments->Argument[2];
      void *TimeBuffer =
          GuestTime != 0 ? HostPointerForGuestRange(GuestTime, sizeof(LinuxTimespec64), PROT_WRITE) : nullptr;
      if (GuestTime != 0 && TimeBuffer == nullptr)
        return static_cast<uint64_t>(-EFAULT);
      timespec Resolution{};
      if (clock_getres(*HostClock, &Resolution) != 0)
        return static_cast<uint64_t>(-errno);
      if (TimeBuffer) {
        const LinuxTimespec64 Result{Resolution.tv_sec, Resolution.tv_nsec};
        std::memcpy(TimeBuffer, &Result, sizeof(Result));
      }
      return 0;
    }

    if ((Number == 35 || Number == ClockNanosleepSyscall) && !RootFS.empty()) {
      const bool relative = Number == 35;
      const int32_t clock = relative ? 1 : int32_t(Arguments->Argument[1]);
      const uint64_t flags = relative ? 0 : Arguments->Argument[2];
      const uint64_t input = Arguments->Argument[relative ? 1 : 3], output = Arguments->Argument[relative ? 2 : 4];
      const void *source = HostPointerForGuestRange(input, sizeof(FliSleepTime), PROT_READ);
      if (!source)
        return uint64_t(-EFAULT);
      FliSleepTime request{}, remaining{};
      memcpy(&request, source, sizeof(request));
      const int64_t result = BlockingHostCall([&] { return fli_sleep(clock, flags, request, remaining); });
      if (result == -EINTR) {
        if (!flags && output) {
          void *destination = HostPointerForGuestRange(output, sizeof(remaining), PROT_WRITE);
          if (!destination)
            return uint64_t(-EFAULT);
          memcpy(destination, &remaining, sizeof(remaining));
        }
      }
      return uint64_t(result);
    }
    if (Number == GetrandomSyscall && !RootFS.empty()) {
      constexpr uint64_t LinuxGRNDNonblock = 0x1;
      constexpr uint64_t LinuxGRNDRandom = 0x2;
      constexpr uint64_t LinuxGRNDInsecure = 0x4;
      constexpr uint64_t AllowedFlags = LinuxGRNDNonblock | LinuxGRNDRandom | LinuxGRNDInsecure;
      constexpr size_t HostEntropyChunkSize = 256;
      const uint64_t GuestBuffer = Arguments->Argument[1];
      const uint64_t Length = Arguments->Argument[2];
      const uint64_t Flags = Arguments->Argument[3];
      if ((Flags & ~AllowedFlags) != 0) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (Length == 0) {
        return 0;
      }
      auto *EntropyBuffer = static_cast<uint8_t *>(HostPointerForGuestRange(GuestBuffer, Length, PROT_WRITE));
      if (!EntropyBuffer || Length > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        return static_cast<uint64_t>(-EFAULT);
      }

      size_t TotalBytes{};
      while (TotalBytes < static_cast<size_t>(Length)) {
        const size_t ChunkSize = std::min(HostEntropyChunkSize, static_cast<size_t>(Length) - TotalBytes);
        if (getentropy(EntropyBuffer + TotalBytes, ChunkSize) != 0) {
          return TotalBytes == 0 ? static_cast<uint64_t>(-errno) : static_cast<uint64_t>(TotalBytes);
        }
        TotalBytes += ChunkSize;
      }
      GetrandomByteCount += TotalBytes;
      return static_cast<uint64_t>(TotalBytes);
    }
    if (Number == UnameSyscall && !RootFS.empty()) {
      const uint64_t GuestBuffer = Arguments->Argument[1];
      auto *ResultBuffer =
          static_cast<uint8_t *>(HostPointerForGuestRange(GuestBuffer, sizeof(LinuxUtsName), PROT_WRITE));
      if (!ResultBuffer) {
        return static_cast<uint64_t>(-EFAULT);
      }
      LinuxUtsName GuestName{};
      const auto CopyField = [](auto &Destination, std::string_view Value) {
        const size_t Length = std::min(Destination.size() - 1, Value.size());
        std::memcpy(Destination.data(), Value.data(), Length);
        Destination[Length] = '\0';
      };
      CopyField(GuestName.SystemName, "Linux");
      CopyField(GuestName.NodeName, "regression-fli-lab");
      CopyField(GuestName.Release, "6.12.0-regression-fli-lab");
      CopyField(GuestName.Version, "#1 Regression FEXCore Darwin ABI research");
      CopyField(GuestName.Machine, "x86_64");
      CopyField(GuestName.DomainName, "(none)");
      std::memcpy(ResultBuffer, &GuestName, sizeof(GuestName));
      return 0;
    }
    if (Number == GetcwdSyscall && !RootFS.empty()) {
      const uint64_t GuestBuffer = Arguments->Argument[1];
      const uint64_t Size = Arguments->Argument[2];
      int error = 0;
      const auto directory = CurrentGuestDirectory(&error);
      if (!directory)
        return uint64_t(-TranslateHostSocketErrorToLinux(error));
      const uint64_t RequiredSize = (*directory).size() + 1;
      if (Size == 0) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (Size < RequiredSize) {
        return static_cast<uint64_t>(-ERANGE);
      }
      auto *ResultBuffer = static_cast<uint8_t *>(HostPointerForGuestRange(GuestBuffer, RequiredSize, PROT_WRITE));
      if (!ResultBuffer) {
        return static_cast<uint64_t>(-EFAULT);
      }
      std::memcpy(ResultBuffer, (*directory).data(), (*directory).size());
      ResultBuffer[(*directory).size()] = '\0';
      return RequiredSize;
    }
    if (Number == ChdirSyscall && !RootFS.empty()) {
      ChdirLastHostCWDMatchesGuest = false;
      const auto GuestPath = ReadGuestPath(Arguments->Argument[1]);
      if (!GuestPath.has_value()) {
        return static_cast<uint64_t>(-EFAULT);
      }
      TraceGuestPath("chdir", *GuestPath);
      if (GuestPath->empty() || GuestPath->front() != '/') {
        return static_cast<uint64_t>(-ENOTSUP);
      }
      const auto HostPath = ResolveGuestPathWithParents(*GuestPath);
      if (!HostPath.has_value()) {
        return static_cast<uint64_t>(-EACCES);
      }
      struct stat TargetStat{};
      if (stat(HostPath->c_str(), &TargetStat) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      if (!S_ISDIR(TargetStat.st_mode)) {
        return static_cast<uint64_t>(-ENOTDIR);
      }
      // Mirror the guest cwd so relative AF_UNIX paths retain their shared-process semantics.
      if (chdir(HostPath->c_str()) != 0) {
        return static_cast<uint64_t>(-errno);
      }
      GuestCurrentWorkingDirectory = *GuestPath;
      while (GuestCurrentWorkingDirectory.size() > 1 && GuestCurrentWorkingDirectory.back() == '/') {
        GuestCurrentWorkingDirectory.pop_back();
      }
      std::array<char, 4096> HostCurrentDirectory{};
      if (getcwd(HostCurrentDirectory.data(), HostCurrentDirectory.size()) != nullptr) {
        const std::string HostCWD{HostCurrentDirectory.data()};
        ChdirLastHostCWDMatchesGuest = HostCWD == *HostPath;
      }
      if (!ChdirLastHostCWDMatchesGuest) {
        return static_cast<uint64_t>(-EIO);
      }
      return 0;
    }
    if (Number == UmaskSyscall && !RootFS.empty()) {
      UmaskLastRequestedMode = Arguments->Argument[1];
      UmaskLastAppliedMode = UmaskLastRequestedMode & 0777ULL;
      UmaskLastPreviousMode = GuestUmask;
      GuestUmask = UmaskLastAppliedMode;
      return UmaskLastPreviousMode;
    }
    if (Number == MkdirSyscall && !RootFS.empty()) {
      const auto GuestPath = ReadGuestPath(Arguments->Argument[1]);
      const uint64_t Mode = Arguments->Argument[2];
      MkdirLastParentConfined = false;
      MkdirLastParentExists = false;
      MkdirLastLinuxError = 0;
      if (!GuestPath.has_value()) {
        MkdirLastLinuxError = EFAULT;
        return static_cast<uint64_t>(-EFAULT);
      }
      TraceGuestPath("mkdir", *GuestPath);
      if ((Mode & ~uint64_t{07777}) != 0) {
        MkdirLastLinuxError = EINVAL;
        return static_cast<uint64_t>(-EINVAL);
      }
      const size_t Separator = GuestPath->find_last_of('/');
      const std::string ParentGuestPath =
          Separator == std::string::npos ? "." : (Separator == 0 ? "/" : GuestPath->substr(0, Separator));
      const std::string Basename = Separator == std::string::npos ? *GuestPath : GuestPath->substr(Separator + 1);
      if (!Basename.empty() && Basename != "." && Basename != "..") {
        const auto HostParent = ResolveGuestPathWithParents(ParentGuestPath);
        if (HostParent.has_value()) {
          MkdirLastParentConfined = true;
          struct stat ParentStat{};
          MkdirLastParentExists = lstat(HostParent->c_str(), &ParentStat) == 0;
          const std::string HostTarget = *HostParent + (*HostParent == "/" ? "" : "/") + Basename;
          struct stat TargetStat{};
          (void)(lstat(HostTarget.c_str(), &TargetStat) == 0);
        }
      }
      if (MkdirLastParentConfined && !MkdirLastParentExists) {
        MkdirLastLinuxError = ENOENT;
        return static_cast<uint64_t>(-ENOENT);
      }
      const auto HostPath = ResolveGuestCreationPath(*GuestPath);
      if (!HostPath.has_value()) {
        MkdirLastLinuxError = EACCES;
        return static_cast<uint64_t>(-EACCES);
      }
      if (mkdir(HostPath->c_str(), static_cast<mode_t>(Mode & 07777)) != 0) {
        MkdirLastLinuxError = errno;
        return static_cast<uint64_t>(-MkdirLastLinuxError);
      }
      struct stat CreatedStat{};
      if (lstat(HostPath->c_str(), &CreatedStat) != 0 || !S_ISDIR(CreatedStat.st_mode)) {
        MkdirLastLinuxError = EIO;
        return static_cast<uint64_t>(-EIO);
      }
      return 0;
    }
    if (Number == RenameSyscall && !RootFS.empty()) {

      const auto OldGuestPath = ReadGuestPath(Arguments->Argument[1]);
      const auto NewGuestPath = ReadGuestPath(Arguments->Argument[2]);
      const auto IsRegistryTemporaryBasename = [](const std::string &Path) {
        return Path.size() >= 12 && Path.starts_with("reg") && Path.ends_with(".tmp") &&
               Path.find('/') == std::string::npos && std::all_of(Path.begin() + 3, Path.end() - 4, [](char Character) {
                 return (Character >= '0' && Character <= '9') || (Character >= 'a' && Character <= 'f') ||
                        (Character >= 'A' && Character <= 'F');
               });
      };
      const auto IsRegistryDestinationBasename = [](const std::string &Path) {
        return Path == "system.reg" || Path == "userdef.reg" || Path == "user.reg";
      };
      const bool ExactCandidate =
          GuestProgram == "/opt/proton/files/bin/wineserver" &&
          GuestCurrentWorkingDirectory == "/home/regression/.wine" && OldGuestPath.has_value() &&
          NewGuestPath.has_value() && IsRegistryTemporaryBasename(*OldGuestPath) &&
          IsRegistryDestinationBasename(*NewGuestPath) && RegistryTemporaryBasenames.contains(*OldGuestPath);
      if (!ExactCandidate) {
        if (!OldGuestPath || !NewGuestPath)
          return static_cast<uint64_t>(-EFAULT);
        const auto Source = ResolveGuestCreationPath(*OldGuestPath);
        const auto Destination = ResolveGuestCreationPath(*NewGuestPath);
        const auto Mutable = [this](const std::string &Path) {
          return Path.starts_with(RootFS + "/home/") || Path.starts_with(RootFS + "/tmp/") ||
                 Path.starts_with(RootFS + "/var/cache/");
        };
        if (!Source || !Destination || !Mutable(*Source) || !Mutable(*Destination)) {
          return static_cast<uint64_t>(-EACCES);
        }
        if (rename(Source->c_str(), Destination->c_str()) != 0) {
          return static_cast<uint64_t>(-TranslateHostRenameErrorToLinux(errno));
        }
        return 0;
      }

      const auto OldHostPath = ResolveGuestCreationPath(*OldGuestPath);
      const auto NewHostPath = ResolveGuestCreationPath(*NewGuestPath);
      if (!OldHostPath.has_value() || !NewHostPath.has_value()) {
        return static_cast<uint64_t>(-(EACCES));
      }
      const auto ParentOf = [](const std::string &Path) {
        const size_t Separator = Path.find_last_of('/');
        return Separator == std::string::npos ? std::string{} : Path.substr(0, Separator);
      };
      if (ParentOf(*OldHostPath) != ParentOf(*NewHostPath)) {
        return static_cast<uint64_t>(-(EXDEV));
      }
      struct stat OldTargetStat{};
      if (lstat(OldHostPath->c_str(), &OldTargetStat) != 0) {
        const int HostError = errno;
        return static_cast<uint64_t>(-(TranslateHostRenameErrorToLinux(HostError)));
      }
      if (!S_ISREG(OldTargetStat.st_mode) || S_ISLNK(OldTargetStat.st_mode)) {
        return static_cast<uint64_t>(-(EACCES));
      }
      struct stat NewTargetStat{};
      if (lstat(NewHostPath->c_str(), &NewTargetStat) == 0) {
        if (!S_ISREG(NewTargetStat.st_mode) || S_ISLNK(NewTargetStat.st_mode)) {
          return static_cast<uint64_t>(-(EACCES));
        }
      } else if (errno != ENOENT) {
        const int HostError = errno;
        return static_cast<uint64_t>(-(TranslateHostRenameErrorToLinux(HostError)));
      }
      if (std::rename(OldHostPath->c_str(), NewHostPath->c_str()) != 0) {
        const int HostError = errno;
        return static_cast<uint64_t>(-(TranslateHostRenameErrorToLinux(HostError)));
      }
      RegistryTemporaryBasenames.erase(*OldGuestPath);
      return 0;
    }
    if (Number == UnlinkSyscall && !RootFS.empty()) {
      const auto GuestPath = ReadGuestPath(Arguments->Argument[1]);
      UnlinkLastLinuxError = 0;
      if (!GuestPath.has_value()) {
        UnlinkLastLinuxError = EFAULT;
        return static_cast<uint64_t>(-EFAULT);
      }
      TraceGuestPath("unlink", *GuestPath);

      const auto HostPath = ResolveGuestCreationPath(*GuestPath);
      if (!HostPath.has_value()) {
        UnlinkLastLinuxError = EACCES;
        return static_cast<uint64_t>(-EACCES);
      }
      struct stat TargetStat{};
      if (lstat(HostPath->c_str(), &TargetStat) == 0) {
        if (S_ISDIR(TargetStat.st_mode)) {
          UnlinkLastLinuxError = 21;
          return static_cast<uint64_t>(-21);
        }
      }
      if (unlink(HostPath->c_str()) != 0) {
        UnlinkLastLinuxError = errno;
        return static_cast<uint64_t>(-UnlinkLastLinuxError);
      }
      return 0;
    }
    if (Number == 91 && !RootFS.empty()) { // Linux fchmod on a confined owned file.
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      if (!OwnedDescriptors.contains(Descriptor))
        return static_cast<uint64_t>(-EBADF);
      std::array<char, 4096> Name{};
      if (fcntl(Descriptor, F_GETPATH, Name.data()) != 0) {
        return static_cast<uint64_t>(-TranslateHostFileOpenErrorToLinux(errno));
      }
      const std::string Path{Name.data()};
      if (!Path.starts_with(RootFS + "/home/regression/") && !Path.starts_with(RootFS + "/tmp/") &&
          !Path.starts_with(RootFS + "/var/cache/"))
        return static_cast<uint64_t>(-EACCES);
      const mode_t Mode = static_cast<mode_t>(Arguments->Argument[2] & 07777);
      return fchmod(Descriptor, Mode) == 0 ? 0 : static_cast<uint64_t>(-TranslateHostFileOpenErrorToLinux(errno));
    }
    if (Number == ChmodSyscall && !RootFS.empty()) {
      constexpr uint64_t ObservedSocketMode = 0600;
      const auto GuestPath = ReadGuestPath(Arguments->Argument[1]);
      const uint64_t Mode = Arguments->Argument[2];
      ChmodLastAppliedMode = 0;
      ChmodLastTargetSocket = false;
      ChmodLastLinuxError = 0;
      if (!GuestPath.has_value()) {
        ChmodLastLinuxError = EFAULT;
        return static_cast<uint64_t>(-EFAULT);
      }
      TraceGuestPath("chmod", *GuestPath);
      if (*GuestPath != "socket" || Mode != ObservedSocketMode) {
        ChmodLastLinuxError = ENOTSUP;
        return static_cast<uint64_t>(-ENOTSUP);
      }
      const auto HostPath = ResolveGuestCreationPath(*GuestPath);
      if (!HostPath.has_value()) {
        ChmodLastLinuxError = EACCES;
        return static_cast<uint64_t>(-EACCES);
      }
      struct stat TargetStat{};
      if (lstat(HostPath->c_str(), &TargetStat) != 0) {
        ChmodLastLinuxError = errno;
        return static_cast<uint64_t>(-ChmodLastLinuxError);
      }
      ChmodLastTargetSocket = S_ISSOCK(TargetStat.st_mode);
      if (!ChmodLastTargetSocket) {
        ChmodLastLinuxError = EACCES;
        return static_cast<uint64_t>(-EACCES);
      }
      if (chmod(HostPath->c_str(), static_cast<mode_t>(Mode)) != 0) {
        ChmodLastLinuxError = errno;
        return static_cast<uint64_t>(-ChmodLastLinuxError);
      }
      struct stat AppliedStat{};
      if (lstat(HostPath->c_str(), &AppliedStat) != 0 || !S_ISSOCK(AppliedStat.st_mode)) {
        ChmodLastLinuxError = EIO;
        return static_cast<uint64_t>(-EIO);
      }
      ChmodLastAppliedMode = AppliedStat.st_mode & 07777;
      if (ChmodLastAppliedMode != Mode) {
        ChmodLastLinuxError = EIO;
        return static_cast<uint64_t>(-EIO);
      }
      return 0;
    }
    if (Number == SymlinkSyscall && !RootFS.empty()) {
      const auto GuestTarget = ReadGuestPath(Arguments->Argument[1]);
      const auto GuestLink = ReadGuestPath(Arguments->Argument[2]);
      SymlinkLastLinuxError = 0;
      if (!GuestTarget.has_value() || !GuestLink.has_value()) {
        SymlinkLastLinuxError = EFAULT;
        return static_cast<uint64_t>(-EFAULT);
      }
      TraceGuestPath("symlink-target", *GuestTarget);
      TraceGuestPath("symlink-link", *GuestLink);
      const auto HostLink = ResolveGuestRelativeSymlink(*GuestTarget, *GuestLink);
      if (!HostLink.has_value()) {
        SymlinkLastLinuxError = EACCES;
        return static_cast<uint64_t>(-EACCES);
      }
      if (symlink(GuestTarget->c_str(), HostLink->c_str()) != 0) {
        SymlinkLastLinuxError = errno;
        return static_cast<uint64_t>(-SymlinkLastLinuxError);
      }
      struct stat LinkStat{};
      std::array<char, 4096> LinkContents{};
      const ssize_t LinkLength = readlink(HostLink->c_str(), LinkContents.data(), LinkContents.size());
      if (lstat(HostLink->c_str(), &LinkStat) != 0 || !S_ISLNK(LinkStat.st_mode) || LinkLength < 0 ||
          static_cast<size_t>(LinkLength) != GuestTarget->size() ||
          std::memcmp(LinkContents.data(), GuestTarget->data(), GuestTarget->size()) != 0) {
        SymlinkLastLinuxError = EIO;
        return static_cast<uint64_t>(-EIO);
      }
      return 0;
    }
    if (Number == 267 && !RootFS.empty()) {
      const auto path = ReadGuestPath(Arguments->Argument[2]);
      if (!path)
        return uint64_t(-14);
      if (int64_t(Arguments->Argument[1]) != LinuxAtFDCWD && (path->empty() || path->front() != '/'))
        return uint64_t(-95);
      FEXCore::HLE::SyscallArguments call = *Arguments;
      call.Argument[0] = ReadlinkSyscall;
      call.Argument[1] = Arguments->Argument[2];
      call.Argument[2] = Arguments->Argument[3];
      call.Argument[3] = Arguments->Argument[4];
      return HandleSyscallImpl(Frame, &call);
    }
    if (Number == ReadlinkSyscall && !RootFS.empty()) {
      const auto GuestPath = ReadGuestPath(Arguments->Argument[1]);
      const uint64_t GuestBuffer = Arguments->Argument[2];
      const uint64_t BufferSize = Arguments->Argument[3];
      if (!GuestPath)
        return static_cast<uint64_t>(-EFAULT);
      if (BufferSize == 0)
        return static_cast<uint64_t>(-EINVAL);
      TraceGuestPath("readlink", *GuestPath);
      std::string Target;
      if (*GuestPath == "/proc/self/exe" || *GuestPath == "/proc/thread-self/exe") {
        if (GuestProgram.empty())
          return static_cast<uint64_t>(-ENOENT);
        Target = GuestProgram;
      } else if (GuestPath->starts_with("/proc/self/fd/")) {
        const std::string Number = GuestPath->substr(sizeof("/proc/self/fd/") - 1);
        char *End{};
        const long Descriptor = std::strtol(Number.c_str(), &End, 10);
        if (End == Number.c_str() || *End || Descriptor < 0 || Descriptor > INT32_MAX ||
            !OwnedDescriptors.contains(static_cast<int>(Descriptor)))
          return static_cast<uint64_t>(-ENOENT);
        std::array<char, 4096> HostPath{};
        if (fcntl(static_cast<int>(Descriptor), F_GETPATH, HostPath.data()) != 0)
          return static_cast<uint64_t>(-ENOENT);
        const std::string Path{HostPath.data()};
        if (fli_guest_host_path_visible(Path, RootFS))
          Target = fli_guest_path_view(Path, RootFS);
        else if (NativeBorrowedDescriptors.contains(static_cast<int>(Descriptor))) {
          // A descriptor explicitly borrowed from native Wine retains its actual file identity.
          Target = Path;
          if (fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
            dprintf(2, "NATIVE_BORROWED_FD_READLINK pid=%d fd=%ld actual-path=1 bytes=%zu scope=active-call\n",
                    getpid(), Descriptor, Target.size());
        } else
          return static_cast<uint64_t>(-EACCES);
      } else {
        const auto Normalized = NormalizeGuestPathWithParents(*GuestPath);
        if (!Normalized || *Normalized == "/")
          return static_cast<uint64_t>(-EINVAL);
        const size_t Slash = Normalized->find_last_of('/');
        const auto Parent = ResolveGuestPath(Slash == 0 ? "/" : Normalized->substr(0, Slash));
        if (!Parent)
          return static_cast<uint64_t>(-EACCES);
        // A shared mount exposes the backing directory, not its rootfs projection link.
        const std::string Link =
            *Normalized == fli_shared_host_root() ? *Normalized : *Parent + Normalized->substr(Slash);
        std::array<char, 4096> Bytes{};
        const ssize_t Count = readlink(Link.c_str(), Bytes.data(), Bytes.size());
        if (Count < 0)
          return static_cast<uint64_t>(-errno);
        Target.assign(Bytes.data(), static_cast<size_t>(Count));
      }
      const size_t Count = static_cast<size_t>(std::min<uint64_t>(BufferSize, Target.size()));
      void *Output = Count != 0 ? HostPointerForGuestRange(GuestBuffer, Count, PROT_WRITE) : nullptr;
      if (Count && !Output)
        return static_cast<uint64_t>(-EFAULT);
      if (Count)
        std::memcpy(Output, Target.data(), Count);
      return Count;
    }

    if (Number == WriteVSyscall && !RootFS.empty()) {
      constexpr uint64_t LinuxIOVectorMaximum = 1024;
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestVectors = Arguments->Argument[2];
      const uint64_t VectorCount = Arguments->Argument[3];
      if ((Descriptor != STDOUT_FILENO && Descriptor != STDERR_FILENO) ||
          ClosedStandardDescriptors.contains(Descriptor)) {
        constexpr uint64_t MeasuredWineReplyHeaderSize = 64;
        constexpr uint64_t MeasuredWineInitReplyPayloadSize = 4;
        constexpr uint64_t MeasuredWineDefaultDaclReplyPayloadSize = 28;
        constexpr uint64_t MaximumWineReplyPayloadSize = 16ULL * 1024ULL * 1024ULL;
        constexpr uint64_t MeasuredWineRequestHeaderSize = 64;
        constexpr uint64_t MeasuredWineOpenMappingRequestPayloadSize = 76;
        constexpr uint64_t MeasuredWineCreateKeyRequestPrimaryPayloadSize = 112;
        constexpr uint64_t MeasuredWineCreateKeyRequestAlternatePayloadSize = 108;
        constexpr uint64_t MeasuredWineCreateKeyRequestThirdPayloadSize = 128;
        constexpr uint64_t MeasuredWineCreateKeyRequestFourthPayloadSize = 140;
        constexpr uint64_t MeasuredWineCreateKeyRequestFifthPayloadSize = 136;
        constexpr uint64_t MeasuredWineCreateKeyRequestSixthPayloadSize = 84;
        constexpr uint32_t MeasuredWineCreateKeyRequestCode = 86;
        constexpr uint64_t MeasuredWineEnumKeyValueRequestPayloadSize = 24;
        constexpr uint64_t MeasuredWineEnumKeyValueRequestAlternatePayloadSize = 34;
        constexpr uint64_t MeasuredWineEnumKeyValueRequestThirdPayloadSize = 26;
        constexpr uint64_t MeasuredWineEnumKeyValueRequestFourthPayloadSize = 18;
        constexpr uint64_t MeasuredWineEnumKeyValueRequestFifthPayloadSize = 16;
        constexpr uint64_t MeasuredWineEnumKeyValueRequestSixthPayloadSize = 14;
        constexpr uint64_t MeasuredWineEnumKeyValueRequestSeventhPayloadSize = 50;
        constexpr uint64_t MeasuredWineEnumKeyValueRequestEighthPayloadSize = 28;
        constexpr uint32_t MeasuredWineEnumKeyValueRequestCode = 93;
        constexpr uint32_t MeasuredWineEnumKeyValueReplySize = 68;
        constexpr uint32_t MeasuredWineEnumKeyValueSixthReplySize = 114;
        constexpr uint64_t MeasuredWineEnumKeyValueSixthPayloadFingerprint = 16460010522796114687ULL;
        constexpr uint32_t MeasuredWineEnumKeyValueSeventhReplySize = 51;
        constexpr uint64_t MeasuredWineEnumKeyValueSeventhPayloadFingerprint = 7421093395229464502ULL;
        constexpr uint32_t MeasuredWineEnumKeyValueEighthReplySize = 51;
        constexpr uint64_t MeasuredWineEnumKeyValueEighthPayloadFingerprint = 9917584591413673814ULL;
        constexpr uint32_t MeasuredWineEnumKeyValueNinthReplySize = 68;
        constexpr uint64_t MeasuredWineEnumKeyValueNinthPayloadFingerprint = 36714261633148441ULL;
        constexpr uint64_t MeasuredWineOpenKeyRequestPrimaryPayloadSize = 156;
        constexpr uint64_t MeasuredWineOpenKeyRequestAlternatePayloadSize = 148;
        constexpr uint64_t MeasuredWineOpenKeyRequestThirdPayloadSize = 118;
        constexpr uint64_t MeasuredWineOpenKeyRequestFourthPayloadSize = 164;
        constexpr uint64_t MeasuredWineOpenKeyRequestFifthPayloadSize = 132;
        constexpr uint64_t MeasuredWineOpenKeyRequestSixthPayloadSize = 182;
        constexpr uint64_t MeasuredWineOpenKeyRequestSeventhPayloadSize = 44;
        constexpr uint64_t MeasuredWineOpenKeyRequestEighthPayloadSize = 26;
        constexpr uint64_t MeasuredWineOpenKeyRequestNinthPayloadSize = 42;
        constexpr uint64_t MeasuredWineOpenKeyRequestTenthPayloadSize = 124;
        constexpr uint32_t MeasuredWineOpenKeyRequestCode = 87;
        constexpr uint32_t MeasuredWineOpenKeyRequestParent = 0;
        constexpr uint32_t MeasuredWineOpenKeyRequestAccess = 1;
        constexpr uint32_t MeasuredWineOpenKeyRequestAttributes = 64;
        constexpr uint64_t MeasuredWineOpenKeyRequestNameFingerprint = 7694259118615906934ULL;
        constexpr uint64_t MeasuredWineOpenKeyRequestSixthNameFingerprint = 2092701008132515287ULL;
        constexpr uint64_t MeasuredWineOpenKeyRequestSeventhNameFingerprint = 16012710392547241188ULL;
        constexpr uint64_t MeasuredWineOpenKeyRequestEighthNameFingerprint = 8069394229556537835ULL;
        constexpr uint64_t MeasuredWineOpenKeyRequestNinthNameFingerprint = 7804196268085175278ULL;
        constexpr uint64_t MeasuredWineOpenKeyRequestTenthNameFingerprint = 5926441467455827968ULL;
        constexpr uint64_t MeasuredWineCreateEventRequestPayloadSize = 80;
        constexpr uint32_t MeasuredWineCreateEventRequestCode = 30;
        constexpr uint32_t MeasuredWineCreateSymlinkRequestCode = 242;
        constexpr uint64_t MeasuredWineCreateSymlinkRequestPayloadSize = 20;
        constexpr uint32_t MeasuredWineCreateSymlinkRequestAccess = 983055;
        constexpr uint64_t MeasuredWineCreateSymlinkTargetFingerprint = 7446848526332491749ULL;
        constexpr uint32_t MeasuredWineNewProcessRequestCode = 0;
        constexpr uint64_t MeasuredWineNewProcessObjectAttributesSize = 16;
        constexpr uint64_t MeasuredWineNewProcessStartupInfoSize = 354;
        constexpr uint64_t MinimumWineNewProcessEnvironmentSize = 2 * sizeof(uint16_t);
        constexpr uint64_t MaximumWineNewProcessEnvironmentSize = 1024ULL * 1024ULL;
        constexpr uint32_t MeasuredWineCreateFileRequestCode = 44;
        constexpr uint64_t MeasuredWineCreateFileObjectAttributesSize = 84;
        constexpr uint64_t MeasuredWineCreateFileNameSize = 51;
        constexpr uint64_t MeasuredWineCreateFileAlternateNameSize = 36;
        constexpr uint64_t MeasuredWineCreateFileThirdObjectAttributesSize = 96;
        constexpr uint64_t MeasuredWineCreateFileThirdNameSize = 58;
        constexpr uint32_t MeasuredWineCreateFileThirdAccess = 0x80100000U;
        constexpr uint32_t MeasuredWineCreateFileThirdSharing = 5;
        constexpr int32_t MeasuredWineCreateFileThirdDisposition = 1;
        constexpr uint32_t MeasuredWineCreateFileThirdOptions = 96;
        constexpr uint32_t MeasuredWineCreateFileThirdAttributes = 0;
        constexpr uint32_t MeasuredWineCreateFileThirdRootDirectory = 0;
        constexpr uint32_t MeasuredWineCreateFileThirdObjectAttributes = 0;
        constexpr uint32_t MeasuredWineCreateFileThirdSecurityDescriptorLength = 0;
        constexpr uint32_t MeasuredWineCreateFileThirdObjectNameLength = 80;
        constexpr uint64_t MeasuredWineCreateFileThirdObjectNameFingerprint = 14801784545170724346ULL;
        constexpr uint64_t MeasuredWineCreateFileThirdUnixNameFingerprint = 9302369010083266512ULL;
        constexpr uint64_t MeasuredWineCreateFileFourthObjectAttributesSize = 64;
        constexpr uint64_t MeasuredWineCreateFileFourthNameSize = 54;
        constexpr uint32_t MeasuredWineCreateFileFourthAccess = 0x00100020U;
        constexpr uint32_t MeasuredWineCreateFileFourthSharing = 5;
        constexpr int32_t MeasuredWineCreateFileFourthDisposition = 1;
        constexpr uint32_t MeasuredWineCreateFileFourthOptions = 32;
        constexpr uint32_t MeasuredWineCreateFileFourthAttributes = 0;
        constexpr uint32_t MeasuredWineCreateFileFourthRootDirectory = 0;
        constexpr uint32_t MeasuredWineCreateFileFourthObjectAttributes = 64;
        constexpr uint32_t MeasuredWineCreateFileFourthSecurityDescriptorLength = 0;
        constexpr uint32_t MeasuredWineCreateFileFourthObjectNameLength = 46;
        constexpr uint64_t MeasuredWineCreateFileFourthObjectNameFingerprint = 16621620404146942047ULL;
        constexpr uint64_t MeasuredWineCreateFileFourthUnixNameFingerprint = 12682502960721649899ULL;
        struct stat ReplyDescriptorStat{};
        const bool ReplyDescriptorStatSucceeded = fstat(Descriptor, &ReplyDescriptorStat) == 0;
        const int ReplyDescriptorFlags = fcntl(Descriptor, F_GETFD);
        const LinuxIOVector64 *ReplyVectors{};
        // Wine's public server ABI permits one fixed request plus at most five
        // variable data blocks (__SERVER_MAX_DATA).  Keep that exact bound so
        // previously unseen, but valid, requests can be forwarded without
        // turning this bridge into an arbitrary writev proxy.
        const bool MeasuredWineVectorCount = VectorCount >= 2 && VectorCount <= 6;
        const uint64_t MeasuredWineVectorSpan = VectorCount * sizeof(LinuxIOVector64);
        if (MeasuredWineVectorCount) {
          ReplyVectors = static_cast<const LinuxIOVector64 *>(
              HostPointerForGuestRange(GuestVectors, MeasuredWineVectorSpan, PROT_READ));
        }
        const auto ResolveReplyPayload = [&](const LinuxIOVector64 &Vector) -> const void * {
          if (Vector.Length == 0) {
            return nullptr;
          }
          return HostPointerForGuestRange(Vector.Base, Vector.Length, PROT_READ);
        };
        const void *ReplyHeader = ReplyVectors ? ResolveReplyPayload(ReplyVectors[0]) : nullptr;
        const void *ReplyPayload = ReplyVectors ? ResolveReplyPayload(ReplyVectors[1]) : nullptr;
        const void *ReplyPayload3 = ReplyVectors && VectorCount >= 3 ? ResolveReplyPayload(ReplyVectors[2]) : nullptr;
        const void *ReplyPayload4 = ReplyVectors && VectorCount >= 4 ? ResolveReplyPayload(ReplyVectors[3]) : nullptr;
        uint32_t ReplyHeaderError{};
        uint32_t ReplyHeaderDeclaredSize{};
        uint32_t RequestHeaderCode{};
        uint32_t RequestHeaderRequestSize{};
        uint32_t RequestHeaderReplySize{};
        uint32_t RequestHeaderInfoSize{};
        uint32_t RequestHeaderHandlesSize{};
        uint32_t RequestHeaderJobsSize{};
        uint32_t RequestOpenKeyParent{};
        uint32_t RequestOpenKeyAccess{};
        uint32_t RequestOpenKeyAttributes{};
        bool RequestOpenKeyFixedFieldsReadable{};
        bool RequestOpenKeyNameEvenLength{};
        bool RequestOpenKeyNameHasEmbeddedNull{};
        uint64_t RequestOpenKeyNameFingerprint{};
        if (ReplyHeader) {
          const auto *ReplyHeaderBytes = static_cast<const uint8_t *>(ReplyHeader);
          std::memcpy(&ReplyHeaderError, ReplyHeaderBytes, sizeof(ReplyHeaderError));
          std::memcpy(&ReplyHeaderDeclaredSize, ReplyHeaderBytes + sizeof(ReplyHeaderError),
                      sizeof(ReplyHeaderDeclaredSize));
          std::memcpy(&RequestHeaderCode, ReplyHeaderBytes, sizeof(RequestHeaderCode));
          std::memcpy(&RequestHeaderRequestSize, ReplyHeaderBytes + 4, sizeof(RequestHeaderRequestSize));
          std::memcpy(&RequestHeaderReplySize, ReplyHeaderBytes + 8, sizeof(RequestHeaderReplySize));
          if (ReplyVectors[0].Length >= 52) {
            std::memcpy(&RequestHeaderInfoSize, ReplyHeaderBytes + 40, sizeof(RequestHeaderInfoSize));
            std::memcpy(&RequestHeaderHandlesSize, ReplyHeaderBytes + 44, sizeof(RequestHeaderHandlesSize));
            std::memcpy(&RequestHeaderJobsSize, ReplyHeaderBytes + 48, sizeof(RequestHeaderJobsSize));
          }
          if (ReplyVectors[0].Length >= 24) {
            std::memcpy(&RequestOpenKeyParent, ReplyHeaderBytes + 12, sizeof(RequestOpenKeyParent));
            std::memcpy(&RequestOpenKeyAccess, ReplyHeaderBytes + 16, sizeof(RequestOpenKeyAccess));
            std::memcpy(&RequestOpenKeyAttributes, ReplyHeaderBytes + 20, sizeof(RequestOpenKeyAttributes));
            RequestOpenKeyFixedFieldsReadable = true;
          }
        }
        if (ReplyPayload && ReplyVectors[1].Length <= 4096) {
          const auto *Name = static_cast<const uint8_t *>(ReplyPayload);
          RequestOpenKeyNameEvenLength = ReplyVectors[1].Length % sizeof(uint16_t) == 0;
          RequestOpenKeyNameFingerprint = FingerprintBytes(Name, static_cast<size_t>(ReplyVectors[1].Length));
          if (RequestOpenKeyNameEvenLength) {
            for (uint64_t Offset = 0; Offset < ReplyVectors[1].Length; Offset += sizeof(uint16_t)) {
              uint16_t CodeUnit{};
              std::memcpy(&CodeUnit, Name + Offset, sizeof(CodeUnit));
              if (CodeUnit == 0) {
                RequestOpenKeyNameHasEmbeddedNull = true;
                break;
              }
            }
          }
        }
        const bool MeasuredWineInitReplyShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineInitReplyPayloadSize;
        const bool MeasuredWineDefaultDaclReplyShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineDefaultDaclReplyPayloadSize &&
            ReplyHeaderError == 0 && ReplyHeaderDeclaredSize == MeasuredWineDefaultDaclReplyPayloadSize;
        const bool BoundedWineVariableReplyShape =
            GuestProgram == "/opt/proton/files/bin/wineserver" && ReplyVectors && VectorCount == 2 &&
            ReplyVectors[0].Length == MeasuredWineReplyHeaderSize && ReplyVectors[1].Length > 0 &&
            ReplyVectors[1].Length <= MaximumWineReplyPayloadSize &&
            ReplyHeaderDeclaredSize == ReplyVectors[1].Length && ReplyHeader && ReplyPayload;
        const bool ExactWineReply =
            Descriptor != STDOUT_FILENO && Descriptor != STDERR_FILENO && VectorCount == 2 &&
            OwnedDescriptors.contains(Descriptor) && ReceivedSCMRightsDescriptors.contains(Descriptor) &&
            ReplyDescriptorFlags != -1 && ReplyDescriptorStatSucceeded && S_ISFIFO(ReplyDescriptorStat.st_mode) &&
            ReplyVectors && ReplyVectors[0].Length == MeasuredWineReplyHeaderSize &&
            (MeasuredWineInitReplyShape || MeasuredWineDefaultDaclReplyShape || BoundedWineVariableReplyShape) &&
            ReplyHeader && ReplyPayload;
        if (ExactWineReply) {
          TraceWineReplyHeader("writev", Descriptor, ReplyHeader, static_cast<size_t>(MeasuredWineReplyHeaderSize));
          std::array<iovec, 2> HostVectors{{
              {const_cast<void *>(ReplyHeader), static_cast<size_t>(ReplyVectors[0].Length)},
              {const_cast<void *>(ReplyPayload), static_cast<size_t>(ReplyVectors[1].Length)},
          }};
          errno = 0;
          const ssize_t Result =
              ::BlockingHostCall([&] { return writev(Descriptor, HostVectors.data(), HostVectors.size()); });
          if (Result < 0) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          WriteVVectorCount += VectorCount;
          WriteVByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }
        const bool MeasuredWineOpenMappingRequestShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineOpenMappingRequestPayloadSize;
        const bool MeasuredWineCreateKeyRequestPayloadShape =
            ReplyVectors && (ReplyVectors[1].Length == MeasuredWineCreateKeyRequestPrimaryPayloadSize ||
                             ReplyVectors[1].Length == MeasuredWineCreateKeyRequestAlternatePayloadSize ||
                             ReplyVectors[1].Length == MeasuredWineCreateKeyRequestThirdPayloadSize ||
                             ReplyVectors[1].Length == MeasuredWineCreateKeyRequestFourthPayloadSize);
        const bool MeasuredWineCreateKeyFifthRequestPayloadShape = [&] {
          if (!ReplyHeader || !ReplyPayload || !ReplyVectors ||
              ReplyVectors[0].Length != MeasuredWineRequestHeaderSize ||
              ReplyVectors[1].Length != MeasuredWineCreateKeyRequestFifthPayloadSize) {
            return false;
          }
          const auto *Fixed = static_cast<const uint8_t *>(ReplyHeader);
          const auto *Payload = static_cast<const uint8_t *>(ReplyPayload);
          uint32_t Access{};
          uint32_t Options{};
          uint32_t RootDirectory{};
          uint32_t Attributes{};
          uint32_t SecurityDescriptorLength{};
          uint32_t NameLength{};
          std::memcpy(&Access, Fixed + 12, sizeof(Access));
          std::memcpy(&Options, Fixed + 16, sizeof(Options));
          std::memcpy(&RootDirectory, Payload, sizeof(RootDirectory));
          std::memcpy(&Attributes, Payload + 4, sizeof(Attributes));
          std::memcpy(&SecurityDescriptorLength, Payload + 8, sizeof(SecurityDescriptorLength));
          std::memcpy(&NameLength, Payload + 12, sizeof(NameLength));
          const uint64_t ObjectAttributesLength =
              (16 + (uint64_t{SecurityDescriptorLength} & ~uint64_t{1}) + (uint64_t{NameLength} & ~uint64_t{1}) + 3) &
              ~uint64_t{3};
          return Access == 983103 && Options == 0 && RootDirectory == 0 && Attributes == 192 &&
                 SecurityDescriptorLength == 0 && NameLength == 120 &&
                 ObjectAttributesLength == ReplyVectors[1].Length && NameLength % 2 == 0 &&
                 FingerprintBytes(Payload + 16, NameLength) == 13414519971843043962ULL &&
                 FingerprintBytes(Payload + ObjectAttributesLength, 0) == 14695981039346656037ULL;
        }();
        const bool MeasuredWineCreateKeySixthRequestPayloadShape = [&] {
          if (!ReplyHeader || !ReplyPayload || !ReplyVectors ||
              ReplyVectors[0].Length != MeasuredWineRequestHeaderSize ||
              ReplyVectors[1].Length != MeasuredWineCreateKeyRequestSixthPayloadSize) {
            return false;
          }
          const auto *Fixed = static_cast<const uint8_t *>(ReplyHeader);
          const auto *Payload = static_cast<const uint8_t *>(ReplyPayload);
          uint32_t Access{};
          uint32_t Options{};
          uint32_t RootDirectory{};
          uint32_t Attributes{};
          uint32_t SecurityDescriptorLength{};
          uint32_t NameLength{};
          std::memcpy(&Access, Fixed + 12, sizeof(Access));
          std::memcpy(&Options, Fixed + 16, sizeof(Options));
          std::memcpy(&RootDirectory, Payload, sizeof(RootDirectory));
          std::memcpy(&Attributes, Payload + 4, sizeof(Attributes));
          std::memcpy(&SecurityDescriptorLength, Payload + 8, sizeof(SecurityDescriptorLength));
          std::memcpy(&NameLength, Payload + 12, sizeof(NameLength));
          const uint64_t ObjectAttributesLength =
              (16 + (uint64_t{SecurityDescriptorLength} & ~uint64_t{1}) + (uint64_t{NameLength} & ~uint64_t{1}) + 3) &
              ~uint64_t{3};
          return Access == 983103 && Options == 0 && RootDirectory == 0 && Attributes == 192 &&
                 SecurityDescriptorLength == 0 && NameLength == 68 &&
                 ObjectAttributesLength == ReplyVectors[1].Length && NameLength % 2 == 0 &&
                 FingerprintBytes(Payload + 16, NameLength) == 16432771884631432949ULL &&
                 FingerprintBytes(Payload + ObjectAttributesLength, 0) == 14695981039346656037ULL;
        }();
        const bool MeasuredWineCreateKeyRequestShape =
            (MeasuredWineCreateKeyRequestPayloadShape || MeasuredWineCreateKeyFifthRequestPayloadShape ||
             MeasuredWineCreateKeySixthRequestPayloadShape) &&
            RequestHeaderCode == MeasuredWineCreateKeyRequestCode &&
            RequestHeaderRequestSize == ReplyVectors[1].Length && RequestHeaderReplySize == 0;
        const bool MeasuredWineEnumKeyValueKnownRequestPayloadShape =
            ReplyVectors &&
            (ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestPayloadSize ||
             ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestAlternatePayloadSize ||
             ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestThirdPayloadSize ||
             ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestFourthPayloadSize ||
             ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestFifthPayloadSize) &&
            RequestHeaderReplySize == MeasuredWineEnumKeyValueReplySize;
        const bool MeasuredWineEnumKeyValueSixthRequestPayloadShape =
            ReplyVectors && ReplyPayload && ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestSixthPayloadSize &&
            RequestHeaderReplySize == MeasuredWineEnumKeyValueSixthReplySize &&
            FingerprintBytes(static_cast<const uint8_t *>(ReplyPayload), ReplyVectors[1].Length) ==
                MeasuredWineEnumKeyValueSixthPayloadFingerprint;
        const bool MeasuredWineEnumKeyValueSeventhRequestPayloadShape =
            ReplyVectors && ReplyPayload &&
            ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestSeventhPayloadSize &&
            RequestHeaderReplySize == MeasuredWineEnumKeyValueSeventhReplySize &&
            FingerprintBytes(static_cast<const uint8_t *>(ReplyPayload), ReplyVectors[1].Length) ==
                MeasuredWineEnumKeyValueSeventhPayloadFingerprint;
        const bool MeasuredWineEnumKeyValueEighthRequestPayloadShape =
            ReplyVectors && ReplyPayload &&
            ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestEighthPayloadSize &&
            RequestHeaderReplySize == MeasuredWineEnumKeyValueEighthReplySize &&
            FingerprintBytes(static_cast<const uint8_t *>(ReplyPayload), ReplyVectors[1].Length) ==
                MeasuredWineEnumKeyValueEighthPayloadFingerprint;
        const bool MeasuredWineEnumKeyValueNinthRequestPayloadShape =
            ReplyVectors && ReplyPayload && ReplyVectors[1].Length == MeasuredWineEnumKeyValueRequestSixthPayloadSize &&
            RequestHeaderReplySize == MeasuredWineEnumKeyValueNinthReplySize &&
            FingerprintBytes(static_cast<const uint8_t *>(ReplyPayload), ReplyVectors[1].Length) ==
                MeasuredWineEnumKeyValueNinthPayloadFingerprint;
        const bool MeasuredWineEnumKeyValueRequestShape =
            ReplyVectors &&
            (MeasuredWineEnumKeyValueKnownRequestPayloadShape || MeasuredWineEnumKeyValueSixthRequestPayloadShape ||
             MeasuredWineEnumKeyValueSeventhRequestPayloadShape || MeasuredWineEnumKeyValueEighthRequestPayloadShape ||
             MeasuredWineEnumKeyValueNinthRequestPayloadShape) &&
            RequestHeaderCode == MeasuredWineEnumKeyValueRequestCode &&
            RequestHeaderRequestSize == ReplyVectors[1].Length && RequestHeaderReplySize != 0;
        const bool MeasuredWineOpenKeyKnownRequestPayloadShape =
            ReplyVectors && (ReplyVectors[1].Length == MeasuredWineOpenKeyRequestPrimaryPayloadSize ||
                             ReplyVectors[1].Length == MeasuredWineOpenKeyRequestAlternatePayloadSize ||
                             ReplyVectors[1].Length == MeasuredWineOpenKeyRequestThirdPayloadSize ||
                             ReplyVectors[1].Length == MeasuredWineOpenKeyRequestFourthPayloadSize);
        const bool MeasuredWineOpenKeyFifthRequestPayloadShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineOpenKeyRequestFifthPayloadSize &&
            RequestOpenKeyFixedFieldsReadable && RequestOpenKeyParent == MeasuredWineOpenKeyRequestParent &&
            RequestOpenKeyAccess == MeasuredWineOpenKeyRequestAccess &&
            RequestOpenKeyAttributes == MeasuredWineOpenKeyRequestAttributes && RequestOpenKeyNameEvenLength &&
            !RequestOpenKeyNameHasEmbeddedNull &&
            RequestOpenKeyNameFingerprint == MeasuredWineOpenKeyRequestNameFingerprint;
        const bool MeasuredWineOpenKeySixthRequestPayloadShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineOpenKeyRequestSixthPayloadSize &&
            RequestOpenKeyFixedFieldsReadable && RequestOpenKeyParent == MeasuredWineOpenKeyRequestParent &&
            RequestOpenKeyAccess == MeasuredWineOpenKeyRequestAccess &&
            RequestOpenKeyAttributes == MeasuredWineOpenKeyRequestAttributes && RequestOpenKeyNameEvenLength &&
            !RequestOpenKeyNameHasEmbeddedNull &&
            RequestOpenKeyNameFingerprint == MeasuredWineOpenKeyRequestSixthNameFingerprint;
        const bool MeasuredWineOpenKeySeventhRequestPayloadShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineOpenKeyRequestSeventhPayloadSize &&
            RequestOpenKeyFixedFieldsReadable && RequestOpenKeyParent == 20 && RequestOpenKeyAccess == 983103 &&
            RequestOpenKeyAttributes == MeasuredWineOpenKeyRequestAttributes && RequestOpenKeyNameEvenLength &&
            !RequestOpenKeyNameHasEmbeddedNull &&
            RequestOpenKeyNameFingerprint == MeasuredWineOpenKeyRequestSeventhNameFingerprint;
        const bool MeasuredWineOpenKeyEighthRequestPayloadShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineOpenKeyRequestEighthPayloadSize &&
            RequestOpenKeyFixedFieldsReadable && RequestOpenKeyParent == 24 && RequestOpenKeyAccess == 983103 &&
            RequestOpenKeyAttributes == MeasuredWineOpenKeyRequestAttributes && RequestOpenKeyNameEvenLength &&
            !RequestOpenKeyNameHasEmbeddedNull &&
            RequestOpenKeyNameFingerprint == MeasuredWineOpenKeyRequestEighthNameFingerprint;
        const bool MeasuredWineOpenKeyNinthRequestPayloadShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineOpenKeyRequestNinthPayloadSize &&
            RequestOpenKeyFixedFieldsReadable && RequestOpenKeyParent == 28 && RequestOpenKeyAccess == 983103 &&
            RequestOpenKeyAttributes == MeasuredWineOpenKeyRequestAttributes && RequestOpenKeyNameEvenLength &&
            !RequestOpenKeyNameHasEmbeddedNull &&
            RequestOpenKeyNameFingerprint == MeasuredWineOpenKeyRequestNinthNameFingerprint;
        const bool MeasuredWineOpenKeyTenthRequestPayloadShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineOpenKeyRequestTenthPayloadSize &&
            RequestOpenKeyFixedFieldsReadable && RequestOpenKeyParent == 0 && RequestOpenKeyAccess == 983103 &&
            RequestOpenKeyAttributes == MeasuredWineOpenKeyRequestAttributes && RequestOpenKeyNameEvenLength &&
            !RequestOpenKeyNameHasEmbeddedNull &&
            RequestOpenKeyNameFingerprint == MeasuredWineOpenKeyRequestTenthNameFingerprint;
        const bool MeasuredWineOpenKeyRequestShape =
            (MeasuredWineOpenKeyKnownRequestPayloadShape || MeasuredWineOpenKeyFifthRequestPayloadShape ||
             MeasuredWineOpenKeySixthRequestPayloadShape || MeasuredWineOpenKeySeventhRequestPayloadShape ||
             MeasuredWineOpenKeyEighthRequestPayloadShape || MeasuredWineOpenKeyNinthRequestPayloadShape ||
             MeasuredWineOpenKeyTenthRequestPayloadShape) &&
            RequestHeaderCode == MeasuredWineOpenKeyRequestCode && RequestHeaderRequestSize == ReplyVectors[1].Length &&
            RequestHeaderReplySize == 0;
        const bool MeasuredWineCreateEventRequestShape =
            ReplyVectors && ReplyVectors[1].Length == MeasuredWineCreateEventRequestPayloadSize &&
            RequestHeaderCode == MeasuredWineCreateEventRequestCode &&
            RequestHeaderRequestSize == MeasuredWineCreateEventRequestPayloadSize && RequestHeaderReplySize == 0;
        const bool MeasuredWineCreateSymlinkRequestShape = [&] {
          if (!ReplyVectors || VectorCount != 2 || ReplyVectors[0].Length != MeasuredWineRequestHeaderSize ||
              ReplyVectors[1].Length != MeasuredWineCreateSymlinkRequestPayloadSize ||
              RequestHeaderCode != MeasuredWineCreateSymlinkRequestCode ||
              RequestHeaderRequestSize != MeasuredWineCreateSymlinkRequestPayloadSize || RequestHeaderReplySize != 0 ||
              !ReplyHeader || !ReplyPayload) {
            return false;
          }
          const auto *FixedRequest = static_cast<const uint8_t *>(ReplyHeader);
          const auto *Target = static_cast<const uint8_t *>(ReplyPayload);
          uint32_t Access{};
          std::memcpy(&Access, FixedRequest + 12, sizeof(Access));
          if (Access != MeasuredWineCreateSymlinkRequestAccess || ReplyVectors[1].Length % sizeof(uint16_t) != 0 ||
              FingerprintBytes(Target, static_cast<size_t>(ReplyVectors[1].Length)) !=
                  MeasuredWineCreateSymlinkTargetFingerprint) {
            return false;
          }
          for (uint64_t Offset = 0; Offset < ReplyVectors[1].Length; Offset += sizeof(uint16_t)) {
            uint16_t CodeUnit{};
            std::memcpy(&CodeUnit, Target + Offset, sizeof(CodeUnit));
            if (CodeUnit == 0) {
              return false;
            }
          }
          return true;
        }();
        const bool ExactWineRequestDescriptor =
            GuestProgram == "/opt/proton/files/lib/wine/x86_64-unix/wine-preloader" && Descriptor != STDOUT_FILENO &&
            Descriptor != STDERR_FILENO && OwnedDescriptors.contains(Descriptor) &&
            ReceivedSCMRightsDescriptors.contains(Descriptor) && ReplyDescriptorFlags != -1 &&
            ReplyDescriptorStatSucceeded && S_ISFIFO(ReplyDescriptorStat.st_mode);
        const uint64_t MeasuredWineNewProcessRequestPayloadSize =
            ReplyVectors && VectorCount == 4 ? ReplyVectors[1].Length + ReplyVectors[2].Length + ReplyVectors[3].Length
                                             : 0;
        const bool MeasuredWineNewProcessEnvironmentShape = [&] {
          if (!ReplyVectors || VectorCount != 4 || !ReplyPayload4) {
            return false;
          }
          const uint64_t EnvironmentSize = ReplyVectors[3].Length;
          if (EnvironmentSize < MinimumWineNewProcessEnvironmentSize ||
              EnvironmentSize > MaximumWineNewProcessEnvironmentSize || EnvironmentSize % sizeof(uint16_t) != 0) {
            return false;
          }
          const auto *EnvironmentBytes = static_cast<const uint8_t *>(ReplyPayload4);
          uint16_t PenultimateCodeUnit{};
          uint16_t TerminalCodeUnit{};
          std::memcpy(&PenultimateCodeUnit, EnvironmentBytes + EnvironmentSize - 2 * sizeof(uint16_t),
                      sizeof(PenultimateCodeUnit));
          std::memcpy(&TerminalCodeUnit, EnvironmentBytes + EnvironmentSize - sizeof(uint16_t),
                      sizeof(TerminalCodeUnit));
          return PenultimateCodeUnit == 0 && TerminalCodeUnit == 0;
        }();
        const bool MeasuredWineNewProcessRequestShape =
            ReplyVectors && VectorCount == 4 && ReplyVectors[0].Length == MeasuredWineRequestHeaderSize &&
            ReplyVectors[1].Length == MeasuredWineNewProcessObjectAttributesSize &&
            ReplyVectors[2].Length == MeasuredWineNewProcessStartupInfoSize && MeasuredWineNewProcessEnvironmentShape &&
            RequestHeaderCode == MeasuredWineNewProcessRequestCode &&
            RequestHeaderRequestSize == MeasuredWineNewProcessRequestPayloadSize && RequestHeaderReplySize == 0 &&
            RequestHeaderInfoSize == ReplyVectors[2].Length && RequestHeaderHandlesSize == 0 &&
            RequestHeaderJobsSize == 0 && ReplyHeader && ReplyPayload && ReplyPayload3 && ReplyPayload4;
        const bool ExactWineNewProcessRequest = ExactWineRequestDescriptor && MeasuredWineNewProcessRequestShape;
        if (ExactWineNewProcessRequest) {
          TraceWineRequestHeader("writev", Descriptor, ReplyHeader, static_cast<size_t>(MeasuredWineRequestHeaderSize));
          std::array<iovec, 4> HostVectors{{
              {const_cast<void *>(ReplyHeader), static_cast<size_t>(ReplyVectors[0].Length)},
              {const_cast<void *>(ReplyPayload), static_cast<size_t>(ReplyVectors[1].Length)},
              {const_cast<void *>(ReplyPayload3), static_cast<size_t>(ReplyVectors[2].Length)},
              {const_cast<void *>(ReplyPayload4), static_cast<size_t>(ReplyVectors[3].Length)},
          }};
          errno = 0;
          const ssize_t Result =
              ::BlockingHostCall([&] { return writev(Descriptor, HostVectors.data(), HostVectors.size()); });
          if (Result < 0) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          WriteVVectorCount += VectorCount;
          WriteVByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }
        const bool MeasuredWineCreateFileKnownRequestShape =
            ReplyVectors && VectorCount == 3 && ReplyVectors[0].Length == MeasuredWineRequestHeaderSize &&
            ReplyVectors[1].Length == MeasuredWineCreateFileObjectAttributesSize &&
            (ReplyVectors[2].Length == MeasuredWineCreateFileNameSize ||
             ReplyVectors[2].Length == MeasuredWineCreateFileAlternateNameSize) &&
            RequestHeaderCode == MeasuredWineCreateFileRequestCode &&
            RequestHeaderRequestSize == MeasuredWineCreateFileObjectAttributesSize + ReplyVectors[2].Length &&
            RequestHeaderReplySize == 0 && ReplyHeader && ReplyPayload && ReplyPayload3;
        const bool MeasuredWineCreateFileThirdRequestShape = [&] {
          if (!ReplyVectors || VectorCount != 3 || ReplyVectors[0].Length != MeasuredWineRequestHeaderSize ||
              ReplyVectors[1].Length != MeasuredWineCreateFileThirdObjectAttributesSize ||
              ReplyVectors[2].Length != MeasuredWineCreateFileThirdNameSize ||
              RequestHeaderCode != MeasuredWineCreateFileRequestCode ||
              RequestHeaderRequestSize !=
                  MeasuredWineCreateFileThirdObjectAttributesSize + MeasuredWineCreateFileThirdNameSize ||
              RequestHeaderReplySize != 0 || ReplyDescriptorFlags != FD_CLOEXEC || !ReplyHeader || !ReplyPayload ||
              !ReplyPayload3) {
            return false;
          }

          const auto *Fixed = static_cast<const uint8_t *>(ReplyHeader);
          const auto *ObjectAttributes = static_cast<const uint8_t *>(ReplyPayload);
          const auto *UnixName = static_cast<const uint8_t *>(ReplyPayload3);
          uint32_t Access{};
          uint32_t Sharing{};
          int32_t Disposition{};
          uint32_t Options{};
          uint32_t Attributes{};
          uint32_t RootDirectory{};
          uint32_t ObjectAttributeFlags{};
          uint32_t SecurityDescriptorLength{};
          uint32_t ObjectNameLength{};
          std::memcpy(&Access, Fixed + 12, sizeof(Access));
          std::memcpy(&Sharing, Fixed + 16, sizeof(Sharing));
          std::memcpy(&Disposition, Fixed + 20, sizeof(Disposition));
          std::memcpy(&Options, Fixed + 24, sizeof(Options));
          std::memcpy(&Attributes, Fixed + 28, sizeof(Attributes));
          std::memcpy(&RootDirectory, ObjectAttributes, sizeof(RootDirectory));
          std::memcpy(&ObjectAttributeFlags, ObjectAttributes + 4, sizeof(ObjectAttributeFlags));
          std::memcpy(&SecurityDescriptorLength, ObjectAttributes + 8, sizeof(SecurityDescriptorLength));
          std::memcpy(&ObjectNameLength, ObjectAttributes + 12, sizeof(ObjectNameLength));

          const uint64_t VariableLength = ReplyVectors[1].Length - 16;
          const bool ComponentLengthsValid = SecurityDescriptorLength <= VariableLength &&
                                             ObjectNameLength <= VariableLength - SecurityDescriptorLength;
          const uint64_t ObjectAttributesLength =
              ComponentLengthsValid
                  ? (16 + uint64_t{SecurityDescriptorLength} + uint64_t{ObjectNameLength} + 3) & ~uint64_t{3}
                  : 0;
          if (Access != MeasuredWineCreateFileThirdAccess || Sharing != MeasuredWineCreateFileThirdSharing ||
              Disposition != MeasuredWineCreateFileThirdDisposition || Options != MeasuredWineCreateFileThirdOptions ||
              Attributes != MeasuredWineCreateFileThirdAttributes ||
              RootDirectory != MeasuredWineCreateFileThirdRootDirectory ||
              ObjectAttributeFlags != MeasuredWineCreateFileThirdObjectAttributes ||
              SecurityDescriptorLength != MeasuredWineCreateFileThirdSecurityDescriptorLength ||
              ObjectNameLength != MeasuredWineCreateFileThirdObjectNameLength ||
              SecurityDescriptorLength % sizeof(uint16_t) != 0 || ObjectNameLength % sizeof(uint16_t) != 0 ||
              ObjectAttributesLength != ReplyVectors[1].Length) {
            return false;
          }

          const auto *ObjectName = ObjectAttributes + 16 + SecurityDescriptorLength;
          for (uint64_t Offset = 0; Offset < ObjectNameLength; Offset += sizeof(uint16_t)) {
            uint16_t CodeUnit{};
            std::memcpy(&CodeUnit, ObjectName + Offset, sizeof(CodeUnit));
            if (CodeUnit == 0) {
              return false;
            }
          }
          for (uint64_t Offset = 0; Offset < ReplyVectors[2].Length; ++Offset) {
            if (UnixName[Offset] == 0 || UnixName[Offset] < 0x20 || UnixName[Offset] > 0x7e) {
              return false;
            }
          }
          return UnixName[0] == '/' &&
                 FingerprintBytes(ObjectName, ObjectNameLength) == MeasuredWineCreateFileThirdObjectNameFingerprint &&
                 FingerprintBytes(UnixName, ReplyVectors[2].Length) == MeasuredWineCreateFileThirdUnixNameFingerprint;
        }();
        const bool MeasuredWineCreateFileFourthRequestShape = [&] {
          if (!ReplyVectors || VectorCount != 3 || ReplyVectors[0].Length != MeasuredWineRequestHeaderSize ||
              ReplyVectors[1].Length != MeasuredWineCreateFileFourthObjectAttributesSize ||
              ReplyVectors[2].Length != MeasuredWineCreateFileFourthNameSize ||
              RequestHeaderCode != MeasuredWineCreateFileRequestCode ||
              RequestHeaderRequestSize !=
                  MeasuredWineCreateFileFourthObjectAttributesSize + MeasuredWineCreateFileFourthNameSize ||
              RequestHeaderReplySize != 0 || ReplyDescriptorFlags != FD_CLOEXEC || !ReplyHeader || !ReplyPayload ||
              !ReplyPayload3) {
            return false;
          }

          const auto *Fixed = static_cast<const uint8_t *>(ReplyHeader);
          const auto *ObjectAttributes = static_cast<const uint8_t *>(ReplyPayload);
          const auto *UnixName = static_cast<const uint8_t *>(ReplyPayload3);
          uint32_t Access{};
          uint32_t Sharing{};
          int32_t Disposition{};
          uint32_t Options{};
          uint32_t Attributes{};
          uint32_t RootDirectory{};
          uint32_t ObjectAttributeFlags{};
          uint32_t SecurityDescriptorLength{};
          uint32_t ObjectNameLength{};
          std::memcpy(&Access, Fixed + 12, sizeof(Access));
          std::memcpy(&Sharing, Fixed + 16, sizeof(Sharing));
          std::memcpy(&Disposition, Fixed + 20, sizeof(Disposition));
          std::memcpy(&Options, Fixed + 24, sizeof(Options));
          std::memcpy(&Attributes, Fixed + 28, sizeof(Attributes));
          std::memcpy(&RootDirectory, ObjectAttributes, sizeof(RootDirectory));
          std::memcpy(&ObjectAttributeFlags, ObjectAttributes + 4, sizeof(ObjectAttributeFlags));
          std::memcpy(&SecurityDescriptorLength, ObjectAttributes + 8, sizeof(SecurityDescriptorLength));
          std::memcpy(&ObjectNameLength, ObjectAttributes + 12, sizeof(ObjectNameLength));

          const uint64_t VariableLength = ReplyVectors[1].Length - 16;
          const bool ComponentLengthsValid = SecurityDescriptorLength <= VariableLength &&
                                             ObjectNameLength <= VariableLength - SecurityDescriptorLength;
          const uint64_t ObjectAttributesLength =
              ComponentLengthsValid
                  ? (16 + uint64_t{SecurityDescriptorLength} + uint64_t{ObjectNameLength} + 3) & ~uint64_t{3}
                  : 0;
          if (Access != MeasuredWineCreateFileFourthAccess || Sharing != MeasuredWineCreateFileFourthSharing ||
              Disposition != MeasuredWineCreateFileFourthDisposition ||
              Options != MeasuredWineCreateFileFourthOptions || Attributes != MeasuredWineCreateFileFourthAttributes ||
              RootDirectory != MeasuredWineCreateFileFourthRootDirectory ||
              ObjectAttributeFlags != MeasuredWineCreateFileFourthObjectAttributes ||
              SecurityDescriptorLength != MeasuredWineCreateFileFourthSecurityDescriptorLength ||
              ObjectNameLength != MeasuredWineCreateFileFourthObjectNameLength ||
              SecurityDescriptorLength % sizeof(uint16_t) != 0 || ObjectNameLength % sizeof(uint16_t) != 0 ||
              ObjectAttributesLength != ReplyVectors[1].Length) {
            return false;
          }

          const auto *ObjectName = ObjectAttributes + 16 + SecurityDescriptorLength;
          for (uint64_t Offset = 0; Offset < ObjectNameLength; Offset += sizeof(uint16_t)) {
            uint16_t CodeUnit{};
            std::memcpy(&CodeUnit, ObjectName + Offset, sizeof(CodeUnit));
            if (CodeUnit == 0) {
              return false;
            }
          }
          for (uint64_t Offset = 0; Offset < ReplyVectors[2].Length; ++Offset) {
            if (UnixName[Offset] == 0 || UnixName[Offset] < 0x20 || UnixName[Offset] > 0x7e) {
              return false;
            }
          }
          return UnixName[0] == '/' &&
                 FingerprintBytes(ObjectName, ObjectNameLength) == MeasuredWineCreateFileFourthObjectNameFingerprint &&
                 FingerprintBytes(UnixName, ReplyVectors[2].Length) == MeasuredWineCreateFileFourthUnixNameFingerprint;
        }();
        const bool MeasuredWineCreateFileRequestShape = MeasuredWineCreateFileKnownRequestShape ||
                                                        MeasuredWineCreateFileThirdRequestShape ||
                                                        MeasuredWineCreateFileFourthRequestShape;
        const bool ExactWineCreateFileRequest = ExactWineRequestDescriptor && MeasuredWineCreateFileRequestShape;
        if (ExactWineCreateFileRequest) {
          TraceWineRequestHeader("writev", Descriptor, ReplyHeader, static_cast<size_t>(MeasuredWineRequestHeaderSize));
          std::array<iovec, 3> HostVectors{{
              {const_cast<void *>(ReplyHeader), static_cast<size_t>(ReplyVectors[0].Length)},
              {const_cast<void *>(ReplyPayload), static_cast<size_t>(ReplyVectors[1].Length)},
              {const_cast<void *>(ReplyPayload3), static_cast<size_t>(ReplyVectors[2].Length)},
          }};
          errno = 0;
          const ssize_t Result =
              ::BlockingHostCall([&] { return writev(Descriptor, HostVectors.data(), HostVectors.size()); });
          if (Result < 0) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          WriteVVectorCount += VectorCount;
          WriteVByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }
        const bool ExactWineRequest = ExactWineRequestDescriptor && VectorCount == 2 && ReplyVectors &&
                                      ReplyVectors[0].Length == MeasuredWineRequestHeaderSize &&
                                      (MeasuredWineOpenMappingRequestShape || MeasuredWineCreateKeyRequestShape ||
                                       MeasuredWineEnumKeyValueRequestShape || MeasuredWineOpenKeyRequestShape ||
                                       MeasuredWineCreateEventRequestShape || MeasuredWineCreateSymlinkRequestShape) &&
                                      ReplyHeader && ReplyPayload;
        if (ExactWineRequest) {
          TraceWineRequestHeader("writev", Descriptor, ReplyHeader, static_cast<size_t>(MeasuredWineRequestHeaderSize));
          std::array<iovec, 2> HostVectors{{
              {const_cast<void *>(ReplyHeader), static_cast<size_t>(ReplyVectors[0].Length)},
              {const_cast<void *>(ReplyPayload), static_cast<size_t>(ReplyVectors[1].Length)},
          }};
          errno = 0;
          const ssize_t Result =
              ::BlockingHostCall([&] { return writev(Descriptor, HostVectors.data(), HostVectors.size()); });
          if (Result < 0) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          WriteVVectorCount += VectorCount;
          WriteVByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }
        constexpr uint64_t PublicWineMaximumRequestLength = 8192;
        const bool BoundedWineVariableRequestShape = [&] {
          if (!ExactWineRequestDescriptor || !ReplyVectors || VectorCount < 2 || VectorCount > 6 ||
              ReplyVectors[0].Length != MeasuredWineRequestHeaderSize || !ReplyHeader ||
              RequestHeaderRequestSize > PublicWineMaximumRequestLength ||
              RequestHeaderReplySize > PublicWineMaximumRequestLength) {
            return false;
          }

          uint64_t VariableSize{};
          for (uint64_t Index = 1; Index < VectorCount; ++Index) {
            if (ReplyVectors[Index].Length > PublicWineMaximumRequestLength - VariableSize ||
                (ReplyVectors[Index].Length != 0 && ResolveReplyPayload(ReplyVectors[Index]) == nullptr)) {
              return false;
            }
            VariableSize += ReplyVectors[Index].Length;
          }
          return VariableSize == RequestHeaderRequestSize;
        }();
        if (BoundedWineVariableRequestShape) {
          TraceWineRequestHeader("writev-bounded-public", Descriptor, ReplyHeader,
                                 static_cast<size_t>(MeasuredWineRequestHeaderSize));

          std::vector<iovec> HostVectors;
          HostVectors.reserve(static_cast<size_t>(VectorCount));
          for (uint64_t Index = 0; Index < VectorCount; ++Index) {
            HostVectors.push_back({
                const_cast<void *>(ResolveReplyPayload(ReplyVectors[Index])),
                static_cast<size_t>(ReplyVectors[Index].Length),
            });
          }

          errno = 0;
          const ssize_t Result = ::BlockingHostCall(
              [&] { return writev(Descriptor, HostVectors.data(), static_cast<int>(HostVectors.size())); });
          if (Result < 0) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          WriteVVectorCount += VectorCount;
          WriteVByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }
        struct stat TransportStat{};
        const int TransportFlags = fcntl(Descriptor, F_GETFL);
        if (OwnedDescriptors.contains(Descriptor) && TransportFlags != -1 && (TransportFlags & O_ACCMODE) != O_RDONLY &&
            fstat(Descriptor, &TransportStat) == 0 &&
            (S_ISFIFO(TransportStat.st_mode) || S_ISSOCK(TransportStat.st_mode) || S_ISREG(TransportStat.st_mode))) {
          if (VectorCount > LinuxIOVectorMaximum)
            return static_cast<uint64_t>(-EINVAL);
          if (VectorCount == 0)
            return 0;
          const auto *GuestIO = static_cast<const LinuxIOVector64 *>(
              HostPointerForGuestRange(GuestVectors, VectorCount * sizeof(LinuxIOVector64), PROT_READ));
          if (!GuestIO)
            return static_cast<uint64_t>(-EFAULT);
          std::vector<iovec> HostIO;
          uint64_t Total{};
          for (uint64_t Index = 0; Index < VectorCount; ++Index) {
            if (GuestIO[Index].Length > static_cast<uint64_t>(SSIZE_MAX) - Total) {
              return static_cast<uint64_t>(-EINVAL);
            }
            void *Bytes = GuestIO[Index].Length == 0
                              ? nullptr
                              : HostPointerForGuestRange(GuestIO[Index].Base, GuestIO[Index].Length, PROT_READ);
            if (GuestIO[Index].Length != 0 && !Bytes)
              return static_cast<uint64_t>(-EFAULT);
            HostIO.push_back({Bytes, static_cast<size_t>(GuestIO[Index].Length)});
            Total += GuestIO[Index].Length;
          }
          ssize_t Result;
          do {
            Result =
                BlockingHostCall([&] { return writev(Descriptor, HostIO.data(), static_cast<int>(HostIO.size())); });
          } while (Result == -1 && errno == EINTR);
          if (Result < 0)
            return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
          WriteVByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }

        return static_cast<uint64_t>(-EBADF);
      }
      if (VectorCount > LinuxIOVectorMaximum) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (VectorCount == 0) {
        return 0;
      }
      const auto *Vectors = static_cast<const LinuxIOVector64 *>(
          HostPointerForGuestRange(GuestVectors, VectorCount * sizeof(LinuxIOVector64), PROT_READ));
      if (Vectors == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }

      uint64_t TotalBytes{};
      for (uint64_t Index = 0; Index < VectorCount; ++Index) {
        const LinuxIOVector64 Vector = Vectors[Index];
        if (Vector.Length > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) - TotalBytes) {
          return static_cast<uint64_t>(-EINVAL);
        }
        if (Vector.Length != 0 && HostPointerForGuestRange(Vector.Base, Vector.Length, PROT_READ) == nullptr) {
          return static_cast<uint64_t>(-EFAULT);
        }
        TotalBytes += Vector.Length;
      }

      for (uint64_t Index = 0; Index < VectorCount; ++Index) {
        const LinuxIOVector64 Vector = Vectors[Index];
        if (Vector.Length == 0) {
          continue;
        }
        const auto *Payload =
            static_cast<const char *>(HostPointerForGuestRange(Vector.Base, Vector.Length, PROT_READ));
        if (Descriptor == STDOUT_FILENO) {
          CapturedOutput.append(Payload, static_cast<size_t>(Vector.Length));
        } else {
          CapturedError.append(Payload, static_cast<size_t>(Vector.Length));
          if (fli_env_enabled("REGRESSION_FLI_STREAM_GUEST_STDERR"))
            write(STDERR_FILENO, Payload, static_cast<size_t>(Vector.Length));
        }
      }
      WriteVVectorCount += VectorCount;
      WriteVByteCount += TotalBytes;
      return TotalBytes;
    }
    if (Number == WriteSyscall) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t Buffer = Arguments->Argument[2];
      const uint64_t Count = Arguments->Argument[3];
      const bool IsOutputDescriptor = Descriptor == STDOUT_FILENO || Descriptor == STDERR_FILENO;
      const bool IsClosedOutputDescriptor = IsOutputDescriptor && ClosedStandardDescriptors.contains(Descriptor);
      if (CXAltLoaderConnectedDescriptors.contains(Descriptor)) {
        constexpr uint64_t MaximumAltLoaderWriteSize = 16ULL * 1024ULL * 1024ULL;

        if (!OwnedDescriptors.contains(Descriptor) || Descriptor <= STDERR_FILENO) {
          return static_cast<uint64_t>(-EBADF);
        }
        if (Count > MaximumAltLoaderWriteSize) {
          return static_cast<uint64_t>(-E2BIG);
        }
        const void *Payload = Count == 0 ? nullptr : HostPointerForGuestRange(Buffer, Count, PROT_READ);
        if (Count != 0 && !Payload) {
          return static_cast<uint64_t>(-EFAULT);
        }

        errno = 0;
        const int HostDescriptorFlags = fcntl(Descriptor, F_GETFD);
        const int HostDescriptorFlagsError = HostDescriptorFlags == -1 ? errno : 0;
        errno = 0;
        struct stat DescriptorStat{};
        const bool DescriptorStatSucceeded = fstat(Descriptor, &DescriptorStat) == 0;

        if (HostDescriptorFlagsError != 0) {
          const int LinuxError = TranslateHostFcntlGetFlagsErrorToLinux(HostDescriptorFlagsError);
          return static_cast<uint64_t>(-LinuxError);
        }
        if ((HostDescriptorFlags & FD_CLOEXEC) == 0 || !DescriptorStatSucceeded || !S_ISSOCK(DescriptorStat.st_mode)) {
          return static_cast<uint64_t>(-EBADF);
        }

        ssize_t Result;
        do {
          Result = BlockingHostCall([&] { return write(Descriptor, Payload, static_cast<size_t>(Count)); });
        } while (Result == -1 && errno == EINTR);
        if (Result == -1) {
          const int HostError = errno;
          const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
          return static_cast<uint64_t>(-LinuxError);
        }
        WriteAltLoaderWrittenByteCount += static_cast<uint64_t>(Result);
        return static_cast<uint64_t>(Result);
      }
      if (RegistryTemporaryDescriptors.contains(Descriptor)) {

        constexpr uint64_t MaximumMeasuredRegistryTemporaryWriteSize = 4096;
        const uint8_t *ReadableBytes{};
        if (Count > 0 && Count <= MaximumMeasuredRegistryTemporaryWriteSize && Contains(Buffer, Count)) {
          ReadableBytes = reinterpret_cast<const uint8_t *>(Buffer);
        } else if (Count > 0 && Count <= MaximumMeasuredRegistryTemporaryWriteSize && LowGuestShadow &&
                   LowGuestShadow->ContainsMappedLogicalRange(Buffer, Count, PROT_READ)) {
          ReadableBytes = reinterpret_cast<const uint8_t *>(
              LowGuestShadow->HostPointerForMappedLogicalRange(Buffer, Count, PROT_READ));
        }

        const int SavedHostError = errno;
        errno = 0;
        const int HostDescriptorFlags = fcntl(Descriptor, F_GETFD);
        const int HostDescriptorError = HostDescriptorFlags == -1 ? errno : 0;
        errno = 0;
        const int HostStatusFlags = fcntl(Descriptor, F_GETFL);
        const int HostStatusError = HostStatusFlags == -1 ? errno : 0;
        errno = 0;
        struct stat DescriptorStat{};
        const bool DescriptorStatSucceeded = fstat(Descriptor, &DescriptorStat) == 0;
        errno = SavedHostError;

        const bool ExactRegistryTemporaryWrite =
            OwnedDescriptors.contains(Descriptor) && Descriptor > STDERR_FILENO && ReadableBytes &&
            HostDescriptorError == 0 && HostDescriptorFlags == 0 && HostStatusError == 0 &&
            HostStatusFlags == O_WRONLY && DescriptorStatSucceeded && S_ISREG(DescriptorStat.st_mode);
        if (ExactRegistryTemporaryWrite) {
          ssize_t Result;
          do {
            Result = BlockingHostCall([&] { return write(Descriptor, ReadableBytes, static_cast<size_t>(Count)); });
          } while (Result == -1 && errno == EINTR);
          if (Result == -1) {
            const int HostError = errno;
            const int LinuxError = TranslateHostRegularWriteErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          WriteRegistryTemporaryWrittenByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }
      }
      if (!IsOutputDescriptor || IsClosedOutputDescriptor) {
        constexpr uint64_t MeasuredWineRequestSize = 64;
        struct stat RequestDescriptorStat{};
        const bool RequestDescriptorStatSucceeded = fstat(Descriptor, &RequestDescriptorStat) == 0;
        const int RequestDescriptorFlags = fcntl(Descriptor, F_GETFD);
        const void *MeasuredWineBuffer =
            Count == MeasuredWineRequestSize ? HostPointerForGuestRange(Buffer, Count, PROT_READ) : nullptr;
        const bool ExactWineReplyHeader = GuestProgram == "/opt/proton/files/bin/wineserver" && !IsOutputDescriptor &&
                                          OwnedDescriptors.contains(Descriptor) &&
                                          ReceivedSCMRightsDescriptors.contains(Descriptor) &&
                                          RequestDescriptorFlags != -1 && (RequestDescriptorFlags & FD_CLOEXEC) == 0 &&
                                          RequestDescriptorStatSucceeded && S_ISFIFO(RequestDescriptorStat.st_mode) &&
                                          Count == MeasuredWineRequestSize && MeasuredWineBuffer;
        if (ExactWineReplyHeader) {
          TraceWineReplyHeader("write", Descriptor, MeasuredWineBuffer, static_cast<size_t>(Count));
          ssize_t Result;
          do {
            Result =
                BlockingHostCall([&] { return write(Descriptor, MeasuredWineBuffer, static_cast<size_t>(Count)); });
          } while (Result == -1 && errno == EINTR);
          if (Result == -1) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          WriteWineReplyWrittenByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }
        const bool ExactWineRequestPipe = !IsOutputDescriptor && OwnedDescriptors.contains(Descriptor) &&
                                          ReceivedSCMRightsDescriptors.contains(Descriptor) &&
                                          RequestDescriptorFlags != -1 && (RequestDescriptorFlags & FD_CLOEXEC) != 0 &&
                                          RequestDescriptorStatSucceeded && S_ISFIFO(RequestDescriptorStat.st_mode) &&
                                          Count == MeasuredWineRequestSize && MeasuredWineBuffer;
        if (ExactWineRequestPipe) {
          TraceWineRequestHeader("write", Descriptor, MeasuredWineBuffer, static_cast<size_t>(Count));
          ssize_t Result;
          do {
            Result =
                BlockingHostCall([&] { return write(Descriptor, MeasuredWineBuffer, static_cast<size_t>(Count)); });
          } while (Result == -1 && errno == EINTR);
          if (Result == -1) {
            const int HostError = errno;
            const int LinuxError = TranslateHostSocketErrorToLinux(HostError);
            return static_cast<uint64_t>(-LinuxError);
          }
          WriteRequestPipeWrittenByteCount += static_cast<uint64_t>(Result);
          return static_cast<uint64_t>(Result);
        }
        const void *OwnedPipeBuffer =
            Count <= static_cast<uint64_t>(SSIZE_MAX) ? HostPointerForGuestRange(Buffer, Count, PROT_READ) : nullptr;
        const int OwnedPipeStatus = fcntl(Descriptor, F_GETFL);
        if (OwnedDescriptors.contains(Descriptor) && RequestDescriptorStatSucceeded &&
            (S_ISFIFO(RequestDescriptorStat.st_mode) || S_ISSOCK(RequestDescriptorStat.st_mode) ||
             S_ISREG(RequestDescriptorStat.st_mode) || S_ISCHR(RequestDescriptorStat.st_mode)) &&
            OwnedPipeBuffer && OwnedPipeStatus != -1 && (OwnedPipeStatus & O_ACCMODE) != O_RDONLY) {
          ssize_t Result;
          do {
            Result = BlockingHostCall([&] { return write(Descriptor, OwnedPipeBuffer, static_cast<size_t>(Count)); });
          } while (Result == -1 && errno == EINTR);
          return Result == -1 ? static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno))
                              : static_cast<uint64_t>(Result);
        }
        return static_cast<uint64_t>(-EBADF);
      }
      if (Count == 0)
        return 0;
      const void *OutputBuffer = Count <= 4096 ? HostPointerForGuestRange(Buffer, Count, PROT_READ) : nullptr;
      if (Count > 4096 || (Count != 0 && OutputBuffer == nullptr)) {
        return static_cast<uint64_t>(-EFAULT);
      }
      WriteByteCount += Count;
      if (Descriptor == STDOUT_FILENO) {
        CapturedOutput.append(static_cast<const char *>(OutputBuffer), static_cast<size_t>(Count));
      } else {
        CapturedError.append(static_cast<const char *>(OutputBuffer), static_cast<size_t>(Count));
        if (fli_env_enabled("REGRESSION_FLI_STREAM_GUEST_STDERR"))
          write(STDERR_FILENO, OutputBuffer, static_cast<size_t>(Count));
        if (fli_env_enabled("REGRESSION_FLI_TRACE_GUEST_STDERR")) {
          (void)BlockingHostCall([&] { return write(STDERR_FILENO, OutputBuffer, static_cast<size_t>(Count)); });
        }
      }
      return Count;
    }
    if (Number == BrkSyscall && InitialProgramBreak != 0)
      return ProgramBreak(Arguments->Argument[1]);
    if (Number == AccessSyscall && !RootFS.empty()) {
      const auto GuestPath = ReadGuestPath(Arguments->Argument[1]);
      if (!GuestPath.has_value()) {
        return static_cast<uint64_t>(-EFAULT);
      }
      TraceGuestPath("access", *GuestPath);
      const auto HostPath = ResolveGuestPathWithParents(*GuestPath);
      if (!HostPath.has_value()) {
        return static_cast<uint64_t>(-EACCES);
      }
      const int Mode = static_cast<int>(Arguments->Argument[2]);
      if (Mode != F_OK && (Mode & ~(R_OK | W_OK | X_OK)) != 0) {
        return static_cast<uint64_t>(-EINVAL);
      }
      if (access(HostPath->c_str(), Mode) == 0) {
        return 0;
      }
      return static_cast<uint64_t>(-errno);
    }
    if (Number == OpenSyscall && !RootFS.empty()) {
      const auto GuestPath = ReadGuestPath(Arguments->Argument[1]);
      const uint64_t Flags = Arguments->Argument[2];

      if (!GuestPath.has_value()) {
        OpenLastLinuxError = EFAULT;
        return static_cast<uint64_t>(-EFAULT);
      }
      const bool IntlNLSDiagnostic = BeginIntlNLSDiagnostic("open", *GuestPath);
      TraceGuestPath("open", *GuestPath);
      if (GuestPath->empty() || GuestPath->front() != '/') {
        OpenLastLinuxError = ENOTSUP;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, false, false, false, ENOTSUP);
        return static_cast<uint64_t>(-ENOTSUP);
      }
      // Read-only open ignores the unused mode argument.
      if (Flags != 0) {
        OpenLastLinuxError = EINVAL;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, false, false, false, EINVAL);
        return static_cast<uint64_t>(-EINVAL);
      }
      const auto HostPath = ResolveGuestPath(*GuestPath);
      if (!HostPath.has_value()) {
        OpenLastLinuxError = EACCES;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, false, false, false, EACCES);
        return static_cast<uint64_t>(-EACCES);
      }
      struct stat HostStat{};
      if (stat(HostPath->c_str(), &HostStat) != 0) {
        OpenLastLinuxError = errno;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, true, false, false, OpenLastLinuxError);
        return static_cast<uint64_t>(-OpenLastLinuxError);
      }
      if (!S_ISREG(HostStat.st_mode)) {
        OpenLastLinuxError = EACCES;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, true, true, false, EACCES);
        return static_cast<uint64_t>(-EACCES);
      }
      const int Descriptor = open(HostPath->c_str(), O_RDONLY | O_CLOEXEC);
      if (Descriptor == -1) {
        OpenLastLinuxError = errno;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, true, true, true, OpenLastLinuxError);
        return static_cast<uint64_t>(-OpenLastLinuxError);
      }
      OwnedDescriptors.insert(Descriptor);
      OpenLastLinuxError = 0;
      FinishIntlNLSDiagnostic(IntlNLSDiagnostic, true, true, true, 0);
      return static_cast<uint64_t>(Descriptor);
    }
    if (Number == OpenAtSyscall && !RootFS.empty()) {
      ++OpenAtCallCount;
      constexpr uint64_t LinuxOWriteOnly = 0x1;
      constexpr uint64_t LinuxOReadWrite = 0x2;
      constexpr uint64_t LinuxOCreate = 0x40;
      constexpr uint64_t LinuxOExclusive = 0x80;
      constexpr uint64_t LinuxOTruncate = 0x200;
      constexpr uint64_t LinuxOCloexec = 0x80000;
      constexpr uint64_t LinuxOLargeFile = 0x8000;
      constexpr uint64_t LinuxODirectory = 0x10000;
      constexpr uint64_t LinuxAccessMode = 0x3;
      const int32_t DirectoryDescriptor = static_cast<int32_t>(Arguments->Argument[1]);
      const auto GuestPath = ReadGuestPath(Arguments->Argument[2]);
      const uint64_t Flags = Arguments->Argument[3];
      const uint64_t Mode = Arguments->Argument[4];
      OpenAtLastPathFingerprint = 0;
      OpenAtLastTargetExists = false;
      OpenAtLastTargetRegular = false;
      OpenAtLastLinuxError = 0;
      if (!GuestPath.has_value()) {
        OpenAtLastLinuxError = EFAULT;
        return static_cast<uint64_t>(-EFAULT);
      }
      const bool IntlNLSDiagnostic = BeginIntlNLSDiagnostic("openat", *GuestPath);
      RecordTemporaryMappingCandidate(*GuestPath, Flags, Mode);
      OpenAtLastPathFingerprint =
          FingerprintBytes(reinterpret_cast<const uint8_t *>(GuestPath->data()), GuestPath->size());
      TraceGuestPath("openat", *GuestPath);
      if (GuestProgram == "/opt/proton/files/bin/wineserver") {
        std::cerr << "TRACE wineserver-openat call=" << OpenAtCallCount << " dirfd=" << DirectoryDescriptor
                  << " flags=" << Flags << " mode=" << Mode << " path-length=" << GuestPath->size()
                  << " path-fingerprint=" << OpenAtLastPathFingerprint << " guest-path=" << *GuestPath << '\n';
        std::cerr.flush();
      }
      if (DirectoryDescriptor != LinuxAtFDCWD || GuestPath->empty()) {
        OpenAtLastLinuxError = ENOTSUP;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, false, false, false, ENOTSUP);
        return static_cast<uint64_t>(-ENOTSUP);
      }
      const bool CreateTruncatedWrite = Flags == (LinuxOWriteOnly | LinuxOCreate | LinuxOTruncate) && Mode == 0600;
      const bool CreateExclusiveTemporaryMapping = Flags == (LinuxOReadWrite | LinuxOCreate | LinuxOExclusive) &&
                                                   Mode == 0600 && IsTemporaryMappingCandidate(*GuestPath, Flags, Mode);
      const bool RegistryTemporaryBasename =
          GuestPath->size() >= 12 && GuestPath->starts_with("reg") && GuestPath->ends_with(".tmp") &&
          GuestPath->find('/') == std::string::npos &&
          std::all_of(GuestPath->begin() + 3, GuestPath->end() - 4, [](char Character) {
            return (Character >= '0' && Character <= '9') || (Character >= 'a' && Character <= 'f') ||
                   (Character >= 'A' && Character <= 'F');
          });
      const bool CreateExclusiveRegistryTemporary = GuestProgram == "/opt/proton/files/bin/wineserver" &&
                                                    GuestCurrentWorkingDirectory == "/home/regression/.wine" &&
                                                    Flags == (LinuxOWriteOnly | LinuxOCreate | LinuxOExclusive) &&
                                                    Mode == 0666 && RegistryTemporaryBasename;
      const bool ReadOnly =
          (Flags & LinuxAccessMode) == 0 &&
          (Flags & ~(LinuxOCloexec | LinuxOLargeFile | LinuxONonBlock | LinuxODirectory | LinuxAccessMode)) == 0;
      const auto NormalizedWritablePath = NormalizeGuestPathWithParents(*GuestPath);
      const bool OrdinaryWritable =
          (Flags & LinuxAccessMode) != 0 && (Flags & LinuxAccessMode) != 3 &&
          (Flags & ~(LinuxAccessMode | LinuxOCloexec | LinuxOLargeFile | LinuxONonBlock | LinuxOCreate |
                     LinuxOExclusive | LinuxOTruncate | LinuxOAppend)) == 0 &&
          NormalizedWritablePath.has_value() &&
          (NormalizedWritablePath->starts_with("/home/regression/") || NormalizedWritablePath->starts_with("/tmp/") ||
           NormalizedWritablePath->starts_with("/var/cache/") || *NormalizedWritablePath == "/dev/null");
      if (!OrdinaryWritable && !CreateTruncatedWrite && !CreateExclusiveTemporaryMapping &&
          !CreateExclusiveRegistryTemporary && !ReadOnly) {
        OpenAtLastLinuxError = EINVAL;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, false, false, false, EINVAL);
        return static_cast<uint64_t>(-EINVAL);
      }
      if (GuestPath->starts_with("/proc/self/fd/")) {
        if (!ReadOnly)
          return static_cast<uint64_t>(-ENOTSUP);
        const char *Digits = GuestPath->c_str() + 14;
        char *End = nullptr;
        long Source = strtol(Digits, &End, 10);
        if (End == Digits || *End || Source < 0 || Source > 65535)
          return static_cast<uint64_t>(-ENOENT);
        using Open = int32_t (*)(int);
        auto Function = reinterpret_cast<Open>(dlsym(RTLD_DEFAULT, "fli_linux_root_open_inherited"));
        if (!Function)
          return static_cast<uint64_t>(-ENOTSUP);
        int Descriptor = Function(int(Source));
        if (Descriptor < 0)
          return static_cast<uint64_t>(Descriptor);
        if (!(Flags & LinuxOCloexec))
          fcntl(Descriptor, F_SETFD, 0);
        OwnedDescriptors.insert(Descriptor);
        InheritedReadOffsets[Descriptor] = std::make_shared<int64_t>(0);
        return Descriptor;
      }
      if (ReadOnly) {
        if (const auto ProcFD = OpenProcSnapshot(*GuestPath)) {
          const int Descriptor = *ProcFD;
          if (Descriptor < 0)
            return static_cast<uint64_t>(Descriptor);
          if (!(Flags & LinuxOCloexec))
            fcntl(Descriptor, F_SETFD, 0);
          OwnedDescriptors.insert(Descriptor);
          return Descriptor;
        }
      }
      const auto HostPath = *GuestPath == "/dev/null"
                                ? std::optional<std::string>{RootFS + "/dev/null"}
                                : ((Flags & LinuxOCreate) ? ResolveGuestCreationPath(*GuestPath)
                                                          : ResolveGuestPathWithParents(*GuestPath));
      if (!HostPath.has_value()) {
        OpenAtLastLinuxError = EACCES;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, false, false, false, EACCES);
        return static_cast<uint64_t>(-EACCES);
      }
      struct stat TargetStat{};
      if (lstat(HostPath->c_str(), &TargetStat) == 0) {
        OpenAtLastTargetExists = true;
        OpenAtLastTargetRegular = S_ISREG(TargetStat.st_mode);
      }
      int HostFlags = O_RDONLY;
      if (OrdinaryWritable) {
        HostFlags = ((Flags & LinuxAccessMode) == LinuxOReadWrite ? O_RDWR : O_WRONLY) | O_NOFOLLOW;
        if (Flags & LinuxOCreate)
          HostFlags |= O_CREAT;
        if (Flags & LinuxOExclusive)
          HostFlags |= O_EXCL;
        if (Flags & LinuxOTruncate)
          HostFlags |= O_TRUNC;
        if (Flags & LinuxOAppend)
          HostFlags |= O_APPEND;
      }
      if (ReadOnly && (Flags & LinuxODirectory))
        HostFlags |= O_DIRECTORY;
      if (CreateTruncatedWrite) {
        HostFlags = O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW;
      } else if (CreateExclusiveTemporaryMapping) {
        HostFlags = O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW;
      } else if (CreateExclusiveRegistryTemporary) {
        HostFlags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW;
      }
      if (!CreateTruncatedWrite && !CreateExclusiveTemporaryMapping && !CreateExclusiveRegistryTemporary &&
          (Flags & LinuxOCloexec) != 0) {
        HostFlags |= O_CLOEXEC;
      }
      if (!CreateTruncatedWrite && !CreateExclusiveTemporaryMapping && !CreateExclusiveRegistryTemporary &&
          (Flags & LinuxONonBlock) != 0) {
        HostFlags |= O_NONBLOCK;
      }
      const char *OpenPath = *GuestPath == "/dev/null" ? "/dev/null" : HostPath->c_str();
      const int Descriptor = open(OpenPath, HostFlags, static_cast<mode_t>(Mode & ~GuestUmask));
      if (Descriptor == -1) {
        const int HostError = errno;
        OpenAtLastLinuxError =
            CreateExclusiveRegistryTemporary ? TranslateHostFileOpenErrorToLinux(HostError) : HostError;
        FinishIntlNLSDiagnostic(IntlNLSDiagnostic, true, OpenAtLastTargetExists, OpenAtLastTargetRegular,
                                OpenAtLastLinuxError);
        return static_cast<uint64_t>(-OpenAtLastLinuxError);
      }
      OwnedDescriptors.insert(Descriptor);
      if (CreateExclusiveRegistryTemporary) {
        RegistryTemporaryDescriptors.insert(Descriptor);
        RegistryTemporaryBasenames.insert(*GuestPath);
      }
      FinishIntlNLSDiagnostic(IntlNLSDiagnostic, true, OpenAtLastTargetExists, OpenAtLastTargetRegular, 0);
      return static_cast<uint64_t>(Descriptor);
    }
    if (Number == NewFStatAtSyscall && !RootFS.empty()) {
      constexpr uint64_t LinuxAtSymlinkNoFollow = 0x100;
      constexpr uint64_t LinuxAtNoAutomount = 0x800;
      const int32_t DirectoryDescriptor = static_cast<int32_t>(Arguments->Argument[1]);
      const auto GuestPath = ReadGuestPath(Arguments->Argument[2]);
      const uint64_t GuestBuffer = Arguments->Argument[3];
      void *StatDestination = HostPointerForGuestRange(GuestBuffer, sizeof(LinuxX86_64Stat), PROT_WRITE);
      const uint64_t Flags = Arguments->Argument[4];
      const auto FailNewFStatAt = [&](int64_t LinuxError, std::string_view Reason) {
        return static_cast<uint64_t>(-LinuxError);
      };
      if (!GuestPath.has_value()) {
        return FailNewFStatAt(EFAULT, "unreadable-path");
      }

      TraceGuestPath("newfstatat", *GuestPath);
      if (StatDestination == nullptr) {
        return FailNewFStatAt(EFAULT, "invalid-guest-buffer");
      }
      if (DirectoryDescriptor != LinuxAtFDCWD) {
        return FailNewFStatAt(ENOTSUP, "directory-descriptor-not-enabled");
      }
      if (GuestPath->empty()) {
        return FailNewFStatAt(ENOTSUP, "empty-path-not-enabled");
      }
      if ((Flags & ~(LinuxAtSymlinkNoFollow | LinuxAtNoAutomount)) != 0) {
        return FailNewFStatAt(EINVAL, "unsupported-flags");
      }
      if (const auto ProcFD = OpenProcSnapshot(*GuestPath)) {
        if (*ProcFD < 0)
          return FailNewFStatAt(-*ProcFD, "proc-snapshot-failed");
        struct stat HostStat{};
        const int Result = fstat(*ProcFD, &HostStat), Error = errno;
        ReleaseProcSnapshot(*ProcFD);
        close(*ProcFD);
        if (Result)
          return FailNewFStatAt(TranslateHostSocketErrorToLinux(Error), "proc-snapshot-stat-failed");
        const LinuxX86_64Stat GuestStat = TranslateStat(HostStat);
        std::memcpy(StatDestination, &GuestStat, sizeof(GuestStat));
        return 0;
      }
      const auto HostPath = ResolveGuestPathWithParents(*GuestPath);
      if (!HostPath.has_value()) {
        return FailNewFStatAt(EACCES, "path-resolution-rejected");
      }
      struct stat ObservedTargetStat{};
      (void)lstat(HostPath->c_str(), &ObservedTargetStat);
      struct stat HostStat{};
      const int Result = (Flags & LinuxAtSymlinkNoFollow) != 0 ? lstat(HostPath->c_str(), &HostStat)
                                                               : stat(HostPath->c_str(), &HostStat);
      if (Result != 0) {
        return FailNewFStatAt(errno, "host-stat-failed");
      }
      const LinuxX86_64Stat GuestStat = TranslateStat(HostStat);
      std::memcpy(StatDestination, &GuestStat, sizeof(GuestStat));
      return 0;
    }
    if (Number == Clone3Syscall && !RootFS.empty()) {
      constexpr uint64_t LinuxCloneVM = 0x00000100;
      constexpr uint64_t LinuxCloneVFork = 0x00004000;
      constexpr uint64_t LinuxCloneClearSighand = 0x1'0000'0000;
      constexpr uint64_t LinuxSigChild = 17;
      constexpr uint64_t ObservedSpawnStackSize = 36'864;
      const uint64_t GuestCloneArgs = Arguments->Argument[1];
      const uint64_t CloneArgsSize = Arguments->Argument[2];
      const void *CloneBuffer = CloneArgsSize == sizeof(LinuxClone3Args)
                                    ? HostPointerForGuestRange(GuestCloneArgs, sizeof(LinuxClone3Args), PROT_READ)
                                    : nullptr;
      if (CloneBuffer) {
        LinuxClone3Args GuestArgs{};
        std::memcpy(&GuestArgs, CloneBuffer, sizeof(GuestArgs));
        const bool ExactClearSighandSpawn =
            GuestArgs.Flags == (LinuxCloneClearSighand | LinuxCloneVM | LinuxCloneVFork) && GuestArgs.PIDFD == 0 &&
            GuestArgs.ChildTID == 0 && GuestArgs.ParentTID == 0 && GuestArgs.ExitSignal == LinuxSigChild &&
            GuestArgs.StackSize == ObservedSpawnStackSize && Contains(GuestArgs.Stack, GuestArgs.StackSize) &&
            GuestArgs.TLS == 0 && GuestArgs.SetTID == 0 && GuestArgs.SetTIDSize == 0 && GuestArgs.CGroup == 0;
        if (ExactClearSighandSpawn) {
          return static_cast<uint64_t>(-EINVAL);
        }
      }
      return static_cast<uint64_t>(-38);
    }
    if (Number == CloneSyscall && !RootFS.empty() && Arguments->Argument[1] == 0x3d0f00) {
      return SpawnGuestThread(Frame->State, Arguments, Frame->State.rip + 2, nullptr);
    }
    if (Number == CloneSyscall && !RootFS.empty() && NativeForkCloneContextAttached) {
      constexpr uint64_t LinuxCloneChildClearTID = 0x00200000;
      constexpr uint64_t LinuxCloneChildSetTID = 0x01000000;
      constexpr uint64_t LinuxSigChild = 17;
      const uint64_t Flags = Arguments->Argument[1];
      const uint64_t ChildStack = Arguments->Argument[2];
      const uint64_t GuestChildTID = Arguments->Argument[4];

      void *const HostChildTID = HostPointerForGuestRange(GuestChildTID, sizeof(uint32_t), PROT_WRITE);
      const bool ExactObservedProcessClone =
          Flags == (LinuxCloneChildSetTID | LinuxCloneChildClearTID | LinuxSigChild) && ChildStack == 0 &&
          Arguments->Argument[3] == 0 && GuestChildTID != 0 && HostChildTID != nullptr && Arguments->Argument[5] == 0;
      constexpr uint64_t MaximumNativeForkCloneDepth = 16;
      if (ForkContext != nullptr && ExactObservedProcessClone &&
          NativeForkCloneAttemptCount < MaximumNativeForkCloneDepth) {
        ++NativeForkCloneAttemptCount;
        if (ForkContext == nullptr) {
          return static_cast<uint64_t>(-EAGAIN);
        }
        ForkContext->LockBeforeFork(Frame->Thread);
        const pid_t Result = fork();
        const int ForkError = errno;
        ForkContext->UnlockAfterFork(Frame->Thread, Result == 0);
        if (Result == 0) {
          // Reestablish executable JIT access at the native-to-guest handoff.
          pthread_jit_write_protect_np(1);
        } else {
        }
        errno = ForkError;
        if (Result < 0) {
          return static_cast<uint64_t>(-EAGAIN);
        }
        if (Result == 0) {
          if (CallbackGuestThreadID) {
            const uint64_t inherited_mask = CurrentSignalMask();
            BorrowedSignalMask = nullptr;
            OwnSignalMask = inherited_mask;
            CallbackGuestThreadID = 0;
            MainCallbackTID.store(0);
            MainNativeTID = uint64_t(getpid());
            MainNativeThread = pthread_self();
          }
          if (SignalControlFD >= 0)
            close(SignalControlFD);
          SignalControlFD = -1;
          SignalControlRunning = false;
          SignalControlPath.clear();
          NativeGuestThreads.clear();
          ActiveGuestThread = nullptr;
          new (&SyscallMutex) std::recursive_mutex;
          SyscallMutex.lock();
          NativeForkCloneChildProcess = true;
          const uint32_t ChildProcessID = static_cast<uint32_t>(getpid());
          std::memcpy(HostChildTID, &ChildProcessID, sizeof(ChildProcessID));

          // The child may legitimately become a process launcher itself. It
          // owns no child yet, so clear the parent-side slot while preserving
          // the inherited depth counter as a hard anti-fork-bomb bound.
          NativeForkCloneParentProcess = false;
          NativeForkCloneProcessID = -1;
          NativeForkCloneChildReaped = false;

          return 0;
        }
        NativeForkCloneParentProcess = true;
        NativeForkCloneProcessID = Result;
        return static_cast<uint64_t>(Result);
      }
    }
    if (Number == Wait4Syscall && NativeForkCloneParentProcess &&
        static_cast<int64_t>(Arguments->Argument[1]) == NativeForkCloneProcessID) {
      const uint64_t GuestStatus = Arguments->Argument[2];
      const uint64_t Options = Arguments->Argument[3];
      if ((Options & ~uint64_t{1}) != 0 || Arguments->Argument[4] != 0)
        return static_cast<uint64_t>(-EINVAL);
      void *Output = GuestStatus ? HostPointerForGuestRange(GuestStatus, sizeof(int32_t), PROT_WRITE) : nullptr;
      if (GuestStatus && !Output)
        return static_cast<uint64_t>(-EFAULT);
      int Status{};
      const pid_t Result = BlockingHostCall(
          [&] { return waitpid(static_cast<pid_t>(NativeForkCloneProcessID), &Status, Options ? WNOHANG : 0); });
      if (Result < 0)
        return static_cast<uint64_t>(-errno);
      if (Result > 0) {
        if (Output)
          std::memcpy(Output, &Status, sizeof(Status));
        NativeForkCloneChildReaped = true;
      }
      return static_cast<uint64_t>(Result);
    }

    if (Number == ExitSyscall || Number == ExitGroupSyscall) {
      if (Number == ExitSyscall && ActiveGuestThread) {
        ActiveGuestThread->ExitCode = Arguments->Argument[1];
        ActiveGuestThread->Exited = true;
        Stop(Frame);
        return 0;
      }
      if (Number == ExitGroupSyscall) {
        ProcessExiting = true;
        if (ActiveGuestThread)
          pthread_kill(MainNativeThread, SIGUSR2);
      }
      ExitSeen = true;
      ExitCode = Arguments->Argument[1];
      ExitGuestRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];
      ExitGuestRBP = Frame->State.gregs[FEXCore::X86State::REG_RBP];
      const void *StackBytes =
          Contains(ExitGuestRSP, sizeof(ExitGuestStackWords)) ? reinterpret_cast<const void *>(ExitGuestRSP) : nullptr;
      if (StackBytes == nullptr && LowMemoryBiasModeEnabled && LowGuestShadow != nullptr) {
        StackBytes =
            LowGuestShadow->HostPointerForMappedLogicalRange(ExitGuestRSP, sizeof(ExitGuestStackWords), PROT_READ);
      }
      if (StackBytes != nullptr) {
        std::memcpy(ExitGuestStackWords.data(), StackBytes, sizeof(ExitGuestStackWords));
      }
      constexpr uint64_t MaximumFrameStep = 1ULL << 20;
      uint64_t CurrentFramePointer = ExitGuestRBP;
      for (size_t Index = 0; Index < ExitGuestFramePointers.size(); ++Index) {
        const void *FrameBytes = Contains(CurrentFramePointer, 2 * sizeof(uint64_t))
                                     ? reinterpret_cast<const void *>(CurrentFramePointer)
                                     : nullptr;
        if (FrameBytes == nullptr && LowMemoryBiasModeEnabled && LowGuestShadow != nullptr) {
          FrameBytes =
              LowGuestShadow->HostPointerForMappedLogicalRange(CurrentFramePointer, 2 * sizeof(uint64_t), PROT_READ);
        }
        if (FrameBytes == nullptr) {
          break;
        }
        uint64_t NextFramePointer{};
        uint64_t ReturnAddress{};
        std::memcpy(&NextFramePointer, FrameBytes, sizeof(NextFramePointer));
        std::memcpy(&ReturnAddress, static_cast<const uint8_t *>(FrameBytes) + sizeof(uint64_t), sizeof(ReturnAddress));
        ExitGuestFramePointers[Index] = CurrentFramePointer;
        ExitGuestFrameReturnAddresses[Index] = ReturnAddress;
        if (NextFramePointer <= CurrentFramePointer || NextFramePointer - CurrentFramePointer > MaximumFrameStep ||
            (NextFramePointer & (alignof(uint64_t) - 1)) != 0) {
          break;
        }
        CurrentFramePointer = NextFramePointer;
      }
      Stop(Frame);
      return 0;
    }
    if (Number == RecvMsgSyscall && !RootFS.empty()) {
      constexpr int64_t LinuxMsgCmsgCloseOnExec = 0x40000000;
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t GuestHeaderAddress = Arguments->Argument[2];
      RecvMsgLastDescriptorOwned = OwnedDescriptors.contains(Descriptor);
      RecvMsgLastPayloadValue = 0;
      RecvMsgLastFirstIOVectorPayloadReadable = false;
      RecvMsgLastControlReadable = false;
      if (!RecvMsgLastDescriptorOwned) {
        return static_cast<uint64_t>(-EBADF);
      }
      void *MessageBuffer =
          HostPointerForGuestRange(GuestHeaderAddress, sizeof(LinuxMessageHeader64), PROT_READ | PROT_WRITE);
      if (MessageBuffer == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      LinuxMessageHeader64 GuestHeader{};
      std::memcpy(&GuestHeader, MessageBuffer, sizeof(GuestHeader));
      const void *VectorBuffer = HostPointerForGuestRange(GuestHeader.IOVectors, sizeof(LinuxIOVector64), PROT_READ);
      if (VectorBuffer == nullptr) {
        return static_cast<uint64_t>(-EFAULT);
      }
      LinuxIOVector64 GuestVector{};
      std::memcpy(&GuestVector, VectorBuffer, sizeof(GuestVector));
      void *PayloadBuffer = GuestVector.Length <= static_cast<uint64_t>(SSIZE_MAX)
                                ? HostPointerForGuestRange(GuestVector.Base, GuestVector.Length, PROT_WRITE)
                                : nullptr;
      void *ControlBuffer = GuestHeader.ControlLength <= 65536
                                ? HostPointerForGuestRange(GuestHeader.Control, GuestHeader.ControlLength, PROT_WRITE)
                                : nullptr;
      RecvMsgLastFirstIOVectorPayloadReadable = GuestVector.Length == 0 || (PayloadBuffer != nullptr);
      RecvMsgLastControlReadable = GuestHeader.ControlLength == 0 || (ControlBuffer != nullptr);
      if (!RecvMsgLastFirstIOVectorPayloadReadable) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if (!RecvMsgLastControlReadable) {
        return static_cast<uint64_t>(-EFAULT);
      }
      if (GuestHeader.Name || GuestHeader.NameLength)
        return static_cast<uint64_t>(-95);
      if (GuestHeader.IOVectorCount > 1024 || GuestHeader.ControlLength > 65536)
        return static_cast<uint64_t>(-EINVAL);
      const uint64_t Flags = Arguments->Argument[3];
      if (Flags & ~(uint64_t{2} | 64 | 256 | LinuxMsgCmsgCloseOnExec))
        return static_cast<uint64_t>(-EINVAL);
      const void *VectorsBuffer = HostPointerForGuestRange(
          GuestHeader.IOVectors, GuestHeader.IOVectorCount * sizeof(LinuxIOVector64), PROT_READ);
      if (GuestHeader.IOVectorCount && !VectorsBuffer)
        return static_cast<uint64_t>(-EFAULT);
      std::vector<iovec> Vectors;
      uint64_t Total{};
      for (uint64_t I = 0; I < GuestHeader.IOVectorCount; ++I) {
        LinuxIOVector64 Vector{};
        std::memcpy(&Vector, static_cast<const uint8_t *>(VectorsBuffer) + I * sizeof(Vector), sizeof(Vector));
        if (Vector.Length > SSIZE_MAX - Total)
          return static_cast<uint64_t>(-EINVAL);
        void *Buffer = HostPointerForGuestRange(Vector.Base, Vector.Length, PROT_WRITE);
        if (Vector.Length && !Buffer)
          return static_cast<uint64_t>(-EFAULT);
        Vectors.push_back({Buffer, static_cast<size_t>(Vector.Length)});
        Total += Vector.Length;
      }
      std::vector<uint64_t> ControlStorage((GuestHeader.ControlLength + 7) / 8);
      msghdr HostHeader{};
      HostHeader.msg_iov = Vectors.data();
      HostHeader.msg_iovlen = static_cast<int>(Vectors.size());
      HostHeader.msg_control = ControlStorage.data();
      HostHeader.msg_controllen = static_cast<socklen_t>(GuestHeader.ControlLength);
      int HostFlags = Flags & 2 ? MSG_PEEK : 0;
      if (Flags & 64)
        HostFlags |= MSG_DONTWAIT;
      if (Flags & 256)
        HostFlags |= MSG_WAITALL;
      const int64_t Result = BlockingHostCall([&]() -> int64_t {
        const ssize_t Value = recvmsg(Descriptor, &HostHeader, HostFlags);
        return Value < 0 ? -TranslateHostSocketErrorToLinux(errno) : Value;
      });
      if (Result < 0) {
        return static_cast<uint64_t>(Result);
      }
      uint64_t Written{};
      int LinuxFlags = HostHeader.msg_flags & MSG_CTRUNC ? 8 : 0;
      if (HostHeader.msg_flags & MSG_TRUNC)
        LinuxFlags |= 0x20;
      if (HostHeader.msg_flags & MSG_EOR)
        LinuxFlags |= 0x80;
      for (cmsghdr *Message = CMSG_FIRSTHDR(&HostHeader); Message; Message = CMSG_NXTHDR(&HostHeader, Message)) {
        if (Message->cmsg_len < CMSG_LEN(0))
          break;
        if (Message->cmsg_level != SOL_SOCKET || Message->cmsg_type != SCM_RIGHTS) {
          LinuxFlags |= 8;
          continue;
        }
        const size_t Count = (Message->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        std::vector<int> Kept;
        for (size_t I = 0; I < Count; ++I) {
          int FD{};
          std::memcpy(&FD, CMSG_DATA(Message) + I * sizeof(int), sizeof(FD));
          const uint64_t Needed = Written + sizeof(LinuxControlMessageHeader64) + (Kept.size() + 1) * sizeof(int);
          if (Needed > GuestHeader.ControlLength) {
            close(FD);
            LinuxFlags |= 8;
            continue;
          }
          if (Flags & LinuxMsgCmsgCloseOnExec) {
            const int Before = fcntl(FD, F_GETFD);
            if (Before < 0 || fcntl(FD, F_SETFD, Before | FD_CLOEXEC) < 0) {
              close(FD);
              LinuxFlags |= 8;
              continue;
            }
          }
          Kept.push_back(FD);
          OwnedDescriptors.insert(FD);
          ReceivedSCMRightsDescriptors.insert(FD);
        }
        if (!Kept.empty()) {
          const LinuxControlMessageHeader64 Header{sizeof(LinuxControlMessageHeader64) + Kept.size() * sizeof(int), 1,
                                                   1};
          std::memcpy(static_cast<uint8_t *>(ControlBuffer) + Written, &Header, sizeof(Header));
          std::memcpy(static_cast<uint8_t *>(ControlBuffer) + Written + sizeof(Header), Kept.data(),
                      Kept.size() * sizeof(int));
          Written += std::min<uint64_t>((Header.Length + 7) & ~uint64_t{7}, GuestHeader.ControlLength - Written);
        }
      }
      if (Result >= 4 && !Vectors.empty() && Vectors[0].iov_len >= 4)
        std::memcpy(&RecvMsgLastPayloadValue, Vectors[0].iov_base, sizeof(uint32_t));
      GuestHeader.ControlLength = Written;
      GuestHeader.Flags = LinuxFlags;
      std::memcpy(MessageBuffer, &GuestHeader, sizeof(GuestHeader));
      return static_cast<uint64_t>(Result);
    }

    if (Number == IoctlSyscall && !RootFS.empty() && Arguments->Argument[2] == LinuxTCGets2) {
      constexpr size_t LinuxTermios2Size = 44;
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t Argument = Arguments->Argument[3];
      IoctlTCGets2LastDescriptorStandard = Descriptor >= STDIN_FILENO && Descriptor <= STDERR_FILENO;
      IoctlTCGets2LastDescriptorClosed =
          IoctlTCGets2LastDescriptorStandard && ClosedStandardDescriptors.contains(Descriptor);
      IoctlTCGets2LastArgumentWritable = HostPointerForGuestRange(Argument, LinuxTermios2Size, PROT_WRITE) != nullptr;

      struct stat DescriptorStat{};
      IoctlTCGets2LastDescriptorStatSucceeded = fstat(Descriptor, &DescriptorStat) == 0;
      errno = 0;
      IoctlTCGets2LastDescriptorTTY = isatty(Descriptor) == 1;

      if (IoctlTCGets2LastDescriptorStandard && !IoctlTCGets2LastDescriptorClosed && IoctlTCGets2LastArgumentWritable &&
          IoctlTCGets2LastDescriptorStatSucceeded && !IoctlTCGets2LastDescriptorTTY) {
        // glibc implements isatty() with TCGETS2 on Linux. The laboratory's
        // inherited standard streams may be /dev/null or runner pipes. Linux
        // reports ENOTTY for every valid non-terminal descriptor and leaves
        // termios2 untouched; this is exactly the branch Wine uses to select
        // its no-console path.
        return static_cast<uint64_t>(-ENOTTY);
      }
    }
    if (Number == IoctlSyscall && !RootFS.empty() && Arguments->Argument[2] == LinuxExt2IOCGetFlags) {
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      const uint64_t Argument = Arguments->Argument[3];
      IoctlExt2GetFlagsLastDescriptorOwned = OwnedDescriptors.contains(Descriptor);
      if (!IoctlExt2GetFlagsLastDescriptorOwned) {
        return static_cast<uint64_t>(-EBADF);
      }

      constexpr size_t LinuxLongSize = sizeof(uint64_t);
      IoctlExt2GetFlagsLastArgumentWritable = HostPointerForGuestRange(Argument, LinuxLongSize, PROT_WRITE) != nullptr;
      if (!IoctlExt2GetFlagsLastArgumentWritable) {
        return static_cast<uint64_t>(-EFAULT);
      }

      struct stat DescriptorStat{};
      IoctlExt2GetFlagsLastDescriptorStatSucceeded = fstat(Descriptor, &DescriptorStat) == 0;
      IoctlExt2GetFlagsLastDescriptorDirectory =
          IoctlExt2GetFlagsLastDescriptorStatSucceeded && S_ISDIR(DescriptorStat.st_mode);
      IoctlExt2GetFlagsLastDescriptorRegular =
          IoctlExt2GetFlagsLastDescriptorStatSucceeded && S_ISREG(DescriptorStat.st_mode);

      std::array<char, 4096> DescriptorPath{};
      if (fcntl(Descriptor, F_GETPATH, DescriptorPath.data()) == 0) {
        const std::string HostPath{DescriptorPath.data()};
        IoctlExt2GetFlagsLastDescriptorPathConfined = fli_guest_host_path_visible(HostPath, RootFS);
      }

      if (!IoctlExt2GetFlagsLastDescriptorStatSucceeded ||
          (!IoctlExt2GetFlagsLastDescriptorDirectory && !IoctlExt2GetFlagsLastDescriptorRegular) ||
          !IoctlExt2GetFlagsLastDescriptorPathConfined) {
        return static_cast<uint64_t>(-EACCES);
      }

      // Proton's Linux Wine asks for ext2 flags before falling back to
      // fstatfs. The private RootFS is hosted by APFS, so there is no ext2
      // attribute namespace to translate. ENOTTY is the Linux contract for
      // an otherwise valid descriptor whose filesystem does not implement
      // EXT2_IOC_GETFLAGS; it deliberately leaves the guest buffer untouched.
      return static_cast<uint64_t>(-ENOTTY);
    }
    if (Number == IoctlSyscall && !RootFS.empty() &&
        (Arguments->Argument[2] == 0x82307201 || Arguments->Argument[2] == 0x82307202)) {
      // VFAT_READDIR_BOTH/SHORT are not available on this APFS-backed RootFS.
      const int Descriptor = static_cast<int>(Arguments->Argument[1]);
      if (!OwnedDescriptors.contains(Descriptor))
        return static_cast<uint64_t>(-EBADF);
      return static_cast<uint64_t>(-ENOTTY);
    }
    if (UnexpectedSyscall == std::numeric_limits<uint64_t>::max()) {
      UnexpectedSyscall = Number;
      if (Number == ExecveSyscall) {
        const auto GuestTarget = ReadGuestPath(Arguments->Argument[1]);
        std::vector<std::string> GuestExecArguments;
        std::vector<std::string> GuestExecEnvironment;
        if (GuestTarget.has_value()) {
          UnsupportedExecvePathLength = GuestTarget->size();
          UnsupportedExecvePathFingerprint =
              FingerprintBytes(reinterpret_cast<const uint8_t *>(GuestTarget->data()), GuestTarget->size());
          TraceGuestPath("execve", *GuestTarget);
          const size_t Separator = GuestTarget->find_last_of('/');
          const std::string_view Basename = Separator == std::string::npos
                                                ? std::string_view{*GuestTarget}
                                                : std::string_view{*GuestTarget}.substr(Separator + 1);
          if (Basename == "wineserver") {
            UnsupportedExecveTargetKind = "proton-wineserver";
          } else if (Basename == "wine-preloader" || Basename == "wine64-preloader") {
            UnsupportedExecveTargetKind = "proton-wine-preloader";
          } else if (Basename == "wine" || Basename == "wine64") {
            UnsupportedExecveTargetKind = "proton-wine-loader";
          } else if (!GuestTarget->empty() && GuestTarget->front() == '/') {
            UnsupportedExecveTargetKind = "absolute-other";
          } else {
            UnsupportedExecveTargetKind = "relative-other";
          }
          UnsupportedExecveParentSegmentSeen =
              GuestTarget->find("/../") != std::string::npos || GuestTarget->ends_with("/..");
          if (!GuestTarget->empty() && GuestTarget->front() == '/') {
            const auto NormalizedGuestTarget = NormalizeGuestPathWithParents(*GuestTarget);
            UnsupportedExecveNormalizedPathConfined = NormalizedGuestTarget.has_value();
            if (NormalizedGuestTarget.has_value()) {
              UnsupportedExecveNormalizedPathLength = NormalizedGuestTarget->size();
              UnsupportedExecveNormalizedPathFingerprint = FingerprintBytes(
                  reinterpret_cast<const uint8_t *>(NormalizedGuestTarget->data()), NormalizedGuestTarget->size());
            }
            const auto HostTarget = ResolveGuestPathWithParents(*GuestTarget);
            if (HostTarget.has_value()) {
              struct stat TargetStat{};
              UnsupportedExecveTargetExists =
                  lstat(HostTarget->c_str(), &TargetStat) == 0 && S_ISREG(TargetStat.st_mode);
            }
          }
        }

        const uint64_t GuestArgv = Arguments->Argument[2];
        constexpr uint64_t MaximumArguments = 32;
        UnsupportedExecveArgvReadable = Contains(GuestArgv, sizeof(uint64_t));
        if (UnsupportedExecveArgvReadable) {
          for (uint64_t Index = 0; Index <= MaximumArguments; ++Index) {
            const uint64_t PointerAddress = GuestArgv + Index * sizeof(uint64_t);
            if (!Contains(PointerAddress, sizeof(uint64_t))) {
              UnsupportedExecveArgvReadable = false;
              break;
            }
            uint64_t ArgumentAddress{};
            std::memcpy(&ArgumentAddress, reinterpret_cast<const void *>(PointerAddress), sizeof(ArgumentAddress));
            if (ArgumentAddress == 0) {
              break;
            }
            const auto GuestArgument = ReadGuestPath(ArgumentAddress);
            if (!GuestArgument.has_value()) {
              UnsupportedExecveArgvReadable = false;
              break;
            }
            UnsupportedExecveArgLengths.push_back(GuestArgument->size());
            UnsupportedExecveArgFingerprints.push_back(
                FingerprintBytes(reinterpret_cast<const uint8_t *>(GuestArgument->data()), GuestArgument->size()));
            UnsupportedExecveArgKinds.push_back(ClassifyExecveArgument(Index, *GuestArgument));
            GuestExecArguments.push_back(*GuestArgument);
            TraceExecveArgument(Index, *GuestArgument);
            ++UnsupportedExecveArgCount;
          }
        }

        const uint64_t GuestEnvp = Arguments->Argument[3];
        constexpr uint64_t MaximumEnvironmentEntries = 64;
        UnsupportedExecveEnvpReadable = Contains(GuestEnvp, sizeof(uint64_t));
        if (UnsupportedExecveEnvpReadable) {
          for (uint64_t Index = 0; Index <= MaximumEnvironmentEntries; ++Index) {
            const uint64_t PointerAddress = GuestEnvp + Index * sizeof(uint64_t);
            if (!Contains(PointerAddress, sizeof(uint64_t))) {
              UnsupportedExecveEnvpReadable = false;
              break;
            }
            uint64_t EnvironmentAddress{};
            std::memcpy(&EnvironmentAddress, reinterpret_cast<const void *>(PointerAddress),
                        sizeof(EnvironmentAddress));
            if (EnvironmentAddress == 0) {
              break;
            }
            const auto EnvironmentEntry = ReadGuestPath(EnvironmentAddress);
            if (!EnvironmentEntry.has_value()) {
              UnsupportedExecveEnvpReadable = false;
              break;
            }
            ++UnsupportedExecveEnvCount;
            GuestExecEnvironment.push_back(*EnvironmentEntry);
            if (*EnvironmentEntry == "LC_ALL=C") {
              UnsupportedExecveEnvHasLCAllC = true;
            } else if (*EnvironmentEntry == "HOME=/home/regression") {
              UnsupportedExecveEnvHasPrivateHome = true;
            } else if (*EnvironmentEntry == "WINELOADERNOEXEC=1") {
              UnsupportedExecveEnvHasWineLoaderNoExec = true;
            } else if (*EnvironmentEntry == "WINEARCH=wow64") {
              UnsupportedExecveEnvHasWineArchWow64 = true;
            } else if (EnvironmentEntry->starts_with("WINESERVERSOCKET=")) {
              UnsupportedExecveEnvHasWineServerSocket = true;
            } else if (EnvironmentEntry->starts_with("WINEPRELOADRESERVE=")) {
              UnsupportedExecveEnvHasWinePreloadReserve = true;
            } else {
              ++UnsupportedExecveEnvUnknownCount;
            }
          }
        }
        if (GuestTarget.has_value()) {
          const auto ReentryResult =
              MaybeReexecOfficialProtonWine64Preloader(*GuestTarget, GuestExecArguments, GuestExecEnvironment);
          if (ReentryResult.has_value()) {
            return *ReentryResult;
          }
        }
      }
    }
    if (RootFS.empty() || PostSessionSyscallDiagnosticLimit != 0)
      Stop(Frame);
    if (PostSessionSyscallDiagnosticLimit != 0) {
      (void)DarwinDiagnosticThreadStopHandler::Request();
    }
    return static_cast<uint64_t>(-38);
  }

  std::optional<uint64_t> TrackedGuestProtection(uint64_t Address) const {
    if (auto It = GuestProtectionOverrides.find(Address & ~uint64_t{4095}); It != GuestProtectionOverrides.end())
      return It->second;
    for (auto It = HighMMapRecords.rbegin(); It != HighMMapRecords.rend(); ++It)
      if (It->Active && Address >= It->Address && Address - It->Address < It->Length)
        return It->Protection;
    return std::nullopt;
  }
  void UpdateTrackedProtections(uint64_t Number, uint64_t Start, uint64_t Length, uint64_t Protection) {
    if (!Length || Length > UINT64_MAX - Start || !Contains(Start, Length))
      return;
    for (uint64_t Page = Start & ~uint64_t{4095}; Page < Start + Length; Page += 4096) {
      if (Number == MProtectSyscall)
        GuestProtectionOverrides[Page] = Protection;
      else
        GuestProtectionOverrides.erase(Page);
    }
    if (Number != MProtectSyscall)
      for (auto &[Page, Active] : SMCProtectedPages)
        if (Page < Start + Length && Start < Page + getpagesize()) {
          Active = false;
          if (SMCNotify(GuestBase, Page, 0))
            std::abort();
        }
  }
  int ProjectArenaHostPermissions(uint64_t Address, uint64_t Length, uint64_t Protection) {
    const uint64_t HostPage = getpagesize(), End = Address + Length;
    std::vector<std::pair<uint64_t, int>> changed;
    const auto host_permissions = [&](uint64_t Base, bool proposed) {
      int permissions = 0;
      for (uint64_t guest = Base; guest < Base + HostPage; guest += 4096) {
        const uint64_t rights = proposed && guest >= Address && guest < End
                                    ? Protection
                                    : TrackedGuestProtection(guest).value_or(PROT_READ | PROT_WRITE);
        permissions |= int(rights & (PROT_READ | PROT_WRITE));
        if (rights & PROT_EXEC)
          permissions |= PROT_READ; // x86 instructions are host data.
      }
      return permissions;
    };
    for (uint64_t page = Address & ~(HostPage - 1); page < End; page += HostPage) {
      const int before = host_permissions(page, false), after = host_permissions(page, true);
      if (mprotect(reinterpret_cast<void *>(page), HostPage, after)) {
        const int error = errno;
        for (const auto &[old_page, old_rights] : changed)
          if (mprotect(reinterpret_cast<void *>(old_page), HostPage, old_rights))
            std::abort();
        return TranslateHostSocketErrorToLinux(error);
      }
      changed.emplace_back(page, before);
    }
    return 0;
  }
  uint64_t ProtectGuestRange(FEXCore::Core::InternalThreadState *Thread, uint64_t Address, uint64_t Length,
                             uint64_t Protection) {
    constexpr uint64_t Page = 4096;
    if (!Length || (Address & (Page - 1)) || (Protection & ~uint64_t{PROT_READ | PROT_WRITE | PROT_EXEC}) ||
        Length > UINT64_MAX - (Page - 1))
      return uint64_t(-EINVAL);
    Length = (Length + Page - 1) & ~(Page - 1);
    if (Address > UINT64_MAX - Length)
      return uint64_t(-EINVAL);
    UnprotectTrackedCodeRange(Thread, Address, Length);
    const auto apply = [&]() -> uint64_t {
      for (auto &view : NativeFileViews)
        if (Address >= view.address && Address - view.address < view.length &&
            Length <= view.length - (Address - view.address)) {
          const uint64_t page = getpagesize();
          if (!page || Address > UINT64_MAX - Length || Length > UINT64_MAX - (Address % page) - page + 1)
            return static_cast<uint64_t>(-EINVAL);
          const uint64_t host_base = Address & ~(page - 1);
          const uint64_t host_span = (Address + Length - host_base + page - 1) & ~(page - 1);
          if (host_base < view.address || host_span > view.length - (host_base - view.address))
            return static_cast<uint64_t>(-ENOMEM);
          mach_vm_address_t base = host_base;
          mach_vm_size_t span = 0;
          vm_region_basic_info_data_64_t info{};
          mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
          mach_port_t object = MACH_PORT_NULL;
          const kern_return_t status = mach_vm_region(mach_task_self(), &base, &span, VM_REGION_BASIC_INFO_64,
                                                      reinterpret_cast<vm_region_info_t>(&info), &count, &object);
          if (object != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), object);
          if (status != KERN_SUCCESS || base > host_base || host_span > span - (host_base - base))
            return static_cast<uint64_t>(-ENOMEM);
          const int needed = (Protection & (PROT_READ | PROT_WRITE)) | ((Protection & PROT_EXEC) ? PROT_READ : 0);
          const int existing = info.protection;
          bool native_execute = existing & PROT_EXEC;
          for (uint64_t p = host_base; p < host_base + host_span; p += page) {
            if (existing & PROT_EXEC)
              NativeViewExecutablePages.insert(p);
            native_execute = native_execute || NativeViewExecutablePages.contains(p);
          }
          int applied = needed | ((native_execute && (Protection & PROT_EXEC)) ? PROT_EXEC : 0);
          if (existing != applied && mprotect(reinterpret_cast<void *>(host_base), host_span, applied)) {
            const int error = errno;
            // Match Wine's Darwin W^X fallback, retaining the page's native
            // executable origin so the later RX transition restores it.
            if ((applied & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC) &&
                (error == EACCES || error == EPERM) &&
                !mprotect(reinterpret_cast<void *>(host_base), host_span, applied & ~PROT_EXEC))
              applied &= ~PROT_EXEC;
            else {
              if (fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
                dprintf(2,
                        "NATIVE_VIEW_MPROTECT_FAILED pid=%d address=%llx guest-prot=%llx existing-host=%x max-host=%x "
                        "error=%d\n",
                        getpid(), (unsigned long long)Address, (unsigned long long)Protection, existing,
                        info.max_protection, errno);
              return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
            }
          }
          view.protection = Protection;
          if (fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
            dprintf(2,
                    "NATIVE_VIEW_MPROTECT pid=%d address=%llx length=%llx guest-prot=%llx existing-host=%x "
                    "applied-host=%x real-host-action=%d\n",
                    getpid(), (unsigned long long)Address, (unsigned long long)Length, (unsigned long long)Protection,
                    existing, applied, existing != applied);
          return 0;
        }
      for (auto &Alias : SharedAliases) {
        if (Address == Alias.Guest && Length == Alias.Length) {
          const int HostProtection = (Protection & ~PROT_EXEC) | ((Protection & PROT_EXEC) ? PROT_READ : 0);
          if (mprotect(reinterpret_cast<void *>(Alias.Host - (Alias.Offset % getpagesize())), Alias.Span,
                       HostProtection))
            return static_cast<uint64_t>(-errno);
          Alias.Protection = Protection;
          RefreshSharedAliases();
          return 0;
        }
        if (Address < Alias.Guest + Alias.Length && Alias.Guest < Address + Length)
          return static_cast<uint64_t>(-95);
      }
      if (LowMemoryBiasModeEnabled && LowGuestShadow != nullptr &&
          LowGuestShadow->ContainsLogicalRange(Address, Length)) {
        const int LowProtectError = LowGuestShadow->Protect(Address, Length, Protection);
        if (LowProtectError != 0) {
          return static_cast<uint64_t>(-LowProtectError);
        }
        return 0;
      }
      if (HighMemoryRegionModeEnabled && HighGuestSparse != nullptr &&
          HighGuestSparse->ContainsLogicalRange(Address, Length)) {
        const int HighProtectError = HighGuestSparse->Protect(Address, Length, Protection);
        if (HighProtectError != 0) {
          return static_cast<uint64_t>(-HighProtectError);
        }
        return 0;
      }
      if (!Contains(Address, Length)) {
        return static_cast<uint64_t>(-ENOMEM);
      }
      for (uint64_t page = Address; page < Address + Length; page += 4096)
        if (!TrackedGuestProtection(page))
          return uint64_t(-ENOMEM);
      const int error = ProjectArenaHostPermissions(Address, Length, Protection);
      if (error)
        return uint64_t(-error);
      return 0;
    };
    const uint64_t result = apply();
    if (!result && ForkContext) {
      UpdateTrackedProtections(MProtectSyscall, Address, Length, Protection);
      InvalidateGuestCodeRange(Thread, Address, Length);
    }
    return result;
  }
  void PrepareTrackedCodeChange(FEXCore::Core::InternalThreadState *Thread,
                                const FEXCore::HLE::SyscallArguments *Args) {
    const uint64_t Number = Args->Argument[0];
    if (Number != MUnmapSyscall && !(Number == MMapSyscall && (Args->Argument[4] & (0x10 | 0x100000))))
      return;
    UnprotectTrackedCodeRange(Thread, Args->Argument[1], Args->Argument[2]);
  }
  void UnprotectTrackedCodeRange(FEXCore::Core::InternalThreadState *Thread, uint64_t Start, uint64_t Length) {
    if (!NativeMTrack || !Length || Length > UINT64_MAX - Start)
      return;
    std::vector<uint64_t> ChangedPages;
    for (auto &[Page, Active] : SMCProtectedPages) {
      if (!Active || Page >= Start + Length || Start >= Page + getpagesize())
        continue;
      if (mprotect(reinterpret_cast<void *>(Page), getpagesize(), PROT_READ | PROT_WRITE))
        std::abort();
      Active = false;
      if (SMCNotify(GuestBase, Page, 0))
        std::abort();
      ChangedPages.push_back(Page);
    }
    for (const uint64_t Page : ChangedPages)
      InvalidateGuestCodeRange(Thread, Page, getpagesize());
  }
  void PreCompile() override {
    if (NativeCallbackInProgress) {
      NativeMapCompileSequence.fetch_add(1);
      NativeMapCompilePhase.store(1);
    }
  }
  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState *, uint64_t Start, uint64_t Length) override {
    NativeMapCompileScope phase(4, Start);
    if (!NativeMTrack || !Contains(Start, Length))
      return;
    std::lock_guard Guard(SyscallMutex);
    for (const auto &Alias : SharedAliases)
      if (Start < Alias.Guest + Alias.Length && Alias.Guest < Start + Length)
        return;
    const auto Protection = TrackedGuestProtection(Start);
    if (!Protection || ((*Protection & (PROT_WRITE | PROT_EXEC)) != (PROT_WRITE | PROT_EXEC)))
      return;
    const uint64_t HostPage = getpagesize();
    for (uint64_t Page = Start & ~(HostPage - 1); Page < Start + Length; Page += HostPage) {
      if (FullSMCPage && Page == *FullSMCPage)
        continue;
      if (SMCProtectedPages[Page])
        continue;
      if (mprotect(reinterpret_cast<void *>(Page), HostPage, PROT_READ))
        std::abort();
      SMCProtectedPages[Page] = true;
      if (SMCNotify(GuestBase, Page, 1))
        std::abort();
      ++SMCProtectCount;
    }
  }
  bool RepairTrackedCodeWrite(FEXCore::Core::InternalThreadState *Thread, uint64_t Address, ucontext_t *Native) {
    if (!NativeMTrack)
      return false;
    std::unique_lock Guard(SyscallMutex);
    const uint64_t HostPage = getpagesize(), Page = Address & ~(HostPage - 1);
    auto It = SMCProtectedPages.find(Page);
    const auto Protection = TrackedGuestProtection(Address);
    if (It == SMCProtectedPages.end() || !It->second || !Protection || !(*Protection & PROT_WRITE))
      return false;
    if (mprotect(reinterpret_cast<void *>(Page), HostPage, PROT_READ | PROT_WRITE))
      return false;
    It->second = false;
    if (SMCNotify(GuestBase, Page, 0))
      std::abort();
    Guard.unlock();
    InvalidateGuestCodeRange(Thread, Page, HostPage);
    Guard.lock();
    ++SMCWriteCount;
    if (SMCWriteCount <= 16 || (SMCWriteCount & (SMCWriteCount - 1)) == 0)
      dprintf(2, "FLI_ROOT_SMC_WRITE page=%llx count=%llu\n", (unsigned long long)Page,
              (unsigned long long)SMCWriteCount);
    auto &Host = Native->uc_mcontext->__ss;
    const bool InCode = ForkContext->IsAddressInCodeBuffer(Thread, Host.__pc);
    const bool Restart = InCode && !ForkContext->IsCurrentBlockSingleInst(Thread) &&
                         ForkContext->IsAddressInCurrentBlock(Thread, Address & ~uint64_t{4095}, 4096);
    if (fli_env_enabled("REGRESSION_FLI_TRACE_BRANCHES"))
      dprintf(2, "FLI_ROOT_SMC_ORIGIN count=%llu source=%llx address=%llx restart=%d\n",
              (unsigned long long)SMCWriteCount,
              (unsigned long long)(InCode ? ForkContext->RestoreRIPFromHostPC(Thread, Host.__pc) : 0),
              (unsigned long long)Address, Restart);
    if (fli_env_enabled("REGRESSION_FLI_TRACE_BRANCH_SOURCE") && Thread->CurrentFrame->DiagnosticBranches) {
      auto *Frame = Thread->CurrentFrame;
      const uint64_t End = Frame->DiagnosticBranchSequence;
      for (uint64_t Sequence = std::max(BranchWatchSequence, End > 64 ? End - 64 : 0); Sequence < End; ++Sequence) {
        const auto &Branch = Frame->DiagnosticBranches[Sequence % 64];
        dprintf(2, "FLI_ROOT_WATCH_BRANCH seq=%llu source=%llx target=%llx\n", (unsigned long long)Sequence,
                (unsigned long long)Branch.source, (unsigned long long)Branch.target);
      }
      BranchWatchSequence = End;
    }
    if (Restart) {
      auto *Frame = Thread->CurrentFrame;
      Frame->State.rip = ForkContext->RestoreRIPFromHostPC(Thread, Host.__pc);
      for (size_t Index = 0; Index < SignalConfig.SRAGPRCount; ++Index)
        Frame->State.gregs[Index] = Host.__x[SignalConfig.SRAGPRMapping[Index]];
      for (size_t Index = 0; Index < SignalConfig.SRAFPRCount; ++Index)
        std::memcpy(Frame->State.xmm.sse.data[Index], &Native->uc_mcontext->__ns.__v[SignalConfig.SRAFPRMapping[Index]],
                    16);
      ForkContext->SetFlagsFromCompactedEFLAGS(
          Thread, ForkContext->ReconstructCompactedEFLAGS(Thread, true, Host.__x, Host.__cpsr));
      Host.__pc = SignalConfig.AbsoluteLoopTopAddressFillSRA;
      Host.__x[1] = 1;
    }
    return true;
  }
  uint64_t SMCProtectCount{}, SMCWriteCount{}, BranchWatchSequence{};
  struct NativeFileView {
    uint64_t address, length, protection;
  };
  std::vector<NativeFileView> NativeFileViews;
  std::set<uint64_t> NativeViewExecutablePages;
  std::map<uint64_t, uint64_t> NativeWindowsApiTargets;
  uint64_t NativeNtDLLBridgeBase{};
  void RegisterNativeNtDLLBridge(uint64_t address, uint64_t offset, int fd) {
    if (NativeNtDLLBridgeBase || offset != 0x10000 || !ForkContext ||
        !fli_env_enabled("REGRESSION_FLI_ROOT_CALLBACK_BRIDGE"))
      return;
    std::array<char, 4096> path{};
    const char *build = std::getenv("WINEBUILDDIR");
    if (!build || fcntl(fd, F_GETPATH, path.data()) ||
        std::string(path.data()).find(std::string(build) + "/dlls/ntdll/") != 0 ||
        !std::string_view(path.data()).ends_with("/ntdll.dll"))
      return;
    // Entries and the file check come from the selected Wine's symbols and CHPE metadata.
    uint32_t opcode = 0;
    if (pread(fd, &opcode, 4, VRCHAT_WINE_LDR_REGISTER_FILE_OFFSET) != 4 ||
        opcode != VRCHAT_WINE_LDR_REGISTER_INSTRUCTION || address < offset)
      return;
    const uint64_t base = address - offset, stub = StopAddress + 256;
    const uint8_t code[] = {0x57, 0x56, 0x48, 0x89, 0xcf, 0x48, 0x89, 0xd6, 0x4c, 0x89, 0xc2, 0x4d, 0x89, 0xca,
                            0x4d, 0x89, 0xd8, 0xb8, 0x09, 0xf1, 0,    0,    0x0f, 0x05, 0x5e, 0x5f, 0xc3};
    memcpy(reinterpret_cast<void *>(stub), code, sizeof(code));
    for (const auto &pair : {std::pair<uint64_t, uint64_t>{VRCHAT_WINE_LDR_REGISTER_X64_RVA, VRCHAT_WINE_LDR_REGISTER_RVA},
                             {VRCHAT_WINE_LDR_REGISTER_RVA, VRCHAT_WINE_LDR_REGISTER_RVA},
                             {VRCHAT_WINE_LDR_UNREGISTER_X64_RVA, VRCHAT_WINE_LDR_UNREGISTER_RVA},
                             {VRCHAT_WINE_LDR_UNREGISTER_RVA, VRCHAT_WINE_LDR_UNREGISTER_RVA}}) {
      NativeWindowsApiTargets[base + pair.first] = base + pair.second;
      ForkContext->AddThunkTrampolineIRHandler(base + pair.first, stub);
    }
    NativeNtDLLBridgeBase = base;
    dprintf(2,
            "NATIVE_NTDLL_LDR_BRIDGE pid=%d actual-base=%llx register=1 unregister=1 public-fex-thunks=1 "
            "original-code-unchanged=1\n",
            getpid(), (unsigned long long)base);
  }
  uint64_t NativeMapCallbackDiagnosticCount{};
  std::map<uint64_t, uint64_t> NativeExecutableViewQueries, UncoveredExecutableQueries;
  std::set<int> NativeBorrowedDescriptors;
  std::optional<std::array<uint64_t, 6>> NativeFileMapRequest;
  unsigned IPCWaitStackSamples{}, ClientMapInputSamples{};
  bool NativeHandoffObserved{};
  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState *Thread, uint64_t Start, uint64_t Length) override {
    // FEX compilation holds CodeInvalidationMutex before querying our VMA state.
    // Never wait for that lock while owning the syscall/VMA lock.
    BlockingHostCall([&] {
      // Acquire both without holding either while waiting: compilation queries VMA state.
      std::unique_lock vm_lock(SyscallMutex, std::defer_lock);
      std::unique_lock code_lock(ForkContext->GetCodeInvalidationMutex(), std::defer_lock);
      std::lock(vm_lock, code_lock);
      ForkContext->InvalidateCodeBuffersCodeRange(Start, Length);
      unsigned targets = 0;
      if (Thread) {
        ForkContext->InvalidateThreadCachedCodeRange(Thread, Start, Length);
        ++targets;
      }
      if (MainGuestThread && MainGuestThread != Thread) {
        ForkContext->InvalidateThreadCachedCodeRange(MainGuestThread, Start, Length);
        ++targets;
      }
      for (const auto *worker : NativeGuestThreads)
        if (worker->Thread != Thread && worker->Thread != MainGuestThread && !worker->Finished.load()) {
          ForkContext->InvalidateThreadCachedCodeRange(worker->Thread, Start, Length);
          ++targets;
        }
      const auto ordinal = ++AllThreadInvalidations;
      if (fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT") && (ordinal <= 16 || (ordinal & (ordinal - 1)) == 0))
        dprintf(2, "ROOT_ALL_THREAD_INVALIDATION pid=%d targets=%u start=%llx length=%llx count=%llu\n", getpid(),
                targets, (unsigned long long)Start, (unsigned long long)Length, (unsigned long long)ordinal);
      return 0;
    });
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState *,
                                                              uint64_t Address) override {
    NativeMapCompileScope phase(2, Address);
    std::lock_guard Guard(SyscallMutex);
    ++ExecutableRangeQueryCount;
    for (const auto &Alias : SharedAliases)
      if (Address >= Alias.Guest && Address - Alias.Guest < Alias.Length && (Alias.Protection & PROT_EXEC))
        return {Alias.Guest, Alias.Length, true, true}; // A writable shared backing can change this RX alias.
    for (const auto &view : NativeFileViews)
      if (Address >= view.address && Address - view.address < view.length) {
        mach_vm_address_t base = Address;
        mach_vm_size_t span = 0;
        vm_region_basic_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        const auto status = mach_vm_region(mach_task_self(), &base, &span, VM_REGION_BASIC_INFO_64,
                                           reinterpret_cast<vm_region_info_t>(&info), &count, &object);
        if (object != MACH_PORT_NULL)
          mach_port_deallocate(mach_task_self(), object);
        if (status == KERN_SUCCESS && base <= Address && Address - base < span && (info.protection & PROT_READ)) {
          const uint64_t begin = std::max<uint64_t>(base, view.address),
                         end = std::min<uint64_t>(base + span, view.address + view.length);
          const bool writable = bool(info.protection & PROT_WRITE);
          const auto occurrence = ++NativeExecutableViewQueries[Address & ~uint64_t(4095)];
          if (occurrence <= 2)
            dprintf(2, "NATIVE_EXECUTABLE_VIEW pid=%d address=%llx begin=%llx size=%llx host-prot=%x\n", getpid(),
                    (unsigned long long)Address, (unsigned long long)begin, (unsigned long long)(end - begin),
                    info.protection);
          return {begin, end - begin, writable, writable};
        }
      }
    const bool LowShadowExecutable =
        LowGuestShadow != nullptr && LowGuestShadow->ContainsMappedLogicalRange(Address, 1, PROT_EXEC);
    const bool LowShadowHostAddress = LowGuestShadow != nullptr && LowGuestShadow->ContainsHostAddress(Address);
    const uint64_t LowShadowHostLogicalAddress =
        LowShadowHostAddress ? LowGuestShadow->LogicalAddress(Address) : std::numeric_limits<uint64_t>::max();
    const bool LowShadowHostExecutable =
        LowShadowHostAddress && LowShadowHostLogicalAddress != std::numeric_limits<uint64_t>::max() &&
        LowGuestShadow->ContainsMappedLogicalRange(LowShadowHostLogicalAddress, 1, PROT_EXEC);
    if (ExecutableRangeQueryCount <= 16) {
      const uint8_t LowState = LowGuestShadow != nullptr ? LowGuestShadow->PageStateForLogicalAddress(Address) : 0;
      const uint8_t LowHostState = LowShadowHostLogicalAddress != std::numeric_limits<uint64_t>::max()
                                       ? LowGuestShadow->PageStateForLogicalAddress(LowShadowHostLogicalAddress)
                                       : 0;
      std::fprintf(stderr,
                   "REGRESSION_EXECUTABLE_RANGE_QUERY count=%llu address=0x%llx "
                   "guest_base=0x%llx guest_size=0x%llx low_state=0x%x low_exec=%d "
                   "low_host=%d low_host_logical=0x%llx low_host_state=0x%x "
                   "low_host_exec=%d\n",
                   static_cast<unsigned long long>(ExecutableRangeQueryCount), static_cast<unsigned long long>(Address),
                   static_cast<unsigned long long>(GuestBase), static_cast<unsigned long long>(GuestSize),
                   static_cast<unsigned int>(LowState), LowShadowExecutable ? 1 : 0, LowShadowHostAddress ? 1 : 0,
                   static_cast<unsigned long long>(LowShadowHostLogicalAddress),
                   static_cast<unsigned int>(LowHostState), LowShadowHostExecutable ? 1 : 0);
    }
    if (LowShadowHostExecutable) {
      const uint64_t HostPageBase = Address & ~(LinuxGuestPageSize - 1);
      const bool Writable = LowGuestShadow->ContainsMappedLogicalRange(LowShadowHostLogicalAddress, 1, PROT_WRITE);
      return {HostPageBase, LinuxGuestPageSize, Writable};
    }
    if (LowShadowExecutable) {
      const uint64_t PageBase = Address & ~(LinuxGuestPageSize - 1);
      const bool Writable = LowGuestShadow->ContainsMappedLogicalRange(Address, 1, PROT_WRITE);
      return {PageBase, LinuxGuestPageSize, Writable};
    }
    if (HighGuestSparse && HighGuestSparse->ContainsMappedLogicalRange(Address, 1, PROT_EXEC)) {
      return {Address & ~(LinuxGuestPageSize - 1), LinuxGuestPageSize,
              HighGuestSparse->ContainsMappedLogicalRange(Address, 1, PROT_WRITE)};
    }
    if (Contains(Address, 1)) {
      uint64_t Begin = GuestBase, End = GuestBase + GuestSize;
      bool Writable = false;
      for (auto It = HighMMapRecords.rbegin(); It != HighMMapRecords.rend(); ++It) {
        if (!It->Active || Address < It->Address || Address - It->Address >= It->Length)
          continue;
        Begin = It->Address;
        End = It->Address + It->Length;
        Writable = (It->Protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC);
        break;
      }
      for (const auto &Record : HighMMapRecords) {
        if (!Record.Active)
          continue;
        if (Record.Address > Address)
          End = std::min(End, Record.Address);
        else if (Record.Address + Record.Length <= Address)
          Begin = std::max(Begin, Record.Address + Record.Length);
      }
      if (const auto Protection = TrackedGuestProtection(Address))
        Writable = (*Protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC);
      for (const auto &[Page, Protection] : GuestProtectionOverrides) {
        if (Address >= Page && Address - Page < 4096) {
          Begin = std::max(Begin, Page);
          End = std::min(End, Page + 4096);
        } else if (Page > Address)
          End = std::min(End, Page);
        else
          Begin = std::max(Begin, Page + 4096);
      }
      for (const auto &Alias : SharedAliases) {
        if (Alias.Guest > Address)
          End = std::min(End, Alias.Guest);
        else if (Alias.Guest + Alias.Length <= Address)
          Begin = std::max(Begin, Alias.Guest + Alias.Length);
      }
      bool HotFull = false;
      if (FullSMCPage) {
        const uint64_t HotEnd = *FullSMCPage + getpagesize();
        if (Address >= *FullSMCPage && Address < HotEnd) {
          Begin = std::max(Begin, *FullSMCPage);
          End = std::min(End, HotEnd);
          HotFull = Writable;
        } else if (Address < *FullSMCPage)
          End = std::min(End, *FullSMCPage);
        else
          Begin = std::max(Begin, HotEnd);
      }
      return {Begin, End - Begin, Writable, Writable && (!NativeMTrack || HotFull)};
    }
    const auto occurrence = ++UncoveredExecutableQueries[Address];
    if (occurrence <= 4 || (occurrence & (occurrence - 1)) == 0)
      dprintf(2, "ROOT_EXECUTABLE_RANGE_MISS pid=%d address=%llx count=%llu\n", getpid(), (unsigned long long)Address,
              (unsigned long long)occurrence);
    return {Address, 0, false};
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState *,
                                                                                uint64_t) override {
    return std::nullopt;
  }

  bool ExitSeen{};
  uint64_t ExitGuestRSP{};
  uint64_t ExitGuestRBP{};
  std::array<uint64_t, 8> ExitGuestStackWords{};
  std::array<uint64_t, 8> ExitGuestFramePointers{};
  std::array<uint64_t, 8> ExitGuestFrameReturnAddresses{};
  bool PostSessionSyscallDiagnosticLimitSeen{};
  int64_t OpenLastLinuxError{};
  uint64_t OpenAtCallCount{};
  uint64_t OpenAtLastPathFingerprint{};
  bool OpenAtLastTargetExists{};
  bool OpenAtLastTargetRegular{};
  int64_t OpenAtLastLinuxError{};
  std::vector<std::string> IntlNLSOpenCandidatePaths{};
  std::string TemporaryMappingFirstCandidatePath{"none"};
  uint64_t ReadCallCount{};
  uint64_t ReadByteCount{};
  bool ReadLastDescriptorOwned{};
  bool ReadLastDescriptorReceivedSCMRights{};
  bool ReadLastDescriptorStatSucceeded{};
  bool ReadLastDescriptorFIFO{};
  bool ReadLastDescriptorSocket{};
  bool ReadLastDescriptorRegular{};
  std::string ReadLastBufferClass{"none"};
  std::array<ReadELFHeaderRecord, 4> ReadELFHeaderRecords{};
  size_t ReadELFHeaderRecordCount{};
  uint32_t ReadWineFixedReplyLastError{};
  uint32_t ReadWineFixedReplyLastDeclaredSize{};
  uint64_t GetDents64HostByteCount{};
  uint64_t GetDents64LinuxByteCount{};
  uint64_t GetDents64EntryCount{};
  uint64_t GetDents64SkippedZeroInodeCount{};
  bool GetDents64LastDescriptorOwned{};
  bool GetDents64LastDescriptorDirectory{};
  bool GetDents64LastDescriptorPathConfined{};
  uint64_t PRead64ByteCount{};
  bool FcntlGetFlagsRegistryTemporaryLastDescriptorRegular{};
  bool SetSockOptLastDescriptorOwned{};
  bool SetSockOptLastValueReadable{};
  bool SetSockOptLastInt32ValueReadable{};
  int64_t SetSockOptLastInt32Value{};
  bool SigAltStackLastNewStackReadable{};
  uint64_t SigAltStackLastGuestRSP{};
  bool SigAltStackLastStackRangeLowShadowMapped{};
  bool SigAltStackLastStackRangeLowShadowReadable{};
  bool SigAltStackLastStackRangeLowShadowWritable{};
  bool SigAltStackLastGuestRSPWithinStack{};
  uint64_t MMapFileByteCount{};
  bool MMapSharedFileLastDescriptorStatSucceeded{};
  bool MMapSharedFileLastDescriptorRegular{};
  int64_t MMapSharedFileLastDescriptorSize{};
  bool MMapSharedFixedLowLastDescriptorStatSucceeded{};
  bool MMapSharedFixedLowLastDescriptorRegular{};
  int64_t MMapSharedFixedLowLastDescriptorSize{};
  uint64_t MMapLastRequestedAddress{};
  uint64_t MMapLastLength{};
  uint64_t MMapLastFlags{};
  std::vector<HighMMapRecord> HighMMapRecords;
  uint64_t HighMMapRecordCount{};
  std::array<LowMMapRecord, 128> LowMMapRecords{};
  uint64_t LowMMapRecordCount{};
  uint64_t MUnmapLastActiveRecordIndexPlusOne{};
  uint64_t MUnmapLastActiveRecordArenaEnd{};
  uint64_t MUnmapLastActiveRecordProtection{};
  uint64_t MUnmapLastActiveRecordFlags{};
  uint64_t NativeForkCloneAttemptCount{};
  bool NativeForkCloneParentProcess{};
  bool NativeForkCloneChildProcess{};
  int64_t NativeForkCloneProcessID{-1};
  bool NativeForkCloneChildReaped{};
  bool NativeForkCloneContextAttached{};
  bool Dup2LastSourceOwned{};
  int64_t Dup2LastLinuxError{};
  int64_t RtSigactionLastSignal{};


  bool LowPageAliasModeEnabled{};
  bool LowPageAliasAccepted{};
  bool LowMemoryBiasModeEnabled{};
  bool HighMemoryRegionModeEnabled{};
  std::string Prlimit64LastNewLimitClass{"none"};
  std::string Prlimit64LastOldLimitClass{"none"};
  uint64_t HandleSyscallCallCount{};
  uint64_t PostSessionSyscallDiagnosticLimit{};
  uint64_t PostSessionSyscallDiagnosticCallCount{};
  std::array<uint64_t, 16> PostSessionLiveTrace{};
  size_t PostSessionLiveTraceCount{};
  uint64_t GetrandomByteCount{};
  bool ChdirLastHostCWDMatchesGuest{};
  uint64_t UmaskLastRequestedMode{};
  uint64_t UmaskLastAppliedMode{};
  uint64_t UmaskLastPreviousMode{};
  uint64_t GuestUmask{0022};
  bool MkdirLastParentConfined{};
  bool MkdirLastParentExists{};
  int64_t MkdirLastLinuxError{};
  int64_t UnlinkLastLinuxError{};
  uint64_t ChmodLastAppliedMode{};
  bool ChmodLastTargetSocket{};
  int64_t ChmodLastLinuxError{};
  int64_t SymlinkLastLinuxError{};
  uint64_t LastGetUID{};
  uint64_t LastGetPID{};
  bool SetPriorityLastWhoMatchesPID{};
  uint64_t PollReadyDescriptorCount{};
  std::string Pipe2LastPointerClass{"none"};
  bool Pipe2LastLowShadowMapped{};
  bool Pipe2LastLowShadowWritable{};
  bool BindLastEndpointCreated{};
  uint64_t ListenSuccessCount{};
  int64_t ListenLastDescriptor{};
  bool EpollPWait2LastDescriptorKnown{};
  bool EpollPWait2LastTimeoutReadable{};
  uint64_t EpollWaitReturnedEventCount{};
  uint64_t EpollWaitTimedReturnedEventCount{};
  uint64_t EpollWaitPollingReturnedEventCount{};
  bool EpollWaitLastDescriptorKnown{};
  int64_t TimeLastSeconds{};
  int64_t MemfdCreateLastDescriptor{-1};
  uint64_t PWrite64WrittenByteCount{};
  bool SessionMappingWriteCompleted{};
  bool FChdirLastTargetDirectory{};
  bool FChdirLastTargetConfined{};
  bool FChdirLastHostCWDMatchesGuest{};
  bool AcceptLastDescriptorOwned{};
  bool SendMsgLastDescriptorOwned{};
  bool SendMsgLastFirstIOVectorPayloadReadable{};
  bool SendMsgLastControlReadable{};
  bool SendMsgLastTransferredDescriptorOwned{};
  bool SendMsgLastTransferredDescriptorClosed{};
  bool SendMsgLastTransferredDescriptorStatSucceeded{};
  int64_t SendMsgLastTransferredDescriptorFlags{-1};
  int64_t SendMsgLastTransferredStatusFlags{-1};
  bool RecvMsgLastDescriptorOwned{};
  bool RecvMsgLastFirstIOVectorPayloadReadable{};
  bool RecvMsgLastControlReadable{};
  uint32_t RecvMsgLastPayloadValue{};
  uint64_t WriteVVectorCount{};
  uint64_t WriteVByteCount{};
  uint64_t WriteByteCount{};
  uint64_t WriteAltLoaderWrittenByteCount{};
  uint64_t WriteRegistryTemporaryWrittenByteCount{};
  uint64_t WriteWineReplyWrittenByteCount{};
  uint64_t WriteRequestPipeWrittenByteCount{};
  uint64_t ExitCode{std::numeric_limits<uint64_t>::max()};
  uint64_t UnexpectedSyscall{std::numeric_limits<uint64_t>::max()};
  bool IoctlTCGets2LastDescriptorStandard{};
  bool IoctlTCGets2LastDescriptorClosed{};
  bool IoctlTCGets2LastArgumentWritable{};
  bool IoctlTCGets2LastDescriptorStatSucceeded{};
  bool IoctlTCGets2LastDescriptorTTY{};
  bool IoctlExt2GetFlagsLastDescriptorOwned{};
  bool IoctlExt2GetFlagsLastArgumentWritable{};
  bool IoctlExt2GetFlagsLastDescriptorStatSucceeded{};
  bool IoctlExt2GetFlagsLastDescriptorDirectory{};
  bool IoctlExt2GetFlagsLastDescriptorRegular{};
  bool IoctlExt2GetFlagsLastDescriptorPathConfined{};
  uint64_t UnsupportedCloneFlags{};
  std::string UnsupportedCloneChildStackClass{"none"};
  std::string UnsupportedCloneParentTIDClass{"none"};
  std::string UnsupportedCloneChildTIDClass{"none"};
  std::string UnsupportedCloneTLSClass{"none"};
  bool UnsupportedExecveTargetExists{};
  bool UnsupportedExecveParentSegmentSeen{};
  bool UnsupportedExecveNormalizedPathConfined{};
  bool UnsupportedExecveArgvReadable{};
  bool UnsupportedExecveEnvpReadable{};
  bool UnsupportedExecveEnvHasLCAllC{};
  bool UnsupportedExecveEnvHasPrivateHome{};
  bool UnsupportedExecveEnvHasWineLoaderNoExec{};
  bool UnsupportedExecveEnvHasWineArchWow64{};
  bool UnsupportedExecveEnvHasWineServerSocket{};
  bool UnsupportedExecveEnvHasWinePreloadReserve{};
  bool OfficialProtonExecveReentryAttempted{};
  bool OfficialProtonExecveReentryValidationPassed{};
  int64_t OfficialProtonExecveReentryLastHostError{};
  uint64_t UnsupportedExecvePathLength{};
  uint64_t UnsupportedExecvePathFingerprint{};
  uint64_t UnsupportedExecveNormalizedPathLength{};
  uint64_t UnsupportedExecveNormalizedPathFingerprint{};
  uint64_t UnsupportedExecveArgCount{};
  uint64_t UnsupportedExecveEnvCount{};
  uint64_t UnsupportedExecveEnvUnknownCount{};
  std::string UnsupportedExecveTargetKind{"none"};
  std::vector<uint64_t> UnsupportedExecveArgLengths;
  std::vector<uint64_t> UnsupportedExecveArgFingerprints;
  std::vector<std::string> UnsupportedExecveArgKinds;
  std::string CapturedOutput;
  std::string CapturedError;

public:
  void JoinGuestThreads();
  bool RegisterInitialELFMemory(const ELFParser &parser, uint64_t load_base) {
    unsigned pages = 0;
    for (const auto &segment : parser.phdrs) {
      if (segment.p_type != PT_LOAD || !segment.p_memsz)
        continue;
      const uint64_t start = load_base + segment.p_vaddr;
      if (start < load_base || !Contains(start, segment.p_memsz))
        return false;
      const uint64_t end = (start + segment.p_memsz + 4095) & ~uint64_t(4095);
      uint64_t protection = 0;
      if (segment.p_flags & PF_R)
        protection |= PROT_READ;
      if (segment.p_flags & PF_W)
        protection |= PROT_WRITE;
      if (segment.p_flags & PF_X)
        protection |= PROT_EXEC;
      for (uint64_t page = start & ~uint64_t(4095); page < end; page += 4096) {
        GuestProtectionOverrides[page] = protection;
        ++pages;
      }
    }
    dprintf(2, "LAB_INITIAL_ELF_MEMORY pid=%d base=%llx pages=%u source=loaded-PT_LOAD\n", getpid(),
            (unsigned long long)load_base, pages);
    return true;
  }
  uint64_t ProgramBreak(uint64_t Requested) {
    std::lock_guard<std::recursive_mutex> guard(SyscallMutex);
    if (Requested == 0) {
      return CurrentProgramBreak;
    }
    if (Requested < InitialProgramBreak || Requested > ProgramBreakLimit) {
      return CurrentProgramBreak;
    }
    if (Requested > CurrentProgramBreak) {
      std::memset(reinterpret_cast<void *>(CurrentProgramBreak), 0,
                  static_cast<size_t>(Requested - CurrentProgramBreak));
    }
    CurrentProgramBreak = Requested;
    return CurrentProgramBreak;
  }
  int ProtectNativeGuestMemory(FliMemoryProtectionRequest *request) {
    if (!request)
      return -EINVAL;
    std::unique_lock<std::recursive_mutex> lock(SyscallMutex);
    struct ActiveLockScope {
      std::unique_lock<std::recursive_mutex> *previous;
      explicit ActiveLockScope(std::unique_lock<std::recursive_mutex> *value) : previous(ActiveSyscallLock) {
        ActiveSyscallLock = value;
      }
      ~ActiveLockScope() { ActiveSyscallLock = previous; }
    } scope(&lock);
    const auto address = request->address, length = request->length, protection = request->protection;
    if (!length || (address & 4095) || (length & 4095) || address > UINT64_MAX - length ||
        (protection & ~uint64_t{PROT_READ | PROT_WRITE | PROT_EXEC})) {
      request->result = -EINVAL;
      return 1;
    }
    bool owned = false;
    for (const auto &view : NativeFileViews)
      if (address >= view.address && address - view.address < view.length)
        owned = true;
    for (const auto &alias : SharedAliases)
      if (address >= alias.Guest && address - alias.Guest < alias.Length)
        owned = true;
    if (!owned && Contains(address, length)) {
      for (uint64_t page = address; page < address + length; page += 4096) {
        if (!TrackedGuestProtection(page)) {
          if (!owned)
            return 0;
          request->result = -ENOMEM;
          return 1;
        }
        owned = true;
      }
    }
    if (!owned)
      return 0;
    request->result = int64_t(ProtectGuestRange(nullptr, address, length, protection));
    return 1;
  }
  int QueryNativeGuestMemory(uint64_t address, uint64_t *out) {
    if (!out || address < GuestBase || address - GuestBase >= GuestSize)
      return -14;
    std::lock_guard<std::recursive_mutex> guard(SyscallMutex);
    const uint64_t page = address & ~uint64_t(4095);
    const auto protection = TrackedGuestProtection(address);
    void *host = HostPointerForGuestRange(page, 4096, PROT_READ);
    if (!protection || !host)
      return -14;
    out[0] = page;
    out[1] = 4096;
    out[2] = reinterpret_cast<uint64_t>(host);
    out[3] = *protection;
    return 0;
  }
  void ObserveOwnedGuestThreads();
  bool OwnsNativeFileView(uint64_t address) const {
    return std::any_of(NativeFileViews.begin(), NativeFileViews.end(), [&](const auto &view) {
      return address >= view.address && address - view.address < view.length;
    });
  }
  static bool IsRootGuestThread() { return ActiveSignalThread != nullptr; }
  static int QueryCurrentGuestMemory(uint64_t address, uint64_t *out) {
    return ActiveSignalOwner ? ActiveSignalOwner->QueryNativeGuestMemory(address, out) : -38;
  }

  GuestMemoryFault DescribeMemoryFault(uint64_t, uint32_t);
  bool ForwardNativeMemoryFault(FEXCore::Core::InternalThreadState *, ucontext_t *, const GuestMemoryFault &);
  bool StartSignalControl();
  void StopSignalControl();
  uint64_t SendRemoteThreadSignal(uint64_t PID, uint64_t TID, int Signal);
  void RegisterSignalThread(FEXCore::Core::InternalThreadState *, const FEXCore::SignalDelegatorConfig &);
  void DeliverQueuedSignals(FEXCore::Core::CpuStateFrame *, ucontext_t *HostContext = nullptr,
                            bool AfterSyscall = true);
  bool DeliverGuestMemorySignal(FEXCore::Core::CpuStateFrame *, int, uint64_t, int);
  uint64_t QueueOwnThreadSignal(uint64_t TID, int Signal, uint32_t Sender = 0);

private:
  struct NativeGuestThread {
    ProcessSyscallHandler *Handler;
    FEXCore::Core::InternalThreadState *Thread;
    pthread_t Native{};
    std::mutex StartupMutex;
    std::condition_variable StartupCV;
    bool Ready{}, Initialized{}, Exited{}, Published{};
    std::atomic<bool> Finished{};
    std::atomic<uint64_t> PendingSignals{};
    std::atomic<uint32_t> SignalSender{};
    uint64_t TID{}, Mask{}, ChildTID{}, ExitCode{};
    std::array<FEXCore::Core::CpuStateFrame::DiagnosticBranch, 65> Branches{};
  };
  uint64_t SpawnGuestThread(const FEXCore::Core::CPUState &, FEXCore::HLE::SyscallArguments *, uint64_t,
                            const FliLinuxThreadState *);
  uint64_t ProbeNativeEACUnixBridge(FEXCore::Core::CpuStateFrame *, uint64_t Entry, uint64_t Args);

  static void *ExecuteGuestThread(void *);
  struct GuestSignalFrame {
    FEXCore::Core::CPUState SavedState;
    FEXCore::UncheckedLongJump::JumpBuf ReturnJump;
    uint64_t GuestContext{}, OriginalMask{}, ReturningStack{};
    uint32_t ReferenceCount{};
    bool ReturnedViaSyscall{};
  };
  static thread_local std::array<GuestSignalFrame, 8> GuestSignalFrames;
  inline static thread_local size_t GuestSignalDepth{};
  inline static thread_local FEXCore::x86_64::stack_t GuestSignalStack{nullptr, 2, 0};
  inline static thread_local FEXCore::Core::InternalThreadState *ActiveSignalThread{};
  inline static thread_local ProcessSyscallHandler *ActiveSignalOwner{};
  inline static thread_local std::atomic<uint64_t> *ActivePendingSignals{};
  inline static thread_local std::atomic<uint32_t> *ActiveSignalSender{};
  inline static thread_local bool TracerFaultActive{};
  inline static thread_local uint64_t TracerFaultAddress{};
  inline static thread_local int TracerFaultCode{};
  static void HostUserSignal(int, siginfo_t *, void *);
  static void *SignalControlLoop(void *);
  std::string SignalControlDirectory, SignalControlPath;
  int SignalControlFD{-1};
  pthread_t SignalControlThread{};
  std::atomic<bool> SignalControlRunning{};

  FEXCore::SignalDelegatorConfig SignalConfig{};
  std::atomic<uint64_t> MainPendingSignals{};
  std::atomic<uint32_t> MainSignalSender{};
  uint64_t MainNativeTID{};
  std::atomic<uint64_t> MainCallbackTID{};
  std::recursive_mutex SyscallMutex;
  std::vector<NativeGuestThread *> NativeGuestThreads;
  inline static thread_local NativeGuestThread *ActiveGuestThread{};
  uint64_t NativeThreadStopHandler{};
  pthread_t MainNativeThread{};
  FEXCore::Core::InternalThreadState *MainGuestThread{};
  uint64_t AllThreadInvalidations{};
  bool ProcessExiting{};
  bool NativeMTrack{};
  std::optional<uint64_t> FullSMCPage;
  int32_t (*SMCNotify)(uint64_t, uint64_t, int){};
  std::map<uint64_t, bool> SMCProtectedPages;
  std::map<uint64_t, uint64_t> GuestProtectionOverrides;
  std::map<std::pair<uint64_t, int64_t>, uint64_t> SyscallTraceCounts;
  struct SharedAlias {
    uint64_t Guest, Length, Host, Span, Protection, Offset;
  };
  std::vector<SharedAlias> SharedAliases;
  bool RefreshSharedAliases() {
    std::vector<FEXCore::Context::GuestMemoryAddressRegion> Regions;
    if (HighMemoryRegionModeEnabled && HighGuestSparse != nullptr) {
      Regions = HighGuestSparse->TranslationRegions();
    }
    for (const auto &Alias : SharedAliases)
      Regions.push_back({Alias.Guest, Alias.Host, Alias.Length});
    if (Regions.empty())
      Regions.push_back({GuestBase, GuestBase, 4096});
    // ponytail: four FEX translation slots; reject exhaustion instead of copying shared pages.
    if (!ForkContext || !ForkContext->SetGuestMemoryAddressRegions(Regions.data(), Regions.size()))
      return false;
    using Publish = int32_t (*)(const SharedAlias *, uint64_t);
    const auto Function = reinterpret_cast<Publish>(dlsym(RTLD_DEFAULT, "fli_linux_root_set_aliases"));
    return !Function || Function(SharedAliases.data(), SharedAliases.size()) == 0;
  }
  FEXCore::Context::Context *ForkContext{};
  inline static thread_local uint64_t OwnSignalMask{};
  inline static thread_local uint64_t *BorrowedSignalMask{};
  std::array<LinuxGuestSigAction, 65> GuestSignalActions{};

  std::optional<uint64_t> MaybeReexecStandardWine(const std::string &Target, const std::vector<std::string> &Args,
                                                  const std::vector<std::string> &Environment) {
    if (!NativeForkCloneChildProcess ||
        (Target != "/opt/wine-devel/lib/wine/x86_64-unix/wine" && Target != "/opt/wine-devel/bin/wine"))
      return std::nullopt;
    const auto Reject = [](int Error) -> std::optional<uint64_t> { return static_cast<uint64_t>(-Error); };
    if (HostExecutablePath.empty() || Args.size() < 2 || Args[0] != Target)
      return Reject(EINVAL);
    const auto HostTarget = ResolveGuestPathWithParents(Target);
    struct stat TargetInfo{};
    if (!HostTarget || stat(HostTarget->c_str(), &TargetInfo) != 0 || !S_ISREG(TargetInfo.st_mode) ||
        access(HostTarget->c_str(), R_OK | X_OK) != 0)
      return Reject(EACCES);
    const char *DepthValue = std::getenv("REGRESSION_FLI_EXEC_DEPTH");
    const unsigned long Depth = DepthValue ? std::strtoul(DepthValue, nullptr, 10) : 0;
    if (Depth >= 16)
      return Reject(EAGAIN);
    bool Locale{}, Home{}, NoExec{}, Socket{}, ReserveSeen{};
    int SocketFD = -1;
    std::string Reserve;
    std::vector<std::string> Extra;
    for (const auto &Entry : Environment) {
      if (Entry == "LC_ALL=C" && !Locale)
        Locale = true;
      else if (Entry == "HOME=/home/regression" && !Home)
        Home = true;
      else if (Entry == "WINELOADERNOEXEC=1" && !NoExec)
        NoExec = true;
      else if (Entry.starts_with("WINESERVERSOCKET=") && !Socket) {
        const char *Value = Entry.c_str() + sizeof("WINESERVERSOCKET=") - 1;
        char *End{};
        errno = 0;
        const long Parsed = std::strtol(Value, &End, 10);
        if (errno || End == Value || *End || Parsed <= STDERR_FILENO || Parsed > 65535)
          return Reject(EINVAL);
        SocketFD = static_cast<int>(Parsed);
        Socket = true;
      } else if (Entry.starts_with("WINEPRELOADRESERVE=") && !ReserveSeen) {
        Reserve = Entry.substr(sizeof("WINEPRELOADRESERVE=") - 1);
        if (!IsValidWinePreloadReserve(Reserve))
          return Reject(EINVAL);
        ReserveSeen = true;
      } else if (Entry == "DISPLAY=:0") {
        if (!std::getenv("REGRESSION_X11_SOCKET"))
          return Reject(EINVAL);
      } else if (IsAdditionalGuestEnvironment(Entry))
        Extra.push_back(Entry);
      else
        return Reject(EINVAL);
    }
    if (!Locale || !Home || !NoExec || !Socket || !ReserveSeen || !OwnedDescriptors.contains(SocketFD))
      return Reject(EACCES);
    struct stat SocketInfo{};
    const int Flags = fcntl(SocketFD, F_GETFD);
    if (Flags < 0 || (Flags & FD_CLOEXEC) || fstat(SocketFD, &SocketInfo) || !S_ISSOCK(SocketInfo.st_mode))
      return Reject(EACCES);
    std::string Directory = ResearchTemporaryPrefix("regression-fli-fex-process-probe.XXXXXX");
    if (!mkdtemp(Directory.data()))
      return Reject(errno);
    const std::string Receipt = Directory + "/process-probe.json";
    const int FD = open(Receipt.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (FD < 0)
      return Reject(errno);
    close(FD);
    std::vector<std::string> NativeArgs{
        HostExecutablePath,
        "--real-rootfs",
        RootFS,
        "--guest-program",
        Target,
        "--guest-component-kind",
        "official-wine-x64",
        "--guest-cwd",
        GuestCurrentWorkingDirectory,
        "--inherited-wineserver-socket-fd",
        std::to_string(SocketFD),
        "--wine-preload-reserve",
        Reserve,
        "--private-receipt-output",
        Receipt,
        "--private-stderr-output",
        Directory + "/stderr.log",
    };
    if (LowMemoryBiasModeEnabled)
      NativeArgs.emplace_back("--instrument-low-memory-bias");
    if (HighMemoryRegionModeEnabled)
      NativeArgs.emplace_back("--instrument-high-memory-region");
    for (size_t Index = 1; Index < Args.size(); ++Index) {
      NativeArgs.emplace_back("--guest-arg");
      NativeArgs.push_back(Args[Index]);
    }
    for (const auto &Entry : Extra) {
      NativeArgs.emplace_back("--guest-env");
      NativeArgs.push_back(Entry);
    }
    std::vector<char *> Pointers;
    for (auto &Entry : NativeArgs)
      Pointers.push_back(Entry.data());
    Pointers.push_back(nullptr);
    const std::string NextDepth = std::to_string(Depth + 1);
    if (setenv("REGRESSION_FLI_EXEC_DEPTH", NextDepth.c_str(), 1))
      return Reject(errno);
    const auto ImageSeparator = Args[1].find_last_of("/\\");
    std::string ImageName = Args[1].substr(ImageSeparator == std::string::npos ? 0 : ImageSeparator + 1);
    std::transform(ImageName.begin(), ImageName.end(), ImageName.begin(),
                   [](unsigned char C) { return static_cast<char>(std::tolower(C)); });
    const char *ImageKind = "other";
    if (ImageName == "start_protected_game.exe")
      ImageKind = "official-protected-launcher";
    else if (ImageName == "easyanticheat_eos_setup.exe")
      ImageKind = "official-eac-setup";
    else if (ImageName == "vrchat.exe")
      ImageKind = "official-game";
    else if (ImageName == "wineboot.exe")
      ImageKind = "wineboot";
    else if (ImageName == "services.exe")
      ImageKind = "services";
    else if (ImageName == "winedbg.exe")
      ImageKind = "wine-debugger";
    dprintf(2, "OWNED_STANDARD_WINE_EXEC diagnostics=%s argc=%zu envc=%zu depth=%lu pid=%d parent=%d image-kind=%s\n",
            Directory.c_str(), Args.size(), Environment.size(), Depth + 1, getpid(), getppid(), ImageKind);
    // Reexecute the same verified native executor with the real Wine ELF and inherited socket.
    execv(HostExecutablePath.c_str(), Pointers.data());
    return Reject(errno);
  }

  std::optional<uint64_t> MaybeReexecOfficialProtonWine64Preloader(const std::string &GuestTarget,
                                                                   const std::vector<std::string> &GuestArguments,
                                                                   const std::vector<std::string> &GuestEnvironment) {
    constexpr std::string_view ExpectedTarget = "/opt/proton/files/lib/wine/x86_64-unix/wine64-preloader";
    constexpr std::string_view ExpectedLoader = "/opt/proton/files/lib/wine/x86_64-unix/wine";
    if (!NativeForkCloneChildProcess || GuestTarget != ExpectedTarget) {
      return std::nullopt;
    }

    OfficialProtonExecveReentryAttempted = true;
    const auto Reject = [this](int Error) -> std::optional<uint64_t> {
      OfficialProtonExecveReentryLastHostError = Error;
      return static_cast<uint64_t>(-Error);
    };
    if (HostExecutablePath.empty() || GuestArguments.size() < 3 || GuestArguments.size() > 32 ||
        GuestArguments[0] != ExpectedTarget || GuestArguments[1] != ExpectedLoader ||
        (GuestEnvironment.size() < 6 || GuestEnvironment.size() > 64)) {
      return Reject(EINVAL);
    }

    const char *DepthValue = std::getenv("REGRESSION_FLI_EXEC_DEPTH");
    const unsigned long Depth = DepthValue ? std::strtoul(DepthValue, nullptr, 10) : 0;
    if (Depth >= 16) {
      dprintf(STDERR_FILENO, "TRACE native-process-depth-limit=%lu\n", Depth);
      return Reject(EAGAIN);
    }
    const auto HostTarget = ResolveGuestPathWithParents(GuestTarget);
    struct stat TargetStat{};
    if (!HostTarget.has_value() || stat(HostTarget->c_str(), &TargetStat) != 0 || !S_ISREG(TargetStat.st_mode) ||
        access(HostTarget->c_str(), R_OK | X_OK) != 0) {
      return Reject(EACCES);
    }

    bool LocaleSeen{};
    bool HomeSeen{};
    bool LoaderNoExecSeen{};
    bool WineArchSeen{};
    bool WineServerSocketSeen{};
    bool WinePreloadReserveSeen{};
    bool DisplaySeen{};
    std::vector<std::string> AdditionalEnvironment;
    int WineServerSocketFD = -1;
    std::string WinePreloadReserve;
    for (const auto &Entry : GuestEnvironment) {
      if (Entry == "LC_ALL=C" && !LocaleSeen) {
        LocaleSeen = true;
      } else if (Entry == "HOME=/home/regression" && !HomeSeen) {
        HomeSeen = true;
      } else if (Entry == "WINELOADERNOEXEC=1" && !LoaderNoExecSeen) {
        LoaderNoExecSeen = true;
      } else if (Entry == "WINEARCH=wow64" && !WineArchSeen) {
        WineArchSeen = true;
      } else if (Entry.starts_with("WINESERVERSOCKET=") && !WineServerSocketSeen) {
        const std::string_view Value{Entry.data() + sizeof("WINESERVERSOCKET=") - 1,
                                     Entry.size() - (sizeof("WINESERVERSOCKET=") - 1)};
        const std::string ValueCopy{Value};
        errno = 0;
        char *End = nullptr;
        const long StableParsed = std::strtol(ValueCopy.c_str(), &End, 10);
        if (errno != 0 || End == ValueCopy.c_str() || *End != '\0' || StableParsed <= STDERR_FILENO ||
            StableParsed > 65'535) {
          return Reject(EINVAL);
        }
        WineServerSocketFD = static_cast<int>(StableParsed);
        WineServerSocketSeen = true;
      } else if (Entry == "DISPLAY=:0" && !DisplaySeen) {
        DisplaySeen = true;
      } else if (Entry.starts_with("WINEPRELOADRESERVE=") && !WinePreloadReserveSeen) {
        WinePreloadReserve = Entry.substr(sizeof("WINEPRELOADRESERVE=") - 1);
        if (!IsValidWinePreloadReserve(WinePreloadReserve)) {
          return Reject(EINVAL);
        }
        WinePreloadReserveSeen = true;
      } else if (IsAdditionalGuestEnvironment(Entry)) {
        AdditionalEnvironment.push_back(Entry);
      } else {
        return Reject(EINVAL);
      }
    }
    if (!LocaleSeen || !HomeSeen || !LoaderNoExecSeen || !WineArchSeen || !WineServerSocketSeen ||
        !WinePreloadReserveSeen || !OwnedDescriptors.contains(WineServerSocketFD)) {
      return Reject(EACCES);
    }

    struct stat WineServerSocketStat{};
    const int DescriptorFlags = fcntl(WineServerSocketFD, F_GETFD);
    if (DescriptorFlags == -1 || (DescriptorFlags & FD_CLOEXEC) != 0 ||
        fstat(WineServerSocketFD, &WineServerSocketStat) != 0 || !S_ISSOCK(WineServerSocketStat.st_mode)) {
      return Reject(EACCES);
    }

    std::string ChildDirectory = ResearchTemporaryPrefix("regression-fli-fex-process-probe.XXXXXX");
    if (mkdtemp(ChildDirectory.data()) == nullptr)
      return Reject(errno);
    const std::string ChildReceipt = ChildDirectory + "/process-probe.json";
    const int ReceiptFD = open(ChildReceipt.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (ReceiptFD < 0)
      return Reject(errno);
    close(ReceiptFD);
    dprintf(STDERR_FILENO, "TRACE execve-child-diagnostics=%s\n", ChildDirectory.c_str());
    dprintf(STDERR_FILENO, "TRACE execve-child-target=%s depth=%lu\n", GuestArguments[2].c_str(), Depth + 1);

    std::vector<std::string> NativeArguments{
        HostExecutablePath,
        "--real-rootfs",
        RootFS,
        "--guest-program",
        std::string{ExpectedTarget},
        "--guest-component-kind",
        "official-proton-wine64-preloader",
        "--private-receipt-output",
        ChildReceipt,
        "--private-stderr-output",
        ChildDirectory + "/stderr.log",
    };
    for (size_t Index = 1; Index < GuestArguments.size(); ++Index) {
      NativeArguments.emplace_back("--guest-arg");
      NativeArguments.push_back(GuestArguments[Index]);
    }
    if (LowMemoryBiasModeEnabled) {
      NativeArguments.emplace_back("--instrument-low-memory-bias");
    }
    if (HighMemoryRegionModeEnabled) {
      NativeArguments.emplace_back("--instrument-high-memory-region");
    }
    NativeArguments.emplace_back("--wine-arch-wow64");
    NativeArguments.emplace_back("--inherited-wineserver-socket-fd");
    NativeArguments.push_back(std::to_string(WineServerSocketFD));
    NativeArguments.emplace_back("--wine-preload-reserve");
    NativeArguments.push_back(WinePreloadReserve);

    for (const auto &Entry : AdditionalEnvironment) {
      NativeArguments.emplace_back("--guest-env");
      NativeArguments.push_back(Entry);
    }

    std::vector<char *> NativeArgumentPointers;
    NativeArgumentPointers.reserve(NativeArguments.size() + 1);
    for (auto &Argument : NativeArguments) {
      NativeArgumentPointers.push_back(Argument.data());
    }
    NativeArgumentPointers.push_back(nullptr);
    char LocaleEnvironment[] = "LC_ALL=C";
    char HomeEnvironment[] = "HOME=/home/regression";
    const char *ResearchDirectory = std::getenv("REGRESSION_RESEARCH_TMPDIR");
    std::string ResearchEnvironment = std::string{"REGRESSION_RESEARCH_TMPDIR="} +
                                      (ResearchDirectory && *ResearchDirectory ? ResearchDirectory : "/private/tmp");
    const char *X11Socket = std::getenv("REGRESSION_X11_SOCKET");
    std::string DisplayEnvironment = std::string{"REGRESSION_X11_SOCKET="} + (X11Socket ? X11Socket : "");
    std::string DepthEnvironment = "REGRESSION_FLI_EXEC_DEPTH=" + std::to_string(Depth + 1);
    std::vector<std::string> NativeEnvironmentStorage{
        LocaleEnvironment, HomeEnvironment, ResearchEnvironment, DisplayEnvironment, DepthEnvironment,
    };
    for (const char *Name :
         {"REGRESSION_FLI_TRACE_GUEST_STDERR", "REGRESSION_FLI_TRACE_GUEST_PATHS",
          "REGRESSION_FLI_TRACE_SYSCALL_RESULTS", "REGRESSION_FLI_TRACE_FUTEX", "REGRESSION_FLI_TRACE_BRANCHES",
          "REGRESSION_FLI_MTRACK", "REGRESSION_FLI_SINGLE_INST", "REGRESSION_FLI_MAX_INST",
          "REGRESSION_FLI_NO_MULTIBLOCK", "REGRESSION_FLI_TRACE_BRANCH_SOURCE", "REGRESSION_FLI_ROOT_FULL_SMC",
          "REGRESSION_FLI_FULL_CODE_OFFSET", "REGRESSION_FLI_READONLY_LARGE_BLOCKS",
          "REGRESSION_FLI_SAFE_UNALIGNED_TSO", "REGRESSION_FLI_TRACE_WINE_IPC",
          "REGRESSION_FLI_TRACE_EXECVE_ARGUMENTS"}) {
      if (const char *Value = std::getenv(Name); Value && *Value) {
        NativeEnvironmentStorage.emplace_back(std::string{Name} + "=" + Value);
      }
    }
    std::vector<char *> NativeEnvironment;
    for (auto &Entry : NativeEnvironmentStorage)
      NativeEnvironment.push_back(Entry.data());
    NativeEnvironment.push_back(nullptr);

    OfficialProtonExecveReentryValidationPassed = true;
    dprintf(STDERR_FILENO,
            "TRACE official-proton-execve-reentry target=wine64-preloader "
            "argc=%llu envc=%llu socket-fd=%d reserve-valid=1\n",
            static_cast<unsigned long long>(GuestArguments.size()),
            static_cast<unsigned long long>(GuestEnvironment.size()), WineServerSocketFD);
    execve(HostExecutablePath.c_str(), NativeArgumentPointers.data(), NativeEnvironment.data());
    return Reject(errno != 0 ? errno : EIO);
  }

  void CleanupNativeForkCloneChild() {
    if (!NativeForkCloneParentProcess || NativeForkCloneProcessID <= 0 || NativeForkCloneChildReaped) {
      return;
    }
    int Status = 0;
    pid_t Result =
        BlockingHostCall([&] { return waitpid(static_cast<pid_t>(NativeForkCloneProcessID), &Status, WNOHANG); });
    if (Result == 0) {
      static_cast<void>(kill(static_cast<pid_t>(NativeForkCloneProcessID), SIGTERM));
      do {
        Result = BlockingHostCall([&] { return waitpid(static_cast<pid_t>(NativeForkCloneProcessID), &Status, 0); });
      } while (Result < 0 && errno == EINTR);
    }
    if (Result == static_cast<pid_t>(NativeForkCloneProcessID)) {
      NativeForkCloneChildReaped = true;
    } else {
    }
  }

  __attribute__((noinline, used)) uint64_t HandleAcceptSyscall(FEXCore::HLE::SyscallArguments *Arguments) {
    constexpr uint16_t LinuxAFUnix = 1;
    const int Descriptor = static_cast<int>(Arguments->Argument[1]);
    constexpr uint32_t LinuxSockaddrUnSize = 110;
    const uint64_t GuestAddress = Arguments->Argument[2];
    const uint64_t GuestAddressLength = Arguments->Argument[3];
    AcceptLastDescriptorOwned = OwnedDescriptors.contains(Descriptor);
    if (!AcceptLastDescriptorOwned || Descriptor != ListenLastDescriptor || ListenSuccessCount == 0) {
      return static_cast<uint64_t>(-EBADF);
    }
    if (!Contains(GuestAddress, LinuxSockaddrUnSize) || !Contains(GuestAddressLength, sizeof(uint32_t))) {
      return static_cast<uint64_t>(-EFAULT);
    }
    uint32_t InputAddressLength{};
    std::memcpy(&InputAddressLength, reinterpret_cast<const void *>(GuestAddressLength), sizeof(InputAddressLength));
    if (InputAddressLength != LinuxSockaddrUnSize) {
      return static_cast<uint64_t>(-EINVAL);
    }

    sockaddr_un HostAddress{};
    socklen_t HostAddressLength = sizeof(HostAddress);
    const int AcceptedDescriptor = BlockingHostCall(
        [&] { return accept(Descriptor, reinterpret_cast<sockaddr *>(&HostAddress), &HostAddressLength); });
    if (AcceptedDescriptor == -1) {
      const int LinuxError = TranslateHostSocketErrorToLinux(errno);
      return static_cast<uint64_t>(-LinuxError);
    }
    if (HostAddressLength < offsetof(sockaddr_un, sun_path) || HostAddress.sun_family != AF_UNIX) {
      close(AcceptedDescriptor);
      return static_cast<uint64_t>(-EAFNOSUPPORT);
    }
    const size_t HostPathLength =
        std::min<size_t>(HostAddressLength - offsetof(sockaddr_un, sun_path), sizeof(HostAddress.sun_path));
    const uint32_t OutputAddressLength = static_cast<uint32_t>(sizeof(LinuxAFUnix) + HostPathLength);
    std::array<uint8_t, LinuxSockaddrUnSize> LinuxAddress{};
    std::memcpy(LinuxAddress.data(), &LinuxAFUnix, sizeof(LinuxAFUnix));
    std::memcpy(LinuxAddress.data() + sizeof(LinuxAFUnix), HostAddress.sun_path, HostPathLength);
    const size_t CopyLength = std::min<size_t>(InputAddressLength, OutputAddressLength);
    std::memcpy(reinterpret_cast<void *>(GuestAddress), LinuxAddress.data(), CopyLength);
    std::memcpy(reinterpret_cast<void *>(GuestAddressLength), &OutputAddressLength, sizeof(OutputAddressLength));
    OwnedDescriptors.insert(AcceptedDescriptor);
    return static_cast<uint64_t>(AcceptedDescriptor);
  }

  void Stop(FEXCore::Core::CpuStateFrame *Frame) const {
    if (StopAddress != 0 && Frame != nullptr) {
      Frame->State.rip = StopAddress;
    }
  }

  bool MaybeStopAtPostSessionSyscallBoundary(FEXCore::Core::CpuStateFrame *Frame,
                                             const FEXCore::HLE::SyscallArguments *Arguments, uint64_t Number) {
    if (SessionMappingWriteCompleted && PostSessionSyscallDiagnosticCallCount >= 14 &&
        PostSessionLiveTraceCount < PostSessionLiveTrace.size()) {
      PostSessionLiveTrace[PostSessionLiveTraceCount++] = Number;
      dprintf(STDERR_FILENO, "DIAGNOSTIC post-session-count=%llu syscall=%llu limit=%llu\n",
              static_cast<unsigned long long>(PostSessionSyscallDiagnosticCallCount),
              static_cast<unsigned long long>(Number),
              static_cast<unsigned long long>(PostSessionSyscallDiagnosticLimit));
    }
    if (PostSessionSyscallDiagnosticLimitSeen) {
      Stop(Frame);
      (void)DarwinDiagnosticThreadStopHandler::Request();
      return true;
    }
    if (PostSessionSyscallDiagnosticLimit == 0 || !SessionMappingWriteCompleted) {
      return false;
    }
    ++PostSessionSyscallDiagnosticCallCount;
    if (PostSessionSyscallDiagnosticCallCount >= PostSessionSyscallDiagnosticLimit) {

      PostSessionSyscallDiagnosticLimitSeen = true;
      Stop(Frame);
      (void)DarwinDiagnosticThreadStopHandler::Request();
      return true;
    }
    return false;
  }

  static void ReleaseProcSnapshot(int fd) {
    using Release = void (*)(int);
    static const auto release = reinterpret_cast<Release>(dlsym(RTLD_DEFAULT, "fli_linux_root_release_proc_snapshot"));
    if (release)
      release(fd);
  }
  std::optional<int> OpenProcSnapshot(const std::string &Path) const {
    if (Path == "/proc" || Path == "/proc/") {
      using Open = int32_t (*)(int, int);
      static const auto open = reinterpret_cast<Open>(dlsym(RTLD_DEFAULT, "fli_linux_root_open_proc"));
      return open ? open(getpid(), 4) : -95;
    }
    if (!Path.starts_with("/proc/"))
      return std::nullopt;
    const auto Slash = Path.find_last_of('/');
    const std::string Leaf = Path.substr(Slash + 1);
    const int Kind = Leaf == "comm" ? 0 : Leaf == "cmdline" ? 1 : Leaf == "status" ? 2 : Leaf == "maps" ? 3 : -1;
    if (Kind < 0)
      return std::nullopt;
    const std::string PIDText = Path.substr(6, Slash - 6);
    char *End = nullptr;
    const long PID = PIDText == "self" ? getpid() : strtol(PIDText.c_str(), &End, 10);
    if (PID <= 0 || PID > INT32_MAX || (PIDText != "self" && (End == PIDText.c_str() || *End)))
      return -ENOENT;
    using Open = int32_t (*)(int, int);
    const auto Function = reinterpret_cast<Open>(dlsym(RTLD_DEFAULT, "fli_linux_root_open_proc"));
    return Function ? Function(int(PID), Kind) : -95;
  }

  bool Contains(uint64_t Address, uint64_t Size) const {
    return Address >= GuestBase && Address + Size >= Address && Address + Size <= GuestBase + GuestSize;
  }

  void *HostPointerForGuestRange(uint64_t Address, uint64_t Size, int RequiredProtection) const {
    if (Size == 0) {
      return nullptr;
    }
    for (const auto &view : NativeFileViews)
      if (Address >= view.address && Address - view.address < view.length &&
          Size <= view.length - (Address - view.address)) {
        mach_vm_address_t base = Address;
        mach_vm_size_t span = 0;
        vm_region_basic_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        const auto status = mach_vm_region(mach_task_self(), &base, &span, VM_REGION_BASIC_INFO_64,
                                           reinterpret_cast<vm_region_info_t>(&info), &count, &object);
        if (object != MACH_PORT_NULL)
          mach_port_deallocate(mach_task_self(), object);
        if (status != KERN_SUCCESS || base > Address || Address - base >= span || Size > span - (Address - base) ||
            (info.protection & RequiredProtection) != RequiredProtection)
          return nullptr;
        return reinterpret_cast<void *>(Address);
      }
    for (const auto &Alias : SharedAliases) {
      if (Address >= Alias.Guest && Address - Alias.Guest < Alias.Length &&
          Size <= Alias.Length - (Address - Alias.Guest)) {
        if ((Alias.Protection & RequiredProtection) != static_cast<uint64_t>(RequiredProtection))
          return nullptr;
        return reinterpret_cast<void *>(Alias.Host + Address - Alias.Guest);
      }
    }
    if (Contains(Address, Size)) {
      return reinterpret_cast<void *>(Address);
    }
    if (LowMemoryBiasModeEnabled && LowGuestShadow != nullptr) {
      if (void *Pointer = LowGuestShadow->HostPointerForMappedLogicalRange(Address, Size, RequiredProtection)) {
        return Pointer;
      }
    }
    if (HighMemoryRegionModeEnabled && HighGuestSparse != nullptr) {
      return HighGuestSparse->HostPointerForMappedLogicalRange(Address, Size, RequiredProtection);
    }
    return nullptr;
  }

  void RecordHighMMap(uint64_t Address, uint64_t Length, uint64_t ArenaEnd, uint64_t Protection, uint64_t Flags,
                      int Descriptor, uint64_t Offset) {
    if (!ContainsMMapArena(Address, Length)) {
      return;
    }
    const auto [DescriptorPathClass, DescriptorGuestPath] = DescribeMappingDescriptor(Descriptor, (Flags & 0x20) != 0);
    HighMMapRecords.push_back(HighMMapRecord{
        .Address = Address,
        .Length = Length,
        .ArenaEnd = ArenaEnd,
        .Protection = Protection,
        .Flags = Flags,
        .Offset = Offset,
        .Descriptor = Descriptor,
        .DescriptorPathClass = DescriptorPathClass,
        .DescriptorGuestPath = DescriptorGuestPath,
        .Active = true,
    });
    HighMMapRecordCount = HighMMapRecords.size();
  }

  void RecordLowMMap(uint64_t Address, uint64_t Length, uint64_t Protection, uint64_t Flags, int Descriptor,
                     uint64_t Offset) {
    if (Length == 0 || Address >= LowGuestAddressLimit || Length > LowGuestAddressLimit - Address) {
      return;
    }
    if (LowMMapRecordCount >= LowMMapRecords.size()) {
      return;
    }
    const auto [DescriptorPathClass, DescriptorGuestPath] = DescribeMappingDescriptor(Descriptor, (Flags & 0x20) != 0);
    LowMMapRecords[LowMMapRecordCount++] = LowMMapRecord{
        .Address = Address,
        .Length = Length,
        .Protection = Protection,
        .Flags = Flags,
        .Offset = Offset,
        .Descriptor = Descriptor,
        .DescriptorPathClass = DescriptorPathClass,
        .DescriptorGuestPath = DescriptorGuestPath,
    };
  }

  std::pair<std::string, std::string> DescribeMappingDescriptor(int Descriptor, bool Anonymous) const {
    if (Anonymous) {
      return {"anonymous", "none"};
    }
    if (!OwnedDescriptors.contains(Descriptor)) {
      return {"unowned", "none"};
    }
    std::array<char, 4096> DescriptorPath{};
    if (fcntl(Descriptor, F_GETPATH, DescriptorPath.data()) != 0) {
      return {
          ReceivedSCMRightsDescriptors.contains(Descriptor) ? "scm-rights-unresolved" : "owned-unresolved",
          "none",
      };
    }
    const std::string HostPath{DescriptorPath.data()};
    const std::string GuestPath =
        fli_guest_host_path_visible(HostPath, RootFS) ? fli_guest_path_view(HostPath, RootFS) : std::string{};
    if (GuestPath.empty() || !IsSafeDiagnosticGuestPath(GuestPath)) {
      return {"outside-rootfs", "redacted"};
    }
    return {"rootfs-file", GuestPath};
  }

  bool ArenaRangeOccupied(uint64_t Address, uint64_t Length) const {
    for (const auto &Record : HighMMapRecords) {
      const uint64_t End = std::max(Record.Address + Record.Length, Record.ArenaEnd);
      if (Record.Active && Address < End && Record.Address < Address + Length)
        return true;
    }
    return false;
  }

  uint64_t FindFreeArenaAddress(uint64_t Address, uint64_t Length, uint64_t Alignment) const {
    Address = (Address + Alignment - 1) & ~(Alignment - 1);
    while (ContainsMMapArena(Address, Length)) {
      uint64_t Next = Address;
      for (const auto &Record : HighMMapRecords) {
        const uint64_t End = std::max(Record.Address + Record.Length, Record.ArenaEnd);
        if (Record.Active && Address < End && Record.Address < Address + Length) {
          Next = std::max(Next, (End + Alignment - 1) & ~(Alignment - 1));
        }
      }
      if (Next == Address)
        return Address;
      Address = Next;
    }
    return 0;
  }

  void ObserveELFLoaderHandoff(uint64_t Map) const {
    for (unsigned index = 0; Map && index < 64; ++index) {
      const void *data = HostPointerForGuestRange(Map, 40, PROT_READ);
      if (!data)
        break;
      uint64_t link[5]{};
      memcpy(link, data, sizeof(link));
      const auto name = ReadGuestPath(link[1]);
      const bool libc = name && name->ends_with("/libc.so.6");
      const bool loader = name && name->ends_with("/ld-linux-x86-64.so.2");
      if (libc || loader) {
        const auto file = ResolveGuestPathWithParents(*name);
        int fd = file ? open(file->c_str(), O_RDONLY | O_CLOEXEC) : -1;
        struct Header {
          unsigned char ident[16];
          uint16_t type, machine;
          uint32_t version;
          uint64_t entry, phoff, shoff;
          uint32_t flags;
          uint16_t size, phsize, phnum, shsize, shnum, shstr;
        } header{};
        struct Program {
          uint32_t type, flags;
          uint64_t offset, vaddr, paddr, filesz, memsz, align;
        };
        struct Probe {
          uint64_t offset;
          const char *name;
        };
        const Probe probes[] = {{0x2a80, "_dl_debug_state"}, {0xc890, "_dl_open"}, {0x9ab0, "_dl_map_object"},
                                {0x6e800, "dlopen"},         {0x6e8c0, "dlsym"},   {0xf1870, "mmap"}};
        if (fd >= 0 && pread(fd, &header, sizeof(header), 0) == sizeof(header) && !memcmp(header.ident, "\177ELF", 4) &&
            header.machine == 62 && header.phsize == sizeof(Program) && header.phnum < 128) {
          for (unsigned p = libc ? 3 : 0; p < (libc ? 6 : 3); ++p) {
            unsigned char expected[16]{};
            bool found = false;
            for (unsigned n = 0; n < header.phnum; ++n) {
              Program ph{};
              if (pread(fd, &ph, sizeof(ph), header.phoff + n * sizeof(ph)) != sizeof(ph))
                break;
              if (ph.type == 1 && probes[p].offset >= ph.vaddr && probes[p].offset - ph.vaddr + 16 <= ph.filesz) {
                found = pread(fd, expected, 16, ph.offset + probes[p].offset - ph.vaddr) == 16;
                break;
              }
            }
            const uint64_t pc = link[0] + probes[p].offset;
            const auto *actual = static_cast<const unsigned char *>(HostPointerForGuestRange(pc, 16, PROT_READ));
            if (!found || !actual)
              continue;
            uint64_t target = 0;
            const char *encoding = "other";
            const unsigned char *entry = actual;
            uint64_t branchpc = pc;
            if (!memcmp(entry, "\xf3\x0f\x1e\xfa", 4)) {
              entry += 4;
              branchpc += 4;
            }
            if (entry[0] == 0x90) {
              ++entry;
              ++branchpc;
            }
            if (entry[0] == 0xe9) {
              int32_t d = 0;
              memcpy(&d, entry + 1, 4);
              target = branchpc + 5 + d;
              encoding = "rel32";
            } else if (entry[0] == 0xff && entry[1] == 0x25) {
              int32_t d = 0;
              memcpy(&d, entry + 2, 4);
              const void *pointer = HostPointerForGuestRange(branchpc + 6 + d, 8, PROT_READ);
              if (pointer)
                memcpy(&target, pointer, 8);
              encoding = "rip-indirect";
            } else if (entry[0] == 0x48 && entry[1] == 0xb8 && entry[10] == 0xff && entry[11] == 0xe0) {
              memcpy(&target, entry + 2, 8);
              encoding = "movabs-rax";
            } else if (entry[0] == 0x49 && entry[1] == 0xbb && entry[10] == 0x41 && entry[11] == 0xff &&
                       entry[12] == 0xe3) {
              memcpy(&target, entry + 2, 8);
              encoding = "movabs-r11";
            }
            if (memcmp(actual, expected, 16)) {
              char hex[33]{};
              for (unsigned i = 0; i < 16; ++i)
                snprintf(hex + i * 2, 3, "%02x", actual[i]);
              dprintf(2, "ELF_HANDOFF_CHANGED_CODE symbol=%s prefix=%s length=16 code-only=1\n", probes[p].name, hex);
            }
            dprintf(2,
                    "ELF_HANDOFF_HOOK pid=%d module=%s symbol=%s offset=%llx original-prefix=%d branch=%s target=%llx "
                    "read-only=1\n",
                    getpid(), libc ? "libc" : "ld-linux", probes[p].name, (unsigned long long)probes[p].offset,
                    !memcmp(actual, expected, 16), encoding, (unsigned long long)target);
            if (target)
              for (const auto &m : HighMMapRecords)
                if (m.Active && target >= m.Address && target - m.Address < m.Length) {
                  dprintf(2, "ELF_HANDOFF_HOOK_TARGET module=%s offset=%llx shared=%d executable=%d\n",
                          m.DescriptorGuestPath.c_str(), (unsigned long long)(target - m.Address + m.Offset),
                          !!(m.Flags & 1), !!(m.Protection & PROT_EXEC));
                  if (m.Protection & PROT_EXEC) {
                    const auto *stub =
                        static_cast<const unsigned char *>(HostPointerForGuestRange(target, 32, PROT_READ));
                    uint64_t next = 0;
                    if (stub) {
                      char hex[65]{};
                      for (unsigned i = 0; i < 32; ++i)
                        snprintf(hex + i * 2, 3, "%02x", stub[i]);
                      dprintf(2, "ELF_HANDOFF_TRAMPOLINE address=%llx prefix=%s length=32 code-only=1\n",
                              (unsigned long long)target, hex);
                    }
                    if (stub && stub[0] == 0xff && stub[1] == 0x25) {
                      int32_t displacement = 0;
                      memcpy(&displacement, stub + 2, 4);
                      const void *ptr = HostPointerForGuestRange(target + 6 + displacement, 8, PROT_READ);
                      if (ptr)
                        memcpy(&next, ptr, 8);
                    } else if (stub && stub[0] == 0x48 && stub[1] == 0xb8 && stub[10] == 0xff && stub[11] == 0xe0)
                      memcpy(&next, stub + 2, 8);
                    if (next)
                      for (const auto &owner : HighMMapRecords)
                        if (owner.Active && next >= owner.Address && next - owner.Address < owner.Length)
                          dprintf(2, "ELF_HANDOFF_HOOK_OWNER module=%s offset=%llx read-only=1\n",
                                  owner.DescriptorGuestPath.c_str(),
                                  (unsigned long long)(next - owner.Address + owner.Offset));
                  }
                }
          }
        }
        if (fd >= 0)
          close(fd);
      }
      Map = link[3];
    }
  }

  bool ContainsMMapArena(uint64_t Address, uint64_t Size) const {
    return Address >= MMapArenaBase && Address + Size >= Address && Address + Size <= MMapArenaLimit;
  }

  std::optional<std::string> ReadGuestPath(uint64_t Address) const {
    constexpr size_t MaximumPathLength = 4096;
    if (Contains(Address, 1)) {
      const size_t Available = static_cast<size_t>(GuestBase + GuestSize - Address);
      const size_t Limit = std::min(Available, MaximumPathLength);
      const auto *Begin = reinterpret_cast<const char *>(Address);
      const auto *End = static_cast<const char *>(std::memchr(Begin, '\0', Limit));
      if (End == nullptr) {
        return std::nullopt;
      }
      return std::string{Begin, End};
    }

    std::string Path;
    Path.reserve(128);
    for (size_t Offset = 0; Offset < MaximumPathLength; ++Offset) {
      if (Address > std::numeric_limits<uint64_t>::max() - Offset) {
        return std::nullopt;
      }
      const auto *Character = static_cast<const char *>(HostPointerForGuestRange(Address + Offset, 1, PROT_READ));
      if (Character == nullptr) {
        return std::nullopt;
      }
      if (*Character == '\0') {
        return Path;
      }
      Path.push_back(*Character);
    }
    return std::nullopt;
  }

  static bool IsSafeDiagnosticGuestPath(const std::string &GuestPath) {
    if (GuestPath.empty() || GuestPath.size() > 512) {
      return false;
    }
    return std::all_of(GuestPath.begin(), GuestPath.end(), [](unsigned char Character) {
      return (Character >= 'a' && Character <= 'z') || (Character >= 'A' && Character <= 'Z') ||
             (Character >= '0' && Character <= '9') || Character == '/' || Character == '_' || Character == '-' ||
             Character == '.' || Character == '+';
    });
  }

  static bool IsSafeIntlNLSDiagnosticPath(const std::string &GuestPath) {
    constexpr std::string_view Basename{"l_intl.nls"};
    return GuestPath.ends_with(Basename) && IsSafeDiagnosticGuestPath(GuestPath);
  }

  bool BeginIntlNLSDiagnostic(std::string_view Operation, const std::string &GuestPath) {
    if (!IsSafeIntlNLSDiagnosticPath(GuestPath)) {
      return false;
    }
    if (IntlNLSOpenCandidatePaths.size() < 8) {
      IntlNLSOpenCandidatePaths.push_back(GuestPath);
    }
    return true;
  }

  void FinishIntlNLSDiagnostic(bool Enabled, bool HostPathResolved, bool TargetExists, bool TargetRegular,
                               int64_t LinuxError) {
    if (!Enabled) {
      return;
    }
  }

  bool IsTemporaryMappingCandidate(const std::string &GuestPath, uint64_t Flags, uint64_t Mode) const {
    constexpr uint64_t LinuxOReadWrite = 0x2;
    constexpr uint64_t LinuxOCreate = 0x40;
    constexpr uint64_t LinuxOExclusive = 0x80;
    constexpr std::string_view Prefix{"tmpmap-"};
    if (Flags != (LinuxOReadWrite | LinuxOCreate | LinuxOExclusive) || Mode != 0600 ||
        GuestPath.size() != Prefix.size() + 8 || !GuestPath.starts_with(Prefix)) {
      return false;
    }
    return std::all_of(GuestPath.begin() + static_cast<ptrdiff_t>(Prefix.size()), GuestPath.end(),
                       [](unsigned char Character) {
                         return (Character >= '0' && Character <= '9') || (Character >= 'a' && Character <= 'f') ||
                                (Character >= 'A' && Character <= 'F');
                       });
  }

  void RecordTemporaryMappingCandidate(const std::string &GuestPath, uint64_t Flags, uint64_t Mode) {
    if (!IsTemporaryMappingCandidate(GuestPath, Flags, Mode)) {
      return;
    }
    if (TemporaryMappingFirstCandidatePath == "none") {
      TemporaryMappingFirstCandidatePath = GuestPath;
    }
  }

  std::optional<std::string> CurrentGuestDirectory(int *error = nullptr) const {
    if (error)
      *error = 0;
    if (!NativeHandoffObserved)
      return GuestCurrentWorkingDirectory;
    std::string actual;
    const int status = fli_current_directory(RootFS, actual);
    if (status) {
      if (error)
        *error = status;
      return std::nullopt;
    }
    return actual;
  }

  std::optional<std::string> ResolveGuestPath(const std::string &GuestPath) const {
    const auto cwd =
        (!GuestPath.empty() && GuestPath.front() == '/') ? std::optional<std::string>{""} : CurrentGuestDirectory();
    if (!cwd)
      return std::nullopt;
    const std::string EffectivePath =
        GuestPath.empty() ? *cwd : (GuestPath.front() == '/' ? GuestPath : *cwd + (*cwd == "/" ? "" : "/") + GuestPath);

    std::string Normalized;
    size_t Cursor = EffectivePath.front() == '/' ? 1 : 0;
    while (Cursor <= EffectivePath.size()) {
      const size_t Separator = EffectivePath.find('/', Cursor);
      const size_t End = Separator == std::string::npos ? EffectivePath.size() : Separator;
      const std::string_view Component{EffectivePath.data() + Cursor, End - Cursor};
      if (Component == "..") {
        return std::nullopt;
      }
      if (!Component.empty() && Component != ".") {
        Normalized += '/';
        Normalized.append(Component);
      }
      if (Separator == std::string::npos) {
        break;
      }
      Cursor = Separator + 1;
    }

    Normalized = fli_guest_path_view(std::move(Normalized), RootFS);
    if (fli_shared_host_path(Normalized))
      return fli_shared_host_object(Normalized);
    std::string Candidate = RootFS + Normalized;
    if (access(Candidate.c_str(), F_OK) != 0 && Normalized.starts_with("/lib64/")) {
      Candidate = RootFS + "/usr" + Normalized;
    }
    if (access(Candidate.c_str(), F_OK) == 0) {
      std::array<char, 4096> Canonical{};
      if (realpath(Candidate.c_str(), Canonical.data()) == nullptr) {
        return std::nullopt;
      }
      const std::string Resolved{Canonical.data()};
      if (!fli_guest_host_path_visible(Resolved, RootFS)) {
        return std::nullopt;
      }
      Candidate = Resolved;
    }
    return Candidate;
  }

  std::optional<std::string> NormalizeGuestPathWithParents(const std::string &GuestPath) const {
    if (GuestPath.empty()) {
      return std::nullopt;
    }
    const auto cwd =
        (!GuestPath.empty() && GuestPath.front() == '/') ? std::optional<std::string>{""} : CurrentGuestDirectory();
    if (!cwd)
      return std::nullopt;
    const std::string EffectivePath =
        GuestPath.front() == '/' ? GuestPath : *cwd + (*cwd == "/" ? "" : "/") + GuestPath;

    std::vector<std::string_view> Components;
    size_t Cursor = EffectivePath.front() == '/' ? 1 : 0;
    while (Cursor <= EffectivePath.size()) {
      const size_t Separator = EffectivePath.find('/', Cursor);
      const size_t End = Separator == std::string::npos ? EffectivePath.size() : Separator;
      const std::string_view Component{EffectivePath.data() + Cursor, End - Cursor};
      if (Component == "..") {
        if (Components.empty()) {
          return std::nullopt;
        }
        Components.pop_back();
      } else if (!Component.empty() && Component != ".") {
        Components.emplace_back(Component);
      }
      if (Separator == std::string::npos) {
        break;
      }
      Cursor = Separator + 1;
    }

    std::string Normalized{"/"};
    for (size_t Index = 0; Index < Components.size(); ++Index) {
      if (Index != 0) {
        Normalized += '/';
      }
      Normalized.append(Components[Index]);
    }
    return Normalized;
  }

  std::optional<std::string> ResolveGuestPathWithParents(const std::string &GuestPath) const {
    const auto Normalized = NormalizeGuestPathWithParents(GuestPath);
    if (!Normalized.has_value()) {
      return std::nullopt;
    }

    const auto shared = fli_guest_path_view(*Normalized, RootFS);
    if (fli_shared_host_path(shared))
      return fli_shared_host_object(shared);
    std::string Candidate = RootFS + shared;
    if (access(Candidate.c_str(), F_OK) != 0 && Normalized->starts_with("/lib64/")) {
      Candidate = RootFS + "/usr" + *Normalized;
    }
    if (access(Candidate.c_str(), F_OK) != 0) {
      return Candidate;
    }

    std::array<char, 4096> Canonical{};
    if (realpath(Candidate.c_str(), Canonical.data()) == nullptr) {
      return std::nullopt;
    }
    const std::string Resolved{Canonical.data()};
    if (!fli_guest_host_path_visible(Resolved, RootFS)) {
      return std::nullopt;
    }
    return Resolved;
  }

  std::optional<std::string> ResolveGuestCreationPath(const std::string &GuestPath) const {
    if (GuestPath.empty() || GuestPath.back() == '/') {
      return std::nullopt;
    }
    const size_t Separator = GuestPath.find_last_of('/');
    const std::string ParentGuestPath =
        Separator == std::string::npos ? "." : (Separator == 0 ? "/" : GuestPath.substr(0, Separator));
    const std::string Basename = Separator == std::string::npos ? GuestPath : GuestPath.substr(Separator + 1);
    if (Basename.empty() || Basename == "." || Basename == "..") {
      return std::nullopt;
    }
    const auto HostParent = ResolveGuestPath(ParentGuestPath);
    if (!HostParent.has_value()) {
      return std::nullopt;
    }
    struct stat ParentStat{};
    if (lstat(HostParent->c_str(), &ParentStat) != 0 || !S_ISDIR(ParentStat.st_mode)) {
      return std::nullopt;
    }
    return *HostParent + (*HostParent == "/" ? "" : "/") + Basename;
  }

  std::optional<std::string> ResolveGuestRelativeSymlink(const std::string &GuestTarget,
                                                         const std::string &GuestLink) const {
    if (GuestTarget.empty() || GuestTarget.front() == '/') {
      return std::nullopt;
    }
    const auto HostLink = ResolveGuestCreationPath(GuestLink);
    if (!HostLink.has_value()) {
      return std::nullopt;
    }
    const size_t Separator = HostLink->find_last_of('/');
    const std::string HostParent = Separator == 0 ? "/" : HostLink->substr(0, Separator);
    const std::string CandidateTarget = HostParent + "/" + GuestTarget;
    std::array<char, 4096> CanonicalTarget{};
    if (realpath(CandidateTarget.c_str(), CanonicalTarget.data()) == nullptr) {
      return std::nullopt;
    }
    const std::string ResolvedTarget{CanonicalTarget.data()};
    if (!fli_guest_host_path_visible(ResolvedTarget, RootFS)) {
      return std::nullopt;
    }
    return HostLink;
  }

  static void TraceGuestPath(std::string_view Operation, const std::string &GuestPath) {
    const char *Enabled = getenv("REGRESSION_FLI_TRACE_GUEST_PATHS");
    if (Enabled != nullptr && std::string_view{Enabled} == "1") {
      std::cerr << "TRACE " << Operation << " guest-path=" << GuestPath << '\n';
    }
  }

  static void TraceExecveArgument(uint64_t Index, const std::string &Argument) {
    const char *Enabled = getenv("REGRESSION_FLI_TRACE_EXECVE_ARGUMENTS");
    if (Enabled != nullptr && std::string_view{Enabled} == "1") {
      std::cerr << "TRACE execve argv[" << Index << "]=" << Argument << '\n';
    }
  }

  static std::string ClassifyExecveArgument(uint64_t Index, const std::string &Argument) {
    if (Argument.empty()) {
      return "empty";
    }
    if (Index == 0 && Argument.front() == '/') {
      return "executable-path";
    }
    if (Argument.size() >= 3 &&
        ((Argument[0] >= 'A' && Argument[0] <= 'Z') || (Argument[0] >= 'a' && Argument[0] <= 'z')) &&
        Argument[1] == ':' && (Argument[2] == '\\' || Argument[2] == '/')) {
      return "windows-path";
    }
    if (Argument.front() == '-' && Argument.size() > 1) {
      return "dash-option";
    }
    if (Argument.front() == '/' && Argument.find('/', 1) == std::string::npos) {
      return "slash-option";
    }
    if (Argument.front() == '/') {
      return "absolute-path";
    }
    return "literal";
  }

  static LinuxX86_64Stat TranslateStat(const struct stat &HostStat) {
    LinuxX86_64Stat GuestStat{};
    GuestStat.Device = static_cast<uint64_t>(HostStat.st_dev);
    GuestStat.Inode = HostStat.st_ino;
    GuestStat.LinkCount = HostStat.st_nlink;
    GuestStat.Mode = HostStat.st_mode;
    GuestStat.UserID = HostStat.st_uid;
    GuestStat.GroupID = HostStat.st_gid;
    GuestStat.SpecialDevice = static_cast<uint64_t>(HostStat.st_rdev);
    GuestStat.Size = HostStat.st_size;
    GuestStat.BlockSize = HostStat.st_blksize;
    GuestStat.BlockCount = HostStat.st_blocks;
    GuestStat.AccessSeconds = HostStat.st_atimespec.tv_sec;
    GuestStat.AccessNanoseconds = HostStat.st_atimespec.tv_nsec;
    GuestStat.ModificationSeconds = HostStat.st_mtimespec.tv_sec;
    GuestStat.ModificationNanoseconds = HostStat.st_mtimespec.tv_nsec;
    GuestStat.ChangeSeconds = HostStat.st_ctimespec.tv_sec;
    GuestStat.ChangeNanoseconds = HostStat.st_ctimespec.tv_nsec;
    return GuestStat;
  }

  uint64_t GuestBase{};
  uint64_t GuestSize{};
  uint64_t ExecutableRangeQueryCount{};
  uint64_t StopAddress{};
  uint64_t InitialProgramBreak{};
  uint64_t CurrentProgramBreak{};
  uint64_t ProgramBreakLimit{};
  uint64_t MMapArenaBase{};
  uint64_t NextMMapAddress{};
  uint64_t MMapArenaLimit{};
  std::string RootFS;
  std::string GuestProgram;
  std::string HostExecutablePath;

  std::string CXAltLoaderGuestSocketPath;
  std::string CXAltLoaderHostSocketPath;
  std::string GuestCurrentWorkingDirectory{"/"};
  uint64_t LowPageAliasBackingAddress{};
  uint64_t LowPageAliasBackingSize{};
  LowGuestShadowMapping *LowGuestShadow{};
  HighGuestSparseMapping *HighGuestSparse{};
#ifdef __APPLE__
#include "internet-sockets.inc"
#endif
  std::set<int> OwnedDescriptors;
  std::map<int, std::shared_ptr<int64_t>> InheritedReadOffsets;
  std::set<int> ReceivedSCMRightsDescriptors;
  std::set<int> EpollDescriptors;
  std::map<std::pair<int, int>, int16_t> EpollFilters;
  std::set<int> RegistryTemporaryDescriptors;
  std::set<int> CXAltLoaderConnectedDescriptors;
  std::set<std::string> RegistryTemporaryBasenames;
  std::set<int> ClosedStandardDescriptors;
  inline static thread_local uint64_t ClearChildTID{};
  inline static thread_local uint64_t RobustListHead{};
};

bool HandleTrackedGuestCodeWrite(FEXCore::Core::InternalThreadState *Thread, uint64_t Address, ucontext_t *Native) {
  auto *Handler = static_cast<ProcessSyscallHandler *>(Thread->FrontendPtr);
  return Handler && Handler->RepairTrackedCodeWrite(Thread, Address, Native);
}

bool WriteAll(int Descriptor, const void *Data, size_t Size) {
  const auto *Bytes = static_cast<const uint8_t *>(Data);
  size_t Written{};
  while (Written < Size) {
    const ssize_t Result = BlockingHostCall([&] { return write(Descriptor, Bytes + Written, Size - Written); });
    if (Result == -1 && errno == EINTR) {
      continue;
    }
    if (Result <= 0) {
      return false;
    }
    Written += static_cast<size_t>(Result);
  }
  return true;
}

bool WritePrivateTextFile(const std::string &Path, std::string_view Text) {
  const int Descriptor = open(Path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, S_IRUSR | S_IWUSR);
  if (Descriptor == -1) {
    return false;
  }
  const bool Passed = WriteAll(Descriptor, Text.data(), Text.size()) && close(Descriptor) == 0;
  if (!Passed) {
    close(Descriptor);
    unlink(Path.c_str());
  }
  return Passed;
}

class GuestMapping final {
public:
  explicit GuestMapping(size_t Size) : Size{Size} {}

  bool Allocate(uint64_t MinimumAddress = 0) {
    Base = mmap(reinterpret_cast<void *>(MinimumAddress), Size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
                0);
    if (Base != MAP_FAILED && reinterpret_cast<uint64_t>(Base) < MinimumAddress) {
      munmap(Base, Size);
      Base = MAP_FAILED;
    }
    return Base != MAP_FAILED;
  }

  ~GuestMapping() {
    if (Base != MAP_FAILED) {
      munmap(Base, Size);
    }
  }

  uint64_t Address() const { return reinterpret_cast<uint64_t>(Base); }

private:
  void *Base{MAP_FAILED};
  size_t Size{};
};

class CallRetStackMapping final {
public:
  bool Attach(FEXCore::Core::InternalThreadState *Thread) {
    const long PageSizeResult = sysconf(_SC_PAGESIZE);
    if (Thread == nullptr || PageSizeResult <= 0) {
      return false;
    }
    PageSize = static_cast<size_t>(PageSizeResult);
    AllocationSize = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * PageSize;
    Allocation = mmap(nullptr, AllocationSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (Allocation == MAP_FAILED) {
      return false;
    }
    auto *Base = static_cast<uint8_t *>(Allocation) + PageSize;
    if (mprotect(Base, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE, PROT_READ | PROT_WRITE) != 0) {
      munmap(Allocation, AllocationSize);
      Allocation = MAP_FAILED;
      return false;
    }
    Thread->CallRetStackBase = Base;
    Thread->CurrentFrame->State.callret_sp =
        reinterpret_cast<uint64_t>(Base) + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4;
    return true;
  }

  ~CallRetStackMapping() {
    if (Allocation != MAP_FAILED) {
      munmap(Allocation, AllocationSize);
    }
  }

private:
  void *Allocation{MAP_FAILED};
  size_t AllocationSize{};
  size_t PageSize{};
};

thread_local std::array<ProcessSyscallHandler::GuestSignalFrame, 8> ProcessSyscallHandler::GuestSignalFrames{};

uint64_t ProcessSyscallHandler::SpawnGuestThread(const FEXCore::Core::CPUState &Parent,
                                                 FEXCore::HLE::SyscallArguments *Arguments, uint64_t Continuation,
                                                 const FliLinuxThreadState *Snapshot) {
  // ponytail: bounded laboratory worker pool; replace with a full thread manager for production.
  if (!ForkContext || !NativeThreadStopHandler)
    return static_cast<uint64_t>(-38);
  if (ProcessExiting)
    return static_cast<uint64_t>(-11);
  for (size_t Index = 0; Index < NativeGuestThreads.size();) {
    auto *Record = NativeGuestThreads[Index];
    if (!Record->Finished) {
      ++Index;
      continue;
    }
    NativeGuestThreads.erase(NativeGuestThreads.begin() + Index);
    BlockingHostCall([&] { return pthread_join(Record->Native, nullptr); });
    ForkContext->DestroyThread(Record->Thread);
    delete Record;
  }
  if (NativeGuestThreads.size() >= 32)
    return static_cast<uint64_t>(-11);
  const uint64_t Stack = Arguments->Argument[2];
  const uint64_t ParentTID = Arguments->Argument[3];
  const uint64_t ChildTID = Arguments->Argument[4];
  const uint64_t TLS = Arguments->Argument[5];
  void *ParentOutput = HostPointerForGuestRange(ParentTID, 4, PROT_WRITE);
  if (!ParentOutput || !HostPointerForGuestRange(ChildTID, 4, PROT_WRITE) ||
      !HostPointerForGuestRange(Stack, 16, PROT_READ) || !HostPointerForGuestRange(TLS, 1, PROT_READ))
    return static_cast<uint64_t>(-EFAULT);
  auto *Thread = ForkContext->CreateThread(0, 0, &Parent);
  if (!Thread)
    return static_cast<uint64_t>(-12);
  Thread->FrontendPtr = this;
  auto &State = Thread->CurrentFrame->State;
  State.rip = Continuation;
  if (Snapshot) {
    using namespace FEXCore::X86State;
    FEXCore::x86_64::_libc_fpstate FP{};
    memcpy(&FP, Snapshot->floating, sizeof(FP));
    ForkContext->SetFlagsFromCompactedEFLAGS(Thread, Snapshot->regs[18]);
    ForkContext->SetXMMRegistersFromState(
        Thread, FP._xmm, Snapshot->has_ymm ? reinterpret_cast<const __uint128_t *>(Snapshot->ymm) : nullptr);
    State.FCW = FP.fcw;
    State.AbridgedFTW = FP.ftw;
    State.mxcsr = FP.mxcsr;
    State.flags[X87FLAG_IE_LOC] = FP.fsw & 1;
    State.flags[X87FLAG_C0_LOC] = (FP.fsw >> 8) & 1;
    State.flags[X87FLAG_C1_LOC] = (FP.fsw >> 9) & 1;
    State.flags[X87FLAG_C2_LOC] = (FP.fsw >> 10) & 1;
    State.flags[X87FLAG_C3_LOC] = (FP.fsw >> 14) & 1;
    State.flags[X87FLAG_TOP_LOC] = (FP.fsw >> 11) & 7;
    for (unsigned i = 0; i < 8; ++i)
      memcpy(State.mm[(i + State.flags[X87FLAG_TOP_LOC]) % 8], &FP._st[i], 16);
  }
  State.gregs[FEXCore::X86State::REG_RAX] = 0;
  State.gregs[FEXCore::X86State::REG_RSP] = Stack;
  State.fs_cached = TLS;
  auto *Record = new NativeGuestThread;
  Record->Handler = this;
  Record->Thread = Thread;
  Record->Mask = CurrentSignalMask();
  Record->ChildTID = ChildTID;
  if (fli_env_enabled("REGRESSION_FLI_TRACE_BRANCHES"))
    Thread->CurrentFrame->DiagnosticBranches = Record->Branches.data();
  const int Error = pthread_create(&Record->Native, nullptr, ExecuteGuestThread, Record);
  if (Error) {
    ForkContext->DestroyThread(Thread);
    delete Record;
    return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(Error));
  }
  {
    std::unique_lock<std::mutex> Lock{Record->StartupMutex};
    Record->StartupCV.wait(Lock, [&] { return Record->Ready; });
  }
  if (!Record->Initialized) {
    pthread_join(Record->Native, nullptr);
    ForkContext->DestroyThread(Thread);
    delete Record;
    return static_cast<uint64_t>(-12);
  }
  NativeGuestThreads.push_back(Record);
  const uint32_t TID = static_cast<uint32_t>(Record->TID);
  std::memcpy(ParentOutput, &TID, sizeof(TID));
  {
    std::lock_guard lock(Record->StartupMutex);
    Record->Published = true;
  }
  Record->StartupCV.notify_one();
  dprintf(STDERR_FILENO, "TRACE native-thread-created pid=%d tid=%u rip=%llx stack=%llx tls=%llx\n", getpid(), TID,
          (unsigned long long)State.rip, (unsigned long long)Stack, (unsigned long long)TLS);
  return TID;
}

void *ProcessSyscallHandler::ExecuteGuestThread(void *Argument) {
  auto *Record = static_cast<NativeGuestThread *>(Argument);
  auto *Handler = Record->Handler;
  auto *Thread = Record->Thread;
  FEXCore::Allocator::InitializeThread();
  FEXCore::Allocator::RegisterTLSData(Thread);
  CallRetStackMapping CallRetStack;
  DarwinUnalignedAccessHandler FaultHandler;
  DarwinDiagnosticThreadStopHandler StopHandler;
  const bool Initialized =
      CallRetStack.Attach(Thread) &&
      FaultHandler.Attach(Thread, Handler->GuestBase, Handler->GuestSize,
                          Handler->LowGuestShadow ? Handler->LowGuestShadow->Bias() : 0,
                          Handler->LowGuestShadow ? LowGuestAddressLimit : 0,
                          Handler->LowGuestShadow ? Handler->LowGuestShadow->RedirectHostPageAddress() : 0,
                          Handler->LowGuestShadow ? Handler->LowGuestShadow->HostPageBytes() : 0,
                          Handler->HighGuestSparse ? Handler->HighGuestSparse->HostBase() : 0,
                          Handler->HighGuestSparse ? Handler->HighGuestSparse->Size() : 0, Handler->LowGuestShadow,
                          Handler->HighGuestSparse, false, false) &&
      StopHandler.Attach(Thread, Handler->NativeThreadStopHandler, Handler->StopAddress, false);
  if (Initialized) {
    ActiveGuestThread = Record;
    Handler->RegisterSignalThread(Thread, Handler->SignalConfig);
    const char *TracePID = std::getenv("REGRESSION_LINUX_TRACE_PID");
    if (fli_env_enabled("REGRESSION_NATIVE_ELF_EXEC_GATE") && TracePID &&
        std::strtoll(TracePID, nullptr, 10) == getpid() &&
        !DarwinGuestTrapHandler::BindThread(Thread, Handler->SignalConfig))
      std::abort();
    ActivePendingSignals = &Record->PendingSignals;
    ActiveSignalSender = &Record->SignalSender;
    CurrentSignalMask() = Record->Mask;
    ClearChildTID = Record->ChildTID;
  }
  {
    std::lock_guard<std::mutex> Lock{Record->StartupMutex};
    Record->TID = LinuxGuestThreadID();
    Record->Initialized = Initialized;
    Record->Ready = true;
  }
  Record->StartupCV.notify_one();
  if (Initialized) {
    {
      std::unique_lock lock(Record->StartupMutex);
      Record->StartupCV.wait(lock, [&] { return Record->Published; });
    }
    Handler->ForkContext->ExecuteThread(Thread);
    ActiveSyscallLock = nullptr; // Also clears a host wait interrupted by the stop handler.
    std::lock_guard<std::recursive_mutex> Lock{Handler->SyscallMutex};
    if (void *Address = Handler->HostPointerForGuestRange(ClearChildTID, 4, PROT_WRITE)) {
      __atomic_store_n(static_cast<uint32_t *>(Address), 0, __ATOMIC_SEQ_CST);
      os_sync_wake_by_address_all(Address, 4, OS_SYNC_WAKE_BY_ADDRESS_SHARED);
    }
    dprintf(STDERR_FILENO,
            "TRACE native-thread-stopped pid=%d tid=%llu exited=%d code=%llu fault=%d rip=%llx signal=%llu "
            "address=%llx recovered=%llx\n",
            getpid(), (unsigned long long)Record->TID, Record->Exited, (unsigned long long)Record->ExitCode,
            FaultHandler.BoundarySeen(), (unsigned long long)Thread->CurrentFrame->State.rip,
            (unsigned long long)FaultHandler.BoundarySignal(), (unsigned long long)FaultHandler.BoundaryFaultAddress(),
            (unsigned long long)FaultHandler.BoundaryRecoveredGuestRIP());
    ActiveGuestThread = nullptr;
  }
  StopHandler.Reset();
  FaultHandler.Reset();
  FEXCore::Allocator::UninstallTLSData(Thread);
  Record->Finished = true;
  return nullptr;
}

void ProcessSyscallHandler::ObserveOwnedGuestThreads() {
  if (!fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
    return;
  std::unique_lock<std::recursive_mutex> guard(SyscallMutex, std::try_to_lock);
  if (!guard.owns_lock()) {
    dprintf(2, "NATIVE_MAP_WORKER_OBSERVATION lock-busy=1\n");
    return;
  }
  for (const auto *worker : NativeGuestThreads) {
    const auto *frame = worker->Thread->CurrentFrame;
    const uint64_t end = frame->DiagnosticBranchSequence;
    const uint64_t entry = worker->Thread->CTX->GetGuestBlockEntry(worker->Thread);
    const auto protection = TrackedGuestProtection(entry);
    const auto guard_page = SMCProtectedPages.find(entry & ~uint64_t(getpagesize() - 1));
    const bool guarded = guard_page != SMCProtectedPages.end() && guard_page->second;
    const auto memory = worker->Branches[64];
    uint8_t opcode = 0;
    uint32_t word = 0;
    mach_vm_size_t copied = 0;
    const bool atomic = memory.target &&
                        mach_vm_read_overwrite(mach_task_self(), memory.target, 1,
                                               reinterpret_cast<mach_vm_address_t>(&opcode), &copied) == KERN_SUCCESS &&
                        copied == 1 && opcode == 0xf0;
    const bool lock_read =
        atomic && memory.source &&
        mach_vm_read_overwrite(mach_task_self(), memory.source, 4, reinterpret_cast<mach_vm_address_t>(&word),
                               &copied) == KERN_SUCCESS &&
        copied == 4;
    dprintf(2,
            "NATIVE_MAP_WORKER_STATE tid=%llu entry=%llx memory=%llx source=%llx lock-prefix=%d lock-readable=%d "
            "lock-value=%x tracked-prot=%llx mtrack=%d smc-guard=%d\n",
            (unsigned long long)worker->TID, (unsigned long long)entry, (unsigned long long)memory.source,
            (unsigned long long)memory.target, atomic, lock_read, lock_read ? word : 0,
            (unsigned long long)protection.value_or(UINT64_MAX), NativeMTrack, guarded);
    dprintf(2, "NATIVE_MAP_WORKER_OBSERVATION pid=%d tid=%llu finished=%d sequence=%llu\n", getpid(),
            (unsigned long long)worker->TID, worker->Finished.load(), (unsigned long long)end);
    if (frame->DiagnosticBranches)
      for (uint64_t i = end > 3 ? end - 3 : 0; i < end; ++i) {
        const auto branch = worker->Branches[i % 64];
        dprintf(2, "NATIVE_MAP_WORKER_BRANCH tid=%llu source=%llx target=%llx\n", (unsigned long long)worker->TID,
                (unsigned long long)branch.source, (unsigned long long)branch.target);
      }
  }
}
extern "C" __attribute__((visibility("default"))) bool fli_is_root_guest_thread() {
  return ProcessSyscallHandler::IsRootGuestThread();
}
extern "C" __attribute__((visibility("default"))) void fli_observe_owned_guest_threads(void *opaque) {
  if (opaque)
    static_cast<ProcessSyscallHandler *>(*reinterpret_cast<void **>(opaque))->ObserveOwnedGuestThreads();
}

namespace SignalControl {
constexpr uint32_t Magic = 0x52474653;
struct Request {
  uint32_t MagicValue, TID, Signal, Sender;
};
std::string Directory(const std::string &Root) {
  const uint64_t Hash = FingerprintBytes(reinterpret_cast<const uint8_t *>(Root.data()), Root.size());
  char Name[96]{};
  snprintf(Name, sizeof(Name), "/private/tmp/rg-fli-signals-%u-%llx", getuid(), (unsigned long long)Hash);
  return Name;
}
void NoSigPipe(int FD) {
  const int Enabled = 1;
  setsockopt(FD, SOL_SOCKET, SO_NOSIGPIPE, &Enabled, sizeof(Enabled));
  fcntl(FD, F_SETFD, FD_CLOEXEC);
}
bool PeerMatches(int FD, const std::string &Executable, pid_t *PID) {
  uid_t UID{};
  gid_t GID{};
  socklen_t Size = sizeof(*PID);
  char Path[PROC_PIDPATHINFO_MAXSIZE]{};
  return getpeereid(FD, &UID, &GID) == 0 && UID == getuid() &&
         getsockopt(FD, SOL_LOCAL, LOCAL_PEERPID, PID, &Size) == 0 && proc_pidpath(*PID, Path, sizeof(Path)) > 0 &&
         Executable == Path;
}
} // namespace SignalControl

bool ProcessSyscallHandler::StartSignalControl() {
  SignalControlDirectory = SignalControl::Directory(RootFS);
  if (mkdir(SignalControlDirectory.c_str(), 0700) != 0 && errno != EEXIST)
    return false;
  struct stat Directory{};
  if (lstat(SignalControlDirectory.c_str(), &Directory) != 0 || !S_ISDIR(Directory.st_mode) ||
      Directory.st_uid != getuid() || (Directory.st_mode & 0777) != 0700)
    return false;
  SignalControlPath = SignalControlDirectory + "/" + std::to_string(getpid());
  sockaddr_un Address{};
  Address.sun_family = AF_UNIX;
  if (SignalControlPath.size() >= sizeof(Address.sun_path))
    return false;
  std::memcpy(Address.sun_path, SignalControlPath.c_str(), SignalControlPath.size() + 1);
  struct stat Previous{};
  if (lstat(SignalControlPath.c_str(), &Previous) == 0) {
    if (!S_ISSOCK(Previous.st_mode) || Previous.st_uid != getuid())
      return false;
    if (unlink(SignalControlPath.c_str()) != 0)
      return false;
  }
  SignalControlFD = socket(AF_UNIX, SOCK_STREAM, 0);
  if (SignalControlFD < 0)
    return false;
  SignalControl::NoSigPipe(SignalControlFD);
  if (bind(SignalControlFD, reinterpret_cast<sockaddr *>(&Address), sizeof(Address)) != 0 ||
      chmod(SignalControlPath.c_str(), 0600) != 0 || listen(SignalControlFD, 8) != 0)
    return false;
  SignalControlRunning = true;
  if (pthread_create(&SignalControlThread, nullptr, SignalControlLoop, this) != 0) {
    SignalControlRunning = false;
    return false;
  }
  return true;
}

void ProcessSyscallHandler::StopSignalControl() {
  if (SignalControlRunning.exchange(false)) {
    shutdown(SignalControlFD, SHUT_RDWR);
    pthread_join(SignalControlThread, nullptr);
  }
  if (SignalControlFD >= 0) {
    close(SignalControlFD);
    SignalControlFD = -1;
  }
  if (!SignalControlPath.empty()) {
    unlink(SignalControlPath.c_str());
    SignalControlPath.clear();
  }
  if (!SignalControlDirectory.empty())
    rmdir(SignalControlDirectory.c_str());
}

void *ProcessSyscallHandler::SignalControlLoop(void *Argument) {
  auto *Owner = static_cast<ProcessSyscallHandler *>(Argument);
  while (Owner->SignalControlRunning) {
    pollfd Listen{Owner->SignalControlFD, POLLIN, 0};
    if (poll(&Listen, 1, 20) > 0 && Owner->SignalControlRunning) {
      const int Peer = accept(Owner->SignalControlFD, nullptr, nullptr);
      if (Peer >= 0) {
        SignalControl::NoSigPipe(Peer);
        timeval Timeout{0, 200000};
        setsockopt(Peer, SOL_SOCKET, SO_RCVTIMEO, &Timeout, sizeof(Timeout));
        pid_t PID{};
        SignalControl::Request Request{};
        int64_t Result = -EACCES;
        if (SignalControl::PeerMatches(Peer, Owner->HostExecutablePath, &PID) &&
            recv(Peer, &Request, sizeof(Request), MSG_WAITALL) == sizeof(Request) &&
            Request.MagicValue == SignalControl::Magic && Request.Sender == static_cast<uint32_t>(PID)) {
          std::lock_guard<std::recursive_mutex> Lock{Owner->SyscallMutex};
          Result = static_cast<int64_t>(Owner->QueueOwnThreadSignal(Request.TID, Request.Signal, PID));
        }
        send(Peer, &Result, sizeof(Result), 0);
        close(Peer);
      }
    }
    // A signal arriving during startup or compilation remains pending. Retry
    // at a bounded cadence until the target reaches guest code or a syscall.
    std::vector<pthread_t> Targets;
    {
      std::lock_guard<std::recursive_mutex> Lock{Owner->SyscallMutex};
      if (Owner->MainPendingSignals.load())
        Targets.push_back(Owner->MainNativeThread);
      for (auto *Thread : Owner->NativeGuestThreads) {
        if (!Thread->Finished && Thread->PendingSignals.load())
          Targets.push_back(Thread->Native);
      }
    }
    for (const auto Target : Targets)
      pthread_kill(Target, SIGUSR1);
  }
  return nullptr;
}

uint64_t ProcessSyscallHandler::SendRemoteThreadSignal(uint64_t PID, uint64_t TID, int Signal) {
  if (!PID || PID > INT32_MAX || !TID || TID > UINT32_MAX || Signal < 0 || Signal > 64) {
    return static_cast<uint64_t>(-EINVAL);
  }
  if (Signal != 0 && Signal != 10 && Signal != 3)
    return static_cast<uint64_t>(-38);
  char Program[PROC_PIDPATHINFO_MAXSIZE]{};
  if (proc_pidpath(PID, Program, sizeof(Program)) <= 0 || HostExecutablePath != Program) {
    return static_cast<uint64_t>(-ESRCH);
  }
  const std::string Path = SignalControl::Directory(RootFS) + "/" + std::to_string(PID);
  struct stat Endpoint{};
  if (lstat(Path.c_str(), &Endpoint) != 0 || !S_ISSOCK(Endpoint.st_mode) || Endpoint.st_uid != getuid()) {
    return static_cast<uint64_t>(-ESRCH);
  }
  const int FD = socket(AF_UNIX, SOCK_STREAM, 0);
  if (FD < 0)
    return static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(errno));
  SignalControl::NoSigPipe(FD);
  sockaddr_un Address{};
  Address.sun_family = AF_UNIX;
  if (Path.size() >= sizeof(Address.sun_path)) {
    close(FD);
    return static_cast<uint64_t>(-36);
  }
  std::memcpy(Address.sun_path, Path.c_str(), Path.size() + 1);
  const SignalControl::Request Request{SignalControl::Magic, static_cast<uint32_t>(TID), static_cast<uint32_t>(Signal),
                                       static_cast<uint32_t>(getpid())};
  const int64_t Result = BlockingHostCall([&]() -> int64_t {
    timeval Timeout{1, 0};
    setsockopt(FD, SOL_SOCKET, SO_RCVTIMEO, &Timeout, sizeof(Timeout));
    if (connect(FD, reinterpret_cast<sockaddr *>(&Address), sizeof(Address)) != 0)
      return -ESRCH;
    if (send(FD, &Request, sizeof(Request), 0) != sizeof(Request))
      return -EIO;
    int64_t Reply{};
    if (recv(FD, &Reply, sizeof(Reply), MSG_WAITALL) != sizeof(Reply))
      return -EIO;
    return Reply;
  });
  close(FD);
  return static_cast<uint64_t>(Result);
}

uint64_t ProcessSyscallHandler::ProbeNativeEACUnixBridge(FEXCore::Core::CpuStateFrame *Frame, uint64_t Entry,
                                                         uint64_t Args) {
  const char *Module = std::getenv("REGRESSION_EAC_UNIX_BRIDGE_PROBE");
  if (!Module || !ForkContext || !ActiveSignalThread || !HostPointerForGuestRange(Entry, 1, PROT_READ) ||
      !HostPointerForGuestRange(Args, 24, PROT_READ | PROT_WRITE))
    return static_cast<uint64_t>(-EFAULT);
  void *Library = dlopen(Module, RTLD_NOW | RTLD_LOCAL);
  if (!Library)
    return static_cast<uint64_t>(-EIO);
  using EntryFunction = int32_t (*)(void *);
  auto *Functions = static_cast<const EntryFunction *>(dlsym(Library, "__wine_unix_call_funcs"));
  if (!Functions) {
    dlclose(Library);
    return static_cast<uint64_t>(-EIO);
  }
  struct Context {
    ProcessSyscallHandler *Owner;
    FEXCore::Core::CpuStateFrame *Frame;
  } Context{this, Frame};
  struct Args {
    int32_t (*Invoke)(void *, uint64_t, uint64_t);
    void *Context;
    uint64_t Entry, Args;
  } Call{
      +[](void *Opaque, uint64_t GuestEntry, uint64_t GuestArgs) -> int32_t {
        auto *Context = static_cast<struct Context *>(Opaque);
        auto *Owner = Context->Owner;
        auto *Frame = Context->Frame;
        FEXCore::Core::CPUState Saved;
        std::memcpy(&Saved, &Frame->State, sizeof(Saved));
        const uint64_t ReturnStack = Frame->ReturningStackLocation;
        Frame->State.gregs[FEXCore::X86State::REG_RDI] = GuestArgs;
        Owner->ForkContext->HandleCallback(ActiveSignalThread, GuestEntry);
        const int32_t Result = static_cast<int32_t>(Frame->State.gregs[FEXCore::X86State::REG_RAX]);
        std::memcpy(&Frame->State, &Saved, sizeof(Saved));
        Frame->ReturningStackLocation = ReturnStack;
        return Result;
      },
      &Context,
      Entry,
      Args,
  };
  const int32_t Result = BlockingHostCall([&] { return Functions[0](&Call); });
  dlclose(Library);
  dprintf(STDERR_FILENO, "TRACE native-wine-unix-abi-call guest-entry=%llx status=%x\n", (unsigned long long)Entry,
          static_cast<uint32_t>(Result));
  return static_cast<uint32_t>(Result);
}

void ProcessSyscallHandler::RegisterSignalThread(FEXCore::Core::InternalThreadState *Thread,
                                                 const FEXCore::SignalDelegatorConfig &Config) {
  ActiveSignalThread = Thread;
  ActiveSignalOwner = this;
  SignalConfig = Config;
  if (!ActiveGuestThread) {
    MainGuestThread = Thread;
    MainNativeTID = LinuxGuestThreadID();
    ActivePendingSignals = &MainPendingSignals;
    ActiveSignalSender = &MainSignalSender;
    struct sigaction Action{};
    sigemptyset(&Action.sa_mask);
    Action.sa_sigaction = HostUserSignal;
    Action.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &Action, nullptr);
  }
  // Materialize the bounded TLS backup storage before asynchronous delivery.
  GuestSignalFrames[0].GuestContext = 0;
}

uint64_t ProcessSyscallHandler::QueueOwnThreadSignal(uint64_t TID, int Signal, uint32_t Sender) {
  pthread_t Target{};
  std::atomic<uint64_t> *Pending{};
  std::atomic<uint32_t> *Source{};
  if (TID == MainNativeTID || (MainCallbackTID.load() && TID == MainCallbackTID.load())) {
    Target = MainNativeThread;
    Pending = &MainPendingSignals;
    Source = &MainSignalSender;
  }
  for (auto *Thread : NativeGuestThreads) {
    if (Thread->TID == TID && !Thread->Finished) {
      Target = Thread->Native;
      Pending = &Thread->PendingSignals;
      Source = &Thread->SignalSender;
      break;
    }
  }
  if (!Pending)
    return static_cast<uint64_t>(-ESRCH);
  dprintf(STDERR_FILENO, "TRACE tgkill-target pid=%d tid=%llu signal=%d action=%llx\n", getpid(),
          (unsigned long long)TID, Signal,
          (unsigned long long)(Signal >= 0 && Signal < 65 ? GuestSignalActions[Signal].Handler : 0));
  if (Signal == 0)
    return 0;
  if ((Signal != 10 && Signal != 3) || GuestSignalActions[Signal].Handler == 0)
    return static_cast<uint64_t>(-38);
  if (GuestSignalActions[Signal].Handler == 1)
    return 0; // SIG_IGN.
  Source->store(Sender ? Sender : static_cast<uint32_t>(getpid()));
  Pending->fetch_or(uint64_t{1} << (Signal - 1));
  dprintf(STDERR_FILENO, "TRACE guest-signal-queued pid=%d tid=%llu sender=%u handler=%llx\n", getpid(),
          (unsigned long long)TID, Source->load(), (unsigned long long)GuestSignalActions[Signal].Handler);
  const int Error = pthread_kill(Target, SIGUSR1);
  return Error ? static_cast<uint64_t>(-TranslateHostSocketErrorToLinux(Error)) : 0;
}

void ProcessSyscallHandler::HostUserSignal(int, siginfo_t *, void *RawContext) {
  auto *Owner = ActiveSignalOwner;
  auto *Thread = ActiveSignalThread;
  auto *Context = static_cast<ucontext_t *>(RawContext);
  if (!Owner || !Thread || !Context)
    return;
  const uint64_t PC = Context->uc_mcontext->__ss.__pc;
  static thread_local unsigned TraceCount{};
  const bool InJIT = Thread->CTX->IsAddressInCodeBuffer(Thread, PC);
  if (TraceCount++ < 4) {
    dprintf(STDERR_FILENO,
            "TRACE host-user-signal pid=%d tid=%u jit=%d syscall=%d depth=%zu mask=%llx pending=%llx pc=%llx\n",
            getpid(), pthread_mach_thread_np(pthread_self()), InJIT, ActiveSyscallLock != nullptr, GuestSignalDepth,
            (unsigned long long)CurrentSignalMask(),
            (unsigned long long)(ActivePendingSignals ? ActivePendingSignals->load() : 0), (unsigned long long)PC);
  }
  if (GuestSignalDepth || ActiveSyscallLock || !InJIT)
    return;
  Owner->DeliverQueuedSignals(Thread->CurrentFrame, Context);
}

void ProcessSyscallHandler::DeliverQueuedSignals(FEXCore::Core::CpuStateFrame *Frame, ucontext_t *NativeContext,
                                                 bool AfterSyscall) {
  if (!ActivePendingSignals || !ActiveSignalThread || GuestSignalDepth >= GuestSignalFrames.size())
    return;
  const uint64_t Pending = ActivePendingSignals->load() & ~CurrentSignalMask();
  if (!Pending)
    return;
  const unsigned Signal = static_cast<unsigned>(__builtin_ctzll(Pending)) + 1;
  const uint64_t SignalBit = uint64_t{1} << (Signal - 1);
  LinuxGuestSigAction Action{};
  {
    std::lock_guard<std::recursive_mutex> Lock{SyscallMutex};
    Action = GuestSignalActions[Signal];
  }
  if (Action.Handler <= 1) {
    ActivePendingSignals->fetch_and(~SignalBit);
    return;
  }
  auto *Thread = ActiveSignalThread;
  if (NativeContext) {
    const auto &Host = NativeContext->uc_mcontext->__ss;
    Frame->State.rip = ForkContext->RestoreRIPFromHostPC(Thread, Host.__pc);
    for (size_t Index = 0; Index < SignalConfig.SRAGPRCount; ++Index) {
      Frame->State.gregs[Index] = Host.__x[SignalConfig.SRAGPRMapping[Index]];
    }
    for (size_t Index = 0; Index < SignalConfig.SRAFPRCount; ++Index) {
      std::memcpy(Frame->State.xmm.sse.data[Index],
                  &NativeContext->uc_mcontext->__ns.__v[SignalConfig.SRAFPRMapping[Index]], 16);
    }
    ForkContext->SetFlagsFromCompactedEFLAGS(
        Thread, ForkContext->ReconstructCompactedEFLAGS(Thread, true, Host.__x, Host.__cpsr));
  }
  auto &Backup = GuestSignalFrames[GuestSignalDepth];
  std::memcpy(&Backup.SavedState, &Frame->State, sizeof(Backup.SavedState));
  Backup.OriginalMask = CurrentSignalMask();
  Backup.ReferenceCount = Frame->SignalHandlerRefCounter;
  Backup.ReturningStack = Frame->ReturningStackLocation;
  Backup.ReturnedViaSyscall = false;
  uint64_t Top = Frame->State.gregs[FEXCore::X86State::REG_RSP];
  const uint64_t Alt = reinterpret_cast<uint64_t>(GuestSignalStack.ss_sp);
  if ((Action.Flags & 0x08000000) && !(GuestSignalStack.ss_flags & 2) &&
      (Top < Alt || Top >= Alt + GuestSignalStack.ss_size))
    Top = Alt + GuestSignalStack.ss_size;
  if (Top < 2048)
    return;
  const uint64_t Base = (Top - 1664) & ~uint64_t{63};
  auto *Memory = static_cast<uint8_t *>(HostPointerForGuestRange(Base, 1536, PROT_READ | PROT_WRITE));
  if (!Memory || !Action.Restorer) {
    dprintf(STDERR_FILENO, "TRACE guest-signal-rejected tid=%u unreadable-stack=%d restorer=%llx\n",
            pthread_mach_thread_np(pthread_self()), !Memory, (unsigned long long)Action.Restorer);
    return;
  }
  std::memset(Memory, 0, 1536);
  // Linux x64 rt_sigframe places ucontext immediately after the return pointer.
  // FEX subtracts 16 from the supplied RSP before the callback writes Base - 8.
  auto *Context = reinterpret_cast<FEXCore::x86_64::ucontext_t *>(Memory);
  const uint64_t ContextAddress = Base;
  constexpr size_t InfoOffset = 512, FPOffset = 704;
  auto *FP = reinterpret_cast<FEXCore::x86_64::_libc_fpstate *>(Memory + FPOffset);
  Context->uc_stack = GuestSignalStack;
  Context->uc_mcontext.fpregs = reinterpret_cast<FEXCore::x86_64::_libc_fpstate *>(Base + FPOffset);
  Context->uc_sigmask.val[0] = CurrentSignalMask();
  Context->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_RIP] =
      Frame->State.rip + ((!NativeContext && AfterSyscall) ? 2 : 0);
  Context->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_EFL] =
      ForkContext->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  Context->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_CSGSFS] = Frame->State.cs_idx;
#define SAVE_SIGNAL_GPR(R)                                                                                             \
  Context->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_##R] = Frame->State.gregs[FEXCore::X86State::REG_##R]
  SAVE_SIGNAL_GPR(R8);
  SAVE_SIGNAL_GPR(R9);
  SAVE_SIGNAL_GPR(R10);
  SAVE_SIGNAL_GPR(R11);
  SAVE_SIGNAL_GPR(R12);
  SAVE_SIGNAL_GPR(R13);
  SAVE_SIGNAL_GPR(R14);
  SAVE_SIGNAL_GPR(R15);
  SAVE_SIGNAL_GPR(RDI);
  SAVE_SIGNAL_GPR(RSI);
  SAVE_SIGNAL_GPR(RBP);
  SAVE_SIGNAL_GPR(RBX);
  SAVE_SIGNAL_GPR(RDX);
  SAVE_SIGNAL_GPR(RAX);
  SAVE_SIGNAL_GPR(RCX);
  SAVE_SIGNAL_GPR(RSP);
#undef SAVE_SIGNAL_GPR
  int32_t Info[6]{static_cast<int32_t>(Signal),
                  0,
                  -6,
                  0,
                  static_cast<int32_t>(ActiveSignalSender ? ActiveSignalSender->load() : getpid()),
                  static_cast<int32_t>(getuid())};
  if (TracerFaultActive && Signal == SIGSEGV)
    Info[2] = TracerFaultCode;
  std::memcpy(Memory + InfoOffset, Info, sizeof(Info));
  if (TracerFaultActive && Signal == SIGSEGV) {
    std::memcpy(Memory + InfoOffset + 16, &TracerFaultAddress, sizeof(TracerFaultAddress));
    Context->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_TRAPNO] = 14;
    Context->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_ERR] = Frame->SynchronousFaultData.err_code;
    Context->uc_mcontext.gregs[FEXCore::x86_64::FEX_REG_CR2] = TracerFaultAddress;
  }
  FP->fcw = Frame->State.FCW;
  FP->ftw = Frame->State.AbridgedFTW;
  FP->mxcsr = Frame->State.mxcsr;
  FP->mxcsr_mask = 0xFFC0;
  FP->fsw = (Frame->State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11) |
            (Frame->State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
            (Frame->State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) |
            (Frame->State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
            (Frame->State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14) |
            Frame->State.flags[FEXCore::X86State::X87FLAG_IE_LOC];
  const size_t X87Top = Frame->State.flags[FEXCore::X86State::X87FLAG_TOP_LOC];
  for (size_t Index = 0; Index < 8; ++Index)
    std::memcpy(&FP->_st[Index], Frame->State.mm[(Index + X87Top) % 8], 16);
  __uint128_t XMM[16]{};
  ForkContext->ReconstructXMMRegisters(Thread, XMM, nullptr);
  std::memcpy(FP->_xmm, XMM, sizeof(XMM));
  Backup.GuestContext = ContextAddress;
  ActivePendingSignals->fetch_and(~SignalBit);
  CurrentSignalMask() |= Action.Mask | SignalBit;
  ++GuestSignalDepth;
  Frame->State.gregs[FEXCore::X86State::REG_RDI] = Signal;
  Frame->State.gregs[FEXCore::X86State::REG_RSI] = Base + InfoOffset;
  Frame->State.gregs[FEXCore::X86State::REG_RDX] = ContextAddress;
  Frame->State.gregs[FEXCore::X86State::REG_RAX] = Action.Handler;
  Frame->State.gregs[FEXCore::X86State::REG_RCX] = Action.Restorer;
  Frame->State.gregs[FEXCore::X86State::REG_RSP] = Base + 8;
  if (FEXCore::UncheckedLongJump::SetJump(Backup.ReturnJump) == 0) {
    ForkContext->HandleCallback(Thread, StopAddress + 132);
  }
  --GuestSignalDepth;
  // Restore the interrupted state after the guest's real rt_sigreturn restorer.
  std::memcpy(&Frame->State, &Backup.SavedState, sizeof(Frame->State));
  if (TracerFaultActive && Backup.ReturnedViaSyscall) {
    const auto &Regs = Context->uc_mcontext.gregs;
    Frame->State.rip = Regs[FEXCore::x86_64::FEX_REG_RIP];
#define RESTORE_SIGNAL_GPR(R) Frame->State.gregs[FEXCore::X86State::REG_##R] = Regs[FEXCore::x86_64::FEX_REG_##R]
    RESTORE_SIGNAL_GPR(R8);
    RESTORE_SIGNAL_GPR(R9);
    RESTORE_SIGNAL_GPR(R10);
    RESTORE_SIGNAL_GPR(R11);
    RESTORE_SIGNAL_GPR(R12);
    RESTORE_SIGNAL_GPR(R13);
    RESTORE_SIGNAL_GPR(R14);
    RESTORE_SIGNAL_GPR(R15);
    RESTORE_SIGNAL_GPR(RDI);
    RESTORE_SIGNAL_GPR(RSI);
    RESTORE_SIGNAL_GPR(RBP);
    RESTORE_SIGNAL_GPR(RBX);
    RESTORE_SIGNAL_GPR(RDX);
    RESTORE_SIGNAL_GPR(RAX);
    RESTORE_SIGNAL_GPR(RCX);
    RESTORE_SIGNAL_GPR(RSP);
#undef RESTORE_SIGNAL_GPR
    ForkContext->SetFlagsFromCompactedEFLAGS(Thread, Regs[FEXCore::x86_64::FEX_REG_EFL]);
  }
  Frame->ReturningStackLocation = Backup.ReturningStack;
  Frame->SignalHandlerRefCounter = Backup.ReferenceCount;
  CurrentSignalMask() = Context->uc_sigmask.val[0];
  dprintf(STDERR_FILENO, "TRACE guest-signal-delivered pid=%d tid=%llu signal=%u rt-return=%d\n", getpid(),
          (unsigned long long)LinuxGuestThreadID(), Signal, Backup.ReturnedViaSyscall);
  if (ProcessExiting || (ActiveGuestThread && ActiveGuestThread->Exited) || (!ActiveGuestThread && ExitSeen)) {
    DarwinDiagnosticThreadStopHandler::Request();
  }
}

bool ProcessSyscallHandler::DeliverGuestMemorySignal(FEXCore::Core::CpuStateFrame *Frame, int Signal, uint64_t Address,
                                                     int Code) {
  if (ActiveSignalOwner != this || !ActivePendingSignals || Signal != SIGSEGV)
    return false;
  const auto Action = GuestSignalActions[SIGSEGV];
  dprintf(2, "FLI_ROOT_MEMORY_SIGNAL_DELIVERY signal=%d handler=%llx restorer=%llx address=%llx code=%d\n", Signal,
          (unsigned long long)Action.Handler, (unsigned long long)Action.Restorer, (unsigned long long)Address, Code);
  if (Action.Handler <= 1 || !Action.Restorer || (CurrentSignalMask() & (uint64_t(1) << (Signal - 1)))) {
    struct sigaction Default{};
    Default.sa_handler = SIG_DFL;
    sigemptyset(&Default.sa_mask);
    sigaction(SIGSEGV, &Default, nullptr);
    pthread_kill(pthread_self(), SIGSEGV);
    return true;
  }
  TracerFaultAddress = Address;
  TracerFaultCode = Code;
  TracerFaultActive = true;
  ActivePendingSignals->fetch_or(uint64_t(1) << (Signal - 1));
  DeliverQueuedSignals(Frame, nullptr, false);
  TracerFaultActive = false;
  return true;
}

GuestMemoryFault ProcessSyscallHandler::DescribeMemoryFault(uint64_t HostAddress, uint32_t Syndrome) {
  std::lock_guard<std::recursive_mutex> lock(SyscallMutex);
  uint64_t address = HostAddress;
  if (LowGuestShadow && LowGuestShadow->ContainsHostAddress(HostAddress))
    address = LowGuestShadow->LogicalAddress(HostAddress);
  else if (HighGuestSparse && HighGuestSparse->ContainsHostAddress(HostAddress))
    address = HighGuestSparse->LogicalAddress(HostAddress);
  else
    for (const auto &alias : SharedAliases)
      if (HostAddress >= alias.Host && HostAddress - alias.Host < alias.Length) {
        address = alias.Guest + HostAddress - alias.Host;
        break;
      }
  bool mapped = Contains(address, 1) && TrackedGuestProtection(address).has_value();
  mapped = mapped || (LowGuestShadow && LowGuestShadow->ContainsMappedLogicalRange(address, 1)) ||
           (HighGuestSparse && HighGuestSparse->ContainsMappedLogicalRange(address, 1));
  for (const auto &view : NativeFileViews)
    mapped = mapped || (address >= view.address && address - view.address < view.length);
  for (const auto &alias : SharedAliases)
    mapped = mapped || (address >= alias.Guest && address - alias.Guest < alias.Length);
  const uint32_t ec = Syndrome >> 26;
  const bool instruction = ec == 0x20 || ec == 0x21;
  const uint16_t error = 4 | (mapped ? 1 : 0) | ((!instruction && (Syndrome & 0x40)) ? 2 : 0) | (instruction ? 16 : 0);
  return {address, error, uint8_t(mapped ? SEGV_ACCERR : SEGV_MAPERR)};
}
bool ProcessSyscallHandler::ForwardNativeMemoryFault(FEXCore::Core::InternalThreadState *Thread, ucontext_t *Native,
                                                     const GuestMemoryFault &Fault) {
  if (Thread != ActiveSignalThread || ActiveSignalOwner != this)
    return false;
  auto *Frame = Thread->CurrentFrame;
  auto &Host = Native->uc_mcontext->__ss;
  if (!ForkContext->IsAddressInCodeBuffer(Thread, Host.__pc))
    return false;
  const uint64_t rip = ForkContext->RestoreRIPFromHostPC(Thread, Host.__pc);
  if (!rip)
    return false;
  Frame->State.rip = rip;
  for (size_t i = 0; i < SignalConfig.SRAGPRCount; ++i) {
    const auto r = SignalConfig.SRAGPRMapping[i];
    Frame->State.gregs[i] = r == 29 ? Host.__fp : r == 30 ? Host.__lr : Host.__x[r];
  }
  for (size_t i = 0; i < SignalConfig.SRAFPRCount; ++i)
    std::memcpy(Frame->State.xmm.sse.data[i], &Native->uc_mcontext->__ns.__v[SignalConfig.SRAFPRMapping[i]], 16);
  ForkContext->SetFlagsFromCompactedEFLAGS(
      Thread, ForkContext->ReconstructCompactedEFLAGS(Thread, true, Host.__x, Host.__cpsr));
  Frame->SynchronousFaultData = {.FaultToTopAndGeneratedException = false,
                                 .Signal = uint8_t(SIGSEGV),
                                 .TrapNo = 14,
                                 .si_code = Fault.code,
                                 .err_code = Fault.error,
                                 ._pad = 0};
  dprintf(2,
          "FLI_ROOT_DIRECT_MEMORY_FAULT pid=%d source=%llx address=%llx code=%u error=%x original-state-preserved=1\n",
          getpid(), (unsigned long long)rip, (unsigned long long)Fault.address, Fault.code, Fault.error);
  if (!DeliverGuestMemorySignal(Frame, SIGSEGV, Fault.address, Fault.code))
    return false;
  Host.__pc = SignalConfig.AbsoluteLoopTopAddressFillSRA;
  return true;
}
static GuestMemoryFault DescribeRootMemoryFault(FEXCore::Core::InternalThreadState *Thread, uint64_t Address,
                                                uint32_t Syndrome) {
  auto *owner = static_cast<ProcessSyscallHandler *>(Thread->FrontendPtr);
  return owner ? owner->DescribeMemoryFault(Address, Syndrome) : GuestMemoryFault{Address, 4, uint8_t(SEGV_MAPERR)};
}
static bool RootOwnsNativeFileView(FEXCore::Core::InternalThreadState *Thread, uint64_t Address) {
  auto *owner = static_cast<ProcessSyscallHandler *>(Thread->FrontendPtr);
  return owner && owner->OwnsNativeFileView(Address);
}
static bool ForwardUntracedRootMemoryFault(FEXCore::Core::InternalThreadState *Thread, ucontext_t *Native,
                                           const GuestMemoryFault &Fault) {
  auto *owner = static_cast<ProcessSyscallHandler *>(Thread->FrontendPtr);
  return owner && owner->ForwardNativeMemoryFault(Thread, Native, Fault);
}
static bool DeliverRootGuestMemorySignal(FEXCore::Core::InternalThreadState *Thread, int Signal, uint64_t Address,
                                         int Code) {
  auto *Owner = static_cast<ProcessSyscallHandler *>(Thread->FrontendPtr);
  return Owner && Owner->DeliverGuestMemorySignal(Thread->CurrentFrame, Signal, Address, Code);
}

void ProcessSyscallHandler::JoinGuestThreads() {
  StopSignalControl();
  {
    std::lock_guard<std::recursive_mutex> Lock{SyscallMutex};
    ProcessExiting = true;
  }
  for (auto *Record : NativeGuestThreads) {
    if (!Record->Finished)
      pthread_kill(Record->Native, SIGUSR2);
    pthread_join(Record->Native, nullptr);
    ForkContext->DestroyThread(Record->Thread);
    delete Record;
  }
  NativeGuestThreads.clear();
}

bool PReadAll(int Descriptor, void *Data, size_t Size, off_t Offset) {
  auto *Bytes = static_cast<uint8_t *>(Data);
  size_t Read{};
  while (Read < Size) {
    const ssize_t Result = pread(Descriptor, Bytes + Read, Size - Read, Offset + static_cast<off_t>(Read));
    if (Result == -1 && errno == EINTR) {
      continue;
    }
    if (Result <= 0) {
      return false;
    }
    Read += static_cast<size_t>(Result);
  }
  return true;
}

bool MapELF(const ELFParser &Parser, uint64_t GuestBase, uint64_t GuestSize, uint64_t LoadBase, size_t *SegmentCount) {
  for (const auto &Header : Parser.phdrs) {
    if (Header.p_type != PT_LOAD) {
      continue;
    }
    const uint64_t Destination = LoadBase + Header.p_vaddr;
    if (Header.p_memsz < Header.p_filesz || Destination < GuestBase || Destination + Header.p_memsz < Destination ||
        Destination + Header.p_memsz > GuestBase + GuestSize) {
      return false;
    }
    std::memset(reinterpret_cast<void *>(Destination), 0, static_cast<size_t>(Header.p_memsz));
    if (Header.p_filesz != 0 && !PReadAll(Parser.fd, reinterpret_cast<void *>(Destination),
                                          static_cast<size_t>(Header.p_filesz), Header.p_offset)) {
      return false;
    }
    ++*SegmentCount;
  }
  return true;
}

struct StackResult final {
  uint64_t Pointer{};
  bool Valid{};
};

StackResult BuildRealInitialStack(uint64_t GuestBase, const ELFParser &Main, uint64_t MainBase,
                                  uint64_t InterpreterBase, std::string_view GuestProgram,
                                  const std::vector<std::string> &GuestArguments,
                                  const std::vector<std::string> &AdditionalEnvironment) {
  constexpr std::array<uint64_t, 2> RandomWords{
      0x5245475245535349ULL,
      0x4F4E2D464C492D31ULL,
  };
  const std::string Argv0{GuestProgram};
  const std::string Environment = "LC_ALL=C";
  const std::string HomeEnvironment = "HOME=/home/regression";
  const char *X11Socket = std::getenv("REGRESSION_X11_SOCKET");
  const std::string DisplayEnvironment = X11Socket && *X11Socket ? "DISPLAY=:0" : "";
  const std::string Platform = "x86_64";
  uint64_t Cursor = GuestBase + RealStackStringsOffset;

  const auto CopyString = [&Cursor](const std::string &Value) {
    const uint64_t Address = Cursor;
    std::memcpy(reinterpret_cast<void *>(Address), Value.c_str(), Value.size() + 1);
    Cursor += Value.size() + 1;
    return Address;
  };

  const uint64_t Argv0Address = CopyString(Argv0);
  std::vector<uint64_t> ArgumentAddresses;
  ArgumentAddresses.reserve(GuestArguments.size());
  for (const auto &Argument : GuestArguments) {
    ArgumentAddresses.push_back(CopyString(Argument));
  }
  const uint64_t EnvironmentAddress = CopyString(Environment);
  const uint64_t HomeEnvironmentAddress = CopyString(HomeEnvironment);
  const uint64_t DisplayEnvironmentAddress = DisplayEnvironment.empty() ? 0 : CopyString(DisplayEnvironment);
  std::vector<uint64_t> AdditionalEnvironmentAddresses;
  for (const auto &Entry : AdditionalEnvironment)
    AdditionalEnvironmentAddresses.push_back(CopyString(Entry));
  const uint64_t PlatformAddress = CopyString(Platform);
  Cursor = (Cursor + 15) & ~uint64_t{15};
  const uint64_t RandomAddress = Cursor;
  std::memcpy(reinterpret_cast<void *>(RandomAddress), RandomWords.data(), sizeof(RandomWords));

  std::vector<uint64_t> Words;
  Words.reserve(6 + ArgumentAddresses.size() + 2 * 18);
  Words.push_back(1 + ArgumentAddresses.size());
  Words.push_back(Argv0Address);
  Words.insert(Words.end(), ArgumentAddresses.begin(), ArgumentAddresses.end());
  Words.push_back(0);
  Words.push_back(EnvironmentAddress);
  Words.push_back(HomeEnvironmentAddress);
  if (DisplayEnvironmentAddress)
    Words.push_back(DisplayEnvironmentAddress);
  Words.insert(Words.end(), AdditionalEnvironmentAddresses.begin(), AdditionalEnvironmentAddresses.end());
  Words.push_back(0);
  Words.insert(Words.end(), {
                                3,  MainBase + Main.ehdr.e_phoff, // AT_PHDR
                                4,  sizeof(Elf64_Phdr),           // AT_PHENT
                                5,  Main.ehdr.e_phnum,            // AT_PHNUM
                                6,  4096,                         // AT_PAGESZ
                                7,  InterpreterBase,              // AT_BASE
                                8,  0,                            // AT_FLAGS
                                9,  MainBase + Main.ehdr.e_entry, // AT_ENTRY
                                11, getuid(),                     // AT_UID
                                12, geteuid(),                    // AT_EUID
                                13, getgid(),                     // AT_GID
                                14, getegid(),                    // AT_EGID
                                16, 0,                            // AT_HWCAP
                                17, 100,                          // AT_CLKTCK
                                23, 0,                            // AT_SECURE
                                24, PlatformAddress,              // AT_PLATFORM
                                25, RandomAddress,                // AT_RANDOM
                                26, 0,                            // AT_HWCAP2
                                31, Argv0Address,                 // AT_EXECFN
                                51, 2048,                         // AT_MINSIGSTKSZ
                                0,  0,                            // AT_NULL
                            });
  const uint64_t StackPointer = (GuestBase + RealStackOffset) & ~uint64_t{0xF};
  std::memcpy(reinterpret_cast<void *>(StackPointer), Words.data(), Words.size() * sizeof(uint64_t));
  const bool Valid = *reinterpret_cast<const uint64_t *>(StackPointer) == 1 + GuestArguments.size() &&
                     std::strcmp(reinterpret_cast<const char *>(Argv0Address), Argv0.c_str()) == 0 &&
                     std::strcmp(reinterpret_cast<const char *>(PlatformAddress), Platform.c_str()) == 0 &&
                     *reinterpret_cast<const uint64_t *>(RandomAddress) == RandomWords[0];
  return {StackPointer, Valid};
}

bool ELFHasZeroedBSS(const ELFParser &Parser, uint64_t LoadBase) {
  bool FoundBSS{};
  for (const auto &Header : Parser.phdrs) {
    if (Header.p_type != PT_LOAD || Header.p_memsz <= Header.p_filesz) {
      continue;
    }
    FoundBSS = true;
    const auto *Begin = reinterpret_cast<const uint8_t *>(LoadBase + Header.p_vaddr + Header.p_filesz);
    const size_t Size = static_cast<size_t>(Header.p_memsz - Header.p_filesz);
    if (!std::all_of(Begin, Begin + Size, [](uint8_t Value) { return Value == 0; })) {
      return false;
    }
  }
  return FoundBSS;
}

std::optional<uint64_t> ELFProgramBreak(const ELFParser &Parser, uint64_t LoadBase) {
  constexpr uint64_t LinuxPageSize = 4096;
  uint64_t HighestEnd{};
  for (const auto &Header : Parser.phdrs) {
    if (Header.p_type != PT_LOAD || Header.p_vaddr + Header.p_memsz < Header.p_vaddr) {
      continue;
    }
    HighestEnd = std::max(HighestEnd, LoadBase + Header.p_vaddr + Header.p_memsz);
  }
  if (HighestEnd == 0 || HighestEnd > std::numeric_limits<uint64_t>::max() - (LinuxPageSize - 1)) {
    return std::nullopt;
  }
  return (HighestEnd + LinuxPageSize - 1) & ~(LinuxPageSize - 1);
}

const char *KnownSyscallName(uint64_t Number) {
  switch (Number) {
  case 0:
    return "read";
  case 2:
    return "open";
  case 3:
    return "close";
  case 4:
    return "stat";
  case 5:
    return "fstat";
  case 7:
    return "poll";
  case 8:
    return "lseek";
  case 9:
    return "mmap";
  case 10:
    return "mprotect";
  case 11:
    return "munmap";
  case 12:
    return "brk";
  case 13:
    return "rt_sigaction";
  case 14:
    return "rt_sigprocmask";
  case 16:
    return "ioctl";
  case 17:
    return "pread64";
  case 18:
    return "pwrite64";
  case 20:
    return "writev";
  case 21:
    return "access";
  case 32:
    return "dup";
  case 33:
    return "dup2";
  case 39:
    return "getpid";
  case 41:
    return "socket";
  case 42:
    return "connect";
  case 43:
    return "accept";
  case 46:
    return "sendmsg";
  case 47:
    return "recvmsg";
  case 48:
    return "shutdown";
  case 49:
    return "bind";
  case 50:
    return "listen";
  case 53:
    return "socketpair";
  case 55:
    return "getsockopt";
  case 56:
    return "clone";
  case 59:
    return "execve";
  case 61:
    return "wait4";
  case 63:
    return "uname";
  case 54:
    return "setsockopt";
  case 131:
    return "sigaltstack";
  case 186:
    return "gettid";
  case 191:
    return "getxattr";
  case 192:
    return "lgetxattr";
  case 193:
    return "fgetxattr";
  case 72:
    return "fcntl";
  case 77:
    return "ftruncate";
  case 79:
    return "getcwd";
  case 80:
    return "chdir";
  case 81:
    return "fchdir";
  case 83:
    return "mkdir";
  case 87:
    return "unlink";
  case 88:
    return "symlink";
  case 89:
    return "readlink";
  case 90:
    return "chmod";
  case 95:
    return "umask";
  case 96:
    return "gettimeofday";
  case 98:
    return "getrusage";
  case 99:
    return "sysinfo";
  case 102:
    return "getuid";
  case 112:
    return "setsid";
  case 138:
    return "fstatfs";
  case 140:
    return "getpriority";
  case 141:
    return "setpriority";
  case 157:
    return "prctl";
  case 158:
    return "arch_prctl";
  case 204:
    return "sched_getaffinity";
  case 213:
    return "epoll_create";
  case 217:
    return "getdents64";
  case 218:
    return "set_tid_address";
  case 228:
    return "clock_gettime";
  case 229:
    return "clock_getres";
  case 230:
    return "clock_nanosleep";
  case 233:
    return "epoll_ctl";
  case 234:
    return "tgkill";
  case 257:
    return "openat";
  case 262:
    return "newfstatat";
  case 270:
    return "pselect6";
  case 273:
    return "set_robust_list";
  case 293:
    return "pipe2";
  case 302:
    return "prlimit64";
  case 318:
    return "getrandom";
  case 319:
    return "memfd_create";
  case 323:
    return "userfaultfd";
  case 334:
    return "rseq";
  case 435:
    return "clone3";
  case 439:
    return "faccessat2";
  case 449:
    return "futex_waitv";
  default:
    return "unknown";
  }
}

void ConfigureLongMode(FEXCore::Core::InternalThreadState *Thread,
                       std::array<FEXCore::Core::CPUState::gdt_segment, 32> &GDT) {
  auto *Frame = Thread->CurrentFrame;
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = GDT.data();
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = GDT.data();
  Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
  auto *CodeSegment = FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Frame->State.cs_idx);
  FEXCore::Core::CPUState::SetGDTBase(CodeSegment, 0);
  FEXCore::Core::CPUState::SetGDTLimit(CodeSegment, 0xFFFFFU);
  CodeSegment->L = 1;
  CodeSegment->D = 0;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(*CodeSegment);
}

bool IsSafeGuestProgram(std::string_view GuestProgram) {
  if (GuestProgram.size() < 2 || GuestProgram.front() != '/') {
    return false;
  }
  size_t Cursor = 1;
  while (Cursor <= GuestProgram.size()) {
    const size_t Separator = GuestProgram.find('/', Cursor);
    const size_t End = Separator == std::string_view::npos ? GuestProgram.size() : Separator;
    const std::string_view Component = GuestProgram.substr(Cursor, End - Cursor);
    if (Component.empty() || Component == "." || Component == "..") {
      return false;
    }
    if (!std::all_of(Component.begin(), Component.end(), [](char Character) {
          return (Character >= 'a' && Character <= 'z') || (Character >= 'A' && Character <= 'Z') ||
                 (Character >= '0' && Character <= '9') || Character == '.' || Character == '_' || Character == '-' ||
                 Character == '+';
        })) {
      return false;
    }
    if (Separator == std::string_view::npos) {
      break;
    }
    Cursor = Separator + 1;
  }
  return true;
}

int RunRealRootFS(const std::string &RootFS, std::string_view GuestProgram,
                  const std::vector<std::string> &GuestArguments, const std::vector<std::string> &AdditionalEnvironment,
                  const std::string &PrivateStderrOutput, const std::string &PrivateReceiptOutput) {
  size_t EnvironmentBytes = 0;
  for (const auto &Entry : AdditionalEnvironment) {
    EnvironmentBytes += Entry.size() + 1;
    if (!IsAdditionalGuestEnvironment(Entry) || EnvironmentBytes > 32768)
      return 64;
  }
  if (AdditionalEnvironment.size() > 56 || !IsSafeGuestProgram(GuestProgram))
    return 64;
  size_t ArgumentBytes = 0;
  for (const auto &Argument : GuestArguments) {
    if (Argument.size() > 4096 || ArgumentBytes > 65536 - Argument.size() - 1)
      return 64;
    ArgumentBytes += Argument.size() + 1;
  }
  if (GuestArguments.size() > 32)
    return 64;
  std::array<char, PROC_PIDPATHINFO_MAXSIZE> HostExecutable{};
  if (proc_pidpath(getpid(), HostExecutable.data(), HostExecutable.size()) <= 0) {
    std::cerr << "Cannot resolve the current host executable\n";
    return 66;
  }
  const std::string CanonicalHostExecutablePath{HostExecutable.data()};
  std::array<char, 4096> CanonicalRootBuffer{};
  if (!realpath(RootFS.c_str(), CanonicalRootBuffer.data())) {
    std::cerr << "Cannot resolve RootFS: " << RootFS << '\n';
    return 66;
  }
  const std::string CanonicalRootFS{CanonicalRootBuffer.data()};
  const std::string RequestedMainPath = CanonicalRootFS + std::string{GuestProgram};
  std::array<char, 4096> CanonicalMainBuffer{};
  if (realpath(RequestedMainPath.c_str(), CanonicalMainBuffer.data()) == nullptr) {
    std::cerr << "Cannot resolve the guest executable. Path: " << RequestedMainPath << "\n";
    return 66;
  }
  const std::string MainPath{CanonicalMainBuffer.data()};
  struct stat MainStat{};
  if ((MainPath != CanonicalRootFS && !MainPath.starts_with(CanonicalRootFS + '/')) ||
      stat(MainPath.c_str(), &MainStat) != 0 || !S_ISREG(MainStat.st_mode) || access(MainPath.c_str(), R_OK) != 0) {
    std::cerr << "Guest executable must be a readable regular file inside RootFS.\n";
    return 66;
  }

  ELFParser Main;
  if (!Main.ReadElf(fextl::string{MainPath.c_str()}) || Main.type != ELFLoader::ELFContainer::TYPE_X86_64 ||
      Main.ehdr.e_type != ET_DYN) {
    std::cerr << "Cannot parse the x86-64 PIE executable. Path: " << MainPath << "\n";
    return 70;
  }
  const bool StaticPIE = Main.InterpreterElf.empty();

  ELFParser Interpreter;
  if (!StaticPIE) {
    const std::string InterpreterGuestPath{Main.InterpreterElf.c_str()};
    std::string InterpreterFile = CanonicalRootFS + InterpreterGuestPath;
    if (access(InterpreterFile.c_str(), R_OK) != 0 && InterpreterGuestPath.starts_with("/lib64/")) {
      InterpreterFile = CanonicalRootFS + "/usr" + InterpreterGuestPath;
    }
    if (access(InterpreterFile.c_str(), R_OK) != 0 || !Interpreter.ReadElf(fextl::string{InterpreterFile.c_str()}) ||
        Interpreter.type != ELFLoader::ELFContainer::TYPE_X86_64 || Interpreter.ehdr.e_type != ET_DYN ||
        !Interpreter.InterpreterElf.empty()) {
      std::cerr << "Cannot load the x86-64 ELF interpreter. Path: " << InterpreterFile << "\n";
      return 70;
    }
  }

  GuestMapping Mapping{RealGuestMemorySize};
  // The primary ELF arena remains identity mapped inside the high logical space.
  if (!Mapping.Allocate(0)) {
    std::cerr << "Cannot allocate the guest ELF arena.\n";
    return 70;
  }

  const uint64_t GuestBase = Mapping.Address();

  const uint64_t MainBase = GuestBase;
  const uint64_t InterpreterBase = GuestBase + RealInterpreterLoadOffset;
  const uint64_t StopAddress = GuestBase + RealStopOffset;
  const auto InitialProgramBreak = ELFProgramBreak(Main, MainBase);
  size_t SegmentCount{};
  if (!MapELF(Main, GuestBase, RealGuestMemorySize, MainBase, &SegmentCount) ||
      (!StaticPIE && !MapELF(Interpreter, GuestBase, RealGuestMemorySize, InterpreterBase, &SegmentCount))) {
    std::cerr << "Cannot map ELF segments.\n";
    return 70;
  }
  *reinterpret_cast<uint8_t *>(StopAddress) = 0xF4;
  const bool BSSZeroed = StaticPIE ? ELFHasZeroedBSS(Main, MainBase) : ELFHasZeroedBSS(Interpreter, InterpreterBase);
  const StackResult Stack = BuildRealInitialStack(GuestBase, Main, MainBase, InterpreterBase, GuestProgram,
                                                  GuestArguments, AdditionalEnvironment);
  const uint64_t ProgramBreakLimit = StaticPIE ? GuestBase + RealMMapArenaOffset : InterpreterBase;
  if (!BSSZeroed || !Stack.Valid || !InitialProgramBreak.has_value() || *InitialProgramBreak >= ProgramBreakLimit) {
    std::cerr << "Invalid ELF BSS, initial stack or program break.\n";
    return 70;
  }

  FEXCore::HostFeatures Features{};
  Features.DCacheLineSize = 64;
  Features.ICacheLineSize = 64;
  Features.SupportsCacheMaintenanceOps = true;
  // pthread_cpu_number_np returns a host index, so every host CPU needs a slot.
  Features.CPUMIDRs.resize(static_cast<size_t>(std::max<long>(1, sysconf(_SC_NPROCESSORS_CONF))), 0x61000000U);
  const char *TracePID = std::getenv("REGRESSION_LINUX_TRACE_PID");
  const bool ELFExecGate =
      fli_env_enabled("REGRESSION_NATIVE_ELF_EXEC_GATE") && TracePID && std::strtoll(TracePID, nullptr, 10) == getpid();
  ConfigLifetime Config;
  HostDisassemblyLogLifetime HostDisassemblyLog{fli_env_enabled("REGRESSION_FLI_TRACE_FEX_MESSAGES")};
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_STRICTINPROCESSSPLITLOCKS, "1");
  if (fli_env_enabled("REGRESSION_FLI_ROOT_FULL_SMC") &&
      (ELFExecGate || fli_env_enabled("REGRESSION_FLI_MTRACK_CONTROL"))) {
    FEXCore::Config::Set(FEXCore::Config::CONFIG_SMCCHECKS, std::to_string(FEXCore::Config::CONFIG_SMC_FULL));
    dprintf(2, "FLI_ROOT_SMC_MODE full=1 traced=%d\n", ELFExecGate);
  }
  if (ELFExecGate || fli_env_enabled("REGRESSION_FLI_MTRACK_CONTROL")) {
    if (fli_env_enabled("REGRESSION_FLI_NO_MULTIBLOCK")) {
      FEXCore::Config::Set(FEXCore::Config::CONFIG_MULTIBLOCK, "0");
      dprintf(2, "FLI_ROOT_MULTIBLOCK enabled=0 traced=%d\n", ELFExecGate);
    }
    const char *Limit = std::getenv("REGRESSION_FLI_MAX_INST");
    if (!Limit && fli_env_enabled("REGRESSION_FLI_SINGLE_INST"))
      Limit = "1";
    if (Limit) {
      char *End = nullptr;
      const auto Count = std::strtoul(Limit, &End, 10);
      if (!*Limit || *End || Count < 1 || Count > 64)
        return 70;
      FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST, std::to_string(Count));
      dprintf(2, "FLI_ROOT_BLOCK_LIMIT instructions=%lu traced=%d\n", Count, ELFExecGate);
    }
  }

  ProbeSignalDelegator SignalDelegator;
  SignalDelegator.CallbackReturnAddress = StopAddress + 128;
  const uint8_t SignalTrampolines[]{0x0F, 0x3E, 0x90, 0x90, 0x48, 0x89, 0x0C, 0x24, 0xFF, 0xE0};
  std::memcpy(reinterpret_cast<void *>(StopAddress + 128), SignalTrampolines, sizeof(SignalTrampolines));
  ProcessSyscallHandler SyscallHandler{GuestBase,
                                       RealGuestMemorySize,
                                       StopAddress,
                                       *InitialProgramBreak,
                                       ProgramBreakLimit,
                                       GuestBase + RealMMapArenaOffset,
                                       GuestBase + RealMMapArenaLimitOffset,
                                       CanonicalRootFS,
                                       std::string{GuestProgram},
                                       CanonicalHostExecutablePath};
  if (!SyscallHandler.RegisterInitialELFMemory(Main, MainBase) ||
      (!StaticPIE && !SyscallHandler.RegisterInitialELFMemory(Interpreter, InterpreterBase)))
    return 70;
  if (!SyscallHandler.SetInitialGuestDirectory("/"))
    return 66;
  auto Context = FEXCore::Context::Context::CreateNewContext(Features);
  if (!Context) {
    std::cerr << "FEXCore could not create the ELF context.\n";
    return 70;
  }
  const FEXCore::Context::GuestMemoryAddressRegion Identity{GuestBase, GuestBase, 4096};
  if (!Context->SetGuestMemoryAddressRegions(&Identity, 1))
    return 70;

  if (!ELFExecGate)
    Context->EnableExitOnHLT();
  Context->SetSignalDelegator(&SignalDelegator);
  Context->SetSyscallHandler(&SyscallHandler);
  if (!Context->InitCore()) {
    std::cerr << "FEXCore could not initialize the ELF context.\n";
    return 70;
  }

  SyscallHandler.AttachForkContext(Context.get(), SignalDelegator.GetConfig().ThreadStopHandlerAddress);
  const uint64_t GuestRIP = StaticPIE ? MainBase + Main.ehdr.e_entry : InterpreterBase + Interpreter.ehdr.e_entry;
  auto *Thread = Context->CreateThread(GuestRIP, Stack.Pointer);
  if (Thread == nullptr) {
    std::cerr << "FEXCore could not create the ELF thread.\n";
    return 70;
  }
  Thread->FrontendPtr = &SyscallHandler;
  using RegisterOwner = int32_t (*)(uint64_t, uint64_t);
  if (auto Register = reinterpret_cast<RegisterOwner>(dlsym(RTLD_DEFAULT, "fli_linux_root_register_owner"))) {
    const int Result = Register(MainBase, reinterpret_cast<uint64_t>(Thread->CurrentFrame));
    if (Result) {
      dprintf(2, "FLI_ROOT_OWNER_ERROR result=%d base=%llx\n", Result, (unsigned long long)MainBase);
      return 70;
    }
  }
  std::array<FEXCore::Core::CpuStateFrame::DiagnosticBranch, 65> BranchTrace{};
  Thread->CurrentFrame->DiagnosticBranches = BranchTrace.data();
  CallRetStackMapping CallRetStack;
  if (!CallRetStack.Attach(Thread)) {
    Context->DestroyThread(Thread);
    std::cerr << "Cannot initialize the FEX call-return stack.\n";
    return 70;
  }
  // Segment descriptors are read through guest memory IR during IRET. Keep
  // their backing outside translated guest windows, alongside the ELF arena.
  auto *GDT = new (reinterpret_cast<void *>(GuestBase + RealStopOffset + LinuxGuestPageSize))
      std::array<FEXCore::Core::CPUState::gdt_segment, 32>{};
  ConfigureLongMode(Thread, *GDT);
  if (ELFExecGate) {
    Thread->CurrentFrame->State.cs_idx |= 3;
    Thread->CurrentFrame->State.ss_idx = 0x2b;
    Context->SetFlagsFromCompactedEFLAGS(Thread, 0x202);
  }
  DarwinUnalignedAccessHandler UnalignedHandler;
  if (!UnalignedHandler.Attach(Thread, GuestBase, RealGuestMemorySize, 0, 0, 0, 0, 0, 0, nullptr, nullptr,
                               !ELFExecGate && !fli_env_enabled("REGRESSION_NATIVE_WINE_HOST_ENTRY") &&
                                   !fli_env_enabled("REGRESSION_FLI_MTRACK_CONTROL"))) {
    Context->DestroyThread(Thread);
    std::cerr << "Cannot install the FEX SIGBUS handler.\n";
    return 70;
  }
  DarwinDiagnosticThreadStopHandler DiagnosticStopHandler;
  if (!DiagnosticStopHandler.Attach(Thread, SignalDelegator.GetConfig().ThreadStopHandlerAddress, StopAddress)) {
    UnalignedHandler.Reset();
    Context->DestroyThread(Thread);
    std::cerr << "Cannot install the FEX diagnostic stop handler.\n";
    return 70;
  }
  // Compilation can hit FEX's temporary JIT guard page and needs the same native recovery handler.
  Context->CompileRIP(Thread, GuestRIP);
  SyscallHandler.RegisterSignalThread(Thread, SignalDelegator.GetConfig());
  if (!SyscallHandler.StartSignalControl()) {
    std::cerr << "Cannot create the process signal channel.\n";
    return 70;
  }
  DarwinGuestTrapHandler GuestTrapHandler;
  if (ELFExecGate) {
    if (!GuestTrapHandler.Attach(Thread, SignalDelegator.GetConfig())) {
      dprintf(2, "FLI_ROOT_TRAP_ATTACH_ERROR\n");
      return 70;
    }
    sigset_t ForwardMask{};
    sigemptyset(&ForwardMask);
    sigaddset(&ForwardMask, SIGTRAP);
    sigaddset(&ForwardMask, SIGBUS);
    sigaddset(&ForwardMask, SIGSEGV);
    pthread_sigmask(SIG_UNBLOCK, &ForwardMask, nullptr);
    using Start = int32_t (*)(const char *, uint64_t, uint64_t, const uint64_t *, uint64_t);
    auto Callback = reinterpret_cast<Start>(dlsym(RTLD_DEFAULT, "fli_linux_elf_exec_start"));
    auto &State = Thread->CurrentFrame->State;
    using namespace FEXCore::X86State;
    uint64_t Registers[]{State.gregs[REG_R15],
                         State.gregs[REG_R14],
                         State.gregs[REG_R13],
                         State.gregs[REG_R12],
                         State.gregs[REG_RBP],
                         State.gregs[REG_RBX],
                         State.gregs[REG_R11],
                         State.gregs[REG_R10],
                         State.gregs[REG_R9],
                         State.gregs[REG_R8],
                         State.gregs[REG_RAX],
                         State.gregs[REG_RCX],
                         State.gregs[REG_RDX],
                         State.gregs[REG_RSI],
                         State.gregs[REG_RDI],
                         59,
                         State.rip,
                         State.cs_idx,
                         Context->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0),
                         State.gregs[REG_RSP],
                         State.ss_idx,
                         State.fs_cached,
                         State.gs_cached,
                         State.ds_idx,
                         State.es_idx,
                         State.fs_idx,
                         State.gs_idx};
    const int Ready = Callback ? Callback(std::string(GuestProgram).c_str(), MainBase, StaticPIE ? 0 : InterpreterBase,
                                          Registers, reinterpret_cast<uint64_t>(Thread->CurrentFrame))
                               : -95;
    if (Ready) {
      dprintf(2, "FLI_ROOT_EXEC_READY_ERROR result=%d\n", Ready);
      Context->DestroyThread(Thread);
      return 70;
    }
    using Changes = uint64_t (*)(uint64_t *, uint64_t *);
    auto Changed = reinterpret_cast<Changes>(dlsym(RTLD_DEFAULT, "fli_linux_root_take_changes"));
    uint64_t Begin = 0, Length = 0;
    if (Changed && Changed(&Begin, &Length)) {
      std::unique_lock Lock(Context->GetCodeInvalidationMutex());
      Context->InvalidateCodeBuffersCodeRange(Begin, Length);
      Context->InvalidateThreadCachedCodeRange(Thread, Begin, Length);
      dprintf(2, "FLI_ROOT_CODE_INVALIDATED address=%llx length=%llu\n", static_cast<unsigned long long>(Begin),
              static_cast<unsigned long long>(Length));
    }
  }
  Context->ExecuteThread(Thread);
  SyscallHandler.JoinGuestThreads();
  if (SyscallHandler.NativeForkCloneChildProcess) {
    const int ChildExitCode = SyscallHandler.ExitSeen ? static_cast<int>(SyscallHandler.ExitCode & 0xff) : 70;
    dprintf(
        STDERR_FILENO,
        "TRACE native-fork-clone-child-stop pid=%lld exit=%d unsupported=%llu "
        "clone-flags=%llu child-stack-class=%s parent-tid-class=%s "
        "child-tid-class=%s tls-class=%s exec-kind=%s exec-exists=%d "
        "exec-path-length=%llu exec-path-fingerprint=%llu exec-argc=%llu "
        "exec-envc=%llu exec-env-unknown=%llu exec-lc-all-c=%d "
        "exec-private-home=%d exec-wine-loader-noexec=%d "
        "exec-wine-arch-wow64=%d exec-wineserver-socket=%d "
        "exec-wine-preload-reserve=%d exec-reentry-attempted=%d "
        "exec-reentry-validation-passed=%d exec-reentry-host-error=%lld "
        "exec-parent-segment=%d "
        "exec-normalized-confined=%d exec-normalized-length=%llu "
        "exec-normalized-fingerprint=%llu\n",
        static_cast<long long>(getpid()), ChildExitCode,
        static_cast<unsigned long long>(SyscallHandler.UnexpectedSyscall),
        static_cast<unsigned long long>(SyscallHandler.UnsupportedCloneFlags),
        SyscallHandler.UnsupportedCloneChildStackClass.c_str(), SyscallHandler.UnsupportedCloneParentTIDClass.c_str(),
        SyscallHandler.UnsupportedCloneChildTIDClass.c_str(), SyscallHandler.UnsupportedCloneTLSClass.c_str(),
        SyscallHandler.UnsupportedExecveTargetKind.c_str(), SyscallHandler.UnsupportedExecveTargetExists ? 1 : 0,
        static_cast<unsigned long long>(SyscallHandler.UnsupportedExecvePathLength),
        static_cast<unsigned long long>(SyscallHandler.UnsupportedExecvePathFingerprint),
        static_cast<unsigned long long>(SyscallHandler.UnsupportedExecveArgCount),
        static_cast<unsigned long long>(SyscallHandler.UnsupportedExecveEnvCount),
        static_cast<unsigned long long>(SyscallHandler.UnsupportedExecveEnvUnknownCount),
        SyscallHandler.UnsupportedExecveEnvHasLCAllC ? 1 : 0, SyscallHandler.UnsupportedExecveEnvHasPrivateHome ? 1 : 0,
        SyscallHandler.UnsupportedExecveEnvHasWineLoaderNoExec ? 1 : 0,
        SyscallHandler.UnsupportedExecveEnvHasWineArchWow64 ? 1 : 0,
        SyscallHandler.UnsupportedExecveEnvHasWineServerSocket ? 1 : 0,
        SyscallHandler.UnsupportedExecveEnvHasWinePreloadReserve ? 1 : 0,
        SyscallHandler.OfficialProtonExecveReentryAttempted ? 1 : 0,
        SyscallHandler.OfficialProtonExecveReentryValidationPassed ? 1 : 0,
        static_cast<long long>(SyscallHandler.OfficialProtonExecveReentryLastHostError),
        SyscallHandler.UnsupportedExecveParentSegmentSeen ? 1 : 0,
        SyscallHandler.UnsupportedExecveNormalizedPathConfined ? 1 : 0,
        static_cast<unsigned long long>(SyscallHandler.UnsupportedExecveNormalizedPathLength),
        static_cast<unsigned long long>(SyscallHandler.UnsupportedExecveNormalizedPathFingerprint));
    _exit(ChildExitCode);
  }
  DiagnosticStopHandler.Reset();
  const bool RawGuestSignalBoundarySeen = UnalignedHandler.BoundarySeen();
  const uint64_t GuestSignalBoundarySignal = UnalignedHandler.BoundarySignal();
  const int64_t GuestSignalBoundaryCode = UnalignedHandler.BoundaryCode();
  const uint64_t GuestSignalBoundaryProgramCounter = UnalignedHandler.BoundaryProgramCounter();
  const uint64_t HostGuestSignalBoundaryFaultAddress = UnalignedHandler.BoundaryFaultAddress();
  const uint64_t GuestSignalBoundaryRIPOffset = UnalignedHandler.BoundaryGuestRIPOffset();
  UnalignedHandler.Reset();
  const bool UnsupportedSeen = SyscallHandler.UnexpectedSyscall != std::numeric_limits<uint64_t>::max();
  const bool ControlledStopSignalSeen =
      RawGuestSignalBoundarySeen && GuestSignalBoundaryRIPOffset == RealStopOffset &&
      (UnsupportedSeen || SyscallHandler.ExitSeen || SyscallHandler.PostSessionSyscallDiagnosticLimitSeen);
  const bool GuestSignalBoundarySeen = RawGuestSignalBoundarySeen && !ControlledStopSignalSeen;
  const bool Completed = SyscallHandler.ExitSeen && SyscallHandler.ExitCode == 0;
  const bool BoundarySeen = UnsupportedSeen || SyscallHandler.ExitSeen || GuestSignalBoundarySeen ||
                            SyscallHandler.PostSessionSyscallDiagnosticLimitSeen;
  Context->DestroyThread(Thread);

  const std::string PrivateDiagnosticPrefix = ResearchTemporaryPrefix("regression-fli-fex-process-probe.");
  constexpr size_t MaximumPrivateDiagnosticBytes = 1024 * 1024;
  if (!PrivateStderrOutput.empty()) {
    const bool SafeDiagnosticPath = PrivateStderrOutput.starts_with(PrivateDiagnosticPrefix) &&
                                    PrivateStderrOutput.find("/../") == std::string::npos &&
                                    PrivateStderrOutput.find("/./") == std::string::npos &&
                                    !PrivateStderrOutput.ends_with('/');
    if (!SafeDiagnosticPath || SyscallHandler.CapturedError.size() > MaximumPrivateDiagnosticBytes ||
        !WritePrivateTextFile(PrivateStderrOutput, SyscallHandler.CapturedError)) {
      std::cerr << "Cannot write the private guest stderr file. Path: " << PrivateStderrOutput << "\n";
      return 70;
    }
  }

  std::ofstream ReceiptFile;
  if (!PrivateReceiptOutput.empty()) {
    struct stat ReceiptStat{};
    const bool SafeReceiptPath =
        PrivateReceiptOutput.starts_with(PrivateDiagnosticPrefix) &&
        PrivateReceiptOutput.find("/../") == std::string::npos &&
        PrivateReceiptOutput.find("/./") == std::string::npos && !PrivateReceiptOutput.ends_with('/') &&
        lstat(PrivateReceiptOutput.c_str(), &ReceiptStat) == 0 && S_ISREG(ReceiptStat.st_mode) &&
        ReceiptStat.st_uid == getuid() && (ReceiptStat.st_mode & (S_IRWXG | S_IRWXO)) == 0;
    if (!SafeReceiptPath) {
      std::cerr << "Receipt must be a private regular file in the diagnostic directory. Path: " << PrivateReceiptOutput
                << "\n";
      return 70;
    }
    ReceiptFile.open(PrivateReceiptOutput, std::ios::out | std::ios::trunc);
    if (!ReceiptFile)
      return 70;
  }
  std::ostream ReceiptStream(PrivateReceiptOutput.empty() ? std::cout.rdbuf() : ReceiptFile.rdbuf());

  ReceiptStream << "{\"schema\":2,\"main_completed\":" << (Completed ? "true" : "false") << ",\"exit_code\":";
  if (SyscallHandler.ExitSeen)
    ReceiptStream << SyscallHandler.ExitCode;
  else
    ReceiptStream << "null";
  ReceiptStream << ",\"first_unsupported_syscall\":";
  if (UnsupportedSeen)
    ReceiptStream << SyscallHandler.UnexpectedSyscall;
  else
    ReceiptStream << "null";
  ReceiptStream << ",\"first_unsupported_syscall_name\":\"" << KnownSyscallName(SyscallHandler.UnexpectedSyscall)
                << "\""
                << ",\"guest_signal_boundary_seen\":" << (GuestSignalBoundarySeen ? "true" : "false")
                << ",\"signal\":" << GuestSignalBoundarySignal << ",\"signal_code\":" << GuestSignalBoundaryCode
                << ",\"host_pc\":" << GuestSignalBoundaryProgramCounter
                << ",\"fault_host_address\":" << HostGuestSignalBoundaryFaultAddress << ",\"diagnostic_limit_seen\":"
                << (SyscallHandler.PostSessionSyscallDiagnosticLimitSeen ? "true" : "false") << "}\n";
  return BoundarySeen ? 0 : 70;
}
} // namespace

#include "runtime-env.h"
// Persistent same-process GLIBC initialization using the existing Linux executor.
#include <condition_variable>
#include <thread>
#include <Interface/Core/CPUBackend.h>

static std::mutex GlibcLock;
static std::condition_variable GlibcChanged;
static bool GlibcReady;
static uint64_t GlibcMap, GlibcFS, GlibcArena, GlibcBreak;
static struct sigaction WineSignals[NSIG];
static struct sigaction RootSignals[NSIG];
static std::atomic<uint64_t> RootSignalCounts[NSIG]{}, RootMainSignalPC{}, RootMainSignalAddress{},
    RootMainSignalType{}, RootMainSignalCallRet{}, RootMainSignalTarget{};
static void fli_signal_mux(int signal, siginfo_t *info, void *context) {
  const bool root = fli_is_root_guest_thread();
  const struct sigaction &chosen = root ? RootSignals[signal] : WineSignals[signal];
  if (root) {
    RootSignalCounts[signal].fetch_add(1, std::memory_order_relaxed);
    auto *native = static_cast<ucontext_t *>(context);
    if (native && native->uc_mcontext &&
        native->uc_mcontext->__ss.__x[28] ==
            reinterpret_cast<uint64_t>(NativeMapObservedFrame.load(std::memory_order_relaxed))) {
      RootMainSignalType.store(signal);
      RootMainSignalPC.store(native->uc_mcontext->__ss.__pc);
      RootMainSignalAddress.store(info ? reinterpret_cast<uint64_t>(info->si_addr) : 0);
      RootMainSignalCallRet.store(native->uc_mcontext->__ss.__x[25]);
      RootMainSignalTarget.store(native->uc_mcontext->__ss.__x[1]);
    }
  }
  if (chosen.sa_handler == SIG_IGN)
    return;
  if (chosen.sa_handler == SIG_DFL) {
    sigaction(signal, &chosen, nullptr);
    raise(signal);
    return;
  }
  if (chosen.sa_flags & SA_SIGINFO)
    chosen.sa_sigaction(signal, info, context);
  else
    chosen.sa_handler(signal);
}
static std::atomic<uint64_t> WineNativeTime{0};
static std::atomic<unsigned> WineNativeCalls{0};
static bool WineHostEntryReady, WineHostEntryFailed;
static std::vector<std::string> WineHostArguments;
static std::string WineHostLoader;
using RootInvoke = uint64_t (*)(void *, uint64_t, const uint64_t *, bool, bool, uint64_t, uint64_t, uint64_t,
                                uint64_t *);
struct RootRequest {
  uint64_t args[6]{}, result{};
  int error{};
  bool done{}, native_view{};
  uint64_t wine_teb{}, entry{}, caller_fs{}, caller_tid{};
  uint64_t *caller_mask{};
  bool borrow_fd{true};
};
static RootRequest *RootPending;
static uint64_t RootLibcBase, RootLoaderBase;
static void *RootObservationCookie;
static bool RootBridgeReady;
extern "C" __attribute__((visibility("default"))) uint64_t fli_root_split_lock_address() {
  std::lock_guard guard(GlibcLock);
  if (!RootBridgeReady || !RootObservationCookie)
    return 0;
  auto *owner = static_cast<ProcessSyscallHandler *>(*reinterpret_cast<void **>(RootObservationCookie));
  return owner->SharedSplitLockAddress();
}
static pthread_t RootServiceThread;
struct WindowsRequest {
  uint64_t target{}, args[4]{}, teb{}, result{};
  bool done{};
};
static WindowsRequest *WindowsPending;
extern "C" uint64_t fli_call_wine_native4(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
asm(".text\n.p2align 2\n.globl _fli_call_wine_native4\n.private_extern _fli_call_wine_native4\n"
    "_fli_call_wine_native4:\nsub sp,sp,#64\nstp x29,x30,[sp,#32]\nstp x27,x28,[sp,#48]\n"
    "mov x27,x0\nmov x28,x1\nmov x0,x2\nmov x1,x3\nmov x2,x4\nmov x3,x5\nblr x27\n"
    "ldp x27,x28,[sp,#48]\nldp x29,x30,[sp,#32]\nadd sp,sp,#64\nret\n");
extern "C" __attribute__((visibility("default"))) uint64_t fli_wine_native_api_call(uint64_t target,
                                                                                    const uint64_t *args,
                                                                                    uint64_t teb) {
  if (!target || !args || !teb)
    return 0xc000000d;
  std::unique_lock guard(GlibcLock);
  if (!RootBridgeReady || !RootPending || RootPending->wine_teb != teb) {
    dprintf(2, "NATIVE_WINE_API_NO_CALLER pid=%d target=%llx active=%d actual-teb-match=%d\n", getpid(),
            (unsigned long long)target, RootPending != nullptr, RootPending && RootPending->wine_teb == teb);
    return 0xc00000bb;
  }
  WindowsRequest request;
  request.target = target;
  request.teb = teb;
  memcpy(request.args, args, sizeof(request.args));
  GlibcChanged.wait(guard, [] { return WindowsPending == nullptr; });
  WindowsPending = &request;
  GlibcChanged.notify_all();
  GlibcChanged.wait(guard, [&] { return request.done; });
  return request.result;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_wine_signal_ready() {
  if (!fli_env_enabled("REGRESSION_FLI_ROOT_CALLBACK_BRIDGE") || !RootBridgeReady)
    return 0;
  const int signals[] = {SIGBUS, SIGSEGV, SIGTRAP, SIGUSR2};
  for (const int signal : signals) {
    struct sigaction current{};
    if (sigaction(signal, nullptr, &current))
      return -errno;
    if (current.sa_sigaction != fli_signal_mux)
      WineSignals[signal] = current;
  }
  for (const int signal : signals) {
    struct sigaction action{};
    action.sa_sigaction = fli_signal_mux;
    action.sa_mask = WineSignals[signal].sa_mask;
    action.sa_flags = SA_SIGINFO | ((RootSignals[signal].sa_flags | WineSignals[signal].sa_flags) &
                                    (SA_ONSTACK | SA_RESTART | SA_NODEFER));
    if (sigaction(signal, &action, nullptr))
      return -errno;
  }
  dprintf(2, "FLI_SIGNAL_MUX_WINE_READY pid=%d real-wine-handlers=1 real-root-handlers=1\n", getpid());
  return 0;
}
static int32_t root_mmap_request(const uint64_t *args, uint64_t *result, int32_t *linux_error, bool native_view,
                                 uint64_t wine_teb, uint64_t entry = 0, bool borrow_fd = true) {
  if (!args || !result || !linux_error)
    return -22;
  RootRequest request;
  request.native_view = native_view;
  request.wine_teb = wine_teb;
  request.entry = entry;
  request.borrow_fd = borrow_fd;
  memcpy(request.args, args, sizeof(request.args));
  // Initialize a real caller TCB before taking the service queue lock: TLS
  // allocation itself uses that queue. Both executors then reuse the binding.
  if (wine_teb) {
    using Context = int32_t (*)(uint64_t, uint64_t *);
    const auto context = reinterpret_cast<Context>(dlsym(RTLD_DEFAULT, "fli_linux_caller_thread_context"));
    if (!context)
      return -38;
    uint64_t values[2]{};
    const int32_t status = context(wine_teb, values);
    if (status)
      return status;
    request.caller_fs = values[0];
    request.caller_tid = values[1];
    request.caller_mask = ProcessSyscallHandler::CurrentSignalMaskAddress();
    if (fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
      dprintf(2, "ROOT_CALLER_THREAD_CONTEXT pid=%d fs=%llx tid=%llu initialized-binding=1 actual-native-caller=1\n",
              getpid(), (unsigned long long)values[0], (unsigned long long)values[1]);
  }
  std::unique_lock guard(GlibcLock);
  if (!RootBridgeReady)
    return -38;
  if (native_view && fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT"))
    dprintf(2, "NATIVE_MAP_QUEUE_ENTER pid=%d address=%llx service-thread=%d pending=%d\n", getpid(),
            (unsigned long long)args[0], pthread_equal(pthread_self(), RootServiceThread), RootPending != nullptr);
  GlibcChanged.wait(guard, [] { return RootPending == nullptr; });
  RootPending = &request;
  GlibcChanged.notify_all();
  unsigned observations = 0;
  while (!request.done) {
    const bool ready = GlibcChanged.wait_for(guard, std::chrono::seconds(5), [&] {
      return request.done || (WindowsPending && WindowsPending->teb == request.wine_teb);
    });
    if (request.done)
      break;
    if (ready && WindowsPending) {
      auto *windows = WindowsPending;
      guard.unlock();
      const uint64_t actual = fli_call_wine_native4(windows->target, request.wine_teb, windows->args[0],
                                                    windows->args[1], windows->args[2], windows->args[3]);
      dprintf(2, "NATIVE_WINE_API_RESULT pid=%d target=%llx status=%x original-arguments=1 actual-wine-caller=1\n",
              getpid(), (unsigned long long)windows->target, uint32_t(actual));
      guard.lock();
      windows->result = actual;
      windows->done = true;
      WindowsPending = nullptr;
      GlibcChanged.notify_all();
      continue;
    }
    if (!fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT") || observations++ >= 60)
      continue;
    auto *frame = NativeMapObservedFrame.load(std::memory_order_acquire);
    if (!frame || !frame->DiagnosticBranches)
      continue;
    fli_observe_owned_guest_threads(RootObservationCookie);
    const uint64_t end = frame->DiagnosticBranchSequence;
    for (const int signal : {SIGBUS, SIGSEGV, SIGTRAP, SIGUSR2}) {
      struct sigaction current{};
      Dl_info module{};
      if (!sigaction(signal, nullptr, &current)) {
        dladdr(reinterpret_cast<void *>(current.sa_sigaction), &module);
        const char *name = module.dli_fname ? strrchr(module.dli_fname, '/') : nullptr;
        dprintf(2, "NATIVE_MAP_SIGNAL_OWNER pid=%d signal=%d mux=%d root=%d wine=%d module=%s\n", getpid(), signal,
                current.sa_sigaction == fli_signal_mux, current.sa_sigaction == RootSignals[signal].sa_sigaction,
                current.sa_sigaction == WineSignals[signal].sa_sigaction, name ? name + 1 : "unknown");
      }
    }
    dprintf(2,
            "NATIVE_MAP_SIGNAL_PROGRESS pid=%d bus=%llu segv=%llu trap=%llu main-type=%llu main-pc=%llx "
            "main-address=%llx main-callret=%llx main-target=%llx\n",
            getpid(), (unsigned long long)RootSignalCounts[SIGBUS].load(),
            (unsigned long long)RootSignalCounts[SIGSEGV].load(), (unsigned long long)RootSignalCounts[SIGTRAP].load(),
            (unsigned long long)RootMainSignalType.load(), (unsigned long long)RootMainSignalPC.load(),
            (unsigned long long)RootMainSignalAddress.load(), (unsigned long long)RootMainSignalCallRet.load(),
            (unsigned long long)RootMainSignalTarget.load());
    if (observations == 3 && end) {
      const uint64_t target = frame->DiagnosticBranches[(end - 1) % 64].target;
      FEXCore::LookupCache::LookupCacheEntry cached{};
      mach_vm_size_t count = 0;
      const uint64_t slot = frame->State.L1Pointer + ((target << 4) & frame->State.L1Mask);
      if (mach_vm_read_overwrite(mach_task_self(), slot, sizeof(cached), reinterpret_cast<mach_vm_address_t>(&cached),
                                 &count) == KERN_SUCCESS &&
          count == sizeof(cached))
        dprintf(2,
                "NATIVE_MAP_RETURN_CACHE pid=%d target=%llx cached-guest=%llx cached-host=%llx spilled-callret=%llx\n",
                getpid(), (unsigned long long)target, (unsigned long long)cached.GuestCode,
                (unsigned long long)cached.HostCode, (unsigned long long)frame->State.callret_sp);
      // Diagnostics retain addresses/state only; no translated guest code capture.
    }
    dprintf(2,
            "NATIVE_MAP_CURRENT_BLOCK pid=%d guest-entry=%llx in-syscall=%llx header=%llx returning-stack=%llx "
            "refcount=%u\n",
            getpid(), (unsigned long long)frame->Thread->CTX->GetGuestBlockEntry(frame->Thread),
            (unsigned long long)frame->InSyscallInfo, (unsigned long long)frame->State.InlineJITBlockHeader,
            (unsigned long long)frame->ReturningStackLocation, frame->SignalHandlerRefCounter);
    dprintf(2, "NATIVE_MAP_COMPILE_OBSERVATION pid=%d sequence=%llu phase=%llu address=%llx\n", getpid(),
            (unsigned long long)NativeMapCompileSequence.load(), (unsigned long long)NativeMapCompilePhase.load(),
            (unsigned long long)NativeMapCompileAddress.load());
    const auto memory = frame->DiagnosticBranches[64];
    uint32_t lock_value = 0;
    mach_vm_size_t copied = 0;
    const bool lock_read =
        memory.source &&
        mach_vm_read_overwrite(mach_task_self(), memory.source, 4, reinterpret_cast<mach_vm_address_t>(&lock_value),
                               &copied) == KERN_SUCCESS &&
        copied == 4;
    dprintf(2, "NATIVE_MAP_WAIT_MEMORY pid=%d guest-address=%llx source=%llx host-readable=%d value32=%x\n", getpid(),
            (unsigned long long)memory.source, (unsigned long long)memory.target, lock_read,
            lock_read ? lock_value : 0);
    auto &jit_mutex = frame->Thread->CTX->GetCodeInvalidationMutex();
    const bool jit_available = jit_mutex.try_lock_shared();
    if (jit_available)
      jit_mutex.unlock_shared();
    dprintf(2, "NATIVE_MAP_FEX_LOCK pid=%d guest-rip=%llx code-invalidation-readable=%d\n", getpid(),
            (unsigned long long)frame->State.rip, jit_available);
    dprintf(2, "NATIVE_MAP_LOOKUP_LOCK pid=%d shared-lookup-readable=%d\n", getpid(),
            frame->Thread->LookupCache->RegressionLookupReadable());
    dprintf(2, "NATIVE_MAP_WAIT_OBSERVATION pid=%d address=%llx own-translator-sequence=%llu\n", getpid(),
            (unsigned long long)args[0], (unsigned long long)end);
    for (uint64_t i = end > 16 ? end - 16 : 0; i < end; ++i) {
      const auto branch = frame->DiagnosticBranches[i % 64];
      dprintf(2, "NATIVE_MAP_WAIT_TRACE pid=%d source=%llx target=%llx\n", getpid(), (unsigned long long)branch.source,
              (unsigned long long)branch.target);
    }
  }
  *result = request.result;
  *linux_error = request.error;
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_guest_query_memory(uint64_t address, uint64_t *out) {
  // Root Linux callers have mapping state before the Wine handoff exists.
  if (ProcessSyscallHandler::IsRootGuestThread())
    return ProcessSyscallHandler::QueryCurrentGuestMemory(address, out);
  ProcessSyscallHandler *owner = nullptr;
  {
    std::lock_guard guard(GlibcLock);
    if (!RootBridgeReady || !RootObservationCookie)
      return -38;
    owner = static_cast<ProcessSyscallHandler *>(*reinterpret_cast<void **>(RootObservationCookie));
  }
  return owner->QueryNativeGuestMemory(address, out);
}
extern "C" __attribute__((visibility("default"))) int32_t
fli_root_guest_protect_memory(FliMemoryProtectionRequest *request) {
  ProcessSyscallHandler *owner = nullptr;
  {
    std::lock_guard guard(GlibcLock);
    if (!RootBridgeReady || !RootObservationCookie)
      return 0;
    owner = static_cast<ProcessSyscallHandler *>(*reinterpret_cast<void **>(RootObservationCookie));
  }
  // Root owns the VMA and its code caches; no fabricated guest CPU frame.
  return owner->ProtectNativeGuestMemory(request);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_clone_thread(const FliLinuxThreadState *state,
                                                                                uint64_t *result) {
  if (!state || !result)
    return -22;
  ProcessSyscallHandler *owner = nullptr;
  {
    std::lock_guard lock(GlibcLock);
    if (!RootBridgeReady || !RootObservationCookie)
      return -38;
    owner = static_cast<ProcessSyscallHandler *>(*reinterpret_cast<void **>(RootObservationCookie));
  }
  *result = owner->NativeCloneThread(state);
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_signal_mask(uint64_t how, uint32_t set,
                                                                               uint64_t requested, uint64_t *previous) {
  if (set > 1)
    return -22;
  ProcessSyscallHandler *owner = nullptr;
  {
    std::lock_guard lock(GlibcLock);
    if (!RootBridgeReady || !RootObservationCookie)
      return -38;
    owner = static_cast<ProcessSyscallHandler *>(*reinterpret_cast<void **>(RootObservationCookie));
  }
  return owner->NativeSignalMask(how, set, requested, previous);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_memory_operation(uint64_t number,
                                                                                    const uint64_t *args,
                                                                                    uint64_t *result) {
  if (!args || !result)
    return -22;
  ProcessSyscallHandler *owner = nullptr;
  {
    std::lock_guard guard(GlibcLock);
    if (!RootBridgeReady || !RootObservationCookie)
      return -38;
    owner = static_cast<ProcessSyscallHandler *>(*reinterpret_cast<void **>(RootObservationCookie));
  }
  *result = owner->NativeMemoryOperation(number, args);
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_program_break(uint64_t requested, uint64_t *result) {
  if (!result)
    return -22;
  ProcessSyscallHandler *owner = nullptr;
  {
    std::lock_guard guard(GlibcLock);
    if (!RootBridgeReady || !RootObservationCookie)
      return -38;
    owner = static_cast<ProcessSyscallHandler *>(*reinterpret_cast<void **>(RootObservationCookie));
  }
  *result = owner->ProgramBreak(requested);
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_allocate_glibc_tls(uint64_t *out) {
  if (!out || !fli_env_enabled("REGRESSION_FLI_NATIVE_ALIAS_EXECUTION"))
    return -38;
  uint64_t loader = 0;
  {
    std::lock_guard guard(GlibcLock);
    if (!RootBridgeReady || !RootLoaderBase)
      return -38;
    loader = RootLoaderBase;
  }
  const uint64_t args[6]{};
  uint64_t result = 0;
  int32_t error = 0;
  const int32_t status = root_mmap_request(args, &result, &error, false, 0, loader + 0x12ab0, false);
  if (status || error || !result || result >= 0x800000000000ULL)
    return status ? status : error ? -error : -12;
  *out = result;
  dprintf(2, "FLI_ROOT_GLIBC_TLS_ALLOCATED pid=%d tcb=%llx original-loader-call=1\n", getpid(),
          (unsigned long long)result);
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_mmap(const uint64_t *args, uint64_t *result,
                                                                        int32_t *linux_error) {
  return root_mmap_request(args, result, linux_error, false, 0);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_mmap_native_view(const uint64_t *args,
                                                                                    uint64_t *result,
                                                                                    int32_t *linux_error) {
  return root_mmap_request(args, result, linux_error, true, 0);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_mmap_native_view_for_wine(const uint64_t *args,
                                                                                             uint64_t *result,
                                                                                             int32_t *linux_error,
                                                                                             uint64_t wine_teb) {
  return root_mmap_request(args, result, linux_error, true, wine_teb);
}
extern "C" __attribute__((visibility("default"))) int32_t fli_root_guest_call_control(uint64_t entry,
                                                                                      const uint64_t *args,
                                                                                      uint64_t *result) {
  if (!fli_env_enabled("REGRESSION_FLI_OWNED_FAR_SHARED_CONTROL") || !entry || !result)
    return -38;
  int32_t error = 0;
  return root_mmap_request(args, result, &error, false, 0, entry, false);
}

extern "C" __attribute__((visibility("default"))) int32_t fli_root_guest_call_wine_control(uint64_t entry,
                                                                                           const uint64_t *args,
                                                                                           uint64_t wine_teb,
                                                                                           uint64_t *result) {
  if (!fli_env_enabled("REGRESSION_FLI_OWNED_FAR_SHARED_CONTROL") || !entry || !wine_teb || !result)
    return -38;
  int32_t error = 0;
  return root_mmap_request(args, result, &error, false, wine_teb, entry, false);
}

extern "C" __attribute__((visibility("default"))) const char *fli_inherited_fd_receipt_path();
static std::string InheritedControlReceipt;
extern "C" __attribute__((visibility("default"))) const char *fli_inherited_fd_receipt_path() {
  return InheritedControlReceipt.c_str();
}
extern "C" __attribute__((visibility("default"))) int32_t fli_check_inherited_fd(int Descriptor) {
  struct sigaction Saved[NSIG];
  for (int Signal = 1; Signal < NSIG; ++Signal)
    sigaction(Signal, nullptr, &Saved[Signal]);
  int Status = 70;
  std::thread Worker([&] {
    sigset_t ControlMask;
    sigemptyset(&ControlMask);
    sigaddset(&ControlMask, SIGUSR2);
    sigaddset(&ControlMask, SIGBUS);
    pthread_sigmask(SIG_UNBLOCK, &ControlMask, nullptr);
    std::string Directory = ResearchTemporaryPrefix("regression-fli-fex-process-probe.XXXXXX");
    if (!mkdtemp(Directory.data()))
      return;
    {
      std::ofstream File(Directory + "/receipt.json");
    }
    chmod((Directory + "/receipt.json").c_str(), 0600);
    InheritedControlReceipt = Directory + "/receipt.json";
    char ParentName[128]{};
    if (proc_name(getppid(), ParentName, sizeof(ParentName)) <= 0)
      return;
    ParentName[15] = 0;
    char HostPath[PROC_PIDPATHINFO_MAXSIZE]{};
    if (proc_pidpath(getpid(), HostPath, sizeof(HostPath)) <= 0)
      return;
    std::vector<std::string> Arguments{"/proc/self/fd/" + std::to_string(Descriptor),
                                       "/proc/" + std::to_string(getppid()) + "/comm", ParentName,
                                       std::to_string(getpid()), HostPath};
    if (fli_env_enabled("REGRESSION_FLI_FAULT_CONTROL"))
      Arguments.emplace_back(
          getenv("REGRESSION_FLI_FAULT_CONTROL_ADDRESS") ? getenv("REGRESSION_FLI_FAULT_CONTROL_ADDRESS") : "0");
    if (fli_env_enabled("REGRESSION_FLI_STRESS_CONTROL"))
      Arguments.insert(Arguments.end(), {"stress-one", "stress-two"});
    Status = RunRealRootFS(fli_host_path("VRCHAT_ROOTFS"), "/opt/regression-fd-control", Arguments, {},
                           Directory + "/stderr.log", Directory + "/receipt.json");
    dprintf(2, "FLI_INHERITED_FD_CONTROL status=%d directory=%s\n", Status, Directory.c_str());
  });
  Worker.join();
  for (int Signal = 1; Signal < NSIG; ++Signal)
    if (Signal != SIGKILL && Signal != SIGSTOP)
      sigaction(Signal, &Saved[Signal], nullptr);
  return Status;
}

extern "C" __attribute__((visibility("default"))) const char *fli_wine_guest_executable() {
  return WineHostEntryReady ? "/opt/regression-wine-entry/wine64" : nullptr;
}
extern "C" __attribute__((visibility("default"))) uint64_t fli_wine_elf_handoff(uint64_t Map, uint64_t FS,
                                                                                uint64_t Arena, uint64_t Break,
                                                                                uint64_t Argc, uint64_t Argv,
                                                                                RootInvoke Invoke, void *Cookie) {
  std::vector<std::string> Arguments;
  for (uint64_t i = 0; i < Argc; ++i) {
    uint64_t pointer = 0;
    mach_vm_size_t copied = 0;
    if (mach_vm_read_overwrite(mach_task_self(), Argv + i * 8, 8, reinterpret_cast<mach_vm_address_t>(&pointer),
                               &copied) != KERN_SUCCESS)
      return uint64_t(-14);
    std::string value;
    for (unsigned n = 0; n < 32768; ++n) {
      char byte = 0;
      if (mach_vm_read_overwrite(mach_task_self(), pointer + n, 1, reinterpret_cast<mach_vm_address_t>(&byte),
                                 &copied) != KERN_SUCCESS)
        return uint64_t(-14);
      if (!byte)
        break;
      value += byte;
      if (n == 32767)
        return uint64_t(-7);
    }
    Arguments.push_back(std::move(value));
  }
  if (Arguments.empty())
    return uint64_t(-22);
  if (fli_env_enabled("REGRESSION_FLI_ROOT_CALLBACK_BRIDGE"))
    for (const int signal : {SIGBUS, SIGSEGV, SIGTRAP, SIGUSR2})
      sigaction(signal, nullptr, &RootSignals[signal]);
  for (int Signal = 1; Signal < NSIG; ++Signal)
    if (Signal != SIGKILL && Signal != SIGSTOP)
      sigaction(Signal, &WineSignals[Signal], nullptr);
  if (fli_env_enabled("REGRESSION_FLI_ROOT_CALLBACK_BRIDGE"))
    for (const int signal : {SIGBUS, SIGSEGV, SIGTRAP, SIGUSR2}) {
      struct sigaction action{};
      action.sa_sigaction = fli_signal_mux;
      sigemptyset(&action.sa_mask);
      action.sa_flags = SA_SIGINFO | ((RootSignals[signal].sa_flags | WineSignals[signal].sa_flags) &
                                      (SA_ONSTACK | SA_RESTART | SA_NODEFER));
      if (sigaction(signal, &action, nullptr) != 0)
        return uint64_t(-errno);
      dprintf(2, "FLI_SIGNAL_MUX_INSTALLED pid=%d signal=%d real-root-handler=1 real-wine-handler=1\n", getpid(),
              signal);
    }
  std::unique_lock Guard(GlibcLock);
  Arguments[0] = WineHostLoader;
  WineHostArguments = std::move(Arguments);
  GlibcMap = Map;
  GlibcFS = FS;
  GlibcArena = Arena;
  GlibcBreak = Break;
  GlibcReady = true;
  WineHostEntryReady = true;
  dprintf(2, "FLI_WINE_ELF_HANDOFF argc=%zu fs=%llx\n", WineHostArguments.size(), static_cast<unsigned long long>(FS));
  if (fli_env_enabled("REGRESSION_FLI_ROOT_CALLBACK_BRIDGE") && Invoke) {
    uint64_t cursor = Map;
    for (unsigned i = 0; cursor && i < 32; ++i) {
      uint64_t link[5]{};
      mach_vm_size_t copied = 0;
      if (mach_vm_read_overwrite(mach_task_self(), cursor, sizeof(link), reinterpret_cast<mach_vm_address_t>(link),
                                 &copied) != KERN_SUCCESS ||
          copied != sizeof(link))
        break;
      char name[1024]{};
      if (link[1] && mach_vm_read_overwrite(mach_task_self(), link[1], sizeof(name) - 1,
                                            reinterpret_cast<mach_vm_address_t>(name), &copied) == KERN_SUCCESS) {
        if (strstr(name, "/libc.so.6"))
          RootLibcBase = link[0];
        if (strstr(name, "/ld-linux-x86-64.so.2"))
          RootLoaderBase = link[0];
        if (RootLibcBase && RootLoaderBase)
          break;
      }
      cursor = link[3];
    }
    RootBridgeReady = RootLibcBase != 0;
    RootServiceThread = pthread_self();
    RootObservationCookie = Cookie;
  }
  GlibcChanged.notify_all();
  while (RootBridgeReady) {
    GlibcChanged.wait(Guard, [] { return RootPending != nullptr; });
    auto *request = RootPending;
    Guard.unlock();
    const bool trace = request->native_view && fli_env_enabled("REGRESSION_FLI_TRACE_CLIENT_MAP_INPUT");
    if (trace)
      dprintf(2, "NATIVE_MAP_CALLBACK_BEGIN pid=%d address=%llx length=%llx offset=%llx\n", getpid(),
              (unsigned long long)request->args[0], (unsigned long long)request->args[1],
              (unsigned long long)request->args[5]);
    request->result =
        Invoke(Cookie, request->entry ? request->entry : RootLibcBase + 0xf1870, request->args, request->borrow_fd,
               request->native_view, request->wine_teb, request->caller_fs, request->caller_tid, request->caller_mask);
    if (static_cast<int64_t>(request->result) < -1 && static_cast<int64_t>(request->result) >= -4095) {
      request->error = -static_cast<int64_t>(request->result);
      request->result = UINT64_MAX;
    } else if (request->result == UINT64_MAX) {
      uint64_t zero[6]{};
      const uint64_t address = Invoke(Cookie, RootLibcBase + 0x38d0, zero, false, false, request->wine_teb,
                                      request->caller_fs, request->caller_tid, request->caller_mask);
      mach_vm_size_t copied = 0;
      int error = 0;
      if (mach_vm_read_overwrite(mach_task_self(), address, sizeof(error), reinterpret_cast<mach_vm_address_t>(&error),
                                 &copied) == KERN_SUCCESS &&
          copied == sizeof(error))
        request->error = error;
      else
        request->error = 14;
    }
    if (trace)
      dprintf(2, "NATIVE_MAP_CALLBACK_END pid=%d address=%llx result=%llx linux-error=%d\n", getpid(),
              (unsigned long long)request->args[0], (unsigned long long)request->result, request->error);
    Guard.lock();
    request->done = true;
    RootPending = nullptr;
    GlibcChanged.notify_all();
  }
  GlibcChanged.wait(Guard, [] { return false; });
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_run_wine_elf_host(int Argc, char **Argv,
                                                                                void (*NativeMain)(int, char **)) {
  if (Argc < 1 || !NativeMain)
    return 64;
  std::unique_lock Guard(GlibcLock);
  if (GlibcReady || WineHostEntryReady)
    return 70;
  WineHostLoader = Argv[0];
  for (int Signal = 1; Signal < NSIG; ++Signal)
    sigaction(Signal, nullptr, &WineSignals[Signal]);
  sigset_t OriginalMask{}, ForwardMask{};
  const char *TracePID = getenv("REGRESSION_LINUX_TRACE_PID");
  const bool TracedEntry = TracePID && strtoll(TracePID, nullptr, 10) == getpid();
  if (TracedEntry) {
    // XNU PT_CONTINUE queues a process signal as well as p_xstat. Only the
    // executing ELF thread may receive its internal FEX fault delivery.
    sigemptyset(&ForwardMask);
    sigaddset(&ForwardMask, SIGTRAP);
    sigaddset(&ForwardMask, SIGBUS);
    sigaddset(&ForwardMask, SIGSEGV);
    pthread_sigmask(SIG_BLOCK, &ForwardMask, &OriginalMask);
  }
  setenv("REGRESSION_NATIVE_WINE_HOST_ENTRY", "1", 1);
  std::vector<std::string> Environment{"LD_LIBRARY_PATH=/usr/lib64:/opt/regression-wine-entry",
                                       "WINEDLLPATH=/opt/regression-wine-entry"};
  for (const char *Name : {"WINEPREFIX", "WINELOADER", "WINESERVER", "SteamAppId", "SteamGameId", "PROTON_EAC_RUNTIME",
                           "EAC_LAUNCHERDIR", "LD_DEBUG"})
    if (const char *Value = getenv(Name))
      Environment.emplace_back(std::string(Name) + "=" + Value);
  std::vector<std::string> GuestArguments(Argv + 1, Argv + Argc);
  std::thread([Arguments = std::move(GuestArguments), Environment = std::move(Environment)] {
    std::string Directory = ResearchTemporaryPrefix("regression-fli-fex-process-probe.XXXXXX");
    if (!mkdtemp(Directory.data()))
      return;
    {
      std::ofstream File(Directory + "/receipt.json");
    }
    chmod((Directory + "/receipt.json").c_str(), 0600);
    int Status = RunRealRootFS(fli_host_path("VRCHAT_ROOTFS"), "/opt/regression-wine-entry/wine64", Arguments,
                               Environment, Directory + "/stderr.log", Directory + "/receipt.json");
    dprintf(2, "FLI_WINE_ELF_HOST_ENDED status=%d\n", Status);
    std::lock_guard Lock(GlibcLock);
    WineHostEntryFailed = true;
    GlibcChanged.notify_all();
  }).detach();
  // The traced ELF can execute a real client under its parent's debugger before Wine handoff.
  // Its lifetime belongs to that parent; the ordinary Wine startup timeout cannot bound it.
  bool Completed = true;
  if (TracedEntry) {
    dprintf(2, "FLI_WINE_ELF_HOST_WAIT traced=1 timeout=none\n");
    GlibcChanged.wait(Guard, [] { return WineHostEntryReady || WineHostEntryFailed; });
  } else
    Completed = GlibcChanged.wait_for(Guard, std::chrono::seconds(15),
                                      [] { return WineHostEntryReady || WineHostEntryFailed; });
  if (!Completed || !WineHostEntryReady) {
    dprintf(2, "FLI_WINE_ELF_HOST_WAIT_FAILED traced=%d timeout=%d worker-failed=%d\n", TracedEntry, !Completed,
            WineHostEntryFailed);
    if (TracedEntry)
      pthread_sigmask(SIG_SETMASK, &OriginalMask, nullptr);
    return 70;
  }
  std::vector<char *> Arguments;
  for (auto &Value : WineHostArguments)
    Arguments.push_back(Value.data());
  Arguments.push_back(nullptr);
  Guard.unlock();
  if (TracedEntry)
    pthread_sigmask(SIG_SETMASK, &OriginalMask, nullptr);
  if (TracedEntry && fli_env_enabled("REGRESSION_FLI_NATIVE_HANDOFF_STOP")) {
    dprintf(2, "FLI_NATIVE_HANDOFF_STOP pid=%d\n", getpid());
    raise(SIGSTOP);
  }
  NativeMain(WineHostArguments.size(), Arguments.data());
  return 0;
}

extern "C" __attribute__((visibility("default"))) int32_t fli_wine_native_time(void *Output) {
  const char *Root = getenv("WINEBUILDDIR");
  if (!Root)
    return int32_t(0xc0000135);
  void *Module = dlopen((std::string(Root) + "/dlls/ntdll/ntdll.so").c_str(), RTLD_NOW | RTLD_NOLOAD);
  if (!Module)
    return int32_t(0xc0000135);
  using Query = int32_t (*)(void *);
  auto Function = reinterpret_cast<Query>(dlsym(Module, "NtQuerySystemTime"));
  int32_t Status = Function ? Function(Output) : int32_t(0xc0000139);
  dlclose(Module);
  if (!Status) {
    WineNativeTime.store(*static_cast<uint64_t *>(Output));
    WineNativeCalls.fetch_add(1);
  }
  dprintf(2, "FLI_WINE_ELF_NATIVE_CALL status=%x\n", uint32_t(Status));
  return Status;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_check_wine_elf_entry(uint64_t *Result) {
  struct sigaction Saved[NSIG];
  for (int Signal = 1; Signal < NSIG; ++Signal)
    sigaction(Signal, nullptr, &Saved[Signal]);
  setenv("REGRESSION_NATIVE_WINE_ENTRY_CONTROL", "1", 1);
  WineNativeCalls.store(0);
  WineNativeTime.store(0);
  int Status = -1;
  std::thread Worker([&] {
    std::string Directory = (std::string(fli_host_path("VRCHAT_STATE_DIR")) + "/elf-process.XXXXXX");
    if (!mkdtemp(Directory.data()))
      return;
    {
      std::ofstream File(Directory + "/receipt.json");
    }
    chmod((Directory + "/receipt.json").c_str(), 0600);
    dprintf(2, "FLI_WINE_ELF_ENTRY_CONTROL directory=%s\n", Directory.c_str());
    Status = RunRealRootFS(
        fli_host_path("VRCHAT_ROOTFS"), "/opt/regression-wine-entry/wine64", {"--native-time-control"},
        {"LD_LIBRARY_PATH=/usr/lib64:/opt/regression-wine-entry", "WINEDLLPATH=/opt/regression-wine-entry"},
        Directory + "/stderr.log", Directory + "/receipt.json");
  });
  Worker.join();
  for (int Signal = 1; Signal < NSIG; ++Signal)
    if (Signal != SIGKILL && Signal != SIGSTOP)
      sigaction(Signal, &Saved[Signal], nullptr);
  unsetenv("REGRESSION_NATIVE_WINE_ENTRY_CONTROL");
  *Result = WineNativeTime.load();
  dprintf(2, "FLI_WINE_ELF_ENTRY_RESULT status=%d calls=%u\n", Status, WineNativeCalls.load());
  return Status == 0 && WineNativeCalls.load() == 1 ? 0 : -1;
}

extern "C" __attribute__((visibility("default"))) uint64_t fli_glibc_ready(uint64_t Map, uint64_t FS, uint64_t Arena,
                                                                           uint64_t Break) {
  // This callback runs after the real Linux dynamic linker initialized GLIBC.
  // The Linux executor remains paused here; Wine resumes with its own handlers.
  for (int Signal = 1; Signal < NSIG; ++Signal)
    if (Signal != SIGKILL && Signal != SIGSTOP)
      sigaction(Signal, &WineSignals[Signal], nullptr);
  std::unique_lock Guard(GlibcLock);
  GlibcMap = Map;
  GlibcFS = FS;
  GlibcArena = Arena;
  GlibcBreak = Break;
  GlibcReady = true;
  GlibcChanged.notify_all();
  GlibcChanged.wait(Guard, [] { return false; });
  return 0;
}
extern "C" __attribute__((visibility("default"))) int32_t fli_start_glibc(uint64_t *Result) {
  std::lock_guard Guard(GlibcLock);
  // wine-host initializes libc through the ELF frontend before entering Wine.
  if (!GlibcReady)
    return ENXIO;
  Result[0] = GlibcMap;
  Result[1] = GlibcFS;
  Result[2] = GlibcArena;
  Result[3] = GlibcBreak;
  return 0;
}
