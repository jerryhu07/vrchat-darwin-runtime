#pragma once
#include <windows.h>
#include "Windows/Common/FEXUnixLib.h"
#include "../platform/runtime-abi.h"
inline uint8_t *FliCreateJITAlias(uint8_t *source, size_t size) {
  FliJITAlias request{reinterpret_cast<uint64_t>(source), size, 0, FLI_JIT_CREATE, 0};
  const auto status = FEX::Windows::UnixLib::Call(static_cast<FEXUnixLibFunctions>(FLI_JIT_SERVICE_CALL), &request);
  return status ? nullptr : reinterpret_cast<uint8_t *>(request.alias);
}
inline void FliReleaseJITAlias(uint8_t *source, size_t size, uint8_t *alias) {
  FliJITAlias request{reinterpret_cast<uint64_t>(source), size, reinterpret_cast<uint64_t>(alias), FLI_JIT_RELEASE, 0};
  const auto status = FEX::Windows::UnixLib::Call(static_cast<FEXUnixLibFunctions>(FLI_JIT_SERVICE_CALL), &request);
  LOGMAN_THROW_A_FMT(status == 0, "Couldn't release JIT writable view");
}

inline void FliTrimJITAlias(uint8_t *source, size_t used) {
  FliJITAlias request{reinterpret_cast<uint64_t>(source), used, 0, FLI_JIT_TRIM, 0};
  const auto status = FEX::Windows::UnixLib::Call(static_cast<FEXUnixLibFunctions>(FLI_JIT_SERVICE_CALL), &request);
  LOGMAN_THROW_A_FMT(status == 0, "Couldn't retire published JIT write pages");
}
