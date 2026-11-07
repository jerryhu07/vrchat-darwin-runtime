#pragma once
#include <FEXCore/Utils/LogManager.h>
#include "jit-writable-alias.h"
namespace FEXCore::CPU {
class ScopedJITPatch {
public:
  uintptr_t Address;
#ifdef ARCHITECTURE_arm64ec
  FliJITAlias Request;
  ScopedJITPatch(uintptr_t source, size_t length) : Request{source, length, 0, FLI_JIT_BEGIN_PATCH, 0} {
    const auto status = FEX::Windows::UnixLib::Call(static_cast<FEXUnixLibFunctions>(FLI_JIT_SERVICE_CALL), &Request);
    LOGMAN_THROW_A_FMT(status == 0 && Request.alias, "JIT patch outside owned backing");
    Address = Request.alias;
  }
  ~ScopedJITPatch() {
    Request.operation = FLI_JIT_END_PATCH;
    const auto status = FEX::Windows::UnixLib::Call(static_cast<FEXUnixLibFunctions>(FLI_JIT_SERVICE_CALL), &Request);
    LOGMAN_THROW_A_FMT(status == 0, "Couldn't release JIT patch window");
  }
#else
  ScopedJITPatch(uintptr_t source, size_t) : Address(source) {}
#endif
  ScopedJITPatch(const ScopedJITPatch &) = delete;
  ScopedJITPatch &operator=(const ScopedJITPatch &) = delete;
};
} // namespace FEXCore::CPU
