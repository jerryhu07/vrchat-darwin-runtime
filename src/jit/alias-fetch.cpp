
#include <cstdint>
#include <atomic>
struct LabAliasRecord {
  uint64_t guest, length, host, span, protection, offset;
};
struct LabAliasSnapshot {
  uint32_t size, count;
  LabAliasRecord rows[4];
};
static std::atomic<const LabAliasSnapshot *> CurrentAliases{};
extern "C" __declspec(dllexport) void LabInstallInstructionAliases(const LabAliasSnapshot *snapshot) {
  CurrentAliases.store(snapshot, std::memory_order_release);
}
extern "C" uint64_t LabTranslateInstructionAddress(uint64_t address) {
  const auto *snapshot = CurrentAliases.load(std::memory_order_acquire);
  if (!snapshot)
    return 0;
  for (uint32_t i = 0; i < snapshot->count; ++i) {
    const auto &row = snapshot->rows[i];
    if ((row.protection & 4) && address >= row.guest && address - row.guest < row.length)
      return row.host + address - row.guest;
  }
  return 0;
}
