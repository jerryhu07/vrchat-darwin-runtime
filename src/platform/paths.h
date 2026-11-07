#pragma once
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

// The launcher supplies canonical absolute directories. Keep path ownership at
// the host boundary; Linux paths are still resolved by the existing rootfs code.
inline const char *fli_host_path(const char *name) {
  const char *value = std::getenv(name);
  if (!value || value[0] != '/' || !value[1]) {
    std::fprintf(stderr, "%s must name an absolute non-root path\n", name);
    std::abort();
  }
  return value;
}

inline bool fli_path_within(const std::string &value, const std::string &root) {
  const auto normalized = std::filesystem::path(value).lexically_normal().string();
  return normalized == root || normalized.starts_with(root + "/");
}

inline bool fli_owned_host_path(const std::string &value) {
  for (const char *name : {"VRCHAT_RUNTIME_ROOT", "VRCHAT_ROOTFS", "VRCHAT_GAME_DIR", "VRCHAT_STATE_DIR"})
    if (fli_path_within(value, fli_host_path(name)))
      return true;
  return false;
}

inline bool fli_owned_host_ancestor(const std::string &value) {
  const auto normalized = std::filesystem::path(value).lexically_normal().string();
  if (normalized.empty() || normalized == "/")
    return false;
  for (const char *name : {"VRCHAT_RUNTIME_ROOT", "VRCHAT_ROOTFS", "VRCHAT_GAME_DIR", "VRCHAT_STATE_DIR"})
    if (fli_path_within(fli_host_path(name), normalized))
      return true;
  return false;
}
