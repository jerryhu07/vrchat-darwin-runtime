#pragma once
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <optional>
#include <string>
#include <string_view>
#include <limits.h>
// stat already exposes the host's numeric dev_t as an opaque guest identifier.
// Every Linux text view must decode that same identifier using the Linux ABI.
inline uint32_t fli_guest_device_major(uint64_t dev) {
  return uint32_t(((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000));
}
inline uint32_t fli_guest_device_minor(uint64_t dev) { return uint32_t((dev & 0xff) | ((dev >> 12) & 0xffffff00)); }
inline std::string_view fli_shared_host_root() {
  const char *path = std::getenv("REGRESSION_FLI_SHARED_HOST_ROOT");
  if (!path || path[0] != '/' || !path[1])
    return {};
  std::string_view root = path;
  while (root.size() > 1 && root.back() == '/')
    root.remove_suffix(1);
  return root;
}
inline bool fli_shared_host_path(std::string_view path) {
  const auto root = fli_shared_host_root();
  return !root.empty() &&
         (path == root || (path.size() > root.size() && path.starts_with(root) && path[root.size()] == '/'));
}
// Namespace eligibility is shared by path resolution and descriptor operations.
inline bool fli_guest_host_path_visible(std::string_view path, std::string_view rootfs) {
  return (!rootfs.empty() && (path == rootfs || (path.size() > rootfs.size() && path.starts_with(rootfs) &&
                                                 path[rootfs.size()] == '/'))) ||
         fli_shared_host_path(path);
}
inline std::string fli_guest_path_view(std::string path, std::string_view rootfs) {
  if (!rootfs.empty()) {
    if (path == rootfs)
      return "/";
    if (path.size() > rootfs.size() && path.starts_with(rootfs) && path[rootfs.size()] == '/')
      path.erase(0, rootfs.size());
  }
  return path;
}
inline std::optional<std::string> fli_shared_host_object(const std::string &path) {
  char canonical[PATH_MAX];
  if (realpath(path.c_str(), canonical))
    return fli_shared_host_path(canonical) ? std::optional<std::string>{canonical} : std::nullopt;
  // Preserve normal ENOENT handling. Creation resolves and checks its parent separately.
  if (errno == ENOENT || errno == ENOTDIR)
    return path;
  return std::nullopt;
}
