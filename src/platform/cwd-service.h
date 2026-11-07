#pragma once
#include <cerrno>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unistd.h>
// The host process owns cwd; render its path into the existing guest namespace.
inline int fli_current_directory(std::string_view root, std::string &out) {
  char *actual = ::getcwd(nullptr, 0);
  if (!actual)
    return errno;
  out = actual;
  std::free(actual);
  if (out == root)
    out = "/";
  else if (out.size() > root.size() && out.starts_with(root) && out[root.size()] == '/')
    out.erase(0, root.size());
  return 0;
}
