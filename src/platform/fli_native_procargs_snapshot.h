/* A local native argv snapshot, produced by the read-only administrator probe. */
struct NativeProcArgsHeader {
  char magic[8], boot_uuid[40];
  uint32_t pid, argc, bytes, reserved;
};
static_assert(sizeof(NativeProcArgsHeader) == 64);
static bool read_native_procargs_snapshot(const char *path, int pid, std::vector<char> &arguments, int &argc) {
  if (!path || pid <= 0)
    return false;
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return false;
  struct stat info{};
  NativeProcArgsHeader header{};
  bool valid = false;
  if (fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == getuid() && !(info.st_mode & 0077) &&
      info.st_size >= int64_t(sizeof(header)) && info.st_size <= 4 * 1024 * 1024 &&
      pread(fd, &header, sizeof(header), 0) == sizeof(header) && !memcmp(header.magic, "PROCARG1", 8) &&
      header.pid == uint32_t(pid) && header.reserved == 0 && header.argc > 0 && header.argc <= 65536 &&
      header.bytes > 0 && info.st_size == int64_t(sizeof(header)) + header.bytes &&
      memchr(header.boot_uuid, 0, sizeof(header.boot_uuid))) {
    char boot[40]{};
    size_t length = sizeof(boot);
    if (sysctlbyname("kern.bootsessionuuid", boot, &length, nullptr, 0) == 0 && !strcmp(boot, header.boot_uuid)) {
      std::vector<char> bytes(header.bytes);
      size_t done = 0;
      while (done < bytes.size()) {
        ssize_t n = pread(fd, bytes.data() + done, bytes.size() - done, sizeof(header) + done);
        if (n < 0 && errno == EINTR)
          continue;
        if (n <= 0)
          break;
        done += size_t(n);
      }
      if (done == bytes.size() && bytes.back() == 0 && std::count(bytes.begin(), bytes.end(), char(0)) == header.argc) {
        arguments = std::move(bytes);
        argc = int(header.argc);
        valid = true;
      }
    }
  }
  close(fd);
  return valid;
}
