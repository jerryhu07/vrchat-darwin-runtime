// Class members shared by both Linux executors. Startup extensions are explicit at the call site.
int EncodeInternetAddress(uint64_t pointer, uint64_t length_pointer, const sockaddr_storage &address) {
  auto *length = static_cast<uint32_t *>(HostPointerForGuestRange(length_pointer, 4, PROT_READ | PROT_WRITE));
  if (!length)
    return 14;
  const uint32_t size = address.ss_family == AF_INET ? 16 : address.ss_family == AF_INET6 ? 28 : 0;
  if (!size)
    return 97;
  const uint32_t copy = std::min(*length, size);
  void *out = copy ? HostPointerForGuestRange(pointer, copy, PROT_WRITE) : nullptr;
  if (copy && !out)
    return 14;
  sockaddr_storage linux_address = address;
  const uint16_t family = address.ss_family == AF_INET ? 2 : 10;
  memcpy(&linux_address, &family, 2);
  if (copy)
    memcpy(out, &linux_address, copy);
  *length = size;
  return 0;
}
// Linux internet-socket ABI over real Darwin sockets; no protocol data is logged.
std::optional<uint64_t> HandleInternetSocketSyscall(uint64_t nr, const uint64_t *a, bool StartupExtensions) {
  auto error = [](int value) -> uint64_t { return uint64_t(-TranslateHostSocketErrorToLinux(value)); };
  if (nr == 41) {
    if (a[1] != 2 && a[1] != 10)
      return std::nullopt;
    const unsigned type = a[2] & 15, flags = a[2] & ~uint64_t(15);
    if ((type != 1 && type != 2) || (flags & ~0x80800U) || (a[3] && a[3] != (type == 1 ? IPPROTO_TCP : IPPROTO_UDP)))
      return uint64_t(-93);
    int fd = socket(a[1] == 2 ? AF_INET : AF_INET6, type == 1 ? SOCK_STREAM : SOCK_DGRAM, int(a[3]));
    if (fd < 0)
      return error(errno);
    int status = 0;
    if (flags & 0x800)
      status = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    if (!status && (flags & 0x80000))
      status = fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (status < 0) {
      int saved = errno;
      close(fd);
      return error(saved);
    }
    OwnedDescriptors.insert(fd);
    return uint64_t(fd);
  }
  if (nr != 42 && nr != 44 && nr != 45 && !(StartupExtensions && nr == 46) && nr != 49 && nr != 51 && nr != 52 &&
      nr != 54 && nr != 55)
    return std::nullopt;
  const int fd = int(a[1]);
  if (!OwnedDescriptors.contains(fd))
    return uint64_t(-9);
  sockaddr_storage local{};
  socklen_t local_size = sizeof(local);
  if (getsockname(fd, reinterpret_cast<sockaddr *>(&local), &local_size) ||
      (local.ss_family != AF_INET && local.ss_family != AF_INET6))
    return std::nullopt;
  // Darwin has no Linux IP_RECVERR/error-queue option; report the real unsupported option.
  if ((nr == 54 || nr == 55) && a[2] == 0 && a[3] == 11)
    return uint64_t(-92);
  if (nr == 54 || nr == 55) {
    if (a[2] != 1 || (!(StartupExtensions && a[3] == 3) && a[3] != 4 && a[3] != 20 && a[3] != 21))
      return uint64_t(-92);
    if (nr == 54 && a[3] == 4)
      return uint64_t(-92);
    const bool is_error = a[3] == 4, is_type = StartupExtensions && a[3] == 3;
    const int option = is_type ? SO_TYPE : is_error ? SO_ERROR : a[3] == 20 ? SO_RCVTIMEO : SO_SNDTIMEO;
    const uint32_t bytes = (is_error || is_type) ? 4 : 16;
    uint32_t *length =
        nr == 55 ? static_cast<uint32_t *>(HostPointerForGuestRange(a[5], 4, PROT_READ | PROT_WRITE)) : nullptr;
    if (nr == 55 && !length)
      return uint64_t(-14);
    const uint32_t copy = nr == 55 ? std::min(*length, bytes) : bytes;
    if (nr == 54 && a[5] < bytes)
      return uint64_t(-22);
    void *value = copy ? HostPointerForGuestRange(a[4], copy, nr == 55 ? PROT_WRITE : PROT_READ) : nullptr;
    if (copy && !value)
      return uint64_t(-14);
    if (is_error || is_type) {
      int result = 0;
      socklen_t size = sizeof(result);
      if (getsockopt(fd, SOL_SOCKET, option, &result, &size))
        return error(errno);
      if (is_error)
        result = TranslateHostSocketErrorToLinux(result);
      if (copy)
        memcpy(value, &result, copy);
      *length = StartupExtensions ? copy : 4;
      return uint64_t(0);
    }
    timeval timeout{};
    int64_t linux_value[2]{};
    if (nr == 54) {
      memcpy(linux_value, value, 16);
      if (linux_value[0] < 0 || linux_value[1] < 0 || linux_value[1] >= 1000000)
        return uint64_t(-33);
      timeout.tv_sec = linux_value[0];
      timeout.tv_usec = linux_value[1];
      return setsockopt(fd, SOL_SOCKET, option, &timeout, sizeof(timeout)) ? error(errno) : uint64_t(0);
    }
    socklen_t size = sizeof(timeout);
    if (getsockopt(fd, SOL_SOCKET, option, &timeout, &size))
      return error(errno);
    linux_value[0] = timeout.tv_sec;
    linux_value[1] = timeout.tv_usec;
    if (copy)
      memcpy(value, linux_value, copy);
    *length = 16;
    return uint64_t(0);
  }
  auto decode = [&](uint64_t pointer, uint64_t length, sockaddr_storage &address, socklen_t &size) -> int {
    auto *family = static_cast<const uint16_t *>(HostPointerForGuestRange(pointer, 2, PROT_READ));
    if (!family)
      return 14;
    if (*family != 2 && *family != 10)
      return 97;
    size = *family == 2 ? 16 : 28;
    if (length < size)
      return 22;
    const void *input = HostPointerForGuestRange(pointer, size, PROT_READ);
    if (!input)
      return 14;
    memcpy(&address, input, size);
    address.ss_len = size;
    address.ss_family = *family == 2 ? AF_INET : AF_INET6;
    return 0;
  };
  if (nr == 46) {
    const auto *message = static_cast<const LinuxMessageHeader64 *>(
        HostPointerForGuestRange(a[2], sizeof(LinuxMessageHeader64), PROT_READ));
    if (!message)
      return uint64_t(-14);
    const LinuxMessageHeader64 input = *message;
    if (input.IOVectorCount > 1024)
      return uint64_t(-90);
    if (input.ControlLength)
      return uint64_t(-95); // Internet send ancillary data is not implemented.
    if (a[3] & ~uint64_t(0x4147))
      return uint64_t(-95);
    const auto *vectors = input.IOVectorCount
                              ? static_cast<const LinuxIOVector64 *>(HostPointerForGuestRange(
                                    input.IOVectors, input.IOVectorCount * sizeof(LinuxIOVector64), PROT_READ))
                              : nullptr;
    if (input.IOVectorCount && !vectors)
      return uint64_t(-14);
    std::vector<iovec> host_vectors;
    host_vectors.reserve(input.IOVectorCount);
    uint64_t total = 0;
    for (uint64_t i = 0; i < input.IOVectorCount; ++i) {
      const auto vector = vectors[i];
      if (vector.Length > SSIZE_MAX - total)
        return uint64_t(-22);
      void *buffer = vector.Length ? HostPointerForGuestRange(vector.Base, vector.Length, PROT_READ) : nullptr;
      if (vector.Length && !buffer)
        return uint64_t(-14);
      host_vectors.push_back({buffer, size_t(vector.Length)});
      total += vector.Length;
    }
    if (host_vectors.empty())
      host_vectors.push_back({nullptr, 0});
    sockaddr_storage address{};
    socklen_t size = 0;
    if (input.Name && input.NameLength) {
      int e = decode(input.Name, input.NameLength, address, size);
      if (e)
        return uint64_t(-e);
    }
    msghdr host{};
    host.msg_iov = host_vectors.data();
    host.msg_iovlen = int(host_vectors.size());
    if (size) {
      host.msg_name = &address;
      host.msg_namelen = size;
    }
    int flags = int(a[3] & 7);
    if (a[3] & 0x40)
      flags |= MSG_DONTWAIT;
    if (a[3] & 0x100)
      flags |= MSG_WAITALL;
    if (a[3] & 0x4000)
      flags |= MSG_NOSIGNAL;
    const ssize_t result = BlockingHostCall([&] { return sendmsg(fd, &host, flags); });
    return result < 0 ? error(errno) : uint64_t(result);
  }
  if (nr == 42 || nr == 49) {
    auto *family = static_cast<const uint16_t *>(HostPointerForGuestRange(a[2], 2, PROT_READ));
    if (nr == 42 && a[3] >= 2 && family && !*family) {
      // Actual XNU disconnection; connect(AF_UNSPEC) is not accepted by Darwin.
      return disconnectx(fd, SAE_ASSOCID_ANY, SAE_CONNID_ANY) ? error(errno) : uint64_t(0);
    }
    sockaddr_storage address{};
    socklen_t size = 0;
    int e = decode(a[2], a[3], address, size);
    if (e)
      return uint64_t(-e);
    if (fli_env_enabled("REGRESSION_FLI_DIAG_OWNED_INET"))
      dprintf(2, "OWNED_INET_DEST family=%u port=%u\n", address.ss_family,
              ntohs(reinterpret_cast<const sockaddr_in *>(&address)->sin_port));
    int result = nr == 42 ? BlockingHostCall([&] { return connect(fd, reinterpret_cast<sockaddr *>(&address), size); })
                          : bind(fd, reinterpret_cast<sockaddr *>(&address), size);
    return result < 0 ? error(errno) : uint64_t(result);
  }
  if (nr == 51 || nr == 52) {
    sockaddr_storage address{};
    socklen_t size = sizeof(address);
    int result = nr == 51 ? getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size)
                          : getpeername(fd, reinterpret_cast<sockaddr *>(&address), &size);
    if (result < 0)
      return error(errno);
    return uint64_t(-EncodeInternetAddress(a[2], a[3], address));
  }
  const uint64_t count = a[3], flags = a[4];
  if (count > SSIZE_MAX)
    return uint64_t(-22);
  if (flags & ~uint64_t(0x4147))
    return uint64_t(-95);
  int host_flags = int(flags & 7);
  if (flags & 0x40)
    host_flags |= MSG_DONTWAIT;
  if (flags & 0x100)
    host_flags |= MSG_WAITALL;
  if (flags & 0x4000)
    host_flags |= MSG_NOSIGNAL;
  void *buffer = count ? HostPointerForGuestRange(a[2], count, nr == 44 ? PROT_READ : PROT_WRITE) : nullptr;
  if (count && !buffer)
    return uint64_t(-14);
  sockaddr_storage address{};
  socklen_t size = sizeof(address);
  sockaddr *host_address = nullptr;
  if (a[5]) {
    host_address = reinterpret_cast<sockaddr *>(&address);
    if (nr == 44) {
      int e = decode(a[5], a[6], address, size);
      if (e)
        return uint64_t(-e);
    } else if (!HostPointerForGuestRange(a[6], 4, PROT_READ | PROT_WRITE))
      return uint64_t(-14);
  } else
    size = 0;
  const ssize_t result = BlockingHostCall([&] {
    return nr == 44 ? sendto(fd, buffer, count, host_flags, host_address, size)
                    : recvfrom(fd, buffer, count, host_flags, host_address, a[5] ? &size : nullptr);
  });
  if (result < 0)
    return error(errno);
  if (nr == 45 && a[5]) {
    int e = EncodeInternetAddress(a[5], a[6], address);
    if (e)
      return uint64_t(-e);
  }
  return uint64_t(result);
}
