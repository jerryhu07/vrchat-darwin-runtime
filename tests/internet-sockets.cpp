#include "linux-abi.h"
#include "runtime-env.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

struct Guest {
  std::unordered_set<int> OwnedDescriptors;
  void *HostPointerForGuestRange(uint64_t address, uint64_t, int) { return reinterpret_cast<void *>(address); }
  template<typename F> auto BlockingHostCall(F call) { return call(); }
#include "internet-sockets.inc"
  ~Guest() { for (int fd : OwnedDescriptors) close(fd); }
};

int main() {
  for (bool startup : {false, true}) {
    Guest guest;
    uint64_t args[7] = {41, 2, 2, 0}; // Linux AF_INET, SOCK_DGRAM.
    int fd = *guest.HandleInternetSocketSyscall(41, args, startup);
    assert(fd >= 0 && guest.OwnedDescriptors.contains(fd));
    int value = -1;
    uint32_t length = sizeof(value);
    uint64_t option[7] = {55, uint64_t(fd), 1, 3, uint64_t(&value), uint64_t(&length)};
    auto result = guest.HandleInternetSocketSyscall(55, option, startup);
    assert(result && (startup ? *result == 0 && value == 2 : int64_t(*result) == -92));
    option[3] = 4; // SO_ERROR also checks each caller's short-buffer convention.
    length = 1;
    assert(guest.HandleInternetSocketSyscall(55, option, startup) == 0);
    assert(length == (startup ? 1u : 4u));

    sockaddr_in address{};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    socklen_t size = sizeof(address);
    assert(getsockname(fd, reinterpret_cast<sockaddr *>(&address), &size) == 0);
    uint16_t family = 2;
    memcpy(&address, &family, sizeof(family));
    char payload[] = "owned";
    LinuxIOVector64 vector{uint64_t(payload), sizeof(payload)};
    LinuxMessageHeader64 message{};
    message.Name = uint64_t(&address);
    message.NameLength = sizeof(address);
    message.IOVectors = uint64_t(&vector);
    message.IOVectorCount = 1;
    uint64_t send[7] = {46, uint64_t(fd), uint64_t(&message)};
    result = guest.HandleInternetSocketSyscall(46, send, startup);
    if (!startup) { assert(!result); continue; }
    assert(result == sizeof(payload));
    pollfd ready{fd, POLLIN, 0};
    assert(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN));
    char received[sizeof(payload)]{};
    assert(recv(fd, received, sizeof(received), MSG_DONTWAIT) == sizeof(payload));
    assert(memcmp(payload, received, sizeof(payload)) == 0);
  }
}
