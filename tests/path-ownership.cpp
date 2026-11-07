#include "paths.h"
#include "runtime-env.h"
#include <cassert>
#include <cstdlib>

int main() {
  unsetenv("VRCHAT_TEST_SWITCH");
  assert(!fli_env_enabled("VRCHAT_TEST_SWITCH"));
  setenv("VRCHAT_TEST_SWITCH", "0", 1);
  assert(!fli_env_enabled("VRCHAT_TEST_SWITCH"));
  setenv("VRCHAT_TEST_SWITCH", "1", 1);
  assert(fli_env_enabled("VRCHAT_TEST_SWITCH"));
  setenv("VRCHAT_RUNTIME_ROOT", "/tmp/runtime", 1);
  setenv("VRCHAT_ROOTFS", "/tmp/rootfs", 1);
  setenv("VRCHAT_GAME_DIR", "/tmp/game", 1);
  setenv("VRCHAT_STATE_DIR", "/tmp/state", 1);
  assert(fli_owned_host_path("/tmp/runtime/lib/bridge.so"));
  assert(fli_owned_host_path("/tmp/game/VRChat.exe"));
  assert(!fli_owned_host_path("/tmp/runtime-other/bridge.so"));
  assert(!fli_owned_host_path("/tmp/runtime/../outside"));
  assert(fli_owned_host_ancestor("/tmp"));
  assert(!fli_owned_host_ancestor("/"));
  assert(!fli_owned_host_ancestor("/tmp/runtime-other"));
}
