# Known issues and validation limits

- Online verification covers VRChat 2026.4.1p1 on an M4 Pro with macOS 27.0.1. A [fresh clone and full build](verification/clean-build.json), new prefixes and a fresh login reached a visible room. Window resizing was also confirmed in the [earlier assembly](verification/reproduced-runtime.json). A second machine, display-mode switching, and performance remain unverified.
- Graphics use the pinned public DXMT/WineMetal binaries. The optional DXMT source build still needs its own rendering and ABI verification.
- The owned tests compare retained observations; they do not establish complete x86 exception-flag fidelity.
- Initial Wine setup can report failures in 32-bit helpers and unavailable drivers. The main `wineboot` process completed in the verified setup; general 32-bit application support is outside the validated path.
- The online run used the existing system TUN route for Photon UDP. The launcher's HTTP(S) proxy option covers bootstrap traffic; room traffic follows the system route.
