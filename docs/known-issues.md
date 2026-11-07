# Known issues and validation limits

- The online result for VRChat 2026.4.1p1 applies to the local `protected-v1759` artifacts. The source components have been built. Complete assembly, online play, window behavior, and performance still need testing.
- The validated local baseline uses a matched DXMT and WineMetal pair. Rebuilding the graphics components requires the Metal tools and a new ABI and rendering check.
- The RootFS staging tool pins the publicly available ELF dependencies. The online run used a separately prepared Linux Wine and EAC startup environment and a native Wine prefix. Setting up the full environment from an empty directory remains unverified.
- An earlier startup process encountered lock reentry when its signal handler accessed the host environment during shutdown. The native game still entered a world in the v1759 run. Startup shutdown needs its own regression check.
- The validated online run routed Photon UDP through TUN. The launcher can use an HTTP(S) proxy for downloads. Room traffic follows the system route.
