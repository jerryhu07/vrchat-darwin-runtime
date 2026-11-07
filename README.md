# VRChat Darwin Runtime

## **Built entirely by Codex. Proof of concept only.**

**VRChat updates are likely to break this project.**

This source preview explores how to run VRChat on Apple Silicon with Wine, FEX, and DXMT. A Linux x86-64 compatibility layer handles the ELF and userspace ABI needed for protected startup. After startup, host Wine and FEX ARM64EC run the Windows game, and DXMT translates D3D11/10 to Metal.

| Scope | Validation |
|---|---|
| Local baseline | `protected-v1759` launched the original VRChat 2026.4.1p1 on an M4 Pro, established an EAC session, and entered Chinese Bar. The standalone launcher reproduced world entry when run from outside the repository. [Baseline record](docs/verification/protected-v1759.json) |
| Source components | Darwin FEX, FEX ARM64EC, and the platform components were rebuilt using an existing Wine build. [Component fingerprints](docs/verification/platform-components.json) |
| Tooling and host checks | 9 checks passed. [Test record](docs/verification/release-tools.json) |
| Windows test programs | 18 compiled. Runtime checks with the rebuilt components are pending. [Compilation record](docs/verification/owned-compile.json) |
| Complete source build | Runtime assembly, window and fullscreen behavior, online world entry, performance, and testing on a second machine are pending. [Known issues](docs/known-issues.md) |

## Build and test

```sh
python3 tools/dev.py test
python3 tools/dev.py fetch --component fex-darwin
python3 tools/dev.py build --component fex-darwin
```

See the [build guide](docs/build.md) for prerequisites, the ARM64EC and Wine builds, and the Linux guest dependencies. The [architecture guide](docs/architecture.md) describes the startup handoff and the role of each component.

## Sources and licenses

`sources.lock.json` pins upstream commits, dependencies, and patches. `graphics.lock.json` records the validated DXMT and WineMetal pairing. See the [project license](LICENSE) and [third-party notices](licenses/README.md).

Game and EAC files, account data, logs, and build outputs belong in the local runtime environment.
