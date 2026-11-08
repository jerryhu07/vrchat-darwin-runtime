# VRChat Darwin Runtime

## **Built entirely by Codex. Proof of concept only.**

**VRChat updates are likely to break this project.**

This source preview explores how to run VRChat on Apple Silicon with Wine, FEX, and DXMT. A Linux x86-64 compatibility layer handles the ELF and userspace ABI needed for protected startup. After startup, host Wine and FEX ARM64EC run the Windows game, and DXMT translates D3D11/10 to Metal.

| Scope | Validation |
|---|---|
| Assembled runtime | Source-built Wine, FEX, and platform components with pinned public graphics and guest inputs launched the original VRChat 2026.4.1p1 on an M4 Pro running macOS 27.0.1. A new prefix and independent game directory established an EAC session and entered a room. [Reproduction record](docs/verification/reproduced-runtime.json) |
| Source components | [Component fingerprints](docs/verification/platform-components.json) record the selected Wine/FEX pairing and platform sources. |
| Tooling and host checks | 8 checks passed. [Test record](docs/verification/release-tools.json) |
| Windows test programs | 20 runtime checks passed in a newly prepared runtime and prefix. [Runtime record](docs/verification/owned-runtime.json) |
| Remaining validation | A second machine, window/fullscreen behavior, performance, and the optional DXMT source build remain unverified. [Known issues](docs/known-issues.md) |

## Build and test

```sh
python3 tools/dev.py test
python3 tools/dev.py fetch --component fex-darwin
python3 tools/dev.py build --component fex-darwin
```

See the [build guide](docs/build.md) for prerequisites, the ARM64EC and Wine builds, and the Linux guest dependencies. The [architecture guide](docs/architecture.md) describes the startup handoff and the role of each component.

## Sources and licenses

`sources.lock.json` pins upstream commits and patches. `graphics.lock.json` and `guest-dependencies.lock.json` pin the public graphics and Linux runtime inputs. See the [project license](LICENSE) and [third-party notices](licenses/README.md).

Game and EAC files, account data, logs, and build outputs belong in the local runtime environment.
