# Build guide

## Prerequisites

Use an Apple Silicon Mac with the macOS SDK, Python 3.9 or later, CMake, GNU Make, pkg-config, Flex, Bison 3 or later, and fmt 12.x with pkg-config and CMake metadata. Building Wine also requires the freetype, fontconfig, GnuTLS, and MoltenVK development dependencies.

The build uses two upstream llvm-mingw distributions.

- 20260616 supplies the ARM64EC toolchain. Rebuild its CRT and C++ runtime with x18 and x28 reserved before building FEX ARM64EC or the optional DXMT components.
- 20261006 supplies the toolchain for Wine and the x64 test programs.

See `toolchain.lock.json` for the download URLs, SHA-256 hashes, and runtime source revisions. Extract the distributions into `.local/toolchain` and `.local/wine-toolchain`, respectively. Build the ARM64EC runtime in the first copy.

```sh
sh tools/build-crt.sh arm64ec cxx
```

The script writes to `.local/toolchain` and builds from pinned mingw-w64 and LLVM commits. The ARM64EC FEX and optional DXMT builds use `-ffixed-x18 -ffixed-x28` and run `fix-x18-tls.py` on the resulting PE files to move TLS accesses from x18 to x28.

## Fetch the sources

```sh
python3 tools/dev.py fetch --component fex-arm64ec
python3 tools/dev.py fetch --component fex-darwin
python3 tools/dev.py fetch --component wine
```

For offline use, pass `--local-repository /path/to/repository` to export the pinned commit from an existing Git checkout. The fetch step verifies patch hashes and the resulting files. Use a fresh source directory when fetching again.

The Wine patches export eight existing Metal helpers. The source lock also records the inputs for the optional DXMT build.

## Build the components

```sh
python3 tools/dev.py build --component fex-arm64ec --toolchain "$PWD/.local/toolchain"
python3 tools/dev.py build --component fex-darwin
```

For Wine, point `VRCHAT_BISON` at a Bison 3 or later executable and `VRCHAT_MOLTENVK_LIB` at the published `libMoltenVK.dylib`.

```sh
python3 tools/dev.py build --component wine \
  --toolchain "$PWD/.local/wine-toolchain" \
  --bison "$VRCHAT_BISON" --moltenvk-lib "$VRCHAT_MOLTENVK_LIB" --jobs 2
```

The Wine build runs configure and Make under the system ARM64 shell, including when Python is running under Rosetta. It gives Autoconf a relative path to the MoltenVK library. For a partial build, pass `--target` once for each target, such as `dlls/ntdll/ntdll.so`, `dlls/ntdll/aarch64-windows/ntdll.dll`, and `server/wineserver`.

```sh
python3 tools/build-platform.py \
  --wine-build .local/build/wine \
  --fex .local/build/fex-arm64ec/Bin/libarm64ecfex.dll \
  --toolchain .local/wine-toolchain --llvm .local/wine-toolchain/bin
```

The platform build derives its ABI header from the selected DLL symbol tables and records the Wine, FEX, and bridge hashes. Rebuild and verify the pairing after changing any of those components.

## Stage the Linux guest inputs

`guest-dependencies.lock.json` pins 16 GNU and ELF inputs. Thirteen come from public debuginfod servers, `librt.so.1` comes from Debian's `libc6_2.41-12+deb13u4_amd64.deb`, and two Wine frontend files come from the official Proton 11.0-1 depot. To obtain the pinned depot in Steam, run `download_depot 4628710 4628711 2323543246978012070` in the Steam console.

```sh
python3 tools/fetch-guest.py --output "$VRCHAT_ROOTFS" --proton "$PROTON_DIR"
```

The script checks the hashes, stages the files in a new RootFS, and writes local user, DNS, and gconv configuration. It installs Proton's `files/bin/wine` as `/opt/wine-devel/bin/wine`, the path expected by the startup executor.

Build the small ELF module that forwards Wine startup using the supplied assembly and an ELF linker.

```sh
python3 tools/build-elf-entry.py --llvm .local/wine-toolchain/bin \
  --linker .local/toolchain/bin/ld.lld --rootfs "$VRCHAT_ROOTFS"
```

Online startup also needs the complete Linux Wine installation, the userspace EAC runtime, private XQuartz authorization, and a shared view of the original game directory. The [baseline record](verification/protected-v1759.json) covers the separately prepared local setup.

## Build the startup executor

Add `--epoll-prefix "$EPOLL_PREFIX"` to the `build-platform.py` command. The prefix must provide `include/libepoll-shim` and `lib/libepoll-shim.0.dylib`. The tested version was epoll-shim v0.0.20240608.

This builds `.local/platform/fli-fexcore-process-probe` and the `linux-bridge.so` it loads. The executor uses ad hoc debug signing to trace children running as the same user. See the [platform build record](verification/platform-components.json) for the artifact fingerprints.

## Graphics

The local baseline used pinned DXMT and WineMetal binaries. If you already have the validated Wine build, you can stage its graphics files without the Metal compiler, Meson, or LLVM 15.

```sh
python3 tools/stage-graphics.py --wine-build "$VRCHAT_ACCEPTED_WINE_BUILD" \
  --output .local/graphics-accepted
```

`graphics.lock.json` pins four PE DLLs, native `winemetal.so`, libunwind, and their Wine pairing. The validated `d3d11` and `dxgi` already use x28 for TLS. Use the pinned `d3d10core` and the paired Wine build's ntdll, winemac, and win32u. A newly built Wine still needs runtime testing with these graphics components.

To rebuild DXMT, install Meson 1.3 or later, Ninja, LLVM 15, and a developer toolchain that provides `metal` and `metallib` through `xcrun`.

```sh
python3 tools/dev.py fetch --component dxmt
python3 tools/dev.py build --component dxmt \
  --toolchain "$PWD/.local/toolchain" --llvm-native "$VRCHAT_LLVM15"
```

The source uses VKMT's v0.80 Xcode 27 and ARM64 patches for the native helper architecture, Metal intrinsics, and view sizing. The rebuild path is unverified on the test machine. Test the rebuilt artifacts before updating the accepted hashes in `graphics.lock.json`.

## Run the checks

`python3 tools/dev.py test` checks source integrity, path ownership, boolean switches, the network ABI, and the graphics inputs. Set `LLVM_BIN` and `ARM64EC_CLANG` to enable the AArch64 PE checks for TLS rewriting and idempotence.

`tools/check-runtime.py` compiles and runs the Windows test programs in `tests/runtime-cases.json`. Use `--compile-only` to check compilation. Running the programs requires an assembled and matched native test prefix and an idle Wine session.

<a id="runtime-profile"></a>
### Runtime profile

The profile is a JSON object mapping environment variable names to strings. Use absolute paths. A compilation check only needs `REGRESSION_WINE_BUILD` to read ntdll symbols.

```sh
mkdir -p .local
python3 - <<'PY'
import json
from pathlib import Path
root = Path.cwd()
profile = {
    'REGRESSION_WINE_BUILD': str(root / '.local/build/wine'),
}
(root / '.local/owned-profile.json').write_text(json.dumps(profile, indent=2) + '\n')
PY
python3 tools/check-runtime.py --compile-only \
  --profile .local/owned-profile.json --rootfs "$VRCHAT_ROOTFS" \
  --toolchain .local/wine-toolchain --llvm .local/wine-toolchain/bin \
  --output .local/owned-compile
```

Choose a new output directory. The `--rootfs` argument supplies libc symbols and sets `VRCHAT_ROOTFS` for the runtime checks.

For runtime checks, keep the feature settings from your assembled environment and add these paths.

| Field | Value |
|---|---|
| `REGRESSION_PREFIX` | Dedicated test prefix with a verified Wine and FEX pairing |
| `REGRESSION_WINE_FRONTEND` | `wine-host` from the platform build |
| `VRCHAT_RUNTIME_ROOT` | Host directory containing the runtime components |
| `VRCHAT_GAME_DIR` | Directory for the test programs, used for path ownership checks |
| `VRCHAT_STATE_DIR` | Private runtime state directory |
| `REGRESSION_FLI_CARRIER` | `linux-carrier.so` from the platform build |
| `REGRESSION_LINUX_BRIDGE_PATH` | `linux-bridge.so` from the same build |
| `REGRESSION_ELF_TRANSPORT_DLL` | `elf-transport.dll` from the same build |

The runner sets `WINEPREFIX`, `WINEBUILDDIR`, `WINESERVER`, `WINELOADER`, and the test switches. It saves the effective profile as `effective-profile.json` in the output directory. Project boolean switches use `"1"` to enable and `"0"` or an unset value to disable. Paths, numbers, and upstream Wine and FEX variables follow their own formats.

Assembling the complete native test environment from an empty directory remains unverified. The example above prepares the input for compilation checks.

## Archive the source

```sh
git archive --format=tar --prefix=vrchat-runtime/ HEAD | gzip -n > source.tar.gz
shasum -a 256 source.tar.gz
```

The archive contains the committed files. See the [README](../README.md) for the validation scope.

## Develop changes

For incremental development, use the component's own CMake, Make, or Meson build. `dev.py build` checks reproducibility against the pinned source and rejects changes to the exported upstream tree.

To retain upstream changes, create a patch against the pinned commit and the existing patch series. Add the patch and its SHA-256 to the ordered list in the source lock, update the hashes of the patched files, and rebuild from a fresh export. Keep project-owned JIT adapters in the normal working tree. The build records their hashes separately.
