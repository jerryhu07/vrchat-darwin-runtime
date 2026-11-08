# Build guide

## Prerequisites

Use an Apple Silicon Mac with the macOS SDK, Python 3.9 or later, CMake, GNU Make, pkg-config, Flex, Bison 3 or later, and fmt 12.x with pkg-config and CMake metadata. Building Wine also requires the freetype, fontconfig, GnuTLS, and MoltenVK development dependencies. Install zstd for the public graphics archive and [XQuartz](https://www.xquartz.org/) for the Linux startup display. Allow roughly 40 GB for sources, builds, runtime, and two new prefixes, in addition to the game. The assembler, objdump, and objcopy from the pinned llvm-mingw toolchains are used for the TEB register adaptation.

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
python3 tools/dev.py fetch --component epoll-shim
```

For offline use, pass `--local-repository /path/to/repository` to export the pinned commit from an existing Git checkout. The fetch step verifies patch hashes and the resulting files. Use a fresh source directory when fetching again.

The Wine patches export eight existing Metal helpers. The source lock also records the inputs for the optional DXMT build.

## Stage the graphics

This downloads the four parts of the public VKMT 1.0 archive, checks the reassembled archive, extracts the graphics inputs, and adapts their TEB references.

```sh
python3 tools/stage-graphics.py --llvm .local/wine-toolchain/bin \
  --output .local/graphics
```

For an existing copy of that public archive, add `--archive /path/to/MetalSharp-Wine-Runtime-COMPLETE-all-arch-2026-07-31.tar.zst`. The same hash check applies.

## Build the components

```sh
python3 tools/dev.py build --component fex-arm64ec --toolchain "$PWD/.local/toolchain"
python3 tools/dev.py build --component fex-darwin
python3 tools/dev.py build --component epoll-shim
```

For Wine, point `VRCHAT_BISON` at a Bison 3 or later executable and `VRCHAT_MOLTENVK_LIB` at `.local/graphics/dlls/winevulkan/libMoltenVK.dylib` from the verified public archive.

```sh
python3 tools/dev.py build --component wine \
  --toolchain "$PWD/.local/wine-toolchain" \
  --bison "$VRCHAT_BISON" --moltenvk-lib "$VRCHAT_MOLTENVK_LIB" --jobs 2
```

The Wine build runs configure and Make under the system ARM64 shell, including when Python is running under Rosetta. It gives Autoconf a relative path to the MoltenVK library. For development, pass `--target` once for each selected target. Runtime assembly requires the complete build, including resource modules such as `aero.msstyles`.

```sh
python3 tools/build-platform.py \
  --wine-build .local/build/wine \
  --fex .local/build/fex-arm64ec/Bin/libarm64ecfex.dll \
  --toolchain .local/wine-toolchain --llvm .local/wine-toolchain/bin \
  --epoll-prefix .local/deps/epoll-shim
```

The platform build derives its ABI header from the selected DLL symbol tables and records the Wine, FEX, and bridge hashes. Rebuild and verify the pairing after changing any of those components.

## Prepare the game inputs

Supply an unmodified official VRChat Windows installation, official Proton 11.0-1, and the Proton EasyAntiCheat Runtime from Steam. Each user supplies their own game installation and account; the repository does not distribute them.

`guest-dependencies.lock.json` pins the Proton depot (`download_depot 4628710 4628711 2323543246978012070` in Steam's console), the complete `files/` tree, EAC runtime members, GNU libraries, Ubuntu startup packages, and Mozilla CA certificates. Set `PROTON_DIR` to the downloaded Proton directory and `PROTON_EAC_DIR` to the official Proton EasyAntiCheat Runtime directory (Steam app 1826330). The preparer rejects inputs with different hashes.

## Assemble and launch

Choose an empty output path outside the game directory. `prepare` copies the built runtime components and their native libraries, downloads the pinned guest packages, creates the game mappings, and initializes separate, empty native and Linux Wine prefixes.

```sh
python3 tools/runtime.py prepare \
  --wine-build .local/build/wine \
  --fex .local/build/fex-arm64ec/Bin/libarm64ecfex.dll \
  --graphics .local/graphics \
  --epoll-prefix .local/deps/epoll-shim \
  --llvm .local/wine-toolchain/bin --linker .local/toolchain/bin/ld.lld \
  --proton "$PROTON_DIR" --eac "$PROTON_EAC_DIR" \
  --game "$VRCHAT_GAME_DIR" --output "$VRCHAT_RUNTIME_DIR"

python3 tools/runtime.py run --runtime "$VRCHAT_RUNTIME_DIR"
```

The runtime uses the original `start_protected_game.exe`. Log in normally when the game prompts. Keep the launcher running until the game exits; Ctrl-C stops only this runtime's processes. Logs and the generated test profile live under the runtime directory. If initialization fails, inspect its `state/` logs before preparing a fresh output directory.

An optional `--proxy http://127.0.0.1:PORT` on `run` supplies the startup HTTP(S) proxy. Photon room traffic uses the system's UDP route. The launcher does not alter network settings.

## Optional DXMT source build

To rebuild DXMT, install Meson 1.3 or later, Ninja, LLVM 15, and a developer toolchain that provides `metal` and `metallib` through `xcrun`.

```sh
python3 tools/dev.py fetch --component dxmt
python3 tools/dev.py build --component dxmt \
  --toolchain "$PWD/.local/toolchain" --llvm-native "$VRCHAT_LLVM15"
```

The source uses VKMT's v0.80 Xcode 27 and ARM64 patches for the native helper architecture, Metal intrinsics, and view sizing. The rebuild path is unverified on the test machine. Test the rebuilt artifacts before replacing the public binary inputs in `graphics.lock.json`.

## Run the checks

`python3 tools/dev.py test` checks source integrity, path ownership, boolean switches, the network ABI, and Wine Metal helper exports. Set `LLVM_BIN` and `ARM64EC_CLANG` to enable the AArch64 PE checks for TLS rewriting and idempotence.

`tools/check-runtime.py` compiles and runs the Windows test programs in `tests/runtime-cases.json`. Use `--compile-only` to check compilation. Running the programs requires an assembled runtime and an idle test prefix. Other Wine prefixes may stay open.

### Runtime profile

`prepare` writes `profile.json` with the matched component paths, dedicated prefix, and runtime settings. Run the owned Windows programs with that profile while the runtime is idle:

```sh
python3 tools/check-runtime.py \
  --profile "$VRCHAT_RUNTIME_DIR/profile.json" \
  --rootfs "$VRCHAT_RUNTIME_DIR/native-rootfs" \
  --toolchain .local/wine-toolchain --llvm .local/wine-toolchain/bin \
  --output "$VRCHAT_RUNTIME_DIR/state/owned-checks"
```

Choose a new output directory for each run. `--compile-only` skips execution; its profile only needs an absolute `REGRESSION_WINE_BUILD`. Project boolean switches use `"1"` to enable and `"0"` or an unset value to disable. Paths, numbers, and upstream Wine/FEX settings retain their own formats.

## Archive the source

```sh
git archive --format=tar --prefix=vrchat-runtime/ HEAD | gzip -n > source.tar.gz
shasum -a 256 source.tar.gz
```

The archive contains the committed files. See the [README](../README.md) for the validation scope.

## Develop changes

For incremental development, use the component's own CMake, Make, or Meson build. `dev.py build` checks reproducibility against the pinned source and rejects changes to the exported upstream tree.

To retain upstream changes, create a patch against the pinned commit and the existing patch series. Add the patch and its SHA-256 to the ordered list in the source lock, update the hashes of the patched files, and rebuild from a fresh export. Keep project-owned JIT adapters in the normal working tree. The build records their hashes separately.
