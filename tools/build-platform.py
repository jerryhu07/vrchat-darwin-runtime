#!/usr/bin/env python3
"""Build platform sources against explicitly selected Wine/FEX artifacts.

This does not build Wine, prepare a prefix, or certify a complete runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
from dev import source_inventory

ROOT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def symbols(path, llvm):
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 60)[0]
    base = struct.unpack_from('<Q', data, pe + 48)[0]
    output = subprocess.check_output([str(llvm / 'llvm-nm'), str(path)], text=True)
    return {row.split()[-1]: int(row.split()[0], 16) - base
            for row in output.splitlines() if len(row.split()) >= 3 and re.fullmatch('[0-9a-fA-F]+', row.split()[0])}


def build(args):
    source = ROOT / 'src/platform'
    inputs = source_inventory(source)
    darwin = ROOT / '.local/source/fex-darwin'
    exported = json.loads((ROOT / '.local/fex-darwin-sources.json').read_text())
    built = json.loads((ROOT / '.local/fex-darwin-build.json').read_text())
    darwin_library = ROOT / built['artifact']
    if exported['files'] != source_inventory(darwin) or hashlib.sha256(darwin_library.read_bytes()).hexdigest() != built['sha256']:
        raise SystemExit('Darwin FEX sources/library no longer match their build receipt')
    output = ROOT / '.local/platform'
    output.mkdir(parents=True, exist_ok=True)
    wine = args.wine_build / 'dlls/ntdll/aarch64-windows/ntdll.dll'
    ws, fs = symbols(wine, args.llvm), symbols(args.fex, args.llvm)
    definitions = {
        'VRCHAT_WINE_UNIX_DISPATCH_RVA': ws['__wine_unix_call_dispatcher_arm64ec'],
        'VRCHAT_FEX_MEMORY_DISPATCH_RVA': fs['#FliMemoryDispatch'],
        'VRCHAT_FEX_CONFIGURE_MEMORY_RVA': fs['#FliConfigureMemoryDispatch'],
        'VRCHAT_FEX_INSTALL_ALIASES_RVA': fs['#LabInstallInstructionAliases'],
        'VRCHAT_FEX_INVALIDATION_TRACKER_RVA': fs['_ZN12_GLOBAL__N_119InvalidationTrackerE'],
        'VRCHAT_FEX_DISPATCHER_QUERY_RVA': fs['#FliDispatcherLoopTop'],
        'REGRESSION_WINE_NOTIFY_ALLOC_RVA': ws['pNotifyMemoryAlloc'],
        'REGRESSION_WINE_NOTIFY_PROTECT_RVA': ws['pNotifyMemoryProtect'],
        'REGRESSION_WINE_CONTEXT_RVA': ws['context_arm_to_x64'],
        'REGRESSION_FEX_RESET_RVA': next(v for k, v in fs.items() if k.startswith('_Z26ResetToConsistentStateImpl')),
        'REGRESSION_FEX_UNALIGNED_RVA': next(v for k, v in fs.items() if k.startswith('_ZN7FEXCore11ArchHelpers5Arm6421HandleUnalignedAccess')),
        'REGRESSION_FEX_CALLRET_RVA': fs['#FliRecoverCallRetGuard'],
        'REGRESSION_FEX_GUEST_BRANCH_RVA': fs.get('RegressionGuestBranchTrace', 0),
        'REGRESSION_FEX_CPUID_OBSERVATION_RVA': fs.get('RegressionCpuidObservation', 0),
    }
    (output / 'generated-abi.h').write_text('#pragma once\n' + ''.join(f'#define {k} {v:#x}\n' for k, v in definitions.items()))
    common = ['clang++', '-std=c++20', '-dynamiclib', '-arch', 'arm64', '-O2', '-g',
              '-ffixed-x18', '-ffixed-x28', '-fvisibility=hidden', '-I' + str(source)]
    run([*common, '-I' + str(output), '-Wno-deprecated-declarations', '-Wno-trigraphs',
         '-framework', 'IOKit', '-framework', 'CoreFoundation', source / 'bridge.cpp', '-o', output / 'linux-bridge.so'])
    run([*common, source / 'jit-service.cpp', '-o', output / 'jit-service.so'])
    run(['clang', '-Wall', '-Wextra', '-Werror', '-O2', '-g', source / 'wine-host.c', '-o', output / 'wine-host'])
    run([args.toolchain / 'bin/x86_64-w64-mingw32-clang', '-shared', '-O2',
         '-DREGRESSION_ELF_THREAD_CONTEXT=1', '-I' + str(source),
         source / 'elf-transport.c', source / 'elf-sysv-call.S', '-o', output / 'elf-transport.dll'])
    fex = ROOT / '.local/source/fex-darwin'
    include = ROOT / '.local/build/fex-darwin/include'
    libs = ROOT / '.local/build/fex-darwin/FEXCore/Source'
    fmt = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'fmt'], text=True).split()
    headers = ['FEXCore/include', 'FEXCore/Source', 'FEXHeaderUtils', 'CodeEmitter',
               'External/unordered_dense/include', 'Source/Tools/CommonTools', 'Source/Tools']
    run([*common, '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-sign-compare',
         '-DREGRESSION_FEXCORE_GUEST_MEMORY_BIAS=1', '-DARCHITECTURE_arm64=1',
         '-I' + str(source / 'compat'), '-I' + str(include),
         *['-I' + str(fex / p) for p in headers], *fmt, source / 'elf-carrier.cpp',
         '-L' + str(libs), '-lFEXCore', '-Wl,-rpath,' + str(libs), '-o', output / 'linux-carrier.so'])
    artifacts = ['linux-bridge.so', 'jit-service.so', 'wine-host', 'elf-transport.dll', 'linux-carrier.so']
    if args.epoll_prefix:
        startup = ROOT / 'src/startup'
        epoll = args.epoll_prefix.resolve()
        epoll_lib = epoll / 'lib/libepoll-shim.0.dylib'
        executor = output / 'fli-fexcore-process-probe'
        run(['clang++', '-std=c++20', '-arch', 'arm64', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-unused-parameter', '-Wno-sign-compare',
             '-DREGRESSION_FEXCORE_GUEST_MEMORY_BIAS=1', '-DARCHITECTURE_arm64=1',
             '-DREGRESSION_FLI_EPOLL_SHIM=1', '-I' + str(source), '-I' + str(source / 'compat'),
             '-I' + str(include), *['-I' + str(fex / p) for p in headers],
             '-isystem', epoll / 'include/libepoll-shim', *fmt, startup / 'root.cpp',
             '-L' + str(libs), '-lFEXCore', '-Wl,-rpath,' + str(libs),
             epoll_lib, '-Wl,-rpath,' + str(epoll_lib.parent), '-o', executor])
        run(['codesign', '--force', '--sign', '-', '--options', 'runtime',
             '--entitlements', startup / 'debug.entitlements', executor])
    for name in artifacts:
        if not name.endswith('.dll'):
            run(['codesign', '--force', '--sign', '-', output / name])
    if inputs != source_inventory(source):
        raise SystemExit('Platform sources changed during the build')
    receipt = {'scope': 'Platform components built against explicitly selected Wine/FEX artifacts; their runtime validation is separate',
               'source_files': inputs,
               'darwin_fex_sha256': built['sha256'],
               'wine_ntdll_sha256': hashlib.sha256(wine.read_bytes()).hexdigest(),
               'fex_sha256': hashlib.sha256(args.fex.read_bytes()).hexdigest(),
               'definitions': definitions,
               'artifacts': {p: hashlib.sha256((output / p).read_bytes()).hexdigest() for p in artifacts}}
    if args.epoll_prefix:
        receipt['startup_sources'] = source_inventory(startup)
        receipt['artifacts'][executor.name] = hashlib.sha256(executor.read_bytes()).hexdigest()
    (output / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wine-build', type=Path, required=True)
    parser.add_argument('--fex', type=Path, required=True)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--llvm', type=Path, required=True)
    parser.add_argument('--epoll-prefix', type=Path,
                        help='also build the startup executor against this epoll-shim installation')
    build(parser.parse_args())
