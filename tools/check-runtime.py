#!/usr/bin/env python3
"""Run the retained owned fixtures in an isolated, explicitly paired runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/owned'


def run(args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def main(args):
    profile = json.loads(args.profile.read_text())
    required = {'REGRESSION_WINE_BUILD'}
    if not args.compile_only:
        required.update({'REGRESSION_PREFIX', 'REGRESSION_WINE_FRONTEND',
                         'VRCHAT_RUNTIME_ROOT', 'VRCHAT_GAME_DIR', 'VRCHAT_STATE_DIR',
                         'REGRESSION_FLI_CARRIER', 'REGRESSION_LINUX_BRIDGE_PATH', 'REGRESSION_ELF_TRANSPORT_DLL'})
    missing = sorted(required - profile.keys())
    if missing:
        raise SystemExit('Profile missing: ' + ', '.join(missing) + '; see docs/build.md#runtime-profile')
    for name in required:
        if not isinstance(profile[name], str) or not Path(profile[name]).is_absolute():
            raise SystemExit(f'{name} must be an absolute path in the profile')
    profile['VRCHAT_ROOTFS'] = str(args.rootfs.resolve())
    if not args.compile_only:
        try:
            subprocess.run([str(Path(profile['REGRESSION_WINE_BUILD']) / 'server/wineserver'), '-w'],
                           env={**os.environ, 'WINEPREFIX': profile['REGRESSION_PREFIX']}, check=True, timeout=1)
        except subprocess.TimeoutExpired:
            raise SystemExit('Close the session using the selected test prefix before running controls') from None
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    profile.pop('REGRESSION_MEMORY_DIAGNOSTIC', None)
    profile['REGRESSION_FLI_OWNED_FAR_SHARED_CONTROL'] = '1'
    (output / 'effective-profile.json').write_text(json.dumps(profile, indent=2) + '\n')
    llvm = args.llvm.resolve()
    libc = args.rootfs.resolve() / 'usr/lib64/libc.so.6'
    lines = subprocess.check_output([str(llvm / 'llvm-nm'), '-D', str(libc)], text=True).splitlines()
    elf = {line.split()[-1].split('@')[0]: int(line.split()[0], 16)
           for line in lines if len(line.split()) >= 3 and re.fullmatch('[0-9a-fA-F]+', line.split()[0])}
    peer_defines = {'RAISE': 'raise', 'FORK': 'fork', 'SYSCALL': 'syscall', 'ERRNO': '__errno_location',
                    'DEV_MAJOR': 'gnu_dev_major', 'DEV_MINOR': 'gnu_dev_minor',
                    'PTHREAD_CREATE': 'pthread_create', 'PTHREAD_JOIN': 'pthread_join'}
    macros = ['-DFLI_TEST_' + name + '_RVA=' + hex(elf[symbol]) for name, symbol in peer_defines.items()]
    for index, name in enumerate(['pthread_mutexattr_init', 'pthread_mutexattr_settype', 'pthread_mutex_init',
                                   'pthread_mutex_lock', 'pthread_mutex_trylock', 'pthread_mutex_unlock']):
        macros.append('-DFLI_TEST_MUTEX_RVA_' + str(index) + '=' + hex(elf[name]))
    peer = output / 'owned-peer.so'
    run(['/usr/bin/clang++', '-std=c++20', '-dynamiclib', '-arch', 'arm64', '-O2', '-g',
         '-fvisibility=hidden', '-ffixed-x18', '-ffixed-x28', *macros,
         FIXTURES / 'memory-owner-peer.cpp', '-o', peer])
    run(['codesign', '--force', '--sign', '-', peer])
    atomic = output / 'atomic.o'
    run(['/usr/bin/clang', '--target=x86_64-linux-gnu', '-c', FIXTURES / 'atomic-contention.S', '-o', atomic])
    arrays = []
    for operation in ['atomic32', 'atomic64', 'mutex']:
        binary = output / (operation + '.bin')
        run([llvm / 'llvm-objcopy', '--only-section=.text.' + operation, '-O', 'binary', atomic, binary])
        arrays.append('static const unsigned char owned_' + operation + '[]={' +
                      ','.join(hex(value) for value in binary.read_bytes()) + '};')
    obj, binary = output / 'pe-export.o', output / 'pe-export.bin'
    run([llvm / 'clang', '--target=x86_64-linux-gnu', '-O2', '-ffreestanding', '-fno-stack-protector',
         '-c', FIXTURES / 'pe-export.c', '-o', obj])
    for operation in ['pe_export', 'pe_notify']:
        run([llvm / 'llvm-objcopy', '--only-section=.text.' + operation, '-O', 'binary', obj, binary])
        arrays.append('static const unsigned char owned_' + operation + '[]={' +
                      ','.join(hex(value) for value in binary.read_bytes()) + '};')
    (output / 'owned-code.h').write_text('\n'.join(arrays) + '\n')
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location('platform_build', ROOT / 'tools/build-platform.py')
    platform_build = module_from_spec(spec)
    spec.loader.exec_module(platform_build)
    wine = Path(profile['REGRESSION_WINE_BUILD'])
    ws = platform_build.symbols(wine / 'dlls/ntdll/aarch64-windows/ntdll.dll', llvm)
    nt_path = '\\??\\Z:' + str(peer).replace('/', '\\')
    generated = output / 'owned-peer-path.h'
    generated.write_text('#define FLI_TEST_PEER_PATH L' + json.dumps(nt_path) + '\n')
    flags = ['-DFLI_TEST_EC_RVA=' + hex(ws['#RtlIsEcCode']),
             '-DFLI_TEST_UNWIND_RVA=' + hex(ws['virtual_unwind'])]
    env = {k: v for k, v in os.environ.items() if not k.startswith(('WINE', 'REGRESSION', 'MONO', 'FEX_', 'VKMT', 'DYLD_'))}
    env.update(profile)
    if not args.compile_only:
        env.update(WINEPREFIX=profile['REGRESSION_PREFIX'], WINEBUILDDIR=str(wine),
                   WINESERVER=str(wine / 'server/wineserver'), WINELOADER=profile['REGRESSION_WINE_FRONTEND'],
                   WINEDEBUG='-all,+timestamp,err+all,warn+seh', FEX_TSOENABLED='0',
                   FEX_VECTORTSOENABLED='0', FEX_MEMCPYSETTSOENABLED='0', LC_ALL='C.UTF-8')
    cases = json.loads((ROOT / 'tests/runtime-cases.json').read_text())
    baseline = json.loads((FIXTURES / 'flag-observations.json').read_text())['cases']
    observations = re.compile(r'^(?:READONLY_FLAGS|CONTROL_FLAGS|EXCEPTION_FLAGS_OBS) (?:kind=\d+ )?case=\d+ expected=[0-9a-f]+ got=[0-9a-f]+', re.M)
    results = []
    report = {'tests': results, 'passed': False, 'full_x86_exception_fidelity': False,
              'profile_sha256': hashlib.sha256(args.profile.read_bytes()).hexdigest(),
              'libc_sha256': hashlib.sha256(libc.read_bytes()).hexdigest()}
    for index, case in enumerate(cases['flags'] + cases['controls']):
        source = FIXTURES / case[0]
        is_flags = index < len(cases['flags'])
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if is_flags and digest != baseline[case[1]]['source_sha256']:
            raise SystemExit(f'Flag fixture changed: {case[0]}')
        executable = output / (source.stem + '.exe')
        libraries = ['-lruntimeobject'] if source.name == 'network-cost.c' else []
        run([args.toolchain / 'bin/x86_64-w64-mingw32-clang', '-O1', '-fms-extensions',
             *flags, '-include', generated, '-I' + str(output), source, *libraries, '-o', executable])
        if args.compile_only:
            results.append({'source': case[0], 'compiled': True})
            continue
        log_path = output / (source.stem + '.log')
        arguments = [] if is_flags else case[1]
        # The PE reader exercises mappings made before Wine starts, as in protected entry.
        case_env = {**env, 'REGRESSION_NATIVE_ELF_EXEC_GATE': '1'} if arguments == ['pe-unaligned-read'] else env
        with log_path.open('w') as log:
            process = subprocess.Popen([profile['REGRESSION_WINE_FRONTEND'], str(executable), *arguments],
                                       cwd=output, env=case_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                try:
                    code = process.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    code = 'timeout'
            finally:
                run([wine / 'server/wineserver', '-k'], env=env, timeout=10)
                run([wine / 'server/wineserver', '-w'], env=env, timeout=10)
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        text = log_path.read_text(errors='replace')
        if is_flags:
            expected = baseline[case[1]]
            passed = (digest == expected['source_sha256'] and code == expected['result'] and
                      len(observations.findall(text)) == case[2] and observations.findall(text) == expected['observations'])
        else:
            passed = code == 0 and case[2] in text
        item = {'source': case[0], 'source_sha256': digest, 'result': code, 'passed': passed}
        results.append(item)
        report['passed'] = len(results) == len(cases['flags']) + len(cases['controls']) and all(row['passed'] for row in results)
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(item), flush=True)
        if not passed:
            raise SystemExit(1)
    if args.compile_only:
        report['scope'] = 'Compilation only; no runtime control executed'
        (output / 'compile-results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'compiled': len(results), 'runtime_executed': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name, help_text in {
        'profile': 'JSON environment map; required fields and example: docs/build.md#runtime-profile',
        'toolchain': 'llvm-mingw prefix containing bin/x86_64-w64-mingw32-clang',
        'llvm': 'directory containing llvm-nm and llvm-objcopy',
        'rootfs': 'Linux root containing usr/lib64/libc.so.6; also sets VRCHAT_ROOTFS',
        'output': 'new directory for fixtures and results; must not already exist',
    }.items():
        parser.add_argument('--' + name, type=Path, required=True, help=help_text)
    parser.add_argument('--compile-only', action='store_true', help='compile fixtures without starting Wine')
    main(parser.parse_args())
