#!/usr/bin/env python3
"""Fetch pinned sources and build the recovered runtime components."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / '.local'
LOCK = json.loads((ROOT / 'sources.lock.json').read_text())


def run(args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_lock():
    return {'path': 'sources.lock.json', 'sha256': sha(ROOT / 'sources.lock.json')}


def source_inventory(directory):
    files = {}
    for path in sorted(directory.rglob('*')):
        relative = path.relative_to(directory)
        if any(part in ['.git', '__pycache__'] for part in relative.parts) or path.suffix == '.pyc':
            continue
        if path.is_symlink():
            files[str(relative)] = 'symlink:' + os.readlink(path)
        elif path.is_file():
            files[str(relative)] = sha(path)
    return files


def jit_sources():
    files = {'jit/' + name: value for name, value in source_inventory(ROOT / 'src/jit').items()}
    files['platform/runtime-abi.h'] = sha(ROOT / 'src/platform/runtime-abi.h')
    return files


def gitdir(path):
    if (path / 'HEAD').is_file() and (path / 'objects').is_dir():
        return path
    return path / '.git'


def export(repository, commit, destination):
    destination.mkdir(parents=True, exist_ok=True)
    # Git archive exports committed files only; local edits and old build outputs
    # cannot silently become build inputs.
    with tempfile.TemporaryFile() as archive:
        run(['git', '--git-dir=' + str(gitdir(repository)), 'archive', commit], stdout=archive)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as tar:
            # These archives come from the pinned repositories, not user uploads.
            tar.extractall(destination)


def repository(url, commit, name):
    cache = LOCAL / 'git' / name
    if not cache.exists():
        run(['git', 'init', '--bare', cache])
    present = subprocess.run(['git', '--git-dir=' + str(cache), 'cat-file', '-e', commit + '^{commit}'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not present:
        run(['git', '--git-dir=' + str(cache), 'fetch', '--depth=1', url, commit])
    return cache


def fetch(args):
    spec = LOCK[args.component]
    destination = LOCAL / 'source' / args.component
    if destination.exists():
        raise SystemExit(f'Preserve existing sources: {destination}; use a fresh checkout to refetch')
    source = args.local_repository
    if source is None:
        source = repository(spec['url'], spec['commit'], args.component)
    try:
        export(source, spec['commit'], destination)
        for module in spec['submodules']:
            if args.local_repository:
                source_module = gitdir(source) / 'modules' / module['module']
            else:
                source_module = repository(module['url'], module['commit'], args.component + '-' + module['path'].replace('/', '-'))
            export(source_module, module['commit'], destination / module['path'])
        for patch in spec['patches']:
            path = ROOT / patch['path']
            if sha(path) != patch['sha256']:
                raise SystemExit(f'Patch checksum mismatch: {path}')
            # Do not discover the release repository above .local/source: Git
            # otherwise treats patch paths as outside the current subdirectory
            # and can silently skip every hunk.
            patch_env = {**os.environ, 'GIT_CEILING_DIRECTORIES': str(destination.parent)}
            run(['git', 'apply', '--no-index', '--check', path], cwd=destination, env=patch_env)
            run(['git', 'apply', '--no-index', path], cwd=destination, env=patch_env)
        for name, expected in spec['patched_files'].items():
            if sha(destination / name) != expected:
                raise SystemExit(f'Patched source mismatch: {name}')
    except BaseException:
        # Never reuse a partly fetched/patched tree on the next build.
        shutil.rmtree(destination)
        raise
    receipt = LOCAL / (args.component + '-sources.json')
    receipt.write_text(json.dumps({'source': spec, 'files': source_inventory(destination)}, indent=2) + '\n')


def build(args):
    source = LOCAL / 'source' / args.component
    if not source.is_dir():
        raise SystemExit('Run fetch for this component first')
    receipt = LOCAL / (args.component + '-sources.json')
    if not receipt.is_file():
        raise SystemExit('Missing source export receipt; fetch this component first')
    exported = json.loads(receipt.read_text())
    if exported['source'] != LOCK[args.component] or exported['files'] != source_inventory(source):
        raise SystemExit('Exported sources changed; use the component build system for development, then refresh patches and fetch a clean tree')
    for name, expected in LOCK[args.component]['patched_files'].items():
        if sha(source / name) != expected:
            raise SystemExit(f'Source differs from the pinned patch: {name}')
    if args.component == 'wine':
        return build_wine(args, source, exported['files'])
    if args.component == 'dxmt':
        return build_dxmt(args, source, exported['files'])
    if args.component == 'epoll-shim':
        output, prefix = LOCAL / 'build/epoll-shim', LOCAL / 'deps/epoll-shim'
        run(['/usr/bin/arch', '-arm64', 'cmake', '-S', source, '-B', output,
             '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_OSX_ARCHITECTURES=arm64',
             '-DBUILD_TESTING=OFF', '-DCMAKE_INSTALL_PREFIX=' + str(prefix)])
        run(['cmake', '--build', output, '-j', args.jobs])
        run(['cmake', '--install', output])
        if source_inventory(source) != exported['files']:
            raise SystemExit('epoll-shim sources changed during the build')
        artifact = prefix / 'lib/libepoll-shim.0.dylib'
        (LOCAL / 'epoll-shim-build.json').write_text(json.dumps({
            'source_lock': source_lock(), 'artifact': str(artifact.relative_to(ROOT)),
            'sha256': sha(artifact)}, indent=2) + '\n')
        return
    own_sources = jit_sources() if args.component == 'fex-arm64ec' else {}
    output = LOCAL / 'build' / args.component
    env = dict(os.environ)
    # The Python interpreter may itself be running under Rosetta.
    cmake = ['/usr/bin/arch', '-arm64', 'cmake'] if args.component == 'fex-darwin' else ['cmake']
    configure = [*cmake, '-S', source, '-B', output, '-G', 'Unix Makefiles',
                 '-DENABLE_CCACHE=OFF', '-DBUILD_TESTING=OFF', '-DTUNE_CPU=none']
    make = shutil.which('gmake') or shutil.which('make')
    if not make:
        raise SystemExit('GNU Make is required')
    configure += ['-DCMAKE_MAKE_PROGRAM=' + make]
    if args.component == 'fex-arm64ec':
        toolchain = args.toolchain
        if not toolchain or not (toolchain / 'bin/arm64ec-w64-mingw32-clang').is_file():
            raise SystemExit('--toolchain must name the fixed-x18/x28 llvm-mingw toolchain')
        env['PATH'] = str(toolchain / 'bin') + os.pathsep + env.get('PATH', '')
        configure += ['-DCMAKE_BUILD_TYPE=Release', '-DENABLE_LTO=OFF',
                      '-DCMAKE_TOOLCHAIN_FILE=' + str(source / 'Data/CMake/toolchain_mingw.cmake'),
                      '-DMINGW_TRIPLE=arm64ec-w64-mingw32',
                      '-DCMAKE_C_FLAGS=-ffixed-x18 -ffixed-x28',
                      '-DCMAKE_CXX_FLAGS=-ffixed-x18 -ffixed-x28',
                      '-DCMAKE_DISABLE_FIND_PACKAGE_fmt=ON',
                      '-DCMAKE_DISABLE_FIND_PACKAGE_range-v3=ON',
                      '-DOVERRIDE_VERSION=FEX-2607', '-DOVERRIDE_HASH=' + LOCK[args.component]['commit'],
                      '-DVRCHAT_PLATFORM_INCLUDE=' + str(ROOT / 'src/jit')]
        target, artifact = 'arm64ecfex', output / 'Bin/libarm64ecfex.dll'
    else:
        fmt_lib = subprocess.check_output(['pkg-config', '--variable=libdir', 'fmt'], text=True).strip()
        configure += ['-DBUILD_DARWIN_CORE_ONLY=ON', '-DCMAKE_BUILD_TYPE=Debug',
                      '-DCMAKE_OSX_ARCHITECTURES=arm64',
                      '-Dfmt_DIR=' + str(Path(fmt_lib) / 'cmake/fmt'),
                      '-DCMAKE_C_COMPILER=clang', '-DCMAKE_CXX_COMPILER=clang++',
                      '-DENABLE_FEX_ALLOCATOR=OFF', '-DENABLE_JEMALLOC_GLIBC_ALLOC=OFF', '-DENABLE_LTO=OFF',
                      '-DOVERRIDE_VERSION=', '-DOVERRIDE_HASH=']
        target, artifact = 'FEXCore_shared', output / 'FEXCore/Source/libFEXCore.dylib'
    run(configure, env=env)
    run([*cmake, '--build', output, '--target', target, '-j', args.jobs], env=env)
    if args.component == 'fex-arm64ec':
        run([sys.executable, ROOT / 'tools/fix-x18-tls.py', artifact], env=env)
    if source_inventory(source) != exported['files']:
        raise SystemExit('Sources changed during the component build')
    if own_sources and own_sources != jit_sources():
        raise SystemExit('JIT adapter sources changed during the component build')
    receipt = {'component': args.component, 'source_lock': source_lock(),
               'artifact': str(artifact.relative_to(ROOT)), 'sha256': sha(artifact),
               'project_sources': own_sources,
               'scope': 'Component source build; not a complete runtime validation'}
    (LOCAL / (args.component + '-build.json')).write_text(json.dumps(receipt, indent=2) + '\n')


def build_wine(args, source, expected_files):
    if not args.toolchain or not args.moltenvk_lib:
        raise SystemExit('Wine needs --toolchain and --moltenvk-lib (a public MoltenVK library)')
    output = LOCAL / 'build/wine'
    output.mkdir(parents=True, exist_ok=True)
    dependency = LOCAL / 'deps/moltenvk/libMoltenVK.dylib'
    dependency.parent.mkdir(parents=True, exist_ok=True)
    if dependency.is_symlink():
        dependency.unlink()
    elif dependency.exists():
        raise SystemExit(f'Preserve the existing dependency file: {dependency}')
    dependency.symlink_to(args.moltenvk_lib.resolve())
    env = dict(os.environ)
    env['PATH'] = str(args.toolchain / 'bin') + os.pathsep + env.get('PATH', '')
    env['LLVM_BIN'] = str(args.toolchain / 'bin')
    env.update(CC='/usr/bin/clang', CXX='/usr/bin/clang++', CFLAGS='-g -O2', CXXFLAGS='-g -O2',
               LDFLAGS='-L../../deps/moltenvk')
    if args.bison:
        env['PATH'] = str(args.bison.parent) + os.pathsep + env['PATH']
        env['BISON'] = args.bison.name
    # The installed Python may be x86-only. Use the native platform shell for
    # configure/Make rather than inheriting Rosetta's host identification.
    run(['/usr/bin/arch', '-arm64', '/bin/sh', source / 'configure', '--enable-archs=aarch64,arm64ec,x86_64,i386', '--disable-tests',
         '--with-vulkan', '--with-freetype', '--with-fontconfig', '--with-gnutls',
         '--without-capi', '--without-dbus', '--without-gphoto', '--without-pcap',
         '--without-sane', '--without-udev', '--without-wayland', '--without-x'], cwd=output, env=env)
    run(['/usr/bin/arch', '-arm64', '/usr/bin/make', '-j', args.jobs, *(args.target or ['all'])], cwd=output, env=env)
    if source_inventory(source) != expected_files:
        raise SystemExit('Wine sources changed during the build')
    artifacts = ['dlls/ntdll/ntdll.so', 'dlls/ntdll/aarch64-windows/ntdll.dll', 'server/wineserver']
    receipt = {'component': 'wine', 'source_lock': source_lock(), 'targets': args.target or ['all'],
               'scope': 'Wine source build; runtime validation is recorded separately',
               'artifacts': {p: sha(output / p) for p in artifacts if (output / p).is_file()}}
    (LOCAL / 'wine-build.json').write_text(json.dumps(receipt, indent=2) + '\n')


def build_dxmt(args, source, expected_files):
    for tool in ['metal', 'metallib']:
        found = subprocess.run(['xcrun', '--find', tool], capture_output=True, text=True)
        if found.returncode:
            raise SystemExit(f'Apple {tool} is unavailable in the selected developer directory')
    if not args.toolchain or not args.llvm_native:
        raise SystemExit('DXMT needs --toolchain (fixed CRT) and --llvm-native (LLVM 15 prefix)')
    version = subprocess.check_output([str(args.llvm_native / 'bin/llvm-config'), '--version'], text=True).strip()
    if not version.startswith('15.'):
        raise SystemExit('The pinned DXMT v0.80 requires LLVM 15')
    if not shutil.which('meson') or not shutil.which('ninja'):
        raise SystemExit('Meson >=1.3 and Ninja are required for DXMT')
    output = LOCAL / 'build/dxmt'
    env = {**os.environ, 'PATH': str(args.toolchain / 'bin') + os.pathsep + os.environ.get('PATH', '')}
    native = LOCAL / 'dxmt-native.ini'
    native.write_text("[binaries]\nc = '/usr/bin/clang'\ncpp = '/usr/bin/clang++'\n")
    cross = LOCAL / 'dxmt-arm64ec.ini'
    cross.write_text((source / 'build-arm64ec.txt').read_text() + "\n[built-in options]\nc_args = ['-ffixed-x18', '-ffixed-x28']\ncpp_args = ['-ffixed-x18', '-ffixed-x28']\n")
    run(['meson', 'setup', output, source, '--cross-file', cross, '--native-file', native,
         '--buildtype=release', '-Dnative_llvm_path=' + str(args.llvm_native),
         '-Dwine_build_path=' + str(LOCAL / 'build/wine'), '-Dwine_builtin_dll=true',
         '-Denable_tests=false', '-Denable_nvapi=false', '-Denable_nvngx=false'], env=env)
    run(['meson', 'compile', '-C', output, '-j', args.jobs], env=env)
    if source_inventory(source) != expected_files:
        raise SystemExit('DXMT sources changed during the build')
    artifacts = {}
    env['LLVM_BIN'] = str(args.toolchain / 'bin')
    for dll in output.rglob('*.dll'):
        run([sys.executable, ROOT / 'tools/fix-x18-tls.py', dll], env=env)
        artifacts[str(dll.relative_to(output))] = sha(dll)
    (LOCAL / 'dxmt-build.json').write_text(json.dumps({'component': 'dxmt', 'source_lock': source_lock(),
        'artifacts': artifacts, 'scope': 'DXMT component build; game regression pending'}, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    get = commands.add_parser('fetch', help='export pinned upstream commits and apply the source patch')
    get.add_argument('--component', choices=LOCK, required=True)
    get.add_argument('--local-repository', type=Path,
                     help='optional Git object cache; only committed objects are exported')
    get.set_defaults(action=fetch)
    compile_ = commands.add_parser('build', help='build a recovered component with its existing CMake targets')
    compile_.add_argument('--component', choices=LOCK, required=True)
    compile_.add_argument('--toolchain', type=Path)
    compile_.add_argument('--moltenvk-lib', type=Path)
    compile_.add_argument('--bison', type=Path)
    compile_.add_argument('--llvm-native', type=Path)
    compile_.add_argument('--target', action='append', help='optional Wine make target; repeat for multiple targets')
    compile_.add_argument('--jobs', type=int, default=6)
    compile_.set_defaults(action=build)
    check = commands.add_parser('test', help='check source inputs and platform integration')
    check.set_defaults(action=lambda args: run([sys.executable, '-m', 'unittest', 'discover', '-s', ROOT / 'tests', '-v']))
    args = parser.parse_args()
    if getattr(args, 'jobs', 1) < 1:
        parser.error('--jobs must be positive')
    args.action(args)


if __name__ == '__main__':
    main()
