#!/usr/bin/env python3
"""Assemble and launch the source-built VRChat runtime in a dedicated directory."""
import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import json
import os
import re
import secrets
import select
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True, **kwargs)


def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def native_environment(runtime):
    game = Path(json.loads((runtime / 'runtime.json').read_text())['game'])
    wine, platform, state = runtime / 'wine', runtime / 'platform', runtime / 'state'
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR') if k in os.environ}
    env.update({key: '1' for key in (
        'REGRESSION_FLI_RESERVE_PE_IMAGE', 'REGRESSION_FLI_READONLY_LARGE_BLOCKS',
        'REGRESSION_FLI_SAFE_UNALIGNED_TSO', 'REGRESSION_HOST_GLIBC', 'REGRESSION_LINUX_FORK',
        'REGRESSION_ROUTE_CHILD_ALIGNMENT', 'REGRESSION_NATIVE_WINE_EXEC',
        'REGRESSION_MACOS_EXEC_NATIVE_STACK', 'REGRESSION_ELF_UNIXLIB',
        'REGRESSION_ELF_NOTIFY_ON_USER_STACK', 'REGRESSION_LAZY_LINUX_TLS',
        'REGRESSION_LINUX_SYSCALL_BRIDGE', 'REGRESSION_FLI_ROOT_CALLBACK_BRIDGE',
        'REGRESSION_NATIVE_PE_LINUX_MMAP', 'REGRESSION_FLI_NATIVE_ALIAS_EXECUTION',
        'REGRESSION_ROOT_VIEW_IMPORT', 'REGRESSION_GUEST_MAP_PERMISSIONS')})
    env.update({k: str(v) for k, v in {
        'VRCHAT_RUNTIME_ROOT': runtime, 'VRCHAT_ROOTFS': runtime / 'native-rootfs',
        'VRCHAT_GAME_DIR': game, 'VRCHAT_STATE_DIR': state,
        'REGRESSION_PREFIX': runtime / 'prefix', 'WINEPREFIX': runtime / 'prefix',
        'REGRESSION_WINE_BUILD': wine, 'WINEBUILDDIR': wine,
        'REGRESSION_WINE_FRONTEND': platform / 'wine-host', 'WINELOADER': platform / 'wine-host',
        'WINESERVER': wine / 'server/wineserver',
        'REGRESSION_FLI_CARRIER': platform / 'linux-carrier.so',
        'REGRESSION_LINUX_BRIDGE_PATH': platform / 'linux-bridge.so',
        'REGRESSION_ELF_TRANSPORT_DLL': platform / 'elf-transport.dll',
        'REGRESSION_RESEARCH_TMPDIR': state, 'REGRESSION_LINUX_SYSCALL_TMPDIR': state,
        'REGRESSION_FLI_SHARED_HOST_ROOT': game,
        'WINEDLLPATH': runtime / 'native-rootfs/opt/eac/v2/lib64',
    }.items()})
    env.update(WINEDEBUG='-all,err+all', WINEDEBUGGER='none', LC_ALL='C.UTF-8',
               WINEDLLOVERRIDES='winemenubuilder.exe=',
               PROTON_EAC_RUNTIME='/opt/eac', WINE_MONO_AOT='interp', MONO_THREADS_SUSPEND='coop',
               FEX_SILENTLOG='1', FEX_ENABLECODECACHINGWIP='0', FEX_SMCCHECKS='full', FEX_MAXINST='500',
               FEX_TSOENABLED='0', FEX_VECTORTSOENABLED='0', FEX_MEMCPYSETTSOENABLED='0',
               FEX_HALFBARRIERTSOENABLED='1', REGRESSION_FLI_MAX_INST='64',
               DXMT_CONFIG='dxmt.metalShaderVersion=310;d3d11.maxFeatureLevel=12_1;d3d11.preferredMaxFrameRate=0;')
    env['DYLD_LIBRARY_PATH'] = ':'.join(str(wine / 'dlls' / name) for name in
                                      ('ntdll', 'win32u', 'winemac.drv', 'winemetal')) + ':' + str(platform)
    return env


def bundle_native_libraries(wine, platform, moltenvk):
    # Wine dlopens these by soname. Copy their native dependency closure so dyld
    # never needs the builder's Cellar paths or a shell-specific search path.
    native_files = list(wine.rglob('*.so')) + list(platform.glob('*.so')) + list(platform.glob('*.dylib'))
    pending = [moltenvk]
    for path in native_files:
        for line in subprocess.check_output(['otool', '-L', str(path)], text=True).splitlines()[2:]:
            dependency = line.strip().split(' (')[0]
            if dependency.startswith('/') and not dependency.startswith(('/usr/lib/', '/System/')):
                pending.append(Path(dependency))
    for package, name in [('freetype2', 'libfreetype.6.dylib'), ('fontconfig', 'libfontconfig.1.dylib'),
                          ('gnutls', 'libgnutls.30.dylib'), ('fmt', 'libfmt.12.dylib')]:
        directory = subprocess.check_output(['pkg-config', '--variable=libdir', package], text=True).strip()
        pending.append(Path(directory) / name)
    visited = set()
    while pending:
        source = pending.pop()
        if source.name in visited:
            continue
        visited.add(source.name)
        target = platform / source.name
        copy(source, target)
        libraries = subprocess.check_output(['otool', '-L', str(target)], text=True).splitlines()[2:]
        for line in libraries:
            dependency = line.strip().split(' (')[0]
            if dependency.startswith('/') and not dependency.startswith(('/usr/lib/', '/System/')):
                pending.append(Path(dependency))

    for path in dict.fromkeys([*native_files, *platform.glob('*.dylib')]):
        for line in subprocess.check_output(['otool', '-L', str(path)], text=True).splitlines()[2:]:
            dependency = line.strip().split(' (')[0]
            if dependency.startswith('/') and not dependency.startswith(('/usr/lib/', '/System/')):
                relative = os.path.relpath(platform / Path(dependency).name, path.parent)
                run(['install_name_tool', '-change', dependency, '@loader_path/' + relative, path])
        run(['install_name_tool', '-id', '@rpath/' + path.name, path])
        run(['codesign', '--force', '--sign', '-', path])


def prepare(args):
    runtime = args.output.resolve()
    game = args.game.resolve()
    for name in ('Xvfb', 'xdpyinfo'):
        if not os.access('/opt/X11/bin/' + name, os.X_OK):
            raise SystemExit('Install XQuartz before preparing the runtime')
    for name in ('VRChat.exe', 'UnityPlayer.dll', 'GameAssembly.dll', 'start_protected_game.exe', 'launch.exe',
                 'EasyAntiCheat/Settings.json', 'EasyAntiCheat/Certificates/base.cer'):
        if not (game / name).is_file():
            raise SystemExit('Missing official game file: ' + name)
    receipt = json.loads((ROOT / '.local/platform/build.json').read_text())
    for path, expected in [(args.wine_build / 'dlls/ntdll/aarch64-windows/ntdll.dll', receipt['wine_ntdll_sha256']),
                           (args.fex, receipt['fex_sha256']),
                           (ROOT / '.local/build/fex-darwin/FEXCore/Source/libFEXCore.dylib', receipt['darwin_fex_sha256'])]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit('Rebuild platform components for the selected Wine/FEX: ' + str(path))
    runtime.mkdir(parents=True, exist_ok=False)
    runtime.chmod(0o700)
    (runtime / 'state').mkdir(mode=0o700)
    (runtime / 'runtime.json').write_text(json.dumps({'game': str(game)}, indent=2) + '\n')
    wine = runtime / 'wine'
    suffixes = {'.dll', '.exe', '.so', '.drv', '.cpl', '.acm', '.sys', '.ocx', '.ax', '.tlb',
                '.nls', '.fon', '.ttf', '.inf', '.winmd', '.msstyles'}
    for source in args.wine_build.rglob('*'):
        if source.is_file() and (source.suffix in suffixes or
                                 source.relative_to(args.wine_build).as_posix() in ('loader/wine', 'server/wineserver')):
            copy(source, wine / source.relative_to(args.wine_build))
    for name, expected in json.loads((ROOT / 'graphics.lock.json').read_text())['files'].items():
        source = args.graphics / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise SystemExit('Run stage-graphics.py for the pinned public inputs: ' + name)
        copy(source, wine / name)
    copy(args.fex, wine / 'dlls/xtajit64/aarch64-windows/xtajit64.dll')
    platform = runtime / 'platform'
    for name, expected in receipt['artifacts'].items():
        source = ROOT / '.local/platform' / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise SystemExit('Platform artifact changed: ' + name)
        copy(source, platform / name)
    copy(platform / 'jit-service.so', wine / 'dlls/libarm64ecfex/libarm64ecfex.so')
    copy(ROOT / '.local/build/fex-darwin/FEXCore/Source/libFEXCore.dylib', platform / 'libFEXCore.dylib')
    copy(args.epoll_prefix / 'lib/libepoll-shim.0.dylib', platform / 'libepoll-shim.0.dylib')
    bundle_native_libraries(wine, platform, args.graphics / 'dlls/winevulkan/libMoltenVK.dylib')
    # Remove build-directory rpaths. The startup executor and carrier share this local FEX/epoll pair.
    for path in [platform / n for n in ('linux-carrier.so', 'fli-fexcore-process-probe', 'libFEXCore.dylib', 'libepoll-shim.0.dylib')]:
        for line in subprocess.check_output(['otool', '-L', str(path)], text=True).splitlines()[1:]:
            dependency = line.strip().split(' (')[0]
            if dependency.startswith('/') and (platform / Path(dependency).name).is_file():
                run(['install_name_tool', '-change', dependency, '@loader_path/' + Path(dependency).name, path])
        lines = subprocess.check_output(['otool', '-l', str(path)], text=True).splitlines()
        rpaths = [lines[i + 2].strip()[5:].rsplit(' (offset ', 1)[0] for i, line in enumerate(lines) if line.strip() == 'cmd LC_RPATH']
        for value in rpaths:
            run(['install_name_tool', '-delete_rpath', value, path])
        run(['install_name_tool', '-add_rpath', '@loader_path', path])
        flags = ['--options', 'runtime', '--entitlements', ROOT / 'src/startup/debug.entitlements'] if path.name == 'fli-fexcore-process-probe' else []
        run(['codesign', '--force', '--sign', '-', *flags, path])
    startup = runtime / 'startup-rootfs'
    run([sys.executable, ROOT / 'tools/fetch-guest.py', '--output', startup,
         '--cache', args.cache, '--proton', args.proton, '--eac', args.eac])
    native = runtime / 'native-rootfs'
    shutil.copytree(startup, native, symlinks=True)
    # Native Wine only needs the guest libc/EAC and the ELF entry frontend.
    shutil.rmtree(native / 'opt/wine-devel')
    (native / 'usr/share/wine').unlink()
    run([sys.executable, ROOT / 'tools/build-elf-entry.py', '--llvm', args.llvm,
         '--linker', args.linker, '--rootfs', native])
    copy(ROOT / '.local/bootstrap/ntdll.so', native / 'opt/regression-wine-entry/ntdll.so')
    certificates = native / 'opt/regression-wine-entry/EasyAntiCheat'
    certificates.mkdir()
    (certificates / 'Certificates').symlink_to('../../vrchat/EasyAntiCheat/Certificates')
    for root in (startup, native):
        (root / 'opt/vrchat').symlink_to(game, target_is_directory=True)
        projection = root / game.relative_to('/')
        projection.parent.mkdir(parents=True, exist_ok=True)
        projection.symlink_to(game, target_is_directory=True)
    env = native_environment(runtime)
    setup_env = {**env, 'WINEDLLOVERRIDES': 'winemenubuilder.exe=;mscoree,mshtml='}
    with (runtime / 'state/wineboot.log').open('w') as log:
        try:
            run([runtime / 'platform/wine-host', 'wineboot', '-u'], env=setup_env,
                stdout=log, stderr=subprocess.STDOUT, timeout=180)
        finally:
            run([wine / 'server/wineserver', '-k'], env=env, timeout=10)
            run([wine / 'server/wineserver', '-w'], env=env, timeout=10)
    (runtime / 'profile.json').write_text(json.dumps(env, indent=2) + '\n')
    initialize_startup(runtime)
    print('Prepared ' + str(runtime), flush=True)


def read_log(path):
    return path.read_text(errors='replace') if path.exists() else ''


@contextmanager
def startup_session(runtime, output, proxy, initialize=False):
    root = runtime / 'startup-rootfs'
    game = Path(json.loads((runtime / 'runtime.json').read_text())['game'])
    native = native_environment(runtime)
    native['REGRESSION_VRCHAT_LOGFILE'] = 'Z:' + str(output / 'player.log')
    # /proc/1 exposes the actual host launchd argv, scoped to the current boot.
    boot = subprocess.check_output(['sysctl', '-n', 'kern.bootsessionuuid']).strip()
    row = subprocess.check_output(['ps', '-ww', '-p', '1', '-o', 'uid=', '-o', 'args=']).split()
    if row != [b'0', b'/sbin/launchd']:
        raise RuntimeError('Cannot read the host PID 1 argv')
    argv = row[1] + b'\0'
    snapshot = runtime / 'state/proc1.snapshot'
    snapshot.write_bytes(struct.pack('<8s40sIIII', b'PROCARG1', boot, 1, 1, len(argv), 0) + argv)
    native['REGRESSION_NATIVE_PROC1_SNAPSHOT'] = str(snapshot)
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR') if k in os.environ}
    env.update({'REGRESSION_NATIVE_ENV_' + k: v for k, v in native.items()})
    env.update(REGRESSION_RESEARCH_TMPDIR=str(runtime / 'state'), REGRESSION_FLI_SAFE_UNALIGNED_TSO='1',
               REGRESSION_FLI_MTRACK_CONTROL='1', REGRESSION_FLI_STREAM_GUEST_STDERR='1',
               REGRESSION_FLI_TRACE_EXEC_METADATA='1', REGRESSION_NATIVE_HANDOFF_GUEST_ROOT=str(game),
               REGRESSION_FLI_SHARED_HOST_ROOT=str(game),
               REGRESSION_NATIVE_TRACE_PROVIDER=str(runtime / 'platform/linux-bridge.so'))
    guest = {'LD_LIBRARY_PATH': '/usr/lib64:/usr/lib/x86_64-linux-gnu:/opt/wine-devel/lib/wine/x86_64-unix',
             'WINEDLLPATH': '/opt/eac/v2/lib64:/opt/wine-devel/lib/wine', 'WINEDEBUG': '-all,err+all',
             'WINEPREFIX': '/home/regression/.wine', 'XAUTHORITY': '/home/regression/.Xauthority',
             'PROTON_EAC_RUNTIME': '/opt/eac', 'WINEDLLOVERRIDES': 'winemenubuilder.exe='}
    if proxy:
        guest.update(http_proxy=proxy, https_proxy=proxy)
    if initialize:
        guest['WINEDLLOVERRIDES'] += ';mscoree,mshtml='
    (root / 'home/regression/.wine').mkdir(mode=0o700, exist_ok=True)
    (root / 'home/regression/.wine/drive_c').mkdir(exist_ok=True)
    drives = root / 'home/regression/.wine/dosdevices'
    drives.mkdir(exist_ok=True)
    for name, target in [('c:', '../drive_c'), ('z:', '../../../..')]:
        if not os.path.lexists(drives / name):
            (drives / name).symlink_to(target)
    authority = root / 'home/regression/.Xauthority'
    # Xauthority FamilyWild, no address/display restriction, one private cookie.
    fields = (b'', b'', b'MIT-MAGIC-COOKIE-1', secrets.token_bytes(16))
    authority.write_bytes(struct.pack('>H', 65535) + b''.join(struct.pack('>H', len(v)) + v for v in fields))
    authority.chmod(0o600)
    processes = []
    with ExitStack() as stack:
        for name in ('runtime.conf', 'base.cer'):
            link = root / 'opt/wine-devel/bin' / ('EasyAntiCheat\\Certificates\\' + name)
            link.symlink_to(game / 'EasyAntiCheat/Certificates' / name)
            stack.callback(link.unlink, missing_ok=True)
        permit, writer = os.pipe()
        os.write(writer, bytes(64 if initialize else 24))
        os.close(writer)
        os.set_blocking(permit, False)
        stack.callback(os.close, permit)
        env['REGRESSION_FLI_FORK_BUDGET_FD'] = str(permit)
        display_fd, display_writer = os.pipe()
        stack.callback(os.close, display_fd)
        xlog = stack.enter_context((output / 'xvfb.log').open('w'))
        xserver = subprocess.Popen(['/opt/X11/bin/Xvfb', '-displayfd', str(display_writer),
                                   '-screen', '0', '1280x720x24', '-nolisten', 'tcp',
                                   '-extension', 'MIT-SHM', '-auth', str(authority)],
                                  pass_fds=(display_writer,), stdout=xlog, stderr=xlog)
        os.close(display_writer)
        try:
            if not select.select([display_fd], [], [], 15)[0]:
                raise RuntimeError('Xvfb readiness timeout; see ' + str(output / 'xvfb.log'))
            display = os.read(display_fd, 32).strip().decode()
            if not display.isdecimal():
                raise RuntimeError('Xvfb exited before assigning a display')
            run(['/opt/X11/bin/xdpyinfo'], env={**os.environ, 'DISPLAY': 'unix:' + display,
                                             'XAUTHORITY': str(authority)},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            env['REGRESSION_X11_SOCKET'] = '/private/tmp/.X11-unix/X' + display

            def start(name, program, arguments, kind='official-wine-x64'):
                receipt = output / (name + '.json')
                receipt.touch(mode=0o600)
                command = [runtime / 'platform/fli-fexcore-process-probe', '--real-rootfs', root,
                           '--guest-program', program, '--guest-component-kind', kind,
                           '--instrument-low-memory-bias', '--instrument-high-memory-region', '--guest-cwd', game]
                for value in arguments:
                    command += ['--guest-arg', value]
                for k, v in guest.items():
                    command += ['--guest-env', k + '=' + v]
                command += ['--private-receipt-output', receipt,
                            '--private-stderr-output', output / (name + '.guest.log')]
                stream = stack.enter_context((output / (name + '.host.log')).open('w'))
                with open(os.devnull, 'rb') as stdin:
                    child = subprocess.Popen(list(map(str, command)), env=env, stdin=stdin, stdout=stream,
                                             stderr=subprocess.STDOUT, start_new_session=True, pass_fds=(permit,))
                processes.append(child)
                return child

            start('server', '/opt/wine-devel/bin/wineserver', ['-f'], 'generic')
            yield start
        finally:
            # Only this runtime's native prefix and owned startup process groups.
            subprocess.run([native['WINESERVER'], '-k'], env=native, timeout=10, check=False)
            for stop_signal in (signal.SIGTERM, signal.SIGKILL):
                rows = subprocess.check_output(['ps', '-axo', 'pid=,uid=,stat=,comm='], text=True)
                owned = {str(runtime / 'platform' / name) for name in ('wine-host', 'fli-fexcore-process-probe')}
                for row in rows.splitlines():
                    pid, uid, status, executable = row.split(None, 3)
                    if int(uid) == os.getuid() and not status.startswith('Z') and executable in owned:
                        try:
                            os.kill(int(pid), stop_signal)
                        except ProcessLookupError:
                            pass
                if stop_signal == signal.SIGTERM:
                    time.sleep(.2)
            for child in processes:
                child.wait(timeout=5)
            xserver.terminate()
            try:
                xserver.wait(timeout=5)
            except subprocess.TimeoutExpired:
                xserver.kill()
                xserver.wait()


def initialize_startup(runtime):
    output = Path(tempfile.mkdtemp(prefix='regression-fli-fex-process-probe.initialize-', dir=runtime / 'state'))
    with startup_session(runtime, output, '', initialize=True) as start:
        child = start('wineboot', '/opt/wine-devel/bin/wine', ['wineboot', '-u'])
        code = child.wait(timeout=180)
        receipt = json.loads((output / 'wineboot.json').read_text())
        if code or not receipt['main_completed']:
            raise RuntimeError('Linux Wine initialization failed; see ' + str(output))


def launch(args):
    runtime = args.runtime
    output = Path(tempfile.mkdtemp(prefix='regression-fli-fex-process-probe.launch-', dir=runtime / 'state'))
    game = Path(json.loads((runtime / 'runtime.json').read_text())['game'])
    logs = runtime / 'startup-rootfs/home/regression/.wine/drive_c/users'
    previous = {p: p.stat().st_mtime_ns for p in logs.rglob('anticheatlauncher.log')}
    print('Launch logs: ' + str(output), flush=True)
    with (runtime / 'state/launch.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with startup_session(runtime, output, args.proxy) as start:
            child = start('client', '/opt/wine-devel/bin/wine',
                          ['Z:' + str(game / 'start_protected_game.exe'), '--no-vr', *args.game_args])
            announced = False
            main_pid = None
            launcher_code = None
            deadline = time.monotonic() + 180
            while True:
                if not main_pid:
                    handoffs = re.findall(r'NATIVE_WINE_HANDOFF pid=(\d+)', read_log(output / 'client.host.log'))
                    if handoffs:
                        main_pid = int(handoffs[-1])
                if not announced:
                    player = read_log(output / 'player.log')
                    for path in logs.rglob('anticheatlauncher.log'):
                        if path.stat().st_mtime_ns == previous.get(path):
                            continue
                        official = read_log(path)
                        codes = re.findall(r'Launcher finished with: (\d+)', official)
                        if codes:
                            launcher_code = int(codes[-1])
                        if 'launching with null client' in official.lower() or (launcher_code is not None and launcher_code != 301):
                            raise RuntimeError('Protected launcher failed; see ' + str(output))
                    if 'Anti-cheat client not available' in player:
                        raise RuntimeError('Protected client did not initialize; see ' + str(output))
                    if any(marker in player for marker in ('Client Violation with Type:', 'IntegrityCatalogMissingMainExecutable')):
                        raise RuntimeError('Game integrity check failed; see ' + str(output))
                    online = all(marker in player for marker in (
                        'AntiCheat Session Begin: Success', 'Successfully joined room', 'Finished entering world'))
                    if launcher_code == 301 and online:
                        announced = True
                        (output / 'result.json').write_text(json.dumps({
                            'launcher_code': launcher_code, 'native_handoff': True,
                            'anti_cheat_session': True, 'room_joined': True, 'world_entry': True}, indent=2) + '\n')
                        print('World entry observed. Close the game or press Ctrl-C to stop.', flush=True)
                if main_pid:
                    status = subprocess.run(['ps', '-p', str(main_pid), '-o', 'stat='], capture_output=True, text=True)
                    if not status.stdout.strip() or status.stdout.lstrip().startswith('Z'):
                        break
                elif child.poll() is not None:
                    raise RuntimeError('Protected launcher exited without a native game; see ' + str(output))
                elif time.monotonic() > deadline:
                    raise RuntimeError('Protected startup timed out; see ' + str(output))
                time.sleep(.5)


def main():
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('prepare', help='assemble into a new directory and initialize a new Wine prefix')
    for name in ('wine-build', 'fex', 'graphics', 'proton', 'eac', 'game', 'output', 'epoll-prefix', 'llvm', 'linker'):
        setup.add_argument('--' + name, type=Path, required=True)
    setup.add_argument('--cache', type=Path, default=ROOT / '.local/guest-cache')
    setup.set_defaults(action=prepare)
    start = commands.add_parser('run', help='launch through the original protected game entry')
    start.add_argument('--runtime', type=Path, required=True)
    start.add_argument('--proxy', default='', help='optional bootstrap HTTP(S) proxy; room UDP uses the system route')
    start.add_argument('game_args', nargs=argparse.REMAINDER)
    start.set_defaults(action=launch)
    args = parser.parse_args()
    for key, value in vars(args).items():
        if isinstance(value, Path):
            # LLVM selects the linker flavour from argv[0] (ld.lld is a symlink).
            setattr(args, key, value.absolute() if key == 'linker' else value.resolve())
    args.action(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
