#!/usr/bin/env python3
"""Stage pinned Linux libraries, Proton and the Proton EAC runtime."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root):
    value = hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            item = 'link:' + str(path.readlink())
        elif path.is_file():
            item = digest(path)
        else:
            continue
        value.update((str(path.relative_to(root)) + '\0' + item + '\n').encode())
    return value.hexdigest()


def main(args):
    spec = json.loads((ROOT / 'guest-dependencies.lock.json').read_text())
    if tree_digest(args.proton / 'files') != spec['proton']['files_tree_sha256']:
        raise SystemExit('Proton files differ from the pinned official depot')
    for name, expected in spec['eac']['files'].items():
        if digest(args.eac / name) != expected:
            raise SystemExit('Proton EAC runtime checksum mismatch: ' + name)
    supplied = []
    local_inputs = {}
    for relative, record in spec['guest_files'].items():
        if record.get('proton'):
            path = args.proton / record['proton']['relative_path']
            if not path.is_file() or digest(path) != record['sha256']:
                raise SystemExit('Provide the official Proton installation matching the guest lock with --proton')
            local_inputs[relative] = path
            supplied.append(relative)
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    cache = args.cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)

    def package(record):
        archive = cache / record['sha256']
        if not archive.exists():
            temporary = archive.with_suffix('.partial')
            subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error', '--retry', '3',
                            '--max-time', '120', record['url'], '-o', str(temporary)], check=True)
            if digest(temporary) != record['sha256']:
                raise ValueError('Package checksum mismatch: ' + record['url'])
            temporary.replace(archive)
        if digest(archive) != record['sha256']:
            raise ValueError('Cached package checksum mismatch: ' + record['url'])
        return archive

    with ThreadPoolExecutor(max_workers=4) as pool:
        archives = list(pool.map(package, spec['startup_packages']))
    for archive in archives:
        data = subprocess.check_output(['tar', '-tf', str(archive)], text=True)
        member = next(name for name in data.splitlines() if name.startswith('data.tar.'))
        with subprocess.Popen(['tar', '-xOf', str(archive), member], stdout=subprocess.PIPE) as unpack:
            subprocess.run(['tar', '-xf', '-', '-C', str(destination)], stdin=unpack.stdout, check=True)
            unpack.stdout.close()
            if unpack.wait():
                raise RuntimeError('Could not unpack ' + str(archive))
    shutil.copytree(args.proton / 'files', destination / 'opt/wine-devel', symlinks=True)
    (destination / 'usr/share/wine').symlink_to('../../opt/wine-devel/share/wine')
    for name in spec['eac']['files']:
        target = destination / 'opt/eac' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.eac / name, target)

    def fetch(item):
        relative, record = item
        archive = cache / record['sha256']
        if record.get('proton') and not archive.exists():
            shutil.copyfile(local_inputs[relative], archive)
        if not archive.exists():
            temporary = archive.with_suffix('.partial')
            if record.get('package'):
                package = record['package']
                container = cache / package['sha256']
                if not container.exists():
                    subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                                    '--max-time', '120', package['url'], '-o', str(container)], check=True)
                if digest(container) != package['sha256']:
                    raise ValueError('Package checksum mismatch: ' + relative)
                data = cache / (package['sha256'] + '.data')
                with data.open('wb') as stream:
                    subprocess.run(['tar', '-xOf', str(container), package['data_member']], stdout=stream, check=True)
                with temporary.open('wb') as stream:
                    subprocess.run(['tar', '-xOf', str(data), package['member']], stdout=stream, check=True)
            else:
                subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                                '--max-time', '120', record['url'], '-o', str(temporary)], check=True)
            if digest(temporary) != record['sha256']:
                raise ValueError('Public input checksum mismatch: ' + relative)
            temporary.replace(archive)
        if digest(archive) != record['sha256']:
            raise ValueError('Cached input checksum mismatch: ' + relative)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(archive, target)
        target.chmod(0o644 if relative.startswith('etc/') else 0o755)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(fetch, spec['guest_files'].items()))
    (destination / 'lib64').symlink_to('usr/lib64')
    alias = destination / 'lib/x86_64-linux-gnu'
    alias.mkdir(parents=True, exist_ok=True)
    for name in ['libc.so.6', 'libdl.so.2', 'libm.so.6', 'libpthread.so.0', 'librt.so.1']:
        (alias / name).symlink_to('../../usr/lib64/' + name)
    shutil.copytree(ROOT / 'config/gconv', destination / 'usr/lib64/gconv', dirs_exist_ok=True)
    # glibc reads the text configuration when no gconv cache is installed.
    for name in ['etc', 'tmp', 'home/regression', 'opt/regression-wine-entry']:
        (destination / name).mkdir(parents=True, exist_ok=True)
    (destination / 'tmp').chmod(0o700)
    (destination / 'home/regression').chmod(0o700)
    (destination / 'etc/passwd').write_text(f'regression:x:{os.getuid()}:{os.getgid()}:runtime:/home/regression:/bin/sh\n')
    (destination / 'etc/group').write_text(f'regression:x:{os.getgid()}:\n')
    (destination / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files dns\n')
    (destination / 'etc/machine-id').write_text(uuid.uuid4().hex + '\n')
    for name in ['hosts', 'resolv.conf']:
        if (Path('/etc') / name).is_file():
            shutil.copyfile(Path('/etc') / name, destination / 'etc' / name)
    (destination.parent / (destination.name + '-inputs.json')).write_text(json.dumps({
        'source_lock': {'path': 'guest-dependencies.lock.json', 'sha256': digest(ROOT / 'guest-dependencies.lock.json')},
        'scope': 'Public startup inputs and official Proton EAC runtime; no game files or Wine prefix staged',
        'runtime_validated': False, 'external_proton_inputs': supplied}, indent=2) + '\n')
    print(destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new directory; existing RootFS is never modified')
    parser.add_argument('--cache', type=Path, default=ROOT / '.local/guest-cache')
    parser.add_argument('--proton', type=Path, required=True, help='official Proton 11.0-1 directory matching the pinned Steam manifest')
    parser.add_argument('--eac', type=Path, required=True, help='official Proton EasyAntiCheat Runtime from Steam')
    main(parser.parse_args())
