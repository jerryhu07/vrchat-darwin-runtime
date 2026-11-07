#!/usr/bin/env python3
"""Stage fingerprinted GNU libraries and the two official Proton frontend members."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(args):
    spec = json.loads((ROOT / 'guest-dependencies.lock.json').read_text())
    supplied = []
    local_inputs = {}
    for relative, record in spec['guest_files'].items():
        if record.get('proton'):
            path = args.proton / record['proton']['relative_path'] if args.proton else args.cache / record['sha256']
            if not path.is_file() or digest(path) != record['sha256']:
                raise SystemExit('Provide the official Proton installation matching the guest lock with --proton')
            local_inputs[relative] = path
            supplied.append(relative)
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    cache = args.cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)

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
        target.chmod(0o755)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(fetch, spec['guest_files'].items()))
    (destination / 'lib64').symlink_to('usr/lib64')
    alias = destination / 'lib/x86_64-linux-gnu'
    alias.mkdir(parents=True)
    for name in ['libc.so.6', 'libdl.so.2', 'libm.so.6', 'libpthread.so.0', 'librt.so.1']:
        (alias / name).symlink_to('../../usr/lib64/' + name)
    shutil.copytree(ROOT / 'config/gconv', destination / 'usr/lib64/gconv', dirs_exist_ok=True)
    # GLibc reads its standard text configuration when no generated gconv cache
    # is installed; do not copy an opaque cache from the original lab.
    for name in ['etc', 'tmp', 'home/regression', 'opt/regression-wine-entry']:
        (destination / name).mkdir(parents=True, exist_ok=True)
    (destination / 'tmp').chmod(0o700)
    (destination / 'home/regression').chmod(0o700)
    (destination / 'etc/passwd').write_text(f'regression:x:{os.getuid()}:{os.getgid()}:runtime:/home/regression:/bin/sh\n')
    (destination / 'etc/group').write_text(f'regression:x:{os.getgid()}:\n')
    (destination / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files dns\n')
    for name in ['hosts', 'resolv.conf']:
        if (Path('/etc') / name).is_file():
            shutil.copyfile(Path('/etc') / name, destination / 'etc' / name)
    (destination.parent / (destination.name + '-inputs.json')).write_text(json.dumps({
        'source_lock': {'path': 'guest-dependencies.lock.json', 'sha256': digest(ROOT / 'guest-dependencies.lock.json')},
        'scope': 'Pinned guest inputs; no game/EAC files or Wine prefix staged',
        'runtime_validated': False, 'external_proton_inputs': supplied}, indent=2) + '\n')
    print(destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new directory; existing RootFS is never modified')
    parser.add_argument('--cache', type=Path, default=ROOT / '.local/guest-cache')
    parser.add_argument('--proton', type=Path, help='official Proton 11.0-1 directory matching the pinned Steam manifest')
    main(parser.parse_args())
