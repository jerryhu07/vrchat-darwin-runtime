#!/usr/bin/env python3
"""Extract and adapt the pinned public DXMT/WineMetal binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def stage(archive, output, llvm):
    lock = json.loads((ROOT / 'graphics.lock.json').read_text())
    if digest(archive) != lock['provider']['archive_sha256']:
        raise SystemExit('Graphics archive checksum mismatch')
    output.mkdir(parents=True, exist_ok=False)
    prefix = lock['provider']['archive'][:-8] + '/'
    with tempfile.TemporaryDirectory(dir=output) as temporary:
        # This release uses a 2 GiB zstd window; the default decoder limit is smaller.
        with subprocess.Popen(['zstd', '--long=31', '-dc', str(archive)], stdout=subprocess.PIPE) as decoder:
            subprocess.run(['tar', '-xf', '-', '--strip-components', '1', '-C', temporary,
                            *[prefix + name for name in lock['archive_members'].values()]],
                           stdin=decoder.stdout, check=True)
            decoder.stdout.close()
            if decoder.wait():
                raise SystemExit('Could not decompress the graphics archive')
        for relative, member in lock['archive_members'].items():
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(Path(temporary) / member, target)
    dlls = [output / name for name in lock['files'] if name.endswith('.dll')]
    subprocess.run([sys.executable, str(ROOT / 'tools/fix-x18-tls.py'), *map(str, dlls)],
                   env={**os.environ, 'LLVM_BIN': str(llvm)}, check=True)
    for name, expected in lock['files'].items():
        if digest(output / name) != expected:
            raise SystemExit('Adapted graphics checksum mismatch: ' + name)
    (output / 'graphics-inputs.json').write_text(json.dumps({
        'archive_sha256': lock['provider']['archive_sha256'], 'files': lock['files'],
        'runtime_executed': False}, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='verified reassembled provider archive; downloads if omitted')
    parser.add_argument('--cache', type=Path, default=ROOT / '.local/graphics-cache')
    parser.add_argument('--llvm', type=Path, required=True, help='directory containing llvm-objdump')
    parser.add_argument('--output', type=Path, required=True, help='new staging directory')
    args = parser.parse_args()
    if args.archive is None:
        provider = json.loads((ROOT / 'graphics.lock.json').read_text())['provider']
        args.cache.mkdir(parents=True, exist_ok=True)
        args.archive = args.cache / provider['archive']
        if not args.archive.exists():
            parts = []
            for number in range(1, 5):
                part = args.cache / (provider['archive'] + f'.part{number:02}')
                subprocess.run(['curl', '--fail', '--location', '--retry', '3',
                                provider['url_prefix'] + part.name, '-o', str(part)], check=True)
                parts.append(part)
            temporary = args.archive.with_suffix('.partial')
            with temporary.open('wb') as output:
                for part in parts:
                    with part.open('rb') as stream:
                        shutil.copyfileobj(stream, output)
            if digest(temporary) != provider['archive_sha256']:
                raise SystemExit('Downloaded graphics archive checksum mismatch')
            temporary.replace(args.archive)
            for part in parts:
                part.unlink()
    stage(args.archive.resolve(), args.output.resolve(), args.llvm.resolve())
