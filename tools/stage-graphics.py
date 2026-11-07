#!/usr/bin/env python3
"""Copy the accepted graphics dependency into a new directory, without building DXMT."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def stage(wine, output):
    lock = json.loads((ROOT / 'graphics.lock.json').read_text())
    if output == wine or wine in output.parents:
        raise SystemExit('Output must be outside the accepted Wine build')
    # Validate the entire input and its Wine pair before creating output.
    for relative, expected in {**lock['files'], **lock['accepted_wine_pair']}.items():
        path = wine / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit('Accepted graphics input missing or changed: ' + relative)
    output.mkdir(parents=True, exist_ok=False)
    for relative in lock['files']:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(wine / relative, target)
    receipt = {'scope': 'Accepted prebuilt graphics dependency; no DXMT compilation or runtime test',
               'files': lock['files'], 'accepted_wine_pair': lock['accepted_wine_pair'],
               'runtime_executed': False}
    (output / 'graphics-inputs.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('Staged ' + str(len(lock['files'])) + ' verified graphics inputs into ' + str(output))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wine-build', type=Path, required=True, help='d18340e accepted Wine build, read only')
    parser.add_argument('--output', type=Path, required=True, help='new private staging directory')
    args = parser.parse_args()
    stage(args.wine_build.resolve(), args.output.resolve())
