#!/usr/bin/env python3
"""Link the retained guest bootstrap using LLVM's standard ELF linker."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm', type=Path, required=True)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--linker', type=Path, required=True, help='path to LLVM ld.lld')
    args = parser.parse_args()
    output = ROOT / '.local/bootstrap'
    output.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'src/platform/elf-entry.S'
    obj, library = output / 'entry.o', output / 'ntdll.so'
    subprocess.run([str(args.llvm / 'clang'), '--target=x86_64-linux-gnu', '-c', str(source), '-o', str(obj)], check=True)
    subprocess.run([str(args.linker), '-shared', '-z', 'noexecstack', '-z', 'max-page-size=4096',
                    '-soname', 'libregression-wine-unix-entry.so', str(obj),
                    '-L' + str(args.rootfs.resolve() / 'usr/lib64'), '-l:libc.so.6', '-o', str(library)], check=True)
    receipt = {'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
               'artifact_sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
               'scope': 'Standard ELF link completed; guest bootstrap runtime validation pending'}
    (output / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
