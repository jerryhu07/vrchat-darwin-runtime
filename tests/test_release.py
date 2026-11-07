import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import importlib.util
import re

ROOT = Path(__file__).resolve().parents[1]


class ReleaseChecks(unittest.TestCase):
    def test_source_integrity(self):
        lock = json.loads((ROOT / 'sources.lock.json').read_text())
        for name, component in lock.items():
            for entry in component['patches']:
                patch = ROOT / entry['path']
                self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), entry['sha256'])
            source = ROOT / '.local/source' / name
            if source.is_dir():
                for relative, expected in component['patched_files'].items():
                    self.assertEqual(hashlib.sha256((source / relative).read_bytes()).hexdigest(), expected, relative)

    def test_no_personal_paths_in_release_sources(self):
        for directory in ['src', 'config', 'tools']:
            for path in (ROOT / directory).rglob('*'):
                if path.is_file() and path.suffix in ['.cpp', '.c', '.h', '.py', '.json']:
                    text = path.read_text()
                    self.assertIsNone(re.search(r'/(?:Users|Volumes)/', text), str(path))

    @unittest.skipUnless(shutil.which('clang++'), 'clang++ is required for the host boundary check')
    def test_host_path_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'paths'
            subprocess.run(['clang++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(ROOT / 'src/platform'), str(ROOT / 'tests/path-ownership.cpp'),
                            '-o', str(executable)], check=True)
            subprocess.run([str(executable)], check=True)

    def test_build_rejects_edited_unpatched_source(self):
        spec = importlib.util.spec_from_file_location('release_driver_test', ROOT / 'tools/dev.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            module.ROOT = Path(directory)
            module.LOCAL = module.ROOT / '.local'
            source = module.LOCAL / 'source/fex-darwin'
            source.mkdir(parents=True)
            file = source / 'unpatched.cpp'
            file.write_text('original')
            module.LOCK = {'fex-darwin': {'patched_files': {}}}
            (module.LOCAL / 'fex-darwin-sources.json').write_text(json.dumps({
                'source': module.LOCK['fex-darwin'], 'files': module.source_inventory(source)}))
            file.write_text('unexpected local edit')
            from argparse import Namespace
            with self.assertRaisesRegex(SystemExit, 'Exported sources changed'):
                module.build(Namespace(component='fex-darwin'))

    @unittest.skipUnless(sys.platform == 'darwin' and shutil.which('clang++'), 'Darwin clang++ is required')
    def test_internet_socket_abi(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'internet-sockets'
            subprocess.run(['clang++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(ROOT / 'src/platform'), str(ROOT / 'tests/internet-sockets.cpp'),
                            '-o', str(executable)], check=True)
            subprocess.run([str(executable)], check=True, timeout=10)

    def test_tls_rewrite(self):
        llvm = os.environ.get('LLVM_BIN')
        compiler = os.environ.get('ARM64EC_CLANG')
        if not llvm or not compiler:
            self.skipTest('Set LLVM_BIN and ARM64EC_CLANG for the owned PE TLS check')
        with tempfile.TemporaryDirectory() as directory:
            source, dll = Path(directory) / 'tls.S', Path(directory) / 'tls.dll'
            source.write_text('.text\n.globl probe\nprobe:\nldr x0, [x18, #88]\nret\n')
            # A plain AArch64 PE makes the tiny assembly section unambiguous to
            # objdump; an ARM64EC fixture also needs a hybrid code map.
            compiler = str(Path(compiler).with_name('aarch64-w64-mingw32-clang'))
            subprocess.run([compiler, '-shared', '-nostdlib', '-Wl,--entry,probe', str(source), '-o', str(dll)], check=True)
            before = dll.read_bytes()
            subprocess.run([sys.executable, str(ROOT / 'tools/fix-x18-tls.py'), str(dll)], check=True)
            self.assertNotEqual(hashlib.sha256(before).hexdigest(), hashlib.sha256(dll.read_bytes()).hexdigest())
            output = subprocess.check_output([str(Path(llvm) / 'llvm-objdump'), '-d', str(dll)], text=True)
            self.assertIn('[x28', output)
            self.assertNotIn('[x18', output)
            changed = dll.read_bytes()
            subprocess.run([sys.executable, str(ROOT / 'tools/fix-x18-tls.py'), str(dll)], check=True)
            self.assertEqual(changed, dll.read_bytes())

    def test_ordinal_only_arm64x_tls_reader(self):
        image = ROOT / '.local/build/wine/dlls/msnet32/aarch64-windows/msnet32.dll'
        llvm = os.environ.get('LLVM_BIN')
        if not image.is_file() or not llvm:
            self.skipTest('Build Wine msnet32 and set LLVM_BIN for the ordinal-only integration check')
        # Wine msnet32 exports 96 functions by ordinal and has no named exports.
        # LLVM previously rejected its null zero-length name/ordinal arrays.
        exports = subprocess.check_output([str(Path(llvm) / 'llvm-readobj'), '--coff-exports', str(image)], text=True)
        count = exports.count('Export {')
        # LLVM versions expose either the native view or both ARM64X views.
        self.assertIn(count, [96, 192])
        self.assertEqual(len(re.findall(r'^ +Name: $', exports, re.M)), count)
        self.assertEqual({int(value) for value in re.findall(r'^ +Ordinal: (\d+)$', exports, re.M)}, set(range(1, 97)))
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / image.name
            shutil.copy2(image, copy)
            subprocess.run([sys.executable, str(ROOT / 'tools/fix-x18-tls.py'), str(copy)], check=True)

    def test_graphics_stage_rejects_changed_input(self):
        spec = importlib.util.spec_from_file_location('graphics_stage_test', ROOT / 'tools/stage-graphics.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        lock = json.loads((ROOT / 'graphics.lock.json').read_text())
        baseline = json.loads((ROOT / 'baseline.json').read_text())
        for name in ['d3d11', 'd3d10core', 'dxgi', 'winemetal']:
            self.assertEqual(lock['files'][f'dlls/{name}/aarch64-windows/{name}.dll'],
                             baseline['components'][name]['sha256'])
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'wine', Path(directory) / 'output'
            first = source / next(iter(lock['files']))
            first.parent.mkdir(parents=True)
            first.write_bytes(b'changed input')
            with self.assertRaisesRegex(SystemExit, 'missing or changed'):
                module.stage(source, output)
            self.assertFalse(output.exists())

    def test_wine_metal_helper_exports(self):
        library = ROOT / '.local/build/wine/dlls/winemac.drv/winemac.so'
        if not library.is_file() or sys.platform != 'darwin':
            self.skipTest('Build Wine winemac.so for the Metal interface check')
        output = subprocess.check_output(['/usr/bin/nm', '-gU', str(library)], text=True)
        symbols = {line.split()[-1] for line in output.splitlines() if line.split()}
        required = ['get_win_data', 'release_win_data', 'macdrv_create_offscreen_swapchain',
                    'macdrv_destroy_swapchain', 'macdrv_swapchain_get_layer', 'macdrv_view_create_metal_view',
                    'macdrv_view_get_metal_layer', 'macdrv_view_release_metal_view']
        self.assertTrue({'_' + name for name in required}.issubset(symbols))


if __name__ == '__main__':
    unittest.main()
