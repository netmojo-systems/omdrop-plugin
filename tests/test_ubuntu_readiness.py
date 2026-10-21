"""Receiver readiness and version checks work without Arch's tools.

Debian and Ubuntu have no vercmp, and a bare $(vercmp ...) there is an
arithmetic syntax error that bash reads as "not older", so any contract
passed. version_ge falls back to coreutils' sort -V.
"""
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'bin/omdrop').read_text()


def function(name):
    start = SOURCE.index(name + '() {')
    return SOURCE[start:SOURCE.index('\n}', start) + 2]


class UbuntuReadinessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {**os.environ, 'PATH': str(self.root),
                    'PYTHONPATH': str(self.root), 'CALLS': str(self.root / 'calls')}
        (self.root / 'python3').symlink_to(sys.executable)
        # coreutils and sed, which every distribution has; vercmp only where a test adds it.
        for tool in ('sort', 'head', 'sed'):
            (self.root / tool).symlink_to(shutil.which(tool))

    def command(self, name, script):
        p = self.root / name
        p.write_text('#!/bin/sh\n' + script)
        p.chmod(0o755)

    def run_function(self, name, preamble=''):
        return subprocess.run(['/bin/bash', '-c', '\n'.join(
            [preamble, function('version_ge'), function(name), name])],
            env=self.env, capture_output=True, text=True)

    def contract(self, version):
        return self.run_function('backend_contract_ok',
                                 f'BACKEND_CONTRACT_MIN=0.7.0\nprobe_field() {{ echo "{version}"; }}')

    def identity_check(self, contract):
        return self.run_function('driver_identity_ready', f'''DRIVER_IDENTITY_VERSION=0.7.0
radio_probe() {{ return 0; }}
radio_probe_hung() {{ return 1; }}
probe_field() {{ [ "$1" = contract ] && echo "{contract}" || echo owl; }}
die() {{ printf '%s\\n' "$*" >&2; exit 1; }}''')

    def test_contracts_compare_without_vercmp(self):
        # 0.07.0 is 0.7.0 to vercmp; sort -V alone ranks it lower.
        for version in ('0.7.0', '0.07.0', '0.7.1', '0.8.1', '0.10.0', '1.0'):
            with self.subTest(version=version):
                result = self.contract(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, '')
        for version in ('0.6.9', '0.1.0', '', 'abc', '0.8.1a'):
            with self.subTest(version=version):
                self.assertNotEqual(self.contract(version).returncode, 0)

    def test_an_old_contract_is_refused_at_the_identity_check_without_vercmp(self):
        # The regression: this check passed 0.1.0 on Ubuntu, with two error lines.
        result = self.identity_check('0.1.0')
        self.assertEqual(result.returncode, 1)
        self.assertIn('follows contract 0.7.0 or newer (owl follows 0.1.0)', result.stderr)
        self.assertNotIn('syntax error', result.stderr)
        result = self.identity_check('0.8.1')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_vercmp_decides_where_it_exists(self):
        # vercmp orders pkgrel, which sort -V alone is not trusted with.
        self.command('vercmp', 'echo "$*" > "$CALLS"\necho "$COMPARISON_RESULT"\n')
        self.env['COMPARISON_RESULT'] = '1'
        self.assertEqual(self.contract('0.8.1').returncode, 0)
        self.assertEqual((self.root / 'calls').read_text().strip(), '0.8.1 0.7.0')
        self.env['COMPARISON_RESULT'] = '-1'
        self.assertNotEqual(self.contract('0.8.1').returncode, 0)

    def test_library_probe_uses_soname_not_a_distribution_path(self):
        (self.root / 'libarchive.py').write_text('stream_reader = object()\n')
        (self.root / 'sitecustomize.py').write_text('''import ctypes, os
original = ctypes.CDLL
def load(name, *args, **kwargs):
    if name == 'libkeyutils.so.1':
        with open(os.environ['CALLS'], 'w') as f: f.write(name)
        if os.environ.get('MISSING_LIBRARY') == '1': raise OSError('missing')
        return object()
    return original(name, *args, **kwargs)
ctypes.CDLL = load
''')
        self.assertEqual(self.run_function('receiver_libs_installed').returncode, 0)
        self.assertEqual((self.root / 'calls').read_text(), 'libkeyutils.so.1')
        self.env['MISSING_LIBRARY'] = '1'
        self.assertNotEqual(self.run_function('receiver_libs_installed').returncode, 0)

    def test_driver_current_compares_without_vercmp(self):
        self.command('pacman', 'echo "brcmfmac-awdl-dkms $INSTALLED"\n')
        preamble = 'DRIVER_PKG=brcmfmac-awdl-dkms\nDRIVER_VERSION=0.10.0'
        for installed, current in (('0.10.0-1', True), ('0.10.2-1', True), ('0.9.9-1', False)):
            with self.subTest(installed=installed):
                self.env['INSTALLED'] = installed
                result = self.run_function('driver_current', preamble)
                self.assertEqual(result.returncode == 0, current, result.stderr)
                self.assertNotIn('syntax error', result.stderr)

    def test_only_version_ge_runs_vercmp(self):
        # Every other comparison goes through version_ge, so none of them reads
        # a missing vercmp as an arithmetic error.
        outside = SOURCE.replace(function('version_ge'), '')
        code = [line for line in outside.splitlines() if not line.lstrip().startswith('#')]
        self.assertEqual([line for line in code if '$(vercmp' in line], [])


if __name__ == '__main__':
    unittest.main()
