"""The identity lifecycle: 1Password fetch, the cache, windows, import.

Runs bin/lifecycle.py in-process against a temporary home and runtime
directory, a stub `op`, and an in-memory stand-in for the kernel keyring, so
nothing touches the real keyring, 1Password, or ~/.omdrop.
"""
import contextlib
import importlib.util
import io
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / 'bin'
sys.path.insert(0, str(BIN))

import identity as ident  # noqa: E402
import lifecycle  # noqa: E402

STUB_OP = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, shutil, sys
    store = os.environ['OP_STUB_DIR']
    with open(os.path.join(store, 'calls'), 'a') as log:
        log.write(' '.join(sys.argv[1:]) + '\\n')
    if os.environ.get('OP_STUB_FAIL'):
        sys.stderr.write('[ERROR] 2026/09/28 10:00:00 ' + os.environ['OP_STUB_FAIL'] + '\\n')
        sys.exit(1)
    args = sys.argv[1:]
    items = os.path.join(store, 'items')
    if args[0] == 'read':
        ref = args[-1][len('op://'):]
        vault, item, name = ref.split('/')
        with open(os.path.join(items, item, name), 'rb') as fh:
            data = fh.read()
        if os.environ.get('OP_STUB_CORRUPT') == name:
            data += b'x'
        sys.stdout.buffer.write(data)
    elif args[:2] == ['item', 'create']:
        os.makedirs(os.path.join(items, 'item1'), exist_ok=True)
        for a in args:
            if '[file]=' in a:
                label, path = a.split('[file]=')
                shutil.copy(path, os.path.join(items, 'item1', label))
        print(json.dumps({'id': 'item1', 'vault': {'id': 'vault1'}}))
    elif args[:2] == ['item', 'get']:
        print(json.dumps({'id': args[2], 'vault': {'id': 'vault1'}}))
    elif args[:2] == ['account', 'list']:
        print(json.dumps([{'account_uuid': 'acct1', 'email': 'x', 'url': 'y', 'user_uuid': 'u'}]))
    ''')


class FakeKeyring:
    """The kernel keyring's behaviour, in memory: one key, a timeout, revoke."""
    store = {}

    def __init__(self):
        pass

    def find(self):
        return 1 if 'payload' in self.store else None

    def read(self, kid=None):
        return self.store.get('payload')

    def publish(self, payload, timeout):
        if timeout < 1:
            raise ident.KeyringError('refusing to publish a cache that has already expired')
        self.store.update(payload=payload, timeout=int(timeout))
        self.store['published'] = self.store.get('published', 0) + 1
        return 1

    def set_timeout(self, timeout):
        if 'payload' not in self.store:
            return False
        if timeout < 1:
            self.revoke()
            return False
        self.store['timeout'] = int(timeout)
        return True

    def revoke(self):
        had = 'payload' in self.store
        self.store.pop('payload', None)
        self.store.pop('timeout', None)
        return had


def make_self_signed(directory, cn='Test'):
    subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1',
                    '-subj', f'/CN={cn}', '-keyout', 'key.pem', '-out', 'certificate.pem'],
                   cwd=directory, check=True, capture_output=True)
    return (Path(directory) / 'certificate.pem').read_bytes(), (Path(directory) / 'key.pem').read_bytes()


class LifecycleFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.home, self.runtime, self.config = root / 'home', root / 'run', root / 'config'
        for d in (self.home, self.runtime, self.config):
            d.mkdir(mode=0o700)
        self.keys = self.home / '.omdrop' / 'keys'
        self.keys.mkdir(parents=True, mode=0o700)
        self.opdir = root / 'op'
        (self.opdir / 'items').mkdir(parents=True)
        stub = root / 'op-stub'
        stub.write_text(STUB_OP)
        stub.chmod(0o755)
        env = {'XDG_RUNTIME_DIR': str(self.runtime), 'XDG_CONFIG_HOME': str(self.config),
               'OMDROP_OP': str(stub), 'OP_STUB_DIR': str(self.opdir)}
        patch_env = unittest.mock.patch.dict(os.environ, env)
        patch_env.start()
        self.addCleanup(patch_env.stop)
        for var in ('OP_STUB_FAIL', 'OP_STUB_CORRUPT'):
            os.environ.pop(var, None)
        FakeKeyring.store = {}
        for target in (unittest.mock.patch.object(ident, 'Keyring', FakeKeyring),
                       unittest.mock.patch.object(ident.pwd, 'getpwuid', self.passwd),
                       unittest.mock.patch.object(ident, 'check_apple', self.check_apple)):
            target.start()
            self.addCleanup(target.stop)
        self.apple_problem = None
        # An "Apple" identity for the stub: a real key pair, since the checks
        # that it chains to Apple are replaced by self.check_apple.
        work = root / 'apple'
        work.mkdir()
        cert, key = make_self_signed(work, 'com.apple.idms.appleid.prd.test')
        self.apple = {'certificate.pem': cert, 'key.pem': key,
                      'validation_record.cms': b'\x30\x82record'}

    def passwd(self, uid):
        return type('pw', (), {'pw_dir': str(self.home), 'pw_gid': os.getgid()})()

    def check_apple(self, cert, key, record):
        return self.apple_problem

    def run_cmd(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = lifecycle.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def fields(self, text):
        return ident.parse_settings(text)

    def settings(self, **values):
        path = self.config / 'omdrop' / 'settings'
        path.parent.mkdir(exist_ok=True)
        path.write_text(''.join(f'{k}={v}\n' for k, v in values.items()))

    def op_item(self, files=None):
        item = self.opdir / 'items' / 'item1'
        item.mkdir(exist_ok=True)
        for name, data in (files or self.apple).items():
            (item / lifecycle.OP_NAMES[name]).write_bytes(data)

    def op_calls(self):
        path = self.opdir / 'calls'
        return path.read_text().splitlines() if path.exists() else []

    def on(self):
        """`omdrop on`'s identity steps: begin, then window with the seq it got."""
        rc, out, err = self.run_cmd('begin', '--name', 'Test')
        self.assertEqual(rc, 0, err)
        begun = self.fields(out)
        rc, out, _ = self.run_cmd('window', '--seq', begun['seq'])
        return rc, begun, self.fields(out)

    def off(self):
        self.run_cmd('stop-begin')
        self.run_cmd('stop-end')

    def window(self):
        return ident.read_window(ident.User())


class OnePasswordWindowTests(LifecycleFixture):
    def setUp(self):
        super().setUp()
        self.settings(identity_source='1password', identity_op_account='acct1',
                      identity_op_vault='vault1', identity_op_item='item1')
        self.op_item()

    def test_first_window_fetches_and_the_window_is_bound_to_that_fetch(self):
        rc, begun, win = self.on()
        self.assertEqual(rc, 0)
        self.assertNotIn('notice', begun)
        payload = ident.parse_payload(FakeKeyring.store['payload'])
        self.assertEqual(payload['key'], self.apple['key.pem'])
        self.assertEqual(payload['period_ends'] - payload['fetched_at'], 12 * 3600)
        self.assertEqual(payload['hard_expiry'] - payload['fetched_at'], 86400)
        self.assertEqual(win['source'], '1password')
        self.assertEqual(self.window(), {'source': '1password', 'fetch_id': payload['fetch_id'],
                                         'hard_expiry': payload['hard_expiry']})
        # During the window the cache lives until the hard expiry, not the period.
        self.assertGreater(FakeKeyring.store['timeout'], 12 * 3600)

    def test_a_later_window_in_the_period_uses_the_cache_without_asking(self):
        self.on()
        self.off()
        calls = len(self.op_calls())
        _, begun, win = self.on()
        self.assertEqual(len(self.op_calls()), calls)
        self.assertEqual(win['source'], '1password')

    def test_off_keeps_the_cache_but_shortens_it_to_the_period(self):
        self.on()
        self.off()
        self.assertIsNone(self.window())
        payload = ident.parse_payload(FakeKeyring.store['payload'])
        self.assertLessEqual(FakeKeyring.store['timeout'], payload['period_ends'] - payload['fetched_at'])

    def test_a_dismissed_prompt_falls_back_to_self_signed_and_says_why(self):
        os.environ['OP_STUB_FAIL'] = 'authorization prompt dismissed, please try again'
        rc, begun, win = self.on()
        self.assertEqual(rc, 0)
        self.assertEqual(begun['notice'], '1Password prompt dismissed; using self-signed '
                                          'certificates. Peers must be in "Everyone" mode.')
        self.assertEqual(win['source'], 'self-signed')
        self.assertNotIn('payload', FakeKeyring.store)

    def test_a_locked_1password_is_named_without_its_error_text(self):
        os.environ['OP_STUB_FAIL'] = ("could not read secret 'op://vault1/item1/certificate': "
                                      'error initializing client: connecting to desktop app: '
                                      'connection reset')
        _, begun, win = self.on()
        self.assertTrue(begun['notice'].startswith('1Password locked; using self-signed'))
        self.assertNotIn('op://', begun['notice'])
        self.assertEqual(win['source'], 'self-signed')

    def test_without_the_cli_the_notice_says_so(self):
        os.environ['OMDROP_OP'] = str(Path(self.tmp.name) / 'no-such-op')
        with unittest.mock.patch.object(lifecycle.shutil, 'which', return_value=None):
            os.environ.pop('OMDROP_OP')
            _, begun, win = self.on()
        self.assertIn('not installed', begun['notice'])
        self.assertEqual(win['source'], 'self-signed')

    def test_an_identity_that_fails_its_checks_is_never_cached(self):
        self.apple_problem = 'validation record has expired'
        _, begun, win = self.on()
        self.assertIn('Apple identity in 1Password is unusable', begun['notice'])
        self.assertNotIn('payload', FakeKeyring.store)
        self.assertEqual(win['source'], 'self-signed')

    def test_a_partial_fetch_publishes_nothing(self):
        (self.opdir / 'items' / 'item1' / 'validation_record').unlink()
        _, begun, win = self.on()
        self.assertIn('notice', begun)
        self.assertNotIn('payload', FakeKeyring.store)

    def test_off_during_the_fetch_means_nothing_starts(self):
        rc, out, _ = self.run_cmd('begin', '--name', 'Test')
        seq = self.fields(out)['seq']
        self.run_cmd('stop-begin')          # `off` arrives while `on` is fetching
        rc, _, _ = self.run_cmd('window', '--seq', seq)
        self.assertEqual(rc, 3)
        self.assertIsNone(self.window())

    def test_lock_during_a_fetch_discards_its_result(self):
        user = ident.User()
        with ident._Flock(user.lock):
            generation = lifecycle.counter(user, 'gen')
        payload = lifecycle.fetch(user)
        self.run_cmd('lock')                 # identity lock while the fetch was out
        self.assertEqual(lifecycle.publish_if_current(user, payload, generation), 'superseded')
        self.assertNotIn('payload', FakeKeyring.store)

    def test_a_live_window_cache_is_never_replaced(self):
        self.on()
        before = FakeKeyring.store['payload']
        user = ident.User()
        fresh = lifecycle.fetch(user)
        self.assertEqual(lifecycle.publish_if_current(user, fresh, lifecycle.counter(user, 'gen')),
                         'window-open')
        self.assertEqual(FakeKeyring.store['payload'], before)

    def test_a_self_signed_window_stays_self_signed_when_the_cache_fills(self):
        os.environ['OP_STUB_FAIL'] = 'dismissed'
        _, _, win = self.on()
        self.assertEqual(win['source'], 'self-signed')
        os.environ.pop('OP_STUB_FAIL')
        # `identity unlock` during the window fills the cache for later windows.
        lifecycle.fill_cache(ident.User())
        self.assertIn('payload', FakeKeyring.store)
        self.assertEqual(self.window(), {'source': 'self-signed'})
        self.off()
        _, _, win = self.on()
        self.assertEqual(win['source'], '1password')

    def test_unlock_does_nothing_when_the_cache_is_filled(self):
        self.assertEqual(self.run_cmd('unlock')[0], 0)
        calls = len(self.op_calls())
        self.assertEqual(self.run_cmd('unlock')[0], 0)
        self.assertEqual(len(self.op_calls()), calls)

    def test_identity_commands_refuse_during_a_window(self):
        self.on()
        for argv in (['lock'], ['1password-off'], ['use', 'item1'], ['import']):
            with self.subTest(argv):
                rc, _, err = self.run_cmd(*argv)
                self.assertEqual(rc, 1)
                self.assertIn('Turn Omdrop off first', err)

    def test_lock_clears_the_cache(self):
        self.on()
        self.off()
        self.assertEqual(self.run_cmd('lock')[0], 0)
        self.assertNotIn('payload', FakeKeyring.store)

    def test_an_expired_period_is_cleared_when_the_window_closes(self):
        self.on()
        payload = ident.parse_payload(FakeKeyring.store['payload'])
        with unittest.mock.patch.object(lifecycle, 'now', return_value=payload['period_ends'] + 1):
            self.off()
        self.assertNotIn('payload', FakeKeyring.store)

    def test_using_another_item_clears_the_old_items_cache(self):
        self.on()
        self.off()
        self.assertIn('payload', FakeKeyring.store)
        self.assertEqual(self.run_cmd('use', 'item1')[0], 0)
        self.assertNotIn('payload', FakeKeyring.store)

    def test_a_window_opened_while_use_is_out_prevents_its_commit(self):
        real = lifecycle.op_read_files

        def open_window_meanwhile(*a, **kw):
            files = real(*a, **kw)
            # What `omdrop on` leaves while `use` talks to 1Password.
            ident._write_private(ident.User().window, 'source=self-signed\n')
            return files
        with unittest.mock.patch.object(lifecycle, 'op_read_files', open_window_meanwhile):
            rc, _, err = self.run_cmd('use', 'item1')
        self.assertEqual(rc, 1)
        self.assertIn('Turn Omdrop off first', err)

    def test_use_is_refused_when_the_old_cache_cannot_be_cleared(self):
        self.on()
        self.off()
        before = (self.config / 'omdrop' / 'settings').read_text()
        cached = FakeKeyring.store['payload']

        def broken_revoke(self):
            raise ident.KeyringError('revoking: Permission denied')
        with unittest.mock.patch.object(FakeKeyring, 'revoke', broken_revoke):
            rc, _, err = self.run_cmd('use', 'item1')
        self.assertEqual(rc, 1)
        self.assertIn('Could not clear the cached identity', err)
        self.assertEqual((self.config / 'omdrop' / 'settings').read_text(), before)
        self.assertEqual(FakeKeyring.store['payload'], cached)

    def test_a_lock_while_use_is_out_prevents_its_commit(self):
        real = lifecycle.op_read_files

        def lock_meanwhile(*a, **kw):
            files = real(*a, **kw)
            self.run_cmd('lock')
            return files
        self.settings(identity_source='self-signed')
        with unittest.mock.patch.object(lifecycle, 'op_read_files', lock_meanwhile):
            rc, _, err = self.run_cmd('use', 'item1')
        self.assertEqual(rc, 1)
        self.assertIn('changed meanwhile', err)
        s = ident.parse_settings((self.config / 'omdrop' / 'settings').read_text())
        self.assertEqual(s['identity_source'], 'self-signed')


class ImportTests(LifecycleFixture):
    def setUp(self):
        super().setUp()
        for name, data in self.apple.items():
            (self.keys / name).write_bytes(data)
            (self.keys / name).chmod(0o600)

    def test_import_moves_the_identity_and_deletes_the_files_last(self):
        rc, _, err = self.run_cmd('import')
        self.assertEqual(rc, 0, err)
        s = ident.parse_settings((self.config / 'omdrop' / 'settings').read_text())
        self.assertEqual((s['identity_source'], s['identity_op_account'], s['identity_op_vault'],
                          s['identity_op_item']), ('1password', 'acct1', 'vault1', 'item1'))
        self.assertEqual([p.name for p in self.keys.iterdir() if p.name in lifecycle.FILES], [])

    def test_a_readback_that_differs_deletes_nothing(self):
        os.environ['OP_STUB_CORRUPT'] = 'key'
        rc, _, err = self.run_cmd('import')
        self.assertEqual(rc, 1)
        self.assertIn('nothing was deleted', err)
        self.assertEqual(sorted(p.name for p in self.keys.iterdir() if p.name in lifecycle.FILES),
                         sorted(lifecycle.FILES))

    def test_an_identity_that_fails_its_checks_is_not_imported(self):
        self.apple_problem = 'certificate is not issued by Apple'
        rc, _, err = self.run_cmd('import')
        self.assertEqual(rc, 1)
        self.assertEqual(self.op_calls(), [])

    def test_a_crash_before_the_mode_is_saved_is_finished_by_a_rerun(self):
        real = lifecycle.setting_set
        calls = []

        def crash_on_mode(user, **changes):
            if 'identity_source' in changes:
                raise OSError('disk full')
            calls.append(changes)
            real(user, **changes)
        with unittest.mock.patch.object(lifecycle, 'setting_set', crash_on_mode):
            rc, _, err = self.run_cmd('import')
        self.assertEqual(rc, 1)
        self.assertIn('Run the import again', err)
        # The item's IDs are already saved, so the rerun reuses it.
        self.assertEqual(ident.parse_settings((self.config / 'omdrop' / 'settings').read_text())
                         .get('identity_op_item'), 'item1')
        s = ident.parse_settings((self.config / 'omdrop' / 'settings').read_text())
        self.assertNotEqual(s.get('identity_source'), '1password')
        self.assertTrue((self.keys / 'key.pem').exists())
        creates = sum('item create' in c for c in self.op_calls())
        rc, _, err = self.run_cmd('import')
        self.assertEqual(rc, 0, err)
        self.assertEqual(sum('item create' in c for c in self.op_calls()), creates)
        self.assertFalse((self.keys / 'key.pem').exists())

    def test_a_superseded_import_does_not_record_its_item(self):
        # Another identity command runs while import is creating its item.
        real = lifecycle.account_id

        def use_meanwhile(user, deadline):
            account = real(user, deadline)
            with ident._Flock(user.lock):
                lifecycle.bump(user, 'gen')
            lifecycle.setting_set(user, identity_op_item='chosen-elsewhere')
            return account
        with unittest.mock.patch.object(lifecycle, 'account_id', use_meanwhile):
            rc, _, err = self.run_cmd('import')
        self.assertEqual(rc, 1)
        self.assertIn('item1', err)
        s = ident.parse_settings((self.config / 'omdrop' / 'settings').read_text())
        self.assertEqual(s['identity_op_item'], 'chosen-elsewhere')
        self.assertTrue((self.keys / 'key.pem').exists())

    def test_a_window_opened_during_import_keeps_every_file(self):
        real = lifecycle.op_read_files

        def open_window_at_readback(*a, **kw):
            files = real(*a, **kw)
            ident._write_private(ident.User().window, 'source=disk\n')
            return files
        with unittest.mock.patch.object(lifecycle, 'op_read_files', open_window_at_readback):
            rc, _, err = self.run_cmd('import')
        self.assertEqual(rc, 1)
        self.assertIn('Nothing was deleted', err)
        self.assertEqual(sorted(p.name for p in self.keys.iterdir() if p.name in lifecycle.FILES),
                         sorted(lifecycle.FILES))
        s = ident.parse_settings((self.config / 'omdrop' / 'settings').read_text())
        self.assertNotEqual(s.get('identity_source'), '1password')

    def test_leftovers_after_an_interrupted_delete_are_removed_by_a_rerun(self):
        self.assertEqual(self.run_cmd('import')[0], 0)
        (self.keys / 'certificate.pem').write_bytes(self.apple['certificate.pem'])
        self.assertEqual(self.run_cmd('import')[0], 0)
        self.assertFalse((self.keys / 'certificate.pem').exists())


class WindowSourceTests(LifecycleFixture):
    def test_disk_mode_with_an_apple_identity(self):
        for name, data in self.apple.items():
            (self.keys / name).write_bytes(data)
        _, _, win = self.on()
        self.assertEqual(win['source'], 'disk')

    def test_disk_mode_with_a_failing_apple_identity_falls_back_and_says_why(self):
        for name, data in self.apple.items():
            (self.keys / name).write_bytes(data)
        self.apple_problem = 'validation record has expired'
        _, _, win = self.on()
        self.assertEqual(win['source'], 'self-signed')
        self.assertTrue(win['notice'].startswith('Apple identity unusable; using self-signed'))

    def test_self_signed_mode_never_uses_the_disk_identity(self):
        for name, data in self.apple.items():
            (self.keys / name).write_bytes(data)
        self.settings(identity_source='self-signed')
        _, _, win = self.on()
        self.assertEqual(win['source'], 'self-signed')

    def test_a_repeated_on_keeps_the_windows_identity(self):
        _, _, win = self.on()
        self.assertEqual(win['source'], 'self-signed')
        for name, data in self.apple.items():
            (self.keys / name).write_bytes(data)
        _, _, again = self.on()
        self.assertEqual(again['source'], 'self-signed')


def _create(keys_parent, results):
    os.environ['HOME'] = keys_parent
    user = ident.User(keys_dir=os.path.join(keys_parent, '.omdrop'))
    results.put(ident.create_self_signed(user, 'Race'))


class SelfSignedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.user = ident.User(keys_dir=os.path.join(self.tmp.name, '.omdrop'))

    def test_two_creators_at_once_end_with_one_intact_pair(self):
        ctx = multiprocessing.get_context('fork')
        results = ctx.Queue()
        procs = [ctx.Process(target=_create, args=(self.tmp.name, results)) for _ in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(60)
        made = [results.get(timeout=5) for _ in procs]
        self.assertEqual(made.count(True), 1)
        cert = Path(self.user.path('certificate.self-signed.pem')).read_bytes()
        key = Path(self.user.path('key.self-signed.pem')).read_bytes()
        self.assertTrue(ident.key_matches(cert, key))
        self.assertEqual(sorted(os.listdir(self.user.keys)),
                         ['.identity.lock', 'certificate.self-signed.pem', 'key.self-signed.pem'])

    def test_half_a_pair_is_never_overwritten(self):
        os.makedirs(self.user.keys)
        Path(self.user.path('key.self-signed.pem')).write_bytes(b'mine')
        with self.assertRaises(ident.IdentityError):
            ident.create_self_signed(self.user, 'X')
        self.assertEqual(Path(self.user.path('key.self-signed.pem')).read_bytes(), b'mine')

    def test_a_failed_second_link_leaves_no_half_pair_behind(self):
        real_link, calls = os.link, []

        def full_disk(src, dst):
            calls.append(dst)
            if len(calls) == 2:
                raise OSError(28, 'No space left on device')
            real_link(src, dst)
        with unittest.mock.patch.object(ident.os, 'link', full_disk):
            with self.assertRaises(ident.IdentityError):
                ident.create_self_signed(self.user, 'X')
        self.assertEqual(ident.pair_state(self.user), {'certificate': False, 'key': False})
        self.assertTrue(ident.create_self_signed(self.user, 'X'))   # and it can try again

    @unittest.skipIf(os.geteuid() == 0, 'root reads a mode-0 file')
    def test_an_unreadable_legacy_key_does_not_stop_the_self_signed_identity(self):
        tmp = Path(self.tmp.name)
        config, runtime = tmp / 'config', tmp / 'run'
        (config / 'omdrop').mkdir(parents=True)
        runtime.mkdir()
        (config / 'omdrop' / 'settings').write_text('identity_source=self-signed\n')
        ident.create_self_signed(self.user, 'X')
        Path(self.user.path('key.pem')).write_bytes(b'legacy')
        os.chmod(self.user.path('key.pem'), 0)
        with unittest.mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': str(config),
                                                   'XDG_RUNTIME_DIR': str(runtime)}):
            user = ident.User(keys_dir=os.path.join(self.tmp.name, '.omdrop'))
            chosen = ident.resolve(user)
        self.assertEqual(chosen.kind, 'self-signed')


class LegacyRenameTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.user = ident.User(keys_dir=os.path.join(self.tmp.name, '.omdrop'))
        os.makedirs(self.user.keys)

    def test_a_genuinely_self_signed_pair_is_renamed(self):
        cert, key = make_self_signed(self.user.keys)
        self.assertEqual(ident.migrate_legacy(self.user), 'renamed')
        self.assertEqual(Path(self.user.path('certificate.self-signed.pem')).read_bytes(), cert)
        self.assertEqual(Path(self.user.path('key.self-signed.pem')).read_bytes(), key)
        self.assertFalse(os.path.exists(self.user.path('certificate.pem')))

    def test_matching_names_without_a_self_signature_are_left_alone(self):
        # Issuer and subject both CN=Twin, but signed by a different key.
        work = Path(self.tmp.name)
        subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1',
                        '-subj', '/CN=Twin', '-keyout', 'ca.key', '-out', 'ca.pem'],
                       cwd=work, check=True, capture_output=True)
        subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Twin',
                        '-keyout', str(Path(self.user.keys) / 'key.pem'), '-out', 'leaf.csr'],
                       cwd=work, check=True, capture_output=True)
        subprocess.run(['openssl', 'x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem',
                        '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1',
                        '-out', str(Path(self.user.keys) / 'certificate.pem')],
                       cwd=work, check=True, capture_output=True)
        self.assertEqual(ident.migrate_legacy(self.user), 'not-self-signed')
        self.assertTrue(os.path.exists(self.user.path('certificate.pem')))

    def test_a_pair_with_a_record_is_left_alone(self):
        make_self_signed(self.user.keys)
        Path(self.user.path('validation_record.cms')).write_bytes(b'r')
        self.assertEqual(ident.migrate_legacy(self.user), 'has-record')

    def test_an_existing_destination_is_never_replaced(self):
        make_self_signed(self.user.keys)
        Path(self.user.path('certificate.self-signed.pem')).write_bytes(b'keep')
        self.assertEqual(ident.migrate_legacy(self.user), 'destination-exists')
        self.assertEqual(Path(self.user.path('certificate.self-signed.pem')).read_bytes(), b'keep')


class DebugDumpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        import debugdump
        self.dd = debugdump
        self.body = __import__('plistlib').dumps(
            {'SenderRecordData': b'secret-record', 'Nested': {'SenderCertificate': b'cert'},
             'SenderComputerName': 'Mac'})

    def dump(self, **env):
        with unittest.mock.patch.dict(os.environ, {'XDG_RUNTIME_DIR': self.tmp.name, **env}):
            for var in ('OMDROP_DEBUG', 'OMDROP_DEBUG_SENSITIVE'):
                if var not in env:
                    os.environ.pop(var, None)
            self.dd.dump('x.plist', self.body)
        return Path(self.tmp.name) / 'omdrop' / 'debug' / 'x.plist'

    def test_nothing_is_written_by_default(self):
        self.assertFalse(self.dump().exists())

    def test_debug_dumps_are_redacted(self):
        text = self.dump(OMDROP_DEBUG='1').read_bytes()
        self.assertNotIn(b'secret-record', text)
        self.assertIn(b'&lt;redacted 13 bytes&gt;', text)
        self.assertIn(b'Mac', text)

    def test_sensitive_dumps_are_verbatim(self):
        self.assertEqual(self.dump(OMDROP_DEBUG_SENSITIVE='1').read_bytes(), self.body)

    def test_a_plist_whose_references_expand_is_dumped_opaque(self):
        # The redacted dump is XML, which writes every reference out in full.
        entry = {'FileName': 'A' * 10_000}
        self.body = __import__('plistlib').dumps({'Files': [entry] * 2000},
                                                 fmt=__import__('plistlib').FMT_BINARY)
        self.assertEqual(self.dump(OMDROP_DEBUG='1').read_bytes(),
                         f'<opaque {len(self.body)} bytes>'.encode())


import unittest.mock  # noqa: E402

if __name__ == '__main__':
    unittest.main()
