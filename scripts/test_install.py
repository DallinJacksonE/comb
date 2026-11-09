#!/usr/bin/env python3
"""Isolated installer contract tests; no real builds or user services touched."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / 'FRAME/install.sh'
UNINSTALL = REPO / 'FRAME/uninstall.sh'

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
p = pathlib.Path
name = p(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['MOCK_LOG'], 'a') as f:
    f.write(json.dumps([name, args, os.getcwd()]) + '\n')
if os.environ.get('MOCK_FAIL') == name or (name == 'systemctl' and os.environ.get('MOCK_SYSTEMCTL_FAIL') in args):
    sys.exit(29)
if name == 'systemctl' and 'is-active' in args and os.environ.get('MOCK_ACTIVE_FAIL_AFTER'):
    calls = [json.loads(line) for line in p(os.environ['MOCK_LOG']).read_text().splitlines()]
    active = sum(c[0] == 'systemctl' and 'is-active' in c[1] for c in calls)
    if active > int(os.environ['MOCK_ACTIVE_FAIL_AFTER']):
        sys.exit(29)
if name == 'git' and args[0] == 'clone':
    shutil.copytree(os.environ['MOCK_SOURCE'], args[-1])
if name == 'cargo':
    target = p(os.environ['CARGO_TARGET_DIR']) / ('release' if '--release' in args else 'debug')
    target.mkdir(parents=True, exist_ok=True)
    binary = target / 'comb'
    binary.write_text(r"""#!/usr/bin/env python3
import json, os, pathlib, sys, time
args = sys.argv[1:]
if args and args[-1] == 'service-status':
    log = pathlib.Path(os.environ['MOCK_LOG'] + '.status')
    attempts = len(log.read_text().splitlines()) if log.exists() else 0
    with log.open('a') as f:
        f.write(json.dumps(args) + '\n')
    if os.environ.get('MOCK_STATUS_HANG'):
        time.sleep(60)
    sys.exit(1 if os.environ.get('MOCK_NO_SOCKET') or attempts < int(os.environ.get('MOCK_STATUS_DELAY', '0')) else 0)
print(json.dumps({'data': os.environ.get('COMB_DATA_DIR'), 'args': args}) if os.environ.get('MOCK_ECHO_RUNTIME') else 'mock comb')
""")
    binary.chmod(0o755)
if name == 'npm' and args == ['run', 'build']:
    (p('dist') / 'assets').mkdir(parents=True, exist_ok=True)
    p('dist/index.html').write_text('<html>built gui</html>')
    p('dist/assets/app.js').write_text('built javascript')
'''


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='comb install ', dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.home = self.base / 'home'
        self.home.mkdir()
        self.tools = self.base / 'tools'
        self.tools.mkdir()
        for tool in ('git', 'cargo', 'rustc', 'node', 'npm', 'systemctl', 'ssh'):
            path = self.tools / tool
            path.write_text(MOCK)
            path.chmod(0o755)
        self.source = self.base / 'source checkout'
        (self.source / 'FRAME/webgui').mkdir(parents=True)
        (self.source / 'Cargo.toml').write_text('[workspace]\n')
        (self.source / 'FRAME/Cargo.toml').write_text('[package]\nname="comb-frame"\n')
        (self.source / 'FRAME/webgui/package-lock.json').write_text('{}')
        shutil.copy2(UNINSTALL, self.source / 'FRAME/uninstall.sh') if UNINSTALL.exists() else None
        self.root = self.home / '.local/share/comb-install'
        self.bin = self.home / '.local/bin/comb'
        self.unit = self.home / '.config/systemd/user/comb.service'
        self.data = self.home / '.local/share/comb'
        self.log = self.base / 'commands.jsonl'
        self.env = dict(os.environ, HOME=str(self.home), PATH=f'{self.tools}:/usr/bin:/bin',
                        MOCK_LOG=str(self.log), MOCK_SOURCE=str(self.source),
                        TMPDIR=str(self.base))
        for key in ('XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'COMB_INSTALL_ROOT', 'COMB_BIN_DIR',
                    'COMB_DATA_DIR', 'COMB_SERVICE_NAME', 'COMB_SERVICE_DIR', 'CARGO_TARGET_DIR',
                    'MOCK_FAIL', 'MOCK_SYSTEMCTL_FAIL', 'MOCK_ACTIVE_FAIL_AFTER',
                    'MOCK_STATUS_HANG', 'MOCK_NO_SOCKET', 'MOCK_STATUS_DELAY', 'MOCK_ECHO_RUNTIME'):
            self.env.pop(key, None)

    def run_install(self, *args, stdin=False):
        if not INSTALL.exists():
            self.fail('FRAME/install.sh is missing')
        return subprocess.run(['bash', '-s', '--', *args] if stdin else ['bash', str(INSTALL), *args],
                              input=INSTALL.read_text() if stdin else None,
                              text=True, capture_output=True, env=self.env, cwd=self.base)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_local_source_entrypoint_uses_checkout_and_can_uninstall_from_source(self):
        entry = self.source / 'FRAME/install.sh'
        shutil.copy2(INSTALL, entry)
        result = subprocess.run(['bash', str(entry)], env=self.env, cwd=self.base, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[0] == 'git' for call in self.calls()), 'local source entrypoint must not replace its checkout with an older clone')
        self.assertEqual(next(call for call in self.calls() if call[0] == 'cargo')[2], str(self.source))
        self.data.mkdir(parents=True)
        recovery = self.data / 'identity.recovery'
        recovery.write_text('preserve fixture recovery')
        result = subprocess.run(['bash', str(self.source / 'FRAME/uninstall.sh')], env=self.env,
                                cwd=self.base, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.bin.exists())
        self.assertFalse(self.unit.exists())
        self.assertEqual(recovery.read_text(), 'preserve fixture recovery')

    def test_missing_or_invalid_source_uninstaller_fails_before_build_or_install(self):
        cleanup = self.source / 'FRAME/uninstall.sh'
        original = cleanup.read_bytes()
        for kind in ('missing', 'symlink', 'invalid-shell'):
            with self.subTest(kind=kind):
                if cleanup.exists() or cleanup.is_symlink():
                    cleanup.unlink()
                if kind == 'symlink':
                    foreign = self.base / 'foreign-cleanup.sh'
                    foreign.write_bytes(original)
                    cleanup.symlink_to(foreign)
                elif kind == 'invalid-shell':
                    cleanup.write_text('if broken syntax\n')
                self.log.unlink(missing_ok=True)
                result = self.run_install('--source', str(self.source))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('uninstaller', result.stderr.lower())
                self.assertFalse(any(call[0] in {'cargo', 'npm'} for call in self.calls()), 'cleanup must be checked before either build')
                self.assertFalse(self.root.exists())
                self.assertFalse(self.bin.exists())
                self.assertFalse(self.unit.exists())
        cleanup.unlink()
        cleanup.write_bytes(original)

    def test_local_release_installs_built_binary_assets_and_service(self):
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(subprocess.check_output([str(self.bin)], text=True), 'mock comb\n')
        self.assertEqual((self.root / 'assets/index.html').read_text(), '<html>built gui</html>')
        self.assertTrue((self.root / 'assets/assets/app.js').is_file())
        unit = self.unit.read_text()
        self.assertIn('serve --managed --assets', unit)
        self.assertIn('--sync-seconds 15', unit)
        calls = self.calls()
        self.assertTrue(any(c[0] == 'cargo' and '--release' in c[1] for c in calls))
        self.assertTrue(any(c[0] == 'npm' and c[1] == ['ci'] for c in calls))
        self.assertTrue(any(c[0] == 'npm' and c[1] == ['run', 'build'] for c in calls))
        cargo = next(c for c in calls if c[0] == 'cargo')
        self.assertEqual(cargo[2], str(self.source))
        self.assertIn('--locked', cargo[1])
        self.assertEqual(cargo[1][-4:], ['--package', 'comb-frame', '--bin', 'comb'])
        self.assertTrue(all(c[2] == str(self.source / 'FRAME/webgui') for c in calls if c[0] == 'npm'))
        self.assertFalse(any(c[0] == 'git' for c in calls))
        self.assertTrue(any(c[:2] == ['systemctl', ['--user', 'enable', '--now', 'comb.service']] for c in calls))
        self.assertTrue(any(c[:2] == ['systemctl', ['--user', 'is-active', '--quiet', 'comb.service']] for c in calls))
        self.assertIn('locked', result.stdout.lower())
        self.assertIn('recovery', result.stdout.lower())

    def test_unsafe_and_foreign_paths_are_rejected_before_changes(self):
        cases = ('home-root', 'relative', 'data-overlap', 'bin-overlap', 'foreign-root',
                 'foreign-binary', 'foreign-unit', 'symlink-parent', 'bad-service')
        for case in cases:
            with self.subTest(case=case):
                env = self.env.copy()
                root = self.base / ('candidate-' + case)
                env['COMB_INSTALL_ROOT'] = str(root)
                sentinel = None
                if case == 'home-root':
                    env['COMB_INSTALL_ROOT'] = str(self.home)
                elif case == 'relative':
                    env['COMB_INSTALL_ROOT'] = 'relative-install'
                elif case == 'data-overlap':
                    env['COMB_DATA_DIR'] = str(root / 'valuable')
                elif case == 'bin-overlap':
                    env['COMB_BIN_DIR'] = str(root / 'bin')
                elif case == 'foreign-root':
                    root.mkdir()
                    sentinel = root / 'foreign'
                elif case == 'foreign-binary':
                    self.bin.parent.mkdir(parents=True, exist_ok=True)
                    sentinel = self.bin
                elif case == 'foreign-unit':
                    self.unit.parent.mkdir(parents=True, exist_ok=True)
                    sentinel = self.unit
                elif case == 'symlink-parent':
                    real = self.base / 'real-dir'
                    real.mkdir()
                    link = self.base / 'linked-dir'
                    link.symlink_to(real, target_is_directory=True)
                    env['COMB_INSTALL_ROOT'] = str(link / 'install')
                elif case == 'bad-service':
                    env['COMB_SERVICE_NAME'] = '../bad.service'
                if sentinel:
                    sentinel.write_text('foreign contents')
                previous = self.env
                self.env = env
                result = self.run_install('--source', str(self.source))
                self.env = previous
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                if sentinel:
                    self.assertEqual(sentinel.read_text(), 'foreign contents')
                    sentinel.unlink()

    def test_reinstall_rejects_new_asset_collisions_before_removing_old_install(self):
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        original = self.bin.read_bytes()
        for kind in ('file', 'directory', 'symlink', 'parent-file', 'parent-directory'):
            with self.subTest(kind=kind):
                dist = self.source / 'FRAME/webgui/dist'
                name = 'new-' + kind
                relative = Path(name) / 'item' if kind.startswith('parent-') else Path(name)
                built = dist / relative
                built.parent.mkdir(parents=True, exist_ok=True)
                built.write_text('new build asset')
                collision = self.root / 'assets' / name
                sentinel = self.base / 'sentinel'
                sentinel.write_text('valuable')
                if kind in ('directory', 'parent-directory'):
                    collision.mkdir()
                    (collision / 'keep').write_text('valuable')
                elif kind == 'symlink':
                    collision.symlink_to(sentinel)
                else:
                    collision.write_text('valuable')
                before = len(self.calls())
                result = self.run_install('--source', str(self.source))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.bin.read_bytes(), original)
                self.assertTrue(self.unit.exists())
                self.assertEqual(sentinel.read_text(), 'valuable')
                self.assertFalse(any(c[0] == 'systemctl' and 'disable' in c[1]
                                     for c in self.calls()[before:]))
                if collision.is_dir() and not collision.is_symlink():
                    self.assertEqual((collision / 'keep').read_text(), 'valuable')
                    shutil.rmtree(collision)
                else:
                    if not collision.is_symlink():
                        self.assertEqual(collision.read_text(), 'valuable')
                    collision.unlink()
                if (dist / name).is_dir():
                    shutil.rmtree(dist / name)
                else:
                    (dist / name).unlink()

    def test_uninstall_rejects_symlink_and_modified_owned_files(self):
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        original = self.bin.read_bytes()
        self.bin.write_text('foreign replacement')
        result = subprocess.run(['bash', str(self.root / 'uninstall.sh')], env=self.env,
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.unit.exists())
        self.bin.write_bytes(original)
        asset = self.root / 'assets/index.html'
        other = self.base / 'foreign-asset'
        other.write_text(asset.read_text())
        asset.unlink()
        asset.symlink_to(other)
        result = subprocess.run(['bash', str(self.root / 'uninstall.sh')], env=self.env,
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(asset.is_symlink())
        self.assertTrue(self.unit.exists())

    def test_path_setup_is_idempotent_and_uninstall_keeps_user_startup_content(self):
        startup = self.home / '.bashrc'
        startup.write_text('# original startup\nexport USER_SETTING=yes\n')
        for _ in range(2):
            result = self.run_install('--source', str(self.source), '--profile', 'dev')
            self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('.profile', '.bashrc', '.zshrc'):
            self.assertTrue((self.home / name).exists(), f'{name} PATH setup missing')
            text = (self.home / name).read_text()
            self.assertEqual(text.count('# >>> comb PATH >>>'), 1)
            self.assertEqual(text.count('# <<< comb PATH <<<'), 1)
        startup.write_text(startup.read_text() + '# later user setting\n')
        probe = subprocess.run(['bash', '-c', '. "$HOME/.profile"; . "$HOME/.profile"; command -v comb; printf "%s" "$PATH"'],
                               env=self.env, text=True, capture_output=True)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(probe.stdout.splitlines()[0], str(self.bin))
        self.assertEqual(probe.stdout.splitlines()[1].split(':').count(str(self.bin.parent)), 1)
        result = subprocess.run(['bash', str(self.root / 'uninstall.sh')], env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('# original startup\nexport USER_SETTING=yes', startup.read_text())
        self.assertIn('# later user setting', startup.read_text())
        self.assertNotIn('comb PATH', startup.read_text())

    def test_build_failures_leave_no_install_and_do_not_touch_old_install(self):
        for tool in ('git', 'cargo', 'npm', 'systemctl'):
            with self.subTest(tool=tool):
                self.env['MOCK_FAIL'] = tool
                result = self.run_install(stdin=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.bin.exists())
                self.assertFalse(self.unit.exists())
                self.assertNotIn('Installed comb.', result.stdout)
        self.env.pop('MOCK_FAIL')
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        original = self.bin.read_bytes()
        self.env['MOCK_FAIL'] = 'npm'
        result = self.run_install('--source', str(self.source))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.bin.read_bytes(), original)
        self.assertTrue(self.unit.is_file())

    def test_stdin_uninstaller_uses_default_or_configured_root(self):
        for custom in (False, True):
            with self.subTest(custom=custom):
                if custom:
                    self.env['COMB_INSTALL_ROOT'] = str(self.home / 'custom install')
                result = self.run_install('--source', str(self.source))
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run(['bash', '-s', '--'], input=UNINSTALL.read_text(),
                                        env=self.env, cwd=self.base, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.bin.exists())
                self.assertFalse(self.unit.exists())

    def test_service_directory_override_is_recorded_for_installed_uninstaller(self):
        service_dir = self.base / 'manager units'
        self.env.update(COMB_SERVICE_DIR=str(service_dir), COMB_SERVICE_NAME='comb-isolated.service')
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        unit = service_dir / 'comb-isolated.service'
        self.assertTrue(unit.is_file(), 'COMB_SERVICE_DIR ignored')
        self.assertFalse(self.unit.exists())
        # Installed uninstaller uses its receipt, not current path/service overrides.
        self.env.pop('COMB_SERVICE_DIR')
        self.env.pop('COMB_SERVICE_NAME')
        result = subprocess.run(['bash', str(self.root / 'uninstall.sh')], env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(unit.exists())

    def test_dangling_binary_symlink_is_never_followed(self):
        self.bin.parent.mkdir(parents=True)
        victim = self.base / 'must-not-create'
        self.bin.symlink_to(victim)
        result = self.run_install('--source', str(self.source))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(victim.exists())
        self.assertTrue(self.bin.is_symlink())

    def test_shell_path_quotes_and_existing_startup_symlinks(self):
        bindir = self.home / '''bin ' $ % \\ " space'''
        self.env['COMB_BIN_DIR'] = str(bindir)
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['bash', '-c', '. "$HOME/.profile"; command -v comb'],
                                env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(bindir / 'comb'))
        foreign = self.base / 'foreign-startup'
        foreign.write_text('untouched')
        (self.home / '.bashrc').unlink()
        (self.home / '.bashrc').symlink_to(foreign)
        result = self.run_install('--source', str(self.source))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(foreign.read_text(), 'untouched')

    def test_launcher_persists_custom_data_and_preserves_runtime_overrides(self):
        data = self.home / "data ' $ % \\\" custom"
        root = self.home / "install ' $ % \\\" custom"
        self.env.update(COMB_DATA_DIR=str(data), COMB_INSTALL_ROOT=str(root))
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        fresh = self.env.copy()
        fresh.pop('COMB_DATA_DIR')
        fresh['MOCK_ECHO_RUNTIME'] = '1'
        args = ['--data', str(self.home / 'explicit data'), 'identity', 'argument with spaces', '$literal']
        for explicit in (None, str(self.home / 'runtime override')):
            with self.subTest(explicit=explicit):
                env = fresh.copy()
                if explicit is not None:
                    env['COMB_DATA_DIR'] = explicit
                result = subprocess.run(['bash', '--noprofile', '--norc', '-c',
                                         '. "$HOME/.profile"; exec comb "$@"', 'probe', *args],
                                        env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'data': explicit or str(data), 'args': args})
        self.assertTrue(self.bin.read_text().startswith('#!/usr/bin/env bash\n'))
        self.assertNotEqual(self.bin.read_bytes(), (root / 'bin/comb').read_bytes())
        hashes = (root / '.comb-install-hashes').read_text()
        for path in (self.bin, root / 'bin/comb'):
            checksum = subprocess.check_output(['sha256sum', '--', str(path)], text=True)
            self.assertIn(checksum, hashes)

    def test_startup_waits_for_native_private_ipc_readiness(self):
        self.env['MOCK_STATUS_DELAY'] = '2'
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        status = Path(str(self.log) + '.status')
        self.assertTrue(status.exists(), 'No native IPC status probe was attempted')
        self.assertEqual([json.loads(line) for line in status.read_text().splitlines()],
                         [['--data', str(self.data), 'service-status']] * 3)
        active = [c for c in self.calls() if c[0] == 'systemctl' and 'is-active' in c[1]]
        self.assertGreaterEqual(len(active), 4)

    def test_startup_rejects_active_service_without_ipc_with_bounded_deadline(self):
        self.env['MOCK_NO_SOCKET'] = '1'
        start = time.monotonic()
        result = self.run_install('--source', str(self.source))
        elapsed = time.monotonic() - start
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Installed comb.', result.stdout)
        self.assertIn('private IPC', result.stderr)
        self.assertGreater(elapsed, 27)
        self.assertLess(elapsed, 36)
        result = subprocess.run(['bash', str(self.root / 'uninstall.sh')], env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_startup_rejects_delayed_failure_and_bounds_hanging_probe(self):
        self.env.update(MOCK_STATUS_HANG='1', MOCK_ACTIVE_FAIL_AFTER='1')
        start = time.monotonic()
        result = self.run_install('--source', str(self.source))
        elapsed = time.monotonic() - start
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Installed comb.', result.stdout)
        self.assertIn('journalctl', result.stderr)
        self.assertGreater(elapsed, 1.8)
        self.assertLess(elapsed, 8)
        self.assertTrue((self.root / '.comb-install-owner').exists())

    def test_startup_checks_activity_again_after_successful_ipc_probe(self):
        self.env['MOCK_ACTIVE_FAIL_AFTER'] = '1'
        result = self.run_install('--source', str(self.source))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('stopped after readiness', result.stderr)
        self.assertNotIn('Installed comb.', result.stdout)

    def test_reinstall_does_not_claim_unknown_files_or_directories(self):
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        unknown = self.root / 'assets/user-file'
        unknown.write_text('valuable')
        unknown_dir = self.root / 'assets/user-empty-tree'
        unknown_dir.mkdir()
        extra_binary = self.root / 'bin/other-tool'
        extra_binary.write_text('valuable')
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['bash', str(self.root / 'uninstall.sh')], env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(unknown.read_text(), 'valuable')
        self.assertEqual(extra_binary.read_text(), 'valuable')
        self.assertTrue(unknown_dir.is_dir())

    def test_startup_or_health_failure_is_reported_and_install_remains_uninstallable(self):
        for action in ('enable', 'is-active'):
            with self.subTest(action=action):
                self.env['MOCK_SYSTEMCTL_FAIL'] = action
                result = self.run_install('--source', str(self.source))
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Installed comb.', result.stdout)
                self.assertIn('systemctl' if action == 'enable' else 'journalctl', result.stderr)
                self.assertTrue((self.root / 'uninstall.sh').is_file())
                self.env.pop('MOCK_SYSTEMCTL_FAIL')
                result = subprocess.run(['bash', str(self.root / 'uninstall.sh')], env=self.env,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_prerequisite_explains_without_bootstrap(self):
        (self.tools / 'node').unlink()
        # Restrict PATH to the fixture, including bash but no system node fallback.
        (self.tools / 'bash').symlink_to(shutil.which('bash'))
        self.env['PATH'] = str(self.tools)
        result = self.run_install('--source', str(self.source))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing prerequisite: node', result.stderr)
        self.assertIn('no sudo', result.stderr)
        self.assertFalse(self.log.exists())

    def test_installed_uninstall_preserves_data_and_unknown_siblings(self):
        result = self.run_install('--source', str(self.source))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'uninstall.sh').exists(), 'installed uninstaller missing')
        (self.data / 'recovery/working-tree').mkdir(parents=True)
        secret = self.data / 'recovery/working-tree/keep'
        secret.write_text('valuable')
        sibling = self.bin.parent / 'other-tool'
        sibling.write_text('keep')
        unknown = self.root / 'user-notes'
        unknown.write_text('keep')
        empty_tree = self.root / 'empty-user-working-tree'
        empty_tree.mkdir()
        extra_asset = self.root / 'assets/user-file'
        extra_asset.write_text('keep')
        shutil.rmtree(self.source)
        result = subprocess.run(['bash', str(self.root / 'uninstall.sh')], env=self.env,
                                cwd=self.base, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.bin.exists())
        self.assertFalse(self.unit.exists())
        self.assertFalse((self.root / 'assets/index.html').exists())
        self.assertEqual(secret.read_text(), 'valuable')
        self.assertEqual(sibling.read_text(), 'keep')
        self.assertEqual(unknown.read_text(), 'keep')
        self.assertTrue(empty_tree.is_dir())
        self.assertEqual(extra_asset.read_text(), 'keep')
        self.assertTrue(any(c[:2] == ['systemctl', ['--user', 'disable', '--now', 'comb.service']] for c in self.calls()))

    def test_stdin_download_dev_override_and_systemd_escaping(self):
        root = self.home / 'install % $cash space'
        data = self.home / 'data % $cash space'
        bindir = self.home / 'custom bin'
        self.env.update(COMB_INSTALL_ROOT=str(root), COMB_DATA_DIR=str(data),
                        COMB_BIN_DIR=str(bindir), COMB_SERVICE_NAME='comb-test.service')
        result = self.run_install('--profile', 'dev', stdin=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((root / 'assets/index.html').is_file())
        self.assertTrue((root / 'uninstall.sh').is_file())
        self.assertTrue((bindir / 'comb').is_file())
        calls = self.calls()
        clone = next(c for c in calls if c[0] == 'git')
        self.assertIn('https://github.com/DallinJacksonE/comb.git', clone[1])
        self.assertIn('main', clone[1])
        cargo = next(c for c in calls if c[0] == 'cargo')
        self.assertNotIn('--release', cargo[1])
        unit = (self.unit.parent / 'comb-test.service').read_text()
        self.assertIn('ExecStart="' + str(root / 'bin/comb').replace('%', '%%') + '"', unit)
        self.assertIn('data %% $$cash space', unit)
        self.assertNotIn(str(self.source), unit)


if __name__ == '__main__':
    unittest.main(verbosity=2)
