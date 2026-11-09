#!/usr/bin/env python3
"""Real PTY initialization, passphrase-protected SSH alias, native Git and restart; disposable state only."""
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import tempfile
import time

from managed_walkthrough_smoke import BINARY, PASSWORD, ROOT, free_port, state, terminal_command

SSH_PASSPHRASE = 'ssh-smoke-only-passphrase'


def wait_for(probe, label, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if probe():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    raise AssertionError(f'Timed out: {label}')


def listening(port):
    with socket.socket() as client:
        client.settimeout(0.2)
        return client.connect_ex(('127.0.0.1', port)) == 0


def main():
    env = {key: value for key, value in os.environ.items() if not key.startswith('COMB_')}
    env.pop('SSH_AUTH_SOCK', None)
    processes = []
    with tempfile.TemporaryDirectory(prefix='comb-ssh-smoke-', dir=os.environ.get('TMPDIR')) as temporary:
        directory = Path(temporary)
        data, config = directory / 'frame', directory / 'ssh-config'
        config.write_text('Host unrelated-fixture\n    HostName example.invalid\n')
        management, peer, ssh_port = free_port(), free_port(), free_port()
        env['COMB_SSH_CONFIG'] = str(config)
        env['COMB_SSH_LISTEN'] = f'127.0.0.1:{ssh_port}'
        client = dict(env, COMB_PASSWORD=PASSWORD)
        arguments = ['--data', str(data), '--api-url', f'http://127.0.0.1:{management}']

        def cli(*args):
            result = subprocess.run([str(BINARY), *arguments, *args], env=client,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
            assert result.returncode == 0, 'Fixture CLI operation failed (output withheld)'
            return json.loads(result.stdout)

        def start():
            process = subprocess.Popen([str(BINARY), '--data', str(data), 'serve', '--managed',
                '--listen', f'127.0.0.1:{management}', '--peer-listen', f'127.0.0.1:{peer}',
                '--ssh-listen', f'127.0.0.1:{ssh_port}', '--assets', str(ROOT / 'FRAME/webgui/dist')],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            wait_for(lambda: process.poll() is not None or data.joinpath('service.sock').exists(), 'private control socket')
            assert process.poll() is None, 'Fixture daemon exited during startup'
            wait_for(lambda: state(data) in {'uninitialized', 'locked'}, 'locked state')
            return process

        try:
            process = start()
            assert not listening(ssh_port), 'SSH must stay closed before first setup/unlock'
            print('Checking: real hidden-input username and protected-key initialization', flush=True)
            terminal_command([*arguments, 'cell', 'list'], env, [
                ('Name: ', 'Alice'), ('Email: ', 'alice@test'), ('Username (SSH login): ', 'alice'),
                ('Choose FRAME/recovery-file password: ', PASSWORD), ('Confirm password: ', PASSWORD),
                ('SSH key passphrase (Enter for none): ', SSH_PASSPHRASE),
                ('Confirm SSH key passphrase: ', SSH_PASSPHRASE),
            ])
            wait_for(lambda: listening(ssh_port), 'unlocked SSH listener')
            settings = cli('ssh', 'status')
            assert settings['username'] == 'alice'
            assert 'Host unrelated-fixture\n    HostName example.invalid\n' in config.read_text()
            assert Path(settings['client_key']).stat().st_mode & 0o777 == 0o600
            assert state(data) == 'ready'

            # Simulate an SSH passphrase prompt without putting the passphrase in argv or Git config.
            askpass = directory / 'askpass.py'
            asklog = directory / 'askpass.log'
            askpass.write_text('#!/usr/bin/env python3\nimport os\nwith open(os.environ["COMB_TEST_ASKLOG"], "a") as log: log.write("prompted\\n")\nprint(os.environ["COMB_TEST_KEY_PASSPHRASE"])\n')
            askpass.chmod(0o700)
            git_env = dict(env, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY='comb-fixture',
                COMB_TEST_KEY_PASSPHRASE=SSH_PASSPHRASE, COMB_TEST_ASKLOG=str(asklog),
                GIT_SSH_COMMAND=f'ssh -F {shlex.quote(str(config))}',
                GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
                GIT_AUTHOR_NAME='Fixture', GIT_AUTHOR_EMAIL='fixture@test',
                GIT_COMMITTER_NAME='Fixture', GIT_COMMITTER_EMAIL='fixture@test')

            def git(cwd, *args):
                result = subprocess.run(['git', '-c', 'init.defaultBranch=main', *args], cwd=cwd, env=git_env,
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=25)
                diagnostic = result.stderr.decode(errors='replace').replace(PASSWORD, '<fixture-secret>').replace(SSH_PASSPHRASE, '<fixture-secret>')
                assert result.returncode == 0, f'Native Git SSH {args[0]} failed: {diagnostic}'
                return result.stdout

            print('Checking: automatic alias selects protected key; clone, push, fetch and ID remote', flush=True)
            cell = cli('cell', 'create', 'SSH Smoke Repo')
            assert cell['ssh_remote'] == f'{settings["alias"]}:ssh-smoke-repo.git'
            clone = directory / 'clone'
            git(directory, 'clone', cell['ssh_remote'], str(clone))
            marker = '# Persistent SSH README\n'
            (clone / 'README.md').write_text(marker)
            git(clone, 'add', 'README.md')
            git(clone, 'commit', '-m', 'SSH fixture commit')
            git(clone, 'push', 'origin', 'main')
            git(clone, 'fetch', 'origin')
            git(directory, 'ls-remote', f'{settings["alias"]}:{cell["id"]}.git')
            assert asklog.is_file() and asklog.read_text().count('prompted') > 0

            print('Checking: restart closes SSH until unlock; committed code survives reopen', flush=True)
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=12) == 0
            assert not listening(ssh_port)
            process = start()
            assert state(data) == 'locked' and not listening(ssh_port)
            cli('cell', 'list')
            wait_for(lambda: listening(ssh_port), 'SSH after restart and unlock')
            reopened = directory / 'reopened'
            git(directory, 'clone', cell['ssh_remote'], str(reopened))
            assert (reopened / 'README.md').read_text() == marker
            assert (clone / 'README.md').read_text() == marker
            print('PASS: real username/passphrase init, preserved SSH config, automatic encrypted-key alias, native SSH Git clone/push/fetch, pinned host key, restart lock and durable reopen.')
        finally:
            for process in processes:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)


if __name__ == '__main__':
    main()
