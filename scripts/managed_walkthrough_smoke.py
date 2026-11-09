#!/usr/bin/env python3
"""Exercise real hidden-password onboarding in a controlling terminal, without user state."""
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/debug/comb"
PASSWORD = "walkthrough-only-password-do-not-use"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def state(data):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(2)
        client.connect(str(data / "service.sock"))
        client.sendall(b'{"action":"status"}\n')
        return json.loads(client.recv(4096))["state"]


def terminal_command(arguments, env, steps):
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.execvpe(str(BINARY), [str(BINARY), *arguments], env)
    transcript = bytearray()
    deadline = time.monotonic() + 120
    step = 0
    consumed = 0
    status = None
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    data = os.read(fd, 8192)
                except OSError:
                    data = b""
                if data:
                    transcript.extend(data)
                    if step < len(steps) and steps[step][0].encode() in transcript[consumed:]:
                        consumed = len(transcript)
                        if any(word in steps[step][0].lower() for word in ('password', 'passphrase')):
                            # The password library prints its prompt before switching
                            # terminal modes. Coordinate machine-speed input with the
                            # actual hidden-input state rather than racing that switch.
                            while termios.tcgetattr(fd)[3] & termios.ECHO:
                                assert time.monotonic() < deadline, "terminal never disabled password echo"
                                time.sleep(0.005)
                        os.write(fd, steps[step][1].encode() + b"\n")
                        step += 1
            finished, result = os.waitpid(pid, os.WNOHANG)
            if finished:
                status = result
                break
        assert status is not None, "interactive walkthrough timed out"
        assert os.waitstatus_to_exitcode(status) == 0, "interactive command failed (transcript intentionally not printed)"
        assert step == len(steps), "not every walkthrough prompt appeared"
        text = transcript.decode(errors="replace")
        secrets = {value for label, value in steps if value and any(word in label.lower() for word in ('password', 'passphrase'))}
        assert all(secret not in text for secret in secrets), "hidden input unexpectedly echoed a fixture secret (transcript withheld)"
        return text
    finally:
        os.close(fd)
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def main():
    assert BINARY.is_file(), "Build comb-frame before running this smoke test"
    env = {key: value for key, value in os.environ.items() if key not in {"COMB_PASSWORD", "COMB_TOKEN"}}
    processes = []
    with tempfile.TemporaryDirectory(prefix="comb-walkthrough-", dir=os.environ.get("TMPDIR")) as directory:
        data = Path(directory) / "frame"
        env['COMB_SSH_CONFIG'] = str(Path(directory) / 'ssh-config')
        management, peer = free_port(), free_port()
        arguments = ["--data", str(data), "--api-url", f"http://127.0.0.1:{management}", "cell", "list"]

        def start():
            process = subprocess.Popen([str(BINARY), "--data", str(data), "serve", "--managed", "--ssh-listen", "127.0.0.1:0", "--listen", f"127.0.0.1:{management}",
                "--peer-listen", f"127.0.0.1:{peer}", "--assets", str(ROOT / "FRAME/webgui/dist")],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            for _ in range(100):
                assert process.poll() is None, "managed service exited"
                try:
                    return process, state(data)
                except (OSError, ValueError):
                    time.sleep(0.05)
            raise AssertionError("managed service did not start")

        try:
            process, initial = start()
            assert initial == "uninitialized"
            text = terminal_command(arguments, env, [
                ("Name: ", "Alice"), ("Email: ", "alice@test"),
                ("Username (SSH login): ", "alice"),
                ("Choose FRAME/recovery-file password: ", PASSWORD), ("Confirm password: ", PASSWORD),
                ("SSH key passphrase (Enter for none): ", ""),
            ])
            for explanation in ["NOT a repository backup", "offline", "verify", "no provider reset", "stolen recovery file"]:
                assert explanation in text, f"missing recovery guidance: {explanation}"
            assert (data / "identity.recovery").is_file()
            assert state(data) == "ready"
            subsequent = subprocess.run([str(BINARY), *arguments], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            assert subsequent.returncode == 0 and json.loads(subsequent.stdout) == []
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=15) == 0
            process, initial = start()
            assert initial == "locked"
            text = terminal_command(arguments, env, [
                ("Unlock FRAME: ", "wrong-fixture-password"),
                ("Unlock FRAME: ", "another-wrong-fixture-password"),
                ("Unlock FRAME: ", PASSWORD),
            ])
            assert text.count("Incorrect password") == 2
            assert "restart" in text and state(data) == "ready"
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=15) == 0
            text = terminal_command(["--data", str(data), "profile"], env, [
                ("Unlock FRAME: ", "wrong-local-fixture-password"),
                ("Unlock FRAME: ", PASSWORD),
            ])
            assert text.count("Incorrect password") == 1 and '"name": "Alice"' in text
            print(json.dumps({"passed": True, "checks": [
                "real controlling-terminal first-command initialization and password confirmation",
                "recovery custody/loss warnings and no echoed password",
                "subsequent command reuses private unlocked session",
                "SIGTERM and restart require an interactive unlock again",
                "incorrect passwords re-prompt until success without echoing secrets",
                "standalone local commands also retry incorrect passwords",
            ]}, indent=2))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    main()
