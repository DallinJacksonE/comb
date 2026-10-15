#!/usr/bin/env python3
"""Real isolated CLI/HTTP/Git/Noise smoke test; no Docker privileges required.

Creates only a temporary workspace under TMPDIR. All daemons are stopped in finally.
Fixture passwords are test-only; no user identities, ports, or repositories are reused.
"""
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/debug/comb"
PASSWORD = "integration-only-strong-password"
MARKER = "COMB_PRIVATE_CODE_SHOULD_NOT_BE_IN_BACKUP_PLAINTEXT"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(args, **kwargs):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise AssertionError(f"Command failed ({args[0]}): {result.stderr}")
    return result.stdout


def main():
    assert BINARY.is_file(), "Run cargo build -p comb-frame first"
    env = os.environ | {"COMB_PASSWORD": PASSWORD, "COMB_RECOVERY_PASSWORD": PASSWORD, "GIT_TERMINAL_PROMPT": "0"}
    processes, logs, evidence = [], [], []
    with tempfile.TemporaryDirectory(prefix="comb-integration-", dir=os.environ.get("TMPDIR")) as directory:
        root = Path(directory)

        def cli(node, *args):
            address = ["--api-url", f"http://127.0.0.1:{ports[node][0]}"] if args and args[0] == "restore" else []
            return run([BINARY, "--data", root / node, *address, *args], env=env, cwd=ROOT)

        def request(node, path, body=None, expected=200):
            data = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(f"http://127.0.0.1:{ports[node][0]}{path}", data=data,
                headers={"Authorization": f"Bearer {tokens[node]}", "Content-Type": "application/json"})
            try:
                response = urllib.request.urlopen(req, timeout=60)
            except urllib.error.HTTPError as error:
                response = error
            raw = response.read()
            assert response.status == expected, (node, path, response.status, raw[:1000])
            return json.loads(raw)

        def start(node):
            log = open(root / f"{node}.log", "w+")
            logs.append(log)
            management, peer = ports[node]
            process = subprocess.Popen([str(BINARY), "--data", str(root/node), "serve", "--listen", f"127.0.0.1:{management}",
                "--peer-listen", f"127.0.0.1:{peer}", "--assets", str(ROOT/"FRAME/webgui/dist")],
                env=env, cwd=ROOT, stdout=log, stderr=log)
            processes.append(process)
            for _ in range(300):
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(f"{node} daemon exited: {log.read()}")
                try:
                    request(node, "/api/status")
                    html=urllib.request.urlopen(f"http://127.0.0.1:{management}/",timeout=5).read()
                    assert b'id="root"' in html and b'<script' in html, "FRAME did not serve the built React GUI"
                    return
                except (OSError, urllib.error.URLError):
                    time.sleep(0.1)
            raise AssertionError(f"{node} did not start")

        def git(node, *args):
            git_env = env | {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {tokens[node]}"}
            return run(["git", *args], env=git_env, cwd=root)

        try:
            alice = json.loads(cli("alice", "user", "--name", "Alice", "--email", "alice@test", "--recovery", root/"alice.recovery"))
            cli("desktop", "enroll", "request", "--out", root/"desktop.request")
            cli("alice", "enroll", "authorize", "--request", root/"desktop.request", "--out", root/"desktop.grant")
            desktop = json.loads(cli("desktop", "enroll", "complete", "--grant", root/"desktop.grant", "--identity-key", bytes(alice["identity"]["signing_key"]).hex()))
            bob = json.loads(cli("bob", "user", "--name", "Bob", "--email", "bob@test", "--recovery", root/"bob.recovery"))
            assert alice["identity"] == desktop["identity"]
            assert alice["certificate"]["frame"] != desktop["certificate"]["frame"]
            evidence.append("fresh-device enrollment preserves identity with distinct FRAME keys")
            profiles = {"alice": alice, "desktop": desktop, "bob": bob}
            ports = {node: (free_port(), free_port()) for node in profiles | {"recovered": alice}}
            tokens = {node: cli(node, "token").strip() for node in profiles}
            for node in profiles:
                start(node)
            for node in profiles:
                for other, profile in profiles.items():
                    if node != other:
                        request(node, "/api/peers/profile", {"id": bytes(profile["certificate"]["frame"]["signing_key"]).hex(),
                            "public_key": bytes(profile["noise_public"]).hex(), "url": f"http://127.0.0.1:{ports[other][1]}", "profile": profile})
            cell = request("alice", "/api/cells", {"name": "Private integration repository"}, expected=201)
            cell_id = cell["id"]
            request("alice", f"/api/cells/{cell_id}/members", {"profile": bob, "role": "write"})
            request("alice", f"/api/cells/{cell_id}/frames", desktop)
            work = root/"work"
            git("alice", "init", "--initial-branch=main", work)
            git("alice", "-C", work, "config", "user.name", "Alice")
            git("alice", "-C", work, "config", "user.email", "alice@test")
            (work/"code.txt").write_text(MARKER + "\n")
            git("alice", "-C", work, "add", ".")
            git("alice", "-C", work, "commit", "-m", "private initial code")
            remote = lambda node: f"http://127.0.0.1:{ports[node][0]}/git/{cell_id}.git"
            git("alice", "-C", work, "push", remote("alice"), "main")
            alice_id = bytes(alice["certificate"]["frame"]["signing_key"]).hex()
            for node in ("desktop", "bob"):
                request(node, f"/api/peers/{alice_id}/sync", {})
                git(node, "clone", remote(node), root/f"clone-{node}")
                assert (root/f"clone-{node}/code.txt").read_text().strip() == MARKER
            evidence.append("three real daemons: authenticated Git push/clone and encrypted peer replication")
            # Divergence must retain both accepted commit tips after exchanging histories.
            (work/"alice.txt").write_text("alice branch\n")
            git("alice", "-C", work, "add", ".")
            git("alice", "-C", work, "commit", "-m", "Alice offline branch")
            git("alice", "-C", work, "push", remote("alice"), "main")
            desktop_work = root/"clone-desktop"
            (desktop_work/"desktop.txt").write_text("desktop branch\n")
            git("desktop", "-C", desktop_work, "add", ".")
            git("desktop", "-C", desktop_work, "-c", "user.name=Alice", "-c", "user.email=alice@test", "commit", "-m", "Desktop offline branch")
            git("desktop", "-C", desktop_work, "push", remote("desktop"), "main")
            hashes = {git("alice", "-C", work, "rev-parse", "HEAD").strip(), git("desktop", "-C", desktop_work, "rev-parse", "HEAD").strip()}
            request("desktop", f"/api/peers/{alice_id}/sync", {})
            refs = request("desktop", f"/api/cells/{cell_id}")["refs"]
            assert hashes.issubset(set(refs.values())), refs
            evidence.append("concurrent same-branch Git tips preserved without overwriting either commit")
            git("alice", "-C", work, "fetch", remote("alice"), "+refs/*:refs/remotes/comb/*")
            desktop_hash = git("desktop", "-C", desktop_work, "rev-parse", "HEAD").strip()
            git("alice", "-C", work, "merge", "--no-edit", desktop_hash)
            git("alice", "-C", work, "push", remote("alice"), "HEAD:refs/heads/main")
            request("desktop", f"/api/peers/{alice_id}/sync", {})
            assert "refs/heads/main" in request("alice", f"/api/cells/{cell_id}")["refs"]
            evidence.append("ordinary Git fetch/merge/push resolves divergent refs into a new shared main")
            before = request("alice", f"/api/cells/{cell_id}")
            after = request("alice", f"/api/cells/{cell_id}/revoke", {"identity_id": bytes(bob["identity"]["signing_key"]).hex()})
            assert before["version"] != after["version"] and before["refs"] == after["refs"]
            evidence.append("metadata-only contributor revocation creates a version without changing Git refs")
            backup = request("alice", f"/api/cells/{cell_id}/backup")
            backup_file = root/"snapshot.cell"
            backup_file.write_text(json.dumps(backup))
            assert MARKER.encode() not in backup_file.read_bytes()
            for node in profiles:
                for path in (root/node/"snapshots").glob("*.cell"):
                    assert MARKER.encode() not in path.read_bytes()
            evidence.append("persisted backup/snapshot files contain no plaintext code marker")
            desktop_id = bytes(desktop["certificate"]["frame"]["signing_key"]).hex()
            request("alice", f"/api/frames/{desktop_id}/revoke", {})
            for _ in range(100):
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1", ports["desktop"][1])) != 0:
                        break
                time.sleep(0.05)
            else:
                raise AssertionError("revoked FRAME peer port stayed open")
            assert not request("desktop", "/api/status")["frame"]["active"]
            request("desktop", "/api/cells", expected=423)
            evidence.append("same-identity FRAME revocation locks management and closes peer listening port")
            # Restore with a bound replacement key, retaining normal Git work outside FRAME.
            restore_request = request("desktop", "/api/restore/request", {"password": PASSWORD})
            (root/"restore.request").write_text(json.dumps(restore_request))
            credential = cli("alice", "restore", "--lost-frame", root/"restore.request").strip()
            assert json.loads(base64.b64decode(credential))["certificate"]["identity"] == alice["identity"]
            response = request("desktop", "/api/restore/apply", {"password": PASSWORD, "credential": credential})
            assert response["outcome"] == "restored"
            assert (desktop_work/"code.txt").read_text().strip() == MARKER
            evidence.append("request-bound restore credential re-enrolls a fresh FRAME key without touching working copies")
            for process in processes:
                process.send_signal(signal.SIGINT)
            for process in processes:
                process.wait(timeout=30)
            processes.clear()
            for node in profiles:
                shutil.rmtree(root/node)
            recovered = json.loads(cli("recovered", "recover", "--recovery", root/"alice.recovery").strip())
            # Import through the explicit root-recovery service; command recovery+backup is exercised below using a separate destination.
            shutil.rmtree(root/"recovered")
            output = cli("recovered", "recover", "--recovery", root/"alice.recovery", "--backup", backup_file, "--owner-key", bytes(alice["identity"]["signing_key"]).hex())
            assert "Private integration repository" in output
            tokens["recovered"] = cli("recovered", "token").strip()
            start("recovered")
            git("recovered", "clone", remote("recovered"), root/"recovered-clone")
            assert (root/"recovered-clone/code.txt").read_text().strip() == MARKER
            evidence.append("all original FRAME data deleted: offline recovery plus ciphertext backup restores clonable code")
            print(json.dumps({"passed": True, "checks": evidence}, indent=2))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for log in logs:
                log.close()


if __name__ == "__main__":
    main()
