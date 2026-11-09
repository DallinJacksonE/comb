#!/usr/bin/env python3
"""Build/install via curl+stdin, exercise a real temporary user unit, then uninstall.

Writes only an isolated home/data/build plus one uniquely named user unit/symlink.
Requires a running systemd user manager. Never replaces comb.service or user data.
"""
import functools
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "installed-smoke-test-only-password"


def run(args, env, **kwargs):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=600, **kwargs)
    assert result.returncode == 0, f"Command failed ({Path(args[0]).name}): {result.stderr}"
    return result.stdout


def state(data):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3)
        client.connect(str(data / "service.sock"))
        client.sendall(b'{"action":"status"}\n')
        return json.loads(client.recv(4096))["state"]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/FRAME/install.sh":
            self.send_error(404)
            return
        super().do_GET()

    def do_HEAD(self):
        self.send_error(405)

    def log_message(self, *_args):
        pass


def main():
    for port in (7331, 7332, 7333):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", port))
    real_home = Path.home()
    unit_dir = Path(os.environ.get("XDG_CONFIG_HOME", str(real_home / ".config"))) / "systemd/user"
    service = f"comb-install-smoke-{os.getpid()}.service"
    unit = unit_dir / service
    assert not unit.exists(), "temporary test unit already exists"
    env = os.environ.copy()
    for key in ["COMB_PASSWORD", "COMB_TOKEN", "COMB_INSTALL_ROOT", "COMB_BIN_DIR", "COMB_DATA_DIR", "COMB_SERVICE_DIR", "CARGO_TARGET_DIR"]:
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="comb-installed-", dir=os.environ.get("TMPDIR")) as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir()
        env.update(HOME=str(home), XDG_DATA_HOME=str(home / ".local/share"),
                   XDG_CONFIG_HOME=str(unit_dir.parent.parent), COMB_SERVICE_NAME=service,
                   RUSTUP_HOME=os.environ.get("RUSTUP_HOME", str(real_home / ".rustup")),
                   CARGO_HOME=os.environ.get("CARGO_HOME", str(real_home / ".cargo")))
        data = home / "custom-frame"
        env["COMB_DATA_DIR"] = str(data)
        install = home / ".local/share/comb-install"
        binary = home / ".local/bin/comb"
        sentinel = home / "working-copy-sentinel"
        sentinel.write_text("preserve unrelated working copy\n")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(ROOT)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        installed = False
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/FRAME/install.sh"
            downloaded = run(["curl", "-fsSL", url], env)
            output = run(["bash", "-s", "--", "--source", str(ROOT), "--profile", "dev"], env, input=downloaded)
            assert "locked" in output.lower() and "recovery" in output.lower()
            installed = True
            cli_env = env.copy()
            cli_env.pop("COMB_DATA_DIR")  # A fresh shell must inherit the installed default.
            run(["systemctl", "--user", "is-active", "--quiet", service], env)
            for _ in range(100):
                try:
                    if state(data) == "uninitialized":
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("installed user service did not reach setup-waiting state")
            run([str(binary), "user", "--name", "Alice", "--email", "alice@test"], cli_env | {"COMB_PASSWORD": PASSWORD}, cwd="/")
            assert state(data) == "ready"
            assert json.loads(run([str(binary), "cell", "list"], cli_env, cwd="/")) == []
            assert not (home / ".local/share/comb/node.vault").exists(), "a custom-data install must not create a second identity"
            import urllib.request
            html = urllib.request.urlopen("http://127.0.0.1:7331/", timeout=5).read()
            assert b'id="root"' in html and b'<script' in html, "installed GUI assets were not served"
            recovery = data / "identity.recovery"
            saved_recovery = recovery.read_bytes()
            saved_vault = (data / "node.vault").read_bytes()
            run(["systemctl", "--user", "restart", service], env)
            for _ in range(100):
                try:
                    if state(data) == "locked":
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("restarted installed service did not return locked")
            run([str(binary), "cell", "list"], cli_env | {"COMB_PASSWORD": PASSWORD}, cwd="/")
            run(["bash", str(install / "uninstall.sh"), "--check"], env, cwd="/")
            run(["bash", str(ROOT / "FRAME/uninstall.sh")], env, cwd="/")
            installed = False
            assert not binary.exists() and not unit.exists()
            assert recovery.read_bytes() == saved_recovery
            assert (data / "node.vault").read_bytes() == saved_vault
            assert sentinel.read_text() == "preserve unrelated working copy\n"
            stopped = subprocess.run(["systemctl", "--user", "is-active", "--quiet", service], env=env)
            assert stopped.returncode != 0
            print(json.dumps({"passed": True, "service": service, "unit_path": str(unit), "checks": [
                "real source build and curl/stdin installer in an isolated home",
                "real uniquely named systemd user service starts setup-waiting",
                "installed command and bundled GUI work outside the checkout",
                "custom data directory persists across fresh command environments without a second identity",
                "service restart requires unlock again",
                "installed cleanup receipt validates; source uninstaller removes only owned programs/unit/PATH and preserves identity/recovery/working copy",
            ]}, indent=2))
        finally:
            server.shutdown()
            server.server_close()
            if installed and (install / "uninstall.sh").exists():
                cleanup = subprocess.run(["bash", str(install / "uninstall.sh")], env=env, capture_output=True, text=True, timeout=60)
                assert cleanup.returncode == 0, "smoke cleanup failed: " + cleanup.stderr
            if unit.exists():
                # Partial installer failure: remove only this unique test unit.
                subprocess.run(["systemctl", "--user", "disable", "--now", service], env=env, capture_output=True, timeout=30)
                unit.unlink()
                subprocess.run(["systemctl", "--user", "daemon-reload"], env=env, check=True, timeout=30)


if __name__ == "__main__":
    main()
