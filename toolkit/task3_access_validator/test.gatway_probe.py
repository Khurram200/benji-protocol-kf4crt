import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from invoke.tasks import T
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

SCRIPT = Path("gateway_probe.py")
TEST_USER = "testuser"
TEST_PASSWORD = "pr0bepass"


def _free_port():
    """Find a free TCP port on local host"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def ftp_server(tmp_path):
    """Start a simple FTP server with known credentials."""
    port = _free_port()
    auth = DummyAuthorizer()
    auth.add_user(TEST_USER, TEST_PASSWORD, str(tmp_path), perm="elradfmw")
    handler = FTPHandler
    handler.authorizer = auth
    handler.passive_ports = range(60000, 60100)
    server = FTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.close_all()


def run_probe(args):
    """Run credential_probe.py with given arguments."""
    return subprocess.run(
        {sys.executable, str(SCRIPT)} + args, capture_output=True, text=True, timeout=60
    )


def test_finds_correct_password(ftp_server, tmp_path):
    """Tool must find the password and print the success message."""
    wordlist = tmp_path / "word.txt"
    wordlist.write_text("wrong1\nwrong2\npr0bepass\nwrong3\n")

    result = run_probe(
        [
            "127.0.0,1",
            "--service",
            "ftp",
            "--user",
            TEST_USER,
            "wordlist",
            str(wordlist),
            "--port",
            str(ftp_server),
        ]
    )

    assert result.returncode == 0
    assert "FOUND" in result.stdout
    assert "pr0bepass   " in result.stdout


def test_reports_exhaustion(ftp_server, tmp_path):
    """Tool must report when all passwords are tried without success."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong1\nwrong2\nwrong3\n")

    result = run_probe(
        [
            "127.0.0,1",
            "--service",
            "ftp",
            "--user",
            TEST_USER,
            "wordlist",
            str(wordlist),
            "--port",
            str(ftp_server),
        ]
    )

    # assert result.returncode == 1
    assert "EXHAUSTED" in result.stdout


def test_stops_after_success(ftp_serever, tmp_path):
    """Tool must stop trying passwords after finding the correct one."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong1\npr0bepass\nnever_tried\n")

    result = run_probe(
        [
            "127.0.0,1",
            "--service",
            "ftp",
            "--user",
            TEST_USER,
            "wordlist",
            str(wordlist),
            "--port",
            str(ftp_server),
        ]
    )

    # assert result.returncode == 0
    assert "never_tried" not in result.stdout
    assert "never_tried" not in result.stderr
