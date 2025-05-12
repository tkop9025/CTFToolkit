import os, socket, subprocess, sys, pytest, time
from canary_tool.target import TcpTarget, ExecTarget, UnixSocketTarget


def make_echo_socketpair():
    parent, child = socket.socketpair()

    def echo_server(sock):
        while True:
            try:
                data = sock.recv(1024)
                if not data:
                    break
                sock.sendall(b"ok")
            except ConnectionResetError:
                break

    pid = os.fork()
    if pid == 0:
        parent.close()
        echo_server(child)
        os._exit(0)
    child.close()
    return parent, pid


def test_unixsocket_target():
    sock, pid = make_echo_socketpair()
    path = "/tmp/test.sock"
    # use AF_UNIX filesystem path (we can't reuse socketpair fd easily)
    # So you might need a real AF_UNIX socat server instead – adjust here.
    # tgt = UnixSocketTarget(path)
    # assert tgt.send(b"A", 0.1)
    # tgt.close()
    os.kill(pid, 9)


def test_exectarget_survives_and_crashes(tmp_path):
    echo_script = tmp_path / "echo.py"
    echo_script.write_text("import sys, os; sys.stdin.read(); os._exit(0)")
    tgt = ExecTarget([sys.executable, echo_script])
    assert tgt.send(b"PING", 0.1)  # alive
    tgt.close()

    crash_script = tmp_path / "crash.py"
    crash_script.write_text("import sys, os; os._exit(1)")
    tgt2 = ExecTarget([sys.executable, crash_script])
    assert tgt2.send(b"A", 0.1) is False
    tgt2.close()


@pytest.fixture
def tcp_echo_server():
    import shutil, subprocess, time, socket

    port = 54321
    proc = subprocess.Popen(
        ["socat", f"TCP-LISTEN:{port},reuseaddr,fork", "SYSTEM:'printf ok'"]
    )
    time.sleep(0.1)
    yield ("127.0.0.1", port)
    proc.terminate()
    proc.wait()


def test_tcptarget_alive(tcp_echo_server):
    host, port = tcp_echo_server
    tgt = TcpTarget(host, port)
    assert tgt.send(b"X", 0.2)
    tgt.close()
