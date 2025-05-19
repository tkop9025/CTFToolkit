import socket
import subprocess
import time
from typing import Sequence
import serial
import ssl


class Target:
    def send(self, data: bytes, timeout: float) -> bool:
        """return true if program survived, false if it crashed"""
        raise NotImplementedError("implement me grrrr")

    def close(self):
        """close connection"""
        raise NotImplementedError("implement me grrrr")


class UnixSocketTarget(Target):
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)

    def send(self, data, timeout):
        self.sock.settimeout(timeout)
        try:
            self.sock.sendall(data)
            self.sock.recv(1)
            # any reply means alive
            return True
        except socket.timeout:
            return False

    def close(self):
        self.sock.close()


class ExecTarget(Target):
    def __init__(self, argv: Sequence[str] | None):
        if not argv:
            raise ValueError("--exec requires at least a program name")
        self._argv = list(argv)
        self._spawn()

    def _spawn(self):
        self.proc = subprocess.Popen(
            self._argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if self.proc.stdin is None:
            raise RuntimeError("stdin PIPE failed")

    def send(self, data: bytes, timeout: float) -> bool:
        # respawn if previous run crashed
        if self.proc.poll() is not None:
            self._spawn()
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
            time.sleep(timeout)
            return self.proc.poll() is None
        except BrokenPipeError:
            return False

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        self.proc.wait(timeout=1)


class TcpTarget(Target):
    def __init__(self, host: str, port: int):
        self.addr = (host, port)
        self.sock = socket.create_connection(self.addr)

    def _reopen(self):
        self.sock.close()
        self.sock = socket.create_connection(self.addr)

    def send(self, data: bytes, timeout: float) -> bool:
        try:
            self.sock.sendall(data)
            self.sock.settimeout(timeout)
            self.sock.recv(1)
            return True
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            try:
                self._reopen()
            except OSError:
                pass
            return False

    def close(self):
        self.sock.close()


class TlsTarget(TcpTarget):
    def __init__(self, host: str, port: int, *, insecure: bool = False):
        super().__init__(host, port)
        ctx = (
            ssl._create_unverified_context()
            if insecure
            else ssl.create_default_context()
        )
        self.sock = ctx.wrap_socket(self.sock, server_hostname=host)

    def send(self, data: bytes, timeout: float) -> bool:
        try:
            self.sock.sendall(data)
            self.sock.settimeout(timeout)
            self.sock.recv(1)
            return True
        except (socket.timeout, ConnectionResetError, BrokenPipeError, ssl.SSLError):
            return False

    def close(self):
        self.sock.close()


class SerialTarget(Target):
    def __init__(self, dev: str, baud: int = 115_200, *, require_echo: bool = False):
        self.ser = serial.Serial(dev, baudrate=baud, timeout=0)
        self.require_echo = require_echo

    def send(self, data: bytes, timeout: float) -> bool:
        try:
            self.ser.write(data)
            self.ser.flush()
            time.sleep(timeout)
            if not self.require_echo:
                return self.ser.is_open
            return self.ser.in_waiting > 0
        except serial.SerialException:
            return False

    def close(self):
        self.ser.close()


class UdpTarget(Target):
    def __init__(self, host, port):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _drain(self):
        self.sock.setblocking(False)
        try:
            while self.sock.recvfrom(4096):
                pass
        except BlockingIOError:
            pass
        finally:
            self.sock.setblocking(True)

    def send(self, data: bytes, timeout: float) -> bool:
        self._drain()
        self.sock.sendto(data, self.addr)
        self.sock.settimeout(timeout)
        try:
            self.sock.recvfrom(1)
            return True
        except socket.timeout:
            return False

    def close(self):
        self.sock.close()


def make_target(args) -> Target:
    if args.unix:
        return UnixSocketTarget(args.unix)
    if args.tcp:
        host, port = args.tcp.split(":")
        return TcpTarget(host, int(port))
    if args.tls:
        host, port = args.tls.split(":")
        return TlsTarget(host, int(port))
    if args.udp:
        host, port = args.udp.split(":")
        return UdpTarget(host, int(port))
    if args.exec:
        return ExecTarget(args.exec)
    if args.serial:
        dev, *baud = args.serial.split(":")
        return SerialTarget(dev, int(baud[0]) if baud else 115200)
    raise ValueError("No transport specified")
