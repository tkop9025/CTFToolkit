# tests/test_cli.py
import subprocess, re, sys, textwrap, pytest
from pathlib import Path

CLI = [sys.executable, "-m", "canary_tool.cli"]


@pytest.fixture(scope="module")
def vuln_prog(tmp_path_factory: pytest.TempPathFactory) -> Path:
    src = textwrap.dedent(
        r"""
        #include <unistd.h>
        #include <stdio.h>

        int main() {
            char buf[16];
            read(0, buf, 256);
            puts("OK");
            return 0;
        }
        """
    )
    build_dir = tmp_path_factory.mktemp("build")
    c = build_dir / "vuln.c"
    exe = build_dir / "vuln"
    c.write_text(src)
    assert (
        subprocess.run(
            ["cc", "-fstack-protector-all", "-o", exe, c],
            capture_output=True,
        ).returncode
        == 0
    )
    return exe


def test_cli_auto_offset(vuln_prog: Path):
    result = subprocess.run(
        CLI
        + [
            "--auto-offset",
            "--canary-len",
            "8",
            "--exec",
            str(vuln_prog),
        ],
        capture_output=True,
        text=True,
        timeout=200,
    )
    assert result.returncode == 0
    assert re.search(r"0x[0-9a-f]{16}", result.stdout)


def test_cli_known_offset(vuln_prog: Path):
    result = subprocess.run(
        CLI
        + [
            "--offset",
            "16",
            "--canary-len",
            "8",
            "--exec",
            str(vuln_prog),
        ],
        capture_output=True,
        text=True,
        timeout=200,
    )
    assert result.returncode == 0
    assert "Canary" in result.stdout
