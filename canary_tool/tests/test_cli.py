import sys, subprocess, re, pytest, textwrap, os

CLI = [sys.executable, "-m", "canary_tool.cli"]


# Fixture: tiny vulnerable program compiled on‑the‑fly
@pytest.fixture(scope="module")
def vuln_prog(tmp_path_factory):
    src = textwrap.dedent(
        """
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
    tmp = tmp_path_factory.mktemp("build")
    c = tmp / "vuln.c"
    exe = tmp / "vuln"
    c.write_text(src)
    assert subprocess.run(["cc", "-fstack-protector-all", "-o", exe, c]).returncode == 0
    return exe


def test_cli_auto_offset(vuln_prog):
    result = subprocess.run(
        CLI
        + [
            "--exec",
            vuln_prog,
            "--auto-offset",
            "--canary-len",
            "8",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert re.search(r"0x[0-9a-f]{16}", result.stdout)


def test_cli_known_offset(vuln_prog):
    # we know buffer is 16, so last safe is 16,
    # fake brute‑forcer still prints *something*
    result = subprocess.run(
        CLI
        + [
            "--exec",
            vuln_prog,
            "--offset",
            "16",
            "--canary-len",
            "8",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "Canary" in result.stdout
