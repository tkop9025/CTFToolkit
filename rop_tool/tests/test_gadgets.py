from pathlib import Path
from rop_tool.gadgets import load_ropgadget

FIXTURE = Path(__file__).parent / "data" / "ropg_sample.txt"
BADBYTES_FIXTURE = Path(__file__).parent / "data" / "ropg_badbytes.txt"


def test_load_basic():
    g = load_ropgadget(FIXTURE)
    assert len(g) == 3
    assert g[0].addr == 0x4006B3
    assert g[0].asm == ("pop rsi", "ret")
    assert g[0].regs_written == {"rsi"}


def test_badbyte_filter():
    g = load_ropgadget(BADBYTES_FIXTURE, badbytes=bytes.fromhex("0a"))
    assert len(g) == 2  # pop rdi gadget filtered out


def test_include_filter():
    g = load_ropgadget(BADBYTES_FIXTURE, include="syscall")
    assert len(g) == 1 and "syscall" in g[0].asm[0]


def test_len_filter():
    g = load_ropgadget(BADBYTES_FIXTURE, max_len=2)
    assert all(len(x.asm) <= 2 for x in g)
