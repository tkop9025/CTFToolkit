from rop_tool.gadgets import Gadget
from rop_tool.store import GadgetStore


G = [
    Gadget(0x400100, ("pop rdi", "ret"), bytes.fromhex("5f c3")),
    Gadget(0x400102, ("pop rsi", "ret"), bytes.fromhex("5e c3")),
    Gadget(0x400104, ("pop rdx", "ret"), bytes.fromhex("5a c3")),
    Gadget(0x400106, ("syscall",), bytes.fromhex("0f 05")),
    Gadget(0x400200, ("pop rdi", "pop rsi", "ret"), bytes.fromhex("5f 5e c3")),
]

STORE = GadgetStore(G)


def test_pop_reg_rdi():
    pops = STORE.pop_reg("rdi")
    assert pops and pops[0].addr == 0x400100


def test_syscall_query():
    scalls = STORE.syscall()
    assert len(scalls) == 1 and scalls[0].asm[0] == "syscall"


def test_len_filter():
    short = STORE.filter(max_len=2)
    assert all(len(g.asm) <= 2 for g in short)
    assert 0x400200 not in {g.addr for g in short}  # 3-instr gadget excluded


def test_badbyte_filter():
    bad = bytes.fromhex("5f")
    clean = STORE.filter(badbytes=bad)
    assert all((g.bytestr is None or 0x5F not in g.bytestr) for g in clean)
    assert 0x400100 not in {g.addr for g in clean}  # filtered out


def test_include_substr():
    rsi_only = STORE.filter(pattern="pop rsi")
    addrs = {g.addr for g in rsi_only}
    assert addrs == {0x400102, 0x400200}  # both single & multi-pop gadgets
