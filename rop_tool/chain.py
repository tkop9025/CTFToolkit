from .store import GadgetStore, Gadget
import struct


def p64(val: int) -> bytes:
    return struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)


class ROPChain:
    def __init__(self, store: GadgetStore, badbytes: bytes = b""):
        self.store = store
        self.bad = badbytes
        self.chain: list[int] = []

    def set_reg(self, reg: str, value: int) -> None:
        """Append the shortest pop-reg gadget + value."""
        g = self._pick_pop(reg)
        self.chain.append(g.addr)
        self.chain.append(value)

    def syscall(self) -> None:
        g = self.store.syscall()[0]
        self.chain.append(g.addr)

    def build(self) -> bytes:
        return b"".join(p64(a) for a in self.chain)

    def _pick_pop(self, reg: str) -> Gadget:
        cands = self.store.pop_reg(reg, max_len=2)
        if not cands:
            raise ValueError(f"no pop {reg} gadget")
        return min(cands, key=lambda g: len(g.asm))
