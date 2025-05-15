from collections import defaultdict
from .gadgets import Gadget


class GadgetStore:
    def __init__(self, gadgets: list[Gadget]):
        self._all = gadgets
        self._by_reg: dict[str, list[Gadget]] = defaultdict(list)
        self._by_len: dict[int, list[Gadget]] = defaultdict(list)

        for g in gadgets:
            self._by_len[len(g.asm)].append(g)
            for r in g.regs_written:
                self._by_reg[r].append(g)

    def pop_reg(self, reg: str, *, max_len: int | None = 2) -> list[Gadget]:
        return [
            g
            for g in self._by_reg.get(reg, [])
            if g.asm[0].startswith("pop") and (max_len is None or len(g.asm) <= max_len)
        ]

    def syscall(self) -> list[Gadget]:
        return [g for g in self._all if "syscall" in g.asm[0]]

    def filter(
        self,
        *,
        pattern: str | None = None,
        max_len: int | None = None,
        badbytes: bytes = b"",
    ) -> list[Gadget]:
        out = self._all
        if pattern:
            out = [g for g in out if pattern in " ; ".join(g.asm)]
        if max_len:
            out = [g for g in out if len(g.asm) <= max_len]
        if badbytes:
            out = [
                g
                for g in out
                if g.bytestr is None or not any(b in badbytes for b in g.bytestr)
            ]
        return out
