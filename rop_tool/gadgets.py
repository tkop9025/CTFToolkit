"""
gadgets.py  – Minimal parser for ROPgadget text output.
Only handles lines like:
    0x00000000004006b3 : pop rdi ; ret
"""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re
from typing import List, Tuple


@dataclass(frozen=True, slots=True)
class Gadget:
    addr: int
    asm: Tuple[str, ...]
    bytestr: bytes | None = None

    @property
    def regs_written(self) -> set[str]:
        """Registers overwritten by first instruction (best-effort)."""
        toks = self.asm[0].split()
        return {toks[1]} if toks[:1] == ["pop"] and len(toks) > 1 else set()


# YUCK
_LINE = re.compile(
    r"0x([0-9a-f]+)\s*:\s*([^|]+?)(?:\|\s*\d+\s+bytes\s+\|\s*(.+))?$",
    re.I,
)


def load_ropgadget(
    path: Path | str,
    badbytes: bytes = b"",
    include: str | None = None,
    max_len: int | None = None,
) -> List[Gadget]:
    """Parse ROPgadget --binary output file ➜ list[ Gadget ]."""
    out: list[Gadget] = []
    for raw in Path(path).read_text().splitlines():
        match = _LINE.match(raw.strip())
        if not match:
            continue

        raw_bytes: bytes | None = None
        addr = int(match.group(1), 16)
        asm = tuple(seg.strip() for seg in match.group(2).split(";"))

        if match.group(3):
            hex_parts = match.group(3).split()
            raw_bytes = bytes(int(p, 16) for p in hex_parts)

        if badbytes and raw_bytes and any(b in badbytes for b in raw_bytes):
            continue

        if include and include not in asm[0]:
            continue

        if max_len and len(asm) > max_len:
            continue

        out.append(Gadget(addr, asm, raw_bytes))
    # drop dup addresses
    seen: set[int] = set()
    uniq: list[Gadget] = []
    for g in out:
        if g.addr not in seen:
            uniq.append(g)
            seen.add(g.addr)
    return uniq
