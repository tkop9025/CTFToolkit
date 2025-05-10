"""
canary_tool
===========

Utility functions for discovering stack‑canary offsets and brute‑forcing
canary values over Unix sockets, TCP, serial, or local processes.
"""

from __future__ import annotations

# ── Version ────────────────────────────────────────────────────────────
__version__: str = "0.1.0"

# ── Public re‑exports ──────────────────────────────────────────────────
from .target import make_target, Target
from .discover import find_offset_binary
from .canary import brute_force_canary

__all__: list[str] = [
    "make_target",
    "Target",
    "find_offset_binary",
    "brute_force_canary",
    "__version__",
]

del annotations
