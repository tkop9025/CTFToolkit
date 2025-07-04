"""
canary_tool
===========

Utility functions for discovering stack canary offsets and brute-forcing
canary values over Unix sockets, TCP, serial, or local processes.
"""

from __future__ import annotations  # Pyright more like pyain in my ass

__version__: str = "0.1.0"

from .target import make_target, Target
from .discover import find_offset_binary, find_offset_linear
from .canary import brute_force_canary

__all__: list[str] = [
    "make_target",
    "Target",
    "find_offset_linear",
    "find_offset_binary",
    "brute_force_canary",
    "__version__",
]

del annotations
