# tests/test_offset_canary.py
# ---------------------------------------------------------------
# Unit‑level mocks and assertions for the offset‑finder and
# canary brute‑force loops.  They use *no* real sockets or
# subprocesses—so they run in < 50 ms.

import pytest
from hypothesis import given, strategies as st

from canary_tool.discover import find_offset_binary
from canary_tool.canary import brute_force_canary


# ── Mock helpers ────────────────────────────────────────────────
class DummyTarget:
    """
    Pretends to be a service that crashes when it receives
    >= crash_at bytes.  Used to test offset‑finding only.
    """

    def __init__(self, crash_at: int):
        self._crash_at = crash_at

    def send(self, data: bytes, timeout: float) -> bool:
        return len(data) < self._crash_at  # survives if shorter

    def close(self):  # API compatibility
        pass


class CanaryTarget(DummyTarget):
    """
    Extends DummyTarget so that it also enforces a *specific*
    stack canary.  The service survives only when the payload
    length is below the canary AND every byte guessed so far
    matches the true canary prefix.
    """

    def __init__(self, offset: int, canary: bytes):
        super().__init__(crash_at=offset + len(canary) + 1)
        self._offset = offset
        self._canary = canary

    def send(self, data: bytes, timeout: float) -> bool:
        if len(data) < self._offset:  # haven’t reached canary yet
            return True
        guess = data[self._offset :]  # bytes attempting to overwrite
        return self._canary.startswith(guess)  # OK if prefix match


# ── Offset‑finder unit test ─────────────────────────────────────
@pytest.mark.parametrize("crash_at", [2, 17, 257, 4096])
def test_find_offset_binary(crash_at):
    tgt = DummyTarget(crash_at)
    good, bad = find_offset_binary(tgt, max_probe=crash_at + 8)
    # Contract: last safe byte‑index == crash_at‑1
    assert good == crash_at - 1
    assert bad == crash_at


# ── Canary brute‑force deterministic test ───────────────────────
def test_bruteforce_exact_canary():
    offset = 64
    canary = b"\x00\xbe\xef\xca\xfe\x12\x34\x56"
    tgt = CanaryTarget(offset, canary)

    found = brute_force_canary(
        tgt,
        offset=offset,
        length=len(canary),
        pad=b"A",
        prefix=b"",
        timeout=0.01,
    )
    assert found == canary


# ── Property‑based fuzz: random offsets & canaries ─────────────
@given(
    offset=st.integers(min_value=0, max_value=512),
    length=st.sampled_from([4, 8]),
    canary=st.binary(min_size=8).map(lambda b: b[:8]),  # cap length
)
def test_bruteforce_random(offset, length, canary):
    canary = canary[:length]
    tgt = CanaryTarget(offset, canary)

    found = brute_force_canary(
        tgt,
        offset=offset,
        length=length,
        pad=b"A",
        prefix=b"",
        timeout=0.01,
    )
    assert found == canary
