def find_offset_linear(tgt, max_len=512, pad=b"A", timeout=0.2):
    for n in range(1, max_len + 1):
        if not tgt.send(pad * n, timeout):
            return n - 1
    raise RuntimeError("No crash up to max_len")


def find_offset_binary(tgt, max_probe=4096, pad=b"A", timeout=0.2):
    """
    Returns (last_safe_len, first_crash_len)  with  last_safe + 1 == first_crash
    Raises RuntimeError if we fail to find a crashing length.
    """
    # 1.   find ANY crashing length with exponential back-off
    good = 0
    bad = 1
    while tgt.send(pad * bad, timeout):
        good = bad
        bad *= 2
        if bad > max_probe:
            bad = max_probe
            if tgt.send(pad * bad, timeout):
                raise RuntimeError("No crash seen up to max_probe")

    # 2.   binary search between (good, bad)
    max_iter = 32
    for _ in range(max_iter):
        if bad - good == 1:
            break
        mid = (good + bad) // 2
        if tgt.send(pad * mid, timeout):
            good = mid
        else:
            bad = mid
    else:
        raise RuntimeError("Search did not converge")

    return good, bad
