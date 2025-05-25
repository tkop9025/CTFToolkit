import base64
import re
import codecs
import urllib.parse
import json
import binascii
import hashlib
import hmac
import string
from typing import ByteString


def caesar_shift(text: str, shift: int) -> str:
    """
    Shift letters by `shift` positions (positive = right).
    Retains case; non-alphabetic characters untouched.

    >>> caesar_shift("Attack at dawn!", 13)
    'Nggnpx ng qnja!'
    """
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    trans = str.maketrans(
        upper + lower,
        upper[shift % 26 :]
        + upper[: shift % 26]
        + lower[shift % 26 :]
        + lower[: shift % 26],
    )
    return text.translate(trans)


def _to_bytes(d):
    if isinstance(d, bytes):
        return d
    if isinstance(d, str):
        return d.encode()
    raise TypeError("str or bytes expected")


def xor_bytes(data: ByteString, key: ByteString) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes-like")

    key_b = bytes(key)
    return bytes(b ^ key_b[i % len(key_b)] for i, b in enumerate(data))


def score_english(buf: bytes) -> float:
    """Chi-square score against English letter frequency (lower is better)."""
    freq = {
        b"e": 12.70,
        b"t": 9.06,
        b"a": 8.17,
        b"o": 7.51,
        b"i": 6.97,
        b"n": 6.75,
        b"s": 6.33,
        b"h": 6.09,
        b"r": 5.99,
        b"d": 4.25,
    }
    total = len(buf) or 1
    chisq = 0.0
    for byte, expected in freq.items():
        observed = buf.lower().count(byte) * 100 / total
        chisq += (observed - expected) ** 2 / expected
    return chisq


def break_repeating_xor(
    cipher: bytes, keylen: int, alphabet=string.printable.encode()
) -> tuple[bytes, bytes]:
    """
    Recover `keylen`-byte XOR key by independent single-byte analysis.
    Returns (plaintext, key).
    """
    key = bytearray()
    for col in range(keylen):
        column_bytes = cipher[col::keylen]
        best_key_byte = min(
            range(256), key=lambda k: score_english(bytes(b ^ k for b in column_bytes))
        )
        key.append(best_key_byte)
    plain = xor_bytes(cipher, key)
    return plain, bytes(key)


def decode_base64(data):
    """Decode a Base64 encoded string."""
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[Base64 Decoding Error] {e}"


def encode_base64(data):
    """Encode a string or bytes to base64."""
    data = _to_bytes(data)
    try:
        return base64.b64encode(data).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[Base64 Encoding Error] {e}"


def decode_hex(data):
    """Decode a hex-encoded string."""
    try:
        return bytes.fromhex(data).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[Hex Decoding Error] {e}"


def encode_hex(data):
    """Encode a string or bytes to hex."""
    data = _to_bytes(data)
    try:
        return data.hex()
    except Exception as e:
        return f"[Hex Encoding Error] {e}"


def decode_url(data):
    """Decode a URL-encoded string."""
    return urllib.parse.unquote(data)


def encode_url(data):
    """Encode a string to URL-format.
    Does not check for double encoding
    """
    data = _to_bytes(data)

    return urllib.parse.quote(data)


def decode_rot13(data):
    """Decode a ROT13 encoded string."""
    return codecs.decode(data, "rot_13")


def encode_rot13(data):
    """Encode a string to ROT13."""
    if not isinstance(data, str):
        raise TypeError("String required.")

    return codecs.encode(data, "rot_13")


def decode_base85(data):
    """Decode a Base 85 encoded string."""
    data = _to_bytes(data)
    return base64.b85decode(data)


def encode_base85(data):
    """Encode a string to Base85."""
    data = _to_bytes(data)
    return base64.b85encode(data)


def decode_binary(data):
    """Convert binary string (e.g., 01001000) to ASCII."""
    try:
        chars = [chr(int(b, 2)) for b in data.split()]
        return "".join(chars)
    except Exception as e:
        return f"[Binary Error] {e}"


def _b64url_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_jwt(token: str) -> str:
    try:
        header, payload, _sig = token.split(".")
        hdr_json = base64.urlsafe_b64decode(_b64url_pad(header))
        pl_json = base64.urlsafe_b64decode(_b64url_pad(payload))

        hdr = json.loads(hdr_json)
        pl = json.loads(pl_json)
        return json.dumps({"header": hdr, "payload": pl}, indent=2)

    except (ValueError, json.JSONDecodeError, binascii.Error) as e:
        return f"[JWT Error] {e}"


def identify(data):
    """Return likely encoding matches."""
    tests = {
        "base64": lambda d: re.fullmatch(r"[A-Za-z0-9+/=]+", d),
        "hex": lambda d: re.fullmatch(r"[0-9A-Fa-f]+", d),
        "b32": lambda d: re.fullmatch(r"[A-Z2-7]+=*", d),
    }
    return [k for k, f in tests.items() if f(data)]


def sha256(data: bytes | str) -> str:
    """Hex-encoded SHA-256 digest."""
    data = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(data).hexdigest()


def hmac_sha1(key: bytes | str, msg: bytes | str) -> str:
    """Hex-encoded HMAC-SHA1."""
    if isinstance(key, str):
        key = key.encode()
    if isinstance(msg, str):
        msg = msg.encode()
    return hmac.new(key, msg, hashlib.sha1).hexdigest()


if __name__ == "__main__":
    print("This is a utility module. Import functions or expand with CLI support.")
