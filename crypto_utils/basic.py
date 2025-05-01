import base64
import codecs
import urllib.parse
import json


def decode_base64(data):
    """Decode a Base64 encoded string."""
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"[Base64 Decoding Error] {e}"


def encode_base64(data):
    """Encode a string or bytes to base64."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif isinstance(data, bytes):
        pass
    else:
        raise TypeError("String or bytes required.")

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
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif isinstance(data, bytes):
        pass
    else:
        raise TypeError("String or bytes required.")

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
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    elif isinstance(data, str):
        pass
    else:
        raise TypeError("String or bytes required.")

    return urllib.parse.quote(data)


def decode_rot13(data):
    """Decode a ROT13 encoded string."""
    return codecs.decode(data, "rot_13")


def encode_rot13(data):
    """Encode a string to ROT13."""
    if not isinstance(data, str):
        raise TypeError("String required.")

    return codecs.encode(data, "rot_13")


def decode_binary(data):
    """Convert binary string (e.g., 01001000) to ASCII."""
    try:
        chars = [chr(int(b, 2)) for b in data.split()]
        return "".join(chars)
    except Exception as e:
        return f"[Binary Error] {e}"


def decode_jwt(token):
    """Decode a JWT token (header & payload only)."""
    try:
        header, payload, _ = token.split(".")
        header_decoded = base64.urlsafe_b64decode(header + "==").decode()
        payload_decoded = base64.urlsafe_b64decode(payload + "==").decode()
        return json.dumps(json.loads(payload_decoded), indent=2)
    except Exception as e:
        return f"[JWT Error] {e}"


if __name__ == "__main__":
    print("This is a utility module. Import functions or expand with CLI support.")
