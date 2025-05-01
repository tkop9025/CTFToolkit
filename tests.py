import crypto_utils
import web_utils as wu


# Base64
encoded = crypto_utils.encode_base64("Hello, World!")
decoded = crypto_utils.decode_base64(encoded)

print("Base 64")
print(encoded)
print(decoded + "\n")

# Hex
hexed = crypto_utils.encode_hex("flag{secret}")
unhexed = crypto_utils.decode_hex(hexed)

print("Hex")
print(hexed)
print(unhexed + "\n")

# URL Encoding
url_safe = crypto_utils.encode_url("https://example.com/flag?ctf=win")
decoded_url = crypto_utils.decode_url(url_safe)

print("Url Encoding")
print(url_safe)
print(decoded_url + "\n")

# ROT13
cipher = crypto_utils.encode_rot13("attackatdawn")
plain = crypto_utils.decode_rot13(cipher)

print("ROT 13")
print(cipher)
print(plain + "\n")

# Binary to ASCII
binary = "01001000 01101001"
ascii_text = crypto_utils.decode_binary(binary)

print("Binary to ASCII")
print(binary)
print(ascii_text + "\n")


# JWT Decoding
jwt_data = crypto_utils.decode_jwt(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY3RmX2h1bnRlciJ9.signature"
)

print("JWT Decoding")
print("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY3RmX2h1bnRlciJ9.signature")
print(jwt_data + "\n")
