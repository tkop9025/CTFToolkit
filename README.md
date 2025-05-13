# Personal CTF Toolkit
Stuff I find myself doing a lot in ctfs. I figured, why not automate.

warning: questionable quality

### crypto_utils

A collection of lightweight Python functions to streamline common encoding and
decoding tasks frequently encountered in CTF challenges, penetration testing,
and general cybersecurity work.


#### Features
- Base64 Encoding/Decoding
- Hex Encoding/Decoding
- URL Encoding/Decoding
- ROT13 Encoding/Decoding
- Binary to ASCII Conversion
- JWT (JSON Web Token) Decoding (Header & Payload only)

#### Designed for flexibility:
- Accepts both str and bytes where applicable.
- Handles common errors gracefully.


### web_utils
crappy unfinished requests wrapper :)


### canary-tool (stack‑canary helper)

Lightweight CLI + library that discovers a program’s **stack‑canary offset** and brute-forces
the canary byte-by-byte across multiple transports for smash-me-hard CTF pwnables.

| Highlights | Details |
|------------|---------|
| **Auto‑offset probe** | `--auto_offset` flag (falls back to `--offset N`). |
| **Multi‑transport** | Local `exec`, Unix socket, TCP, UDP, TLS, Serial. |
| **Noise‑resistant** | Confirmation loop, auto‑respawn, reconnect on drop. |
| **Zero heavy deps** | Pure std-lib (+ `pyserial` only if you use serial). |
| **Importable API** | `from canary_tool import brute_force_canary`. |

Example:

```bash
canary-tool --tcp chall.pwn.xyz:31337 --auto_offset --canary-len 8
```


### rop-tool (barely started)
oh boy I'm ropping so hard I'm going to rop all over your binary.
