# Personal CTF Toolkit
Stuff I find myself doing a lot in ctfs. I figured, why not automate.

warning: increadibly noobish code

### crypto_utils.py

A collection of lightweight Python functions to streamline common encoding and
decoding tasks frequently encountered in CTF challenges, penetration testing,
and general cybersecurity work.

This module helps automate repetitive crypto and encoding tasks, saving time
during competitions or security assessments.


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
- Minimal dependencies — pure Python standard library.
