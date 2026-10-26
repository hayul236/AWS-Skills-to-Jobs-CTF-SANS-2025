# Base64-decode an intercepted string, then XOR against candidate keys.
#
# Used in the forensics challenge: a value carved from a TCP stream was
# base64 + repeating-key XOR, the key being a theme word/phrase. Pass the
# candidate string and one or more keys to guess; printable output wins.
#
# Usage: python xor_decode_message.py <base64_string> key1 key2 ...
import base64
import sys


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: python xor_decode_message.py <base64_string> key1 [key2 ...]")
        sys.exit(1)

    blob = base64.b64decode(sys.argv[1])
    for k in sys.argv[2:]:
        out = xor_bytes(blob, k.encode())
        printable = all(32 <= b <= 126 for b in out)
        print(f"key={k!r} printable={printable} -> {out}")
