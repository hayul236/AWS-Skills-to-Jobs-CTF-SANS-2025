# Reinterpret a dump of signed ints (-128..127) as unsigned bytes.
#
# Some challenges dump binary as signed integers by mistake. Convert with
# (n + 256) % 256, write the raw bytes, and print the ASCII so a hidden string
# becomes readable.
#
# Usage: python signed_bytes_to_binary.py dump.txt output.bin
import sys

src = sys.argv[1] if len(sys.argv) > 1 else "dump.txt"
out = sys.argv[2] if len(sys.argv) > 2 else "output.bin"

with open(src) as f:
    nums = f.read().split()

decoded = bytes((int(x) + 256) % 256 for x in nums)

with open(out, "wb") as f:
    f.write(decoded)

print(decoded.decode(errors="ignore"))
