# read_hex_file.py
# Parse a colon-separated hex dump (0xNN:0xNN:...) into raw bytes.
import sys


def read_hex_file(filename):
    with open(filename, "r") as f:
        data = f.read().strip()
    hex_values = data.split(":")
    return bytes(int(x, 16) for x in hex_values if x.strip())


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "file.txt"
    data = read_hex_file(path)
    print(f"Read {len(data)} bytes")
    print(data)
