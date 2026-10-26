# Break repeating-key XOR (Vigenere on bytes).
#
# Input file holds the ciphertext as whitespace-separated signed ints
# (reinterpreted as unsigned bytes). Guesses key size via normalized Hamming
# distance, then solves each transposed column by English-frequency scoring.
import sys


def read_signed_file(path):
    with open(path, "r") as f:
        nums = list(map(int, f.read().split()))
    return bytes((n + 256) % 256 for n in nums)


def hamming(b1, b2):
    return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))


def keysize_score(keysize, data, blocks=8):
    pairs = []
    for i in range(blocks):
        a = data[i * keysize:(i + 1) * keysize]
        b = data[(i + 1) * keysize:(i + 2) * keysize]
        if len(a) < keysize or len(b) < keysize:
            break
        pairs.append(hamming(a, b) / keysize)
    return sum(pairs) / len(pairs) if pairs else float("inf")


ENGLISH = {
    "a": .08167, "b": .01492, "c": .02782, "d": .04253, "e": .12702, "f": .02228,
    "g": .02015, "h": .06094, "i": .06966, "j": .00153, "k": .00772, "l": .04025,
    "m": .02406, "n": .06749, "o": .07507, "p": .01929, "q": .00095, "r": .05987,
    "s": .06327, "t": .09056, "u": .02758, "v": .00978, "w": .02360, "x": .00150,
    "y": .01974, "z": .00074, " ": .13000,
}


def english_score(bs):
    s = sum(ENGLISH.get(chr(b).lower(), 0) for b in bs)
    nonprint = sum(1 for b in bs if b < 9 or (13 < b < 32) or b == 127)
    return s - nonprint * 0.5


def break_with_keysize(data, keysize):
    key = bytearray()
    for col in (data[i::keysize] for i in range(keysize)):
        best_k, best = 0, float("-inf")
        for k in range(256):
            sc = english_score(bytes(b ^ k for b in col))
            if sc > best:
                best, best_k = sc, k
        key.append(best_k)
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return bytes(key), plain


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "flag2.txt"
    data = read_signed_file(path)
    candidates = sorted((keysize_score(k, data), k) for k in range(2, 41))
    for nh, keysize in candidates[:12]:
        key, plain = break_with_keysize(data, keysize)
        ratio = sum(32 <= b < 127 for b in plain) / max(1, len(plain))
        preview = "".join(chr(b) if 32 <= b < 127 else "." for b in plain[:200])
        print(f"keysize {keysize} nh={nh:.4f} printable={ratio:.3f}")
        print("  key:", key.hex())
        print("  preview:", preview)
