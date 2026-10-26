# XOR two 1-bit QR images into the real, scannable QR.
#
# Neither half scans alone; XOR-ing them pixel-wise reconstructs the code.
# Usage: python qr_xor.py part1.png part2.png combined_qr.png
import sys
import numpy as np
from PIL import Image

a = sys.argv[1] if len(sys.argv) > 1 else "binary_qr_code1.png"
b = sys.argv[2] if len(sys.argv) > 2 else "binary_qr_code.png"
out = sys.argv[3] if len(sys.argv) > 3 else "combined_qr.png"

img1 = Image.open(a).convert("1")
img2 = Image.open(b).convert("1")

combined = np.bitwise_xor(np.array(img1, dtype=np.uint8), np.array(img2, dtype=np.uint8))
Image.fromarray((combined * 255).astype(np.uint8)).save(out)
print("wrote", out)
