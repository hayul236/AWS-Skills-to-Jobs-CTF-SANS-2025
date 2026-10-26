# Forge a ciphertext for the "counter-length" AES service.
#
# The server derives each block key as (counter_bytes + KEY)[:32] and reads the
# first ciphertext byte as counter_length on decrypt. Setting counter_length = 32
# makes counter_bytes 32 zero bytes, so the key is all zeros and KEY is unused.
# We encrypt the target locally under the zero key and prefix 0x20, then feed the
# result to the decrypt oracle.
from Crypto.Cipher import AES

target = b"open sesame"
pad_len = 16 - (len(target) % 16)
padded = target + bytes([pad_len]) * pad_len
c = AES.new(b"\x00" * 32, AES.MODE_ECB).encrypt(padded)
print((b"\x20" + c).hex())
