# Solvers

My own solve scripts, cleaned for publishing. Live hostnames/ports are replaced
with `TARGET_HOST:PORT` placeholders, and challenge-provided data blobs, captures,
and flags are not included — point each script at your own authorized target or
input file. See the top-level [README](../README.md) for the full write-ups.

| Script | Challenge | Technique |
|---|---|---|
| `ssti_read_flag.py` | anime | Jinja2 SSTI — subclass walk to file read / RCE |
| `redos_probe.py` | race | ReDoS race on `(a+)+$`, find the length that wins the timeout |
| `ctr_forge_ciphertext.py` | CTR | Forge ciphertext using attacker-controlled counter-length → zero key |
| `break_repeating_xor.py` | ce01 | Repeating-key XOR break (Hamming keysize + frequency analysis) |
| `signed_bytes_to_binary.py` | ce02 | Reinterpret signed ints as unsigned bytes |
| `read_hex_file.py` | 3 | Parse colon-separated hex dump into bytes |
| `extract_gps.py` | GPS | Parse `$GPGGA` NMEA sentences into lat/lon CSV |
| `xor_decode_message.py` | FORENSICS | base64-decode + repeating-key XOR against theme keys |
| `qr_xor.py` | QR | XOR two half-QR images into the scannable code |

Scripts using `requests` disable TLS verification for self-signed lab certs; only
run them against targets you are authorized to test.
