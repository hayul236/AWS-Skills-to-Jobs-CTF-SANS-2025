# CTF Task Write-ups

A short record of each challenge in this folder — the core vulnerability/concept and the
fundamental approach used to reach the flag. Each heading matches its subfolder/file.

---

## `5` — JWT signed with an empty secret

**Concept:** JWT signature verification with a rotated-secret list.

The FastAPI app (`main.py`) stores a click `count` in a `d` cookie signed with
`jwt.encode(..., secrets[0], HS256)`, and `/flag` requires `count < 0`. The secret list comes
from the `jwt_secrets` env var split on commas; in this instance the first secret was the
**empty string** `""`.

**Approach:** Forge a token `{"count": -1}` signed with the empty key, set it as cookie `d`,
and request `/flag`.

```bash
python3 -c 'import jwt; print(jwt.encode({"count": -1}, "", algorithm="HS256"))'
curl -s -k -b "d=<TOKEN>" 'https://cpp.bootupctf.net:8085/flag'
```

---

## `well this is confusing` — JWT RS256 → HS256 algorithm confusion

**Concept:** The server signs tokens with RS256 (RSA private key) and verifies with the public
key. A buggy verifier that trusts the token's `alg` header will verify an **HS256** token using
the RSA **public key as the HMAC secret** — which the attacker also has.

**Approach:**
1. Get a legitimate `crew` token and read its structure.
2. Obtain/decode the server's public key into PEM.
3. Re-sign a forged payload `{"name":"Reinhard","role":"commander"}` with **HS256**, using the
   public key bytes as the shared secret.
4. Send the forged token as the `astral_token` cookie to the restricted `/bridge` endpoint.

The restricted endpoint then returns the flag.

---

## `g1` — Cookie privilege tampering

**Concept:** Authorization decided by an unsigned, client-controlled cookie.

**Approach:** Change the `user_level` cookie value to `admin` and reload — the flag is returned.

---

## `anime` — Server-Side Template Injection (Jinja2)

**Concept:** User input (`username` GET param) is rendered directly into a Jinja2 template, so
`{{ ... }}` expressions execute server-side.

**Approach** (`ssti_read_flag.py`): walk the Python object graph from a string literal to reach a
class capable of file read / command exec, then read the flag:

```
{{''.__class__.__mro__[2].__subclasses__()[<i>]('/flag').read()}}
{{''.__class__.__mro__[2].__subclasses__()[<i>].__init__.__globals__['os'].popen('cat /flag').read()}}
```

The script brute-forces the subclass index `<i>` by probing `__name__` for `file`/`popen`/`os`,
then reads `/flag` (or runs `cat /flag`).

---

## `traverse` — Path traversal with encoding bypass

**Concept:** `picture.php?image=` includes a file by name with insufficient filtering. A naive
`../` strip is defeated by the `....//` pattern (and URL-encoded variants `..%2f`, `..%252f`).

**Approach:** Fuzz traversal payloads/targets, then grab the file whose response size differs
from the normal image:

```bash
curl -s -k 'https://nm02.bootupctf.net:8082/picture.php?image=....//....//....//....//....//....//....//....//etc/flag.txt'
```

---

## `race` — ReDoS race condition (catastrophic backtracking)

**Concept:** A request to `/flag/<path>` spawns a bot that runs `re.match(r'(a+)+$', path)`. The
nested quantifier `(a+)+` backtracks exponentially on input like `aaaa…a` + one non-`a`. The web
process only waits `bot.join(timeout=2)`; if the bot is still stuck it is killed and, since
`flag.txt` exists, the flag is returned.

**Approach** (`probe_flag.py`): send `"a"*N + "b"` for increasing `N`, avoiding `414 URI Too
Large`, and find the length (~800) that makes the response take **>2 s** — that length wins the
race and returns the flag.

---

## `CTR` — AES counter-length key forgery

**Concept:** Per-block key is derived as `(counter_bytes + KEY)[:32]`, and on decryption the
**first ciphertext byte is used as `counter_length`** (attacker-controlled). Setting
`counter_length = 32 (0x20)` makes `counter_bytes` 32 zero bytes, so the key becomes
`b"\x00"*32` — the secret `KEY` is never used.

**Approach** (`cipher.py`): direct `encrypt("open sesame")` is blacklisted, so forge the
ciphertext instead — AES-ECB encrypt PKCS#7-padded `"open sesame"` under the all-zero key, prefix
byte `0x20`, and feed it to the decrypt oracle. It decrypts to `open sesame` → flag.

---

## `ce01` — Repeating-key XOR break

**Concept:** A byte blob (stored as signed ints) is encrypted with repeating-key XOR (Vigenère on
bytes).

**Approach** (`ce01.py`): reinterpret signed ints as unsigned bytes, then classic break — guess
key size via normalized **Hamming distance** between blocks, transpose into single-byte-XOR
columns, and solve each column by English-frequency scoring. Reassemble the key and decrypt.

---

## `ce02` — Signed-byte reinterpretation

**Concept:** Binary data was dumped as **signed** integers (−128…127) instead of unsigned bytes.

**Approach** (`ce02.py`): convert each with `(n + 256) % 256`, write to `output.bin`, read as
ASCII. The flag appears in plaintext within the decoded output.

---

## `3` — Hex byte parsing

**Concept:** `file.txt` is colon-separated hex (`0xdc:0x67:0xe2:…`).

**Approach** (`read_hex_file.py`): split on `:` and map each `0xNN` to a byte to recover the raw
binary for further analysis.

---

## `d1` — ODT is a ZIP (hidden content)

**Concept:** OpenDocument `.odt` files are ZIP archives.

**Approach:** copy `report.odt` → `report.zip`, unzip, and inspect `content.xml` where the flag
is hidden in the document body/metadata.

---

## `FORENSICS` — PCAP carving + keyed XOR

**Concept:** A capture (`server.pcap`) carries data exfiltrated as base64; the decoded bytes are
XOR-encrypted with a themed key (a song/artist — Radiohead "I Will" / "Reckoner").

**Approach:** follow TCP streams, pull out base64 candidate strings, base64-decode, then XOR
against candidate keys derived from the theme (`decode_message.py`, `try_keys.py`) until printable
ASCII / the flag appears. Side artifacts (`logs.zip` → `.evtx`, `product_specs.docx` → ZIP) are
unpacked the same "office/zip is a container" way.

---

## `f4` / `f5` / `f6` — Windows Event Log forensics

Windows `.evtx` logs (Security, PowerShell, TaskScheduler, …) analyzed for attacker activity:

- **`f4`** — find the **attacker hostname** from the Security event log (logon events carry the
  source workstation name).
- **`f5`** — **PowerShell Script Block Logging** captures the in-memory script text the attacker
  actually executed, revealing the commands run.
- **`f6`** — persistence hunt: a scheduled task (`CreateBackdoor`) runs at startup to create a
  local admin user (`notabackdooruser` / `bdpassbdpass123!`) added to Administrators; the account
  name was obfuscated with **ROT13**.

---

## `GPS` — NMEA trail reconstruction

**Concept:** A PCAP contains GPS **NMEA** sentences (`$GPGGA`).

**Approach** (`extract_gps..py`): filter `frame contains "$GP"` in Wireshark, export packets,
parse `$GPGGA` lat/lon (ddmm.mmmm → decimal degrees), write `trail_trace.csv`, and plot with
Folium/Google My Maps. The plotted path (around Bristol) reveals the answer.

---

## QR XOR (`binary_qr_code*.png` → `combined_qr.png`)

**Concept:** The real QR is split across two images; neither scans alone.

**Approach** (`decode_icmp_timing_scapy.py`): load both as 1-bit images and **XOR** them
pixel-wise to produce `combined_qr.png`, then scan it.

---

## ICMP timing covert channel (`the_echo_protocol_1.pcap`, `icmp_times.txt`)

**Concept:** Data is hidden not in packet payloads but in the **inter-arrival timing** of ICMP
echo packets.

**Approach:** extract ICMP packet timestamps, compute deltas between consecutive packets, and
threshold the delays into bits (short vs. long gap) to reconstruct the hidden message.
