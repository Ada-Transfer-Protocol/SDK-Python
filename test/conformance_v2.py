"""v2 authenticated-handshake conformance for the Python SDK.

Replays the shared golden vectors (test/vectors/adatp-v2-handshake-vectors.json,
copied from the server repo) and checks this SDK reproduces them byte-for-byte.
No server needed. Run: python3 test/conformance_v2.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from adatp import handshake_v2  # noqa: E402

VEC = os.path.join(os.path.dirname(__file__), "vectors", "adatp-v2-handshake-vectors.json")
with open(VEC) as f:
    cases = {c["id"]: c for c in json.load(f)["cases"]}


def h(s):
    return bytes.fromhex(s)


fails = 0


def check(cond, name):
    global fails
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        fails += 1


# 1. transcript hash
tc = cases["handshake-v2-transcript-hash"]
th = handshake_v2.transcript_hash(
    h(tc["input"]["epk_c_hex"]), h(tc["input"]["epk_s_hex"]), h(tc["input"]["spk_s_hex"])
)
check(th.hex() == tc["expected"]["transcript_hash_hex"], "transcript hash matches Rust reference")

# 2. signed ServerHello verifies under the pinned key
sh = cases["handshake-v2-server-hello"]
pinned = h(tc["input"]["spk_s_hex"])
epk_s, th2 = handshake_v2.verify_server_hello(
    pinned, h(sh["input"]["epk_c_hex"]), h(sh["expected"]["server_hello_hex"])
)
check(
    epk_s.hex() == sh["input"]["epk_s_hex"] and th2.hex() == tc["expected"]["transcript_hash_hex"],
    "signed ServerHello accepted; epk_s + th recovered",
)

# 3. wrong pin rejected
wp = cases["handshake-v2-server-hello-wrong-pin"]
try:
    handshake_v2.verify_server_hello(
        h(wp["input"]["pinned_spk_s_hex"]), h(wp["input"]["epk_c_hex"]), h(wp["input"]["server_hello_hex"])
    )
    check(False, "wrong pin rejected")
except handshake_v2.AdaTPHandshakeError as e:
    check(e.code == "unknown_identity", "wrong pin rejected (unknown_identity)")

# 4. substituted ephemeral rejected
te = cases["handshake-v2-server-hello-tampered-ephemeral"]
try:
    handshake_v2.verify_server_hello(
        h(te["input"]["pinned_spk_s_hex"]), h(te["input"]["epk_c_hex"]), h(te["input"]["server_hello_hex"])
    )
    check(False, "substituted ephemeral rejected")
except handshake_v2.AdaTPHandshakeError as e:
    check(e.code == "signature_verification_failed", "substituted ephemeral rejected (signature_verification_failed)")

# 5. malformed length rejected
try:
    handshake_v2.verify_server_hello(b"\x00" * 32, b"\x00" * 32, b"\x00" * 127)
    check(False, "malformed length rejected")
except handshake_v2.AdaTPHandshakeError as e:
    check(e.code == "malformed_server_hello", "malformed response length rejected")

# 6. Finished plaintext
fc = cases["handshake-v2-finished"]
check(
    handshake_v2.finished_plaintext(h(fc["input"]["transcript_hash_hex"])).hex()
    == fc["expected"]["finished_plaintext_hex"],
    "Finished plaintext matches Rust reference",
)

print(f"\nPython v2 handshake conformance: {'PASS' if fails == 0 else 'FAIL'} ({fails} failure{'' if fails == 1 else 's'})")
sys.exit(0 if fails == 0 else 1)
