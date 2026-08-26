"""v2 end-to-end client: connects to a live AdaTP server with a pinned key,
runs the authenticated handshake, then an encrypted auth + join + text round-trip
(which only works if the AAD-bound v2 session agrees end to end). Exit 0 on
success. Driven by test/run_e2e_v2.sh.

usage: python3 test/e2e_v2.py <host> <port> <server_key_hex(64) | v1>
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from adatp import AdaTPClient  # noqa: E402


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3196
    key = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("ADATP_SERVER_KEY")
    v1_mode = key == "v1"
    if not v1_mode and (not key or len(key) != 64):
        print("usage: e2e_v2.py <host> <port> <server_key_hex(64) | v1>", file=sys.stderr)
        return 2

    client = AdaTPClient(host, port, server_key=None if v1_mode else key)
    client.connect()  # v2 handshake (verify + AAD) unless v1_mode
    me = client.authenticate("guest", "")
    assert me.get("role") == "anonymous", f"unexpected identity: {me}"
    client.join_room("lobby")
    client.send_text_message("hello from Python")
    client.disconnect()
    label = "v1" if v1_mode else "v2"
    extra = "" if v1_mode else " with header-AAD"
    print(f"Python E2E {label} PASSED: handshake + round-trip (auth + join + text){extra}.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print(f"Python E2E FAILED: {e}", file=sys.stderr)
        sys.exit(1)
