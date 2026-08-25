# AdaTP Python SDK

A robust, object-oriented Python client library for the **Ada Transfer Protocol (AdaTP)**. This SDK provides a simple API for building secure chat and file transfer applications using pure Python 3.

## 📦 Features
*   **Security:** Full implementation of X25519 Key Exchange and AES-256-GCM encryption (`cryptography` library).
*   **Threading:** Socket handling is designed to be easily integrated into threaded or select-based loops.
*   **Ease of Use:** High-level wrappers for `connect()`, `authenticate()`, and `send_file()`.

## 🚀 Installation

Requires Python 3.7+ and the `cryptography` library.

```bash
# Install dependencies
pip install cryptography

# Set PYTHONPATH to include source
export PYTHONPATH=$PYTHONPATH:$(pwd)/src
```

## 🛠️ Usage

### 1. Basic Chat Client

```python
from adatp.client import AdaTPClient

# 1. Initialize
client = AdaTPClient('127.0.0.1', 3000)

try:
    # 2. Connect
    client.connect()

    # 3. Authenticate
    client.authenticate("username", "secret_password")

    # 4. Join Room
    client.join_room("general")
    
    # 5. Send Message
    client.send_text_message("Hello from Python!")

    # 6. Read Loop
    while True:
        packet = client.read_packet()
        # Decryption is handled manually in loop or via helper
        # See example.py for precise handling of flags & decryption
        
except Exception as e:
    print(f"Error: {e}")
```

### 2. File Transfer

The SDK abstracts the complexity of chunking and metadata into a simple method:

**Sending a File:**
```python
client.send_file("path/to/document.pdf")
```

**Receiving Files:**
The reception logic requires handling `FILE_INIT`, `FILE_CHUNK`, and `FILE_COMPLETE` packets in your main loop. See `filetransfer_example.py` for a complete reference implementation.

### 3. Authenticated handshake (protocol v2)

By default the client runs the v1 (unauthenticated) handshake, which relies on
TLS for server authentication. Pinning the server's long-term Ed25519 identity
switches to **protocol v2**: the client verifies the server's signature over the
handshake transcript (and binds the frame header as AEAD AAD) **before** deriving
any key, defeating an active man-in-the-middle even without TLS.

```python
# The server's 32-byte Ed25519 public key (hex), obtained out of band. The
# server logs its fingerprint at startup.
client = AdaTPClient("127.0.0.1", 3000,
                     server_key="d04ab232...c9778737")  # <-- enables v2 + pinning
client.connect()   # authenticated handshake; raises AdaTPHandshakeError on a bad key/signature
```

Verified against the Rust reference server end to end (`test/run_e2e_v2.sh`) and
by golden-vector conformance (`test/conformance_v2.py`, run in CI). Require v2
server-side with `ADATP_MIN_PROTOCOL_VERSION=2`.

## 📂 Examples

*   **Chat CLI:** `python3 example.py`
    *   A fully functional terminal chat client supporting rooms (`/join`).
*   **File Transfer:** `python3 filetransfer_example.py`
    *   Demonstrates uploading a dummy file and processing incoming file streams concurrently.

## 🔧 Configuration

By default, the SDK connects to `ws://127.0.0.1:3000/ws` (WebSocket). You can modify the host and port during `AdaTPClient` initialization, or pass a full URL: `AdaTPClient(url="wss://example.com/ws")`. Requires `websocket-client` and `cryptography` (`pip install websocket-client cryptography`).

## Language / locale

The client takes a `locale` argument for its user-facing strings
(client-side metadata — the wire protocol is language-neutral). Default
`en`; supported: `en tr it fr de zh ja hi ar`.

```python
client = AdaTPClient('127.0.0.1', 3000, locale='tr')
client.set_locale('de')  # switch at runtime
```
