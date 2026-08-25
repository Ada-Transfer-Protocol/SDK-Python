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

## 📂 Examples

*   **Chat CLI:** `python3 example.py`
    *   A fully functional terminal chat client supporting rooms (`/join`).
*   **File Transfer:** `python3 filetransfer_example.py`
    *   Demonstrates uploading a dummy file and processing incoming file streams concurrently.

## 🔧 Configuration

By default, the SDK connects to `ws://127.0.0.1:3000/ws` (WebSocket). You can modify the host and port during `AdaTPClient` initialization, or pass a full URL: `AdaTPClient(url="wss://example.com/ws")`. Requires `websocket-client` and `cryptography` (`pip install websocket-client cryptography`).
