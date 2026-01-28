# AdaTP Python SDK

A robust, spec-compliant Python client for the Ada Transport Protocol (AdaTP). This SDK provides necessary primitives and a client implementation to communicate with AdaTP servers using secure, encrypted channels.

## Features

- **Secure Handshake**: Implements X25519 key exchange and HKDF key derivation.
- **End-to-End Encryption**: AES-256-GCM encryption for all messages.
- **Type-Safe Protocol Definitions**: Clear and mostly type-hinted protocol structures.
- **Protocol Compliant**: Fully compatible with the official AdaTP Rust server.

## Requirements

- Python 3.7+
- `cryptography` library

## Installation

```bash
pip install .
# or if developing locally
pip install -e .
```

## Usage

```python
from adatp import AdaTPClient

def main():
    try:
        # Create client
        client = AdaTPClient('127.0.0.1', 8443)
        
        # Connect (Performs Handshake)
        client.connect()
        
        # Send Message
        client.send_text_message("Hello from Python!")
        
        # Disconnect
        client.disconnect()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
```

## Protocol Support

| Feature | Status |
|---------|--------|
| Handshake (X25519) | ✅ |
| Encryption (AES-GCM) | ✅ |
| Text Messages | ✅ |
| Multi-Room Chat | ✅ |
| File Transfer | ✅ (Implemented) |
| Voice/Video | 🚧 (Planned) |

### Multi-Room Support

```python
# Join a room
client.join_room("lobby")

# Reading requires a loop (see example.py)
```

## structure

- `src/adatp/protocol.py`: Packet definitions and Enums.
- `src/adatp/crypto.py`: SecureSession and Key Derivation logic.
- `src/adatp/client.py`: TCP Client implementation.

## License

MIT
# SDK-Python
