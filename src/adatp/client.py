import json
import os
import uuid

import websocket  # websocket-client

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .protocol import Packet, MessageType, PacketFlags, HEADER_SIZE, MAGIC_NUMBER
from .crypto import SecureSession


class AdaTPClient:
    """AdaTP client for Python.

    Transport is WebSocket (binary frames, one AdaTP packet per message).
    ``connect()`` performs the X25519 handshake so all subsequent traffic is
    encrypted with AES-256-GCM.

    >>> client = AdaTPClient('127.0.0.1', 3000)
    >>> client.connect()
    >>> client.authenticate('user1', 'password123')
    >>> client.join_room('lobby')
    >>> client.send_text_message('Hello!')

    A full URL is also accepted: ``AdaTPClient(url='wss://example.com/ws')``.
    """

    #: Locales supported by the SDK's language option.
    LOCALES = ('en', 'tr', 'it', 'fr', 'de', 'zh', 'ja', 'hi', 'ar')

    def __init__(self, host: str = '127.0.0.1', port: int = 3000,
                 path: str = '/ws', secure: bool = False, url: str = None,
                 locale: str = 'en'):
        if url:
            self.url = url
        else:
            scheme = 'wss' if secure else 'ws'
            self.url = f"{scheme}://{host}:{port}{path}"
        self.ws = None
        self.crypto_session = None
        self.session_id = None
        self._inbox = []
        # SDK language (client-side metadata; the wire protocol is
        # language-neutral). Falls back to 'en'.
        self.locale = locale if locale in self.LOCALES else 'en'

    def set_locale(self, locale: str):
        """Switches the SDK language at runtime (one of LOCALES)."""
        self.locale = locale if locale in self.LOCALES else 'en'

    def connect(self, timeout: float = 10.0):
        self.ws = websocket.create_connection(self.url, timeout=timeout)
        print(f"Connected to {self.url}")

        self.session_id = uuid.uuid4().bytes
        self._handshake()

    @property
    def socket(self):
        """Underlying socket — usable with select.select() in event loops.

        Check ``has_pending()`` first: packets already buffered by the
        WebSocket layer are invisible to select().
        """
        return self.ws.sock if self.ws else None

    def fileno(self) -> int:
        return self.ws.sock.fileno()

    def has_pending(self) -> bool:
        """True if a packet can be read without touching the network."""
        return bool(self._inbox)

    def disconnect(self):
        if self.ws:
            try:
                packet = Packet(MessageType.DISCONNECT, b'', self.session_id)
                self._send_packet(packet)
            except Exception:
                pass
            self.ws.close()
            self.ws = None

    def _handshake(self):
        # 1. Ephemeral X25519 key pair
        private_key = x25519.X25519PrivateKey.generate()
        my_pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # 2. HANDSHAKE_INIT carries our public key
        packet = Packet(MessageType.HANDSHAKE_INIT, my_pub_bytes, self.session_id)
        self._send_packet(packet)

        # 3. HANDSHAKE_RESPONSE carries the server's public key
        resp = self.read_packet()
        if resp.header.msg_type != MessageType.HANDSHAKE_RESPONSE:
            raise Exception(f"Handshake failed: expected RESPONSE, got {resp.header.msg_type}")
        server_pub_bytes = resp.payload
        if len(server_pub_bytes) < 32:
            raise Exception("Server did not provide a key")
        server_pub = x25519.X25519PublicKey.from_public_bytes(bytes(server_pub_bytes[:32]))

        # 4. Shared secret + session keys
        shared_secret = private_key.exchange(server_pub)
        self.crypto_session = SecureSession('client', shared_secret)

        # 5. HANDSHAKE_COMPLETE proves both sides derived the same keys
        ciphertext, tag, seq = self.crypto_session.encrypt(b"Verification OK")
        packet = Packet(MessageType.HANDSHAKE_COMPLETE, ciphertext, self.session_id)
        packet.header.flags |= PacketFlags.ENCRYPTED
        packet.header.sequence = seq
        packet.auth_tag = tag
        self._send_packet(packet)

    def authenticate(self, username: str, password: str) -> dict:
        """Sends credentials; returns the identity dict or raises on failure."""
        payload = json.dumps({"username": username, "password": password}).encode('utf-8')
        self._send_encrypted(MessageType.AUTH_REQUEST, payload)

        resp = self.read_packet()
        plaintext = self._decrypt_if_needed(resp)

        if resp.header.msg_type == MessageType.AUTH_SUCCESS:
            identity = json.loads(plaintext.decode('utf-8'))
            print(f"Auth success: {identity}")
            return identity
        if resp.header.msg_type == MessageType.AUTH_FAILURE:
            raise Exception(f"Auth failed: {plaintext.decode('utf-8', 'replace')}")
        raise Exception(f"Unexpected packet during auth: {resp.header.msg_type}")

    def join_room(self, room_name: str) -> str:
        """Joins a room; blocks until the server confirms with ROOM_JOINED."""
        self._send_encrypted(MessageType.JOIN_ROOM, room_name.encode('utf-8'))
        while True:
            resp = self.read_packet()
            if resp.header.msg_type == MessageType.ROOM_JOINED:
                joined = self._decrypt_if_needed(resp).decode('utf-8')
                print(f"Joined room: {joined}")
                return joined
            if resp.header.msg_type == MessageType.AUTH_FAILURE:
                raise Exception(self._decrypt_if_needed(resp).decode('utf-8', 'replace'))
            self._inbox.append(resp)

    def send_text_message(self, text: str):
        self._send_encrypted(MessageType.TEXT_MESSAGE, text.encode('utf-8'))

    def send_game_state(self, state):
        """Broadcasts a game state (dict → JSON, or raw bytes) to the room."""
        payload = state if isinstance(state, bytes) else json.dumps(state).encode('utf-8')
        self._send_encrypted(MessageType.GAME_STATE, payload)

    def read_game_state(self):
        """Blocks until the next GAME_STATE arrives; returns dict (or bytes)."""
        while True:
            packet = self.read_packet()
            if packet.header.msg_type == MessageType.GAME_STATE:
                raw = self._decrypt_if_needed(packet)
                try:
                    return json.loads(raw.decode('utf-8'))
                except Exception:
                    return raw

    def call_tool(self, tool: str, args: dict = None, timeout_calls: int = 256) -> dict:
        """Calls a server-side tool; returns the result or raises on error."""
        call_id = str(uuid.uuid4())
        body = json.dumps({"id": call_id, "tool": tool, "args": args or {}})
        self._send_encrypted(MessageType.TOOL_CALL, body.encode('utf-8'))

        for _ in range(timeout_calls):
            packet = self.read_packet()
            if packet.header.msg_type in (MessageType.TOOL_RESULT, MessageType.TOOL_ERROR):
                parsed = json.loads(self._decrypt_if_needed(packet).decode('utf-8'))
                if parsed.get('id') != call_id:
                    continue
                if packet.header.msg_type == MessageType.TOOL_RESULT and parsed.get('ok'):
                    return parsed.get('result')
                err = parsed.get('error') or {}
                raise Exception(f"Tool '{tool}' failed: {err.get('code')}: {err.get('message')}")
            self._inbox.append(packet)
        raise Exception(f"No response for tool '{tool}'")

    def list_tools(self):
        """Lists the tools available on the server."""
        result = self.call_tool('system.list_tools', {})
        return (result or {}).get('tools', [])

    def read_text_message(self) -> str:
        """Blocks until the next TEXT_MESSAGE arrives; returns the plaintext."""
        while True:
            packet = self.read_packet()
            if packet.header.msg_type == MessageType.TEXT_MESSAGE:
                return self._decrypt_if_needed(packet).decode('utf-8', 'replace')

    def send_file(self, file_path: str):
        if not self.crypto_session:
            raise Exception("Secure session required")

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_id = str(uuid.uuid4())
        file_id_bytes = uuid.UUID(file_id).bytes

        init_data = {"id": file_id, "filename": filename, "size": file_size}
        self._send_encrypted(MessageType.FILE_INIT, json.dumps(init_data).encode('utf-8'))

        CHUNK_SIZE = 16384
        print(f"Sending file {filename} ({file_size} bytes)")
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                self._send_encrypted(MessageType.FILE_CHUNK, file_id_bytes + chunk)

        self._send_encrypted(MessageType.FILE_COMPLETE, file_id_bytes)
        print("File sent.")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _decrypt_if_needed(self, packet: Packet) -> bytes:
        if packet.header.flags & PacketFlags.ENCRYPTED:
            if not self.crypto_session:
                raise Exception("Encrypted packet without a session")
            return self.crypto_session.decrypt(
                packet.payload, packet.auth_tag, packet.header.sequence)
        return packet.payload

    def _send_encrypted(self, msg_type, payload: bytes):
        if not self.crypto_session:
            raise Exception("No crypto session (call connect() first)")

        ciphertext, tag, seq = self.crypto_session.encrypt(payload)
        packet = Packet(msg_type, ciphertext, self.session_id)
        packet.header.flags |= PacketFlags.ENCRYPTED
        packet.header.sequence = seq
        packet.auth_tag = tag
        self._send_packet(packet)

    def _send_packet(self, packet: Packet):
        self.ws.send_binary(Packet.encode(packet))

    def read_packet(self) -> Packet:
        """Returns the next packet (queued packets first, then the wire)."""
        if self._inbox:
            return self._inbox.pop(0)

        while True:
            frame = self.ws.recv()
            if frame is None or frame == '':
                raise Exception("Connection closed")
            if isinstance(frame, str):
                continue  # AdaTP is binary-only; ignore text frames
            return self._decode_frame(frame)

    @staticmethod
    def _decode_frame(frame: bytes) -> Packet:
        if len(frame) < HEADER_SIZE:
            raise Exception("Frame too short")
        packet = Packet.decode_header(frame[:HEADER_SIZE])
        if packet.header.magic != MAGIC_NUMBER:
            raise Exception("Bad magic")
        end = HEADER_SIZE + packet.header.length
        packet.payload = frame[HEADER_SIZE:end]
        if packet.header.flags & PacketFlags.ENCRYPTED:
            packet.auth_tag = frame[end:end + 16]
            if len(packet.auth_tag) != 16:
                raise Exception("Missing auth tag")
        return packet
