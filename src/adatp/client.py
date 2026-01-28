import socket
import uuid
import os
import json
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from .protocol import Packet, MessageType, PacketFlags, HEADER_SIZE
from .crypto import SecureSession

class AdaTPClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None
        self.crypto_session = None
        self.session_id = None
        
    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        # Nagle disabled for lower latency
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(f"Connected to {self.host}:{self.port}")
        
        self.session_id = uuid.uuid4().bytes
        self._handshake()
        
    def disconnect(self):
        if self.socket:
            try:
                packet = Packet(MessageType.DISCONNECT, b'', self.session_id)
                self._send_packet(packet)
            except:
                pass
            self.socket.close()
            self.socket = None

    def _handshake(self):
        # 1. Generate Ephemeral Keys
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        my_pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # 2. Send HANDSHAKE_INIT
        # print("Sending Handshake Init...")
        packet = Packet(MessageType.HANDSHAKE_INIT, my_pub_bytes, self.session_id)
        self._send_packet(packet)
        
        # 3. Receive HANDSHAKE_RESPONSE
        resp = self.read_packet()
        if resp.header.msg_type != MessageType.HANDSHAKE_RESPONSE:
            raise Exception(f"Handshake Failed: Expected RESPONSE, got {resp.header.msg_type}")
            
        server_pub_bytes = resp.payload
        if len(server_pub_bytes) != 32:
            raise Exception("Invalid Server Key")
            
        server_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
        
        # 4. Compute Shared Secret
        shared_secret = private_key.exchange(server_pub)
        
        # 5. Init Crypto Session
        self.crypto_session = SecureSession('client', shared_secret)
        
        # 6. Send HANDSHAKE_COMPLETE (Encrypted)
        verify_msg = b"Verification OK"
        ciphertext, tag, seq = self.crypto_session.encrypt(verify_msg)
        
        packet = Packet(MessageType.HANDSHAKE_COMPLETE, ciphertext, self.session_id)
        packet.header.flags |= PacketFlags.ENCRYPTED
        packet.header.sequence = seq
        packet.auth_tag = tag
        
        self._send_packet(packet)
        print("Handshake Complete")

    def authenticate(self, username, password):
        payload = json.dumps({"username": username, "password": password}).encode('utf-8')
        self._send_encrypted(MessageType.AUTH_REQUEST, payload)
        
        resp = self.read_packet()
        if resp.header.flags & PacketFlags.ENCRYPTED and self.crypto_session:
             # Decrypt
             # Note: decrypt signature in crypto.py might vary, assuming (ciphertext, tag, seq)
             plaintext = self.crypto_session.decrypt(resp.payload, resp.auth_tag, resp.header.sequence)
             
             if resp.header.msg_type == MessageType.AUTH_SUCCESS:
                 print(f"Auth Success: {plaintext.decode()}")
             elif resp.header.msg_type == MessageType.AUTH_FAILURE:
                 raise Exception(f"Auth Failed: {plaintext.decode()}")
             else:
                 # It might be TEXT_MESSAGE or something else if server is chatty?
                 # But in Auth protocol, response is strictly AuthSuccess/Failure.
                 raise Exception(f"Unexpected packet during auth: {resp.header.msg_type}")
        else:
             raise Exception("Auth response not encrypted")

    def join_room(self, room_name):
        self._send_encrypted(MessageType.JOIN_ROOM, room_name.encode('utf-8'))
        print(f"Joined room: {room_name}")

    def send_text_message(self, text):
        self._send_encrypted(MessageType.TEXT_MESSAGE, text.encode('utf-8'))

    def send_file(self, file_path: str):
        if not self.crypto_session:
            raise Exception("Secure session required")
            
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_id = str(uuid.uuid4())
        file_id_bytes = uuid.UUID(file_id).bytes
        
        # Init
        init_data = {"id": file_id, "filename": filename, "size": file_size}
        init_json = json.dumps(init_data).encode('utf-8')
        
        self._send_encrypted(MessageType.FILE_INIT, init_json)
        
        # Chunks
        CHUNK_SIZE = 16384
        print(f"Sending file {filename} ({file_size} bytes)")
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                # Payload: [FileID(16)][Data]
                payload = file_id_bytes + chunk
                self._send_encrypted(MessageType.FILE_CHUNK, payload)
                # Small sleep to yield to IO?
                # time.sleep(0.001) 
        
        # Complete
        self._send_encrypted(MessageType.FILE_COMPLETE, file_id_bytes)
        print("File sent.")
        
    def _send_encrypted(self, msg_type, payload: bytes):
        if not self.crypto_session:
             raise Exception("No crypto session")
        
        ciphertext, tag, seq = self.crypto_session.encrypt(payload)
        
        packet = Packet(msg_type, ciphertext, self.session_id)
        packet.header.flags |= PacketFlags.ENCRYPTED
        packet.header.sequence = seq
        packet.auth_tag = tag
        
        self._send_packet(packet)

    def _send_packet(self, packet: Packet):
        buf = Packet.encode(packet)
        self.socket.sendall(buf)

    def read_packet(self) -> Packet:
        header_buf = self._recv_exact(HEADER_SIZE)
        if not header_buf:
            raise Exception("Connection closed")
            
        packet = Packet.decode_header(header_buf)
        
        if packet.header.length > 0:
            packet.payload = self._recv_exact(packet.header.length)
            if packet.payload is None:
                 raise Exception("Connection closed during payload")
            
        if packet.header.flags & PacketFlags.ENCRYPTED:
             # Read Auth Tag (16 bytes)
             packet.auth_tag = self._recv_exact(16)
             if packet.auth_tag is None:
                  raise Exception("Connection closed during auth tag")
        
        return packet

    def _recv_exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
