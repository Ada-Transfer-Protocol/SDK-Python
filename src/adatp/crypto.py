import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureSession:
    def __init__(self, role: str, shared_secret: bytes):
        self.role = role
        self.client_write_key = None
        self.server_write_key = None
        self.client_iv_root = None
        self.server_iv_root = None
        
        self.my_sequence = 1
        self.peer_sequence = 1
        
        self._derive_keys(shared_secret)
        
    def _derive_keys(self, shared_secret: bytes):
        salt = b'\x00' * 32
        
        def derive(info: bytes, length: int) -> bytes:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                info=info,
            )
            return hkdf.derive(shared_secret)
            
        self.client_write_key = derive(b'client_write', 32)
        self.server_write_key = derive(b'server_write', 32)
        self.client_iv_root = derive(b'client_iv', 12)
        self.server_iv_root = derive(b'server_iv', 12)
        
    def encrypt(self, plaintext: bytes) -> tuple:
        seq = self.my_sequence
        iv = self._compute_iv(seq, self.role)
        
        key = self.client_write_key if self.role == 'client' else self.server_write_key
        aesgcm = AESGCM(key)
        
        # AESGCM.encrypt(nonce, data, associated_data) returns ciphertext + tag appended
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
        
        # Split tag (last 16 bytes)
        actual_ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        self.my_sequence += 1
        return actual_ciphertext, tag, seq
        
    def decrypt(self, ciphertext: bytes, auth_tag: bytes, sequence: int) -> bytes:
        peer_role = 'server' if self.role == 'client' else 'client'
        iv = self._compute_iv(sequence, peer_role)
        
        key = self.client_write_key if peer_role == 'client' else self.server_write_key
        aesgcm = AESGCM(key)
        
        # AESGCM.decrypt expects ciphertext + tag appended
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
            
        if sequence >= self.peer_sequence:
            self.peer_sequence = sequence + 1
            
        return plaintext

    def _compute_iv(self, sequence: int, role: str) -> bytes:
        root = self.client_iv_root if role == 'client' else self.server_iv_root
        
        # Sequence to bytes 8 bytes LE
        seq_bytes = sequence.to_bytes(8, 'little')
        
        # XOR last 8 bytes of root with sequence
        iv = bytearray(root)
        for i in range(8):
            iv[4 + i] ^= seq_bytes[i]
            
        return bytes(iv)
