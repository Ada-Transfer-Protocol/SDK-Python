from enum import IntEnum
import struct
import time
import uuid

MAGIC_NUMBER = 0x41444154
HEADER_SIZE = 45

class MessageType(IntEnum):
    HANDSHAKE_INIT = 0x0001
    HANDSHAKE_RESPONSE = 0x0002
    HANDSHAKE_COMPLETE = 0x0003
    AUTH_REQUEST = 0x0010
    AUTH_CHALLENGE = 0x0011
    AUTH_RESPONSE = 0x0012
    AUTH_SUCCESS = 0x0013
    AUTH_FAILURE = 0x0014
    TEXT_MESSAGE = 0x0020
    TEXT_ACK = 0x0021
    TEXT_READ = 0x0022
    
    FILE_INIT = 0x0030
    FILE_CHUNK = 0x0031
    FILE_ACK = 0x0032
    FILE_COMPLETE = 0x0033
    FILE_CANCEL = 0x0034
    
    VOICE_INIT = 0x0040
    VOICE_OFFER = 0x0041
    VOICE_ANSWER = 0x0042
    VOICE_ICE = 0x0043
    VOICE_DATA = 0x0044
    VOICE_END = 0x0045
    
    VIDEO_INIT = 0x0050
    VIDEO_OFFER = 0x0051
    VIDEO_ANSWER = 0x0052
    VIDEO_DATA = 0x0053
    VIDEO_END = 0x0054
    
    PRESENCE_UPDATE = 0x0060
    TYPING_INDICATOR = 0x0061
    JOIN_ROOM = 0x00A0
    ROOM_JOINED = 0x00A1
    PING = 0x0070
    PONG = 0x0071
    DISCONNECT = 0x00FF

class PacketFlags(IntEnum):
    NONE = 0
    ENCRYPTED = 0x0001
    COMPRESSED = 0x0002
    RELIABLE = 0x0004

class PacketHeader:
    def __init__(self):
        self.magic = MAGIC_NUMBER
        self.version = 1
        self.flags = 0
        self.length = 0
        self.sequence = 0
        self.msg_type = 0
        self.timestamp = int(time.time() * 1000)
        self.session_id = b'\x00' * 16

class Packet:
    def __init__(self, msg_type: int, payload: bytes, session_id: bytes = None):
        self.header = PacketHeader()
        self.header.msg_type = msg_type
        self.header.length = len(payload)
        if session_id and len(session_id) == 16:
            self.header.session_id = session_id
        self.payload = payload
        self.auth_tag = None

    @staticmethod
    def encode(packet) -> bytes:
        h = packet.header
        mtype = h.msg_type.value if hasattr(h.msg_type, 'value') else h.msg_type
        
        # <I B H I Q H Q 16s
        # Total 45
        buf = struct.pack(
            '<I B H I Q H Q 16s',
            h.magic,
            h.version,
            h.flags,
            h.length,
            h.sequence,
            mtype,
            h.timestamp,
            h.session_id
        )
        out = buf + packet.payload
        if packet.auth_tag:
            out += packet.auth_tag
        return out

    @staticmethod
    def decode_header(data: bytes):
        if len(data) < HEADER_SIZE:
            raise Exception("Header too short")
            
        magic, ver, flags, length, seq, mtype, ts, sess = struct.unpack(
            '<I B H I Q H Q 16s', data
        )
        
        # Create dummy wrapper
        # Using 0 as type initially, will set correct one
        p = Packet(mtype, b'', sess)
        p.header.magic = magic
        p.header.version = ver
        p.header.flags = flags
        p.header.length = length
        p.header.sequence = seq
        p.header.timestamp = ts
        
        # Try to cast mtype to Enum if possible
        try:
            p.header.msg_type = MessageType(mtype)
        except:
            pass # Keep as int
            
        return p
