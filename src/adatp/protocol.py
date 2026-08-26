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
    
    GAME_STATE = 0x0050

    PRESENCE_UPDATE = 0x0060
    TYPING_INDICATOR = 0x0061

    TOOL_CALL = 0x0070
    TOOL_RESULT = 0x0071
    TOOL_ERROR = 0x0072

    PING = 0x0080
    PONG = 0x0081

    VIDEO_INIT = 0x0090
    VIDEO_OFFER = 0x0091
    VIDEO_ANSWER = 0x0092
    VIDEO_DATA = 0x0093
    VIDEO_END = 0x0094

    JOIN_ROOM = 0x00A0
    ROOM_JOINED = 0x00A1
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
    def header_bytes(header) -> bytes:
        """The 45-byte header, serialized as on the wire. Also used as the AEAD
        AAD in protocol v2, so it must match the server's
        ``PacketHeader::header_bytes()`` byte-for-byte."""
        mtype = header.msg_type.value if hasattr(header.msg_type, 'value') else header.msg_type
        return struct.pack(
            '<I B H I Q H Q 16s',
            header.magic, header.version, header.flags, header.length,
            header.sequence, mtype, header.timestamp, header.session_id,
        )

    @staticmethod
    def encode(packet) -> bytes:
        out = Packet.header_bytes(packet.header) + packet.payload
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
