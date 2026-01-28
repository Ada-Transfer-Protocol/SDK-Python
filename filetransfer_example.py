
import sys
import os
import time
import json
import uuid
from adatp.client import AdaTPClient
from adatp.protocol import MessageType, PacketFlags, Packet

def main():
    try:
        client = AdaTPClient('127.0.0.1', 8444)
        client.connect()
        client.authenticate("pybot", "secret_password")
        
        # 1. Join Room "files"
        room_name = "files"
        ct, tag, seq = client.crypto_session.encrypt(room_name.encode('utf-8'))
        # JOIN_ROOM = 0x00A0
        pkt = Packet(0x00A0, ct, client.session_id) 
        pkt.header.flags |= PacketFlags.ENCRYPTED
        pkt.header.sequence = seq
        pkt.auth_tag = tag
        client._send_packet(pkt)
        
        # 2. Prepare Upload
        upload_path = "upload_test_py.txt"
        with open(upload_path, "w") as f:
            f.write("Hello from Python File Transfer!\n" * 100)
            
        print(f"Joined 'files'. Sending {upload_path} in 2 seconds...")
        time.sleep(2)
        client.send_file(upload_path)
        
        # 3. Listen Loop
        downloads_dir = "downloads_py"
        if not os.path.exists(downloads_dir):
            os.mkdir(downloads_dir)
            
        active_files = {} # id -> {file, path, total}
        
        print("Listening for files...")
        while True:
            pkt = client.read_packet()
            if pkt.header.flags & PacketFlags.ENCRYPTED:
                decrypted = client.crypto_session.decrypt(pkt.payload, pkt.auth_tag, pkt.header.sequence)
                
                if pkt.header.msg_type == MessageType.FILE_INIT:
                    try:
                        meta = json.loads(decrypted.decode('utf-8'))
                        fid = meta['id']
                        fname = meta['filename']
                        sender = meta.get('sender', 'unknown')
                        size = meta['size']
                        
                        print(f"\nReceiving {fname} from {sender} (Size: {size})")
                        save_path = os.path.join(downloads_dir, f"{sender}_{fname}")
                        f = open(save_path, 'wb')
                        active_files[fid] = {'file': f, 'path': save_path, 'total': 0}
                    except Exception as e:
                        print("Error parsing init:", e)
                    
                elif pkt.header.msg_type == MessageType.FILE_CHUNK:
                    if len(decrypted) > 16:
                        fid_bytes = decrypted[:16]
                        data = decrypted[16:]
                        
                        try:
                            fid = str(uuid.UUID(bytes=fid_bytes))
                            if fid in active_files:
                                active_files[fid]['file'].write(data)
                                active_files[fid]['total'] += len(data)
                                sys.stdout.write(".")
                                sys.stdout.flush()
                        except:
                            pass
                            
                elif pkt.header.msg_type == MessageType.FILE_COMPLETE:
                    if len(decrypted) >= 16:
                        fid_bytes = decrypted[:16]
                        fid = str(uuid.UUID(bytes=fid_bytes))
                        
                        if fid in active_files:
                            active_files[fid]['file'].close()
                            print(f"\nDownload Complete: {active_files[fid]['path']}")
                            del active_files[fid]
                        
                elif pkt.header.msg_type == MessageType.TEXT_MESSAGE:
                    print(f"Chat: {decrypted.decode('utf-8')}")
                    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
