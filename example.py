import sys
import os
import select
import threading

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from adatp.client import AdaTPClient
from adatp.protocol import MessageType, PacketFlags

def main():
    print("==========================================")
    print("   AdaTP Python Chat Client (CLI)         ")
    print("==========================================")
    
    username = input("Enter your username: ").strip()
    if not username:
        print("Username cannot be empty")
        return
        
    password = input("Enter password (default: secret_password): ").strip() or "secret_password"

    client = AdaTPClient('127.0.0.1', 8444)
    
    try:
        print("Connecting...")
        client.connect()
        print("Authenticating...")
        client.authenticate(username, password)
        print(f"Joined chat as '{username}'.")
        print("Type '/join <room>' to switch rooms.")
        print("Type '/quit' to exit.")
        
        # We need a loop to handle both user input and socket data
        # Using select.select()
        
        sock = client.socket
        stdin = sys.stdin
        
        while True:
            # Watch stdin and socket
            readable, _, _ = select.select([sock, stdin], [], [])
            
            for source in readable:
                if source == sock:
                    try:
                        packet = client.read_packet()
                        if packet.header.msg_type == MessageType.TEXT_MESSAGE:
                            if packet.header.flags & PacketFlags.ENCRYPTED and client.crypto_session:
                                plaintext = client.crypto_session.decrypt(packet.payload, packet.auth_tag, packet.header.sequence)
                                print(f"< {plaintext.decode('utf-8')}")
                            else:
                                print(f"< [Raw] {packet.payload}")
                        elif packet.header.msg_type == MessageType.DISCONNECT:
                             print("Server disconnected.")
                             return
                        else:
                             # print(f"Received Packet Type: {packet.header.msg_type}")
                             pass
                    except Exception as e:
                        print(f"Error reading packet: {e}")
                        return

                elif source == stdin:
                    line = sys.stdin.readline()
                    if not line:
                        return # EOF
                    
                    line = line.strip()
                    if not line:
                        continue
                        
                    if line == '/quit':
                        print("Exiting...")
                        client.disconnect()
                        return
                    
                    if line.startswith('/join '):
                        room = line[6:].strip()
                        if room:
                            client.join_room(room)
                            print(f"Joined room: {room}")
                        continue
                        
                    # Send Message
                    msg = f"[{username}] {line}"
                    client.send_text_message(msg)
                    
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        try:
             client.disconnect()
        except:
            pass

if __name__ == "__main__":
    main()
