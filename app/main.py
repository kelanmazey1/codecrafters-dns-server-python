import socket
from app.message import DNSHeader, DNSHeaderFlags
import struct


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # TODO: Uncomment the code below to pass the first stage
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            msg = DNSHeader.from_bytes(buf)
            flags = DNSHeaderFlags()
            flags.toggle_is_query() # Fresh flag will always be query
            
            q_count = 0
            ans_count = 0
            auth_rec_count = 0
            add_rec_count = 0

            # Pack out var in 2 bytes chunks with big endian
            out = struct.pack(">HHHHHH",
                msg.get_packetid(),
                int(flags),
                q_count,
                ans_count,
                auth_rec_count,
                add_rec_count,
                )

    
            udp_socket.sendto(out, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
