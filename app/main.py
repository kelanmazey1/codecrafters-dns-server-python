import socket
import struct
from app.message import DNSHeader, DNSMessage, DNSHeaderFlags, DNSQuestion, DNSRecordType


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # TODO: Uncomment the code below to pass the first stage

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            out = DNSMessage()

            flags = DNSHeaderFlags()
            flags.toggle_is_query()
            out_header = DNSHeader(
                packetid=1234,
                flags=flags
                )
            
            out_question = DNSQuestion(
                labels="codecrafters.io".split("."),
                record_type=DNSRecordType.A,
                )
            
            out_header.set_qdcount(1)

            out.set_header(out_header)
            out.set_question(out_question)

            udp_socket.sendto(out.to_bytes(), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
