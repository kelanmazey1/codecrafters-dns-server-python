import socket
from app.message import (
    DNSHeader,
    DNSMessage,
    DNSHeaderFlags,
    DNSQuestion,
    DNSRecordType,
    ResourceRecord,
    DNSAnswer,
)


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # TODO: Uncomment the code below to pass the first stage

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            out_msg = DNSMessage()

            flags = DNSHeaderFlags()
            if not flags.is_resp():
                flags.toggle_is_resp()

            out_header = DNSHeader(packetid=1234, flags=flags)

            DOMAIN_NAME="codecrafters.io"
            out_question = DNSQuestion(
                domain_name=DOMAIN_NAME,
                record_type=DNSRecordType.A,
            )
            
            out_resource_record = ResourceRecord(
                domain_name=DOMAIN_NAME,
                type=DNSRecordType.A,
                time_to_live=60,
                rdata="8.8.8.8")
            
            out_answer = DNSAnswer()
            out_answer.add_resource_record(out_resource_record)
            out_msg.set_header(out_header)

            # Set out_msg components
            out_msg.add_question(out_question)
            out_msg.add_answer(out_answer)

            udp_socket.sendto(out_msg.to_bytes(), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
