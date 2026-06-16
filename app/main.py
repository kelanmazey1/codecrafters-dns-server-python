import socket
from app.message import (
    DNSHeader,
    DNSMessage,
    DNSQuestion,
    DNSRecordType,
    ResourceRecord,
    DNSAnswer,
)

from app.encode import DNSEncoder
from app.decode import DNSDecoder


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # TODO: Uncomment the code below to pass the first stage

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            decoder = DNSDecoder()
            
            req_msg = decoder.decode_message(buf)
            req_header = req_msg.get_header()
            packetid = req_header.get_packetid()

            opcode = req_header.flags.get_opcode()
            
            recursion_desired = req_header.flags.is_recursion_desired()

            resp_packet = DNSMessage()

            resp_header = DNSHeader(packetid=packetid)
            if not resp_header.flags.is_resp():
                resp_header.flags.toggle_is_resp()

            resp_header.flags.set_opcode(opcode)

            if recursion_desired != resp_header.flags.is_recursion_desired():
                resp_header.flags.toggle_recursion_desired()

            if opcode == 0:
                rcode = 0
            else:
                rcode = 4

            resp_header.flags.set_response_code(rcode)

            resp_packet.set_header(resp_header)
            resp_answer = DNSAnswer()

            # TODO: Assuming only responding with 1 question
            for q in req_msg.get_questions():
                print("trying to get the questions")
                resp_question = DNSQuestion(
                    domain_name=q.domain_name,
                    record_type=DNSRecordType(q.record_type)
                )

                
                resp_resource_record = ResourceRecord(
                    domain_name=q.domain_name,
                    type=DNSRecordType.A,
                    time_to_live=60,
                    rdata="8.8.8.8",
                )

                resp_answer.add_resource_record(resp_resource_record)
                resp_packet.add_question(resp_question)
                resp_packet.add_answer(resp_answer)



            encoder = DNSEncoder()
            udp_socket.sendto(encoder.encode_message(resp_packet), source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            raise e
            break


if __name__ == "__main__":
    main()
