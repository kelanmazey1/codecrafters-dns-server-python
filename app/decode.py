from app.message import (
    DNSMessage,
    DNSAnswer,
    DNSHeader,
    DNSHeaderFlags,
    DNSQuestion,
    DNSRecordType,
    ResourceRecord

)
import struct



class DNSDecoder:
    def decode_message(self, b: bytes) -> DNSMessage:
        m = DNSMessage()
        h = self.decode_header(b[:12]) # First 12 are header
        m.set_header(h)
        
        return m

    def decode_header(self, b: bytes) -> DNSHeader:
        chunks = struct.unpack_from("!6H", b, 0)

        return DNSHeader(chunks[0], DNSHeaderFlags(chunks[1]), chunks[2], chunks[3], chunks[4], chunks[5])

    def decode_answer(self, b: bytes) -> DNSAnswer:
        pass

    def decode_header_flags(self, b: bytes) ->  DNSHeaderFlags:
        pass

    def decode_question(self, b: bytes) -> DNSQuestion:
        pass

    def decode_resource_record(self, b: bytes) -> ResourceRecord:
        pass