"""Module to hold objects that comprise a DNS message"""

from enum import Enum
from dataclasses import dataclass


class DNSRecordType(Enum):
    A = 1
    CNAME = 5


class DNSMessage:
    def __init__(self) -> None:
        self._header: DNSHeader = None
        self._questions: list[DNSQuestion] = []
        self._answer: DNSAnswer = None

    def set_header(self, h: DNSHeader) -> None:
        """Sets header and updates h._qdcount and h._an_count"""
        self._header = h

        self._header.set_qdcount(len(self._questions))
        
        if self._answer:
            self._header.set_ancount(self._answer.get_num_records())
        else:
            self._header.set_ancount(0)
    
    def get_header(self) -> DNSHeader:
        return self._header

    def add_question(self, q: DNSQuestion) -> None:
        self._questions.append(q)
        self._header.set_qdcount(len(self._questions))

    def get_questions(self) -> list[DNSQuestion]:
        return self._questions

    def add_answer(self, a: DNSAnswer) -> None:
        """Add a DNSAnswer to self. Updates self._header._an_count"""
        self._answer = a
        self._header.set_ancount(self._answer.get_num_records())

    def get_answer(self) -> DNSAnswer:
        return self._answer



class DNSAnswer:
    def __init__(self) -> None:
        self._records: list[ResourceRecord] = []

    def add_resource_record(self, rr: ResourceRecord) -> None:
        self._records.append(rr)

    def get_num_records(self) -> int:
        return len(self._records)

    def get_records(self):
        return self._records



@dataclass
class ResourceRecord:
    domain_name: str
    type: DNSRecordType
    time_to_live: int
    rdlength: int = 0
    rdata: bytes = None



class DNSQuestion:
    def __init__(self, domain_name: str, record_type: DNSRecordType) -> None:
        if not isinstance(record_type, DNSRecordType):
            raise ValueError("record_type is not a valid DNSRecordType")

        self.domain_name = domain_name

        self.record_type = record_type


class DNSHeaderFlags:
    def __init__(self, data: int | None = None) -> None:
        if data and not isinstance(data, int):
            raise ValueError("DNSHeaderFlags can only be passed an int, was given type: ", type(data))

        if data:
            self._flags = data
        else:
            self._flags = 0

    def __int__(self) -> int:
        return self._flags

    def toggle_is_resp(self) -> None:
        """Set header flag for if query or response"""
        self._flags ^= 1 << 15

    def is_resp(self) -> bool:
        return bool(self._flags & (1 << 15))

    def set_opcode(self, opcode: int) -> None:
        if not (0 <= opcode <= 0xF):
            raise ValueError("opcode must be a 4 bit unsigned int")
        # Clear opcode bits
        OPCODE_MASK = 0xF << 11
        self._flags = self._flags & ~OPCODE_MASK

        # Set opcode
        self._flags |= opcode << 11

    def get_opcode(self) -> int:
        return (self._flags >> 11) & 0xF

    def toggle_is_auth_ans(self) -> None:
        """Set header flag for if authoratative answer"""
        self._flags ^= 1 << 10

    def is_auth_ans(self) -> bool:
        return bool(self._flags & (1 << 10))

    def toggle_truncated_msg(self) -> None:
        """Set header flag for if truncated message"""
        self._flags ^= 1 << 9

    def is_truncated(self) -> bool:
        return bool(self._flags & (1 << 9))

    def toggle_recursion_desired(self) -> None:
        self._flags ^= 1 << 8

    def is_recursion_desired(self) -> bool:
        return bool(self._flags & (1 << 8))

    def toggle_recursion_available(self) -> None:
        self._flags ^= 1 << 7

    def is_recursion_available(self) -> bool:
        return bool(self._flags & (1 << 7))

    def set_reserved(self, reserved: int) -> None:
        if not (0 <= reserved <= 0x7):
            raise ValueError("reserved must be a 3 bit unsigned int")
        # Clear reserved bits
        RESERVED_MASK = 0x7 << 4
        self._flags = self._flags & -RESERVED_MASK

        # Set reserved
        self._flags |= reserved << 4

    def get_reserved(self) -> int:
        """Return reserved 3 bits in int format"""
        return (self._flags >> 4) & 0x7

    def set_response_code(self, resp_code: int) -> None:
        if not (0 <= resp_code <= 0xF):
            raise ValueError("resp_code must be a 4 bit unsigned int")
        # Clear resp_code bits, ie. 4 right most bits
        RESP_CODE_MASK = 0xF
        self._flags = self._flags & -RESP_CODE_MASK

        # Set resp_code
        self._flags |= resp_code

    def get_response_code(self) -> int:
        """Return response code 4 bits in int format"""
        return (self._flags) & 0xF


class DNSHeader:
    def __init__(
        self,
        packetid: int = 0,
        flags: DNSHeaderFlags = DNSHeaderFlags(),
        qd_count: int = 0,
        ans_count: int = 0,
        auth_rec_count: int = 0,
        add_rec_count: int = 0,
    ) -> None:
        self.set_packetid(packetid)
        self.flags = flags
        self._qd_count = qd_count
        self._an_count = ans_count
        self.auth_rec_count = auth_rec_count
        self.add_rec_count = add_rec_count

    def get_packetid(self) -> int:
        return self._packetid

    def set_packetid(self, pid: int) -> int:
        if not (0 <= pid <= 0xFFFF):
            raise ValueError("packetid must be a 2-byte unsigned integer")
        self._packetid = pid

    def get_qdcount(self) -> int:
        return self._qd_count

    def set_qdcount(self, qd_count: int) -> int:
        if not (0 <= qd_count <= 0xFFFF):
            raise ValueError("qd_count must be a 2-byte unsigned integer")

        self._qd_count = qd_count

    def get_ancount(self) -> int:
        return self._an_count

    def set_ancount(self, an_count: int) -> int:
        if not (0 <= an_count <= 0xFFFF):
            raise ValueError("an_count must be a 2-byte unsigned integer")

        self._an_count = an_count
