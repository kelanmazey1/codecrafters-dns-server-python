"""Module to hold objects that comprise a DNS message"""

import struct


class DNSMessage:
    def __init__(self) -> None:
        self.header = bytearray(2)

    
    def set_header(self, h: DNSHeader) -> None:
        self.header = h


class DNSHeader:
    def __init__(self, packetid: int, flags: int, q_count: int, ans_count: int, auth_rec_count: int, add_rec_count: int) -> None:
        self.packetid = packetid
        self.flags = DNSHeaderFlags(flags)
        self.q_count = q_count
        self.ans_count = ans_count
        self.auth_rec_count = auth_rec_count
        self.add_rec_count = add_rec_count

    @classmethod
    def from_bytes(cls, data: bytes) -> DNSHeader:
        chunks = struct.unpack_from("!6H", data, 0)
        
        return cls(chunks[0], chunks[1], chunks[2], chunks[3], chunks[4], chunks[5])
    
    def to_bytes(self) -> bytes:
        return struct.pack(">HHHHHH",
            self.packetid,
            int(self.flags),
            self.q_count,
            self.ans_count,
            self.auth_rec_count,
            self.add_rec_count,
            )
    
    def get_packetid(self) -> int:
        return self.packetid

class DNSHeaderFlags:
    def __init__(self, data: int | None = None) -> None:
        if data:
            self._flags = data
        else:
            self._flags = 0

    def __int__(self) -> int:
        return self._flags

    def toggle_is_query(self) -> None:
        """Set header flag for if query or response""" 
        self._flags ^= (1 << 15)

    def is_query(self) -> bool:
        return bool(self._flags & (1 << 15))

    def set_opcode(self, opcode: int) -> None:
        if not (0 <= opcode <= 0xF):
            raise ValueError("opcode must be a 4 bit unsigned int")
        # Clear opcode bits
        OPCODE_MASK = 0xF << 11
        self._flags = (self._flags & -OPCODE_MASK)

        # Set opcode
        self._flags |= (opcode << 11)
    
    def get_opcode(self) -> int:
        return (self._flags >> 11) & 0xF

    def toggle_is_auth_ans(self) -> None:
        """Set header flag for if authoratative answer""" 
        self._flags ^= (1 << 10)
    
    def is_auth_ans(self) -> bool:
        return bool(self._flags & (1 << 10))
        
    def toggle_truncated_msg(self) -> None:
        """Set header flag for if truncated message""" 
        self._flags ^= (1 << 9)

    def is_truncated(self) -> bool:
        return bool(self._flags & (1 << 9))

    def toggle_recursion_desired(self, data: bytes) -> None:
        self._flags ^= (1 << 8)

    def is_recursion_desired(self) -> bool:
        return bool(self._flags & (1 << 8))

    def toggle_recursion_available(self, data: bytes) -> None:
        self._flags ^= (1 << 7)

    def is_recursion_available(self) -> bool:
        return bool(self._flags & (1 << 7))

    def set_reserved(self, reserved: int) -> None:
        if not (0 <= reserved <= 0x7):
            raise ValueError("reserved must be a 3 bit unsigned int")
        # Clear reserved bits
        RESERVED_MASK = 0x7 << 4
        self._flags = (self._flags & -RESERVED_MASK)

        # Set reserved
        self._flags |= (reserved << 4)
    
    def get_reserved(self) -> int:
        """Return reserved 3 bits in int format"""
        return (self._flags >> 4) & 0x7

    def set_response_code(self, resp_code: int) -> None:
        if not (0 <= resp_code <= 0xF):
            raise ValueError("resp_code must be a 4 bit unsigned int")
        # Clear resp_code bits, ie. 4 right most bits
        RESP_CODE_MASK = 0xF
        self._flags = (self._flags & -RESP_CODE_MASK)

        # Set resp_code
        self._flags |= resp_code

    def get_response_code(self) -> int:
        """Return response code 4 bits in int format"""
        return (self._flags) & 0xF
        
    

