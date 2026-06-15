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

def get_pointer(label: bytes) -> int | None:
    """Gets the index of the label if l is a pointer is None if a regular label"""
    # Check if 1st byte == 11000000 ie. has 11 pointer indicator
    if not label[0] & 0xc0 == 0xc0:
        return None
    else:
        # Only need number from 2nd byte as remaining 6 octets of label[0] would point out of DNS packet range
        return int.from_bytes(label[1])

    

    

class DNSDecoder:
    #TODO: There might be a clever way of doing this but it's late
    _buffer: bytes # Holds the initial bytes when decoding whole message
    _remaining_index: int # Holds the remaining bytes to be inspected

    def decode_message(self, b: bytes) -> DNSMessage:
        """Handles decoding whole message as buffer of bytes instead of individually creating elements"""
        self._buffer = b
        self._remaining_index = 12

        m = DNSMessage()
        
        h = self.decode_header((self._buffer[:self._remaining_index])) # First 12 are header
        m.set_header(h)
        print("m qdcount ", m.get_header().get_qdcount())
        print("h qdcount ", h.get_qdcount())

        for _ in range(m.get_header().get_qdcount()):
            print("Are we adding questions")
            q = self.decode_question(self._buffer[self._remaining_index:])
            m.add_question(q)
            self._remaining_index += len(q)

        return m

    def decode_header(self, b: bytes) -> DNSHeader:
        chunks = struct.unpack_from("!6H", b, 0)

        return DNSHeader(chunks[0], DNSHeaderFlags(chunks[1]), chunks[2], chunks[3], chunks[4], chunks[5])

    def decode_answer(self, b: bytes) -> DNSAnswer:
        pass

    def decode_header_flags(self, b: bytes) ->  DNSHeaderFlags:
        pass

    def decode_question(self, b: bytes) -> DNSQuestion:
        print("decoding questions")
        labels, remainder = self.decode_labels(b)   

        try:
            record_type, _ = struct.unpack_from("!HH", remainder) # Record class is ignored, always assumed 1 / IN
            self._remaining_index = len(self._buffer) - len(remainder)
        except ValueError as e:
            raise ValueError("Expected to unpack record type and class from next 4 bytes") from e
        
        return DNSQuestion(labels, DNSRecordType(record_type))

    def decode_labels(self, labels: bytes) -> tuple[list[str|int], bytes]:
        """
        Decodes a DNS label sequence from a buffer of bytes.
        Returns: The decoded label sequence of either labels or points, and any remaining bytes in the buffer
        """
        out_list = []
        index = 0

        while index <= len(labels):

            # NOTE: 0xc0 = 11000000 = 192 labels are max 63 chars long

            # If byte is start of a pointer, get byte position, recursively call to return label
            if labels[index] & 0xc0 == 0xc0:
                label_position = labels[index+1]
                out_list.append(self.decode_labels(self._buffer[label_position]))
                index += 2
                continue

            # Read indexed byte to get length
            label_len = labels[index]
            if label_len == 0:
                return out_list, labels[index+1]

            # Move index past length label
            index += 1
            
            # Add new label, is always from index to index + label_len
            out_list.append(labels[index:index+label_len].decode())

            index += label_len
        
        raise ValueError("No null byte found in label sequence: ", labels)



    def decode_resource_record(self, b: bytes) -> ResourceRecord:
        pass