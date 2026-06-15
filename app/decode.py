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


def decode_labels(labels: bytes) -> tuple[str, bytes]:
    """
    Decodes a DNS label sequence from a buffer of bytes.
    Returns: The decoded label sequence and any remaining bytes in the buffer
    """
    out_list = []
    index = 0

    while index <= len(labels):

        # Read indexed byte to get length
        label_len = labels[index]
        if label_len == 0:
            return ".".join(out_list), labels[index+1:]

        # Move index past length label
        index += 1
        
        # Add new label, is always from index to index + label_len
        out_list.append(labels[index:index+label_len].decode())

        index += label_len
    
    raise ValueError("No null byte found in label sequence: ", labels)
    

class DNSDecoder:
    # Fields used if decoding whole DNSMessage
    _remaining_bytes: bytes
    _offset: int = 0

    def decode_message(self, b: bytes) -> DNSMessage:
        """Handles decoding whole message as buffer of bytes instead of individually creating elements"""
        self._remaining_bytes = b
        self._offset = 0

        m = DNSMessage()
        
        h = self.decode_header((self._remaining_bytes[:12])) # First 12 are header
        m.set_header(h)
        self._remaining_bytes = self._remaining_bytes[12:]

        q = self.decode_question(self._remaining_bytes)
        m.add_question(q)

        return m

    def decode_header(self, b: bytes) -> DNSHeader:
        chunks = struct.unpack_from("!6H", b, 0)

        return DNSHeader(chunks[0], DNSHeaderFlags(chunks[1]), chunks[2], chunks[3], chunks[4], chunks[5])

    def decode_answer(self, b: bytes) -> DNSAnswer:
        pass

    def decode_header_flags(self, b: bytes) ->  DNSHeaderFlags:
        pass

    def decode_question(self, b: bytes) -> DNSQuestion:
        labels, remainder = decode_labels(b)   
        try:
            record_type, _ = struct.unpack_from("!HH", remainder) # Record class is ignored, always assumed 1 / IN

            # Move offset and remaining_bytes to allow for reading whole answer if in decode_message()
            self._offset += 4 
            self._remaining_bytes = remainder
        except ValueError as e:
            raise ValueError("Expected ") from e
        
        return DNSQuestion(labels, DNSRecordType(record_type))

    def decode_resource_record(self, b: bytes) -> ResourceRecord:
        pass