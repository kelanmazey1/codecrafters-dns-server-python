from app.message import (
    DNSMessage,
    DNSAnswer,
    DNSHeader,
    DNSHeaderFlags,
    DNSQuestion,
    DNSRecordType,
    ResourceRecord,
)
import struct


class DNSDecoder:
    # TODO: There might be a clever way of doing this but it's late
    _buffer: bytes  # Holds the initial bytes when decoding whole message
    _remaining_index: int  # Holds the remaining bytes to be inspected

    def decode_message(self, b: bytes) -> DNSMessage:
        """Handles decoding whole message as buffer of bytes instead of individually creating elements"""
        self._buffer = b
        self._remaining_index = 12

        m = DNSMessage()

        h = self.decode_header(
            (self._buffer[: self._remaining_index])
        )  # First 12 are header
        m.set_header(h)
        for _ in range(m.get_header().get_qdcount()):
            q = self.decode_question(self._buffer[self._remaining_index :])
            m.add_question(q)

        return m

    def decode_header(self, b: bytes) -> DNSHeader:
        chunks = struct.unpack_from("!6H", b, 0)

        return DNSHeader(
            chunks[0],
            DNSHeaderFlags(chunks[1]),
            chunks[2],
            chunks[3],
            chunks[4],
            chunks[5],
        )

    def decode_answer(self, b: bytes) -> DNSAnswer:
        pass

    def decode_header_flags(self, b: bytes) -> DNSHeaderFlags:
        pass

    def decode_question(self, b: bytes) -> DNSQuestion:
        labels, remainder = self.decode_labels(b)
        self._remaining_index = len(self._buffer) - len(remainder)

        try:
            record_type, _ = struct.unpack_from(
                "!HH", remainder
            )  # Record class is ignored, always assumed 1 / IN
            self._remaining_index += 4  # We add 4 to the remainder to skip past the record type and class just unpacked
        except ValueError as e:
            raise ValueError(
                "Expected to unpack record type and class from next 4 bytes"
            ) from e

        return DNSQuestion(".".join(labels), DNSRecordType(record_type))

    def decode_labels(self, labels: bytes) -> tuple[list[str | int], bytes]:
        """
        Decodes a DNS label sequence from a buffer of bytes.
        Returns: The decoded label sequence of either labels or points, and any remaining bytes in the buffer
        """
        out_list = []
        index = 0

        while index <= len(labels):
            # NOTE: 0xc0 = 11000000 = 192 labels are max 63 chars long so we know it must be a pointer byte

            # If byte is start of a pointer, get byte position, recursively call to return label
            if labels[index] & 0xC0 == 0xC0:
                label_position = labels[index + 1]

                # Read label from label_position, returns the label being pointed to and appends
                resolved_label, _ = self.decode_labels(self._buffer[label_position:])
                out_list.extend(resolved_label)

                # Return bytes after label_position pointer
                return out_list, labels[index + 2 :]

            # Read indexed byte to get length
            label_len = labels[index]
            if label_len == 0:
                return out_list, labels[index + 1 :]

            # Move index past length label
            index += 1

            # Add new label, is always from index to index + label_len
            out_list.append(labels[index : index + label_len].decode())

            index += label_len

        raise ValueError("No null byte found in label sequence: ", labels)

    def decode_resource_record(self, b: bytes) -> ResourceRecord:
        pass
