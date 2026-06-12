from app.message import (
    DNSMessage,
    DNSAnswer,
    DNSHeader,
    DNSHeaderFlags,
    DNSQuestion,
    DNSRecordType,
    ResourceRecord,
)
from typing import Callable
import struct


def encode_ipv4(ip_addr: str) -> bytes:
    str_elements = ip_addr.split(".")
    if len(str_elements) != 4:
        raise ValueError(
            "Invalid IP address given, expected 4 numbers separated by '.', got: ",
            ip_addr,
        )

    out = bytearray()
    for el in str_elements:
        out.extend(struct.pack("B", int(el)))

    return bytes(out)


def record_rdata_handler_factory(
    record_type: DNSRecordType,
) -> Callable[[str], bytearray]:
    """Returns an appropriate function to encode rdata, passed as a python string, based on record_type
    Also length is returned for rdlength
    bytearray is returned to allow for extension.
    """
    if record_type == DNSRecordType.A:
        return encode_ipv4

    elif record_type == DNSRecordType.CNAME:
        return encode_domain_name

    else:
        raise ValueError("Record type not supported")


def encode_domain_name(domain_name: str) -> bytes:
    """Helper function to turn a list of strings into encodes labels for DNS questions and resource records"""
    labels = domain_name.split(".")

    label_buf = bytearray()
    for label in labels:
        label_buf.extend(struct.pack("B", len(label)))  # Put length byte in initiall
        for char in label:
            label_buf.extend(struct.pack("B", ord(char)))

    # NULL byte to terminate labels
    label_buf.extend(struct.pack("B", 0))

    return bytes(label_buf)


class DNSEncoder:
    def encode_message(self, m: DNSMessage) -> bytes:
        out = bytearray()
        out.extend(self.encode_header(m.get_header()))

        for q in m.get_questions():
            out.extend(self.encode_question(q))

        out.extend(self.encode_answer(m.get_answer()))
        return bytes(out)

    def encode_header(self, h: DNSHeader) -> bytes:
        return struct.pack(
            "!HHHHHH",
            h.get_packetid(),
            int(h.flags),
            h.get_qdcount(),
            h.get_ancount(),
            h.auth_rec_count,
            h.add_rec_count,
        )

    def encode_answer(self, a: DNSAnswer) -> bytes:
        out = bytearray()
        for record in a.get_records():
            out.extend(self.encode_resource_record(record))
        return bytes(out)

    def encode_header_flags(self, hf: DNSHeaderFlags) -> bytes:
        return struct.pack("!H", int(hf))

    def encode_question(self, q: DNSQuestion) -> bytes:
        """Output self._len_labels in DNS question format

        ie. \x05label\x00
        """
        packet_buf = bytearray()
        packet_buf.extend(encode_domain_name(q.domain_name))
        # Add Type bytes
        packet_buf.extend(struct.pack("!H", q.record_type.value))

        # NOTE: Only going to implement Class type 1
        packet_buf.extend(struct.pack("!H", 1))

        return bytes(packet_buf)

    def encode_resource_record(self, rr: ResourceRecord) -> bytes:
        record_buf = bytearray()
        record_buf.extend(encode_domain_name(rr.domain_name))

        handler = record_rdata_handler_factory(rr.type)

        encoded_rdata = handler(rr.rdata)
        rr.rdlength = len(encoded_rdata)

        record_buf.extend(
            struct.pack(
                "!HHIH",
                rr.type.value,
                1,  # NOTE: only supporting class IN
                rr.time_to_live,
                rr.rdlength,
            )
        )

        record_buf.extend(encoded_rdata)

        return bytes(record_buf)
