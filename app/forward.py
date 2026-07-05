import socket
import ipaddress
from app.message import DNSMessage
from app.decode import DNSDecoder


class ForwardingAddress:
    def __init__(self, address: str):
        host, _, port = address.partition(":")
        try:
            self.host = ipaddress.ip_address(host) 
        except ValueError as err:
            raise ValueError(f"Expected valid IP to forward got: {host}") from err
        
        try:
            self.port = int(port)
        except ValueError as err:
            raise ValueError(f"Port should be an int got {port}") from err

    def get_addr(self) -> tuple[str, int]:
        return (self.get_host(), self.get_port())
    
    def get_host(self) -> str:
        return str(self.host)

    def get_port(self) -> int:
        return self.port

def forward_query(fa: ForwardingAddress, data: bytes) -> DNSMessage:
    """Forward data to fa, returns response decoded"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(data, fa.get_addr())
        # Read back reply
        buf, source = client.recvfrom(512)
        d = DNSDecoder()
        return d.decode_message(buf)


    