import binascii
from scapy.all import Packet, IntField

TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

HEADER_SIZE = 16
MAX_PAYLOAD_SIZE = 1456


class PacketHeader(Packet):
    name = "PacketHeader"
    fields_desc = [
        IntField("type", 0),
        IntField("seq_num", 0),
        IntField("length", 0),
        IntField("checksum", 0),
    ]


def compute_checksum(pkt):
    return binascii.crc32(bytes(pkt)) & 0xFFFFFFFF


def build_packet(pkt_type, seq_num, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    hdr = PacketHeader(
        type=pkt_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0,
    )
    hdr.checksum = compute_checksum(hdr / payload)
    return bytes(hdr / payload)


def unpack_packet(raw_bytes):
    if len(raw_bytes) < HEADER_SIZE:
        return None, None
    hdr = PacketHeader(raw_bytes[:HEADER_SIZE])
    if len(raw_bytes) < HEADER_SIZE + hdr.length:
        return None, None
    payload = raw_bytes[HEADER_SIZE : HEADER_SIZE + hdr.length]
    received_checksum = hdr.checksum
    hdr.checksum = 0
    if received_checksum != compute_checksum(hdr / payload):
        return None, None
    return hdr, payload
