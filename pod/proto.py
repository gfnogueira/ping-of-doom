"""ICMP helpers and the small wire format shared by server, client and detector."""
import socket
import struct
from collections import namedtuple

ECHO_REPLY = 0
ECHO_REQUEST = 8

MAGIC = b"POD1"
MANIFEST = 0xFFFFFFFF
CHUNK = 1400  # data bytes per reply, keeps the IP packet under a 1500 MTU

Packet = namedtuple("Packet", "src dst type ident seq payload")


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo(icmp_type, ident, seq, payload):
    header = struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq)
    csum = checksum(header + payload)
    return struct.pack("!BBHHH", icmp_type, 0, csum, ident, seq) + payload


def parse_ip(raw):
    """Parse a raw IPv4 packet. Returns a Packet for ICMP echo, else None."""
    if len(raw) < 28 or raw[9] != 1:
        return None
    ihl = (raw[0] & 0x0F) * 4
    if len(raw) < ihl + 8:
        return None
    icmp_type, _code, _csum, ident, seq = struct.unpack("!BBHHH", raw[ihl:ihl + 8])
    if icmp_type not in (ECHO_REQUEST, ECHO_REPLY):
        return None
    return Packet(
        socket.inet_ntoa(raw[12:16]),
        socket.inet_ntoa(raw[16:20]),
        icmp_type,
        ident,
        seq,
        raw[ihl + 8:],
    )


def request_payload(index):
    return MAGIC + struct.pack("!I", index)


def reply_payload(index, body):
    return MAGIC + struct.pack("!I", index) + body


def split_payload(payload):
    """Return (index, body) for a ping-of-doom payload, or None."""
    if len(payload) < 8 or not payload.startswith(MAGIC):
        return None
    return struct.unpack("!I", payload[4:8])[0], payload[8:]
