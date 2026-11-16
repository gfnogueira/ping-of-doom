"""Minimal pcap and pcapng reader. Yields (timestamp, ip_packet_bytes) for IPv4 frames."""
import struct

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100

PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

# magic bytes -> (byte order, timestamp fraction divisor)
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}


def strip_link(linktype, frame):
    if linktype == 1:  # ethernet
        offset = 12
        ethertype = struct.unpack("!H", frame[offset:offset + 2])[0]
        if ethertype == ETHERTYPE_VLAN:
            offset += 4
            ethertype = struct.unpack("!H", frame[offset:offset + 2])[0]
        return frame[offset + 2:] if ethertype == ETHERTYPE_IPV4 else None
    if linktype == 113:  # linux cooked
        proto = struct.unpack("!H", frame[14:16])[0]
        return frame[16:] if proto == ETHERTYPE_IPV4 else None
    if linktype == 276:  # linux cooked v2
        proto = struct.unpack("!H", frame[0:2])[0]
        return frame[20:] if proto == ETHERTYPE_IPV4 else None
    if linktype == 0:  # bsd loopback
        return frame[4:]
    if linktype == 101:  # raw ip
        return frame
    raise ValueError(f"unsupported link type {linktype}")


def read_pcap(path):
    with open(path, "rb") as f:
        header = f.read(24)
        if header[:4] == PCAPNG_SHB:
            f.seek(0)
            yield from _read_pcapng(f)
            return
        if len(header) < 24 or header[:4] not in MAGICS:
            raise ValueError("not a pcap or pcapng file")
        order, divisor = MAGICS[header[:4]]
        linktype = struct.unpack(order + "I", header[20:24])[0]
        while True:
            record = f.read(16)
            if len(record) < 16:
                return
            sec, frac, caplen, _ = struct.unpack(order + "IIII", record)
            frame = f.read(caplen)
            packet = strip_link(linktype, frame)
            if packet:
                yield sec + frac / divisor, packet


def _read_pcapng(f):
    order = "<"
    interfaces = []  # (linktype, timestamp divisor)
    while True:
        head = f.read(8)
        if len(head) < 8:
            return
        if head[:4] == PCAPNG_SHB:
            # the byte order magic follows the block length
            magic = f.read(4)
            order = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            length = struct.unpack(order + "I", head[4:8])[0]
            f.read(length - 12)
            interfaces = []
            continue
        btype, length = struct.unpack(order + "II", head)
        body = f.read(length - 12)
        f.read(4)
        if btype == 1:  # interface description
            linktype = struct.unpack(order + "H", body[:2])[0]
            interfaces.append((linktype, _tsresol(order, body[8:])))
        elif btype == 6:  # enhanced packet
            iface, hi, lo, caplen = struct.unpack(order + "IIII", body[:16])
            if iface >= len(interfaces):
                continue
            linktype, divisor = interfaces[iface]
            try:
                packet = strip_link(linktype, body[20:20 + caplen])
            except ValueError:
                continue
            if packet:
                yield ((hi << 32) | lo) / divisor, packet


def _tsresol(order, options):
    # option code 9 is if_tsresol, default is microseconds
    pos = 0
    while pos + 4 <= len(options):
        code, size = struct.unpack(order + "HH", options[pos:pos + 4])
        if code == 0:
            break
        if code == 9 and size >= 1:
            value = options[pos + 4]
            return float(2 ** (value & 0x7F)) if value & 0x80 else 10.0 ** value
        pos += 4 + (size + 3) // 4 * 4
    return 1e6
