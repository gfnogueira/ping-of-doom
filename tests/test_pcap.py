import os
import struct
import tempfile
import unittest

from pod.pcap import read_pcap
from tests.helpers import echo_pair


def block(btype, body):
    pad = b"\x00" * (-len(body) % 4)
    total = 12 + len(body) + len(pad)
    return struct.pack("<II", btype, total) + body + pad + struct.pack("<I", total)


def pcapng(frames):
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    out = shb + idb
    for ts, frame in frames:
        usec = int(ts * 1e6)
        body = struct.pack("<IIIII", 0, usec >> 32, usec & 0xFFFFFFFF, len(frame), len(frame))
        out += block(6, body + frame)
    return out


class PcapngTest(unittest.TestCase):
    def test_reads_packets(self):
        pair = echo_pair(1.0, 1, b"abcd" * 8, b"abcd" * 8)
        frames = [(ts, b"\x00" * 12 + b"\x08\x00" + raw) for ts, raw in pair]
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(pcapng(frames))
        try:
            packets = list(read_pcap(tmp.name))
        finally:
            os.unlink(tmp.name)
        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0][1], pair[0][1])

    def test_rejects_other_files(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"not a capture at all, just text")
        try:
            with self.assertRaises(ValueError):
                list(read_pcap(tmp.name))
        finally:
            os.unlink(tmp.name)
