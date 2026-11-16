import unittest

from pod.proto import (ECHO_REQUEST, MAGIC, build_echo, checksum, parse_ip,
                       reply_payload, request_payload, split_payload)
from tests.helpers import CLIENT, HOST, ip_packet


class ProtoTests(unittest.TestCase):
    def test_checksum_of_valid_packet_is_zero(self):
        pkt = build_echo(ECHO_REQUEST, 1234, 9, b"hello")
        self.assertEqual(checksum(pkt), 0)

    def test_odd_length_payload(self):
        pkt = build_echo(ECHO_REQUEST, 1, 1, b"abc")
        self.assertEqual(checksum(pkt), 0)

    def test_parse_roundtrip(self):
        icmp = build_echo(ECHO_REQUEST, 4242, 77, b"payload")
        pkt = parse_ip(ip_packet(CLIENT, HOST, icmp))
        self.assertEqual((pkt.src, pkt.dst, pkt.ident, pkt.seq), (CLIENT, HOST, 4242, 77))
        self.assertEqual(pkt.payload, b"payload")

    def test_non_icmp_is_ignored(self):
        raw = bytearray(ip_packet(CLIENT, HOST, b"\x00" * 8))
        raw[9] = 6  # tcp
        self.assertIsNone(parse_ip(bytes(raw)))

    def test_payload_split(self):
        self.assertEqual(split_payload(request_payload(5)), (5, b""))
        self.assertEqual(split_payload(reply_payload(5, b"data")), (5, b"data"))
        self.assertIsNone(split_payload(b"nope"))
        self.assertTrue(request_payload(0).startswith(MAGIC))


if __name__ == "__main__":
    unittest.main()
