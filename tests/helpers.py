"""Builds tiny in-memory captures so the detector can be tested without a network."""
import random
import socket
import struct

from pod.proto import ECHO_REPLY, ECHO_REQUEST, build_echo

CLIENT = "10.0.0.5"
HOST = "10.0.0.9"
rng = random.Random(1)


def ip_packet(src, dst, icmp):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + icmp


def echo_pair(ts, seq, request_body, reply_body, ident=7):
    req = ip_packet(CLIENT, HOST, build_echo(ECHO_REQUEST, ident, seq, request_body))
    rep = ip_packet(HOST, CLIENT, build_echo(ECHO_REPLY, ident, seq, reply_body))
    return [(ts, req), (ts + 0.0005, rep)]


def ping_like(count, size, interval):
    """Honest ping: reply mirrors the request, payload is a repeating pattern."""
    body = bytes(i % 256 for i in range(size))
    frames = []
    for n in range(count):
        frames += echo_pair(n * interval, n, body, body)
    return frames


def tunnel_like(count, interval):
    """Small requests answered with large random replies."""
    frames = []
    for n in range(count):
        frames += echo_pair(n * interval, n, b"\x00" * 8, rng.randbytes(1400))
    return frames
