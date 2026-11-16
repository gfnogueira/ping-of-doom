"""Pulls a file from a ping-of-doom server using nothing but ICMP echo requests."""
import argparse
import gzip
import hashlib
import json
import os
import socket
import sys
import time
from collections import deque
from pathlib import Path

from .proto import (ECHO_REPLY, ECHO_REQUEST, MANIFEST, build_echo, parse_ip,
                    request_payload, split_payload)


class Session:
    def __init__(self, server):
        self.dst = socket.gethostbyname(server)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.sock.settimeout(0.2)
        self.ident = int.from_bytes(os.urandom(2), "big")

    def ask(self, index):
        pkt = build_echo(ECHO_REQUEST, self.ident, index & 0xFFFF, request_payload(index))
        self.sock.sendto(pkt, (self.dst, 0))

    def listen(self):
        """Return (index, body) for the next reply meant for us, or None on timeout."""
        try:
            raw, _ = self.sock.recvfrom(65535)
        except socket.timeout:
            return None
        pkt = parse_ip(raw)
        if not pkt or pkt.type != ECHO_REPLY or pkt.src != self.dst or pkt.ident != self.ident:
            return None
        return split_payload(pkt.payload)


def get_manifest(session, tries=10):
    for _ in range(tries):
        session.ask(MANIFEST)
        deadline = time.time() + 1
        while time.time() < deadline:
            reply = session.listen()
            if reply and reply[0] == MANIFEST:
                return json.loads(reply[1])
    sys.exit("no manifest, is the server up?")


def fetch(session, total, window, timeout, delay):
    chunks = {}
    todo = deque(range(total))
    pending = {}
    resent = 0
    last_logged = 0
    tty = sys.stderr.isatty()
    while len(chunks) < total:
        while todo and len(pending) < window:
            index = todo.popleft()
            session.ask(index)
            pending[index] = time.time()
            if delay:
                time.sleep(delay)

        reply = session.listen()
        if reply and reply[0] in pending:
            chunks[reply[0]] = reply[1]
            del pending[reply[0]]

        now = time.time()
        for index, sent_at in list(pending.items()):
            if now - sent_at > timeout:
                session.ask(index)
                pending[index] = now
                resent += 1

        done = len(chunks)
        if tty:
            print(f"\rchunks {done}/{total}  resent {resent}", end="", file=sys.stderr, flush=True)
        elif done % 250 == 0 and done != last_logged:
            print(f"chunks {done}/{total}  resent {resent}", file=sys.stderr, flush=True)
            last_logged = done
    if tty:
        print(file=sys.stderr)
    return b"".join(chunks[i] for i in range(total))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("server", help="hostname or IP of the ping-of-doom server")
    ap.add_argument("--out", default="out/doom1.wad", help="where to write the rebuilt file")
    ap.add_argument("--window", type=int, default=32, help="requests in flight at once")
    ap.add_argument("--timeout", type=float, default=1.0, help="seconds before a request is resent")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds to sleep between requests")
    args = ap.parse_args()

    try:
        session = Session(args.server)
    except PermissionError:
        sys.exit("raw sockets need root or CAP_NET_RAW")

    manifest = get_manifest(session)
    print(f"manifest: {manifest['name']}, {manifest['size']} bytes in {manifest['chunks']} chunks")

    packed = fetch(session, manifest["chunks"], args.window, args.timeout, args.delay)
    data = gzip.decompress(packed)
    if hashlib.sha256(data).hexdigest() != manifest["sha256"]:
        sys.exit("sha256 mismatch, file is corrupt")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(f"sha256 ok, wrote {out} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
