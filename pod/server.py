"""Answers ICMP echo requests with slices of a gzipped file.

The kernel must not answer pings itself, or the client sees two replies.
On Linux set net.ipv4.icmp_echo_ignore_all=1 (docker-compose.yml does this).
"""
import argparse
import gzip
import hashlib
import json
import socket
import sys
from pathlib import Path

from .proto import (CHUNK, ECHO_REPLY, ECHO_REQUEST, MANIFEST, build_echo,
                    parse_ip, reply_payload, split_payload)


def prepare(path):
    raw = Path(path).read_bytes()
    packed = gzip.compress(raw, 9, mtime=0)
    chunks = [packed[i:i + CHUNK] for i in range(0, len(packed), CHUNK)]
    manifest = json.dumps({
        "name": Path(path).name,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "chunks": len(chunks),
    }).encode()
    return manifest, chunks


def serve(path):
    manifest, chunks = prepare(path)
    print(f"serving {Path(path).name}: {len(chunks)} chunks of up to {CHUNK} bytes", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sent = 0
    while True:
        raw, (addr, _) = sock.recvfrom(65535)
        pkt = parse_ip(raw)
        if not pkt or pkt.type != ECHO_REQUEST:
            continue
        req = split_payload(pkt.payload)
        if not req:
            continue
        index = req[0]
        if index == MANIFEST:
            body = manifest
        elif index < len(chunks):
            body = chunks[index]
        else:
            continue
        reply = build_echo(ECHO_REPLY, pkt.ident, pkt.seq, reply_payload(index, body))
        sock.sendto(reply, (addr, 0))
        sent += 1
        if sent % 500 == 0:
            print(f"{sent} replies sent", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", help="file to serve, for example wad/doom1.wad")
    args = ap.parse_args()
    try:
        serve(args.file)
    except PermissionError:
        sys.exit("raw sockets need root or CAP_NET_RAW")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
