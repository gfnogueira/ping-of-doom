"""Flags ICMP echo traffic that does not behave like ping.

Reads a pcap or pcapng and scores every pair of hosts on four behaviours:

  big_payload     echo payloads larger than a normal ping
  high_entropy    payloads that look compressed or encrypted
  reply_mismatch  echo replies that do not mirror the request payload
  high_rate       too many echo requests per second to one host

It never looks for the ping-of-doom marker on purpose. A marker is trivial
to change, the behaviours above are not.
"""
import argparse
import json
import math
import sys
from collections import Counter, defaultdict, deque

from .color import paint
from .pcap import read_pcap
from .proto import ECHO_REQUEST, parse_ip

VERDICT_COLOR = {"ok": "green", "notice": "yellow", "suspicious": "red"}

MIN_ENTROPY_LEN = 64  # shorter payloads give a meaningless entropy value

RULES = {
    "big_payload": "echo payloads above the size limit",
    "high_entropy": "payloads that look compressed or encrypted",
    "reply_mismatch": "replies that differ from the request they answer",
    "high_rate": "burst of echo requests to one host",
}


def entropy(data):
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_incrementing(data):
    """True for the 0,1,2,... filler that Linux and BSD ping put in the payload.

    Such a filler has near-maximum entropy but is not compressed or encrypted
    data, so the entropy rule has to skip it or `ping -s 1400` gets flagged.
    """
    steps = sum(1 for a, b in zip(data, data[1:]) if (b - a) % 256 == 1)
    return steps >= 0.9 * (len(data) - 1)


def looks_random(data, min_entropy):
    return (len(data) >= MIN_ENTROPY_LEN
            and not is_incrementing(data)
            and entropy(data) >= min_entropy)


def analyze(frames, max_payload=100, max_rate=100, min_entropy=7.0, min_hits=10):
    pairs = defaultdict(Counter)
    windows = defaultdict(deque)
    open_requests = {}
    total = 0

    for ts, raw in frames:
        pkt = parse_ip(raw)
        if not pkt:
            continue
        total += 1
        stats = pairs[tuple(sorted((pkt.src, pkt.dst)))]
        stats["packets"] += 1
        stats["bytes"] += len(pkt.payload)

        if len(pkt.payload) > max_payload:
            stats["big_payload"] += 1
        if looks_random(pkt.payload, min_entropy):
            stats["high_entropy"] += 1

        if pkt.type == ECHO_REQUEST:
            open_requests[(pkt.src, pkt.dst, pkt.ident, pkt.seq)] = pkt.payload
            window = windows[(pkt.src, pkt.dst)]
            window.append(ts)
            while ts - window[0] > 1.0:
                window.popleft()
            stats["peak_rate"] = max(stats["peak_rate"], len(window))
        else:
            sent = open_requests.pop((pkt.dst, pkt.src, pkt.ident, pkt.seq), None)
            if sent is not None and sent != pkt.payload:
                stats["reply_mismatch"] += 1

    findings = []
    for (a, b), stats in sorted(pairs.items()):
        fired = [r for r in ("big_payload", "high_entropy", "reply_mismatch") if stats[r] >= min_hits]
        if stats["peak_rate"] > max_rate:
            fired.append("high_rate")
        if "reply_mismatch" in fired or len(fired) >= 2:
            verdict = "suspicious"
        elif fired:
            verdict = "notice"
        else:
            verdict = "ok"
        findings.append({
            "hosts": [a, b],
            "packets": stats["packets"],
            "payload_bytes": stats["bytes"],
            "peak_rate": stats["peak_rate"],
            "hits": {r: stats[r] for r in ("big_payload", "high_entropy", "reply_mismatch")},
            "rules": fired,
            "verdict": verdict,
        })
    return total, findings


def print_report(path, total, findings):
    print(f"capture: {path}")
    print(f"echo packets: {total}\n")
    if not findings:
        print("no ICMP echo traffic found")
        return
    header = f"{'HOSTS':<34}{'PKTS':>7}{'BIG':>7}{'ENTROPY':>9}{'MISMATCH':>10}{'PEAK/S':>8}  VERDICT"
    print(paint(header, "cyan"))
    for f in findings:
        h = f["hits"]
        row = (f"{' <-> '.join(f['hosts']):<34}{f['packets']:>7}{h['big_payload']:>7}"
               f"{h['high_entropy']:>9}{h['reply_mismatch']:>10}{f['peak_rate']:>8}  ")
        print(row + paint(f["verdict"], VERDICT_COLOR[f["verdict"]]))
    for f in findings:
        if f["rules"]:
            print(f"\n{' <-> '.join(f['hosts'])}")
            for rule in f["rules"]:
                print(f"  {paint(rule, 'yellow')}: {RULES[rule]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pcap", help="pcap or pcapng file with ICMP traffic")
    ap.add_argument("--max-payload", type=int, default=100, help="largest normal echo payload in bytes")
    ap.add_argument("--max-rate", type=int, default=100, help="echo requests per second before flagging")
    ap.add_argument("--min-entropy", type=float, default=7.0, help="bits per byte that count as high")
    ap.add_argument("--min-hits", type=int, default=10, help="packets needed before a rule fires")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    args = ap.parse_args()

    try:
        total, findings = analyze(read_pcap(args.pcap), args.max_payload, args.max_rate,
                                  args.min_entropy, args.min_hits)
    except (OSError, ValueError) as err:
        sys.exit(f"cannot read {args.pcap}: {err}")
    if args.json:
        print(json.dumps({"echo_packets": total, "findings": findings}, indent=2))
    else:
        print_report(args.pcap, total, findings)
    sys.exit(1 if any(f["verdict"] == "suspicious" for f in findings) else 0)


if __name__ == "__main__":
    main()
