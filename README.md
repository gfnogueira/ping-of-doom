# ping-of-doom

[![tests](https://github.com/gfnogueira/ping-of-doom/actions/workflows/test.yml/badge.svg)](https://github.com/gfnogueira/ping-of-doom/actions/workflows/test.yml)
![license](https://img.shields.io/badge/license-MIT-blue)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

**Shareware Doom, delivered inside ICMP echo replies. Plus a detector that catches it.**

![demo](docs/demo.gif)

A server answers `ping`-style packets with a slice of the game. A client glues the
slices back together, checks the hash, and you boot Doom from a file that arrived
over ping. Then a detector reads the capture and calls out the tunnel.

The tunnel is the fun part. The detector is the part worth reusing.

## Try it

You need Docker and Python 3.10+. Works on macOS and Linux.

```sh
git clone https://github.com/gfnogueira/ping-of-doom
cd ping-of-doom
./demo.sh
```

It downloads the shareware WAD, runs the server, a sniffer and the client in
containers, pulls the game over ICMP, runs the detector and opens Doom if
`chocolate-doom` is installed. The transfer takes about a second. No `pip install`,
no scapy, just the Python standard library.

## How it works

```
client asks:     "give me chunk 5"       echo request, 8 byte payload
server answers:  "chunk 5 is: ...."      echo reply, up to 1400 byte payload
```

The server gzips the WAD into 1250 chunks. A manifest chunk carries the name, size
and sha256. The client keeps 32 requests in flight, resends what times out and
checks the hash before writing the file. ICMP payloads can carry any bytes, which is
why tools like ptunnel exist. Nothing here is new. The point is to see it end to end
and learn what it looks like on the wire.

<details>
<summary>Run it step by step, and why it uses containers</summary>

```sh
./fetch-wad.sh                          # shareware doom1.wad, md5 checked
docker compose up -d --build server sniffer
docker compose run --rm client          # rebuilds out/doom1.wad over ICMP
docker compose stop sniffer
python3 -m pod.detect out/capture.pcap
chocolate-doom -iwad out/doom1.wad
```

Raw sockets need root, and the server has to stop the kernel from answering pings
by itself (`net.ipv4.icmp_echo_ignore_all=1`). Docker gives you both without
touching your host.
</details>

## The detector

Same detector, two captures:

| Capture | Echo packets | Verdict |
| --- | --- | --- |
| `ping -c 5 1.1.1.1` and `ping -s 1000 -c 3 1.1.1.1` from a laptop | 16 | ok |
| Doom over ICMP | 2502 | suspicious |

| Check | What it means |
| --- | --- |
| `reply_mismatch` | The reply is not a copy of the request. A real ping always echoes the payload back, a tunnel has to put new data in there |
| `high_entropy` | Payloads that look compressed or encrypted |
| `big_payload` | Echo payloads larger than a normal ping (default 100 bytes) |
| `high_rate` | Too many echo requests per second to one host |

`reply_mismatch` is the strongest signal. The detector ignores this project's
`POD1` marker on purpose, because anyone can change a marker in a minute.

It reads pcap and pcapng, exits with code 1 when something is suspicious, and has
`--json` for scripts and `--help` for the thresholds.

<details>
<summary>Run it on your own traffic</summary>

Find the interface your traffic leaves through, capture, ping, analyze.

```sh
# macOS
IF=$(route get 1.1.1.1 | awk '/interface:/ {print $2}')
# Linux
IF=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')

sudo tcpdump -i "$IF" -U -w /tmp/icmp.pcap icmp &
ping -c 5 1.1.1.1
sudo pkill -INT tcpdump
python3 -m pod.detect /tmp/icmp.pcap
```
</details>

<details>
<summary>Suricata rules</summary>

`rules/suricata.rules` has four rules: large request, large reply, request burst
and this project's marker. I ran them with Suricata 8.0.8 against the demo capture
and they fire. Suricata cannot compare a reply with its request or measure entropy,
so those two checks only exist in the Python detector.
</details>

## Honest limits

* **Size alone gives false positives.** `ping -s 1400` trips the size checks, and the
  Suricata size rules alert on it too. The detector reports a size-only hit as a
  `notice`, not as suspicious.
* **This tunnel is not hidden.** No obfuscation, no timing tricks. A tunnel that
  tries to blend in will be harder to catch, and the detector was not tested
  against one.
* **Lab scale.** The tunnel runs between containers. The detector also ran on real
  ping traffic from a laptop, but not on a busy production network.
* IPv4 and ICMP echo only. Unit tests: `python3 -m unittest discover`.

## Use it on your own machines only

Run this in a lab or on machines you own. Moving data through ICMP on a network you
do not have permission to test can break policy, and in some places the law.

## Credits and license

Inspired by Adam Rice's [doom-over-dns](https://github.com/resumex/doom-over-dns),
which stores Doom in DNS TXT records. Doom is by id Software. The shareware WAD is
free to redistribute and is downloaded at runtime, not stored here.

MIT
