#!/usr/bin/env bash
# Runs the whole lab: serve, pull over ICMP, capture, detect, then play.
# PLAY=0 skips launching the game.
set -euo pipefail
cd "$(dirname "$0")"

python3 -m pod.banner --pin
trap 'python3 -m pod.banner --unpin' EXIT
./fetch-wad.sh
mkdir -p out && rm -f out/*

docker compose up -d --build server sniffer
sleep 2
docker compose run --rm -T client
sleep 1  # let tcpdump drain its buffer
docker compose stop sniffer > /dev/null
docker compose down > /dev/null

echo
python3 -m pod.detect out/capture.pcap || true

python3 -m pod.banner --unpin
trap - EXIT

if [ "${PLAY:-1}" = "1" ]; then
  if command -v chocolate-doom > /dev/null; then
    chocolate-doom -iwad out/doom1.wad
  else
    echo "Install chocolate-doom to play it: brew install chocolate-doom"
  fi
fi
