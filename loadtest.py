#!/usr/bin/env python3
"""
Load test for the SIP Blocklist Responder (early-media edition).

Spins up N concurrent virtual callers, each placing a real SIP call to a BLOCKED
number and driving the full early-media flow:

    INVITE -> 183 Session Progress -> RTP announcement (captured) -> 486 Busy Here

It verifies, per call, that the 183 arrived, the full ~5.3s / ~264-packet audio
streamed, and the final block code came back -- then prints an aggregate summary.

RUN THIS ON THE VM (or any host on the same L3 as the server). Each caller
advertises 127.0.0.1 as its media address so the server's RTP returns locally
and can be counted; from behind NAT the audio would never arrive.

    python3 loadtest.py --calls 15
    python3 loadtest.py --calls 15 --server 127.0.0.1:5060 --timeout 15
"""
from __future__ import annotations

import argparse
import json
import random
import select
import socket
import statistics
import threading
import time
import uuid


def build_invite(number: str, advertise: str, media_ip: str,
                 rtp_port: int, lport: int, cid: str) -> bytes:
    uri = f"sip:{number}@{advertise}"  # host is cosmetic; responder reads the user part
    sdp = (
        "v=0\r\n"
        f"o=loadtest {random.randint(1, 10**6)} 1 IN IP4 {media_ip}\r\n"
        "s=loadtest\r\n"
        f"c=IN IP4 {media_ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {rtp_port} RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
    )
    msg = (
        f"INVITE {uri} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {media_ip}:{lport};branch=z9hG4bK-{cid}\r\n"
        f"From: <sip:loadtest@test>;tag={cid}\r\n"
        f"To: <{uri}>\r\n"
        f"Call-ID: {cid}@loadtest\r\n"
        "CSeq: 1 INVITE\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(sdp)}\r\n\r\n"
        f"{sdp}"
    )
    return msg.encode()


def run_caller(idx: int, number: str, server: tuple[str, int], advertise: str,
               media_ip: str, timeout: float, results: dict) -> None:
    rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp.bind((media_ip, 0)); rtp_port = rtp.getsockname()[1]
    sip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sip.bind((media_ip, 0)); lport = sip.getsockname()[1]
    cid = uuid.uuid4().hex[:12]

    rec = {"idx": idx, "number": number, "got_183": False, "final": None,
           "rtp_packets": 0, "rtp_span": 0.0, "duration": 0.0, "error": None}
    first_rtp = last_rtp = None
    t0 = time.time()
    try:
        sip.sendto(build_invite(number, advertise, media_ip, rtp_port, lport, cid), server)
        deadline = t0 + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([sip, rtp], [], [], 0.5)
            for s in ready:
                if s is sip:
                    data, _ = sip.recvfrom(4096)
                    line = data.decode(errors="ignore").split("\r\n", 1)[0]
                    if " 183 " in line:
                        rec["got_183"] = True
                    elif any(f" {c} " in line for c in ("486", "603", "404", "200")):
                        rec["final"] = line.split("SIP/2.0 ", 1)[-1].strip()
                else:
                    rtp.recvfrom(2048); rec["rtp_packets"] += 1
                    now = time.time()
                    if first_rtp is None:
                        first_rtp = now
                    last_rtp = now
            if rec["final"] and not rec["final"].startswith("404"):
                break  # got the post-announcement final response
    except Exception as e:  # noqa: BLE001
        rec["error"] = f"{type(e).__name__}: {e}"
    finally:
        rec["duration"] = round(time.time() - t0, 2)
        rec["rtp_span"] = round((last_rtp - first_rtp), 2) if first_rtp else 0.0
        results[idx] = rec
        rtp.close(); sip.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="Concurrent early-media load test")
    ap.add_argument("--calls", type=int, default=15, help="concurrent calls (default 15)")
    ap.add_argument("--server", default="127.0.0.1:5060", help="host:port of the responder")
    ap.add_argument("--media-ip", default="127.0.0.1",
                    help="local IP callers advertise for RTP (must reach back here)")
    ap.add_argument("--timeout", type=float, default=15.0, help="per-call timeout seconds")
    ap.add_argument("--blocklist", default="/opt/sip-blocklist/blocklist.json",
                    help="pick blocked numbers from here (so calls hit the block path)")
    args = ap.parse_args()

    host, _, port = args.server.partition(":")
    server = (host, int(port or 5060))
    advertise = host  # R-URI host (cosmetic; the responder only reads the number)

    with open(args.blocklist) as f:
        pool = json.load(f)
    numbers = [random.choice(pool) for _ in range(args.calls)]

    print(f"Launching {args.calls} concurrent calls to {server[0]}:{server[1]} "
          f"(blocked numbers, early-media)\n")
    results: dict = {}
    threads = [threading.Thread(target=run_caller,
                                args=(i, numbers[i], server, advertise, args.media_ip,
                                      args.timeout, results))
               for i in range(args.calls)]
    wall0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.time() - wall0

    print(f"{'#':>3}  {'number':<13} {'183':>4} {'final':<12} {'rtp_pkts':>8} {'span_s':>7} {'dur_s':>6}")
    print("-" * 62)
    full_ok = 0
    rtp_counts = []
    for i in sorted(results):
        r = results[i]
        rtp_counts.append(r["rtp_packets"])
        ok = r["got_183"] and (r["final"] or "").startswith("486") and r["rtp_packets"] >= 250
        full_ok += 1 if ok else 0
        flag = "" if ok else "  <-- check"
        fin = r["error"] or (r["final"] or "-")
        print(f"{r['idx']:>3}  {r['number']:<13} {('yes' if r['got_183'] else 'NO'):>4} "
              f"{fin:<12} {r['rtp_packets']:>8} {r['rtp_span']:>7} {r['duration']:>6}{flag}")

    print("-" * 62)
    print(f"Fully-successful calls (183 + >=250 RTP pkts + 486): {full_ok}/{args.calls}")
    if rtp_counts:
        print(f"RTP packets/call: min={min(rtp_counts)} max={max(rtp_counts)} "
              f"mean={statistics.mean(rtp_counts):.1f}  (expect ~264 for a 5.3s clip)")
    print(f"Wall-clock for all {args.calls} concurrent calls: {wall:.1f}s")


if __name__ == "__main__":
    main()
