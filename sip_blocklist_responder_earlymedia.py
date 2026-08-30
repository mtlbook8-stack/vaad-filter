"""
SIP Blocklist Responder — Early Media edition
---------------------------------------------
Same job as sip_blocklist_responder.py, but for BLOCKED calls it plays a
spoken announcement to the caller *before* rejecting, using SIP early media:

    INVITE
      -> 183 Session Progress (+ SDP offering PCMU/8000)
      -> RTP stream of the announcement audio (one-way, to the caller)
      -> 603 Decline  (after the audio finishes)

ALLOWED calls are handled exactly as before: a 404 so PortaSIP fails over
to the next real carrier. No media is set up for allowed calls.

Audio format:
  The announcement must be raw 8 kHz, mono, G.711 mu-law (PCMU) samples.
  Produce it from any source file with ffmpeg:

      ffmpeg -i announcement.wav -ar 8000 -ac 1 -f mulaw announcement.ulaw

  PCMU is chosen because every SIP system supports it and it needs no
  codec library -- the bytes are streamed as-is, 160 bytes per 20 ms.

NOTE: This is a working prototype of the media path. Hand-rolled RTP is
fine for a single fixed announcement at low concurrency. For high volume
or production hardening, consider a media-capable stack (e.g. aiortc, or
FreeSWITCH/Asterisk for the media leg).
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import re
import socket
import struct
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from blocklist import Blocklist  # shared JSON-backed store (also used by the sync)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("sip-blocklist-em")


def _detect_media_ip() -> str:
    """Resolve the IP this server advertises in SDP for RTP.

    GOTCHA: this must be an address the softswitch can actually route back to,
    or blocked callers get *silence* (the server tells them to receive audio at
    an address that never answers).
      * Directly-addressed Linux host -> the primary outbound IP (auto-detected
        below) is correct.
      * Behind NAT / on a cloud VM with a separate public IP -> you MUST export
        SIP_MEDIA_ADVERTISE_IP=<public IP>; auto-detection only sees the private
        address.
    """
    override = os.environ.get("SIP_MEDIA_ADVERTISE_IP")
    if override:
        return override
    try:  # best-effort primary outbound IPv4 (no packet is actually sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

@dataclass
class ResponderConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 5060
    blocklist_path: Path = Path("blocklist.json")

    # Address advertised in SDP for RTP. Auto-detected from the primary
    # interface; override with SIP_MEDIA_ADVERTISE_IP when behind NAT/cloud.
    # See _detect_media_ip() for the gotcha.
    media_advertise_ip: str = field(default_factory=_detect_media_ip)

    # UDP port range the server uses for outbound RTP streams.
    rtp_port_min: int = 40000
    rtp_port_max: int = 40100

    # Announcement audio: raw 8 kHz mono PCMU. See module docstring.
    announcement_path: Path = Path("announcement.ulaw")

    # 486 Busy Here confirmed as the code Telinta/PortaSIP treats as a hard
    # stop (603 Decline was rerouted by their config). See SETUP.md section 6.
    block_status_code: int = 486
    block_reason: str = "Busy Here"
    passthrough_status_code: int = 404
    passthrough_reason: str = "Not Found"

    control_host: str = "127.0.0.1"
    control_port: int = 5099


# --------------------------------------------------------------------------
# SIP parsing (same as the text-only version)
# --------------------------------------------------------------------------

@dataclass
class SipRequest:
    method: str
    request_uri: str
    headers: dict[str, str]
    raw: bytes
    via: list[str] = field(default_factory=list)
    record_route: list[str] = field(default_factory=list)

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())


class SipMessageParser:
    REQUEST_LINE_RE = re.compile(r"^(\w+)\s+(\S+)\s+SIP/2\.0", re.IGNORECASE)

    @classmethod
    def parse(cls, data: bytes) -> Optional[SipRequest]:
        try:
            text = data.decode("utf-8", errors="ignore")
            lines = text.split("\r\n")
            if not lines:
                return None
            match = cls.REQUEST_LINE_RE.match(lines[0])
            if not match:
                return None
            method, uri = match.group(1).upper(), match.group(2)
            headers: dict[str, str] = {}
            via: list[str] = []
            record_route: list[str] = []
            for line in lines[1:]:
                if not line:
                    break
                if ":" not in line:
                    continue
                name, _, value = line.partition(":")
                lname = name.strip().lower()
                val = value.strip()
                # Preserve multi-valued headers in order. SIP responses are
                # matched to a transaction by the FULL Via stack -- a proxy
                # chain (e.g. PortaSIP) sends several Via headers, and every
                # one must be echoed back or the far end discards the reply.
                if lname in ("via", "v"):
                    via.append(val)
                elif lname == "record-route":
                    record_route.append(val)
                headers[lname] = val
            return SipRequest(
                method=method, request_uri=uri, headers=headers, raw=data,
                via=via, record_route=record_route,
            )
        except Exception:
            log.exception("Failed to parse incoming SIP message")
            return None


class DialedNumberExtractor:
    NUMBER_RE = re.compile(r"sip:([^@;]+)@")

    @classmethod
    def extract(cls, request: SipRequest) -> Optional[str]:
        match = cls.NUMBER_RE.search(request.request_uri)
        if not match:
            return None
        return re.sub(r"\D", "", match.group(1))


class SdpParser:
    """Pulls the caller's RTP address + port out of the INVITE's SDP body."""

    @staticmethod
    def extract_media_endpoint(raw: bytes) -> Optional[tuple[str, int]]:
        try:
            text = raw.decode("utf-8", errors="ignore")
            if "\r\n\r\n" not in text:
                return None
            _, body = text.split("\r\n\r\n", 1)
            conn_ip = None
            media_port = None
            for line in body.split("\n"):
                line = line.strip()
                if line.startswith("c=") and "IN IP4" in line:
                    conn_ip = line.split()[-1]
                elif line.startswith("m=audio"):
                    media_port = int(line.split()[1])
            if conn_ip and media_port:
                return conn_ip, media_port
        except Exception:
            log.exception("Failed to parse SDP from INVITE")
        return None


class Decision(Enum):
    BLOCK = "block"
    PASSTHROUGH = "passthrough"


class CallPolicy:
    def __init__(self, blocklist: Blocklist):
        self._blocklist = blocklist

    def evaluate(self, number: Optional[str]) -> Decision:
        if number and self._blocklist.is_blocked(number):
            return Decision.BLOCK
        return Decision.PASSTHROUGH


# --------------------------------------------------------------------------
# Announcement audio
# --------------------------------------------------------------------------

class Announcement:
    """Holds the raw PCMU announcement bytes, chunked into 20 ms RTP frames."""

    SAMPLES_PER_FRAME = 160  # 8 kHz * 20 ms = 160 samples = 160 bytes (PCMU)

    def __init__(self, path: Path):
        self._frames: list[bytes] = []
        if path.exists():
            data = path.read_bytes()
            self._frames = [
                data[i:i + self.SAMPLES_PER_FRAME]
                for i in range(0, len(data), self.SAMPLES_PER_FRAME)
            ]
            log.info("Loaded announcement: %d frames (~%.1fs) from %s",
                     len(self._frames), len(self._frames) * 0.02, path)
        else:
            log.warning("Announcement file %s not found -- blocked callers "
                        "will get silence before the reject", path)

    @property
    def frames(self) -> list[bytes]:
        return self._frames


# --------------------------------------------------------------------------
# RTP sender
# --------------------------------------------------------------------------

class RtpSender:
    """Streams PCMU frames to the caller's RTP endpoint, paced at 20 ms."""

    PAYLOAD_TYPE_PCMU = 0

    def __init__(self, local_port: int):
        self._local_port = local_port

    async def stream(self, frames: list[bytes], dest_ip: str, dest_port: int) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            local_addr=("0.0.0.0", self._local_port),
        )
        try:
            ssrc = random.randint(0, 0xFFFFFFFF)
            seq = random.randint(0, 0xFFFF)
            timestamp = random.randint(0, 0xFFFFFFFF)

            for frame in frames:
                packet = self._build_packet(frame, seq, timestamp, ssrc)
                transport.sendto(packet, (dest_ip, dest_port))
                seq = (seq + 1) & 0xFFFF
                timestamp = (timestamp + Announcement.SAMPLES_PER_FRAME) & 0xFFFFFFFF
                await asyncio.sleep(0.02)  # 20 ms pacing
        finally:
            transport.close()

    def _build_packet(self, payload: bytes, seq: int, timestamp: int, ssrc: int) -> bytes:
        # RTP header: version 2, no padding/extension/CSRC, PT=0 (PCMU)
        first_byte = 0x80
        second_byte = self.PAYLOAD_TYPE_PCMU
        header = struct.pack("!BBHII", first_byte, second_byte, seq, timestamp, ssrc)
        return header + payload


# --------------------------------------------------------------------------
# SIP response building
# --------------------------------------------------------------------------

class SipResponseBuilder:
    def __init__(self, config: ResponderConfig):
        self._config = config

    def _base_headers(self, request: SipRequest, add_to_tag: bool = True) -> list[str]:
        to_header = request.header("to") or ""
        if add_to_tag and "tag=" not in to_header:
            to_header = f"{to_header};tag={uuid.uuid4().hex[:8]}"
        # Echo the ENTIRE Via stack in order (critical for transaction
        # matching through a proxy chain), then any Record-Route headers.
        via_lines = [f"Via: {v}" for v in request.via] or [f"Via: {request.header('via')}"]
        lines = list(via_lines)
        lines += [f"Record-Route: {rr}" for rr in request.record_route]
        lines += [
            f"From: {request.header('from')}",
            f"To: {to_header}",
            f"Call-ID: {request.header('call-id')}",
            f"CSeq: {request.header('cseq')}",
        ]
        return lines

    def build_183_with_sdp(self, request: SipRequest, rtp_port: int) -> bytes:
        sdp = (
            "v=0\r\n"
            f"o=- {random.randint(1, 1_000_000)} 1 IN IP4 {self._config.media_advertise_ip}\r\n"
            "s=block-announcement\r\n"
            f"c=IN IP4 {self._config.media_advertise_ip}\r\n"
            "t=0 0\r\n"
            f"m=audio {rtp_port} RTP/AVP 0\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=sendonly\r\n"
        ).encode("utf-8")

        head = ["SIP/2.0 183 Session Progress"]
        head += self._base_headers(request)
        head += [
            "Content-Type: application/sdp",
            f"Content-Length: {len(sdp)}",
            "",
            "",
        ]
        return "\r\n".join(head).encode("utf-8") + sdp

    def build_final(self, request: SipRequest, decision: Decision) -> bytes:
        if decision is Decision.BLOCK:
            code, reason = self._config.block_status_code, self._config.block_reason
        else:
            code, reason = self._config.passthrough_status_code, self._config.passthrough_reason
        head = [f"SIP/2.0 {code} {reason}"]
        head += self._base_headers(request)
        head += ["Content-Length: 0", "", ""]
        return "\r\n".join(head).encode("utf-8")

    def build_options_ok(self, request: SipRequest) -> bytes:
        head = ["SIP/2.0 200 OK"]
        head += self._base_headers(request, add_to_tag=False)
        head += ["Content-Length: 0", "", ""]
        return "\r\n".join(head).encode("utf-8")


# --------------------------------------------------------------------------
# RTP port pool
# --------------------------------------------------------------------------

class RtpPortPool:
    def __init__(self, low: int, high: int):
        self._ports = list(range(low, high + 1))
        self._in_use: set[int] = set()

    def acquire(self) -> Optional[int]:
        for port in self._ports:
            if port not in self._in_use:
                self._in_use.add(port)
                return port
        return None

    def release(self, port: int) -> None:
        self._in_use.discard(port)


# --------------------------------------------------------------------------
# UDP protocol
# --------------------------------------------------------------------------

class BlocklistResponderProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        policy: CallPolicy,
        response_builder: SipResponseBuilder,
        announcement: Announcement,
        port_pool: RtpPortPool,
        config: ResponderConfig,
    ):
        self._policy = policy
        self._response_builder = response_builder
        self._announcement = announcement
        self._port_pool = port_pool
        self._config = config
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        request = SipMessageParser.parse(data)
        if request is None:
            return

        if request.method == "OPTIONS":
            self._transport.sendto(self._response_builder.build_options_ok(request), addr)
            log.info("OPTIONS from %s:%d  =>  200 OK", addr[0], addr[1])
            return

        if request.method != "INVITE":
            return

        number = DialedNumberExtractor.extract(request)
        decision = self._policy.evaluate(number)
        if decision is Decision.BLOCK:
            code, reason = self._config.block_status_code, self._config.block_reason
        else:
            code, reason = self._config.passthrough_status_code, self._config.passthrough_reason
        log.info("INVITE to %s  ->  %s  =>  sent %d %s",
                 number, decision.value.upper(), code, reason)

        if decision is Decision.PASSTHROUGH:
            # Allowed: no media, just fail over to the next carrier.
            self._transport.sendto(
                self._response_builder.build_final(request, decision), addr
            )
            return

        # Blocked: play the announcement, then reject.
        asyncio.create_task(self._play_then_reject(request, addr))

    async def _play_then_reject(self, request: SipRequest, addr: tuple[str, int]) -> None:
        caller_media = SdpParser.extract_media_endpoint(request.raw)
        frames = self._announcement.frames

        # If we can't find where to send audio, or have no audio, skip media
        # and reject immediately -- caller still gets the 603.
        if caller_media is None or not frames:
            self._transport.sendto(
                self._response_builder.build_final(request, Decision.BLOCK), addr
            )
            return

        rtp_port = self._port_pool.acquire()
        if rtp_port is None:
            log.warning("No free RTP port -- rejecting without announcement")
            self._transport.sendto(
                self._response_builder.build_final(request, Decision.BLOCK), addr
            )
            return

        try:
            # 183 opens the early-media path
            self._transport.sendto(
                self._response_builder.build_183_with_sdp(request, rtp_port), addr
            )
            # stream the announcement to the caller
            dest_ip, dest_port = caller_media
            await RtpSender(rtp_port).stream(frames, dest_ip, dest_port)
        except Exception:
            log.exception("Error during early-media playback")
        finally:
            self._port_pool.release(rtp_port)
            # final reject after the audio has played
            self._transport.sendto(
                self._response_builder.build_final(request, Decision.BLOCK), addr
            )


# --------------------------------------------------------------------------
# Control socket (cross-platform reload trigger)
# --------------------------------------------------------------------------

async def _handle_control_connection(reader, writer, blocklist: Blocklist,
                                     config: ResponderConfig) -> None:
    try:
        data = await asyncio.wait_for(reader.readline(), timeout=5)
        raw = data.decode("utf-8", errors="ignore").strip()
        parts = raw.split()
        verb = parts[0].lower() if parts else ""
        if verb == "reload":
            blocklist.reload()
            log.info("Blocklist reloaded via control socket")
            writer.write(b"OK\n")
        elif verb == "setcode" and len(parts) >= 2 and parts[1].isdigit():
            # Change the BLOCK response code live, no restart. Lets us find
            # the code PortaSIP/Telinta actually treats as a hard stop.
            config.block_status_code = int(parts[1])
            if len(parts) >= 3:
                config.block_reason = " ".join(parts[2:])
            log.info("Block code set to %d %s via control socket",
                     config.block_status_code, config.block_reason)
            writer.write(
                f"OK block={config.block_status_code} {config.block_reason}\n".encode()
            )
        elif verb == "getcode":
            writer.write(
                (f"OK block={config.block_status_code} {config.block_reason} "
                 f"passthrough={config.passthrough_status_code} "
                 f"{config.passthrough_reason}\n").encode()
            )
        else:
            writer.write(b"ERR unknown command (use: reload | setcode NNN [reason] | getcode)\n")
        await writer.drain()
    except Exception:
        log.exception("Error handling control connection")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

async def run_server(config: ResponderConfig) -> None:
    blocklist = Blocklist(config.blocklist_path)
    policy = CallPolicy(blocklist)
    response_builder = SipResponseBuilder(config)
    announcement = Announcement(config.announcement_path)
    port_pool = RtpPortPool(config.rtp_port_min, config.rtp_port_max)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: BlocklistResponderProtocol(policy, response_builder, announcement, port_pool, config),
        local_addr=(config.listen_host, config.listen_port),
    )
    control_server = await asyncio.start_server(
        lambda r, w: _handle_control_connection(r, w, blocklist, config),
        host=config.control_host,
        port=config.control_port,
    )

    log.info("Listening for SIP on %s:%d (UDP)", config.listen_host, config.listen_port)
    log.info("Advertising media IP %s, RTP ports %d-%d",
             config.media_advertise_ip, config.rtp_port_min, config.rtp_port_max)
    if config.media_advertise_ip.startswith("127."):
        log.warning("media_advertise_ip is loopback -- blocked callers will get "
                    "SILENCE. Set SIP_MEDIA_ADVERTISE_IP to a reachable address.")
    log.info("Control socket on %s:%d (TCP, loopback)", config.control_host, config.control_port)
    try:
        async with control_server:
            await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(run_server(ResponderConfig()))
