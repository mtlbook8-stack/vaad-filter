"""
SIP Blocklist Responder
------------------------
A lightweight SIP UAS (User Agent Server) that answers INVITE requests
with a BLOCK or PASSTHROUGH response, based on a per-number blocklist.

Design intent (Telinta's "Option 1"):
  - Registered inside PortaBilling as a vendor/trunk.
  - Receives an INVITE for every call routed to this vendor.
  - Never connects any audio -- signalling-only, no media path.
  - Returns a *final* SIP error code (e.g. 603 Decline) to stop the call
    outright, or a *retriable* SIP error code (e.g. 404 Not Found) so
    PortaSIP fails over to the next real carrier in the routing plan.

IMPORTANT: Confirm both status codes with Telinta before going live --
their routing-plan / hunting config decides which codes are treated
as final vs. retriable, not the SIP spec alone.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from blocklist import Blocklist  # shared JSON-backed store (also used by the sync)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("sip-blocklist")


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

@dataclass
class ResponderConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 5060
    blocklist_path: Path = Path("blocklist.json")

    block_status_code: int = 603
    block_reason: str = "Decline"

    passthrough_status_code: int = 404
    passthrough_reason: str = "Not Found"

    # Cross-platform reload trigger: the responder listens on this loopback
    # TCP port; blacklist_sync.py connects and sends "reload" after pulling
    # new data. Works identically on Windows, Linux and macOS.
    control_host: str = "127.0.0.1"
    control_port: int = 5099


# --------------------------------------------------------------------------
# SIP message parsing
# --------------------------------------------------------------------------

@dataclass
class SipRequest:
    method: str
    request_uri: str
    headers: dict[str, str]
    raw: bytes

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())


class SipMessageParser:
    """Parses just enough of a raw SIP request to route a decision."""

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
                return None  # not a request (could be a response) - ignore

            method, uri = match.group(1).upper(), match.group(2)
            headers: dict[str, str] = {}

            for line in lines[1:]:
                if not line:
                    break  # blank line = end of headers
                if ":" not in line:
                    continue
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()

            return SipRequest(method=method, request_uri=uri, headers=headers, raw=data)
        except Exception:
            log.exception("Failed to parse incoming SIP message")
            return None


# --------------------------------------------------------------------------
# Number extraction
# --------------------------------------------------------------------------

class DialedNumberExtractor:
    """Pulls the dialed number out of the Request-URI, e.g. sip:19005551234@host."""

    NUMBER_RE = re.compile(r"sip:([^@;]+)@")

    @classmethod
    def extract(cls, request: SipRequest) -> Optional[str]:
        match = cls.NUMBER_RE.search(request.request_uri)
        if not match:
            return None
        return re.sub(r"\D", "", match.group(1))  # digits only


# Blocklist + normalize_number live in blocklist.py (imported at the top),
# shared by both responders and the sync client.


# --------------------------------------------------------------------------
# Decision logic
# --------------------------------------------------------------------------

class Decision(Enum):
    BLOCK = "block"
    PASSTHROUGH = "passthrough"


class CallPolicy:
    """Decides BLOCK vs PASSTHROUGH for a given dialed number."""

    def __init__(self, blocklist: Blocklist):
        self._blocklist = blocklist

    def evaluate(self, number: Optional[str]) -> Decision:
        if number and self._blocklist.is_blocked(number):
            return Decision.BLOCK
        return Decision.PASSTHROUGH


# --------------------------------------------------------------------------
# Response building
# --------------------------------------------------------------------------

class SipResponseBuilder:
    """Builds a valid final SIP response for a received request."""

    def __init__(self, config: ResponderConfig):
        self._config = config

    def build(self, request: SipRequest, decision: Decision) -> bytes:
        if decision is Decision.BLOCK:
            code, reason = self._config.block_status_code, self._config.block_reason
        else:
            code, reason = self._config.passthrough_status_code, self._config.passthrough_reason

        to_header = request.header("to") or ""
        if "tag=" not in to_header:
            to_header = f"{to_header};tag={uuid.uuid4().hex[:8]}"

        lines = [
            f"SIP/2.0 {code} {reason}",
            f"Via: {request.header('via')}",
            f"From: {request.header('from')}",
            f"To: {to_header}",
            f"Call-ID: {request.header('call-id')}",
            f"CSeq: {request.header('cseq')}",
            "Content-Length: 0",
            "",
            "",
        ]
        return "\r\n".join(lines).encode("utf-8")


# --------------------------------------------------------------------------
# UDP server
# --------------------------------------------------------------------------

class BlocklistResponderProtocol(asyncio.DatagramProtocol):
    def __init__(self, policy: CallPolicy, response_builder: SipResponseBuilder):
        self._policy = policy
        self._response_builder = response_builder
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        request = SipMessageParser.parse(data)
        if request is None:
            return

        if request.method == "OPTIONS":
            self._reply_ok_to_options(request, addr)
            return

        if request.method != "INVITE":
            return  # ignore ACK, CANCEL, BYE, etc. -- no dialog state to track

        number = DialedNumberExtractor.extract(request)
        decision = self._policy.evaluate(number)
        response = self._response_builder.build(request, decision)

        log.info("INVITE to %s -> %s", number, decision.value.upper())
        self._transport.sendto(response, addr)

    def _reply_ok_to_options(self, request: SipRequest, addr: tuple[str, int]) -> None:
        # Telinta's platform (like most softswitches) pings vendors with
        # OPTIONS to check they're alive. Answer 200 OK so this box isn't
        # marked as an unreachable vendor.
        lines = [
            "SIP/2.0 200 OK",
            f"Via: {request.header('via')}",
            f"From: {request.header('from')}",
            f"To: {request.header('to')}",
            f"Call-ID: {request.header('call-id')}",
            f"CSeq: {request.header('cseq')}",
            "Content-Length: 0",
            "",
            "",
        ]
        self._transport.sendto("\r\n".join(lines).encode("utf-8"), addr)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

async def _handle_control_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    blocklist: Blocklist,
) -> None:
    """Handles a single control-socket connection. Any line containing
    'reload' triggers a blocklist reload."""
    try:
        data = await asyncio.wait_for(reader.readline(), timeout=5)
        command = data.decode("utf-8", errors="ignore").strip().lower()
        if command == "reload":
            blocklist.reload()
            log.info("Blocklist reloaded via control socket")
            writer.write(b"OK\n")
        else:
            writer.write(b"ERR unknown command\n")
        await writer.drain()
    except Exception:
        log.exception("Error handling control connection")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run_server(config: ResponderConfig) -> None:
    blocklist = Blocklist(config.blocklist_path)
    policy = CallPolicy(blocklist)
    response_builder = SipResponseBuilder(config)

    loop = asyncio.get_running_loop()

    # SIP UDP endpoint
    transport, _ = await loop.create_datagram_endpoint(
        lambda: BlocklistResponderProtocol(policy, response_builder),
        local_addr=(config.listen_host, config.listen_port),
    )

    # Loopback control server: sync script connects here to trigger a reload.
    # Bound to 127.0.0.1 only, so it is never reachable from outside the host.
    control_server = await asyncio.start_server(
        lambda r, w: _handle_control_connection(r, w, blocklist),
        host=config.control_host,
        port=config.control_port,
    )

    log.info("Listening for SIP on %s:%d (UDP)", config.listen_host, config.listen_port)
    log.info("Control socket on %s:%d (TCP, loopback)", config.control_host, config.control_port)
    try:
        async with control_server:
            await asyncio.Event().wait()  # run forever
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(run_server(ResponderConfig()))
