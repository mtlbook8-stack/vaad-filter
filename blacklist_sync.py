"""
Blacklist Sync Client
----------------------
Pulls incremental blacklist updates from a partner API (AES-256-CBC
encrypted envelope) and applies them to the local Blocklist used by
sip_blocklist_responder.py.

Requires:
    pip install requests pycryptodome

Requires two secrets, provided via environment variables (never hardcode):
    VH_API_TOKEN       - Bearer token issued by the API admin
    VH_SHARED_KEY_HEX  - 32-byte AES key, as a 64-char hex string

Run this file from the same directory as sip_blocklist_responder.py so
it can import the Blocklist class.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import socket
import time
from pathlib import Path
from typing import Any

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# GOTCHA: the sync always imports the read/write Blocklist from the TEXT-ONLY
# responder module, even when you run the early-media edition. Both editions
# share the same blocklist.json file on disk; the early-media responder has its
# own read-only Blocklist and reloads the file when we poke its control socket.
# So sip_blocklist_responder.py must be present alongside whichever responder
# you actually run.
from sip_blocklist_responder import Blocklist  # read/write blocklist store

log = logging.getLogger("blacklist-sync")


# --------------------------------------------------------------------------
# Encrypted API client
# --------------------------------------------------------------------------

class BlacklistApiClient:
    """Talks to the partner blacklist API using its AES-256-CBC envelope."""

    def __init__(self, base_url: str, token: str, shared_key_hex: str):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._key = self._load_key(shared_key_hex)

    @staticmethod
    def _load_key(value: str) -> bytes:
        # AES-256 needs a 32-byte key. The partner may hand it over either as
        # 64 hex characters, OR as a literal 32-character string used directly
        # as the key bytes (which is what this API actually uses).
        value = value.strip()
        if re.fullmatch(r"[0-9a-fA-F]{64}", value):
            return bytes.fromhex(value)
        raw = value.encode("utf-8")
        if len(raw) == 32:
            return raw
        raise ValueError(
            f"VH_SHARED_KEY_HEX must be 64 hex chars or a 32-byte string; "
            f"got {len(value)} chars ({len(raw)} bytes)"
        )

    RETRY_STATUS = (429, 500, 502, 503, 504)
    MAX_RETRIES = 6

    def fetch_updates(self, last_update: int = 0) -> dict[str, Any]:
        body = {"lastUpdate": last_update}
        payload = self._encrypt(json.dumps(body))
        url = f"{self._base_url}/blacklist/numbers"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        for attempt in range(self.MAX_RETRIES):
            resp = requests.post(url, json={"data": payload}, headers=headers, timeout=10)
            if resp.status_code in self.RETRY_STATUS:
                # 429 (rate limit) / 5xx (server) -> exponential backoff + retry,
                # honouring Retry-After if the server sends one. Per the API docs.
                wait = min(60, 2 ** attempt)
                retry_after = resp.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    wait = min(120, int(retry_after))
                log.warning("API returned %d; backing off %ds (attempt %d/%d)",
                            resp.status_code, wait, attempt + 1, self.MAX_RETRIES)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return json.loads(self._decrypt(resp.json()["data"]))
        raise RuntimeError(
            f"API still returning a retryable error after {self.MAX_RETRIES} attempts"
        )

    def _encrypt(self, plaintext: str) -> str:
        iv = get_random_bytes(16)
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        return base64.b64encode(iv + ciphertext).decode("ascii")

    def _decrypt(self, payload_b64: str) -> str:
        raw = base64.b64decode(payload_b64)
        iv, ciphertext = raw[:16], raw[16:]
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode("utf-8")


# --------------------------------------------------------------------------
# Sync service
# --------------------------------------------------------------------------

class BlacklistSyncService:
    """
    Drains delta updates from the API and applies them to a Blocklist.
    Persists the last-seen timestamp so restarts resume incrementally
    instead of re-pulling the full list.
    """

    PAGE_SIZE = 10_000  # API's documented max records per call

    def __init__(
        self,
        api_client: BlacklistApiClient,
        blocklist: Blocklist,
        state_path: Path,
        control_addr: tuple[str, int] | None = None,
    ):
        self._api = api_client
        self._blocklist = blocklist
        self._state_path = state_path
        self._control_addr = control_addr
        self._last_update = self._load_last_update()

    def _load_last_update(self) -> int:
        if self._state_path.exists():
            return json.loads(self._state_path.read_text()).get("last_update", 0)
        return 0

    def _save_last_update(self, value: int) -> None:
        self._state_path.write_text(json.dumps({"last_update": value}))

    def _notify_responder(self) -> None:
        """Tell the responder to reload, via its loopback control socket.
        Cross-platform (no Unix signals)."""
        if self._control_addr is None:
            return
        try:
            with socket.create_connection(self._control_addr, timeout=5) as sock:
                sock.sendall(b"reload\n")
                sock.recv(64)  # read the OK/ERR acknowledgement
            log.info("Notified responder to reload via %s:%d", *self._control_addr)
        except OSError:
            log.warning(
                "Could not reach responder control socket at %s:%d "
                "(is the responder running?)", *self._control_addr
            )

    def sync_once(self) -> int:
        """Drains all pages until fully caught up. Returns total records applied."""
        total = 0
        changed = False

        while True:
            prev_update = self._last_update
            result = self._api.fetch_updates(self._last_update)

            if not result.get("success"):
                log.warning("Sync call failed: %s", result.get("message"))
                break

            batch = result.get("numbers", [])
            total += len(batch)
            if batch:
                changed = True

            # Collect the whole page, then apply in one shot -- one disk write
            # per page instead of one per number (the old per-number save was
            # O(n^2) and took ~36s for 16k numbers).
            active: list[str] = []
            inactive: list[str] = []
            max_ts = self._last_update
            for entry in batch:
                number = re.sub(r"\D", "", entry.get("phoneNumber", ""))
                if not number:
                    continue
                (active if entry.get("isActive") else inactive).append(number)
                max_ts = max(max_ts, entry.get("timestamp", 0))
            self._blocklist.apply_updates(active, inactive)

            if max_ts > self._last_update:
                self._last_update = max_ts
                self._save_last_update(max_ts)

            log.info("Applied %d entries (last_update=%d)", len(batch), self._last_update)

            if len(batch) < self.PAGE_SIZE:
                break  # fully caught up

            if self._last_update <= prev_update:
                # Full page but the timestamp cursor didn't advance -- without
                # this guard we'd re-request the same page forever.
                log.warning("Pagination stalled at last_update=%d (full page, no "
                            "newer timestamp); stopping to avoid an infinite loop",
                            self._last_update)
                break

        if changed:
            self._notify_responder()

        return total

    async def run_forever(self, interval_seconds: int = 300) -> None:
        while True:
            try:
                self.sync_once()
            except Exception:
                log.exception("Blacklist sync error")
            await asyncio.sleep(interval_seconds)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    token = os.environ["VH_API_TOKEN"]
    shared_key_hex = os.environ["VH_SHARED_KEY_HEX"]

    api_client = BlacklistApiClient(
        base_url="https://internalapi.vaadhakehilos.org/api",
        token=token,
        shared_key_hex=shared_key_hex,
    )
    blocklist = Blocklist(Path("blocklist.json"))
    sync_service = BlacklistSyncService(
        api_client,
        blocklist,
        state_path=Path("sync_state.json"),
        control_addr=("127.0.0.1", 5099),  # must match the responder's control_port
    )

    await sync_service.run_forever(interval_seconds=86_400)  # once a day


if __name__ == "__main__":
    asyncio.run(main())
