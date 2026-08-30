"""
Shared blocklist store.

Kept in its own module so the responder(s) and the sync client don't have to
import one another -- they all share this single JSON-file-backed set of
numbers. The responder process reads it (reload/is_blocked) and reloads on the
control-socket poke; the sync client writes it (apply_updates/add/remove). Both
point at the same blocklist.json on disk.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

log = logging.getLogger("blocklist")


def normalize_number(raw: str) -> str:
    """Canonicalise a phone number so the same subscriber matches regardless of
    format. Digits only; for NANP (+1) numbers a leading country-code '1' is
    dropped, so 11-digit (1XXXXXXXXXX) and 10-digit (XXXXXXXXXX) forms -- and
    the API's E.164 '+1XXXXXXXXXX' -- all compare equal.

    GOTCHA: only NANP (+1) is canonicalised. International numbers are matched as
    their raw digit string, so a blocklist entry and the dialled form must agree
    digit-for-digit. Extend this if you need to block non-NANP numbers reliably.
    """
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return digits


class Blocklist:
    """JSON-file-backed set of blocked numbers, editable at runtime.

    Numbers are stored normalised (see normalize_number), and lookups normalise
    the query too, so matching is format-independent.
    """

    def __init__(self, path: Path):
        self._path = path
        self._numbers: set[str] = set()
        self.reload()

    def reload(self) -> None:
        if self._path.exists():
            self._numbers = {normalize_number(n) for n in json.loads(self._path.read_text())}
        else:
            self._numbers = set()
        log.info("Loaded %d blocked numbers from %s", len(self._numbers), self._path)

    def save(self) -> None:
        self._path.write_text(json.dumps(sorted(self._numbers), indent=2))

    def is_blocked(self, number: str) -> bool:
        return normalize_number(number) in self._numbers

    def add(self, number: str) -> None:
        self._numbers.add(normalize_number(number))
        self.save()

    def remove(self, number: str) -> None:
        self._numbers.discard(normalize_number(number))
        self.save()

    def apply_updates(self, active: list[str], inactive: list[str]) -> None:
        """Bulk add/remove, saving once. Used by the sync client so a large pull
        is a single disk write instead of one per number (the per-number save
        was O(n^2))."""
        for n in active:
            self._numbers.add(normalize_number(n))
        for n in inactive:
            self._numbers.discard(normalize_number(n))
        self.save()
