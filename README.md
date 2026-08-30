# vaad-filter

A lightweight SIP blocklist responder for a softswitch (PortaBilling / Telinta).
It registers as a fake vendor/trunk, and for every call the softswitch routes to
it, either **blocks** the number (plays a recorded announcement, then rejects) or
**passes it through** (so the call fails over to the real carrier). A companion
sync client keeps the blocklist current from the VH Helper partner API.

Runs on any Linux server with Python 3.10+. No database, no framework.

**See [SETUP.md](SETUP.md) for install, configuration, running, and operations.**

## Components

- `sip_blocklist_responder_earlymedia.py` — the server (announcement + reject)
- `sip_blocklist_responder.py` — text-only variant (reject, no audio)
- `blocklist.py` — shared blocklist store + number normalization
- `blacklist_sync.py` — scheduled blocklist sync from the partner API
- `loadtest.py` — concurrency/soak test for the block path
