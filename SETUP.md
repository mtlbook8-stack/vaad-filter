# SIP Blocklist Responder — Setup & Handover Guide

A small SIP server that sits inside a softswitch (e.g. PortaBilling / Telinta)
as a fake vendor/trunk and blocks calls to specific numbers, plus a sync client
that keeps the blocklist current from the VH Helper partner API.

Runs on any Linux server with Python 3.10+. No database, no framework.

---

## What's in this repo

| File | Purpose |
|------|---------|
| `sip_blocklist_responder_earlymedia.py` | **The server you run.** Plays a recorded announcement to blocked callers, then rejects. |
| `sip_blocklist_responder.py` | Text-only variant (rejects with no audio) — an alternative to the early-media server. |
| `blocklist.py` | Shared store: the `Blocklist` class + number normalization, used by both responders **and** the sync. |
| `blacklist_sync.py` | Pulls the blocklist from the partner API on a schedule and updates `blocklist.json`. |
| `loadtest.py` | Concurrency/soak test that drives real calls through the block path. |
| `SETUP.md` | This file. |

Keep `blocklist.py` alongside whichever responder you run — both the responder
and the sync import the `Blocklist` class from it.

You provide at runtime (not in the repo): `announcement.ulaw`, `blocklist.json`
(auto-created by the sync), `sync.env` (your secrets), and a Python venv.

---

## How it works

For every call the softswitch routes to this vendor it sends a SIP `INVITE`.
The responder checks the dialled number against `blocklist.json` and replies:

- **Blocked** → (early-media edition) `183 Session Progress` + a recorded
  announcement, then a **final "hard stop" code** (default `486 Busy Here`).
- **Allowed** → `404 Not Found`, so the softswitch fails over to the next real
  carrier and the call connects normally.
- **`OPTIONS` health pings** → answered `200 OK` so the platform keeps the
  vendor marked reachable.

The responder never bridges audio for allowed calls — it only answers signalling
(and streams the one announcement for blocked calls).

```
                 VH Helper API
                       │  (scheduled, AES-256-CBC encrypted)
                       ▼
              blacklist_sync.py ──writes──▶ blocklist.json
                       │                          ▲
                       │ "reload" over            │ read on start
                       │ 127.0.0.1:5099           │ + on reload
                       ▼                          │
              sip_blocklist_responder ────────────┘
                       ▲
                       │ SIP INVITE / 486 / 404 / OPTIONS
                       │
                    Softswitch
```

### Things worth knowing (operator notes)

- **Block code is softswitch-specific.** Whether a code is treated as a *final*
  stop or a *retriable* failover is decided by the softswitch's routing/hunting
  config, **not** the SIP standard. The default here is `486 Busy Here`; confirm
  with your platform which code it treats as final and set it accordingly (see
  *Changing the block code live* below). `404` is the retriable/passthrough code.
- **Number matching is normalised.** The code canonicalises NANP (+1) numbers so
  `+1XXXXXXXXXX`, `1XXXXXXXXXX` and `XXXXXXXXXX` all match the same subscriber.
  International numbers are matched as their raw digit string — extend
  `normalize_number()` if you need to block non-NANP numbers reliably.
- **`media_advertise_ip` must be reachable by the softswitch.** It's auto-detected
  from the primary interface; **behind NAT or on a cloud host with a separate
  public IP you must set `SIP_MEDIA_ADVERTISE_IP` to the public address**, or
  blocked callers get silence instead of the announcement.
- **The control port (5099) is loopback-only** — never expose it. Anyone who can
  reach it can force a blocklist reload.

---

## 1. Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip ffmpeg
```
Python 3.10+ required. `ffmpeg` is only needed to (re)generate the announcement.

Two secrets from the VH Helper admin:
- `VH_API_TOKEN` — 64-character bearer token.
- `VH_SHARED_KEY_HEX` — the AES key (the client accepts either a 64-hex string
  or a literal 32-character key; use whatever the admin gives you, verbatim).

---

## 2. Install

```bash
sudo mkdir -p /opt/sip-blocklist && sudo chown "$USER" /opt/sip-blocklist
# copy the .py files into /opt/sip-blocklist/
python3 -m venv /opt/sip-blocklist/venv
/opt/sip-blocklist/venv/bin/pip install requests pycryptodome
```
(The responder uses only the standard library; the venv is for the sync client.)

---

## 3. Configure

### Secrets — `/opt/sip-blocklist/sync.env` (chmod 600)
```
VH_API_TOKEN=<your 64-char token>
VH_SHARED_KEY_HEX=<your key, verbatim>
```
```bash
chmod 600 /opt/sip-blocklist/sync.env
```
Raw values only — no quotes (a systemd `EnvironmentFile` treats quotes as literal
characters).

### Announcement audio
The server streams raw **8 kHz mono G.711 µ-law (PCMU)** as `announcement.ulaw`.
This repo ships with the announcement clip **`VAAD-FILTER-BLC-MSG.mp3`** — convert
it (or any replacement clip) to the required format:
```bash
ffmpeg -i VAAD-FILTER-BLC-MSG.mp3 -ar 8000 -ac 1 -f mulaw /opt/sip-blocklist/announcement.ulaw
```
`announcement.ulaw` itself is generated (and git-ignored), so you always produce
it from the source clip. If the file is missing, blocked callers simply get the
reject with no audio.

### Media / SIP settings
- `SIP_MEDIA_ADVERTISE_IP` — export this (or set it in the systemd unit) to the
  IP the softswitch can reach when the server is behind NAT/cloud.
- Other defaults live in `ResponderConfig` at the top of the responder file:
  SIP port `5060`, RTP range `40000-40100`, block code `486`, control port `5099`.

---

## 4. Run as systemd services

`/etc/systemd/system/sip-responder.service`
```ini
[Unit]
Description=SIP Blocklist Responder
After=network.target

[Service]
User=sipblock
WorkingDirectory=/opt/sip-blocklist
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment=SIP_MEDIA_ADVERTISE_IP=<public-or-reachable-IP>
ExecStart=/usr/bin/python3 /opt/sip-blocklist/sip_blocklist_responder_earlymedia.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```
`AmbientCapabilities=CAP_NET_BIND_SERVICE` lets a non-root user bind port 5060.

`/etc/systemd/system/blacklist-sync.service`
```ini
[Unit]
Description=Blacklist Sync Client
After=network-online.target sip-responder.service
Wants=network-online.target

[Service]
User=sipblock
WorkingDirectory=/opt/sip-blocklist
EnvironmentFile=/opt/sip-blocklist/sync.env
ExecStart=/opt/sip-blocklist/venv/bin/python /opt/sip-blocklist/blacklist_sync.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sip-responder blacklist-sync
```

The sync pulls the full list on first run and then refreshes on its interval
(default once a day), writing `blocklist.json` and poking the responder to reload
— no restart needed. It handles rate-limits (`429`) and server errors with
exponential backoff on its own.

---

## 5. Operations

```bash
# watch call decisions live (shows the actual SIP response sent)
sudo journalctl -u sip-responder -f

# change the block code live, no restart (find the one your softswitch honours):
/opt/sip-blocklist/setcode.sh 486 Busy Here      # or 603, 403, 600, ...
/opt/sip-blocklist/getcode.sh                    # show current codes

# edit the blocklist by hand, then reload without restarting:
python3 -c "import socket;s=socket.create_connection(('127.0.0.1',5099));s.sendall(b'reload\n');print(s.recv(64).decode())"
```

Optional `setcode`/`getcode` helpers (put on PATH for convenience):
```bash
# /opt/sip-blocklist/setcode.sh
#!/usr/bin/env bash
code="$1"; shift; reason="$*"
python3 - "$code" "$reason" <<'PY'
import socket, sys
s=socket.create_connection(('127.0.0.1',5099))
s.sendall(("setcode %s %s\n" % (sys.argv[1], sys.argv[2])).encode())
print(s.recv(200).decode().strip())
PY
```

**Verify inbound UDP actually reaches the box** (run on the server while the
softswitch or a test tool sends a call):
```bash
sudo tcpdump -nn -A -i any 'udp port 5060'
```

---

## 6. Load / soak test

Run **on the server** (each virtual caller advertises `127.0.0.1` so the RTP
returns locally and can be counted — from a remote host the audio dies at NAT):
```bash
python3 loadtest.py --calls 15
python3 loadtest.py --calls 50        # push toward the RTP-pool ceiling (~101)
```
It reports, per call, whether `183` arrived, how many RTP packets streamed, and
the final code — plus an aggregate pass count.

---

## 7. Softswitch side (done with your platform/vendor)

1. Register this server as a **vendor connection** → its reachable IP, UDP 5060.
2. **Confirm code semantics**: which code the platform treats as *final*
   (use that as the block code) vs *retriable* (use that as passthrough, `404`).
3. Create a routing plan that includes this vendor and **assign it only to the
   accounts that should be filtered** — that assignment is the per-customer
   on/off switch. ⚠️ A too-broad assignment will route *all* traffic through
   this box; scope it deliberately.
4. Ensure a real fallback carrier sits after this vendor so a passthrough (`404`)
   has somewhere to fail over to.

---

## 8. Firewall

Open, restricted to the softswitch's signalling/media IPs (not the whole
internet — SIP scanners hammer 5060):

- **UDP 5060** — SIP signalling
- **UDP 40000-40100** — RTP media (the announcement)
- **TCP 22** — SSH, restricted to admin IPs

The OS firewall is the gate; nothing about the responder blocks UDP itself.
Keep the control port **5099 bound to loopback only** (it is by default).

---

## 9. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Blocked calls still connect | The softswitch isn't treating the block code as *final*. Try another code with `setcode.sh` and confirm with the platform. |
| Allowed calls fail instead of connecting | The passthrough `404` is being treated as final by the platform's config. |
| Blocked callers hear silence | `announcement.ulaw` missing, **or** `media_advertise_ip` isn't reachable — set `SIP_MEDIA_ADVERTISE_IP` to the public IP. |
| The softswitch retransmits INVITEs / marks vendor unreachable | Signalling/media not reaching the box — check the firewall and that UDP 5060 is open from the platform's IP. |
| `sync` exits with `KeyError: 'VH_API_TOKEN'` | Secrets not loaded — check `sync.env` / the unit's `EnvironmentFile`. |
| `403` from the API | Token revoked/expired — get a new one from the VH Helper admin. |
| `429` from the API | Rate limited; the client backs off and retries automatically. |
