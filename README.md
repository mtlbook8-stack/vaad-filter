# vaad-filter

A lightweight SIP blocklist responder for a softswitch (PortaBilling / Telinta).
It registers as a fake vendor/trunk, and for every call the softswitch routes to
it, either **blocks** the number (plays a recorded announcement, then rejects) or
**passes it through** (so the call fails over to the real carrier). A companion
sync client keeps the blocklist current from the VH Helper partner API.

Runs on any Linux server with Python 3.10+. No database, no framework.

**Full install, systemd units, firewall, and operations: [SETUP.md](SETUP.md).**

## Quick start (impatient edition)

```bash
# 1. Get it + deps
sudo apt update && sudo apt install -y python3 python3-venv ffmpeg
git clone https://github.com/mtlbook8-stack/vaad-filter.git /opt/sip-blocklist
cd /opt/sip-blocklist
python3 -m venv venv && venv/bin/pip install requests pycryptodome

# 2. Announcement + secrets
ffmpeg -i VAAD-FILTER-BLC-MSG.mp3 -ar 8000 -ac 1 -f mulaw announcement.ulaw
printf 'VH_API_TOKEN=%s\nVH_SHARED_KEY_HEX=%s\n' 'YOUR_TOKEN' 'YOUR_KEY' > sync.env
chmod 600 sync.env

# 3. Run (behind NAT/cloud, set the reachable IP first)
export SIP_MEDIA_ADVERTISE_IP=<public-or-reachable-IP>   # skip if directly addressed
sudo -E venv/bin/python sip_blocklist_responder_earlymedia.py &   # sudo: binds UDP 5060
venv/bin/python blacklist_sync.py &                               # pulls the blocklist
```

**Is it running?** (expect `SIP/2.0 200 OK`)
```bash
python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(b"OPTIONS sip:127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bK-t\r\n"
         b"From: <sip:t@t>;tag=1\r\nTo: <sip:127.0.0.1>\r\nCall-ID: t@t\r\nCSeq: 1 OPTIONS\r\n"
         b"Content-Length: 0\r\n\r\n", ("127.0.0.1", 5060))
print(s.recvfrom(2048)[0].decode().splitlines()[0])
PY
```

**Does it block?** add a test number, reload, and drive one call:
```bash
echo '["15551230000"]' > blocklist.json
python3 -c "import socket;s=socket.create_connection(('127.0.0.1',5099));s.sendall(b'reload\n');print(s.recv(64).decode())"
python3 loadtest.py --calls 1          # expect: 1/1, final '486 Busy Here', ~264 RTP pkts
```

For production, run both under systemd instead of `&` — see [SETUP.md](SETUP.md).

## Components

- `sip_blocklist_responder_earlymedia.py` — the server (announcement + reject)
- `sip_blocklist_responder.py` — text-only variant (reject, no audio)
- `blocklist.py` — shared blocklist store + number normalization
- `blacklist_sync.py` — scheduled blocklist sync from the partner API
- `loadtest.py` — concurrency/soak test for the block path
