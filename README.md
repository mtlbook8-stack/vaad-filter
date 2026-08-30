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

# 3. Firewall -- allow SIP + RTP ONLY from the softswitch (Telinta / PortaBilling).
#    SOFTSWITCH_IP = its SIP signalling IP (a single /32, or their subnet as a CIDR).
#    NEVER open 5060 to the whole internet -- SIP scanners hammer it constantly.
SOFTSWITCH_IP=<telinta/porta signalling IP or CIDR>
sudo ufw allow from "$SOFTSWITCH_IP" to any port 5060 proto udp         # SIP signalling
sudo ufw allow from "$SOFTSWITCH_IP" to any port 40000:40100 proto udp  # RTP media

# 3b. CLOUD VM: there's a SECOND firewall in front of the VM (provider security
#     group). Open the SAME two UDP ports from the SAME source there too, or
#     traffic never reaches the OS. Grab the PUBLIC IP for step 4 while here.
#   PUB=$(curl -s ifconfig.me)
#   Azure (Network Security Group):
#   az network nsg rule create -g <RG> --nsg-name <NSG> -n allow-sip-udp \
#     --priority 310 --direction Inbound --access Allow --protocol Udp \
#     --source-address-prefixes "$SOFTSWITCH_IP" --destination-port-ranges 5060
#   az network nsg rule create -g <RG> --nsg-name <NSG> -n allow-rtp-udp \
#     --priority 320 --direction Inbound --access Allow --protocol Udp \
#     --source-address-prefixes "$SOFTSWITCH_IP" --destination-port-ranges 40000-40100
#   (AWS: Security Group inbound UDP rules; GCP: `gcloud compute firewall-rules create`.)
#
#   THEN, on the softswitch side, register THIS server as a vendor/trunk at:
#       <this server's PUBLIC IP> : 5060 / UDP

# 4. Install as systemd services (auto-start on boot, restart on crash)
PUB=<public-or-reachable-IP>          # or: PUB=$(curl -s ifconfig.me); leave blank if directly addressed

sudo tee /etc/systemd/system/sip-responder.service >/dev/null <<EOF
[Unit]
Description=SIP Blocklist Responder
After=network.target
[Service]
User=$(id -un)
WorkingDirectory=/opt/sip-blocklist
AmbientCapabilities=CAP_NET_BIND_SERVICE
Environment=SIP_MEDIA_ADVERTISE_IP=$PUB
ExecStart=/opt/sip-blocklist/venv/bin/python /opt/sip-blocklist/sip_blocklist_responder_earlymedia.py
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/blacklist-sync.service >/dev/null <<EOF
[Unit]
Description=Blacklist Sync Client
After=network-online.target sip-responder.service
Wants=network-online.target
[Service]
User=$(id -un)
WorkingDirectory=/opt/sip-blocklist
EnvironmentFile=/opt/sip-blocklist/sync.env
ExecStart=/opt/sip-blocklist/venv/bin/python /opt/sip-blocklist/blacklist_sync.py
Restart=always
RestartSec=30
[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sip-responder blacklist-sync
sudo systemctl status sip-responder blacklist-sync --no-pager
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

Manage it: `sudo systemctl status|restart sip-responder`, `journalctl -u sip-responder -f`.
See [SETUP.md](SETUP.md) for the full reference — dedicated service user, restricting
the firewall to the softswitch IP, changing the block code, and troubleshooting.

## Components

- `sip_blocklist_responder_earlymedia.py` — the server (announcement + reject)
- `sip_blocklist_responder.py` — text-only variant (reject, no audio)
- `blocklist.py` — shared blocklist store + number normalization
- `blacklist_sync.py` — scheduled blocklist sync from the partner API
- `loadtest.py` — concurrency/soak test for the block path
