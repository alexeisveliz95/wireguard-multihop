# WireGuard Multihop

Single-file WireGuard server installer with optional multihop (exit via Surfshark or any WireGuard provider).

Take it to any VPS, run it, and you have a working WireGuard server in minutes.

## Features

- **WireGuard server** — wg0 for clients, autoconfigured
- **Multihop** — client traffic exits via a second WG peer (Surfshark, Mullvad, etc.)
- **Firewall** — iptables rules (SSH + WG + ICMP allowed, rest DROP)
- **Anti-lockout** — mgmt routing table so your SSH session never gets cut
- **Kill switch** — blackhole route in the clients table prevents leaks
- **Self-healing watchdog** — checks interfaces, routes, handshake, FORWARD rules every 5 min (via cron)
- **Client management** — `add-client`, `remove-client`, `list-clients`, generates `.conf` + QR
- **DRY_RUN** — simulate everything without touching the system
- **Self-test** — `test` command runs 15 tests in isolated network namespaces

## Quick start

```bash
# Download
wget https://raw.githubusercontent.com/alexeisveliz95/wireguard-multihop/main/wg-multihop.sh
chmod +x wg-multihop.sh

# Optional: place a WireGuard .conf file (e.g. from Surfshark) next to the script
# The installer will auto-detect and parse it.

# Install (interactive)
sudo bash wg-multihop.sh install

# Add a client
sudo bash wg-multihop.sh add-client my-phone

# Toggle multihop on/off
sudo bash wg-multihop.sh multihog on
sudo bash wg-multihop.sh multihog off
```

## Usage

```
Usage: bash wg-multihop.sh <command> [args]

Commands:
  install              Full interactive setup
  add-client <name>    Add a client
  remove-client <name> Remove a client
  list-clients         List configured clients
  multihog [on|off]    Toggle traffic exit via wg1
  status               Dashboard
  watchdog             Self-heal (runs via cron)
  uninstall            Revert everything
  recover              Emergency recovery
  test                 Self-test in isolated namespaces
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DRY_RUN=1` | `0` | Simulation mode (no real changes) |
| `BATCH=1` | `0` | Non-interactive (uses defaults/env) |
| `WG_PORT` | `51820` | WireGuard listen port |
| `SSH_PORT` | `22` | SSH port (for firewall rules) |
| `WG_DIR` | `/etc/wireguard` | WireGuard config directory |
| `CLIENT_DIR` | `/home/wireguard/clients-peers` | Client config output directory |
| `SURFSHARK_CONF` | `./surfshark.conf` | Path to multihop provider `.conf` |
| `WG0_SUBNET` | `10.8.0.0/24` | Client subnet |
| `WG0_MTU` | `1420` | wg0 MTU |
| `WG1_MTU` | `1320` | wg1 MTU |
| `CLIENT_MTU` | `1380` | Client interface MTU |
| `CLIENT_DNS` | `8.8.8.8, 1.1.1.1` | Client DNS servers |
| `WG1_KEEPALIVE` | `5` | PersistentKeepalive for wg1 |
| `CLIENT_KEEPALIVE` | `25` | PersistentKeepalive for clients |
| `WG_HANDSHAKE_TIMEOUT` | `180` | Seconds before watchdog restarts wg1 |
| `MIN_RAM_MB` | `50` | RAM threshold for watchdog cache clear |
| `PING_TARGETS` | `8.8.8.8 1.1.1.1` | Connectivity check targets |

### Multihop

The multihop feature routes all client traffic through a second WireGuard interface (wg1). This is useful when you want clients to exit through a different IP than the VPS itself.

The installer accepts:
1. A standard WireGuard `.conf` file (from Surfshark, Mullvad, etc.) with `[Interface]` + `[Peer]` sections
2. A legacy config file with shell variables (`WG1_ENDPOINT`, `SS_PUB`, etc.)

The VPS's own traffic continues to use its direct WAN connection — only client traffic is routed through wg1.

### Self-test

```bash
# Full test suite in isolated network namespaces
sudo bash wg-multihop.sh test

# Expected output: ✅  ALL TESTS PASSED (15/15)
```

## Requirements

- Linux with WireGuard kernel module (`wireguard.ko`)
- `wg`, `wg-quick`, `iptables`
- Root access

## License

MIT
