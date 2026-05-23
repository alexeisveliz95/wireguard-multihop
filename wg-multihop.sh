#!/bin/bash
set -euo pipefail

# =============================================================================
# wg-multihop.sh — WireGuard Multihop Toolbox
#
# Single file. Take it to any VPS and go.
#
# Commands:
#   install            Full interactive setup (WG + firewall + routing + multihop)
#   add-client <name>  Add a peer to wg0, generate .conf + QR
#   remove-client <n>  Remove a peer from wg0, delete .conf
#   list-clients       List configured clients
#   multihog [on|off]  Toggle traffic exit via wg1 (multihop)
#   status             Dashboard
#   watchdog           Self-heal (run via cron)
#   failover           Switch provider (requires WG2_* vars)
#   tor [on|off]       Route VPS traffic through Tor
#   uninstall          Revert everything
#   recover            Emergency recovery (restore iptables + clean WG)
#   test               Self-test in isolated network namespaces
#
# Usage:
#   DRY_RUN=1 bash wg-multihop.sh install           # simulate
#   bash wg-multihop.sh add-client pepe --expires 7d # client expires
# =============================================================================

# --- Config defaults (env vars override) ---
WG_PORT="${WG_PORT:-51820}"
WG_DIR="${WG_DIR:-/etc/wireguard}"
CLIENT_DIR="${CLIENT_DIR:-/home/wireguard/clients-peers}"
SURFSHARK_CONF="${SURFSHARK_CONF:-$(cd "$(dirname "$0")" && pwd)/surfshark.conf}"
MULTIHOP_STATE="${WG_DIR}/.multihop_state"
ACTIVE_PROVIDER="${WG_DIR}/.active_provider"
DRY_RUN="${DRY_RUN:-0}"
BATCH="${BATCH:-0}"  # 1 = non-interactive (uses defaults or env vars)
SSH_PORT="${SSH_PORT:-22}"

# WireGuard subnets / tunables
WG0_SUBNET="${WG0_SUBNET:-10.8.0.0/24}"
WG1_MTU="${WG1_MTU:-1320}"
WG0_MTU="${WG0_MTU:-${WG1_MTU}}"
CLIENT_MTU="${CLIENT_MTU:-$(( WG1_MTU - 60 ))}"
CLIENT_DNS="${CLIENT_DNS:-8.8.8.8, 1.1.1.1}"
WG1_KEEPALIVE="${WG1_KEEPALIVE:-5}"
CLIENT_KEEPALIVE="${CLIENT_KEEPALIVE:-25}"
WG_HANDSHAKE_TIMEOUT="${WG_HANDSHAKE_TIMEOUT:-180}"
MIN_RAM_MB="${MIN_RAM_MB:-50}"
PING_TARGETS="${PING_TARGETS:-8.8.8.8 1.1.1.1}"

# Backup provider (multi-provider failover)
WG2_ENDPOINT="${WG2_ENDPOINT:-}"
SS2_PUB="${SS2_PUB:-}"
WG2_VPS_IP="${WG2_VPS_IP:-10.16.0.2/32}"
WG2_MTU="${WG2_MTU:-${WG1_MTU}}"
WG2_KEEPALIVE="${WG2_KEEPALIVE:-5}"

# Tor transparent proxy
TOR_PORT="${TOR_PORT:-9040}"
TOR_DNS_PORT="${TOR_DNS_PORT:-5353}"
TOR_SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"
TOR_USER="${TOR_USER:-debian-tor}"

# Cargar config persistente de instalaciones anteriores
WG_PERSIST="${WG_DIR}/.wg-multihop-config"
[[ -f "$WG_PERSIST" ]] && source "$WG_PERSIST"

# --- Colores ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ============================================================================
# Utilities
# ============================================================================
log()  { echo -e "  ${GREEN}[+]${NC} $*"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $*"; }
err()  { echo -e "  ${RED}[x]${NC} $*"; }
info() { echo -e "  ${CYAN}[i]${NC} $*"; }
title(){ echo -e "\n${BOLD}$*${NC}\n"; }

dry() {
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "    [DRY-RUN] $*" >&2
        return 0
    fi
    "$@"
}

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        err "Requiere root. Ejecute: sudo bash $0 $*"
        exit 1
    fi
}

prompt() {
    local var="$1" msg="$2" default="$3"
    if [[ "$BATCH" == "1" ]]; then
        # En BATCH: no sobrescribir si ya seteado en entorno
        if [[ -n "$(eval echo "\${${var}-}")" ]]; then
            return 0
        fi
        printf -v "$var" "%s" "${default}"
        return 0
    fi
    local input
    if [[ -n "$default" ]]; then
        read -r -p "? ${msg} [${default}]: " input
        printf -v "$var" "%s" "${input:-$default}"
    else
        read -r -p "? ${msg}: " input
        printf -v "$var" "%s" "${input}"
    fi
}

confirm() {
    local msg="$1" default="${2:-Y}"
    if [[ "$BATCH" == "1" ]]; then
        [[ "$default" =~ ^[Yy] ]] && return 0 || return 1
    fi
    local input
    read -r -p "? ${msg} [${default}]: " input
    input="${input:-$default}"
    [[ "$input" =~ ^[Yy] ]]
}

run_wg_quick() {
    local conf="$1" action="$2"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "    [DRY-RUN] wg-quick ${action} ${conf}" >&2
        return 0
    fi
    wg-quick "$action" "$conf" 2>&1 | grep -v "Warning:" || true
    return "${PIPESTATUS[0]}"
}

# ============================================================================
# Pre-flight checks & validation
# ============================================================================

__preflight_critical() {
    local errors=0

    info "Checking WireGuard kernel module..."
    if ! lsmod 2>/dev/null | grep wireguard >/dev/null 2>&1; then
        modprobe wireguard 2>/dev/null || true
        sleep 1
        lsmod 2>/dev/null | grep wireguard >/dev/null 2>&1 || { err "wireguard.ko no disponible"; errors=1; }
    fi

    info "Checking required tools..."
    command -v wg &>/dev/null || { err "wg no encontrado — instale wireguard-tools"; errors=1; }
    command -v wg-quick &>/dev/null || { err "wg-quick no encontrado"; errors=1; }
    command -v iptables &>/dev/null || { err "iptables no encontrado"; errors=1; }

    info "Checking rt_tables..."
    touch /etc/iproute2/rt_tables 2>/dev/null || { err "/etc/iproute2/rt_tables not writable"; errors=1; }

    info "Checking for existing WG interfaces..."
    local conflicts
    conflicts=$(ip link show 2>/dev/null | grep -oP '^\d+:\s+\K(wg0|wg1)' || true)
    if [[ -n "$conflicts" ]]; then
        warn "Existing WG interfaces found: ${conflicts}"
        warn "Run 'bash $0 uninstall' first or remove interfaces manually"
        errors=1
    fi

    if [[ "$errors" -gt 0 ]]; then
        err "${errors} preflight check(s) failed. Aborting."
        return 1
    fi
    log "Critical preflight OK"
}

__preflight_interactive() {
    [[ "$BATCH" == "1" ]] && { log "Batch mode — skipping interactive preflight"; return 0; }
    local errors=0
    info "Checking connectivity..."
    local target fail=0
    for target in ${PING_TARGETS}; do
        ping -c 1 -W 3 "$target" &>/dev/null || { warn "Cannot reach ${target}"; fail=1; }
    done
    [[ "$fail" == "1" ]] && errors=1
    host github.com &>/dev/null || warn "DNS may not be working"

    if [[ "$errors" -gt 0 ]]; then
        err "${errors} connectivity check(s) failed. Aborting."
        return 1
    fi
    log "Interactive preflight OK"
}

__preflight() {
    __preflight_critical || return 1
    __preflight_interactive || return 1
    log "Preflight OK"
}

__validate_surfshark_conf() {
    [[ "$BATCH" == "1" ]] && return 0
    local errors=0
    if [[ -z "${WG1_ENDPOINT:-}" ]]; then
        err "WG1_ENDPOINT is empty"; errors=1
    else
        local port_part
        port_part=$(echo "$WG1_ENDPOINT" | cut -d: -f2)
        if ! [[ "$port_part" =~ ^[0-9]+$ ]] || [[ "$port_part" -lt 1 ]] || [[ "$port_part" -gt 65535 ]]; then
            err "Invalid port in WG1_ENDPOINT (${port_part})"; errors=1
        fi
    fi
    if [[ -z "${SS_PUB:-}" ]]; then
        err "SS_PUB is empty"; errors=1
    elif [[ "${#SS_PUB}" -ne 44 ]]; then
        err "SS_PUB debe tener 44 caracteres (tiene ${#SS_PUB})"; errors=1
    fi
    return $errors
}

# ============================================================================
# Internal — installation
# ============================================================================

__detect_wan() {
    local iface
    iface=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    [[ -n "$iface" ]] && { echo "$iface"; return 0; }
    iface=$(ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    [[ -n "$iface" ]] && { echo "$iface"; return 0; }
    iface=$(ip route 2>/dev/null | grep -m1 '^default' | grep -oP 'dev \K\S+')
    [[ -n "$iface" ]] && { echo "$iface"; return 0; }
    echo "eth0"
}

__detect_ip() {
    local iface="$1"
    ip addr show "$iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+/[0-9]+' | head -1 || echo "0.0.0.0/24"
}

__install_wireguard() {
    title "[1/7] Instalando WireGuard"
    log "Installing packages..."
    if command -v apt &>/dev/null; then
        dry DEBIAN_FRONTEND=noninteractive apt update -qq 2>/dev/null || true
        dry DEBIAN_FRONTEND=noninteractive apt install -y -qq wireguard qrencode iptables-persistent 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dry dnf install -y -q wireguard-tools qrencode iptables-services 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        dry yum install -y -q wireguard-tools qrencode iptables-services 2>/dev/null || true
    elif command -v apk &>/dev/null; then
        dry apk add wireguard-tools qrencode iptables 2>/dev/null || true
    else
        warn "Unknown package manager — install wireguard-tools + qrencode + iptables manually"
    fi
    dry mkdir -p "$WG_DIR"
    if [[ ! -f "${WG_DIR}/vps_private.key" ]]; then
        log "Generating server keys..."
        dry bash -c "wg genkey | tee ${WG_DIR}/vps_private.key | wg pubkey > ${WG_DIR}/vps_public.key" || true
        dry chmod 600 "${WG_DIR}/vps_private.key" 2>/dev/null || true
    else
        info "Keys already exist, reusing"
    fi
    log "Enabling IP forwarding..."
    dry bash -c "sysctl -w net.ipv4.ip_forward=1 >/dev/null && sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf 2>/dev/null || true"
    log "Enabling TCP MTU probing..."
    dry bash -c "sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null 2>/dev/null || true"
}

__install_firewall() {
    local wan="$1"
    title "[2/7] Configuring firewall"

    # ufw interfiere con nuestras reglas — desactivarlo
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi active; then
        warn "ufw is active — it interferes with iptables rules de wg-multihop"
        log "Disabling ufw..."
        dry ufw disable 2>/dev/null || true
        log "ufw disabled"
    fi

    # Backup iptables actual antes de tocarlas
    dry mkdir -p /etc/iptables 2>/dev/null || true
    dry iptables-save > /etc/iptables/rules.v4.pre-wg-multihop 2>/dev/null || true
    log "Backup saved to /etc/iptables/rules.v4.pre-wg-multihop"
    log "Applying base iptables rules..."
    dry iptables -P INPUT DROP 2>/dev/null || true
    dry iptables -P FORWARD DROP 2>/dev/null || true
    dry iptables -P OUTPUT ACCEPT 2>/dev/null || true
    dry iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || dry iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    dry iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || dry iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    dry iptables -C INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT 2>/dev/null || dry iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT 2>/dev/null || true
    dry iptables -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || dry iptables -A INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || true
    dry iptables -C INPUT -p icmp -m limit --limit 10/second -j ACCEPT 2>/dev/null || dry iptables -A INPUT -p icmp -m limit --limit 10/second -j ACCEPT 2>/dev/null || true
    dry iptables -C FORWARD -i wg0 -o wg1 -j ACCEPT 2>/dev/null || dry iptables -A FORWARD -i wg0 -o wg1 -j ACCEPT 2>/dev/null || true
    dry iptables -C FORWARD -i wg1 -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || dry iptables -A FORWARD -i wg1 -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    dry iptables -C FORWARD -i wg0 -o "${wan}" -j ACCEPT 2>/dev/null || dry iptables -A FORWARD -i wg0 -o "${wan}" -j ACCEPT 2>/dev/null || true
    dry iptables -C FORWARD -i "${wan}" -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || dry iptables -A FORWARD -i "${wan}" -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    dry iptables -t nat -C POSTROUTING -o wg1 -j MASQUERADE 2>/dev/null || dry iptables -t nat -A POSTROUTING -o wg1 -j MASQUERADE 2>/dev/null || true
    log "Saving iptables rules..."
    dry netfilter-persistent save 2>/dev/null || mkdir -p /etc/iptables 2>/dev/null; dry iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
}

__install_mgmt_routing() {
    title "[3/7] Anti-lockout (tabla mgmt 100)"
    # Crear tabla (limpiar duplicados previos)
    dry sed -i '/^100\s\+mgmt/d' /etc/iproute2/rt_tables 2>/dev/null || true
    dry bash -c "echo '100 mgmt' >> /etc/iproute2/rt_tables"
    local wan_ip
    wan_ip=$(__detect_ip "$(__detect_wan)" | cut -d/ -f1)
    local gw
    gw=$(ip route show default 2>/dev/null | grep -oP 'via \K\S+' | head -1 || echo "")
    if [[ -n "$gw" && "$wan_ip" != "0.0.0.0" ]]; then
        dry ip route add default via "$gw" dev "$(__detect_wan)" table mgmt 2>/dev/null || true
        dry ip rule add from "$wan_ip" table mgmt priority 100 2>/dev/null || true
        log "Regla mgmt agregada: ${wan_ip} → tabla 100"
    else
        warn "No gateway detected, skipping mgmt routing (can be configured manually)"
    fi

    # Instalar systemd service para persistencia en boot
    local persist_script="/usr/local/bin/wg-multihop-persist.sh"
    local persist_unit="/etc/systemd/system/wg-multihop-persist.service"
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0")")

    dry cp "${script_dir}/wg-multihop-persist.sh" "$persist_script" 2>/dev/null || \
        dry install -m 755 /dev/null "$persist_script"
    dry cp "${script_dir}/wg-multihop-persist.service" "$persist_unit" 2>/dev/null || \
        dry install -m 644 /dev/null "$persist_unit"

    if [[ "$DRY_RUN" != "1" ]]; then
        chmod 755 "$persist_script" 2>/dev/null || true
        chmod 644 "$persist_unit" 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable wg-multihop-persist.service 2>/dev/null || true
        systemctl start wg-multihop-persist.service 2>/dev/null || true
        log "systemd service wg-multihop-persist installed and enabled"
    else
        echo "    [DRY-RUN] cp + chmod + systemctl enable wg-multihop-persist.service" >&2
    fi
}

__install_wg0() {
    title "[6/7] Configuring wg0 (clients)"
    local priv
    priv=$(cat "${WG_DIR}/vps_private.key" 2>/dev/null || wg genkey)
    local pub
    pub=$(echo "$priv" | wg pubkey)
    echo "$priv" > "${WG_DIR}/vps_private.key"
    echo "$pub" > "${WG_DIR}/vps_public.key"

    local subnet_base subnet_prefix vps_ip
    subnet_base="${WG0_SUBNET%.*}"
    subnet_prefix="${WG0_SUBNET#*/}"
    vps_ip="${subnet_base}.1/${subnet_prefix}"

    cat > "${WG_DIR}/wg0.conf" << EOF
[Interface]
PrivateKey = ${priv}
Address = ${vps_ip}
ListenPort = ${WG_PORT}
MTU = ${WG0_MTU}
Table = off

PostUp = ip rule add to ${subnet_base}.0/${subnet_prefix} table main priority 99 2>/dev/null || true
PostUp = ip rule add from ${subnet_base}.0/${subnet_prefix} table wg_clients priority 200 2>/dev/null || true
PostUp = ip route add default dev wg1 table wg_clients 2>/dev/null || true
PostUp = ip route add ${subnet_base}.0/${subnet_prefix} dev wg0 table wg_clients 2>/dev/null || true
PostUp = ip route add blackhole 0.0.0.0/0 table wg_clients metric 999 2>/dev/null || true
PostUp = iptables -C FORWARD -i wg0 -o wg1 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -o wg1 -j ACCEPT 2>/dev/null || true
PostUp = iptables -C FORWARD -i wg1 -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg1 -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
PostUp = iptables -t nat -C POSTROUTING -o wg1 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o wg1 -j MASQUERADE 2>/dev/null || true

PostDown = ip rule del to ${subnet_base}.0/${subnet_prefix} table main 2>/dev/null || true
PostDown = ip rule del from ${subnet_base}.0/${subnet_prefix} table wg_clients 2>/dev/null || true
PostDown = ip route flush table wg_clients 2>/dev/null || true
PostDown = iptables -D FORWARD -i wg0 -o wg1 -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i wg1 -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o wg1 -j MASQUERADE 2>/dev/null || true
EOF
    dry chmod 600 "${WG_DIR}/wg0.conf"
    dry sed -i '/^200\s\+wg_clients/d' /etc/iproute2/rt_tables 2>/dev/null || true
    dry bash -c "echo '200 wg_clients' >> /etc/iproute2/rt_tables"
    log "Bringing up wg0..."
    run_wg_quick "${WG_DIR}/wg0.conf" up || true

    # PostUp may fail (ip route add default dev wg1 might be early)
    # so retry routes manually
    local wg0_verify
    for wg0_verify in 1 2 3; do
        if ip route show table wg_clients 2>/dev/null | grep "default.*wg1" >/dev/null 2>&1 && \
           ip route show table wg_clients 2>/dev/null | grep "blackhole" >/dev/null 2>&1; then
            break
        fi
        sleep 1
        ip rule add to ${subnet_base}.0/${subnet_prefix} table main priority 99 2>/dev/null || true
        ip route add default dev wg1 table wg_clients 2>/dev/null || true
        ip route add ${subnet_base}.0/${subnet_prefix} dev wg0 table wg_clients 2>/dev/null || true
        ip route add blackhole 0.0.0.0/0 table wg_clients metric 999 2>/dev/null || true
    done
    dry mkdir -p "$CLIENT_DIR"
}

__install_wg1() {
    local vps_ip="$1"
    title "[4/7] Configuring wg1 — primary provider"

    if [[ -z "${WG1_ENDPOINT:-}" || -z "${SS_PUB:-}" ]]; then
        err "Missing Surfshark data (WG1_ENDPOINT or SS_PUB)"
        err "Configure a .conf file or set environment variables"
        return 1
    fi

    local priv
    if [[ -f "${WG_DIR}/wg1_private.key" ]]; then
        priv=$(cat "${WG_DIR}/wg1_private.key")
        info "Using wg1-specific private key"
    else
        priv=$(cat "${WG_DIR}/vps_private.key")
    fi

    cat > "${WG_DIR}/wg1.conf" << EOF
[Interface]
PrivateKey = ${priv}
Address = ${vps_ip}/32
MTU = ${WG1_MTU}
Table = off

[Peer]
PublicKey = ${SS_PUB}
Endpoint = ${WG1_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = ${WG1_KEEPALIVE}
EOF
    dry chmod 600 "${WG_DIR}/wg1.conf"
    log "Bringing up wg1..."
    run_wg_quick "${WG_DIR}/wg1.conf" up || true
    # Forzar handshake inicial
    local peer
    peer=$(wg show wg1 peers 2>/dev/null | head -1 || true)
    [[ -n "$peer" ]] && dry wg set wg1 peer "$peer" endpoint "${WG1_ENDPOINT}" 2>/dev/null || true
    dry bash -c "echo 'ON' > '${MULTIHOP_STATE}'"
}

__install_wg2() {
    local vps_ip="$1"
    title "[5/7] Configuring wg2 — backup provider"

    if [[ -z "${WG2_ENDPOINT:-}" || -z "${SS2_PUB:-}" ]]; then
        err "Missing backup provider data (WG2_ENDPOINT or SS2_PUB)"
        return 1
    fi

    if [[ -f "${WG_DIR}/vps_private.key" ]]; then
        local priv
        priv=$(cat "${WG_DIR}/vps_private.key")
    else
        err "No VPS private key found"
        return 1
    fi

    cat > "${WG_DIR}/wg2.conf" << EOF
[Interface]
PrivateKey = ${priv}
Address = ${vps_ip}/32
MTU = ${WG2_MTU}
Table = off

[Peer]
PublicKey = ${SS2_PUB}
Endpoint = ${WG2_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = ${WG2_KEEPALIVE}
EOF
    dry chmod 600 "${WG_DIR}/wg2.conf"
    log "Bringing up wg2..."
    run_wg_quick "${WG_DIR}/wg2.conf" up || true
    local peer
    peer=$(wg show wg2 peers 2>/dev/null | head -1 || true)
    [[ -n "$peer" ]] && dry wg set wg2 peer "$peer" endpoint "${WG2_ENDPOINT}" 2>/dev/null || true
}

__install_watchdog() {
    title "[7/7] Watchdog + Cron"
    local script_path
    script_path=$(readlink -f "$0")
    # Usar /etc/cron.d (formato correcto: incluye usuario root)
    dry mkdir -p /etc/cron.d
    dry bash -c "echo '*/5 * * * * root bash ${script_path} watchdog >/dev/null 2>&1' > /etc/cron.d/wg-multihop" 2>/dev/null || {
        # Fallback: crontab de root (SIN columna usuario)
        dry bash -c "(crontab -l 2>/dev/null; echo '*/5 * * * * bash ${script_path} watchdog >/dev/null 2>&1') | crontab -" 2>/dev/null || true
    }
    log "Watchdog installed (every 5 minutes)"
}

# ============================================================================
# Internas — clientes
# ============================================================================

__get_next_ip() {
    local base
    base=$(echo "${WG0_SUBNET}" | sed 's/\.0\/[0-9]*$/.0/')
    local prefix
    prefix=$(echo "${base}" | grep -oP '^\d+\.\d+\.\d+')
    local last=2
    if [[ -f "${WG_DIR}/wg0.conf" ]]; then
        last=$(grep -oP "AllowedIPs = \\K${prefix//./\\.}\\.\\d+" "${WG_DIR}/wg0.conf" 2>/dev/null | \
               grep -oP '\d+$' | sort -n | tail -1 || echo "2")
    fi
    echo "${prefix}.$((last + 1))/32"
}

__add_peer_to_wg0() {
    local name="$1" pub="$2" ip="$3"
    # Remover peer existente del mismo nombre
    __remove_peer_from_wg0 "$name" 2>/dev/null || true
    cat >> "${WG_DIR}/wg0.conf" << EOF

# ${name}
[Peer]
PublicKey = ${pub}
AllowedIPs = ${ip}
PersistentKeepalive = 30
EOF
    if ! dry wg syncconf wg0 <(wg-quick strip "${WG_DIR}/wg0.conf" 2>/dev/null) 2>/dev/null; then
        dry wg addconf wg0 <(echo "[Peer]" ; echo "PublicKey = ${pub}" ; echo "AllowedIPs = ${ip}" ; echo "PersistentKeepalive = 30") 2>/dev/null || true
    fi
    log "wg0 recargado"
}

__remove_peer_from_wg0() {
    local name="$1"
    if [[ -f "${WG_DIR}/wg0.conf" ]]; then
        dry sed -i "/^# ${name}$/,/^$/d" "${WG_DIR}/wg0.conf" 2>/dev/null || true
    fi
    # Also try to remove by IP if we have it
    dry wg set wg0 peer "$name" remove 2>/dev/null || true
}

# ============================================================================
# Modos de comando
# ============================================================================

cmd_install() {
    check_root
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   WireGuard Multihop Installer      ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""

    # Pre-flight checks (no toca nada)
    __preflight

    local WAN_IFACE
    local MULTIHOP_ENABLE="${MULTIHOP_ENABLE:-n}"
    local WD_ENABLE="${WD_ENABLE:-y}"
    local SS_CITY WG1_ENDPOINT SS_PUB WG1_VPS_IP

    # Detectar WAN
    WAN_IFACE="${WAN_IFACE:-$(__detect_wan)}"
    prompt WAN_IFACE "Interfaz WAN (detectada: ${WAN_IFACE})" "$WAN_IFACE"

    prompt WG_PORT "WireGuard port" "$WG_PORT"
    prompt SSH_PORT "SSH port" "$SSH_PORT"

    prompt MULTIHOP_ENABLE "Enable multihop (exit via Surfshark)" "n"
    [[ "$MULTIHOP_ENABLE" =~ ^[Yy] ]] && MULTIHOP_ENABLE=1 || MULTIHOP_ENABLE=0

    if [[ "$MULTIHOP_ENABLE" == "1" ]]; then
        local SCRIPT_DIR
        SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
        local CONF_FILES=()
        local conf_f
        for conf_f in "$SCRIPT_DIR"/*.conf; do
            [[ -f "$conf_f" ]] && CONF_FILES+=("$conf_f")
        done

        # Auto-detectar .conf en el directorio del script si SURFSHARK_CONF no existe
        if [[ ! -f "$SURFSHARK_CONF" ]] && [[ "${#CONF_FILES[@]}" -gt 0 ]]; then
            if [[ "${#CONF_FILES[@]}" -eq 1 ]]; then
                SURFSHARK_CONF="${CONF_FILES[0]}"
                info "Detectado: ${SURFSHARK_CONF}"
            elif [[ "$BATCH" == "0" ]]; then
                echo ""
                info ".conf files detected in ${SCRIPT_DIR}:"
                local ci=0
                for conf_f in "${CONF_FILES[@]}"; do
                    ci=$((ci+1))
                    echo "  ${ci}) $(basename "$conf_f")"
                done
                echo "  0)  Enter data manually"
                local chosen
                prompt chosen "Select wg1 config file (0-${#CONF_FILES[@]})" ""
                if [[ "$chosen" =~ ^[0-9]+$ ]] && [[ "$chosen" -ge 1 ]] && [[ "$chosen" -le "${#CONF_FILES[@]}" ]]; then
                    SURFSHARK_CONF="${CONF_FILES[$((chosen-1))]}"
                    info "Using: ${SURFSHARK_CONF}"
                fi
            fi
        fi

        local ss_conf_path=""
        if [[ ! -f "$SURFSHARK_CONF" ]] && [[ "$BATCH" == "0" ]]; then
            prompt ss_conf_path "Path to .conf file de wg1 (leave empty to enter manually)" ""
            [[ -n "$ss_conf_path" ]] && SURFSHARK_CONF="$ss_conf_path"
        fi

        if [[ -f "$SURFSHARK_CONF" ]]; then
            if grep -q '^\[Interface\]' "$SURFSHARK_CONF" 2>/dev/null; then
                # Parsear archivo .conf estilo WireGuard
                info "Parseando ${SURFSHARK_CONF}..."
                local parsed_addr parsed_pub parsed_endpoint parsed_priv
                # Address del [Interface], solo el primer IP/prefix
                parsed_addr=$(grep -oP '^Address\s*=\s*\K[0-9./]+' "$SURFSHARK_CONF" | head -1 || true)
                # PrivateKey from [Interface] (key Surfshark assigned to this peer)
                parsed_priv=$(grep -oP '^PrivateKey\s*=\s*\K\S+' "$SURFSHARK_CONF" | head -1 || true)
                # PublicKey del [Peer] (Surfshark server)
                parsed_pub=$(grep -A10 '^\[Peer\]' "$SURFSHARK_CONF" | grep -oP '^PublicKey\s*=\s*\K\S+' | head -1 || true)
                # Endpoint del [Peer]
                parsed_endpoint=$(grep -A10 '^\[Peer\]' "$SURFSHARK_CONF" | grep -oP '^Endpoint\s*=\s*\K\S+' | head -1 || true)

                WG1_VPS_IP="${WG1_VPS_IP:-${parsed_addr:-10.2.0.2/32}}"
                [[ -z "${WG1_ENDPOINT:-}" ]] && WG1_ENDPOINT="${parsed_endpoint:-}"
                [[ -z "${SS_PUB:-}" ]] && SS_PUB="${parsed_pub:-}"
                if [[ -n "$parsed_priv" ]]; then
                    mkdir -p "$WG_DIR" 2>/dev/null || true
                    echo "$parsed_priv" > "${WG_DIR}/wg1_private.key"
                    chmod 600 "${WG_DIR}/wg1_private.key" 2>/dev/null || true
                fi

                if [[ -z "$WG1_ENDPOINT" || -z "$SS_PUB" ]]; then
                    warn "File incomplete — filling manually"
                else
                    info "Configuration extracted de ${SURFSHARK_CONF}"
                fi
            else
                # Formato legacy (variables shell)
                info "Reading ${SURFSHARK_CONF}..."
                source "$SURFSHARK_CONF"
                WG1_VPS_IP="${WG1_VPS_IP:-10.2.0.2/32}"
            fi
        fi

        # Completar valores faltantes
        [[ -z "${SS_CITY:-}" ]] && prompt SS_CITY "Surfshark city (usa-atl, usa-ny, usa-la)" "usa-atl"
        [[ -z "${WG1_ENDPOINT:-}" ]] && prompt WG1_ENDPOINT "Endpoint wg1 (IP:puerto)" ""
        [[ -z "${SS_PUB:-}" ]] && prompt SS_PUB "Public key del peer Surfshark" ""
        [[ -z "${WG1_VPS_IP:-}" ]] && prompt WG1_VPS_IP "IP interna wg1 (VPS)" "10.2.0.2/32"

        __validate_surfshark_conf || { err "Invalid Surfshark config. Abortando."; exit 1; }
    fi

    prompt WD_ENABLE "Auto-repair watchdog (self-heal every 5 min)" "y"
    [[ "$WD_ENABLE" =~ ^[Yy] ]] && WD_ENABLE=1 || WD_ENABLE=0

    # Resumen
    echo ""
    log "Summary of changes:"
    log "  • WireGuard: wg0 on port ${WG_PORT}"
    log "  • SSH: port ${SSH_PORT}"
    log "  • Firewall: SSH + WG + ICMP allowed, rest DROP"
    log "  • Multihop: $([ "$MULTIHOP_ENABLE" == "1" ] && echo "ON → Surfshark" || echo "OFF")"
    log "  • Anti-lockout: mgmt table (100)"
    log "  • Watchdog: $([ "$WD_ENABLE" == "1" ] && echo "every 5 min via cron" || echo "OFF")"
    echo ""

    if [[ "$BATCH" == "0" ]]; then
        confirm "Apply changes" "Y" || { info "Cancelled"; exit 0; }
    fi

    # Automatic rollback on failure
    _INSTALL_FAILED=1
    local wg0_was_up=0 wg1_was_up=0 rt_tables_modified=0
    local backup_file="/etc/iptables/rules.v4.pre-wg-multihop"

    cleanup_rollback() {
        if [[ "${_INSTALL_FAILED:-1}" == "1" ]]; then
            warn "Install failed — reverting changes..."
            if [[ -f "$backup_file" ]]; then
                iptables-restore < "$backup_file" 2>/dev/null || true
                log "iptables restauradas desde backup"
            fi
            wg-quick down "${WG_DIR}/wg0.conf" 2>/dev/null || true
            wg-quick down "${WG_DIR}/wg1.conf" 2>/dev/null || true
            if [[ "${rt_tables_modified:-0}" == "1" ]]; then
                sed -i '/^200 wg_clients/d' /etc/iproute2/rt_tables 2>/dev/null || true
                sed -i '/^100 mgmt/d' /etc/iproute2/rt_tables 2>/dev/null || true
            fi
            warn "Check errors above and fix before retrying."
            warn "For full recovery: bash $0 recover"
        fi
    }
    trap cleanup_rollback EXIT

    # Ejecutar (wg1 ANTES que wg0, porque wg0 PostUp referencia wg1)
    __install_wireguard
    __install_firewall "$WAN_IFACE"
    __install_mgmt_routing
    if [[ "$MULTIHOP_ENABLE" == "1" ]]; then
        WG1_VPS_IP="${WG1_VPS_IP:-10.2.0.2/32}"
        __install_wg1 "${WG1_VPS_IP%/*}"
        if [[ -n "${WG2_ENDPOINT:-}" && -n "${SS2_PUB:-}" ]]; then
            __install_wg2 "${WG2_VPS_IP%/*}"
        fi
    fi
    __install_wg0
    [[ "$WD_ENABLE" == "1" ]] && __install_watchdog

    # Persist config for future runs
    dry mkdir -p "$WG_DIR"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "    [DRY-RUN] cat > ${WG_PERSIST} (config persistente)" >&2
    else
        cat > "${WG_PERSIST}" << EOF
# wg-multihop persistent config
SSH_PORT="${SSH_PORT}"
WG_PORT="${WG_PORT}"
WAN_IFACE="${WAN_IFACE}"
EOF
        if [[ "$MULTIHOP_ENABLE" == "1" ]]; then
            cat >> "${WG_PERSIST}" << EOF2
SS_PUB="${SS_PUB:-}"
WG1_ENDPOINT="${WG1_ENDPOINT:-}"
WG1_VPS_IP="${WG1_VPS_IP:-}"
WG2_ENDPOINT="${WG2_ENDPOINT:-}"
SS2_PUB="${SS2_PUB:-}"
WG2_VPS_IP="${WG2_VPS_IP:-}"
EOF2
        fi
    fi

    _INSTALL_FAILED=0
    echo ""
    log "  Done. Your VPS is a WireGuard server."
    log "  To add clients: bash $(basename "$0") add-client <name>"
    log "  Emergency recovery: bash $(basename "$0") recover"
    echo ""

    # Post-install validation
    __post_install_validate
}

__post_install_validate() {
    title "Post-install — Validation"
    local errors=0

    # 1. Interfaces UP
    for iface in wg0 wg1; do
        if wg show "$iface" &>/dev/null 2>&1; then
            log "${iface}: UP"
        else
            warn "${iface}: DOWN"
            errors=1
        fi
    done

    # 2. Handshake providers
    for iface in wg1 wg2; do
        if wg show "$iface" &>/dev/null 2>&1; then
            local peer_hs
            peer_hs=$(wg show "$iface" latest-handshakes 2>/dev/null | awk '{print $2}' || echo "0")
            if [[ -n "$peer_hs" ]] && [[ "$peer_hs" -gt 0 ]]; then
                local now
                now=$(date +%s)
                log "Handshake ${iface}: hace $((now - peer_hs)) segundos"
            else
                warn "${iface} handshake: not yet established"
                errors=1
            fi
            local pub
            pub=$(wg show "$iface" peers 2>/dev/null | head -1 || true)
            if [[ -n "$pub" ]]; then
                log "Peer ${iface}: ${pub:0:20}..."
                local ep
                ep=$(wg show "$iface" endpoints 2>/dev/null | awk '{print $2}' || true)
                [[ -n "$ep" ]] && log "Endpoint ${iface}: ${ep}"
            fi
        fi
    done

    # 3. Routing table wg_clients
    if ip route show table wg_clients 2>/dev/null | grep "default" >/dev/null 2>&1; then
        log "Routing table wg_clients: default route OK"
    elif ip route show table 200 2>/dev/null | grep "default" >/dev/null 2>&1; then
        log "Routing table 200: default route OK"
    else
        warn "Routing table wg_clients: missing default route"
        errors=1
    fi
    if ip route show table wg_clients 2>/dev/null | grep "blackhole" >/dev/null 2>&1 || \
       ip route show table 200 2>/dev/null | grep "blackhole" >/dev/null 2>&1; then
        log "Routing table wg_clients: blackhole (kill switch) OK"
    else
        warn "Routing table wg_clients: missing blackhole"
    fi

    # 4. FORWARD rules
    for iface in wg1 wg2; do
        if [[ -f "${WG_DIR}/${iface}.conf" ]] || wg show "$iface" &>/dev/null 2>&1; then
            if iptables -L FORWARD -v -n 2>/dev/null | grep -q "wg0.*${iface}"; then
                log "FORWARD wg0→${iface} OK"
            else
                warn "FORWARD wg0→${iface} missing"
                errors=1
            fi
        fi
    done

    # 5. NAT MASQUERADE
    if iptables -t nat -L POSTROUTING 2>/dev/null | grep -q "MASQUERADE"; then
        log "NAT MASQUERADE OK"
    else
        warn "NAT MASQUERADE faltante"
    fi

    # 6. IP de salida (si hay handshake, por wg1 si multihop ON)
    if command -v curl &>/dev/null; then
        local exit_ip
        if wg show wg1 &>/dev/null 2>&1; then
            exit_ip=$(curl -s --max-time 5 --interface wg1 ifconfig.me 2>/dev/null || true)
        fi
        if [[ -z "$exit_ip" ]]; then
            exit_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || true)
        fi
        if [[ -n "$exit_ip" ]]; then
            log "Exit IP (client): ${exit_ip}"
        else
            warn "Could not determine exit IP"
        fi
    fi

    echo ""
    if [[ "$errors" -eq 0 ]]; then
        log "${GREEN}Post-install validation: OK${NC}"
    else
        warn "${YELLOW}Post-install validation: ${errors} advertencia(s)${NC}"
    fi
    echo ""
}

__parse_duration() {
    local dur="$1"
    local unit="${dur: -1}"
    local num="${dur%?}"
    local seconds=0
    case "$unit" in
        s|S) seconds=$num ;;
        m|M) seconds=$((num * 60)) ;;
        h|H) seconds=$((num * 3600)) ;;
        d|D) seconds=$((num * 86400)) ;;
        *) seconds=$((dur * 86400)) ;;
    esac
    echo "$seconds"
}

__format_remaining() {
    local secs="$1"
    if [[ "$secs" -le 0 ]]; then echo "expired"; return; fi
    local d=$((secs / 86400)) h=$(( (secs % 86400) / 3600 )) m=$(( (secs % 3600) / 60 ))
    local out=""
    [[ "$d" -gt 0 ]] && out="${d}d "
    [[ "$h" -gt 0 ]] && out="${out}${h}h "
    out="${out}${m}m"
    echo "$out"
}

cmd_add_client() {
    check_root
    local name="${1:-}" expires=""
    shift 2>/dev/null || true
    if [[ "${1:-}" == "--expires" ]]; then
        shift 2>/dev/null || true
        expires="${1:-}"
        shift 2>/dev/null || true
    fi
    if [[ -z "$name" ]]; then
        err "Usage: $0 add-client <name> [--expires <Nd|Nh|Nm>]"
        exit 1
    fi
    if [[ ! -f "${WG_DIR}/wg0.conf" ]]; then
        err "wg0.conf does not exist. Run 'install' first."
        exit 1
    fi

    log "Generating keys for ${name}..."
    local priv pub ip
    priv=$(wg genkey)
    pub=$(echo "$priv" | wg pubkey)
    ip=$(__get_next_ip)

    log "IP assigned: ${ip%/*}"
    __add_peer_to_wg0 "$name" "$pub" "$ip"

    # Save expiry if set
    local expiry_ts=0
    if [[ -n "$expires" ]]; then
        local delta
        delta=$(__parse_duration "$expires")
        expiry_ts=$(( $(date +%s) + delta ))
        echo "$expiry_ts" > "${CLIENT_DIR}/.${name}.expires" 2>/dev/null || true
        log "Expires in ${expires} ($(__format_remaining "$delta") remaining)"
    fi

    # Generate .conf
    local server_pub wan_endpoint
    server_pub=$(cat "${WG_DIR}/vps_public.key")
    wan_endpoint=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -1 || echo "0.0.0.0")

    dry mkdir -p "$CLIENT_DIR"
    cat > "${CLIENT_DIR}/${name}.conf" << EOF
[Interface]
PrivateKey = ${priv}
Address = ${ip}
DNS = ${CLIENT_DNS}
MTU = ${CLIENT_MTU}

[Peer]
PublicKey = ${server_pub}
Endpoint = ${wan_endpoint}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = ${CLIENT_KEEPALIVE}
EOF
    log "Configuration: ${CLIENT_DIR}/${name}.conf"
    if command -v qrencode &>/dev/null; then
        log "QR Code (scan with WireGuard app):"
        dry qrencode -t ansiutf8 < "${CLIENT_DIR}/${name}.conf" 2>/dev/null || true
    fi
}

cmd_remove_client() {
    check_root
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        err "Usage: $0 remove-client <nombre>"
        exit 1
    fi
    log "Removing client ${name}..."
    __remove_peer_from_wg0 "$name"
    dry rm -f "${CLIENT_DIR}/${name}.conf" "${CLIENT_DIR}/.${name}.expires"
    log "Client ${name} removed"
}

cmd_list_clients() {
    check_root
    if [[ ! -f "${WG_DIR}/wg0.conf" ]]; then
        err "wg0.conf does not exist"
        exit 1
    fi
    echo ""
    title "Clients"
    grep -B1 "^AllowedIPs" "${WG_DIR}/wg0.conf" 2>/dev/null | grep -v "^--" | \
        sed 's/# //' | sed 's/AllowedIPs = //' | paste - - | \
        awk '{ printf "  %-20s %s\n", $1, $2 }' || echo "  (none)"
    # Show expiry info
    local now cname
    now=$(date +%s)
    while read -r cname _; do
        local ef="${CLIENT_DIR}/.${cname}.expires"
        if [[ -f "$ef" ]]; then
            local ets remaining
            ets=$(cat "$ef" 2>/dev/null || echo 0)
            remaining=$((ets - now))
            if [[ "$remaining" -le 0 ]]; then
                printf "  %-20s expired\n" "$cname"
            else
                printf "  %-20s expires in %s\n" "$cname" "$(__format_remaining "$remaining")"
            fi
        fi
    done < <(grep -B1 "^AllowedIPs" "${WG_DIR}/wg0.conf" 2>/dev/null | grep "#" | sed 's/# //' | paste - - 2>/dev/null || true)
    echo ""

    if command -v wg &>/dev/null && wg show wg0 &>/dev/null 2>&1; then
        title "Active peers (handshake)"
        wg show wg0 latest-handshakes | awk '{
            if ($2 > 0) printf "  %s → %d s ago\n", $1, systime() - $2
            else printf "  %s → no handshake\n", $1
        }' 2>/dev/null || echo "  (unavailable)"
    fi
}

cmd_multihop() {
    check_root
    local action="${1:-toggle}"
    local current=""
    [[ -f "$MULTIHOP_STATE" ]] && current=$(cat "$MULTIHOP_STATE")

    if [[ "$action" == "on" ]]; then
        [[ "$current" == "ON" ]] && { info "Multihop is already ON"; exit 0; }
        log "Enabling multihop..."
        local peer
        peer=$(wg show wg1 peers 2>/dev/null | head -1 || true)
        if [[ -z "$peer" ]]; then
            err "wg1 is not configured. Run 'install' first."
            exit 1
        fi
        # Remove direct WAN route if exists
        local wan gw
        wan=$(__detect_wan)
        gw=$(ip route show default 2>/dev/null | grep -oP 'via \K\S+' | head -1 || echo "")
        if [[ -n "$gw" ]]; then
            dry ip route del default via "$gw" dev "$wan" table wg_clients 2>/dev/null || true
            dry iptables -t nat -D POSTROUTING -o "$wan" -j MASQUERADE 2>/dev/null || true
        fi
        # Bring up wg1
        dry wg-quick up "${WG_DIR}/wg1.conf" 2>/dev/null || true
        dry wg set wg1 peer "$peer" endpoint "$(grep -oP 'Endpoint = \K\S+' "${WG_DIR}/wg1.conf" 2>/dev/null)" 2>/dev/null || true
        # Bring up wg2 if configured
        if [[ -f "${WG_DIR}/wg2.conf" ]]; then
            dry wg-quick up "${WG_DIR}/wg2.conf" 2>/dev/null || true
            local peer2
            peer2=$(wg show wg2 peers 2>/dev/null | head -1 || true)
            [[ -n "$peer2" ]] && dry wg set wg2 peer "$peer2" endpoint "$(grep -oP 'Endpoint = \K\S+' "${WG_DIR}/wg2.conf" 2>/dev/null)" 2>/dev/null || true
        fi
        dry ip rule add to "${WG0_SUBNET}" table main priority 99 2>/dev/null || true
        dry ip route add default dev wg1 table wg_clients 2>/dev/null || true
        dry iptables -t nat -C POSTROUTING -o wg1 -j MASQUERADE 2>/dev/null || dry iptables -t nat -A POSTROUTING -o wg1 -j MASQUERADE 2>/dev/null || true
        dry bash -c "echo 'ON' > '${MULTIHOP_STATE}'"
        dry bash -c "echo 'wg1' > '${ACTIVE_PROVIDER}'"
        log "Multihop enabled — client traffic exits via primary provider"
    elif [[ "$action" == "off" ]]; then
        [[ "$current" == "OFF" ]] && { info "Multihop is already OFF"; exit 0; }
        log "Disabling multihop..."
        local wan gw
        wan=$(__detect_wan)
        gw=$(ip route show default 2>/dev/null | grep -oP 'via \K\S+' | head -1 || echo "")
        # Remove MASQUERADE from providers + bring them down
        for iface in wg1 wg2; do
            if [[ -f "${WG_DIR}/${iface}.conf" ]] && wg show "$iface" &>/dev/null 2>&1; then
                dry iptables -t nat -D POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null || true
                dry wg-quick down "${WG_DIR}/${iface}.conf" 2>/dev/null || true
            fi
        done
        if [[ -n "$gw" ]]; then
            dry ip route replace default via "$gw" dev "$wan" table wg_clients 2>/dev/null || \
                dry ip route add default via "$gw" dev "$wan" table wg_clients 2>/dev/null || true
            dry iptables -t nat -A POSTROUTING -o "$wan" -j MASQUERADE 2>/dev/null || true
            dry bash -c "echo 'OFF' > '${MULTIHOP_STATE}'"
            dry bash -c "echo '' > '${ACTIVE_PROVIDER}'"
            log "Multihop disabled — client traffic exits via direct VPS IP (${wan})"
        else
            warn "No WAN gateway detected — clients without internet"
            dry bash -c "echo 'OFF' > '${MULTIHOP_STATE}'"
            dry bash -c "echo '' > '${ACTIVE_PROVIDER}'"
        fi
    else
        # toggle
        if [[ "$current" == "ON" ]]; then
            cmd_multihop off
        else
            cmd_multihop on
        fi
    fi
}

__set_active_provider() {
    local iface="$1"
    local tb="wg_clients"
    if [[ "$iface" != "wg1" && "$iface" != "wg2" ]]; then
        warn "Invalid provider: $iface (use wg1 or wg2)"
        return 1
    fi
    if ! ip link show "$iface" &>/dev/null; then
        warn "Interface $iface does not exist"
        return 1
    fi
    log "Switching active provider to $iface..."
    # Remove current default from wg_clients table
    for tbl in "$tb" 200; do
        local cur
        cur=$(ip route show table "$tbl" 2>/dev/null | grep "^default" || true)
        [[ -n "$cur" ]] && dry ip route del table "$tbl" "$cur" 2>/dev/null || true
    done
    # Add new default via active provider
    dry ip route add default dev "$iface" table "$tb" 2>/dev/null || \
    dry ip route add default dev "$iface" table 200 2>/dev/null || true
    dry bash -c "echo '${iface}' > '${ACTIVE_PROVIDER}'"
    info "Active provider: ${iface}"
}

cmd_failover() {
    check_root
    local target="${1:-}"
    local current="wg1"
    [[ -f "$ACTIVE_PROVIDER" ]] && current=$(cat "$ACTIVE_PROVIDER")

    if [[ -z "$target" ]]; then
        echo ""
        title "Failover Status"
        echo "  Active provider: $current"
        for iface in wg1 wg2; do
            if wg show "$iface" &>/dev/null 2>&1; then
                local hs
                hs=$(wg show "$iface" latest-handshakes 2>/dev/null | awk '{if($2>0) print systime()-$2" s ago"; else print "no handshake"}')
                echo "  $iface handshake: $hs"
            fi
        done
        echo ""
        return
    fi

    if [[ "$target" != "wg1" && "$target" != "wg2" ]]; then
        err "Usage: $0 failover [wg1|wg2]"
        exit 1
    fi
    if [[ "$target" == "$current" ]]; then
        info "Already using $target"
        exit 0
    fi
    __set_active_provider "$target"
}

cmd_status() {
    echo ""
    title "WireGuard Multihop — Dashboard"
    # Multihop state
    local mh="OFF"
    [[ -f "$MULTIHOP_STATE" ]] && mh=$(cat "$MULTIHOP_STATE")
    echo -e "  Multihop:     $([ "$mh" == "ON" ] && echo -e "${GREEN}ON${NC}" || echo -e "${YELLOW}OFF${NC}")"
    local active="wg1"
    [[ -f "$ACTIVE_PROVIDER" ]] && active=$(cat "$ACTIVE_PROVIDER")
    echo -e "  Active:       ${CYAN}${active}${NC}"
    echo ""

    # WG interfaces
    for iface in wg0 wg1 wg2; do
        if wg show "$iface" &>/dev/null 2>&1; then
            title "${iface}"
            wg show "$iface" 2>/dev/null | head -6 | sed 's/^/  /'
        fi
    done

    # Firewall
    title "Firewall (FORWARD)"
    iptables -L FORWARD -v -n 2>/dev/null | head -5 | sed 's/^/  /'

    title "NAT (MASQUERADE)"
    iptables -t nat -L POSTROUTING -v -n 2>/dev/null | head -5 | sed 's/^/  /'

    # Sistema
    local mem mem_total
    mem=$(free -m | awk '/Mem:/{print $4}')
    mem_total=$(free -m | awk '/Mem:/{print $2}')
    echo ""
    info "RAM libre: ${mem}/${mem_total} MB"
    info "Disk: $(df -h / | awk 'NR==2{print $4}') libre de $(df -h / | awk 'NR==2{print $2}')"
    echo ""
}

__install_tor() {
    if command -v tor &>/dev/null; then
        info "Tor already installed"
        return 0
    fi
    log "Installing Tor..."
    if command -v apt &>/dev/null; then
        dry bash -c "apt update && apt install -y tor socat" 2>/dev/null || \
        dry bash -c "apt install -y tor socat" 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dry bash -c "dnf install -y tor socat" 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        dry bash -c "yum install -y tor socat" 2>/dev/null || true
    elif command -v apk &>/dev/null; then
        dry bash -c "apk add tor socat" 2>/dev/null || true
    else
        err "No package manager found for Tor install"
        return 1
    fi
    log "Tor installed"
}

__tor_config() {
    local conf="/etc/tor/torrc"
    if [[ -f "$conf" ]]; then
        # Backup original
        dry cp "$conf" "${conf}.bak.$(date +%s)" 2>/dev/null || true
    fi
    cat > "$conf" << TOREOF
## wg-multihop Tor config
## Transparent proxy + DNS
SOCKSPort 127.0.0.1:${TOR_SOCKS_PORT}
TransPort 127.0.0.1:${TOR_PORT}
DNSPort 127.0.0.1:${TOR_DNS_PORT}
## Don't use exit nodes for local/WG ranges
ExitPolicy reject 10.0.0.0/8:*
ExitPolicy reject 172.16.0.0/12:*
ExitPolicy reject 192.168.0.0/16:*
## Hardware acceleration
HardwareAccel 1
## Log
Log notice syslog
DataDirectory /var/lib/tor
TOREOF
    dry chmod 644 "$conf"
}

cmd_tor() {
    check_root
    local action="${1:-status}"
    local tor_running=0
    pidof tor &>/dev/null && tor_running=1

    case "$action" in
        on|start)
            if [[ "$tor_running" == "1" ]]; then
                info "Tor is already running"
                exit 0
            fi
            __install_tor || exit 1
            __tor_config
            dry bash -c "systemctl enable tor 2>/dev/null || true"
            dry bash -c "systemctl restart tor 2>/dev/null || service tor restart 2>/dev/null || true"
            sleep 2
            if pidof tor &>/dev/null; then
                log "Tor started (SOCKS :${TOR_SOCKS_PORT}, Trans :${TOR_PORT}, DNS :${TOR_DNS_PORT})"
            else
                err "Tor failed to start — check journalctl -u tor"
                exit 1
            fi
            # iptables: redirect VPS-originated TCP through Tor
            # Create TOR chain in nat table
            iptables -t nat -N TOR 2>/dev/null || iptables -t nat -F TOR 2>/dev/null || true
            # Exclude traffic going out via wg interfaces
            for iface in wg0 wg1 wg2; do
                iptables -t nat -A TOR -o "$iface" -j RETURN 2>/dev/null || true
            done
            # Exclude local/rfc1918
            for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
                iptables -t nat -A TOR -d "$net" -j RETURN 2>/dev/null || true
            done
            # Exclude Tor's own traffic
            iptables -t nat -A TOR -m owner --uid-owner "$TOR_USER" -j RETURN 2>/dev/null || true
            # Redirect remaining TCP to TransPort
            iptables -t nat -A TOR -p tcp -j REDIRECT --to-port "${TOR_PORT}" 2>/dev/null || true
            # Apply to OUTPUT chain
            iptables -t nat -A OUTPUT -p tcp -j TOR 2>/dev/null || true
            # Redirect UDP 53 through Tor DNS
            iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port "${TOR_DNS_PORT}" 2>/dev/null || true
            # Accept DNS through Tor's DNSPort
            iptables -A INPUT -p udp --dport "${TOR_DNS_PORT}" -s 127.0.0.1 -j ACCEPT 2>/dev/null || true
            log "Tor transparent proxy active"
            ;;
        off|stop)
            if [[ "$tor_running" == "0" ]]; then
                info "Tor is not running"
            fi
            # Remove iptables rules
            iptables -t nat -D OUTPUT -p tcp -j TOR 2>/dev/null || true
            iptables -t nat -F TOR 2>/dev/null || true
            iptables -t nat -X TOR 2>/dev/null || true
            iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-port "${TOR_DNS_PORT}" 2>/dev/null || true
            iptables -D INPUT -p udp --dport "${TOR_DNS_PORT}" -s 127.0.0.1 -j ACCEPT 2>/dev/null || true
            dry bash -c "systemctl stop tor 2>/dev/null || service tor stop 2>/dev/null || pkill tor 2>/dev/null || true"
            log "Tor stopped and rules cleaned"
            ;;
        status)
            echo ""
            title "Tor Status"
            if [[ "$tor_running" == "1" ]]; then
                echo -e "  Status:   ${GREEN}running${NC}"
                echo "  SOCKS:    127.0.0.1:${TOR_SOCKS_PORT}"
                echo "  Trans:    127.0.0.1:${TOR_PORT}"
                echo "  DNS:      127.0.0.1:${TOR_DNS_PORT}"
                # Show active circuits
                local circuits
                circuits=$(echo -e "GETINFO circuit-status" | nc -w1 127.0.0.1 "${TOR_SOCKS_PORT}" 2>/dev/null | grep "BUILT" | wc -l || echo "0")
                echo "  Circuits: ${circuits}"
                # Check if TOR iptables chain exists
                if iptables -t nat -L TOR &>/dev/null 2>&1; then
                    echo -e "  Proxy:    ${GREEN}active${NC}"
                else
                    echo -e "  Proxy:    ${YELLOW}inactive${NC}"
                fi
            else
                echo -e "  Status:   ${YELLOW}stopped${NC}"
            fi
            echo ""
            ;;
        *)
            err "Usage: $0 tor [on|off|status]"
            exit 1
            ;;
    esac
}

cmd_watchdog() {
    # Silent — corre cada 5 min desde cron, solo logea si repara algo
    local logfile="/var/log/wg-watchdog.log"
    local fixed=0

    # 1. wg0
    if ! wg show wg0 &>/dev/null 2>&1; then
        echo "[$(date)] wg0 down — restarting" >> "$logfile"
        wg-quick up "${WG_DIR}/wg0.conf" 2>/dev/null && fixed=1
    fi

    # 2. Active provider check (wg1 or wg2) — failover + restart
    if [[ -f "$MULTIHOP_STATE" ]] && [[ "$(cat "$MULTIHOP_STATE")" == "ON" ]]; then
        local cur="wg1"
        [[ -f "$ACTIVE_PROVIDER" ]] && cur=$(cat "$ACTIVE_PROVIDER")
        local backup=""
        if [[ -f "${WG_DIR}/wg2.conf" ]]; then
            [[ "$cur" == "wg1" ]] && backup="wg2" || backup="wg1"
        fi

        if ! wg show "$cur" &>/dev/null 2>&1; then
            echo "[$(date)] ${cur} down — attempting failover" >> "$logfile"
            if [[ -n "$backup" ]] && [[ -f "${WG_DIR}/${backup}.conf" ]] && wg show "$backup" &>/dev/null 2>&1; then
                echo "[$(date)] Failing over to ${backup}" >> "$logfile"
                __set_active_provider "$backup" &>/dev/null || true
                fixed=1
            else
                echo "[$(date)] ${cur} down — restarting" >> "$logfile"
                wg-quick up "${WG_DIR}/${cur}.conf" 2>/dev/null && fixed=1
            fi
        else
            local handshake
            handshake=$(wg show "$cur" latest-handshakes 2>/dev/null | awk '{print $2}' || echo "0")
            if [[ -n "$handshake" ]] && [[ "$handshake" -gt 0 ]]; then
                local now
                now=$(date +%s)
                if [[ $((now - handshake)) -gt ${WG_HANDSHAKE_TIMEOUT} ]]; then
                    if [[ -n "$backup" ]] && [[ -f "${WG_DIR}/${backup}.conf" ]]; then
                        echo "[$(date)] ${cur} stale — attempting failover to ${backup}" >> "$logfile"
                        wg-quick up "${WG_DIR}/${backup}.conf" 2>/dev/null || true
                        sleep 1
                        __set_active_provider "$backup" &>/dev/null || true
                        fixed=1
                    else
                        echo "[$(date)] ${cur} handshake >${WG_HANDSHAKE_TIMEOUT}s — restarting" >> "$logfile"
                        wg-quick down "${WG_DIR}/${cur}.conf" 2>/dev/null
                        sleep 1
                        wg-quick up "${WG_DIR}/${cur}.conf" 2>/dev/null && fixed=1
                    fi
                fi
            fi
        fi
    fi

    # 3. Mgmt table
    local wan_ip gw
    wan_ip=$(__detect_ip "$(__detect_wan)" | cut -d/ -f1)
    gw=$(ip route show default 2>/dev/null | grep -oP 'via \K\S+' | head -1 || echo "")
    if [[ -n "$gw" && "$wan_ip" != "0.0.0.0" ]]; then
        # Ensure rt_tables has mgmt entry
        if ! grep -q "^100\s\+mgmt" /etc/iproute2/rt_tables 2>/dev/null; then
            echo "[$(date)] rt_tables mgmt faltante — restaurando" >> "$logfile"
            echo '100 mgmt' >> /etc/iproute2/rt_tables
            fixed=1
        fi
        if ! ip rule show 2>/dev/null | grep -q "from ${wan_ip}.*table mgmt"; then
            echo "[$(date)] mgmt rule faltante — restaurando" >> "$logfile"
            ip route add default via "$gw" dev "$(__detect_wan)" table mgmt 2>/dev/null || true
            ip rule add from "$wan_ip" table mgmt priority 100 2>/dev/null || true
            fixed=1
        fi
        if ! ip route show table mgmt 2>/dev/null | grep -q default; then
            echo "[$(date)] mgmt route faltante — restaurando" >> "$logfile"
            ip route add default via "$gw" dev "$(__detect_wan)" table mgmt 2>/dev/null || true
            fixed=1
        fi
        # Ensure systemd persist service is active
        if ! systemctl is-active --quiet wg-multihop-persist.service 2>/dev/null; then
            echo "[$(date)] systemd persist service caido — reiniciando" >> "$logfile"
            systemctl start wg-multihop-persist.service 2>/dev/null || true
            fixed=1
        fi
    fi

    # 4. Routing table wg_clients (routes + blackhole)
    local tb="wg_clients"
    local active_def="wg1"
    [[ -f "$ACTIVE_PROVIDER" ]] && active_def=$(cat "$ACTIVE_PROVIDER")
    # Ensure rt_tables has wg_clients entry
    if ! grep -q "^200\s\+wg_clients" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "[$(date)] rt_tables wg_clients faltante — restaurando" >> "$logfile"
        echo '200 wg_clients' >> /etc/iproute2/rt_tables
        fixed=1
    fi
    if ! ip route show table "$tb" 2>/dev/null | grep -q "default" && \
       ! ip route show table 200 2>/dev/null | grep -q "default"; then
        echo "[$(date)] wg_clients default route faltante — restaurando via ${active_def}" >> "$logfile"
        ip route add default dev "$active_def" table "$tb" 2>/dev/null || \
        ip route add default dev "$active_def" table 200 2>/dev/null || true
        fixed=1
    fi
    local bh_route
    bh_route=$(ip route show table "$tb" 2>/dev/null | grep "blackhole" || ip route show table 200 2>/dev/null | grep "blackhole" || true)
    if [[ -z "$bh_route" ]]; then
        echo "[$(date)] wg_clients blackhole kill-switch faltante — restaurando" >> "$logfile"
        ip route add blackhole 0.0.0.0/0 table "$tb" metric 999 2>/dev/null || \
        ip route add blackhole 0.0.0.0/0 table 200 metric 999 2>/dev/null || true
        fixed=1
    fi
    local subnet="${WG0_SUBNET%%/*}"
    if ! ip rule show 2>/dev/null | grep "to ${WG0_SUBNET}.*table main" >/dev/null 2>&1; then
        echo "[$(date)] ip rule to ${WG0_SUBNET} table main faltante — restaurando" >> "$logfile"
        ip rule add to "${WG0_SUBNET}" table main priority 99 2>/dev/null || true
        fixed=1
    fi
    if ! ip rule show 2>/dev/null | grep "from ${WG0_SUBNET}.*wg_clients\|from ${WG0_SUBNET}.*table 200" >/dev/null 2>&1; then
        echo "[$(date)] ip rule wg_clients faltante — restaurando" >> "$logfile"
        ip rule add from "${WG0_SUBNET}" table "$tb" priority 200 2>/dev/null || true
        fixed=1
    fi

    # 5. FORWARD rules
    if ! iptables -L FORWARD -v -n 2>/dev/null | grep -q "wg0.*wg1"; then
        echo "[$(date)] FORWARD wg0→wg1 faltante — restaurando" >> "$logfile"
        iptables -A FORWARD -i wg0 -o wg1 -j ACCEPT 2>/dev/null || true
        iptables -A FORWARD -i wg1 -o wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        iptables -t nat -A POSTROUTING -o wg1 -j MASQUERADE 2>/dev/null || true
        fixed=1
    fi

    # 6. Expired clients
    local now cname
    now=$(date +%s)
    while read -r cname _; do
        local ef="${CLIENT_DIR}/.${cname}.expires"
        if [[ -f "$ef" ]]; then
            local ets
            ets=$(cat "$ef" 2>/dev/null || echo 0)
            if [[ "$now" -ge "$ets" ]]; then
                echo "[$(date)] Client ${cname} expired — removing" >> "$logfile"
                __remove_peer_from_wg0 "$cname"
                dry rm -f "${CLIENT_DIR}/${cname}.conf" "$ef"
                fixed=1
            fi
        fi
    done < <(grep -B1 "^AllowedIPs" "${WG_DIR}/wg0.conf" 2>/dev/null | grep "#" | sed 's/# //' | paste - - 2>/dev/null || true)

    # 7. RAM
    local mem
    mem=$(free -m | awk '/Mem:/{print $4}')
    if [[ "$mem" -lt ${MIN_RAM_MB} ]]; then
        echo "[$(date)] Low RAM: ${mem}MB — clearing cache" >> "$logfile"
        dry bash -c "echo 3 > /proc/sys/vm/drop_caches" 2>/dev/null || true
        fixed=1
    fi

    [[ "$fixed" == "1" ]] && echo "[$(date)] Watchdog: healing applied" >> "$logfile"
}

cmd_uninstall() {
    check_root
    title "Uninstalling WireGuard Multihop"
    confirm "Are you sure? This will delete all WG configs, iptables rules, and routes" "n" || { info "Cancelled"; exit 0; }

    log "Deteniendo WireGuard..."
    dry wg-quick down "${WG_DIR}/wg0.conf" 2>/dev/null || true
    for iface in wg1 wg2; do
        [[ -f "${WG_DIR}/${iface}.conf" ]] && dry wg-quick down "${WG_DIR}/${iface}.conf" 2>/dev/null || true
    done

    log "Limpiando reglas iptables..."
    dry iptables -P INPUT ACCEPT 2>/dev/null || true
    dry iptables -P FORWARD ACCEPT 2>/dev/null || true
    dry iptables -P OUTPUT ACCEPT 2>/dev/null || true
    dry iptables -F 2>/dev/null || true
    dry iptables -t nat -F 2>/dev/null || true
    dry iptables -t mangle -F 2>/dev/null || true

    log "Eliminando reglas de ruteo..."
    dry ip rule del to "${WG0_SUBNET}" table main 2>/dev/null || true
    dry ip rule del from "${WG0_SUBNET}" table wg_clients 2>/dev/null || true
    dry ip rule del from "$(__detect_ip "$(__detect_wan)" | cut -d/ -f1)" table mgmt 2>/dev/null || true
    dry ip route flush table wg_clients 2>/dev/null || true
    dry ip route flush table mgmt 2>/dev/null || true

    log "Eliminando archivos..."
    dry rm -f "${WG_DIR}/wg0.conf" "${WG_DIR}/wg1.conf" "${WG_DIR}/wg2.conf" 2>/dev/null || true
    dry rm -f "${WG_DIR}/wg1_private.key" "${WG_DIR}/vps_private.key" "${WG_DIR}/vps_public.key" 2>/dev/null || true
    dry rm -f "$MULTIHOP_STATE" "$ACTIVE_PROVIDER" 2>/dev/null || true
    dry rm -rf "$CLIENT_DIR" 2>/dev/null || true

    log "Eliminando cron..."
    dry crontab -l 2>/dev/null | grep -v "wg-multihop.sh" | crontab - 2>/dev/null || true
    dry rm -f /etc/cron.d/wg-multihop 2>/dev/null || true

    log "Eliminando systemd persist service..."
    dry systemctl disable wg-multihop-persist.service 2>/dev/null || true
    dry systemctl stop wg-multihop-persist.service 2>/dev/null || true
    dry rm -f /etc/systemd/system/wg-multihop-persist.service 2>/dev/null || true
    dry rm -f /usr/local/bin/wg-multihop-persist.sh 2>/dev/null || true
    dry systemctl daemon-reload 2>/dev/null || true

    log "WireGuard Multihop desinstalado"
}

cmd_recover() {
    check_root
    title "Emergency network recovery"
    local backup_file="/etc/iptables/rules.v4.pre-wg-multihop"

    log "This command restores network connectivity WITHOUT deleting WireGuard configs."
    log "For full uninstall (delete all configs), use: bash $0 uninstall"
    echo ""

    if [[ -f "$backup_file" ]]; then
        log "Restaurando iptables desde backup..."
        iptables-restore < "$backup_file" 2>/dev/null || err "Error restaurando iptables"
        log "iptables restauradas"
    else
        warn "No hay backup de iptables (${backup_file} no existe)"
        warn "Firewall policies may have changed"
    fi

    log "Deteniendo WireGuard..."
    wg-quick down "${WG_DIR}/wg0.conf" 2>/dev/null || true
    for iface in wg1 wg2; do
        [[ -f "${WG_DIR}/${iface}.conf" ]] && wg-quick down "${WG_DIR}/${iface}.conf" 2>/dev/null || true
    done

    log "Restaurando ruta default vía WAN..."
    local wan_iface
    wan_iface=$(ip -4 route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || echo "eth0")
    local gw
    gw=$(ip -4 route show default 2>/dev/null | grep -oP 'via \K\S+' | head -1 || echo "")
    if [[ -n "$gw" && -n "$wan_iface" ]]; then
        ip route replace default via "$gw" dev "$wan_iface" 2>/dev/null || true
        log "Default route: via ${gw} dev ${wan_iface}"
    fi

    log "Limpiando reglas de ruteo de WireGuard..."
    ip rule del to "${WG0_SUBNET}" table main 2>/dev/null || true
    ip rule del from "${WG0_SUBNET}" table wg_clients 2>/dev/null || true
    ip rule del from "$(__detect_ip "$(__detect_wan)" | cut -d/ -f1)" table mgmt 2>/dev/null || true
    ip route flush table wg_clients 2>/dev/null || true
    ip route flush table mgmt 2>/dev/null || true
    # NOTA: NO eliminar rt_tables entries — se reusan al reinstalar

    log "Relanzando systemd persist service..."
    systemctl start wg-multihop-persist.service 2>/dev/null || true

    log "Recovery completo. WireGuard configs preserved en ${WG_DIR}"
    log "Para reactivar wg-multihop: bash $0 multihog on"
}

cmd_test() {
    check_root

    # Globales (necesarias en el EXIT trap)
    TMPDIR="/tmp/wg-multihop-test"
    NS_VPS="wgtest-mh-vps"
    NS_CLIENT="wgtest-mh-client"
    NS_SS="wgtest-mh-ss"
    VETH_V="mh-veth-v"
    VETH_C="mh-veth-c"
    VETH_V2="mh-veth-v2"
    VETH_S="mh-veth-s"
    client_wg0=""

    _test_cleanup() {
        local cl="${client_wg0:-}"
        [[ -n "$cl" ]] && ip netns exec "$NS_VPS" wg-quick down "$cl" 2>/dev/null || true
        for ns in "$NS_CLIENT" "$NS_VPS" "$NS_SS"; do
            ip netns exec "$ns" wg-quick down wg0 2>/dev/null || true
            ip netns exec "$ns" wg-quick down wg1 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        done
        for v in "$VETH_C" "$VETH_V" "$VETH_V2" "$VETH_S"; do
            ip link del "$v" 2>/dev/null || true
        done
        rm -rf "$TMPDIR" 2>/dev/null || true
    }
    trap _test_cleanup EXIT
    local WG_PORT="${WG_PORT:-51820}"
    local failed=0 passed=0

    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║   wg-multihop.sh — Self Test        ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""

    # Limpiar cualquier residuo
    for ns in "$NS_CLIENT" "$NS_VPS" "$NS_SS"; do
        if ip netns list 2>/dev/null | grep -q "$ns"; then
            ip netns exec "$ns" wg-quick down wg0 2>/dev/null || true
            ip netns exec "$ns" wg-quick down wg1 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        fi
    done
    for v in "$VETH_C" "$VETH_V" "$VETH_V2" "$VETH_S"; do
        ip link del "$v" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    mkdir -p "$TMPDIR"

    # --- Crear namespaces ---
    echo "  [lab] Creando namespaces..."
    ip netns add "$NS_CLIENT"
    ip netns add "$NS_VPS"
    ip netns add "$NS_SS"

    # --- Veth pairs ---
    ip link add "$VETH_C" type veth peer name "$VETH_V"
    ip link set "$VETH_C" netns "$NS_CLIENT"
    ip link set "$VETH_V" netns "$NS_VPS"

    ip link add "$VETH_V2" type veth peer name "$VETH_S"
    ip link set "$VETH_V2" netns "$NS_VPS"
    ip link set "$VETH_S" netns "$NS_SS"

    # --- IPs ---
    ip netns exec "$NS_CLIENT" ip addr add "10.99.0.2/24" dev "$VETH_C"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_C" up
    ip netns exec "$NS_CLIENT" ip link set lo up

    ip netns exec "$NS_VPS" ip addr add "10.99.0.1/24" dev "$VETH_V"
    ip netns exec "$NS_VPS" ip link set "$VETH_V" up
    ip netns exec "$NS_VPS" ip addr add "10.99.1.1/24" dev "$VETH_V2"
    ip netns exec "$NS_VPS" ip link set "$VETH_V2" up
    ip netns exec "$NS_VPS" ip link set lo up

    ip netns exec "$NS_SS" ip addr add "10.99.1.2/24" dev "$VETH_S"
    ip netns exec "$NS_SS" ip link set "$VETH_S" up
    ip netns exec "$NS_SS" ip link set lo up

    # --- Rutas entre namespaces ---
    ip netns exec "$NS_CLIENT" ip route replace 10.99.1.0/24 via 10.99.0.1
    ip netns exec "$NS_VPS" ip route replace 10.99.0.0/24 dev "$VETH_V"
    ip netns exec "$NS_VPS" ip route replace 10.99.1.0/24 dev "$VETH_V2"
    ip netns exec "$NS_SS" ip route replace 10.99.0.0/24 via 10.99.1.1

    # --- Generar claves Surfshark simulado ---
    echo "  [lab] Generating keys SS simuladas..."
    local ss_priv ss_pub vps_priv vps_pub
    ss_priv=$(wg genkey); ss_pub=$(echo "$ss_priv" | wg pubkey)

    # Generar VPS keys
    vps_priv=$(wg genkey); vps_pub=$(echo "$vps_priv" | wg pubkey)

    # Crear WG_DIR de prueba
    local WG_TEST_DIR="${TMPDIR}/vps-etc/wireguard"
    mkdir -p "$WG_TEST_DIR"
    echo "$vps_priv" > "$WG_TEST_DIR/vps_private.key"
    echo "$vps_pub" > "$WG_TEST_DIR/vps_public.key"

    # Iniciar Surfshark simulado (wg1 peer)
    echo "  [lab] Iniciando Surfshark simulado..."
    cat > "$TMPDIR/ss-wg1.conf" << EOF
[Interface]
PrivateKey = ${ss_priv}
Address = 10.2.0.1/32
ListenPort = ${WG_PORT}
MTU = 1320

[Peer]
PublicKey = ${vps_pub}
AllowedIPs = 0.0.0.0/0
EOF

    ip netns exec "$NS_SS" wg-quick up "$TMPDIR/ss-wg1.conf" 2>&1 | grep -v "Warning:" || true

    # --- Test 1: VPS reachability ---
    echo ""
    echo -n "  T1 - VPS → SS (veth): "
    if ip netns exec "$NS_VPS" ping -c 1 -W 2 10.99.1.2 &>/dev/null; then
        echo "OK"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    echo -n "  T2 - Client → VPS (veth): "
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.99.0.1 &>/dev/null; then
        echo "OK"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # --- Instalar wg-multihop dentro del VPS namespace ---
    echo ""
    echo "  [lab] Instalando wg-multihop en VPS namespace..."
    local SCRIPT_PATH
    SCRIPT_PATH=$(readlink -f "$0")
    cp "$SCRIPT_PATH" "$TMPDIR/wg-multihop.sh"
    chmod +x "$TMPDIR/wg-multihop.sh"

    # Preparar surfshark.conf para el VPS
    cat > "$TMPDIR/surfshark-test.conf" << EOF
WG1_ENDPOINT="10.99.1.2:${WG_PORT}"
SS_PUB="${ss_pub}"
WG1_VPS_IP="10.2.0.2/32"
EOF

    # Ejecutar install dentro del VPS namespace con variables de entorno
    local install_ok=1
    # Las variables de entorno fluyen al bash -c del ip netns exec
    export -p | grep -E "^(declare -x )?WG_" > /dev/null 2>&1 || true
    local install_out
    install_out=$(ip netns exec "$NS_VPS" env \
        BATCH=1 \
        WG_PORT="${WG_PORT}" \
        WG_DIR="${WG_TEST_DIR}" \
        CLIENT_DIR="${WG_TEST_DIR}/clients" \
        MULTIHOP_STATE="${WG_TEST_DIR}/.multihop_state" \
        SURFSHARK_CONF="${TMPDIR}/surfshark-test.conf" \
        WAN_IFACE="${VETH_V2}" \
        WG1_ENDPOINT="10.99.1.2:${WG_PORT}" \
        SS_PUB="${ss_pub}" \
        WG1_VPS_IP="10.2.0.2/32" \
        MULTIHOP_ENABLE="y" \
        WD_ENABLE="y" \
        bash "${TMPDIR}/wg-multihop.sh" install 2>&1) || install_ok=0
    echo "$install_out" | grep -E "(\[\+|\[!|\[x|\[i|error)" || true
    echo "$install_out" | grep -q "Done." && { echo -n "  T3 - Install on VPS: "; echo "OK"; passed=$((passed+1)); } || { echo -n "  T3 - Install on VPS: "; echo "FAIL"; failed=$((failed+1)); }

    # --- Test 4: Handshake wg1 ---
    echo -n "  T4 - Handshake wg1 (VPS↔SS): "
    local peer_hs
    peer_hs=$(ip netns exec "$NS_VPS" wg show wg1 2>/dev/null | grep "latest handshake" | awk '{print $3, $4}' || echo "")
    if [[ -n "$peer_hs" ]]; then
        echo "OK (${peer_hs})"; passed=$((passed+1))
    else
        # Forzar handshake
        local p peer
        peer=$(ip netns exec "$NS_VPS" wg show wg1 peers 2>/dev/null | head -1 || true)
        if [[ -n "$peer" ]]; then
            ip netns exec "$NS_VPS" wg set wg1 peer "$peer" endpoint "10.99.1.2:${WG_PORT}" 2>/dev/null || true
            sleep 2
            peer_hs=$(ip netns exec "$NS_VPS" wg show wg1 2>/dev/null | grep "latest handshake" | awk '{print $3, $4}' || echo "")
            if [[ -n "$peer_hs" ]]; then
                echo "OK (${peer_hs})"; passed=$((passed+1))
            else
                echo "FAIL"; failed=$((failed+1))
            fi
        else
            echo "FAIL (sin peer)"; failed=$((failed+1))
        fi
    fi

    # --- Test 5: Client en namespace puede llegar a SS vía wg0+wg1 ---
    echo -n "  T5 - Client→SS (wg0+wg1): "
    local client_priv client_pub server_pub
    client_priv=$(wg genkey); client_pub=$(echo "$client_priv" | wg pubkey)
    server_pub=$(cat "$WG_TEST_DIR/vps_public.key" 2>/dev/null || echo "")

    # Add peer al VPS wg0
    ip netns exec "$NS_VPS" wg set wg0 peer "${client_pub}" allowed-ips 10.8.0.2/32 2>/dev/null || true
    local client_wg0="${TMPDIR}/mh-client-wg0.conf"
    cat > "$client_wg0" << EOF
[Interface]
PrivateKey = ${client_priv}
Address = 10.8.0.2/24
MTU = ${CLIENT_MTU:-1260}

[Peer]
PublicKey = ${server_pub}
Endpoint = 10.99.0.1:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 5
EOF
    ip netns exec "$NS_CLIENT" wg-quick up "$client_wg0" 2>&1 | grep -v "Warning:" || true
    sleep 2
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 3 10.2.0.1 &>/dev/null; then
        echo "OK (tunnel up)"
        # MTU chain verification: large payload should work with new defaults
        local mtu_test
        mtu_test=$(ip netns exec "$NS_CLIENT" ping -c 1 -W 2 -M do -s 1200 10.2.0.1 2>&1 || true)
        if echo "$mtu_test" | grep -q "message too long"; then
            echo "         ⚠ MTU chain: 1200b payload blocked — might need tuning"
        else
            echo "         ✓ MTU chain: 1200b payload OK"
        fi
        passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # --- Test 6: Routing table wg_clients ---
    echo -n "  T6 - Routing table wg_clients: "
    local t6_ok=0
    for _ in 1 2 3; do
        if ip netns exec "$NS_VPS" ip route show table wg_clients 2>/dev/null | grep "default" >/dev/null 2>&1 || \
           ip netns exec "$NS_VPS" ip route show table 200 2>/dev/null | grep "default" >/dev/null 2>&1; then
            t6_ok=1; break
        fi
        sleep 1
    done
    if [[ "$t6_ok" == "1" ]]; then echo "OK"; passed=$((passed+1)); else echo "FAIL"; failed=$((failed+1)); fi

    # --- Test 7: Blackhole ---
    echo -n "  T7 - Kill switch (blackhole): "
    local t7_ok=0
    for _ in 1 2 3; do
        if ip netns exec "$NS_VPS" ip route show table wg_clients 2>/dev/null | grep "blackhole" >/dev/null 2>&1 || \
           ip netns exec "$NS_VPS" ip route show table 200 2>/dev/null | grep "blackhole" >/dev/null 2>&1; then
            t7_ok=1; break
        fi
        sleep 1
    done
    if [[ "$t7_ok" == "1" ]]; then echo "OK"; passed=$((passed+1)); else echo "FAIL"; failed=$((failed+1)); fi

    # --- Test 8: NAT MASQUERADE ---
    echo -n "  T8 - NAT MASQUERADE: "
    if ip netns exec "$NS_VPS" iptables -t nat -L POSTROUTING 2>/dev/null | grep -q "MASQUERADE"; then
        echo "OK"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # --- Test 9: Anti-lockout mgmt ---
    echo -n "  T9 - Anti-lockout (mgmt table): "
    if ip netns exec "$NS_VPS" grep -q "100 mgmt" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "OK"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # --- Test 10: FORWARD rules ---
    echo -n "  T10 - FORWARD wg0→wg1: "
    if ip netns exec "$NS_VPS" iptables -L FORWARD -v -n 2>/dev/null | grep -q "wg0.*wg1"; then
        echo "OK"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # --- Test 11: add-client ---
    echo -n "  T11 - add-client test: "
    local add_out
    add_out=$(ip netns exec "$NS_VPS" env \
        WG_DIR="${WG_TEST_DIR}" \
        CLIENT_DIR="${WG_TEST_DIR}/clients" \
        bash "${TMPDIR}/wg-multihop.sh" add-client testclient 2>&1) || true
    if grep -q "testclient" "${WG_TEST_DIR}/wg0.conf" 2>/dev/null; then
        echo "OK"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # --- Test 12: remove-client ---
    echo -n "  T12 - remove-client test: "
    ip netns exec "$NS_VPS" env \
        WG_DIR="${WG_TEST_DIR}" \
        CLIENT_DIR="${WG_TEST_DIR}/clients" \
        bash "${TMPDIR}/wg-multihop.sh" remove-client testclient 2>&1 || true
    if ! grep -q "testclient" "${WG_TEST_DIR}/wg0.conf" 2>/dev/null; then
        echo "OK"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # --- Test 13: multihog toggle ---
    echo -n "  T13 - multihog toggle: "
    ip netns exec "$NS_VPS" env \
        WG_DIR="${WG_TEST_DIR}" \
        MULTIHOP_STATE="${WG_TEST_DIR}/.multihop_state" \
        bash "${TMPDIR}/wg-multihop.sh" multihog off 2>&1 || true
    local mh_state
    mh_state=$(cat "${WG_TEST_DIR}/.multihop_state" 2>/dev/null || echo "OFF")
    if [[ "$mh_state" == "OFF" ]]; then
        echo "OK"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # --- Test 14: status funciona ---
    echo -n "  T14 - status dashboard: "
    local t14_out
    t14_out=$(ip netns exec "$NS_VPS" env \
        WG_DIR="${WG_TEST_DIR}" \
        MULTIHOP_STATE="${WG_TEST_DIR}/.multihop_state" \
        bash "${TMPDIR}/wg-multihop.sh" status 2>&1) || true
    echo "$t14_out" | grep -q "Dashboard" && { echo "OK"; passed=$((passed+1)); } \
        || { echo "FAIL"; failed=$((failed+1)); }

    # --- Test 15: VPS traffic isolation (mgmt) ---
    echo -n "  T15 - VPS traffic isolation (no default via wg): "
    local vps_default
    vps_default=$(ip netns exec "$NS_VPS" ip route show table main 2>/dev/null | grep "default" || echo "")
    if ! echo "$vps_default" | grep -q "wg"; then
        echo "OK${vps_default:+ (no default route via wg)}"; passed=$((passed+1))
    else
        echo "FAIL"; failed=$((failed+1))
    fi

    # Results ---
    echo ""
    echo "  ═══════════════════════════════════════"
    if [[ "$failed" -eq 0 ]]; then
        echo "  ✅  TODOS LOS TESTS PASARON (${passed}/15)"
    else
        echo "  ❌  ${failed} FALLOS — ${passed}/15 PASADOS"
    fi
    echo "  ═══════════════════════════════════════"
    echo ""

    return $failed
}

# ============================================================================
# Main
# ============================================================================
main() {
    local mode="${1:-}"
    shift 2>/dev/null || true

    case "$mode" in
        install)
            cmd_install
            ;;
        add-client)
            cmd_add_client "$@"
            ;;
        remove-client)
            cmd_remove_client "${1:-}"
            ;;
        list-clients)
            cmd_list_clients
            ;;
        multihog)
            cmd_multihop "${1:-toggle}"
            ;;
        status)
            check_root
            cmd_status
            ;;
        watchdog)
            check_root
            cmd_watchdog
            ;;
        failover)
            check_root
            cmd_failover "${1:-}"
            ;;
        tor)
            check_root
            cmd_tor "${1:-status}"
            ;;
        uninstall)
            cmd_uninstall
            ;;
        test)
            cmd_test
            ;;
        recover)
            cmd_recover
            ;;
        *)
            echo ""
            echo "  WireGuard Multihop Toolbox"
            echo ""
            echo "  Usage: bash $0 <command> [args]"
            echo ""
            echo "  Commands:"
            echo "    install              Full interactive setup"
            echo "    add-client <name>    Add a client (--expires 7d for auto-remove)"
            echo "    remove-client <name> Remove a client"
            echo "    list-clients         List configured clients"
            echo "    multihog [on|off]    Toggle traffic exit via wg1"
            echo "    status               Dashboard"
            echo "    watchdog             Self-heal (runs via cron)"
            echo "    failover [wg1|wg2]   Switch active provider"
            echo "    tor [on|off|status]  Tor transparent proxy"
            echo "    uninstall            Revert everything (delete all configs)"
            echo "    recover              Emergency recovery (restore network, keep WG configs)"
            echo "    test                 Self-test in isolated namespaces"
            echo ""
            echo "  Environment variables:"
            echo "    DRY_RUN=1            Simulation mode (no real changes)"
            echo "    BATCH=1              Non-interactive (uses defaults)"
            echo "    WG_PORT=51820        WireGuard listen port"
            echo "    SSH_PORT=22          SSH port (for firewall rules)"
            echo "    SURFSHARK_CONF=/path/to/file.conf   Surfshark config file path"
            echo ""
            ;;
    esac
}

main "$@"
