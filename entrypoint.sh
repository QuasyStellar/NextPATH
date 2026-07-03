#!/bin/bash
set -e

debug_log() {
    local val
    val=$(echo "${DEBUG:-false}" | tr '[:upper:]' '[:lower:]' | xargs)
    if [ "$val" = "true" ] || [ "$val" = "1" ] || [ "$val" = "y" ] || [ "$val" = "yes" ]; then
        printf "\033[0m[$(date +'%H:%M:%S')] \033[1;36m%-7s\033[0m | %s\n" "[INIT]" "$1"
    fi
}
warn_log() {
    printf "\033[0m[$(date +'%H:%M:%S')] \033[1;33m%-7s\033[0m | %s\n" "[WARN]" "$1"
}
info_log() {
    printf "\033[0m[$(date +'%H:%M:%S')] \033[1;32m%-7s\033[0m | %s\n" "[INIT]" "$1"
}

export SOURCES_DIR=${SOURCES_DIR:-/app/nextpath/lists/sources}
export MANUAL_DIR=${MANUAL_DIR:-/app/nextpath/lists/manual}
export RESULT_DIR=${RESULT_DIR:-/app/nextpath/result}
export DOWNLOAD_DIR=${DOWNLOAD_DIR:-/app/nextpath/download}

debug_log "Loading nf_conntrack kernel module..."
modprobe nf_conntrack 2>/dev/null || true

debug_log "Setting file descriptor limits..."
ulimit -n 524288 2>/dev/null || warn_log "Failed to set ulimit (requires privileged mode)"

if [ -w /proc/sys/net/ipv4/ip_forward ]; then
    debug_log "Applying kernel sysctl performance optimizations..."
    for f in /app/nextpath/config/99-*.conf; do
        if [ -f "$f" ]; then
            filename=$(basename "$f")
            cp "$f" "/etc/sysctl.d/$filename" 2>/dev/null || true
            sysctl -p "$f" >/dev/null 2>/dev/null || true
        fi
    done
else
    warn_log "/proc/sys is mounted as read-only (standard for non-privileged containers)."
    warn_log "To achieve maximum network performance, please apply sysctl parameters manually on the HOST machine:"
    warn_log "          sudo cp /app/nextpath/config/99-*.conf /etc/sysctl.d/"
    warn_log "          sudo sysctl --system"
fi


if [ ! -d "$SOURCES_DIR" ] || [ -z "$(find "$SOURCES_DIR" -maxdepth 1 -name "*.txt" 2>/dev/null)" ]; then
    debug_log "Mount empty or missing. Bootstrapping default lists from defaults..."
    mkdir -p "$(dirname "$SOURCES_DIR")"
    cp -r /usr/src/nextpath/defaults/lists/* "$(dirname "$SOURCES_DIR")"/ 2>/dev/null || true
fi

COMPILE_LOCAL_VAL="${COMPILE_LOCAL:-false}"
LIST_SOURCE_VAL="${LIST_SOURCE:-}"

RUNS_LOCAL=0
if [ "$COMPILE_LOCAL_VAL" = "true" ] || [ "$COMPILE_LOCAL_VAL" = "1" ] || [ "$COMPILE_LOCAL_VAL" = "y" ] || [ "$COMPILE_LOCAL_VAL" = "yes" ]; then
    RUNS_LOCAL=1
elif [ -z "$LIST_SOURCE_VAL" ]; then
    RUNS_LOCAL=1
fi

if [ "$RUNS_LOCAL" -eq 1 ]; then
    DATA_COUNT=$(find "$SOURCES_DIR" "$MANUAL_DIR" -type f -name "*.txt" 2>/dev/null | wc -l | tr -d ' ')
    if [ "${DATA_COUNT:-0}" -eq 0 ]; then
        echo -e "\n\e[1;33m[WARNING] YOUR PROXY LISTS ARE EMPTY OR LIST_SOURCE IS NOT CONFIGURED!\e[0m"
        echo -e "No local configuration files were found and no remote LIST_SOURCE is configured."
        echo -e "To resolve this, please either:"
        echo -e "  1. Define a valid remote archive URL in the \e[1;32mLIST_SOURCE\e[0m variable inside your .env"
        echo -e "  2. Or add local sources to \e[1;34m$SOURCES_DIR\e[0m and manual rules to \e[1;34m$MANUAL_DIR\e[0m"
        echo -e "Then run: \e[1;32mdocker compose restart\e[0m\n"
    fi
fi

NP_IP=${NEXTPATH_DNS_IP:-10.77.77.77}
STD_IP=${GLOBAL_DNS_IP:-10.88.88.88}
info_log "Binding routing IP addresses: $NP_IP (NextPATH DNS) and $STD_IP (Global DNS)"
ip addr add "$NP_IP/32" dev lo 2>/dev/null || true
ip addr add "$STD_IP/32" dev lo 2>/dev/null || true

PRIMARY_IF=$(ip route show default | awk '/default/ {print $5}' | head -n1)
if [ -n "$PRIMARY_IF" ] && [ -e "/sys/class/net/$PRIMARY_IF/device" ]; then
    debug_log "Optimizing primary network interface: $PRIMARY_IF..."
    
    ethtool -K "$PRIMARY_IF" rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || warn_log "Failed to set UDP GRO forwarding for $PRIMARY_IF"
    ip link set "$PRIMARY_IF" txqueuelen 1000 2>/dev/null || warn_log "Failed to set txqueuelen for $PRIMARY_IF"
    
    CORES=$(nproc 2>/dev/null || echo 1)
    if [ "$CORES" -gt 16 ]; then CORES=16; fi
    CPU_MASK=$(printf '%x' $(( (1 << CORES) - 1 )))

    for rps in /sys/class/net/"$PRIMARY_IF"/queues/rx-*/rps_cpus; do
        [ -e "$rps" ] && (echo "$CPU_MASK" > "$rps" 2>/dev/null || warn_log "Failed to set RPS for $PRIMARY_IF") || true
    done
else
    debug_log "Primary physical interface not found. Skipping RPS/GRO optimizations."
fi

export DOH_ENABLE=${DOH_ENABLE:-n}
export DOH_PORT=${DOH_PORT:-443}
export DOH_CERT=${DOH_CERT:-}
export DOH_KEY=${DOH_KEY:-}

if [ -z "$DOH_CERT" ]; then
    if [ -f "/run/secrets/cert.pem" ]; then DOH_CERT="/run/secrets/cert.pem"
    elif [ -f "/app/nextpath/certs/cert.pem" ]; then DOH_CERT="/app/nextpath/certs/cert.pem"
    fi
fi
if [ -z "$DOH_KEY" ]; then
    if [ -f "/run/secrets/key.pem" ]; then DOH_KEY="/run/secrets/key.pem"
    elif [ -f "/app/nextpath/certs/key.pem" ]; then DOH_KEY="/app/nextpath/certs/key.pem"
    fi
fi

doh_val=$(echo "${DOH_ENABLE:-false}" | tr '[:upper:]' '[:lower:]' | xargs)
if [[ "$doh_val" == "true" || "$doh_val" == "1" || "$doh_val" == "y" || "$doh_val" == "yes" ]]; then
    if [[ -z "$DOH_CERT" || ! -f "$DOH_CERT" || -z "$DOH_KEY" || ! -f "$DOH_KEY" ]]; then
        warn_log "DOH_ENABLE is enabled but DOH_CERT/DOH_KEY are not provided or not found. Disabling DoH."
        export DOH_ENABLE="n"
    else
        export DOH_ENABLE="y"
    fi
else
    export DOH_ENABLE="n"
fi

mkdir -p "$RESULT_DIR"

debug_log "Generating supervisord configuration..."
mkdir -p /etc/supervisor

SUPERVISOR_PASS=$(tr -dc A-Za-z0-9 </dev/urandom 2>/dev/null | head -c 32 || echo "$RANDOM$RANDOM$RANDOM")

cat <<EOF > /etc/supervisor/supervisord.conf
[unix_http_server]
file=/var/run/supervisor.sock
chmod=0700
username=admin
password=${SUPERVISOR_PASS}

[supervisorctl]
serverurl=unix:///var/run/supervisor.sock
username=admin
password=${SUPERVISOR_PASS}

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisord]
nodaemon=true
user=root
logfile=/tmp/supervisord.log
logfile_maxbytes=0
loglevel=warn
pidfile=/var/run/supervisord.pid

[program:nextpath-engine]
command=/usr/local/bin/nextpath-engine
autostart=true
autorestart=true
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stderr_logfile=/dev/fd/2
stderr_logfile_maxbytes=0

[program:nextpath-updater]
command=/usr/local/bin/nextpath-engine --updater
autostart=true
autorestart=unexpected
exitcodes=0
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stderr_logfile=/dev/fd/2
stderr_logfile_maxbytes=0
EOF

if [[ "$KRESD_WORKERS" == "auto" ]]; then
    CORES=$(nproc)
    WORKERS=$(( CORES / 2 ))
    if [ "$WORKERS" -lt 1 ]; then WORKERS=1; fi
elif [[ "$KRESD_WORKERS" =~ ^[0-9]+$ ]]; then
    WORKERS=$KRESD_WORKERS
else
    WORKERS=1
fi
if [ "$WORKERS" -gt 16 ]; then WORKERS=16; fi
mkdir -p /run/knot-resolver/control && chmod 777 /run/knot-resolver/control

debug_log "Configuring $WORKERS worker(s) for Knot Resolver Instance 1 (PATH DNS) and Instance 2 (Full DNS)..."
for i in $(seq 1 $WORKERS); do
    cat <<EOF >> /etc/supervisor/supervisord.conf

[program:kresd-1-$i]
command=/bin/bash -c "while [ ! -s $RESULT_DIR/proxy.rpz ] || [ ! -s $RESULT_DIR/adblock.rpz ] || [ ! -s $RESULT_DIR/deny.rpz ] || [ ! -s $RESULT_DIR/deny2.rpz ]; do sleep 0.5; done; exec /usr/sbin/kresd -c /app/nextpath/config/kresd.conf -n"
environment=SYSTEMD_INSTANCE="1_$i"
autostart=true
autorestart=true
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stderr_logfile=/dev/fd/2
stderr_logfile_maxbytes=0

[program:kresd-2-$i]
command=/bin/bash -c "while [ ! -s $RESULT_DIR/proxy.rpz ] || [ ! -s $RESULT_DIR/adblock.rpz ] || [ ! -s $RESULT_DIR/deny.rpz ] || [ ! -s $RESULT_DIR/deny2.rpz ]; do sleep 0.5; done; exec /usr/sbin/kresd -c /app/nextpath/config/kresd.conf -n"
environment=SYSTEMD_INSTANCE="2_$i"
autostart=true
autorestart=true
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
stderr_logfile=/dev/fd/2
stderr_logfile_maxbytes=0
EOF
done

cleanup() {
    debug_log "Stopping Supervisor..."
    if [ -n "$PID" ]; then
        kill -TERM $PID 2>/dev/null || true
        wait $PID 2>/dev/null || true
    fi
    debug_log "Removing nftables..."
    nft delete table inet nextpath 2>/dev/null || true
    debug_log "Removing loopback IPs..."
    ip addr del "$NP_IP/32" dev lo 2>/dev/null || true
    ip addr del "$STD_IP/32" dev lo 2>/dev/null || true
}
trap cleanup EXIT SIGTERM SIGINT

debug_log "Ready to start Supervisor..."

debug_log "Starting Supervisor..."
/usr/bin/supervisord -c /etc/supervisor/supervisord.conf &
PID=$!
wait $PID
