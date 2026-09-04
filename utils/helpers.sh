#!/bin/bash

# Tool availability check
tool_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Resolve ProjectDiscovery httpx vs Python httpx
get_httpx_bin() {
  if [[ -x "$HOME/go/bin/httpx" ]] && "$HOME/go/bin/httpx" -version 2>&1 | grep -qi "projectdiscovery"; then
    echo "$HOME/go/bin/httpx"
  elif command -v httpx-toolkit >/dev/null 2>&1; then
    echo "httpx-toolkit"
  elif command -v httpx >/dev/null 2>&1 && httpx -version 2>&1 | grep -qi "projectdiscovery"; then
    echo "httpx"
  else
    echo ""
  fi
}

# Root check warning
check_root() {
  [[ $EUID -ne 0 ]] && log_warn "Running without root privileges may limit raw socket scans (Masscan, OS detection)"
}

# Parallel execution manager
run_parallel() {
  local max_jobs=${MAX_PARALLEL_JOBS:-10}

  if [[ "$max_jobs" -lt 1 ]]; then
    max_jobs=1
  fi

  for cmd in "$@"; do
    while [[ $(jobs -r | wc -l) -ge "$max_jobs" ]]; do
      wait -n 2>/dev/null || wait
    done
    eval "$cmd" &
  done
  wait
}

# ═══════════════════════════════════════════════════════════════
# Dynamic Parameter Getters (Decoupled from menu.sh)
# ═══════════════════════════════════════════════════════════════

get_scan_threads() {
    local level=${ROBUSTNESS_LEVEL:-3}
    case $level in
        1) echo 10 ;;
        2) echo 25 ;;
        3) echo 50 ;;
        4) echo 100 ;;
        5) echo 200 ;;
        *) echo 50 ;;
    esac
}

get_scan_timeout() {
    local level=${ROBUSTNESS_LEVEL:-3}
    case $level in
        1) echo 5 ;;
        2) echo 10 ;;
        3) echo 15 ;;
        4) echo 30 ;;
        5) echo 60 ;;
        *) echo 15 ;;
    esac
}

get_nmap_timing() {
    local level=${ROBUSTNESS_LEVEL:-3}
    case $level in
        1) echo "T2" ;;
        2) echo "T3" ;;
        3) echo "T4" ;;
        4) echo "T4" ;;
        5) echo "T5" ;;
        *) echo "T4" ;;
    esac
}

get_port_range() {
    local level=${ROBUSTNESS_LEVEL:-3}
    case $level in
        1) echo "21,22,23,25,53,80,110,143,443,445,3306,3389,8080" ;;
        2) echo "1-1000" ;;
        3) echo "1-10000" ;;
        4) echo "1-65535" ;;
        5) echo "1-65535" ;;
        *) echo "1-10000" ;;
    esac
}

# DNS resolver check
resolve_subdomain() {
    local sub=$1
    local resolver=${DNS_RESOLVER:-"8.8.8.8"}
    dig +short +time=2 +tries=1 @"$resolver" "$sub" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}

# ═══════════════════════════════════════════════════════════════
# Wildcard DNS Detection
# ═══════════════════════════════════════════════════════════════
detect_wildcard_dns() {
    local domain=$1
    local rand1="reconx-wildcard-check-1-$RANDOM.$domain"
    local rand2="reconx-wildcard-check-2-$RANDOM.$domain"
    
    local ip1=$(resolve_subdomain "$rand1")
    local ip2=$(resolve_subdomain "$rand2")
    
    if [[ -n "$ip1" ]] && [[ "$ip1" == "$ip2" ]]; then
        echo "$ip1"
        return 0
    fi
    return 1
}

# ═══════════════════════════════════════════════════════════════
# OPSEC & Network Helpers
# ═══════════════════════════════════════════════════════════════

get_random_user_agent() {
    if [[ -n "$CUSTOM_USER_AGENT" ]]; then
        echo "$CUSTOM_USER_AGENT"
        return
    fi
    
    local user_agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0"
    )
    local rand_idx=$((RANDOM % ${#user_agents[@]}))
    echo "${user_agents[$rand_idx]}"
}

# Check if target is in exclusion list / blacklisted
is_target_excluded() {
    local host=$1
    local exclude_input=$2
    
    [[ -z "$exclude_input" ]] && return 1
    
    if [[ -f "$exclude_input" ]]; then
        if grep -Fxq "$host" "$exclude_input" 2>/dev/null; then
            return 0
        fi
    else
        IFS=',' read -ra EXCLUDES <<< "$exclude_input"
        for ex in "${EXCLUDES[@]}"; do
            [[ "$host" == *"$ex"* ]] && return 0
        done
    fi
    return 1
}

# ═══════════════════════════════════════════════════════════════
# Webhook Notifications (Slack / Discord)
# ═══════════════════════════════════════════════════════════════
send_webhook_notification() {
    local title="$1"
    local message="$2"
    local level="${3:-INFO}"
    
    # Discord Notification
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        local color="3447003" # Blue
        [[ "$level" == "WARN" ]] && color="16776960" # Yellow
        [[ "$level" == "CRITICAL" ]] && color="15158332" # Red
        [[ "$level" == "SUCCESS" ]] && color="3066993" # Green
        
        local payload=$(cat <<EOF
{
  "embeds": [{
    "title": "🔍 ReconX: $title",
    "description": "$message",
    "color": $color,
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  }]
}
EOF
)
        curl -s -H "Content-Type: application/json" -X POST -d "$payload" "$DISCORD_WEBHOOK" >/dev/null 2>&1 &
    fi
    
    # Slack Notification
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        local payload=$(cat <<EOF
{
  "text": "*[ReconX - $title]*\n$message"
}
EOF
)
        curl -s -H "Content-Type: application/json" -X POST -d "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1 &
    fi
}


