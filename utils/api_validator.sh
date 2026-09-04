#!/bin/bash

# API Key Validation Module

BASE_DIR="${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$BASE_DIR/utils/colors.sh" ]] && source "$BASE_DIR/utils/colors.sh"
[[ -f "$BASE_DIR/utils/logger.sh" ]] && source "$BASE_DIR/utils/logger.sh"

_json_has_key() {
    local json="$1"
    local key="$2"
    if command -v jq >/dev/null 2>&1; then
        echo "$json" | jq -e ".$key" >/dev/null 2>&1 && return 0 || return 1
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys, json; data=json.loads(sys.argv[1]); sys.exit(0 if sys.argv[2] in str(data) else 1)" "$json" "$key" 2>/dev/null
    else
        echo "$json" | grep -q "\"$key\""
    fi
}

validate_shodan_key() {
    [[ -z "$SHODAN_API_KEY" ]] && return 1
    local response=$(curl -s --max-time 10 --get --data-urlencode "key=$SHODAN_API_KEY" "https://api.shodan.io/api-info")
    echo "$response" | grep -q '"plan"' && return 0 || return 1
}

validate_virustotal_key() {
    [[ -z "$VIRUSTOTAL_API_KEY" ]] && return 1
    local response=$(curl -s --max-time 10 -H "x-apikey: $VIRUSTOTAL_API_KEY" "https://www.virustotal.com/api/v3/users/current")
    echo "$response" | grep -q '"data"' && return 0 || return 1
}

validate_securitytrails_key() {
    [[ -z "$SECURITYTRAILS_API_KEY" ]] && return 1
    local response=$(curl -s --max-time 10 -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/ping")
    echo "$response" | grep -q '"success"' && return 0 || return 1
}

validate_censys_keys() {
    [[ -z "$CENSYS_API_ID" ]] || [[ -z "$CENSYS_API_SECRET" ]] && return 1
    local response=$(curl -s --max-time 10 -u "$CENSYS_API_ID:$CENSYS_API_SECRET" "https://search.censys.io/api/v2/hosts/search?q=example.com&per_page=1")
    echo "$response" | grep -q '"result"' && return 0 || return 1
}

validate_chaos_key() {
    [[ -z "$CHAOS_API_KEY" ]] && return 1
    local response=$(curl -s --max-time 10 -H "Authorization: $CHAOS_API_KEY" "https://dns.projectdiscovery.io/dns/example.com/subdomains")
    echo "$response" | grep -q '"subdomains"' && return 0 || return 1
}

validate_wpscan_token() {
    [[ -z "$WPSCAN_API_TOKEN" ]] && return 1
    local response=$(curl -s --max-time 10 -H "Authorization: Token token=$WPSCAN_API_TOKEN" "https://wpscan.com/api/v3/status")
    echo "$response" | grep -q '"plan"' && return 0 || return 1
}

validate_bevigil_key() {
    [[ -z "$BEVIGIL_API_KEY" ]] && return 1
    local response=$(curl -s --max-time 10 -H "X-Access-Token: $BEVIGIL_API_KEY" "https://osint.bevigil.com/api/example.com/subdomains/")
    echo "$response" | grep -q '"subdomains"' && return 0 || return 1
}

validate_alienvault_key() {
    [[ -z "$ALIENVAULT_API_KEY" ]] && return 1
    local response=$(curl -s --max-time 10 -H "X-OTX-API-KEY: $ALIENVAULT_API_KEY" "https://otx.alienvault.com/api/v1/user/me")
    echo "$response" | grep -q '"username"' && return 0 || return 1
}

validate_all_keys() {
    log_info "Validating configured API keys..."
    echo ""
    
    if validate_shodan_key; then
        log_success "✓ Shodan API key is valid (Active)"
    else
        [[ -n "$SHODAN_API_KEY" ]] && log_warn "✗ Shodan API key invalid or expired" || log_info "○ Shodan API key not configured"
    fi
    
    if validate_virustotal_key; then
        log_success "✓ VirusTotal API key is valid (Active)"
    else
        [[ -n "$VIRUSTOTAL_API_KEY" ]] && log_warn "✗ VirusTotal API key invalid or expired" || log_info "○ VirusTotal API key not configured"
    fi
    
    if validate_wpscan_token; then
        log_success "✓ WPScan API token is valid (Active)"
    else
        [[ -n "$WPSCAN_API_TOKEN" ]] && log_warn "✗ WPScan API token invalid or expired" || log_info "○ WPScan API token not configured"
    fi
    
    if [[ -n "$CENSYS_API_ID" ]] && [[ -n "$CENSYS_API_SECRET" ]]; then
        if validate_censys_keys; then
            log_success "✓ Censys API credentials are valid"
        else
            log_warn "✗ Censys API credentials invalid (Requires Organization/Academic account)"
        fi
    fi
    
    if validate_chaos_key; then
        log_success "✓ Chaos (ProjectDiscovery) API key is valid"
    else
        [[ -n "$CHAOS_API_KEY" ]] && log_warn "✗ Chaos API key invalid (ProjectDiscovery now uses keys from cloud.projectdiscovery.io)" || log_info "○ Chaos API key not configured"
    fi

    if [[ -n "$BEVIGIL_API_KEY" ]]; then
        if validate_bevigil_key; then
            log_success "✓ BeVigil OSINT API key is valid"
        else
            log_warn "✗ BeVigil OSINT API key invalid"
        fi
    fi

    if [[ -n "$ALIENVAULT_API_KEY" ]]; then
        if validate_alienvault_key; then
            log_success "✓ AlienVault OTX API key is valid"
        else
            log_warn "✗ AlienVault OTX API key invalid"
        fi
    fi
    
    if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
        if validate_securitytrails_key; then
            log_success "✓ SecurityTrails API key is valid"
        else
            log_warn "✗ SecurityTrails API key invalid"
        fi
    fi
    
    echo ""
    log_info "API-free reconnaissance and built-in fallbacks will be used for unconfigured/invalid services."
}
