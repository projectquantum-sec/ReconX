#!/bin/bash

# Interactive API Key Configuration Wizard

BASE_DIR="${BASE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
[[ -f "$BASE_DIR/utils/colors.sh" ]] && source "$BASE_DIR/utils/colors.sh"
[[ -f "$BASE_DIR/utils/logger.sh" ]] && source "$BASE_DIR/utils/logger.sh"

config_wizard() {
    clear
    echo -e "${CYAN}╔═════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║       ReconX Configuration Wizard v1.0              ║${RESET}"
    echo -e "${CYAN}╚═════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${YELLOW}This wizard will help you configure API keys for enhanced reconnaissance.${RESET}"
    echo -e "${YELLOW}All API keys are optional. Press Enter to skip any key.${RESET}"
    echo -e "${YELLOW}ReconX works perfectly fine without API keys using free sources.${RESET}"
    echo ""
    
    # Shodan
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}Shodan API Key${RESET}"
    echo -e "${DIM}Shodan is a search engine for Internet-connected devices.${RESET}"
    echo -e "${DIM}Benefits: Find exposed services, open ports, and vulnerabilities${RESET}"
    echo -e "${DIM}Free tier: 100 results/month${RESET}"
    echo -e "${DIM}Get your free key at: ${CYAN}https://account.shodan.io/${RESET}"
    echo ""
    read -p "Enter Shodan API key (or press Enter to skip): " shodan_key
    echo ""
    
    # VirusTotal
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}VirusTotal API Key${RESET}"
    echo -e "${DIM}VirusTotal aggregates threat intelligence from multiple sources.${RESET}"
    echo -e "${DIM}Benefits: Subdomain discovery, malware analysis, domain reputation${RESET}"
    echo -e "${DIM}Free tier: 4 requests/minute${RESET}"
    echo -e "${DIM}Get your free key at: ${CYAN}https://www.virustotal.com/gui/join-us${RESET}"
    echo ""
    read -p "Enter VirusTotal API key (or press Enter to skip): " vt_key
    echo ""
    
    # SecurityTrails
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}SecurityTrails API Key${RESET}"
    echo -e "${DIM}SecurityTrails provides historical DNS data and subdomain discovery.${RESET}"
    echo -e "${DIM}Benefits: Historical DNS records, subdomain enumeration${RESET}"
    echo -e "${DIM}Free tier: 50 API requests/month${RESET}"
    echo -e "${DIM}Get your free key at: ${CYAN}https://securitytrails.com/app/signup${RESET}"
    echo ""
    read -p "Enter SecurityTrails API key (or press Enter to skip): " st_key
    echo ""
    
    # Censys
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}Censys API Credentials (Optional - Organization / Academic Accounts)${RESET}"
    echo -e "${DIM}Censys scans the Internet to create a searchable database of hosts.${RESET}"
    echo -e "${DIM}Benefits: Certificate search, host discovery${RESET}"
    echo -e "${DIM}Note: Free community accounts no longer offer direct API access.${RESET}"
    echo ""
    read -p "Enter Censys API ID (or press Enter to skip): " censys_id
    read -p "Enter Censys API Secret (or press Enter to skip): " censys_secret
    echo ""
    
    # Chaos
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}Chaos (ProjectDiscovery) API Key${RESET}"
    echo -e "${DIM}Chaos provides curated subdomain data from bug bounty programs.${RESET}"
    echo -e "${DIM}Benefits: High-quality subdomain enumeration${RESET}"
    echo -e "${DIM}Get your key at: ${CYAN}https://chaos.projectdiscovery.io/${RESET}"
    echo ""
    read -p "Enter Chaos API key (or press Enter to skip): " chaos_key
    echo ""
    
    # WPScan
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}WPScan API Token${RESET}"
    echo -e "${DIM}WPScan is a WordPress vulnerability scanner.${RESET}"
    echo -e "${DIM}Benefits: WordPress vulnerability database access${RESET}"
    echo -e "${DIM}Free tier: 25 API requests/day${RESET}"
    echo -e "${DIM}Get your free token at: ${CYAN}https://wpscan.com/register${RESET}"
    echo ""
    read -p "Enter WPScan API token (or press Enter to skip): " wpscan_token
    echo ""

    # AlienVault OTX (SecurityTrails Replacement)
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}AlienVault OTX API Key (SecurityTrails Alternative)${RESET}"
    echo -e "${DIM}Open Threat Exchange provides extensive passive DNS and threat intel.${RESET}"
    echo -e "${DIM}Benefits: High rate limits for passive subdomain & IP resolution${RESET}"
    echo -e "${DIM}Get your free key at: ${CYAN}https://otx.alienvault.com/${RESET}"
    echo ""
    read -p "Enter AlienVault OTX key (or press Enter to skip): " alienvault_key
    echo ""

    # BeVigil OSINT
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}BeVigil OSINT API Key (SecurityTrails Alternative)${RESET}"
    echo -e "${DIM}BeVigil extracts subdomains, mobile endpoints, and exposed assets.${RESET}"
    echo -e "${DIM}Free tier: 50 API queries/day${RESET}"
    echo -e "${DIM}Get your free key at: ${CYAN}https://osint.bevigil.com/${RESET}"
    echo ""
    read -p "Enter BeVigil OSINT key (or press Enter to skip): " bevigil_key
    echo ""
    
    # Save to config helper function
    local config_file="$BASE_DIR/config/tools.conf"
    
    set_config_val() {
        local key="$1"
        local val="$2"
        [[ -z "$val" ]] && return 0
        local escaped_val=$(printf '%s\n' "$val" | sed 's/[.*^$/]/\\&/g')
        if grep -q "^${key}=" "$config_file" 2>/dev/null; then
            sed -i "s|^${key}=.*|${key}=\"${escaped_val}\"|" "$config_file"
        else
            echo "${key}=\"${escaped_val}\"" >> "$config_file"
        fi
    }
    
    set_config_val "SHODAN_API_KEY" "$shodan_key"
    set_config_val "VIRUSTOTAL_API_KEY" "$vt_key"
    set_config_val "SECURITYTRAILS_API_KEY" "$st_key"
    set_config_val "ALIENVAULT_API_KEY" "$alienvault_key"
    set_config_val "BEVIGIL_API_KEY" "$bevigil_key"
    set_config_val "CENSYS_API_ID" "$censys_id"
    set_config_val "CENSYS_API_SECRET" "$censys_secret"
    set_config_val "CHAOS_API_KEY" "$chaos_key"
    set_config_val "WPSCAN_API_TOKEN" "$wpscan_token"
    
    echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
    log_success "Configuration saved to $config_file"
    echo ""
    
    # Validate keys
    source "$config_file"
    source "$BASE_DIR/utils/api_validator.sh"
    validate_all_keys
    
    echo ""
    read -p "Press Enter to continue..."
}

# Quick validation check
check_api_config() {
    local has_keys=false
    
    [[ -n "$SHODAN_API_KEY" ]] && has_keys=true
    [[ -n "$VIRUSTOTAL_API_KEY" ]] && has_keys=true
    [[ -n "$SECURITYTRAILS_API_KEY" ]] && has_keys=true
    [[ -n "$CENSYS_API_ID" ]] && has_keys=true
    [[ -n "$CHAOS_API_KEY" ]] && has_keys=true
    
    if ! $has_keys; then
        log_warn "No API keys configured. Running in API-free mode."
        echo -e "${YELLOW}Would you like to configure API keys now for enhanced results? (y/N)${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            config_wizard
        fi
    fi
}
