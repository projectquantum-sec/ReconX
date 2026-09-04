#!/bin/bash

# Enhanced Passive Reconnaissance Module
# Supports robustness levels 1-5 with dedicated OSINT tools & API-free sources

passive_recon() {
    local domain=$1
    local OUT="output/$domain/passive"
    mkdir -p "$OUT"
    
    log_section "PASSIVE RECONNAISSANCE - $domain"
    log_info "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
    
    local clean_domain="${TARGET_HOST:-$(echo "$domain" | sed 's|https\?://||; s|/.*||; s/:.*//')}"
    if echo "$clean_domain" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
        log_info "Target is an IP address ($clean_domain). Skipping public OSINT subdomain queries."
        echo "$clean_domain" > "$OUT/subdomains.txt"
        echo "# Passive Recon for IP: $clean_domain" > "$OUT/summary.md"
        return
    fi
    
    local CMDS=()
    local total_tools=0
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 1: Quick/Basic - Essential tools only
    # ═══════════════════════════════════════════════════════════════
    
    # WHOIS Lookup (Always run)
    log_tool "whois" "start"
    CMDS+=("whois \"$domain\" > \"$OUT/whois.txt\" 2>/dev/null && echo 'whois:done' || echo 'whois:fail'")
    ((total_tools++))
    
    # Certificate Transparency (crt.sh)
    log_tool "crt.sh" "start"
    CMDS+=("curl -s --max-time 30 \"https://crt.sh/?q=%25.$domain&output=json\" 2>/dev/null \
           | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
           | sed 's/^\\*\\.//' \
           | sort -u > \"$OUT/crtsh.txt\" && echo 'crtsh:done' || echo 'crtsh:fail'")
    ((total_tools++))
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 2+: Add Subfinder
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 2 ]]; then
        if tool_exists subfinder; then
            log_tool "subfinder" "start"
            local sf_threads=$(get_scan_threads)
            if type run_subfinder_stealth &>/dev/null; then
                CMDS+=("run_subfinder_stealth \"$domain\" \"$OUT/subfinder.txt\" $sf_threads >/dev/null 2>&1 && echo 'subfinder:done' || echo 'subfinder:fail'")
            else
                CMDS+=("subfinder -d \"$domain\" -silent -t $sf_threads > \"$OUT/subfinder.txt\" 2>/dev/null && echo 'subfinder:done' || echo 'subfinder:fail'")
            fi
            ((total_tools++))
        else
            log_tool "subfinder" "skip" "not installed"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 3+: Add Amass, theHarvester, and more sources
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]]; then
        # Amass passive enumeration
        if tool_exists amass; then
            log_tool "amass" "start"
            local amass_timeout=$(get_scan_timeout)
            if type run_amass_stealth &>/dev/null; then
                CMDS+=("run_amass_stealth \"$domain\" \"$OUT/amass.txt\" $amass_timeout >/dev/null 2>&1 && echo 'amass:done' || echo 'amass:fail'")
            else
                CMDS+=("timeout ${amass_timeout}m amass enum -passive -d \"$domain\" -o \"$OUT/amass.txt\" 2>/dev/null && echo 'amass:done' || echo 'amass:fail'")
            fi
            ((total_tools++))
        else
            log_tool "amass" "skip" "not installed"
        fi
        
        # theHarvester - Enhanced with API key support
        if tool_exists theHarvester; then
            log_tool "theHarvester" "start"
            local sources="crtsh,dnsdumpster,google"
            [[ -n "$SHODAN_API_KEY" ]] && sources="$sources,shodan"
            [[ -n "$VIRUSTOTAL_API_KEY" ]] && sources="$sources,virustotal"
            [[ -n "$SECURITYTRAILS_API_KEY" ]] && sources="$sources,securitytrails"
            
            local harvester_config="$OUT/harvester_api_keys.yaml"
            cat > "$harvester_config" << EOF
apikeys:
  shodan: ${SHODAN_API_KEY:-}
  virustotal: ${VIRUSTOTAL_API_KEY:-}
  securitytrails: ${SECURITYTRAILS_API_KEY:-}
EOF
            if type run_theharvester_stealth &>/dev/null; then
                CMDS+=("run_theharvester_stealth \"$domain\" \"$sources\" \"$OUT/theharvester\" \"$harvester_config\" >/dev/null 2>&1 && echo 'theharvester:done' || echo 'theharvester:fail'")
            else
                CMDS+=("theHarvester -d \"$domain\" -b \"$sources\" -f \"$OUT/theharvester\" --api-config \"$harvester_config\" 2>/dev/null && echo 'theharvester:done' || echo 'theharvester:fail'")
            fi
            ((total_tools++))
        else
            log_tool "theHarvester" "skip" "not installed"
        fi
        
        # SecurityTrails API (if configured)
        if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
            log_tool "SecurityTrails" "start"
            CMDS+=("curl -s --max-time 30 \"https://api.securitytrails.com/v1/domain/$domain/subdomains\" \
                   -H \"APIKEY: $SECURITYTRAILS_API_KEY\" \
                   | jq -r '.subdomains[]' 2>/dev/null \
                   | sed \"s/\$/.${domain}/\" > \"$OUT/securitytrails.txt\" && echo 'securitytrails:done' || echo 'securitytrails:fail'")
            ((total_tools++))
        fi
        
        # Wayback Machine URLs
        log_tool "wayback" "start"
        CMDS+=("curl -s --max-time 60 \"https://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey\" \
               | sort -u > \"$OUT/wayback_urls.txt\" 2>/dev/null && echo 'wayback:done' || echo 'wayback:fail'")
        ((total_tools++))
        
        # AlienVault OTX (Enhanced with optional API Key)
        log_tool "alienvault" "start"
        local otx_header=""
        [[ -n "$ALIENVAULT_API_KEY" ]] && otx_header="-H \"X-OTX-API-KEY: $ALIENVAULT_API_KEY\""
        CMDS+=("curl -s --max-time 30 $otx_header \"https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns\" 2>/dev/null \
               | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
               | sort -u > \"$OUT/alienvault.txt\" && echo 'alienvault:done' || echo 'alienvault:fail'")
        ((total_tools++))

        # BeVigil OSINT API (if configured)
        if [[ -n "$BEVIGIL_API_KEY" ]]; then
            log_tool "bevigil" "start"
            CMDS+=("curl -s --max-time 30 -H \"X-Access-Token: $BEVIGIL_API_KEY\" \"https://osint.bevigil.com/api/$domain/subdomains/\" 2>/dev/null \
                   | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
                   | sort -u > \"$OUT/bevigil.txt\" && echo 'bevigil:done' || echo 'bevigil:fail'")
            ((total_tools++))
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 4+: Add more OSINT sources
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]]; then
        # Findomain
        if tool_exists findomain; then
            log_tool "findomain" "start"
            CMDS+=("findomain -t \"$domain\" -q > \"$OUT/findomain.txt\" 2>/dev/null && echo 'findomain:done' || echo 'findomain:fail'")
            ((total_tools++))
        else
            log_tool "findomain" "skip" "not installed"
        fi
        
        # Assetfinder
        if tool_exists assetfinder; then
            log_tool "assetfinder" "start"
            CMDS+=("assetfinder --subs-only \"$domain\" > \"$OUT/assetfinder.txt\" 2>/dev/null && echo 'assetfinder:done' || echo 'assetfinder:fail'")
            ((total_tools++))
        else
            log_tool "assetfinder" "skip" "not installed"
        fi
        
        # GAU (getallurls)
        if tool_exists gau; then
            log_tool "gau" "start"
            CMDS+=("echo \"$domain\" | gau --subs > \"$OUT/gau_urls.txt\" 2>/dev/null && echo 'gau:done' || echo 'gau:fail'")
            ((total_tools++))
        else
            log_tool "gau" "skip" "not installed"
        fi
        
        # Shodan (if API key configured)
        if [[ -n "$SHODAN_API_KEY" ]]; then
            log_tool "shodan" "start"
            CMDS+=("curl -s --max-time 30 \"https://api.shodan.io/dns/domain/$domain?key=$SHODAN_API_KEY\" 2>/dev/null \
                   | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
                   | sort -u > \"$OUT/shodan.txt\" && echo 'shodan:done' || echo 'shodan:fail'")
            ((total_tools++))
        fi
        
        # VirusTotal (if API key configured)
        if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
            log_tool "virustotal" "start"
            CMDS+=("curl -s --max-time 30 \"https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VIRUSTOTAL_API_KEY&domain=$domain\" 2>/dev/null \
                   | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
                   | sort -u > \"$OUT/virustotal.txt\" && echo 'virustotal:done' || echo 'virustotal:fail'")
            ((total_tools++))
        fi
        
        # HackerTarget
        log_tool "hackertarget" "start"
        CMDS+=("curl -s --max-time 30 \"https://api.hackertarget.com/hostsearch/?q=$domain\" 2>/dev/null \
               | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
               | sort -u > \"$OUT/hackertarget.txt\" && echo 'hackertarget:done' || echo 'hackertarget:fail'")
        ((total_tools++))
        
        # ThreatCrowd
        log_tool "threatcrowd" "start"
        CMDS+=("curl -s --max-time 30 \"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain\" 2>/dev/null \
               | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
               | sort -u > \"$OUT/threatcrowd.txt\" && echo 'threatcrowd:done' || echo 'threatcrowd:fail'")
        ((total_tools++))
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 5: Maximum depth - All available tools
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 5 ]]; then
        # Chaos (ProjectDiscovery)
        if tool_exists chaos && [[ -n "$CHAOS_API_KEY" ]]; then
            log_tool "chaos" "start"
            CMDS+=("chaos -d \"$domain\" -api-key \"$CHAOS_API_KEY\" -silent > \"$OUT/chaos.txt\" 2>/dev/null && echo 'chaos:done' || echo 'chaos:fail'")
            ((total_tools++))
        fi
        
        # Censys (if API configured)
        if [[ -n "$CENSYS_API_ID" ]] && [[ -n "$CENSYS_API_SECRET" ]]; then
            log_tool "censys" "start"
            CMDS+=("curl -s --max-time 60 \"https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names:$domain\" \
                   -u \"$CENSYS_API_ID:$CENSYS_API_SECRET\" 2>/dev/null \
                   | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
                   | sort -u > \"$OUT/censys.txt\" && echo 'censys:done' || echo 'censys:fail'")
            ((total_tools++))
        fi
        
        # DNSDumpster scraping
        log_tool "dnsdumpster" "start"
        CMDS+=("curl -s --max-time 30 \"https://api.hackertarget.com/dnslookup/?q=$domain\" 2>/dev/null \
               | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
               | sort -u > \"$OUT/dnsdumpster.txt\" && echo 'dnsdumpster:done' || echo 'dnsdumpster:fail'")
        ((total_tools++))
        
        # Rapid7 FDNS (if available)
        if tool_exists rapid7; then
            log_tool "rapid7" "start"
            CMDS+=("rapid7 fdns \"$domain\" > \"$OUT/rapid7.txt\" 2>/dev/null && echo 'rapid7:done' || echo 'rapid7:fail'")
            ((total_tools++))
        fi
        
        # BufferOver
        log_tool "bufferover" "start"
        CMDS+=("curl -s --max-time 30 \"https://dns.bufferover.run/dns?q=.$domain\" 2>/dev/null \
               | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
               | sort -u > \"$OUT/bufferover.txt\" && echo 'bufferover:done' || echo 'bufferover:fail'")
        ((total_tools++))
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # API-Free Reconnaissance Sources (Always Available)
    # ═══════════════════════════════════════════════════════════════
    log_info "Adding API-free reconnaissance sources..."
    
    # RapidDNS
    log_tool "rapiddns" "start"
    CMDS+=("curl -s --max-time 30 'https://rapiddns.io/subdomain/$domain?full=1' 2>/dev/null \
           | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
           | sort -u > \"$OUT/rapiddns.txt\" && echo 'rapiddns:done' || echo 'rapiddns:fail'")
    ((total_tools++))
    
    # Anubis DB
    log_tool "anubisdb" "start"
    CMDS+=("curl -s --max-time 30 'https://jldc.me/anubis/subdomains/$domain' 2>/dev/null \
           | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
           | sort -u > \"$OUT/anubisdb.txt\" && echo 'anubisdb:done' || echo 'anubisdb:fail'")
    ((total_tools++))
    
    # URLScan.io
    log_tool "urlscan" "start"
    CMDS+=("curl -s --max-time 30 'https://urlscan.io/api/v1/search/?q=domain:$domain' 2>/dev/null \
           | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
           | sort -u > \"$OUT/urlscan.txt\" && echo 'urlscan:done' || echo 'urlscan:fail'")
    ((total_tools++))
    
    # CertSpotter
    log_tool "certspotter" "start"
    CMDS+=("curl -s --max-time 30 'https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names' 2>/dev/null \
           | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
           | sort -u > \"$OUT/certspotter.txt\" && echo 'certspotter:done' || echo 'certspotter:fail'")
    ((total_tools++))
    
    # Riddler.io
    log_tool "riddler" "start"
    CMDS+=("curl -s --max-time 30 'https://riddler.io/search/exportcsv?q=pld:$domain' 2>/dev/null \
           | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
           | sort -u > \"$OUT/riddler.txt\" && echo 'riddler:done' || echo 'riddler:fail'")
    ((total_tools++))
    
    # CommonCrawl
    log_tool "commoncrawl" "start"
    local cc_index="CC-MAIN-2024-10"
    CMDS+=("curl -s --max-time 30 'http://index.commoncrawl.org/$cc_index-index?url=*.$domain&output=json' 2>/dev/null \
           | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
           | sort -u > \"$OUT/commoncrawl.txt\" && echo 'commoncrawl:done' || echo 'commoncrawl:fail'")
    ((total_tools++))

    # Subdomain Center (Free OSINT API)
    log_tool "subdomaincenter" "start"
    CMDS+=("curl -s --max-time 30 'https://api.subdomain.center/?domain=$domain' 2>/dev/null \
           | grep -Po \"([a-zA-Z0-9_\\-\\.]+\\.$domain)\" \
           | sort -u > \"$OUT/subdomaincenter.txt\" && echo 'subdomaincenter:done' || echo 'subdomaincenter:fail'")
    ((total_tools++))
    
    # ═══════════════════════════════════════════════════════════════
    # Execute all commands in parallel
    # ═══════════════════════════════════════════════════════════════
    log_info "Running $total_tools passive recon tools in parallel..."
    
    run_parallel "${CMDS[@]}"
    
    # ═══════════════════════════════════════════════════════════════
    # Consolidate and deduplicate results
    # ═══════════════════════════════════════════════════════════════
    log_info "Consolidating subdomain results..."
    
    # Combine all subdomain files
    cat "$OUT"/*.txt 2>/dev/null \
        | grep -E "^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.$domain$" \
        | sort -u > "$OUT/all_subdomains_raw.txt"
    
    # Clean and validate subdomains
    cat "$OUT/all_subdomains_raw.txt" \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/^\*\.//' \
        | sed 's/^www\.//' \
        | grep "$domain" \
        | sort -u > "$OUT/subdomains.txt"
    
    local subdomain_count=$(wc -l < "$OUT/subdomains.txt" 2>/dev/null || echo 0)
    
    # Active DNS Resolution verification (identify live hosts early)
    if tool_exists dnsx; then
        log_info "Resolving subdomains via dnsx..."
        dnsx -l "$OUT/subdomains.txt" -silent -a -resp -o "$OUT/resolved_subdomains.txt" 2>/dev/null
    fi
    
    # Extract emails and URLs from collected data
    extract_emails "$domain"
    extract_urls "$domain"
    
    # Generate summary
    {
        echo "# Passive Reconnaissance Summary"
        echo "Domain: $domain"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
        echo ""
        echo "## Results"
        echo "Total unique subdomains found: $subdomain_count"
        echo ""
        echo "## Sources"
        for f in "$OUT"/*.txt; do
            [[ -f "$f" ]] || continue
            local fname=$(basename "$f")
            local count=$(wc -l < "$f" 2>/dev/null || echo 0)
            echo "- $fname: $count entries"
        done
    } > "$OUT/summary.md"
    
    log_success "Passive reconnaissance completed"
    log_info "Found $subdomain_count unique subdomains"
    log_info "Results saved to: $OUT/"
}

# Extract emails from passive recon results
extract_emails() {
    local domain=$1
    local OUT="output/$domain/passive"
    
    log_info "Extracting email addresses..."
    
    grep -rhoE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$OUT" 2>/dev/null \
        | sort -u > "$OUT/emails.txt"
    
    local email_count=$(wc -l < "$OUT/emails.txt" 2>/dev/null || echo 0)
    log_info "Found $email_count unique email addresses"
}

# Extract URLs from passive recon results
extract_urls() {
    local domain=$1
    local OUT="output/$domain/passive"
    
    log_info "Extracting URLs..."
    
    grep -rhoE "https?://[a-zA-Z0-9./?=_-]*" "$OUT" 2>/dev/null \
        | sort -u > "$OUT/urls.txt"
    
    local url_count=$(wc -l < "$OUT/urls.txt" 2>/dev/null || echo 0)
    log_info "Found $url_count unique URLs"
}