#!/bin/bash

# Enhanced DNS Reconnaissance Module
# Supports robustness levels 1-5

dns_recon() {
    local domain=$1
    local OUT="output/$domain/dns"
    mkdir -p "$OUT"
    
    log_section "DNS RECONNAISSANCE - $domain"
    log_info "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
    
    local clean_domain="${TARGET_HOST:-$(echo "$domain" | sed 's|https\?://||; s|/.*||; s/:.*//')}"
    if echo "$clean_domain" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
        log_info "Target is an IP address ($clean_domain). Skipping domain DNS record queries."
        echo "# DNS Summary for IP: $clean_domain" > "$OUT/summary.md"
        return
    fi
    
    local CMDS=()
    
    # ═══════════════════════════════════════════════════════════════
    # Wildcard DNS Detection
    # ═══════════════════════════════════════════════════════════════
    local wildcard_ip
    if wildcard_ip=$(detect_wildcard_dns "$domain"); then
        log_warn "Wildcard DNS detected for $domain (resolves to $wildcard_ip)"
        echo "$wildcard_ip" > "$OUT/wildcard.txt"
    fi

    # ═══════════════════════════════════════════════════════════════
    # LEVEL 1+: Basic DNS Records
    # ═══════════════════════════════════════════════════════════════
    log_info "Querying basic DNS records..."
    
    log_tool "dig-NS" "start"
    CMDS+=("dig NS \"$domain\" +short > \"$OUT/ns.txt\" 2>/dev/null")
    
    log_tool "dig-MX" "start"
    CMDS+=("dig MX \"$domain\" +short > \"$OUT/mx.txt\" 2>/dev/null")
    
    log_tool "dig-TXT" "start"
    CMDS+=("dig TXT \"$domain\" +short > \"$OUT/txt.txt\" 2>/dev/null")
    
    log_tool "dig-A" "start"
    CMDS+=("dig A \"$domain\" +short > \"$OUT/a.txt\" 2>/dev/null")
    
    log_tool "dig-AAAA" "start"
    CMDS+=("dig AAAA \"$domain\" +short > \"$OUT/aaaa.txt\" 2>/dev/null")
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 2+: Additional Records
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 2 ]]; then
        log_tool "dig-SOA" "start"
        CMDS+=("dig SOA \"$domain\" +short > \"$OUT/soa.txt\" 2>/dev/null")
        
        log_tool "dig-CNAME" "start"
        CMDS+=("dig CNAME \"$domain\" +short > \"$OUT/cname.txt\" 2>/dev/null")
        
        log_tool "dig-PTR" "start"
        CMDS+=("dig -x \$(dig A \"$domain\" +short | head -1) +short > \"$OUT/ptr.txt\" 2>/dev/null")
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 3+: Extended DNS Analysis
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]]; then
        # SPF, DKIM, DMARC records
        log_tool "dig-SPF" "start"
        CMDS+=("dig TXT \"$domain\" +short | grep -i spf > \"$OUT/spf.txt\" 2>/dev/null")
        
        log_tool "dig-DMARC" "start"
        CMDS+=("dig TXT \"_dmarc.$domain\" +short > \"$OUT/dmarc.txt\" 2>/dev/null")
        
        log_tool "dig-DKIM" "start"
        CMDS+=("dig TXT \"default._domainkey.$domain\" +short > \"$OUT/dkim.txt\" 2>/dev/null")
        
        # CAA records
        log_tool "dig-CAA" "start"
        CMDS+=("dig CAA \"$domain\" +short > \"$OUT/caa.txt\" 2>/dev/null")
        
        # SRV records for common services
        log_tool "dig-SRV" "start"
        CMDS+=("dig SRV \"_sip._tcp.$domain\" +short > \"$OUT/srv_sip.txt\" 2>/dev/null")
        CMDS+=("dig SRV \"_xmpp-server._tcp.$domain\" +short > \"$OUT/srv_xmpp.txt\" 2>/dev/null")
        CMDS+=("dig SRV \"_ldap._tcp.$domain\" +short > \"$OUT/srv_ldap.txt\" 2>/dev/null")
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 4+: DNS Enumeration Tools
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]]; then
        # DNSRecon (if available)
        if tool_exists dnsrecon; then
            log_tool "dnsrecon" "start"
            CMDS+=("dnsrecon -d \"$domain\" -t std -j \"$OUT/dnsrecon.json\" 2>/dev/null")
        fi
        
        # DNSEnum (if available)
        if tool_exists dnsenum; then
            log_tool "dnsenum" "start"
            CMDS+=("dnsenum --noreverse \"$domain\" -o \"$OUT/dnsenum.xml\" 2>/dev/null")
        fi
        
        # Fierce (if available)
        if tool_exists fierce; then
            log_tool "fierce" "start"
            CMDS+=("fierce --domain \"$domain\" > \"$OUT/fierce.txt\" 2>/dev/null")
        fi
        
        # DNSX Brute-Force (if available)
        if tool_exists dnsx; then
            local dns_wl="${CUSTOM_WORDLIST:-${WORDLIST_SUBS_MEDIUM:-$BASE_DIR/wordlists/subdomains-fast.txt}}"
            if [[ -f "$dns_wl" ]]; then
                log_tool "dnsx-bruteforce" "start"
                CMDS+=("dnsx -d \"$domain\" -w \"$dns_wl\" -silent -resp -o \"$OUT/dnsx_bruteforce.txt\" 2>/dev/null")
            fi
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 5: Maximum DNS Analysis
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 5 ]]; then
        # Full ANY query
        log_tool "dig-ANY" "start"
        CMDS+=("dig ANY \"$domain\" > \"$OUT/any.txt\" 2>/dev/null")
        
        # DNSSEC records
        log_tool "dig-DNSSEC" "start"
        CMDS+=("dig DNSKEY \"$domain\" +short > \"$OUT/dnskey.txt\" 2>/dev/null")
        CMDS+=("dig DS \"$domain\" +short > \"$OUT/ds.txt\" 2>/dev/null")
        CMDS+=("dig NSEC \"$domain\" +short > \"$OUT/nsec.txt\" 2>/dev/null")
        
        # TLSA records
        log_tool "dig-TLSA" "start"
        CMDS+=("dig TLSA \"_443._tcp.$domain\" +short > \"$OUT/tlsa.txt\" 2>/dev/null")
    fi
    
    # Execute all commands in parallel
    run_parallel "${CMDS[@]}"
    
    # ═══════════════════════════════════════════════════════════════
    # Zone Transfer Attempts
    # ═══════════════════════════════════════════════════════════════
    log_info "Attempting zone transfers..."
    
    if [[ -f "$OUT/ns.txt" ]]; then
        while IFS= read -r ns; do
            [[ -z "$ns" ]] && continue
            ns=$(echo "$ns" | sed 's/\.$//')
            log_tool "axfr-$ns" "start"
            dig AXFR "$domain" @"$ns" > "$OUT/axfr_${ns}.txt" 2>/dev/null &
        done < "$OUT/ns.txt"
        wait
        
        # Check for successful zone transfers
        for axfr_file in "$OUT"/axfr_*.txt; do
            [[ -f "$axfr_file" ]] || continue
            if grep -q "XFR size" "$axfr_file" 2>/dev/null; then
                log_warn "Zone transfer successful: $axfr_file"
            fi
        done
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # Generate Summary
    # ═══════════════════════════════════════════════════════════════
    {
        echo "# DNS Reconnaissance Summary"
        echo "Domain: $domain"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
        echo ""
        echo "## DNS Records"
        echo ""
        echo "### A Records"
        cat "$OUT/a.txt" 2>/dev/null || echo "None found"
        echo ""
        echo "### AAAA Records"
        cat "$OUT/aaaa.txt" 2>/dev/null || echo "None found"
        echo ""
        echo "### NS Records"
        cat "$OUT/ns.txt" 2>/dev/null || echo "None found"
        echo ""
        echo "### MX Records"
        cat "$OUT/mx.txt" 2>/dev/null || echo "None found"
        echo ""
        echo "### TXT Records"
        cat "$OUT/txt.txt" 2>/dev/null || echo "None found"
        echo ""
        if [[ -f "$OUT/spf.txt" ]]; then
            echo "### SPF Record"
            cat "$OUT/spf.txt"
            echo ""
        fi
        if [[ -f "$OUT/dmarc.txt" ]]; then
            echo "### DMARC Record"
            cat "$OUT/dmarc.txt"
            echo ""
        fi
    } > "$OUT/summary.md"
    
    log_success "DNS reconnaissance completed"
    log_info "Results saved to: $OUT/"
}