#!/bin/bash

# Enhanced Active Reconnaissance Module
# Supports robustness levels 1-5 with multiple scanning tools

active_recon() {
    local target=$1
    local OUT="output/$target/active"
    mkdir -p "$OUT"
    
    log_section "ACTIVE RECONNAISSANCE - $target"
    log_info "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
    log_info "Mode: ${MODE:-normal}"
    
    local timing=$(get_nmap_timing)
    local port_range=$(get_port_range)
    local threads=$(get_scan_threads)
    
    # Extract clean hostname or IP for nmap (strip scheme, paths, ports)
    local scan_host="${TARGET_HOST:-$(echo "$target" | sed 's|https\?://||; s|/.*||; s/:.*//')}"
    [[ -n "$TARGET_PORT" ]] && port_range="$TARGET_PORT,$port_range"
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: Host Discovery
    # ═══════════════════════════════════════════════════════════════
    log_info "Phase 1: Host Discovery"
    
    # Ping sweep (if not in bug bounty mode)
    if [[ "$MODE" != "bugbounty" ]]; then
        log_tool "ping-sweep" "start"
        if tool_exists nmap; then
            nmap -sn "$scan_host" -oN "$OUT/host_discovery.txt" 2>/dev/null
            log_tool "ping-sweep" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: Port Scanning
    # ═══════════════════════════════════════════════════════════════
    log_info "Phase 2: Port Scanning"
    
    # Bug bounty mode - limited ports
    if [[ "$MODE" == "bugbounty" ]]; then
        log_warn "Bug Bounty mode: Using limited port range and rate limiting"
        port_range="21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443"
        [[ -n "$TARGET_PORT" ]] && port_range="$TARGET_PORT,$port_range"
        timing="T2"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 1: Quick scan - Top ports only
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -eq 1 ]]; then
        log_tool "nmap-quick" "start"
        nmap --top-ports 100 -$timing "$scan_host" -oN "$OUT/ports_quick.txt" -oX "$OUT/ports_quick.xml" 2>/dev/null
        log_tool "nmap-quick" "success"
        
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 2: Basic scan - Top 1000 ports
    # ═══════════════════════════════════════════════════════════════
    elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 2 ]]; then
        log_tool "nmap-basic" "start"
        nmap --top-ports 1000 -$timing "$scan_host" -oN "$OUT/ports_basic.txt" -oX "$OUT/ports_basic.xml" 2>/dev/null
        log_tool "nmap-basic" "success"
        
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 3: Normal scan - Custom port range
    # ═══════════════════════════════════════════════════════════════
    elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 3 ]]; then
        log_tool "nmap-normal" "start"
        nmap -p "$port_range" --min-rate 1000 -$timing "$scan_host" \
            -oN "$OUT/ports_normal.txt" -oX "$OUT/ports_normal.xml" 2>/dev/null
        log_tool "nmap-normal" "success"
        
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 4: Thorough scan - Full port range with multiple tools
    # ═══════════════════════════════════════════════════════════════
    elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 4 ]]; then
        # Masscan for fast initial scan (if available and running as root)
        if tool_exists masscan && [[ "$MODE" != "bugbounty" ]]; then
            if [[ $EUID -eq 0 ]]; then
                log_tool "masscan" "start"
                local target_ip
                target_ip=$(resolve_subdomain "$scan_host")
                [[ -z "$target_ip" ]] && target_ip="$scan_host"
                masscan -p1-65535 "$target_ip" --rate=10000 -oL "$OUT/masscan.txt" 2>/dev/null
                log_tool "masscan" "success"
            else
                log_warn "Masscan skipped: requires root/raw socket privileges. Using Nmap/RustScan."
            fi
        fi
        
        # Nmap full port scan
        log_tool "nmap-full" "start"
        nmap -p- --min-rate 2000 -$timing "$scan_host" \
            -oN "$OUT/ports_full.txt" -oX "$OUT/ports_full.xml" 2>/dev/null
        log_tool "nmap-full" "success"
        
        # RustScan (if available)
        if tool_exists rustscan; then
            log_tool "rustscan" "start"
            rustscan -a "$scan_host" --ulimit 5000 -- -sV > "$OUT/rustscan.txt" 2>/dev/null
            log_tool "rustscan" "success"
        fi
        
    # ═══════════════════════════════════════════════════════════════
    # LEVEL 5: Aggressive scan - All techniques
    # ═══════════════════════════════════════════════════════════════
    elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 5 ]]; then
        # Masscan ultra-fast scan (if available and running as root)
        if tool_exists masscan && [[ "$MODE" != "bugbounty" ]]; then
            if [[ $EUID -eq 0 ]]; then
                log_tool "masscan-aggressive" "start"
                local target_ip
                target_ip=$(resolve_subdomain "$scan_host")
                [[ -z "$target_ip" ]] && target_ip="$scan_host"
                masscan -p1-65535 "$target_ip" --rate=50000 -oL "$OUT/masscan_aggressive.txt" 2>/dev/null
                log_tool "masscan-aggressive" "success"
            else
                log_warn "Masscan skipped: requires root/raw socket privileges. Using Nmap/RustScan."
            fi
        fi
        
        # Nmap aggressive scan
        log_tool "nmap-aggressive" "start"
        nmap -p- -A --min-rate 5000 -T5 "$scan_host" \
            -oN "$OUT/ports_aggressive.txt" -oX "$OUT/ports_aggressive.xml" 2>/dev/null
        log_tool "nmap-aggressive" "success"
        
        # UDP scan (top ports)
        if [[ "$MODE" != "bugbounty" ]]; then
            log_tool "nmap-udp" "start"
            nmap -sU --top-ports 100 -$timing "$scan_host" \
                -oN "$OUT/udp_ports.txt" -oX "$OUT/udp_ports.xml" 2>/dev/null
            log_tool "nmap-udp" "success"
        fi
        
        # RustScan with all ports
        if tool_exists rustscan; then
            log_tool "rustscan-full" "start"
            rustscan -a "$scan_host" -r 1-65535 --ulimit 10000 -- -A > "$OUT/rustscan_full.txt" 2>/dev/null
            log_tool "rustscan-full" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: Extract Open Ports
    # ═══════════════════════════════════════════════════════════════
    log_info "Phase 3: Extracting open ports"
    
    # Combine all port scan results
    cat "$OUT"/ports_*.txt "$OUT"/masscan*.txt "$OUT"/rustscan*.txt 2>/dev/null \
        | grep -E "^[0-9]+/(tcp|udp)" \
        | grep "open" \
        | awk -F/ '{print $1}' \
        | sort -un > "$OUT/open_ports_list.txt"
    
    # Create comma-separated port list
    PORTS=$(cat "$OUT/open_ports_list.txt" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    echo "$PORTS" > "$OUT/open_ports.txt"
    
    if [[ -z "$PORTS" ]]; then
        log_warn "No open ports found"
        return
    fi
    
    local port_count=$(wc -l < "$OUT/open_ports_list.txt" 2>/dev/null || echo 0)
    log_info "Found $port_count open ports: $PORTS"
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: Service Detection
    # ═══════════════════════════════════════════════════════════════
    log_info "Phase 4: Service Detection"
    
    log_tool "nmap-services" "start"
    nmap -sC -sV -p "$PORTS" -$timing "$scan_host" \
        -oN "$OUT/services.txt" -oX "$OUT/services.xml" 2>/dev/null
    log_tool "nmap-services" "success"
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: Advanced Scanning (Level 4+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]]; then
        log_info "Phase 5: Advanced Scanning"
        
        # OS Detection
        if [[ "$MODE" != "bugbounty" ]]; then
            log_tool "nmap-os" "start"
            nmap -O -p "$PORTS" "$target" -oN "$OUT/os_detection.txt" 2>/dev/null
            log_tool "nmap-os" "success"
        fi
        
        # Vulnerability scripts
        log_tool "nmap-vuln-scripts" "start"
        nmap --script=vuln -p "$PORTS" "$target" -oN "$OUT/vuln_scripts.txt" 2>/dev/null
        log_tool "nmap-vuln-scripts" "success"
        
        # SSL/TLS analysis
        if echo "$PORTS" | grep -qE "(443|8443|993|995)"; then
            log_tool "nmap-ssl" "start"
            nmap --script=ssl-enum-ciphers,ssl-cert -p 443,8443,993,995 "$target" \
                -oN "$OUT/ssl_analysis.txt" 2>/dev/null
            log_tool "nmap-ssl" "success"
            
            # SSLScan (if available)
            if tool_exists sslscan; then
                log_tool "sslscan" "start"
                sslscan "$target" > "$OUT/sslscan.txt" 2>/dev/null
                log_tool "sslscan" "success"
            fi
            
            # testssl.sh (if available)
            if tool_exists testssl.sh; then
                log_tool "testssl" "start"
                testssl.sh --quiet "$target" > "$OUT/testssl.txt" 2>/dev/null
                log_tool "testssl" "success"
            fi
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: Maximum Depth Scanning (Level 5)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 5 ]]; then
        log_info "Phase 6: Maximum Depth Scanning"
        
        # All NSE scripts
        log_tool "nmap-all-scripts" "start"
        nmap --script=default,safe -p "$PORTS" "$target" \
            -oN "$OUT/all_scripts.txt" 2>/dev/null
        log_tool "nmap-all-scripts" "success"
        
        # Banner grabbing
        log_tool "banner-grab" "start"
        for port in $(echo "$PORTS" | tr ',' ' '); do
            timeout 5 nc -nv "$target" "$port" < /dev/null > "$OUT/banner_$port.txt" 2>&1 &
        done
        wait
        log_tool "banner-grab" "success"
        
        # Nmap firewall evasion techniques
        if [[ "$MODE" != "bugbounty" ]]; then
            log_tool "nmap-evasion" "start"
            nmap -f -D RND:5 -p "$PORTS" "$target" -oN "$OUT/evasion_scan.txt" 2>/dev/null
            log_tool "nmap-evasion" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # Generate Summary
    # ═══════════════════════════════════════════════════════════════
    {
        echo "# Active Reconnaissance Summary"
        echo "Target: $target"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
        echo "Mode: ${MODE:-normal}"
        echo ""
        echo "## Open Ports"
        echo "Total: $port_count"
        echo ""
        echo "### Port List"
        cat "$OUT/open_ports_list.txt" 2>/dev/null
        echo ""
        echo "## Services Detected"
        grep -E "^[0-9]+/(tcp|udp)" "$OUT/services.txt" 2>/dev/null | head -50
    } > "$OUT/summary.md"
    
    log_success "Active reconnaissance completed"
    log_info "Results saved to: $OUT/"
}

# Quick port check for specific services
check_common_ports() {
    local target=$1
    local OUT="output/$target/active"
    
    log_info "Checking common service ports..."
    
    local common_ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"
    
    nmap -p "$common_ports" --open "$target" -oN "$OUT/common_ports.txt" 2>/dev/null
    
    log_success "Common port check completed"
}

# Scan for specific service
scan_service() {
    local target=$1
    local service=$2
    local OUT="output/$target/active"
    
    log_info "Scanning for $service service..."
    
    case "$service" in
        "http"|"web")
            nmap -p 80,443,8080,8443,8000,8888 --script=http-* "$target" -oN "$OUT/http_scan.txt"
            ;;
        "ssh")
            nmap -p 22 --script=ssh-* "$target" -oN "$OUT/ssh_scan.txt"
            ;;
        "ftp")
            nmap -p 21 --script=ftp-* "$target" -oN "$OUT/ftp_scan.txt"
            ;;
        "smb")
            nmap -p 139,445 --script=smb-* "$target" -oN "$OUT/smb_scan.txt"
            ;;
        "mysql")
            nmap -p 3306 --script=mysql-* "$target" -oN "$OUT/mysql_scan.txt"
            ;;
        "mssql")
            nmap -p 1433 --script=ms-sql-* "$target" -oN "$OUT/mssql_scan.txt"
            ;;
        "rdp")
            nmap -p 3389 --script=rdp-* "$target" -oN "$OUT/rdp_scan.txt"
            ;;
        *)
            log_warn "Unknown service: $service"
            ;;
    esac
}
