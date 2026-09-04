#!/bin/bash

# Network Scanning Module
# Additional scanning utilities for ReconX

# Quick network scan
quick_scan() {
    local target=$1
    local OUT="output/$target/scan"
    mkdir -p "$OUT"
    
    log_info "Running quick network scan on $target"
    
    if tool_exists nmap; then
        nmap --top-ports 100 -T4 "$target" -oN "$OUT/quick_scan.txt" 2>/dev/null
    fi
    
    log_success "Quick scan completed"
}

# Comprehensive network scan
full_network_scan() {
    local target=$1
    local OUT="output/$target/scan"
    mkdir -p "$OUT"
    
    log_info "Running comprehensive network scan on $target"
    
    if tool_exists nmap; then
        # TCP SYN scan
        nmap -sS -p- --min-rate 5000 -T4 "$target" -oN "$OUT/tcp_syn.txt" 2>/dev/null
        
        # UDP scan (top ports)
        nmap -sU --top-ports 100 -T4 "$target" -oN "$OUT/udp_scan.txt" 2>/dev/null
        
        # Service version detection
        local ports=$(grep "open" "$OUT/tcp_syn.txt" | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
        [[ -n "$ports" ]] && nmap -sV -sC -p "$ports" "$target" -oN "$OUT/service_scan.txt" 2>/dev/null
    fi
    
    log_success "Comprehensive scan completed"
}

# Stealth scan
stealth_scan() {
    local target=$1
    local OUT="output/$target/scan"
    mkdir -p "$OUT"
    
    log_info "Running stealth scan on $target"
    
    if tool_exists nmap; then
        nmap -sS -T2 -f --data-length 24 "$target" -oN "$OUT/stealth_scan.txt" 2>/dev/null
    fi
    
    log_success "Stealth scan completed"
}

# Vulnerability scan
vuln_network_scan() {
    local target=$1
    local OUT="output/$target/scan"
    mkdir -p "$OUT"
    
    log_info "Running vulnerability scan on $target"
    
    if tool_exists nmap; then
        nmap --script=vuln "$target" -oN "$OUT/vuln_scan.txt" 2>/dev/null
    fi
    
    log_success "Vulnerability scan completed"
}
