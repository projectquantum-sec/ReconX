#!/bin/bash

# Enhanced Service Enumeration Module
# Supports robustness levels 1-5

enum_recon() {
    local target=$1
    local SERVICES="output/$target/active/services.txt"
    local OUT="output/$target/enum"
    mkdir -p "$OUT"
    
    log_section "SERVICE ENUMERATION - $target"
    log_info "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
    
    if [[ ! -f "$SERVICES" ]]; then
        log_warn "No services file found. Run active recon first."
        return
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # HTTP/HTTPS Enumeration
    # ═══════════════════════════════════════════════════════════════
    if grep -qiE "(http|https|80/|443/|8080/|8443/)" "$SERVICES"; then
        log_info "HTTP/HTTPS service detected"
        web_recon "$target"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # FTP Enumeration
    # ═══════════════════════════════════════════════════════════════
    if grep -qiE "(ftp|21/)" "$SERVICES"; then
        log_info "FTP service detected"
        log_tool "ftp-enum" "start"
        
        # Banner grab
        timeout 10 nc -nv "$target" 21 > "$OUT/ftp_banner.txt" 2>&1
        
        # Anonymous login check
        {
            echo "USER anonymous"
            sleep 1
            echo "PASS anonymous@test.com"
            sleep 1
            echo "LIST"
            sleep 1
            echo "QUIT"
        } | timeout 15 nc -nv "$target" 21 > "$OUT/ftp_anon.txt" 2>&1
        
        # Nmap FTP scripts (Level 3+)
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists nmap; then
            nmap -p 21 --script=ftp-* "$target" -oN "$OUT/ftp_nmap.txt" 2>/dev/null
        fi
        
        log_tool "ftp-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # SSH Enumeration
    # ═══════════════════════════════════════════════════════════════
    if grep -qiE "(ssh|22/)" "$SERVICES"; then
        log_info "SSH service detected"
        log_tool "ssh-enum" "start"
        
        # Banner grab
        timeout 10 nc -nv "$target" 22 > "$OUT/ssh_banner.txt" 2>&1
        
        # SSH audit (if available)
        if tool_exists ssh-audit && [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]]; then
            ssh-audit "$target" > "$OUT/ssh_audit.txt" 2>/dev/null
        fi
        
        # Nmap SSH scripts (Level 3+)
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists nmap; then
            nmap -p 22 --script=ssh-* "$target" -oN "$OUT/ssh_nmap.txt" 2>/dev/null
        fi
        
        log_tool "ssh-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # SMB Enumeration
    # ═══════════════════════════════════════════════════════════════
    if grep -qiE "(smb|microsoft-ds|netbios|139/|445/)" "$SERVICES"; then
        log_info "SMB service detected"
        log_tool "smb-enum" "start"
        
        # enum4linux
        if tool_exists enum4linux; then
            enum4linux -a "$target" > "$OUT/enum4linux.txt" 2>/dev/null
        fi
        
        # smbclient
        if tool_exists smbclient; then
            smbclient -L "//$target" -N > "$OUT/smbclient.txt" 2>/dev/null
        fi
        
        # Nmap SMB scripts (Level 3+)
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists nmap; then
            nmap -p 139,445 --script=smb-* "$target" -oN "$OUT/smb_nmap.txt" 2>/dev/null
        fi
        
        # CrackMapExec (Level 4+)
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]] && tool_exists crackmapexec; then
            crackmapexec smb "$target" > "$OUT/cme_smb.txt" 2>/dev/null
        fi
        
        log_tool "smb-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # MySQL Enumeration
    # ═══════════════════════════════════════════════════════════════
    if grep -qiE "(mysql|3306/)" "$SERVICES"; then
        log_info "MySQL service detected"
        log_tool "mysql-enum" "start"
        
        # Banner grab
        timeout 10 nc -nv "$target" 3306 > "$OUT/mysql_banner.txt" 2>&1
        
        # Nmap MySQL scripts (Level 3+)
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists nmap; then
            nmap -p 3306 --script=mysql-* "$target" -oN "$OUT/mysql_nmap.txt" 2>/dev/null
        fi
        
        log_tool "mysql-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PostgreSQL Enumeration
    # ═══════════════════════════════════════════════════════════════
    if grep -qiE "(postgresql|postgres|5432/)" "$SERVICES"; then
        log_info "PostgreSQL service detected"
        log_tool "postgres-enum" "start"
        
        # Nmap PostgreSQL scripts (Level 3+)
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists nmap; then
            nmap -p 5432 --script=pgsql-* "$target" -oN "$OUT/postgres_nmap.txt" 2>/dev/null
        fi
        
        log_tool "postgres-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # MSSQL Enumeration
    # ═══════════════════════════════════════════════════════════════
    if grep -qiE "(mssql|ms-sql|1433/)" "$SERVICES"; then
        log_info "MSSQL service detected"
        log_tool "mssql-enum" "start"
        
        # Nmap MSSQL scripts (Level 3+)
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists nmap; then
            nmap -p 1433 --script=ms-sql-* "$target" -oN "$OUT/mssql_nmap.txt" 2>/dev/null
        fi
        
        log_tool "mssql-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # RDP Enumeration
    # ═══════════════════════════════════════════════════════════════
    if grep -qiE "(rdp|ms-wbt-server|3389/)" "$SERVICES"; then
        log_info "RDP service detected"
        log_tool "rdp-enum" "start"
        
        # Nmap RDP scripts (Level 3+)
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists nmap; then
            nmap -p 3389 --script=rdp-* "$target" -oN "$OUT/rdp_nmap.txt" 2>/dev/null
        fi
        
        log_tool "rdp-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # LDAP Enumeration (Level 3+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && grep -qiE "(ldap|389/|636/)" "$SERVICES"; then
        log_info "LDAP service detected"
        log_tool "ldap-enum" "start"
        
        # ldapsearch
        if tool_exists ldapsearch; then
            ldapsearch -x -h "$target" -s base > "$OUT/ldap_base.txt" 2>/dev/null
        fi
        
        # Nmap LDAP scripts
        if tool_exists nmap; then
            nmap -p 389,636 --script=ldap-* "$target" -oN "$OUT/ldap_nmap.txt" 2>/dev/null
        fi
        
        log_tool "ldap-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # SNMP Enumeration (Level 3+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && grep -qiE "(snmp|161/|162/)" "$SERVICES"; then
        log_info "SNMP service detected"
        log_tool "snmp-enum" "start"
        
        # snmpwalk
        if tool_exists snmpwalk; then
            snmpwalk -v2c -c public "$target" > "$OUT/snmpwalk.txt" 2>/dev/null
        fi
        
        # onesixtyone
        if tool_exists onesixtyone; then
            onesixtyone "$target" public > "$OUT/onesixtyone.txt" 2>/dev/null
        fi
        
        # Nmap SNMP scripts
        if tool_exists nmap; then
            nmap -sU -p 161 --script=snmp-* "$target" -oN "$OUT/snmp_nmap.txt" 2>/dev/null
        fi
        
        log_tool "snmp-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # SMTP Enumeration (Level 3+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && grep -qiE "(smtp|25/|587/|465/)" "$SERVICES"; then
        log_info "SMTP service detected"
        log_tool "smtp-enum" "start"
        
        # Banner grab
        timeout 10 nc -nv "$target" 25 > "$OUT/smtp_banner.txt" 2>&1
        
        # Nmap SMTP scripts
        if tool_exists nmap; then
            nmap -p 25,587,465 --script=smtp-* "$target" -oN "$OUT/smtp_nmap.txt" 2>/dev/null
        fi
        
        # smtp-user-enum (if available)
        if tool_exists smtp-user-enum; then
            smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t "$target" > "$OUT/smtp_users.txt" 2>/dev/null
        fi
        
        log_tool "smtp-enum" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # Generate Summary
    # ═══════════════════════════════════════════════════════════════
    {
        echo "# Service Enumeration Summary"
        echo "Target: $target"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
        echo ""
        echo "## Detected Services"
        echo ""
        grep -E "^[0-9]+/(tcp|udp)" "$SERVICES" 2>/dev/null
        echo ""
        echo "## Enumeration Results"
        echo ""
        for f in "$OUT"/*.txt; do
            [[ -f "$f" ]] || continue
            local fname=$(basename "$f")
            local size=$(wc -c < "$f" 2>/dev/null || echo 0)
            [[ $size -gt 0 ]] && echo "- $fname: $size bytes"
        done
    } > "$OUT/summary.md"
    
    log_success "Service enumeration completed"
    log_info "Results saved to: $OUT/"
}
