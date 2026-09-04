#!/bin/bash

# Enhanced Vulnerability Finding Module
# Supports robustness levels 1-5 with multiple vulnerability scanners

vuln_scan() {
    local target=$1
    local LIVE="output/$target/web/live.txt"
    local SUBDOMAINS="output/$target/passive/subdomains.txt"
    local SERVICES="output/$target/active/services.txt"
    local OUT="output/$target/vuln"
    mkdir -p "$OUT"
    
    log_section "VULNERABILITY SCANNING - $target"
    log_info "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
    
    local threads=$(get_scan_threads)
    local vuln_count=0
    
    # Determine severity levels based on robustness
    local severity=""
    case ${ROBUSTNESS_LEVEL:-3} in
        1) severity="critical" ;;
        2) severity="critical,high" ;;
        3) severity="critical,high,medium" ;;
        4) severity="critical,high,medium,low" ;;
        5) severity="critical,high,medium,low,info" ;;
    esac
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: Nuclei Scanning (Primary Scanner)
    # ═══════════════════════════════════════════════════════════════
    if tool_exists nuclei; then
        log_info "Phase 1: Nuclei Vulnerability Scanning"
        
        # Prepare target list
        local nuclei_targets="$OUT/nuclei_targets.txt"
        {
            [[ -f "$LIVE" ]] && cat "$LIVE"
            [[ -f "$SUBDOMAINS" ]] && sed 's|^https\?://||; s/^/https:\/\//' "$SUBDOMAINS"
            if [[ -n "$TARGET_URL" ]]; then
                echo "$TARGET_URL"
            elif [[ "$target" =~ ^https?:// ]]; then
                echo "$target" | sed 's|/$||'
            else
                echo "https://$target"
                echo "http://$target"
            fi
        } | grep -E '^https?://' | sort -u > "$nuclei_targets"
        
        # Prepare extra nuclei flags (Proxy, User-Agent, Custom Headers)
        local extra_nuclei_opts=""
        [[ -n "$HTTP_PROXY" ]] && extra_nuclei_opts="$extra_nuclei_opts -proxy $HTTP_PROXY"
        local ua=$(get_random_user_agent)
        extra_nuclei_opts="$extra_nuclei_opts -H \"User-Agent: $ua\""
        [[ -n "$CUSTOM_HEADERS" ]] && extra_nuclei_opts="$extra_nuclei_opts -H \"$CUSTOM_HEADERS\""

        # ═══════════════════════════════════════════════════════════════
        # Technology-Directed Scanning (High-Confidence)
        # ═══════════════════════════════════════════════════════════════
        local detected_techs=""
        [[ -f "output/$target/web/whatweb.txt" ]] && detected_techs="$detected_techs $(cat "output/$target/web/whatweb.txt" 2>/dev/null)"
        [[ -f "output/$target/web/httpx.json" ]] && detected_techs="$detected_techs $(cat "output/$target/web/httpx.json" 2>/dev/null)"
        
        local target_tags=()
        echo "$detected_techs" | grep -qi "wordpress" && target_tags+=("wordpress")
        echo "$detected_techs" | grep -qi "joomla" && target_tags+=("joomla")
        echo "$detected_techs" | grep -qi "drupal" && target_tags+=("drupal")
        echo "$detected_techs" | grep -qi "spring" && target_tags+=("spring,springboot")
        echo "$detected_techs" | grep -qi "laravel" && target_tags+=("laravel")
        echo "$detected_techs" | grep -qi "jenkins" && target_tags+=("jenkins")
        echo "$detected_techs" | grep -qi "grafana" && target_tags+=("grafana")
        echo "$detected_techs" | grep -qi "jira" && target_tags+=("jira")
        
        if [[ ${#target_tags[@]} -gt 0 ]]; then
            local joined_tags=$(IFS=,; echo "${target_tags[*]}")
            log_info "Running technology-directed Nuclei templates: $joined_tags"
            log_tool "nuclei-tech-targeted" "start"
            eval nuclei -l "$nuclei_targets" \
                   -tags "$joined_tags" \
                   -c $threads \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_targeted_tech.json" 2>/dev/null
            log_tool "nuclei-tech-targeted" "success"
        fi

        # ═══════════════════════════════════════════════════════════════
        # LEVEL 1: Quick scan - Critical only, fast templates
        # ═══════════════════════════════════════════════════════════════
        if [[ ${ROBUSTNESS_LEVEL:-3} -eq 1 ]]; then
            log_tool "nuclei-quick" "start"
            eval nuclei -l "$nuclei_targets" \
                   -severity critical \
                   -c $threads \
                   -timeout 5 \
                   -retries 1 \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_critical.json" 2>/dev/null
            log_tool "nuclei-quick" "success"
            
        # ═══════════════════════════════════════════════════════════════
        # LEVEL 2: Basic scan - Critical and High
        # ═══════════════════════════════════════════════════════════════
        elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 2 ]]; then
            log_tool "nuclei-basic" "start"
            eval nuclei -l "$nuclei_targets" \
                   -severity critical,high \
                   -c $threads \
                   -timeout 10 \
                   -retries 2 \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_high.json" 2>/dev/null
            log_tool "nuclei-basic" "success"
            
        # ═══════════════════════════════════════════════════════════════
        # LEVEL 3: Normal scan - Standard templates
        # ═══════════════════════════════════════════════════════════════
        elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 3 ]]; then
            log_tool "nuclei-normal" "start"
            eval nuclei -l "$nuclei_targets" \
                   -severity critical,high,medium \
                   -c $threads \
                   -timeout 15 \
                   -retries 2 \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_medium.json" 2>/dev/null
            log_tool "nuclei-normal" "success"
            
            # CVE scanning
            log_tool "nuclei-cve" "start"
            eval nuclei -l "$nuclei_targets" \
                   -tags cve \
                   -severity critical,high,medium \
                   -c $threads \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_cve.json" 2>/dev/null
            log_tool "nuclei-cve" "success"

            # Default logins & exposures (DVWA, admin panels, configs)
            log_tool "nuclei-exposures" "start"
            eval nuclei -l "$nuclei_targets" \
                   -tags default-login,exposure,misconfig,login \
                   -c $threads \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_exposures.json" 2>/dev/null
            log_tool "nuclei-exposures" "success"
            
        # ═══════════════════════════════════════════════════════════════
        # LEVEL 4: Thorough scan - Extended templates
        # ═══════════════════════════════════════════════════════════════
        elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 4 ]]; then
            log_tool "nuclei-thorough" "start"
            nuclei -l "$nuclei_targets" \
                   -severity critical,high,medium,low \
                   -c $threads \
                   -timeout 30 \
                   -retries 3 \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_all.json" 2>/dev/null
            log_tool "nuclei-thorough" "success"
            
            # Technology detection
            log_tool "nuclei-tech" "start"
            nuclei -l "$nuclei_targets" \
                   -tags tech \
                   -c $threads \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_tech.json" 2>/dev/null
            log_tool "nuclei-tech" "success"
            
            # Exposed panels
            log_tool "nuclei-panels" "start"
            nuclei -l "$nuclei_targets" \
                   -tags panel,login \
                   -c $threads \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_panels.json" 2>/dev/null
            log_tool "nuclei-panels" "success"
            
            # Misconfigurations
            log_tool "nuclei-misconfig" "start"
            nuclei -l "$nuclei_targets" \
                   -tags misconfig \
                   -c $threads \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_misconfig.json" 2>/dev/null
            log_tool "nuclei-misconfig" "success"
            
        # ═══════════════════════════════════════════════════════════════
        # LEVEL 5: Aggressive scan - All templates
        # ═══════════════════════════════════════════════════════════════
        elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 5 ]]; then
            log_tool "nuclei-aggressive" "start"
            nuclei -l "$nuclei_targets" \
                   -severity critical,high,medium,low,info \
                   -c $threads \
                   -timeout 60 \
                   -retries 3 \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_full.json" 2>/dev/null
            log_tool "nuclei-aggressive" "success"
            
            # All vulnerability categories
            for category in cve,cnvd,osint,exposed,takeover,misconfiguration,exposure,file,default-login,token,xss,sqli,lfi,rce,ssrf,redirect; do
                log_tool "nuclei-$category" "start"
                nuclei -l "$nuclei_targets" \
                       -tags "$category" \
                       -c $threads \
                       $extra_nuclei_opts \
                       -jsonl \
                       -o "$OUT/nuclei_${category}.json" 2>/dev/null
                log_tool "nuclei-$category" "success"
            done
            
            # Fuzzing templates
            log_tool "nuclei-fuzz" "start"
            nuclei -l "$nuclei_targets" \
                   -tags fuzz \
                   -c $threads \
                   $extra_nuclei_opts \
                   -jsonl \
                   -o "$OUT/nuclei_fuzz.json" 2>/dev/null
            log_tool "nuclei-fuzz" "success"
        fi
    else
        log_tool "nuclei" "skip" "not installed"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: Nikto Web Scanner (Level 3+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists nikto; then
        log_info "Phase 2: Nikto Web Scanning"
        
        log_tool "nikto" "start"
        if [[ -f "$LIVE" ]]; then
            while IFS= read -r url; do
                local host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
                local safe_host=$(echo "$host" | tr ':' '_')
                nikto -h "$url" -output "$OUT/nikto_${safe_host}.txt" -Format txt -maxtime 300s 2>/dev/null &
            done < "$LIVE"
            wait
        else
            local safe_target=$(echo "${TARGET_HOST:-$target}" | tr ':' '_')
            nikto -h "https://${TARGET_HOST:-$target}" -output "$OUT/nikto_${safe_target}.txt" -Format txt -maxtime 300s 2>/dev/null
        fi
        log_tool "nikto" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: SQLMap (Level 4+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]] && tool_exists sqlmap; then
        log_info "Phase 3: SQL Injection Testing"
        
        # Check for URLs with parameters
        local param_urls="$OUT/param_urls.txt"
        if [[ -f "output/$target/passive/wayback_urls.txt" ]]; then
            grep -E "\?.*=" "output/$target/passive/wayback_urls.txt" | head -50 > "$param_urls"
        fi
        
        if [[ -s "$param_urls" ]]; then
            log_tool "sqlmap" "start"
            while IFS= read -r url; do
                local url_hash=$(echo "$url" | md5sum | cut -c1-8)
                sqlmap -u "$url" --batch --level=2 --risk=2 \
                       --output-dir="$OUT/sqlmap_$url_hash" 2>/dev/null &
            done < <(head -10 "$param_urls")
            wait
            log_tool "sqlmap" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: WPScan for WordPress (Level 3+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && tool_exists wpscan; then
        log_info "Phase 4: WordPress Vulnerability Scanning"
        
        # Check if WordPress is detected
        if grep -qi "wordpress" "$SERVICES" 2>/dev/null || \
           grep -qi "wordpress" "output/$target/web/whatweb.txt" 2>/dev/null; then
            log_tool "wpscan" "start"
            local wp_opts="--enumerate vp,vt,u --random-user-agent"
            [[ -n "$WPSCAN_API_TOKEN" ]] && wp_opts="$wp_opts --api-token $WPSCAN_API_TOKEN"
            
            wpscan --url "https://$target" $wp_opts \
                   --output "$OUT/wpscan.json" --format json 2>/dev/null
            log_tool "wpscan" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: XSS Testing (Level 4+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]]; then
        log_info "Phase 5: XSS Vulnerability Testing"
        
        # Dalfox (if available)
        if tool_exists dalfox && [[ -f "$param_urls" ]]; then
            log_tool "dalfox" "start"
            dalfox file "$param_urls" \
                   --silence \
                   --output "$OUT/dalfox.txt" 2>/dev/null
            log_tool "dalfox" "success"
        fi
        
        # XSStrike (if available)
        if tool_exists xsstrike && [[ -f "$param_urls" ]]; then
            log_tool "xsstrike" "start"
            while IFS= read -r url; do
                python3 -m xsstrike -u "$url" --crawl -l 2 \
                        >> "$OUT/xsstrike.txt" 2>/dev/null &
            done < <(head -5 "$param_urls")
            wait
            log_tool "xsstrike" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: Subdomain Takeover (Level 3+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]] && [[ -f "$SUBDOMAINS" ]]; then
        log_info "Phase 6: Subdomain Takeover Detection"
        
        # Subjack (if available)
        if tool_exists subjack; then
            log_tool "subjack" "start"
            subjack -w "$SUBDOMAINS" -t $threads -timeout 30 \
                    -o "$OUT/subjack.txt" -ssl 2>/dev/null
            log_tool "subjack" "success"
        fi
        
        # Nuclei takeover templates
        if tool_exists nuclei; then
            log_tool "nuclei-takeover" "start"
            nuclei -l "$SUBDOMAINS" \
                   -tags takeover \
                   -c $threads \
                   -jsonl \
                   -o "$OUT/nuclei_takeover.json" 2>/dev/null
            log_tool "nuclei-takeover" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 7: CORS Misconfiguration (Level 4+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]]; then
        log_info "Phase 7: CORS Misconfiguration Testing"
        
        # CORScanner (if available)
        if tool_exists cors; then
            log_tool "corscanner" "start"
            if [[ -f "$LIVE" ]]; then
                cors -i "$LIVE" -o "$OUT/cors.json" 2>/dev/null
            fi
            log_tool "corscanner" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 8: SSL/TLS Vulnerabilities (Level 3+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]]; then
        local ssl_host="${TARGET_HOST:-$target}"
        local ssl_port="${TARGET_PORT:-443}"
        # Skip SSL tests if explicitly plain HTTP on non-SSL port
        if [[ "$TARGET_URL" != http://* || "$ssl_port" == "443" || "$ssl_port" == "8443" ]]; then
            log_info "Phase 8: SSL/TLS Vulnerability Testing"
            
            # testssl.sh (if available)
            if tool_exists testssl.sh; then
                log_tool "testssl" "start"
                testssl.sh --quiet --jsonfile "$OUT/testssl.json" "${ssl_host}:${ssl_port}" 2>/dev/null
                log_tool "testssl" "success"
            fi
            
            # SSLyze (if available)
            if tool_exists sslyze; then
                log_tool "sslyze" "start"
                sslyze --json_out="$OUT/sslyze.json" "${ssl_host}:${ssl_port}" 2>/dev/null
                log_tool "sslyze" "success"
            fi
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 9: API Security Testing (Level 5)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 5 ]]; then
        log_info "Phase 9: API Security Testing"
        
        # Check for API endpoints
        if [[ -f "output/$target/passive/wayback_urls.txt" ]]; then
            grep -iE "(api|v[0-9]+|graphql|rest)" "output/$target/passive/wayback_urls.txt" \
                | sort -u > "$OUT/api_endpoints.txt"
        fi
        
        # Arjun for parameter discovery (if available)
        if tool_exists arjun && [[ -f "$OUT/api_endpoints.txt" ]]; then
            log_tool "arjun" "start"
            while IFS= read -r url; do
                arjun -u "$url" -oJ "$OUT/arjun_params.json" 2>/dev/null &
            done < <(head -10 "$OUT/api_endpoints.txt")
            wait
            log_tool "arjun" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # Consolidate Results
    # ═══════════════════════════════════════════════════════════════
    log_info "Consolidating vulnerability results..."
    
    # Count vulnerabilities by severity
    local critical_count=0 high_count=0 medium_count=0 low_count=0 info_count=0
    
    for json_file in "$OUT"/*.json; do
        [[ -f "$json_file" ]] || continue
        critical_count=$((critical_count + $(grep -c '"severity":"critical"' "$json_file" 2>/dev/null || true)))
        high_count=$((high_count + $(grep -c '"severity":"high"' "$json_file" 2>/dev/null || true)))
        medium_count=$((medium_count + $(grep -c '"severity":"medium"' "$json_file" 2>/dev/null || true)))
        low_count=$((low_count + $(grep -c '"severity":"low"' "$json_file" 2>/dev/null || true)))
        info_count=$((info_count + $(grep -c '"severity":"info"' "$json_file" 2>/dev/null || true)))
    done
    
    vuln_count=$((critical_count + high_count + medium_count + low_count))
    
    # Generate vulnerability summary
    {
        echo "# Vulnerability Scan Summary"
        echo "Target: $target"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
        echo ""
        echo "## Vulnerability Statistics"
        echo "| Severity | Count |"
        echo "|----------|-------|"
        echo "| Critical | $critical_count |"
        echo "| High     | $high_count |"
        echo "| Medium   | $medium_count |"
        echo "| Low      | $low_count |"
        echo "| Info     | $info_count |"
        echo ""
        echo "**Total Vulnerabilities: $vuln_count**"
        echo ""
        echo "## Critical Findings"
        for json_file in "$OUT"/*.json; do
            [[ -f "$json_file" ]] || continue
            [[ "$json_file" == *"consolidated.json"* ]] && continue
            if command -v jq >/dev/null 2>&1; then
                jq -r 'select(.info.severity == "critical") | "- \(.info.name): \(.host)"' "$json_file" 2>/dev/null
            elif command -v python3 >/dev/null 2>&1; then
                python3 -c '
import json, sys
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
        if d.get("info", {}).get("severity") == "critical":
            print(f"- {d.get(\"info\", {}).get(\"name\")}: {d.get(\"host\")}")
    except Exception: pass
' "$json_file" 2>/dev/null
            fi
        done
        echo ""
        echo "## High Severity Findings"
        for json_file in "$OUT"/*.json; do
            [[ -f "$json_file" ]] || continue
            [[ "$json_file" == *"consolidated.json"* ]] && continue
            if command -v jq >/dev/null 2>&1; then
                jq -r 'select(.info.severity == "high") | "- \(.info.name): \(.host)"' "$json_file" 2>/dev/null
            elif command -v python3 >/dev/null 2>&1; then
                python3 -c '
import json, sys
for line in open(sys.argv[1]):
    try:
        d = json.loads(line)
        if d.get("info", {}).get("severity") == "high":
            print(f"- {d.get(\"info\", {}).get(\"name\")}: {d.get(\"host\")}")
    except Exception: pass
' "$json_file" 2>/dev/null
            fi
        done
    } > "$OUT/summary.md"
    
    # Create consolidated JSON report
    {
        echo "{"
        echo "  \"target\": \"$target\","
        echo "  \"scan_date\": \"$(date -Iseconds)\","
        echo "  \"robustness_level\": ${ROBUSTNESS_LEVEL:-3},"
        echo "  \"statistics\": {"
        echo "    \"critical\": $critical_count,"
        echo "    \"high\": $high_count,"
        echo "    \"medium\": $medium_count,"
        echo "    \"low\": $low_count,"
        echo "    \"info\": $info_count,"
        echo "    \"total\": $vuln_count"
        echo "  },"
        echo "  \"findings\": ["
        local first=true
        for json_file in "$OUT"/*.json; do
            [[ -f "$json_file" ]] || continue
            [[ "$json_file" == *"consolidated.json"* ]] && continue
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                [[ "$first" == "true" ]] && first=false || echo ","
                echo "    $line"
            done < "$json_file"
        done
        echo "  ]"
        echo "}"
    } > "$OUT/consolidated.json"
    
    log_success "Vulnerability scanning completed"
    log_info "Found $vuln_count vulnerabilities (Critical: $critical_count, High: $high_count, Medium: $medium_count, Low: $low_count)"
    log_info "Results saved to: $OUT/"

    if [[ $critical_count -gt 0 ]] || [[ $high_count -gt 0 ]]; then
        send_webhook_notification "🚨 Vulnerabilities Found on $target" "Critical: $critical_count | High: $high_count | Total: $vuln_count" "CRITICAL"
    fi
}

# Quick vulnerability check
quick_vuln_check() {
    local target=$1
    local OUT="output/$target/vuln"
    mkdir -p "$OUT"
    
    log_info "Running quick vulnerability check..."
    
    if tool_exists nuclei; then
        nuclei -u "https://$target" \
               -severity critical,high \
               -c 50 \
               -timeout 10 \
               -jsonl \
               -o "$OUT/quick_check.json" 2>/dev/null
    fi
    
    log_success "Quick vulnerability check completed"
}

# Scan for specific vulnerability type
scan_vuln_type() {
    local target=$1
    local vuln_type=$2
    local OUT="output/$target/vuln"
    mkdir -p "$OUT"
    
    log_info "Scanning for $vuln_type vulnerabilities..."
    
    if tool_exists nuclei; then
        nuclei -u "https://$target" \
               -tags "$vuln_type" \
               -jsonl \
               -o "$OUT/${vuln_type}_scan.json" 2>/dev/null
    fi
    
    log_success "$vuln_type vulnerability scan completed"
}
