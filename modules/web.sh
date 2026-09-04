#!/bin/bash

# Enhanced Web Reconnaissance Module
# Supports robustness levels 1-5

web_recon() {
    local target=$1
    local OUT="output/$target/web"
    mkdir -p "$OUT"
    
    log_section "WEB RECONNAISSANCE - $target"
    log_info "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
    log_info "Mode: ${MODE:-normal}"
    
    local threads=$(get_scan_threads)
    local timeout=$(get_scan_timeout)
    
    # Bug bounty mode adjustments
    if [[ "$MODE" == "bugbounty" ]]; then
        threads=10
        log_warn "Bug Bounty mode: Using reduced thread count"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: HTTP Probing
    # ═══════════════════════════════════════════════════════════════
    log_info "Phase 1: HTTP Probing"
    
    local targets_file="$OUT/targets.txt"
    
    # Prepare target list
    local raw_targets=()
    if [[ -n "$TARGET_URL" ]]; then
        raw_targets+=("$TARGET_URL")
    elif [[ "$target" =~ ^https?:// ]]; then
        raw_targets+=("$target")
    else
        raw_targets+=("$target")
        # Do not prepend www to IP addresses
        if ! echo "$target" | grep -qE "^([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?$"; then
            raw_targets+=("www.$target")
        fi
    fi

    if [[ -f "output/$target/passive/subdomains.txt" ]]; then
        while IFS= read -r sub; do
            raw_targets+=("$sub")
        done < "output/$target/passive/subdomains.txt"
    fi
    
    for host in "${raw_targets[@]}"; do
        [[ -z "$host" ]] && continue
        if ! is_target_excluded "$host" "$EXCLUDE_TARGETS"; then
            echo "$host"
        else
            log_warn "Excluding out-of-scope target: $host"
        fi
    done | sort -u > "$targets_file"
    
    local ua=$(get_random_user_agent)
    local httpx_bin=$(get_httpx_bin)
    
    if [[ -n "$httpx_bin" ]]; then
        log_tool "httpx" "start"
        
        local httpx_opts="-silent -threads $threads -timeout $timeout -H \"User-Agent: $ua\""
        [[ -n "$CUSTOM_HEADERS" ]] && httpx_opts="$httpx_opts -H \"$CUSTOM_HEADERS\""
        [[ -n "$HTTP_PROXY" ]] && httpx_opts="$httpx_opts -http-proxy \"$HTTP_PROXY\""
        
        # Probing and extracting clean URLs for live.txt
        cat "$targets_file" | eval "$httpx_bin" $httpx_opts 2>/dev/null | awk '{print $1}' | grep -E '^https?://' | sort -u > "$OUT/live.txt"
        
        # Save detailed metadata and JSON
        if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]]; then
            cat "$targets_file" | eval "$httpx_bin" -silent -json -H "\"User-Agent: $ua\"" -o "$OUT/httpx.json" 2>/dev/null
        fi
        
        log_tool "httpx" "success"
    else
        log_tool "httpx" "skip" "ProjectDiscovery httpx not found, using curl"
        # Fallback to curl
        log_info "Using curl as fallback..."
        while IFS= read -r host; do
            [[ -z "$host" ]] && continue
            if [[ "$host" =~ ^https?:// ]]; then
                if curl -s -k -o /dev/null -w "%{http_code}" --max-time 6 "$host" 2>/dev/null | grep -qE "^[2345]"; then
                    echo "$host" >> "$OUT/live.txt"
                fi
            else
                for proto in https http; do
                    if curl -s -k -o /dev/null -w "%{http_code}" --max-time 6 "$proto://$host" 2>/dev/null | grep -qE "^[2345]"; then
                        echo "$proto://$host" >> "$OUT/live.txt"
                    fi
                done
            fi
        done < "$targets_file"
    fi
    
    # Ensure URL targets are always registered as live if accessible
    if [[ -s "$targets_file" ]] && [[ ! -s "$OUT/live.txt" ]]; then
        while IFS= read -r entry; do
            if [[ "$entry" =~ ^https?:// ]]; then
                echo "$entry" >> "$OUT/live.txt"
            fi
        done < "$targets_file"
    fi
    
    [[ ! -s "$OUT/live.txt" ]] && { log_warn "No live hosts found"; return; }
    
    local live_count=$(wc -l < "$OUT/live.txt" 2>/dev/null || echo 0)
    log_info "Found $live_count live web hosts"
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: Technology Detection
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 2 ]]; then
        log_info "Phase 2: Technology Detection"
        
        # WhatWeb
        if tool_exists whatweb; then
            log_tool "whatweb" "start"
            local whatweb_aggression=1
            [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]] && whatweb_aggression=3
            
            whatweb -i "$OUT/live.txt" -a $whatweb_aggression --log-json="$OUT/whatweb.json" > "$OUT/whatweb.txt" 2>/dev/null
            log_tool "whatweb" "success"
        fi
        
        # Wappalyzer (if available)
        if tool_exists wappalyzer && [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]]; then
            log_tool "wappalyzer" "start"
            while IFS= read -r url; do
                wappalyzer "$url" >> "$OUT/wappalyzer.json" 2>/dev/null
            done < <(head -20 "$OUT/live.txt")
            log_tool "wappalyzer" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: WAF Detection
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 3 ]]; then
        log_info "Phase 3: WAF Detection"
        
        # wafw00f
        if tool_exists wafw00f; then
            log_tool "wafw00f" "start"
            wafw00f -i "$OUT/live.txt" -o "$OUT/wafw00f.json" -f json 2>/dev/null
            log_tool "wafw00f" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: Directory/File Enumeration
    # ═══════════════════════════════════════════════════════════════
    log_info "Phase 4: Directory Enumeration"
    
    # Select wordlist based on custom parameter or robustness level
    local wordlist="${CUSTOM_WORDLIST:-${WORDLIST_DIRS_COMMON:-$BASE_DIR/wordlists/directories-fast.txt}}"
    if [[ -n "$CUSTOM_WORDLIST" && -f "$CUSTOM_WORDLIST" ]]; then
        wordlist="$CUSTOM_WORDLIST"
    elif [[ ${ROBUSTNESS_LEVEL:-3} -eq 4 ]] && [[ -n "$WORDLIST_DIRS_MEDIUM" ]] && [[ -f "$WORDLIST_DIRS_MEDIUM" ]]; then
        wordlist="$WORDLIST_DIRS_MEDIUM"
    elif [[ ${ROBUSTNESS_LEVEL:-3} -ge 5 ]] && [[ -n "$WORDLIST_DIRS_LARGE" ]] && [[ -f "$WORDLIST_DIRS_LARGE" ]]; then
        wordlist="$WORDLIST_DIRS_LARGE"
    fi
    log_info "Using wordlist: $(basename "$wordlist") ($(wc -l < "$wordlist" 2>/dev/null || echo 0) entries)"
    
    if tool_exists ffuf; then
        log_tool "ffuf" "start"
        
        local ffuf_opts="-mc 200,201,204,301,302,307,401,403,405 -t $threads -timeout $timeout -H \"User-Agent: $(get_random_user_agent)\""
        [[ -n "$CUSTOM_HEADERS" ]] && ffuf_opts="$ffuf_opts -H \"$CUSTOM_HEADERS\""
        [[ -n "$HTTP_PROXY" ]] && ffuf_opts="$ffuf_opts -x \"$HTTP_PROXY\""
        
        # Add recursion for higher levels
        [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]] && ffuf_opts="$ffuf_opts -recursion -recursion-depth 2"
        
        while IFS= read -r url; do
            local host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
            ffuf -u "$url/FUZZ" \
                 -w "$wordlist" \
                 $ffuf_opts \
                 -o "$OUT/ffuf_${host}.json" \
                 -of json 2>/dev/null &
        done < <(head -10 "$OUT/live.txt")
        wait
        
        # Combine results
        if command -v jq >/dev/null 2>&1; then
            cat "$OUT"/ffuf_*.json 2>/dev/null | jq -s 'add' > "$OUT/ffuf.json" 2>/dev/null
        elif command -v python3 >/dev/null 2>&1; then
            python3 -c '
import sys, json, glob
combined = {"results": []}
for f in glob.glob(sys.argv[1] + "/ffuf_*.json"):
    try:
        data = json.load(open(f))
        if isinstance(data, dict) and "results" in data:
            combined["results"].extend(data["results"])
    except Exception: pass
json.dump(combined, open(sys.argv[1] + "/ffuf.json", "w"))
' "$OUT" 2>/dev/null
        fi
        
        log_tool "ffuf" "success"
    elif tool_exists gobuster; then
        log_tool "gobuster" "start"
        
        while IFS= read -r url; do
            local host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
            gobuster dir -u "$url" -w "$wordlist" -t $threads \
                     -o "$OUT/gobuster_${host}.txt" 2>/dev/null &
        done < <(head -10 "$OUT/live.txt")
        wait
        
        log_tool "gobuster" "success"
    elif tool_exists dirsearch; then
        log_tool "dirsearch" "start"
        
        while IFS= read -r url; do
            dirsearch -u "$url" -w "$wordlist" -t $threads \
                      --format=json -o "$OUT/dirsearch.json" 2>/dev/null &
        done < <(head -10 "$OUT/live.txt")
        wait
        
        log_tool "dirsearch" "success"
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: Screenshot Capture (Level 4+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]]; then
        log_info "Phase 5: Screenshot Capture"
        
        mkdir -p "$OUT/screenshots"
        
        # gowitness
        if tool_exists gowitness; then
            log_tool "gowitness" "start"
            gowitness file -f "$OUT/live.txt" -P "$OUT/screenshots" --timeout 10 2>/dev/null
            log_tool "gowitness" "success"
        # aquatone
        elif tool_exists aquatone; then
            log_tool "aquatone" "start"
            cat "$OUT/live.txt" | aquatone -out "$OUT/screenshots" -threads $threads 2>/dev/null
            log_tool "aquatone" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: JavaScript Analysis (Level 4+)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]]; then
        log_info "Phase 6: JavaScript Analysis"
        
        # Extract JS files
        if tool_exists gau; then
            log_tool "gau-js" "start"
            echo "$target" | gau --subs | grep -iE "\.js$" | sort -u > "$OUT/js_files.txt" 2>/dev/null
            log_tool "gau-js" "success"
        fi
        
        # LinkFinder for endpoints
        if tool_exists linkfinder && [[ -s "$OUT/js_files.txt" ]]; then
            log_tool "linkfinder" "start"
            while IFS= read -r js_url; do
                python3 -m linkfinder -i "$js_url" -o cli >> "$OUT/js_endpoints.txt" 2>/dev/null
            done < <(head -20 "$OUT/js_files.txt")
            log_tool "linkfinder" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # PHASE 7: Parameter Discovery (Level 5)
    # ═══════════════════════════════════════════════════════════════
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 5 ]]; then
        log_info "Phase 7: Parameter Discovery"
        
        # Arjun
        if tool_exists arjun; then
            log_tool "arjun" "start"
            while IFS= read -r url; do
                arjun -u "$url" -oJ "$OUT/arjun_params.json" 2>/dev/null &
            done < <(head -10 "$OUT/live.txt")
            wait
            log_tool "arjun" "success"
        fi
        
        # ParamSpider
        if tool_exists paramspider; then
            log_tool "paramspider" "start"
            paramspider -d "$target" -o "$OUT/paramspider.txt" 2>/dev/null
            log_tool "paramspider" "success"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # Generate Summary
    # ═══════════════════════════════════════════════════════════════
    {
        echo "# Web Reconnaissance Summary"
        echo "Target: $target"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
        echo ""
        echo "## Live Hosts ($live_count)"
        echo ""
        cat "$OUT/live.txt" 2>/dev/null
        echo ""
        if [[ -f "$OUT/whatweb.txt" ]]; then
            echo "## Technologies Detected"
            echo ""
            head -30 "$OUT/whatweb.txt"
            echo ""
        fi
        if [[ -f "$OUT/ffuf.json" ]]; then
            echo "## Discovered Paths"
            echo ""
            if command -v jq >/dev/null 2>&1; then
                jq -r '.results[]? | "\(.status) - \(.url)"' "$OUT/ffuf.json" 2>/dev/null | head -50
            elif command -v python3 >/dev/null 2>&1; then
                python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    for r in d.get("results", [])[:50]:
        print(f"{r.get(\"status\")} - {r.get(\"url\")}")
except Exception: pass
' "$OUT/ffuf.json" 2>/dev/null
            fi
            echo ""
        fi
    } > "$OUT/summary.md"
    
    log_success "Web reconnaissance completed"
    log_info "Results saved to: $OUT/"
}
