#!/bin/bash

# ReconX JavaScript Analysis, Secret Extraction & SourceMap Module
# Analyzes gathered frontend JavaScript assets for API tokens, hardcoded credentials, and hidden endpoints.

modules_secrets_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd "$modules_secrets_dir/.." && pwd)}"

source "$BASE_DIR/utils/colors.sh"
source "$BASE_DIR/utils/logger.sh"
source "$BASE_DIR/utils/helpers.sh"

secrets_module() {
    local domain=$1
    local OUT="${OUTPUT_BASE_DIR:-output}/$domain/secrets"
    local WEB_OUT="${OUTPUT_BASE_DIR:-output}/$domain/web"
    local PASSIVE_OUT="${OUTPUT_BASE_DIR:-output}/$domain/passive"
    
    mkdir -p "$OUT/js_files" 2>/dev/null
    
    log_section "JAVASCRIPT ANALYSIS & SECRET HUNTING: $domain"
    
    # ═══════════════════════════════════════════════════════════════
    # 1. Harvest & Aggregate JS URLs
    # ═══════════════════════════════════════════════════════════════
    log_info "Collecting JavaScript URLs from web crawlers & passive logs..."
    
    local js_sources=(
        "$WEB_OUT/katana.txt"
        "$WEB_OUT/gau.txt"
        "$WEB_OUT/wayback.txt"
        "$PASSIVE_OUT/urls.txt"
    )
    
    cat "${js_sources[@]}" 2>/dev/null \
        | grep -Ei '\.js(\?|$)' \
        | grep -Ev '\.json(\?|$)' \
        | grep -Ev '(jquery|bootstrap|google-analytics|gtag|recaptcha|cloudflare)' \
        | sort -u > "$OUT/js_urls.txt"
    
    local js_count=$(wc -l < "$OUT/js_urls.txt" 2>/dev/null || echo 0)
    log_info "Found $js_count unique target JavaScript files"
    
    if [[ $js_count -eq 0 ]]; then
        log_warn "No JavaScript files found. Creating placeholder."
        touch "$OUT/findings_summary.txt"
        return
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # 2. Download and Unminify JS Files (Top 50 or full based on level)
    # ═══════════════════════════════════════════════════════════════
    local max_download=50
    [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]] && max_download=200
    [[ ${ROBUSTNESS_LEVEL:-3} -ge 5 ]] && max_download=1000
    
    log_info "Downloading up to $max_download JavaScript files for deep static analysis..."
    
    local dl_count=0
    while IFS= read -r js_url; do
        [[ -z "$js_url" ]] && continue
        ((dl_count++))
        [[ $dl_count -gt $max_download ]] && break
        
        local fname="js_$(echo "$js_url" | md5sum | cut -d' ' -f1).js"
        curl -s --max-time 15 -H "User-Agent: $(get_random_user_agent)" "$js_url" -o "$OUT/js_files/$fname" 2>/dev/null &
        
        # Concurrency limit
        if (( dl_count % 15 == 0 )); then
            wait
        fi
    done < "$OUT/js_urls.txt"
    wait
    
    # ═══════════════════════════════════════════════════════════════
    # 3. Source Map (.js.map) Detection & Extraction
    # ═══════════════════════════════════════════════════════════════
    log_info "Checking for exposed JavaScript Source Maps (.js.map)..."
    while IFS= read -r js_url; do
        [[ -z "$js_url" ]] && continue
        local clean_url=$(echo "$js_url" | cut -d'?' -f1)
        local map_url="${clean_url}.map"
        
        # Test if map file exists
        local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$map_url" 2>/dev/null)
        if [[ "$status" == "200" ]]; then
            echo "$map_url" >> "$OUT/sourcemaps.txt"
            log_success "Discovered accessible SourceMap: $map_url"
        fi
    done < <(head -50 "$OUT/js_urls.txt")
    
    # ═══════════════════════════════════════════════════════════════
    # 4. Pattern-Based Hardcoded Secret Hunting
    # ═══════════════════════════════════════════════════════════════
    log_info "Executing regex secret scanners across downloaded JS bundles..."
    
    local REPORT="$OUT/findings_summary.txt"
    {
        echo "# JavaScript Secret & Endpoint Analysis Report"
        echo "Target: $domain"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Analyzed JS Files: $(ls -1 "$OUT/js_files" 2>/dev/null | wc -l)"
        echo ""
        echo "## 🔑 Discovered Hardcoded Secrets & Tokens"
        echo ""
    } > "$REPORT"
    
    scan_regex() {
        local name="$1"
        local pattern="$2"
        local matches=$(grep -rhoE "$pattern" "$OUT/js_files/" 2>/dev/null | sort -u | head -20)
        if [[ -n "$matches" ]]; then
            log_warn "Potential Secret Found: $name"
            echo "### $name" >> "$REPORT"
            echo '```text' >> "$REPORT"
            echo "$matches" >> "$REPORT"
            echo '```' >> "$REPORT"
            echo "" >> "$REPORT"
        fi
    }
    
    # Secret Signatures
    scan_regex "AWS Access Key ID" "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    scan_regex "AWS Secret Access Key" "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]"
    scan_regex "Google API Key" "AIza[0-9A-Za-z\\-_]{35}"
    scan_regex "Google OAuth Access Token" "ya29\\.[0-9A-Za-z\\-_]+"
    scan_regex "Firebase Database URL" "https:\/\/[a-z0-9-]+\.firebaseio\.com"
    scan_regex "Stripe Standard / Restricted API Key" "(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,34}"
    scan_regex "Stripe Publishable Key" "pk_(?:test|live)_[0-9a-zA-Z]{24,34}"
    scan_regex "GitHub Personal Access Token" "ghp_[0-9a-zA-Z]{36}"
    scan_regex "Slack Incoming Webhook" "https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}"
    scan_regex "JSON Web Token (JWT)" "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    scan_regex "Private RSA/EC/OpenSSH Key" "-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"
    scan_regex "Generic API Key Assignment" "(?i)(api_key|apikey|secret_key|app_secret|auth_token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,64}['\"]"
    
    # ═══════════════════════════════════════════════════════════════
    # 5. Extract Hidden Endpoints & Paths from JS
    # ═══════════════════════════════════════════════════════════════
    log_info "Extracting hidden internal routes and API paths..."
    
    grep -rhoE "(['\"])(\/api\/[a-zA-Z0-9_\-\/]+|\/v[0-9]\/[a-zA-Z0-9_\-\/]+|\/admin\/[a-zA-Z0-9_\-\/]+)\1" "$OUT/js_files/" 2>/dev/null \
        | tr -d "'\"" \
        | sort -u > "$OUT/extracted_endpoints.txt"
    
    local ep_count=$(wc -l < "$OUT/extracted_endpoints.txt" 2>/dev/null || echo 0)
    log_success "Extracted $ep_count internal API paths from JS bundles"
    
    echo "## 🛣️ Discovered Internal API Endpoints ($ep_count)" >> "$REPORT"
    echo '```text' >> "$REPORT"
    head -50 "$OUT/extracted_endpoints.txt" >> "$REPORT" 2>/dev/null
    echo '```' >> "$REPORT"
    
    log_success "JavaScript analysis completed. Summary saved to: $REPORT"
}
