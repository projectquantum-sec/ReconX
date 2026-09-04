#!/bin/bash

# ReconX Visual Reconnaissance & Screenshot Gallery Module
# Captures full-page screenshots of all live HTTP/HTTPS services using gowitness, aquatone, or Chrome headless.

modules_visual_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd "$modules_visual_dir/.." && pwd)}"

source "$BASE_DIR/utils/colors.sh"
source "$BASE_DIR/utils/logger.sh"
source "$BASE_DIR/utils/helpers.sh"

visual_module() {
    local domain=$1
    local OUT="${OUTPUT_BASE_DIR:-output}/$domain/visual"
    local WEB_OUT="${OUTPUT_BASE_DIR:-output}/$domain/web"
    local LIVE_FILE="$WEB_OUT/live.txt"
    
    mkdir -p "$OUT/screenshots" 2>/dev/null
    
    log_section "VISUAL RECONNAISSANCE & SCREENSHOTS: $domain"
    
    if [[ ! -f "$LIVE_FILE" ]] || [[ ! -s "$LIVE_FILE" ]]; then
        log_warn "No live web hosts found in $LIVE_FILE to screenshot. Skipping visual recon."
        return
    fi
    
    local host_count=$(wc -l < "$LIVE_FILE" 2>/dev/null || echo 0)
    log_info "Capturing visual screenshots for $host_count live endpoints..."
    
    # Method 1: gowitness (if available)
    if tool_exists gowitness; then
        log_tool "gowitness" "start"
        gowitness file -f "$LIVE_FILE" --screenshot-path "$OUT/screenshots" --threads 8 --timeout 15 2>/dev/null
        
    # Method 2: aquatone (if available)
    elif tool_exists aquatone; then
        log_tool "aquatone" "start"
        cat "$LIVE_FILE" | aquatone -out "$OUT" -threads 8 2>/dev/null
        
    # Method 3: Built-in Headless Chrome / Chromium (Zero external Go tool dependency)
    else
        local chrome_bin=""
        for bin in chromium google-chrome-stable google-chrome chromium-browser; do
            if command -v "$bin" >/dev/null 2>&1; then
                chrome_bin="$bin"
                break
            fi
        done
        
        if [[ -n "$chrome_bin" ]]; then
            log_info "Using built-in headless browser: $chrome_bin"
            local count=0
            while IFS= read -r target_url; do
                [[ -z "$target_url" ]] && continue
                ((count++))
                [[ $count -gt 50 ]] && break # Cap to 50 for performance
                
                local safe_name=$(echo "$target_url" | sed 's|https\?://||; s|/|_|g; s|:|_|g')
                local out_img="$OUT/screenshots/${safe_name}.png"
                
                "$chrome_bin" --headless --disable-gpu --no-sandbox --hide-scrollbars \
                    --window-size=1280,800 --screenshot="$out_img" "$target_url" 2>/dev/null &
                
                if (( count % 6 == 0 )); then
                    wait
                fi
            done < "$LIVE_FILE"
            wait
        else
            log_warn "Neither gowitness, aquatone, nor chromium-browser was found. Install chromium to enable screenshots."
        fi
    fi
    
    local shots_taken=$(ls -1 "$OUT/screenshots"/*.png 2>/dev/null | wc -l)
    log_success "Captured $shots_taken screenshots"
    log_info "Gallery images saved to: $OUT/screenshots/"
}
