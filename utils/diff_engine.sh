#!/bin/bash

# ReconX Asset Snapshot & Differential Engine
# Computes asset deltas (new subdomains, new ports, status transitions) between scans.

diff_engine_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd "$diff_engine_dir/.." && pwd)}"

source "$BASE_DIR/utils/colors.sh"
source "$BASE_DIR/utils/logger.sh"

run_diff_analysis() {
    local domain="$1"
    local TARGET_DIR="${OUTPUT_BASE_DIR:-output}/$domain"
    local HIST_DIR="$TARGET_DIR/history"
    local DIFF_DIR="$TARGET_DIR/diffs"
    local TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    
    mkdir -p "$HIST_DIR" "$DIFF_DIR" 2>/dev/null
    
    # 1. Check if a previous snapshot exists
    local latest_snap=$(ls -1t "$HIST_DIR"/snapshot_*.tar.gz 2>/dev/null | head -1)
    
    if [[ -z "$latest_snap" ]]; then
        log_info "No previous snapshot found for $domain. Saving initial baseline..."
        tar -czf "$HIST_DIR/snapshot_${TIMESTAMP}.tar.gz" -C "$TARGET_DIR" passive dns active web enum vuln 2>/dev/null || true
        log_success "Initial baseline snapshot saved to: $HIST_DIR/snapshot_${TIMESTAMP}.tar.gz"
        return
    fi
    
    log_section "DIFFERENTIAL ASSET ANALYSIS: $domain"
    log_info "Comparing against latest baseline: $(basename "$latest_snap")"
    
    # Extract baseline to temp directory
    local TMP_OLD=$(mktemp -d)
    tar -xzf "$latest_snap" -C "$TMP_OLD" 2>/dev/null
    
    local DIFF_REPORT="$DIFF_DIR/diff_${TIMESTAMP}.md"
    {
        echo "# 🔄 ReconX Differential Alert Report"
        echo "Target: **$domain**"
        echo "Scan Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Comparing Against Baseline: $(basename "$latest_snap")"
        echo ""
    } > "$DIFF_REPORT"
    
    local has_diffs=false
    
    # ═══════════════════════════════════════════════════════════════
    # Diff 1: New Subdomains
    # ═══════════════════════════════════════════════════════════════
    local old_subs="$TMP_OLD/passive/subdomains.txt"
    local new_subs="$TARGET_DIR/passive/subdomains.txt"
    
    if [[ -f "$new_subs" ]]; then
        local added_subs=$(comm -13 <(sort "$old_subs" 2>/dev/null) <(sort "$new_subs") 2>/dev/null)
        local count_new_subs=$(echo "$added_subs" | grep -v '^$' | wc -l)
        
        if [[ $count_new_subs -gt 0 ]]; then
            has_diffs=true
            log_warn "🚨 $count_new_subs NEW SUBDOMAINS DISCOVERED!"
            echo "## 🆕 New Subdomains ($count_new_subs)" >> "$DIFF_REPORT"
            echo '```text' >> "$DIFF_REPORT"
            echo "$added_subs" >> "$DIFF_REPORT"
            echo '```' >> "$DIFF_REPORT"
            echo "" >> "$DIFF_REPORT"
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════
    # Diff 2: New Open Ports
    # ═══════════════════════════════════════════════════════════════
    local old_ports="$TMP_OLD/active/ports_open.txt"
    local new_ports="$TARGET_DIR/active/ports_open.txt"
    
    if [[ -f "$new_ports" ]]; then
        local added_ports=$(comm -13 <(sort "$old_ports" 2>/dev/null) <(sort "$new_ports") 2>/dev/null)
        local count_new_ports=$(echo "$added_ports" | grep -v '^$' | wc -l)
        
        if [[ $count_new_ports -gt 0 ]]; then
            has_diffs=true
            log_warn "🚨 $count_new_ports NEW OPEN PORTS/SERVICES DETECTED!"
            echo "## 🚪 New Open Ports ($count_new_ports)" >> "$DIFF_REPORT"
            echo '```text' >> "$DIFF_REPORT"
            echo "$added_ports" >> "$DIFF_REPORT"
            echo '```' >> "$DIFF_REPORT"
            echo "" >> "$DIFF_REPORT"
        fi
    fi
    
    # Clean temporary baseline extraction
    rm -rf "$TMP_OLD"
    
    # Save current scan as new snapshot
    tar -czf "$HIST_DIR/snapshot_${TIMESTAMP}.tar.gz" -C "$TARGET_DIR" passive dns active web enum vuln 2>/dev/null || true
    
    if [[ "$has_diffs" == true ]]; then
        log_success "Differential analysis completed with findings! Report: $DIFF_REPORT"
        
        # Trigger webhook notifications if configured
        if type send_webhook_alert &>/dev/null; then
            send_webhook_alert "$domain" "$DIFF_REPORT"
        fi
    else
        log_info "No new asset deltas detected between scans."
        echo "No newly discovered assets or state changes detected." >> "$DIFF_REPORT"
    fi
}
