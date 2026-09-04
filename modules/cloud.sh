#!/bin/bash

# ReconX Cloud Assets, Buckets & DevOps Auditor Module
# Scans for misconfigured AWS S3, GCP, Azure Blob storage, Firebase DBs, and Spring Boot / CI interfaces.

modules_cloud_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd "$modules_cloud_dir/.." && pwd)}"

source "$BASE_DIR/utils/colors.sh"
source "$BASE_DIR/utils/logger.sh"
source "$BASE_DIR/utils/helpers.sh"

cloud_module() {
    local domain=$1
    local OUT="${OUTPUT_BASE_DIR:-output}/$domain/cloud"
    local WEB_OUT="${OUTPUT_BASE_DIR:-output}/$domain/web"
    mkdir -p "$OUT" 2>/dev/null
    
    log_section "CLOUD INFRASTRUCTURE & DEVOPS AUDIT: $domain"
    
    local company=$(echo "$domain" | cut -d'.' -f1)
    local REPORT="$OUT/cloud_audit_summary.md"
    
    {
        echo "# Cloud Infrastructure & DevOps Audit Report"
        echo "Target: $domain"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
    } > "$REPORT"
    
    # ═══════════════════════════════════════════════════════════════
    # 1. AWS S3 / GCP / Azure Storage Bucket Permutations
    # ═══════════════════════════════════════════════════════════════
    log_info "Auditing Cloud Storage Buckets (AWS S3, GCP, Azure)..."
    
    local bucket_names=(
        "$company"
        "$company-backup"
        "$company-data"
        "$company-assets"
        "$company-dev"
        "$company-prod"
        "$company-staging"
        "$company-media"
        "$company-public"
        "$company-internal"
        "$company-logs"
        "$(echo "$domain" | tr '.' '-')"
    )
    
    echo "## ☁️ Cloud Storage Buckets" >> "$REPORT"
    echo "" >> "$REPORT"
    
    for bucket in "${bucket_names[@]}"; do
        # AWS S3 Check
        local s3_url="https://${bucket}.s3.amazonaws.com"
        local s3_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$s3_url" 2>/dev/null)
        if [[ "$s3_code" == "200" ]]; then
            log_warn "OPEN S3 BUCKET DETECTED: $s3_url (Listing Allowed!)"
            echo "- 🔴 **CRITICAL**: AWS S3 Bucket [${bucket}](${s3_url}) is **PUBLICLY READABLE/LISTABLE** (HTTP 200)" >> "$REPORT"
        elif [[ "$s3_code" == "403" ]]; then
            echo "- 🟡 AWS S3 Bucket [${bucket}](${s3_url}) exists (Access Denied / Protected)" >> "$REPORT"
        fi
        
        # Google Cloud Storage Check
        local gcp_url="https://storage.googleapis.com/${bucket}"
        local gcp_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$gcp_url" 2>/dev/null)
        if [[ "$gcp_code" == "200" ]]; then
            log_warn "OPEN GCP STORAGE BUCKET: $gcp_url"
            echo "- 🔴 **CRITICAL**: GCP Bucket [${bucket}](${gcp_url}) is **PUBLICLY READABLE** (HTTP 200)" >> "$REPORT"
        elif [[ "$gcp_code" == "403" ]]; then
            echo "- 🟡 GCP Bucket [${bucket}](${gcp_url}) exists (Protected)" >> "$REPORT"
        fi
        
        # Azure Blob Storage Check
        local azure_url="https://${bucket}.blob.core.windows.net"
        local azure_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$azure_url" 2>/dev/null)
        if [[ "$azure_code" == "400" ]] || [[ "$azure_code" == "200" ]]; then
            echo "- 🟡 Azure Storage Account [${bucket}](${azure_url}) detected" >> "$REPORT"
        fi
    done
    
    # ═══════════════════════════════════════════════════════════════
    # 2. Firebase Database Misconfiguration Check
    # ═══════════════════════════════════════════════════════════════
    log_info "Testing Firebase Realtime Database instances..."
    echo "" >> "$REPORT"
    echo "## 🔥 Firebase Databases" >> "$REPORT"
    echo "" >> "$REPORT"
    
    local fb_urls=(
        "https://${company}.firebaseio.com/.json"
        "https://${company}-default-rtdb.firebaseio.com/.json"
        "https://${company}-dev.firebaseio.com/.json"
        "https://${company}-staging.firebaseio.com/.json"
    )
    
    for fb in "${fb_urls[@]}"; do
        local resp=$(curl -s --max-time 8 "$fb" 2>/dev/null)
        if [[ -n "$resp" ]] && [[ ! "$resp" =~ "Permission denied" ]] && [[ ! "$resp" =~ "error" ]] && [[ "$resp" != "null" ]]; then
            log_warn "OPEN FIREBASE DATABASE DETECTED: $fb"
            echo "- 🔴 **CRITICAL**: Firebase DB [${fb}](${fb}) is **EXPOSED TO PUBLIC READS**" >> "$REPORT"
        fi
    done
    
    # ═══════════════════════════════════════════════════════════════
    # 3. Spring Boot Actuators, Swagger & DevOps Endpoints
    # ═══════════════════════════════════════════════════════════════
    log_info "Probing for exposed Spring Boot Actuators & DevOps interfaces..."
    echo "" >> "$REPORT"
    echo "## ⚙️ DevOps, Actuators & Management Interfaces" >> "$REPORT"
    echo "" >> "$REPORT"
    
    local devops_paths=(
        "/actuator"
        "/actuator/env"
        "/actuator/heapdump"
        "/actuator/mappings"
        "/actuator/health"
        "/swagger-ui.html"
        "/v2/api-docs"
        "/v3/api-docs"
        "/openapi.json"
        "/metrics"
        "/healthz"
        "/phpinfo.php"
        "/server-status"
        "/.git/HEAD"
        "/.env"
    )
    
    local live_hosts="$WEB_OUT/live.txt"
    if [[ -f "$live_hosts" ]]; then
        while IFS= read -r host_url; do
            [[ -z "$host_url" ]] && continue
            for path in "${devops_paths[@]}"; do
                local target_endpoint="${host_url}${path}"
                local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "$target_endpoint" 2>/dev/null)
                if [[ "$status" == "200" ]]; then
                    log_warn "Exposed interface ($status): $target_endpoint"
                    echo "- ⚠️ **Exposed Interface**: \`$target_endpoint\` returned HTTP 200" >> "$REPORT"
                    echo "$target_endpoint" >> "$OUT/exposed_interfaces.txt"
                fi
            done
        done < <(head -10 "$live_hosts")
    fi
    
    log_success "Cloud & DevOps audit completed. Report saved to: $REPORT"
}
