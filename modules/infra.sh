#!/bin/bash

# ReconX Infrastructure & ASN Mapping Module
# Resolves ASNs, CIDRs, reverse PTR lookups, and organization-level network assets.

modules_infra_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${BASE_DIR:-$(cd "$modules_infra_dir/.." && pwd)}"

source "$BASE_DIR/utils/colors.sh"
source "$BASE_DIR/utils/logger.sh"
source "$BASE_DIR/utils/helpers.sh"

# Resolve ASN to CIDR prefixes and metadata
resolve_asn() {
    local asn="$1"
    local OUT="${OUTPUT_BASE_DIR:-output}/ASN_${asn}/infra"
    mkdir -p "$OUT" 2>/dev/null

    # Normalize ASN format (strip AS prefix for queries if needed)
    local asn_clean=$(echo "$asn" | tr '[:lower:]' '[:upper:]')
    [[ ! "$asn_clean" =~ ^AS ]] && asn_clean="AS$asn_clean"
    local asn_num="${asn_clean#AS}"

    log_section "ASN INFRASTRUCTURE MAPPING: $asn_clean"
    log_info "Discovering IP prefixes and routes for $asn_clean..."

    # Method 1: whois RADB / Cymru lookup
    log_tool "whois-radb" "start"
    whois -h whois.radb.net -- "-i origin $asn_clean" 2>/dev/null \
        | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}" \
        | sort -u > "$OUT/prefixes_radb.txt"

    # Method 2: BGPView / HackerTarget API (free, zero-key)
    log_tool "bgpview-api" "start"
    curl -s --max-time 30 "https://api.bgpview.io/asn/$asn_num/prefixes" 2>/dev/null \
        | grep -Po '"prefix":"\K[^"]*' \
        | sort -u > "$OUT/prefixes_bgpview.txt"

    # Method 3: asnmap (if available)
    if tool_exists asnmap; then
        log_tool "asnmap" "start"
        asnmap -a "$asn_clean" -silent 2>/dev/null | sort -u > "$OUT/prefixes_asnmap.txt"
    fi

    # Consolidate all unique CIDR blocks
    cat "$OUT"/prefixes_*.txt 2>/dev/null | grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$" | sort -u > "$OUT/cidrs.txt"
    local cidr_count=$(wc -l < "$OUT/cidrs.txt" 2>/dev/null || echo 0)

    log_success "Found $cidr_count unique CIDR prefix blocks for $asn_clean"
    log_info "CIDRs saved to: $OUT/cidrs.txt"

    # Reverse PTR lookups across discovered CIDRs if requested
    if [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]] && [[ $cidr_count -gt 0 ]]; then
        expand_and_resolve_cidrs "$OUT/cidrs.txt" "$OUT"
    fi
}

# Expand CIDRs and resolve reverse PTR hostnames
expand_and_resolve_cidrs() {
    local cidr_file="$1"
    local OUT="$2"

    log_info "Resolving reverse PTR hostnames for discovered prefixes..."

    # If dnsx is available, use fast PTR scanning
    if tool_exists dnsx; then
        log_tool "dnsx-ptr" "start"
        dnsx -l "$cidr_file" -ptr -silent -resp -o "$OUT/ptr_resolved.txt" 2>/dev/null
        
        # Extract discovered hostnames
        awk '{print $NF}' "$OUT/ptr_resolved.txt" 2>/dev/null \
            | sed 's/\[//g; s/\]//g; s/\.$//' \
            | grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" \
            | sort -u > "$OUT/discovered_hostnames.txt"
        
        local host_count=$(wc -l < "$OUT/discovered_hostnames.txt" 2>/dev/null || echo 0)
        log_success "Discovered $host_count hostnames via reverse PTR lookup"
    elif tool_exists nmap; then
        log_tool "nmap-sL" "start"
        nmap -sL -n -iL "$cidr_file" 2>/dev/null \
            | grep -Po "Nmap scan report for \K[^\s]+" \
            | sort -u > "$OUT/discovered_hostnames.txt"
    fi
}

# Scan a single CIDR block
run_cidr_recon() {
    local cidr="$1"
    local safe_name=$(echo "$cidr" | tr '/' '_')
    local OUT="${OUTPUT_BASE_DIR:-output}/CIDR_${safe_name}/infra"
    mkdir -p "$OUT" 2>/dev/null

    log_section "CIDR BLOCK INFRASTRUCTURE: $cidr"
    echo "$cidr" > "$OUT/cidrs.txt"
    expand_and_resolve_cidrs "$OUT/cidrs.txt" "$OUT"
}

# Export module entrypoint
infra_module() {
    local target="$1"
    if [[ "$target" =~ ^AS[0-9]+$ ]] || [[ "$target" =~ ^[0-9]+$ ]]; then
        resolve_asn "$target"
    elif [[ "$target" =~ / ]]; then
        run_cidr_recon "$target"
    else
        log_info "No ASN/CIDR target specified for infra module. Skipping."
    fi
}
