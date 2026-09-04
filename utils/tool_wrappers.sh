#!/bin/bash

# Tool Wrappers - Custom wrappers for third-party tools
# Provides branded output and better control over tool execution

# ═══════════════════════════════════════════════════════════════
# theHarvester Wrapper - Hide original banner, show ReconX brand
# ═══════════════════════════════════════════════════════════════

run_theharvester_stealth() {
    local domain=$1
    local sources=$2
    local output_file=$3
    local api_config=$4
    
    # Custom ReconX branded header for theHarvester
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║                                                            ║${RESET}"
    echo -e "${CYAN}║         ReconX Email & Subdomain Discovery Module          ║${RESET}"
    echo -e "${CYAN}║                                                            ║${RESET}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
    echo -e "${GREEN}[*] Target Domain: ${RESET}$domain"
    echo -e "${GREEN}[*] Data Sources: ${RESET}$sources"
    echo -e ""
    
    # Create temporary file for output capture
    local temp_output=$(mktemp)
    
    # Run theHarvester and capture output
    theHarvester -d "$domain" \
                 -b "$sources" \
                 -f "$output_file" \
                 --api-config "$api_config" \
                 2>&1 | tee "$temp_output" | \
    while IFS= read -r line; do
        # Filter out theHarvester branding and banner
        if [[ ! "$line" =~ "theHarvester" ]] && \
           [[ ! "$line" =~ "Version" ]] && \
           [[ ! "$line" =~ "Coded by" ]] && \
           [[ ! "$line" =~ "Christian Martorella" ]] && \
           [[ ! "$line" =~ "Edge-Security" ]] && \
           [[ ! "$line" =~ "laramies" ]] && \
           [[ ! "$line" =~ "^\s*$" ]] && \
           [[ ! "$line" =~ "^\*{20,}" ]] && \
           [[ ! "$line" =~ "^-{20,}" ]]; then
            
            # Apply ReconX branding to useful output
            if [[ "$line" =~ "Found" ]] || [[ "$line" =~ "Searching" ]]; then
                echo -e "${YELLOW}[ReconX]${RESET} $line"
            elif [[ "$line" =~ "@" ]]; then
                echo -e "${GREEN}  [Email]${RESET} $line"
            elif [[ "$line" =~ "\." ]]; then
                echo -e "${BLUE}  [Host]${RESET} $line"
            else
                echo -e "${RESET}$line"
            fi
        fi
    done
    
    # Get exit status of theHarvester
    local exit_status=${PIPESTATUS[0]}
    
    # Clean up
    rm -f "$temp_output" 2>/dev/null
    
    echo ""
    
    return $exit_status
}

# ════════════════════════════════��══════════════════════════════
# Nuclei Wrapper - Add ReconX branding and progress tracking
# ═══════════════════════════════════════════════════════════════

run_nuclei_optimized() {
    local targets_file=$1
    local output_file=$2
    shift 2
    local extra_args=("$@")
    
    # Load Nuclei configuration from tools.conf
    local rate_limit=${NUCLEI_RATE_LIMIT:-300}
    local bulk_size=${NUCLEI_BULK_SIZE:-50}
    local concurrency=${NUCLEI_CONCURRENCY:-25}
    local timeout=${NUCLEI_TIMEOUT:-10}
    local exclude_tags=${NUCLEI_EXCLUDE_TAGS:-"dos,fuzz,intrusive"}
    
    echo -e "${CYAN}[ReconX Nuclei]${RESET} Starting optimized vulnerability scan..."
    echo -e "${GREEN}[*] Rate Limit: ${RESET}${rate_limit} req/s"
    echo -e "${GREEN}[*] Concurrency: ${RESET}${concurrency} templates"
    echo -e "${GREEN}[*] Bulk Size: ${RESET}${bulk_size}"
    
    # Run nuclei with optimized settings
    nuclei -l "$targets_file" \
           -rate-limit "$rate_limit" \
           -bulk-size "$bulk_size" \
           -c "$concurrency" \
           -timeout "$timeout" \
           -exclude-tags "$exclude_tags" \
           "${extra_args[@]}" \
           -jsonl \
           -o "$output_file" \
           2>&1 | \
    while IFS= read -r line; do
        # Filter and brand Nuclei output
        if [[ "$line" =~ "Templates loaded" ]]; then
            echo -e "${YELLOW}[ReconX]${RESET} $line"
        elif [[ "$line" =~ "\[" ]]; then
            echo -e "${GREEN}[Finding]${RESET} $line"
        fi
    done
    
    return ${PIPESTATUS[0]}
}

# ═══════════════════════════════════════════════════════════════
# Amass Wrapper - Suppress verbose output, show progress
# ═══════════════════════════════════════════════════════════════

run_amass_stealth() {
    local domain=$1
    local output_file=$2
    local timeout=${3:-30}
    
    echo -e "${CYAN}[ReconX Amass]${RESET} Deep passive enumeration in progress..."
    
    timeout "${timeout}m" amass enum -passive -d "$domain" -o "$output_file" 2>&1 | \
    grep -v "Average DNS queries" | \
    grep -v "Querying" | \
    while IFS= read -r line; do
        if [[ "$line" =~ "OWASP Amass" ]]; then
            # Skip Amass banner
            continue
        elif [[ ! -z "$line" ]]; then
            echo -e "${BLUE}  [Subdomain]${RESET} $line"
        fi
    done
    
    return ${PIPESTATUS[0]}
}

# ═══════════════════════════════════════════════════════════════
# Subfinder Wrapper - Enhanced output formatting
# ═══════════════════════════════════════════════════════════════

run_subfinder_stealth() {
    local domain=$1
    local output_file=$2
    local threads=${3:-50}
    
    echo -e "${CYAN}[ReconX Subfinder]${RESET} Fast subdomain enumeration..."
    
    subfinder -d "$domain" -silent -t "$threads" -o "$output_file" 2>&1
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    echo -e "${GREEN}[✓]${RESET} Found ${count} subdomains via Subfinder"
    
    return 0
}

# ═══════════════════════════════════════════════════════════════
# Nmap Wrapper - Clean output with progress
# ═══════════════════════════════════════════════════════════════

run_nmap_stealth() {
    local target=$1
    local output_file=$2
    shift 2
    local extra_args=("$@")
    
    echo -e "${CYAN}[ReconX Nmap]${RESET} Port scanning in progress..."
    
    nmap "${extra_args[@]}" "$target" -oN "$output_file" 2>&1 | \
    while IFS= read -r line; do
        if [[ "$line" =~ "Nmap scan report" ]]; then
            echo -e "${YELLOW}[*]${RESET} $line"
        elif [[ "$line" =~ "/tcp" ]] || [[ "$line" =~ "/udp" ]]; then
            echo -e "${GREEN}  [Port]${RESET} $line"
        elif [[ "$line" =~ "Host is up" ]]; then
            echo -e "${GREEN}[✓]${RESET} $line"
        fi
    done
    
    return ${PIPESTATUS[0]}
}

# ═══════════════════════════════════════════════════════════════
# WPScan Wrapper - Branded output
# ═══════════════════════════════════════════════════════════════

run_wpscan_stealth() {
    local url=$1
    local output_file=$2
    local api_token=${3:-}
    
    echo -e "${CYAN}[ReconX WPScan]${RESET} WordPress vulnerability scanning..."
    
    local opts="--url $url --enumerate vp,vt,u --random-user-agent --format json --output $output_file"
    [[ -n "$api_token" ]] && opts="$opts --api-token $api_token"
    
    wpscan $opts 2>&1 | \
    grep -v "_______________" | \
    grep -v "WordPress Security Scanner" | \
    while IFS= read -r line; do
        if [[ "$line" =~ "Vulnerability" ]]; then
            echo -e "${RED}  [Vuln]${RESET} $line"
        elif [[ "$line" =~ "Plugin" ]] || [[ "$line" =~ "Theme" ]]; then
            echo -e "${YELLOW}  [Component]${RESET} $line"
        fi
    done
    
    return ${PIPESTATUS[0]}
}

# ═══════════════════════════════════════════════════════════════
# Generic tool output filter
# ═══════════════════════════════════════════════════════════════

filter_tool_output() {
    local tool_name=$1
    
    while IFS= read -r line; do
        # Remove empty lines
        [[ -z "$line" ]] && continue
        
        # Remove common banner patterns
        [[ "$line" =~ "Version" ]] && continue
        [[ "$line" =~ "Author" ]] && continue
        [[ "$line" =~ "Coded by" ]] && continue
        [[ "$line" =~ "^\*{10,}" ]] && continue
        [[ "$line" =~ "^-{10,}" ]] && continue
        [[ "$line" =~ "^={10,}" ]] && continue
        
        # Show filtered output with ReconX prefix
        echo -e "${BLUE}[$tool_name]${RESET} $line"
    done
}