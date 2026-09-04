#!/bin/bash

# Comprehensive Error Handling Module

# Safe curl wrapper with error handling
safe_curl() {
    local url=$1
    local output=$2
    local max_time=${3:-30}
    local retries=${4:-2}
    
    # Use curl's built-in retry mechanism for efficiency
    if curl -s --max-time "$max_time" --retry "$retries" --retry-delay 5 --retry-max-time 60 --fail "$url" -o "$output" 2>/dev/null; then
        return 0
    else
        log_error "Failed to fetch $url after $retries retries"
        return 1
    fi
}

# Safe command execution with timeout
safe_exec() {
    local cmd=$1
    local timeout=${2:-60}
    local description=${3:-"command"}
    
    if timeout "$timeout" bash -c "$cmd" 2>/dev/null; then
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_error "$description timed out after ${timeout}s"
        else
            log_error "$description failed with exit code $exit_code"
        fi
        return $exit_code
    fi
}

# Validate output file
validate_output() {
    local file=$1
    local min_size=${2:-0}
    
    if [[ ! -f "$file" ]]; then
        log_error "Output file not created: $file"
        return 1
    elif [[ ! -s "$file" ]]; then
        log_warn "Output file is empty: $file"
        return 2
    elif [[ -n "$min_size" ]] && [[ $min_size -gt 0 ]]; then
        # Get file size once and store it
        local file_size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)
        if [[ $file_size -lt $min_size ]]; then
            log_warn "Output file smaller than expected: $file (${file_size} bytes < ${min_size} bytes)"
            return 3
        fi
    fi
    
    return 0
}

# Check disk space before operations
check_disk_space() {
    local required_mb=${1:-100}
    local output_dir=${2:-"output"}
    
    local available=$(df -m "$output_dir" | tail -1 | awk '{print $4}')
    
    if [[ $available -lt $required_mb ]]; then
        log_error "Insufficient disk space. Required: ${required_mb}MB, Available: ${available}MB"
        return 1
    fi
    
    return 0
}

# Validate domain format
validate_domain() {
    local domain=$1
    
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Invalid domain format: $domain"
        return 1
    fi
    
    return 0
}

# Check network connectivity
check_connectivity() {
    local test_urls=("https://google.com" "https://cloudflare.com" "https://1.1.1.1")
    
    for url in "${test_urls[@]}"; do
        if curl -s --max-time 5 --head "$url" >/dev/null 2>&1; then
            return 0
        fi
    done
    
    log_error "No network connectivity detected"
    return 1
}
