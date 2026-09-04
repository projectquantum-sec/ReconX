#!/bin/bash

# Enhanced Logging System with daily logs and timestamps
# Log levels: DEBUG, INFO, WARN, ERROR, SUCCESS

# Colors for log levels
LOG_RED="\e[31m"
LOG_GREEN="\e[32m"
LOG_YELLOW="\e[33m"
LOG_BLUE="\e[34m"
LOG_CYAN="\e[36m"
LOG_RESET="\e[0m"
LOG_BOLD="\e[1m"

# Initialize logging system
init_logging() {
    local base_dir="${1:-$BASE_DIR}"
    local target="${2:-general}"
    
    # Create daily log directory
    LOG_DATE=$(date '+%Y-%m-%d')
    LOG_TIME=$(date '+%H-%M-%S')
    LOG_DIR="${base_dir}/logs/${LOG_DATE}"
    mkdir -p "$LOG_DIR"
    
    # Create session-specific log file with timestamp
    SESSION_LOG="${LOG_DIR}/reconx_${LOG_TIME}_${target}.log"
    MAIN_LOG="${LOG_DIR}/reconx_${LOG_DATE}.log"
    
    # Export for use in other modules
    export LOG_DIR SESSION_LOG MAIN_LOG LOG_DATE LOG_TIME
    
    # Write log header
    {
        echo "=============================================="
        echo "ReconX Session Log"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "Target: $target"
        echo "Robustness Level: ${ROBUSTNESS_LEVEL:-3}"
        echo "=============================================="
        echo ""
    } >> "$SESSION_LOG"
    
    log_info "Logging initialized - Session: $SESSION_LOG"
}

# Ensure logging is initialized (safe to call multiple times)
ensure_logging() {
    # Skip if already initialized
    [[ -n "$SESSION_LOG" ]] && [[ -f "$SESSION_LOG" ]] && return 0
    
    # If we have BASE_DIR and TARGET, do full initialization
    if [[ -n "$BASE_DIR" ]] && [[ -n "$TARGET" ]]; then
        init_logging "$BASE_DIR" "$TARGET"
        return 0
    fi
    
    # Otherwise, do minimal initialization
    local fallback_dir="${BASE_DIR:-$(pwd)}/logs"
    mkdir -p "$fallback_dir" 2>/dev/null || {
        fallback_dir="/tmp/reconx-logs"
        mkdir -p "$fallback_dir"
    }
    
    local timestamp_file=$(date '+%Y%m%d_%H%M%S')
    SESSION_LOG="$fallback_dir/reconx_${timestamp_file}.log"
    MAIN_LOG="$fallback_dir/reconx.log"
    
    export SESSION_LOG MAIN_LOG
    
    # Write minimal header
    {
        echo "=============================================="
        echo "ReconX Session Log"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "=============================================="
        echo ""
    } >> "$SESSION_LOG" 2>/dev/null
    
    return 0
}

# Get formatted timestamp
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S.%3N'
}

# Core logging function
_log() {
    local level="$1"
    local message="$2"
    local color="$3"
    local timestamp=$(get_timestamp)
    
    # Auto-initialize logging if not already done
    if [[ -z "$SESSION_LOG" ]] || [[ -z "$MAIN_LOG" ]]; then
        # Create basic logs directory relative to BASE_DIR
        local fallback_dir="${BASE_DIR:-$(pwd)}/logs"
        mkdir -p "$fallback_dir" 2>/dev/null || {
            # If mkdir fails, use /tmp as last resort
            fallback_dir="/tmp/reconx-logs"
            mkdir -p "$fallback_dir"
        }
        
        # Set fallback log files
        local timestamp_file=$(date '+%Y%m%d_%H%M%S')
        SESSION_LOG="$fallback_dir/reconx_${timestamp_file}.log"
        MAIN_LOG="$fallback_dir/reconx.log"
        
        export SESSION_LOG MAIN_LOG
    fi
    
    # Format: [TIMESTAMP] [LEVEL] Message
    local log_entry="[$timestamp] [$level] $message"
    
    # Write to session log (plain text)
    echo "$log_entry" >> "$SESSION_LOG" 2>/dev/null
    
    # Write to daily main log
    echo "$log_entry" >> "$MAIN_LOG" 2>/dev/null
    
    # Print to console with colors
    echo -e "${color}${LOG_BOLD}[$level]${LOG_RESET} ${color}$message${LOG_RESET}"
}

# Log level functions
log_debug() {
    [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]] && _log "DEBUG" "$1" "$LOG_CYAN"
}

log_info() {
    _log "INFO" "$1" "$LOG_BLUE"
}

log_warn() {
    _log "WARN" "$1" "$LOG_YELLOW"
}

log_error() {
    _log "ERROR" "$1" "$LOG_RED"
}

log_success() {
    _log "SUCCESS" "$1" "$LOG_GREEN"
}

# Legacy log function for backward compatibility
log() {
    log_info "$1"
}

# Log section header
log_section() {
    local section="$1"
    local timestamp=$(get_timestamp)
    local separator="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Auto-initialize logging if not already done
    if [[ -z "$SESSION_LOG" ]] || [[ -z "$MAIN_LOG" ]]; then
        local fallback_dir="${BASE_DIR:-$(pwd)}/logs"
        mkdir -p "$fallback_dir" 2>/dev/null || {
            fallback_dir="/tmp/reconx-logs"
            mkdir -p "$fallback_dir"
        }
        
        local timestamp_file=$(date '+%Y%m%d_%H%M%S')
        SESSION_LOG="$fallback_dir/reconx_${timestamp_file}.log"
        MAIN_LOG="$fallback_dir/reconx.log"
        
        export SESSION_LOG MAIN_LOG
    fi
    
    echo "" >> "$SESSION_LOG" 2>/dev/null
    echo "[$timestamp] $separator" >> "$SESSION_LOG" 2>/dev/null
    echo "[$timestamp] ▶ $section" >> "$SESSION_LOG" 2>/dev/null
    echo "[$timestamp] $separator" >> "$SESSION_LOG" 2>/dev/null
    
    echo -e "\n${LOG_BOLD}${LOG_CYAN}$separator${LOG_RESET}"
    echo -e "${LOG_BOLD}${LOG_CYAN}▶ $section${LOG_RESET}"
    echo -e "${LOG_BOLD}${LOG_CYAN}$separator${LOG_RESET}\n"
}

# Log tool execution
log_tool() {
    local tool="$1"
    local status="$2"
    local details="${3:-}"
    
    case "$status" in
        "start")
            log_info "Starting tool: $tool ${details:+- $details}"
            ;;
        "success")
            log_success "Tool completed: $tool ${details:+- $details}"
            ;;
        "fail")
            log_error "Tool failed: $tool ${details:+- $details}"
            ;;
        "skip")
            log_warn "Tool skipped: $tool ${details:+- $details}"
            ;;
    esac
}

# Log scan progress
log_progress() {
    local current="$1"
    local total="$2"
    local task="$3"
    local percent=$((current * 100 / total))
    
    log_info "Progress: [$current/$total] ($percent%) - $task"
}

# Rotate old logs (keep last 30 days)
rotate_logs() {
    local log_base="${1:-logs}"
    local keep_days="${2:-30}"
    
    find "$log_base" -type d -mtime +$keep_days -exec rm -rf {} \; 2>/dev/null
    log_info "Log rotation completed - removed logs older than $keep_days days"
}

# Export log summary
export_log_summary() {
    local output_file="$1"
    local session_log="${SESSION_LOG:-logs/reconx.log}"
    
    {
        echo "# ReconX Log Summary"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "## Errors"
        grep -c "\[ERROR\]" "$session_log" 2>/dev/null || true
        echo ""
        echo "## Warnings"
        grep -c "\[WARN\]" "$session_log" 2>/dev/null || true
        echo ""
        echo "## Successful Operations"
        grep -c "\[SUCCESS\]" "$session_log" 2>/dev/null || true
    } > "$output_file"
}

# Progress bar function
show_progress() {
    local current=$1
    local total=$2
    local task=$3
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))
    
    printf "\r${LOG_BLUE}[%-50s] %3d%% ${LOG_RESET}%s" \
           "$(printf '#%.0s' $(seq 1 $filled))$(printf ' %.0s' $(seq 1 $empty))" \
           "$percent" \
           "$task"
    
    [[ $current -eq $total ]] && echo ""
}

# Spinner for long operations
show_spinner() {
    local pid=$1
    local message=$2
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "\r${LOG_BLUE}%c${LOG_RESET} %s" "$spinstr" "$message"
        spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
    done
    printf "\r${LOG_GREEN}✓${LOG_RESET} %s\n" "$message"
}
