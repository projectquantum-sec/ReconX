#!/bin/bash

# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                           ReconX v2.0                                      ║
# ║              Unified Reconnaissance Framework                              ║
# ║                                                                            ║
# ║  Features:                                                                 ║
# ║  - Robustness levels 1-5 for scan intensity                               ║
# ║  - Enhanced logging with daily logs and timestamps                        ║
# ║  - Multiple export formats (MD, HTML, JSON, CSV, PDF)                     ║
# ║  - Interactive menu system                                                 ║
# ║  - Bug bounty safe mode                                                    ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

# Ensure Go binary directory and local bin are prioritized in PATH
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"

# Canonical resolution of BASE_DIR even when invoked via symlink (e.g., ~/.local/bin/reconx)
PRG="${BASH_SOURCE[0]:-$0}"
while [ -h "$PRG" ]; do
    DIR="$( cd -P "$( dirname "$PRG" )" >/dev/null 2>&1 && pwd )"
    PRG="$(readlink "$PRG")"
    [[ $PRG != /* ]] && PRG="$DIR/$PRG"
done
BASE_DIR="$( cd -P "$( dirname "$PRG" )" >/dev/null 2>&1 && pwd )"
export BASE_DIR

# Default settings
MODE="normal"
ROBUSTNESS_LEVEL=3
INTERACTIVE=false
EXPORT_FORMAT="md"
RESUME_SCAN=false
EXCLUDE_TARGETS=""

# Process cleanup trap
cleanup_all() {
    echo -e "\n${RED}[!] Scan interrupted by user. Cleaning up background tasks...${RESET}"
    kill 0 2>/dev/null || true
    exit 130
}
trap cleanup_all SIGINT SIGTERM

# Source utilities
source "$BASE_DIR/utils/colors.sh"
source "$BASE_DIR/utils/logger.sh"
source "$BASE_DIR/utils/helpers.sh"
source "$BASE_DIR/utils/banner.sh"
source "$BASE_DIR/utils/menu.sh"

# Source new utilities (only if files exist to avoid errors on fresh installs)
[[ -f "$BASE_DIR/utils/error_handler.sh" ]] && source "$BASE_DIR/utils/error_handler.sh"
[[ -f "$BASE_DIR/utils/api_validator.sh" ]] && source "$BASE_DIR/utils/api_validator.sh"
[[ -f "$BASE_DIR/utils/config_wizard.sh" ]] && source "$BASE_DIR/utils/config_wizard.sh"
[[ -f "$BASE_DIR/utils/diff_engine.sh" ]] && source "$BASE_DIR/utils/diff_engine.sh"
[[ -f "$BASE_DIR/utils/notifier.sh" ]] && source "$BASE_DIR/utils/notifier.sh"

# Source modules
source "$BASE_DIR/modules/passive.sh"
source "$BASE_DIR/modules/dns.sh"
source "$BASE_DIR/modules/active.sh"
source "$BASE_DIR/modules/web.sh"
source "$BASE_DIR/modules/enum.sh"
source "$BASE_DIR/modules/vuln.sh"
source "$BASE_DIR/modules/report.sh"
[[ -f "$BASE_DIR/modules/infra.sh" ]] && source "$BASE_DIR/modules/infra.sh"
[[ -f "$BASE_DIR/modules/secrets.sh" ]] && source "$BASE_DIR/modules/secrets.sh"
[[ -f "$BASE_DIR/modules/cloud.sh" ]] && source "$BASE_DIR/modules/cloud.sh"
[[ -f "$BASE_DIR/modules/visual.sh" ]] && source "$BASE_DIR/modules/visual.sh"

# Load configuration files
[[ -f "$BASE_DIR/config/reconx.conf" ]] && source "$BASE_DIR/config/reconx.conf"
[[ -f "$BASE_DIR/config/tools.conf" ]] && source "$BASE_DIR/config/tools.conf"
[[ -f "$BASE_DIR/config/wordlists.conf" ]] && source "$BASE_DIR/config/wordlists.conf"

# Version
VERSION="2.1.0"

# Usage/Help
usage() {
    echo -e "${CYAN}"
    cat << 'EOF'
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
EOF
    echo -e "${RESET}"
    echo -e "${YELLOW}ReconX v${VERSION} - Unified Reconnaissance Framework${RESET}"
    echo ""
    echo -e "${GREEN}Usage:${RESET}"
    echo "  ./reconx.sh [OPTIONS]"
    echo ""
    echo -e "${GREEN}Target Options:${RESET}"
    echo "  -t, --target <domain>     Target domain to scan"
    echo "  --exclude <list/file>     Exclude subdomains/IPs from scanning"
    echo ""
    echo -e "${GREEN}Scan Modules:${RESET}"
    echo "  --passive                 Run passive reconnaissance"
    echo "  --dns                     Run DNS reconnaissance"
    echo "  --active                  Run active reconnaissance (port scanning)"
    echo "  --web                     Run web reconnaissance"
    echo "  --enum                    Run service enumeration"
    echo "  --vuln                    Run vulnerability scanning"
    echo "  --full                    Run all modules"
    echo ""
    echo -e "${GREEN}Scan Options & Controls:${RESET}"
    echo "  -w, --wordlist <file>     Custom wordlist for DNS & web fuzzing"
    echo "  -o, --output <dir>        Custom output directory (Default: output/)"
    echo "  --threads <num>           Set worker threads count"
    echo "  --rate-limit <rps>        Set global request rate limit (req/sec)"
    echo ""
    echo -e "${GREEN}Robustness Level (1-5):${RESET}"
    echo "  -r, --robustness <1-5>    Set scan intensity level"
    echo "                            1 = Quick (minimal tools, fastest)"
    echo "                            2 = Light (basic tools)"
    echo "                            3 = Normal (balanced, default)"
    echo "                            4 = Thorough (more tools, deeper)"
    echo "                            5 = Aggressive (all tools, maximum depth)"
    echo ""
    echo -e "${GREEN}Mode & OPSEC Options:${RESET}"
    echo "  --bb, --bugbounty         Bug bounty safe mode (rate limited)"
    echo "  -i, --interactive         Launch interactive menu"
    echo "  --proxy <url>             Route traffic through HTTP/SOCKS5 proxy"
    echo "  -H, --header <header>     Add custom identification header (e.g., 'X-Bug-Bounty: user')"
    echo "  --resume                  Resume previously interrupted scan"
    echo ""
    echo -e "${GREEN}Report Options:${RESET}"
    echo "  --report                  Generate report"
    echo "  --export <format>         Export format: md, html, json, csv, pdf, all"
    echo ""
    echo -e "${GREEN}Other Options:${RESET}"
    echo "  -v, --version             Show version"
    echo "  -h, --help                Show this help message"
    echo "  --debug                   Enable debug logging"
    echo "  --config-wizard           Run interactive API configuration wizard"
    echo "  --validate-keys           Validate configured API keys"
    echo ""
    echo -e "${GREEN}Examples:${RESET}"
    echo "  ./reconx.sh -t example.com --full"
    echo "  ./reconx.sh -t example.com --web -w /path/to/wordlist.txt -r 4"
    echo "  ./reconx.sh -t example.com --passive --dns -r 4"
    echo "  ./reconx.sh -t example.com --vuln --bb -H 'X-Bug-Bounty: hacker1'"
    echo "  ./reconx.sh -t example.com --report --export html,json,csv"
    echo "  ./reconx.sh -i"
    echo ""
    exit 0
}

# Version display
show_version() {
    echo "ReconX v${VERSION}"
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target|-d|--domain)
                TARGET="$2"
                shift 2
                ;;
            --exclude)
                EXCLUDE_TARGETS="$2"
                export EXCLUDE_TARGETS
                shift 2
                ;;
            --proxy)
                HTTP_PROXY="$2"
                export HTTP_PROXY
                shift 2
                ;;
            -H|--header)
                CUSTOM_HEADERS="$2"
                export CUSTOM_HEADERS
                shift 2
                ;;
            -w|--wordlist)
                CUSTOM_WORDLIST="$2"
                export CUSTOM_WORDLIST
                shift 2
                ;;
            -o|--output)
                OUTPUT_BASE_DIR="$2"
                export OUTPUT_BASE_DIR
                shift 2
                ;;
            --threads)
                THREADS="$2"
                export THREADS
                shift 2
                ;;
            --rate-limit)
                RATE_LIMIT="$2"
                export RATE_LIMIT
                shift 2
                ;;
            --resume)
                RESUME_SCAN=true
                shift
                ;;
            -r|--robustness)
                if [[ "$2" =~ ^[1-5]$ ]]; then
                    ROBUSTNESS_LEVEL="$2"
                else
                    echo -e "${RED}Error: Robustness level must be between 1 and 5${RESET}"
                    exit 1
                fi
                shift 2
                ;;
            --passive)
                RUN_PASSIVE=true
                shift
                ;;
            --dns)
                RUN_DNS=true
                shift
                ;;
            --active)
                RUN_ACTIVE=true
                shift
                ;;
            --web)
                RUN_WEB=true
                shift
                ;;
            --enum)
                RUN_ENUM=true
                shift
                ;;
            --vuln)
                RUN_VULN=true
                shift
                ;;
            --report)
                RUN_REPORT=true
                shift
                ;;
            --full)
                RUN_FULL=true
                shift
                ;;
            --bb|--bugbounty)
                MODE="bugbounty"
                shift
                ;;
            -l|--list)
                TARGET_LIST="$2"
                export TARGET_LIST
                shift 2
                ;;
            --asn)
                TARGET_ASN="$2"
                export TARGET_ASN
                shift 2
                ;;
            --cidr)
                TARGET_CIDR="$2"
                export TARGET_CIDR
                shift 2
                ;;
            --secrets)
                RUN_SECRETS=true
                shift
                ;;
            --cloud)
                RUN_CLOUD=true
                shift
                ;;
            --visual)
                RUN_VISUAL=true
                shift
                ;;
            --diff)
                RUN_DIFF=true
                shift
                ;;
            --serve)
                SERVE_PORT="${2:-8000}"
                if [[ "$SERVE_PORT" =~ ^[0-9]+$ ]]; then
                    shift 2
                else
                    SERVE_PORT=8000
                    shift
                fi
                echo -e "${GREEN}[*] Launching ReconX Web Dashboard on port $SERVE_PORT...${RESET}"
                python3 "$BASE_DIR/web/server.py" "$SERVE_PORT"
                exit 0
                ;;
            --debug)
                LOG_LEVEL="DEBUG"
                export LOG_LEVEL
                shift
                ;;
            --config-wizard)
                if type config_wizard &>/dev/null; then
                    config_wizard
                else
                    echo -e "${RED}Error: Configuration wizard not available${RESET}"
                fi
                exit 0
                ;;
            --validate-keys)
                if type validate_all_keys &>/dev/null; then
                    validate_all_keys
                else
                    echo -e "${RED}Error: API validator not available${RESET}"
                fi
                exit 0
                ;;
            -v|--version)
                show_version
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo -e "${RED}Unknown option: $1${RESET}"
                usage
                ;;
        esac
    done
}

# Normalize target URL, IP, or domain
normalize_target() {
    local raw="$TARGET"
    
    # Extract scheme
    TARGET_SCHEME=""
    if [[ "$raw" =~ ^https:// ]]; then
        TARGET_SCHEME="https"
    elif [[ "$raw" =~ ^http:// ]]; then
        TARGET_SCHEME="http"
    fi
    
    # Strip scheme, trailing slashes, and path
    local no_scheme="${raw#*://}"
    local host_port="${no_scheme%%/*}"
    
    TARGET_PORT=""
    if [[ "$host_port" =~ :([0-9]+)$ ]]; then
        TARGET_PORT="${BASH_REMATCH[1]}"
        TARGET_HOST="${host_port%:*}"
    else
        TARGET_HOST="$host_port"
        [[ "$TARGET_SCHEME" == "https" ]] && TARGET_PORT="443"
        [[ "$TARGET_SCHEME" == "http" ]] && TARGET_PORT="80"
    fi
    
    # Filesystem safe directory name (no slashes, no colons)
    TARGET_SAFE="$(echo "$host_port" | tr ':' '_')"
    
    # Canonical base URL
    if [[ -n "$TARGET_SCHEME" ]]; then
        if [[ -n "$TARGET_PORT" ]] && [[ "$TARGET_PORT" != "80" ]] && [[ "$TARGET_PORT" != "443" ]]; then
            TARGET_URL="${TARGET_SCHEME}://${TARGET_HOST}:${TARGET_PORT}"
        else
            TARGET_URL="${TARGET_SCHEME}://${TARGET_HOST}"
        fi
    elif [[ -n "$TARGET_PORT" ]] && [[ "$TARGET_PORT" != "80" ]] && [[ "$TARGET_PORT" != "443" ]]; then
        TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"
    else
        TARGET_URL=""
    fi
    
    # Reassign TARGET to filesystem-safe name for directory operations
    TARGET_ORIGINAL="$TARGET"
    TARGET="$TARGET_SAFE"
    export TARGET TARGET_ORIGINAL TARGET_SAFE TARGET_HOST TARGET_PORT TARGET_SCHEME TARGET_URL
}

# Validate target
validate_target() {
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}Error: No target specified${RESET}"
        echo "Use -t <domain> to specify a target or -i for interactive mode"
        exit 1
    fi
    normalize_target
}

# Checkpoint state helpers
mark_checkpoint() {
    local mod=$1
    local state_file="output/$TARGET/.reconx_state"
    echo "$mod" >> "$state_file"
    sort -u "$state_file" -o "$state_file" 2>/dev/null || true
}

is_checkpoint_done() {
    local mod=$1
    local state_file="output/$TARGET/.reconx_state"
    [[ "$RESUME_SCAN" == true ]] && [[ -f "$state_file" ]] && grep -Fxq "$mod" "$state_file" 2>/dev/null
}

# Initialize scan environment
init_scan() {
    local target_out="${OUTPUT_BASE_DIR:-output}/$TARGET"
    
    # Create output directories
    mkdir -p "$target_out"/{passive,dns,active,web,enum,vuln,reports} 2>/dev/null
    
    # Create logs directory at BASE_DIR level
    mkdir -p "$BASE_DIR/logs" 2>/dev/null
    
    # Initialize logging (this must come BEFORE any log calls)
    init_logging "$BASE_DIR" "$TARGET"
    
    # Export variables
    export TARGET MODE ROBUSTNESS_LEVEL SESSION_LOG MAIN_LOG EXCLUDE_TARGETS HTTP_PROXY CUSTOM_HEADERS CUSTOM_WORDLIST THREADS RATE_LIMIT
    
    # Log scan start
    log_section "SCAN INITIALIZATION"
    log_info "Target: $TARGET"
    log_info "Mode: $MODE"
    log_info "Robustness Level: $ROBUSTNESS_LEVEL"
    [[ -n "$CUSTOM_WORDLIST" ]] && log_info "Custom Wordlist: $CUSTOM_WORDLIST"
    [[ -n "$THREADS" ]] && log_info "Threads: $THREADS"
    [[ -n "$RATE_LIMIT" ]] && log_info "Rate Limit: $RATE_LIMIT rps"
    [[ -n "$HTTP_PROXY" ]] && log_info "Proxy: $HTTP_PROXY"
    [[ -n "$EXCLUDE_TARGETS" ]] && log_info "Excluded Targets: $EXCLUDE_TARGETS"
    log_info "Output Directory: $target_out"
    log_info "Log file: $SESSION_LOG"
}

# Run selected modules
run_modules() {
    local start_time=$(date +%s)
    
    run_step() {
        local name="$1"
        local func="$2"
        if is_checkpoint_done "$name"; then
            log_info "Skipping $name (already completed in previous scan)"
        else
            $func "$TARGET"
            mark_checkpoint "$name"
        fi
    }
    
    if [[ "$RUN_FULL" == true ]]; then
        log_section "FULL SCAN"
        run_step "passive" passive_recon
        run_step "dns" dns_recon
        run_step "active" active_recon
        run_step "web" web_recon
        run_step "enum" enum_recon
        run_step "secrets" secrets_module
        run_step "cloud" cloud_module
        [[ ${ROBUSTNESS_LEVEL:-3} -ge 4 ]] && run_step "visual" visual_module
        run_step "vuln" vuln_scan
        run_step "diff" run_diff_analysis
        run_step "report" generate_report
    else
        [[ "$RUN_PASSIVE" == true ]] && run_step "passive" passive_recon
        [[ "$RUN_DNS" == true ]] && run_step "dns" dns_recon
        [[ "$RUN_ACTIVE" == true ]] && run_step "active" active_recon
        [[ "$RUN_WEB" == true ]] && run_step "web" web_recon
        [[ "$RUN_ENUM" == true ]] && run_step "enum" enum_recon
        [[ "$RUN_SECRETS" == true ]] && run_step "secrets" secrets_module
        [[ "$RUN_CLOUD" == true ]] && run_step "cloud" cloud_module
        [[ "$RUN_VISUAL" == true ]] && run_step "visual" visual_module
        [[ "$RUN_VULN" == true ]] && run_step "vuln" vuln_scan
        [[ "$RUN_DIFF" == true ]] && run_step "diff" run_diff_analysis
        [[ "$RUN_REPORT" == true ]] && run_step "report" generate_report
        [[ "$RUN_EXPORT" == true ]] && export_report "$TARGET" "$EXPORT_FORMAT"
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_section "SCAN COMPLETE"
    log_success "Total scan duration: ${duration}s"
    log_info "Results saved to: output/$TARGET/"
    log_info "Logs saved to: $SESSION_LOG"
    
    send_webhook_notification "Scan Completed for $TARGET" "Total scan duration: ${duration}s. Results stored in output/$TARGET/" "SUCCESS"
}

# Check if any module is selected
any_module_selected() {
    [[ "$RUN_PASSIVE" == true ]] || \
    [[ "$RUN_DNS" == true ]] || \
    [[ "$RUN_ACTIVE" == true ]] || \
    [[ "$RUN_WEB" == true ]] || \
    [[ "$RUN_ENUM" == true ]] || \
    [[ "$RUN_SECRETS" == true ]] || \
    [[ "$RUN_CLOUD" == true ]] || \
    [[ "$RUN_VISUAL" == true ]] || \
    [[ "$RUN_VULN" == true ]] || \
    [[ "$RUN_DIFF" == true ]] || \
    [[ "$RUN_REPORT" == true ]] || \
    [[ "$RUN_EXPORT" == true ]] || \
    [[ "$RUN_FULL" == true ]]
}

# Main entry point
main() {
    # Parse arguments
    parse_args "$@"
    
    # Show banner
    show_banner
    
    # Check for root (warning only)
    check_root
    
    # Interactive mode
    if [[ "$INTERACTIVE" == true ]]; then
        run_interactive_menu
        exit 0
    fi
    
    # 1. ASN target mode
    if [[ -n "$TARGET_ASN" ]]; then
        if type resolve_asn &>/dev/null; then
            resolve_asn "$TARGET_ASN"
        else
            echo -e "${RED}Error: Infrastructure module not available${RESET}"
        fi
        exit 0
    fi

    # 2. CIDR target mode
    if [[ -n "$TARGET_CIDR" ]]; then
        if type run_cidr_recon &>/dev/null; then
            run_cidr_recon "$TARGET_CIDR"
        else
            echo -e "${RED}Error: Infrastructure module not available${RESET}"
        fi
        exit 0
    fi
    
    # 3. Batch Target List mode
    if [[ -n "$TARGET_LIST" ]]; then
        if [[ ! -f "$TARGET_LIST" ]]; then
            echo -e "${RED}Error: Target list file not found: $TARGET_LIST${RESET}"
            exit 1
        fi
        
        local total_targets=$(grep -v '^[[:space:]]*$' "$TARGET_LIST" | wc -l)
        log_section "BATCH TARGET SCAN: $total_targets Targets"
        
        local count=0
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            ((count++))
            TARGET="$line"
            log_info "Processing target [$count/$total_targets]: $TARGET"
            init_scan
            run_modules
        done < "$TARGET_LIST"
        
        log_success "Batch reconnaissance completed for all $total_targets targets!"
        exit 0
    fi
    
    # 4. Standard Single Target mode
    validate_target
    
    # Check if any module selected
    if ! any_module_selected; then
        echo -e "${YELLOW}No scan module selected. Use --help for options or -i for interactive mode.${RESET}"
        exit 1
    fi
    
    # Initialize scan
    init_scan
    
    # Run modules
    run_modules
}

# Run main
main "$@"
