#!/bin/bash

# Interactive Menu System for ReconX
# Includes robustness level selection (1-5)

# Colors are already sourced from main script

# Robustness Level Descriptions
declare -A ROBUSTNESS_DESC
ROBUSTNESS_DESC[1]="Quick Scan - Minimal tools, fastest execution"
ROBUSTNESS_DESC[2]="Light Scan - Basic tools, quick results"
ROBUSTNESS_DESC[3]="Normal Scan - Balanced approach (Default)"
ROBUSTNESS_DESC[4]="Thorough Scan - More tools, deeper analysis"
ROBUSTNESS_DESC[5]="Aggressive Scan - All tools, maximum depth"

# Default robustness level
ROBUSTNESS_LEVEL=${ROBUSTNESS_LEVEL:-3}

# Display robustness level menu
show_robustness_menu() {
    echo -e "\n${YELLOW}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}║           SELECT ROBUSTNESS LEVEL (1-5)                     ║${RESET}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${YELLOW}║${RESET}                                                            ${YELLOW}║${RESET}"
    
    for i in {1..5}; do
        local marker=" "
        [[ $i -eq $ROBUSTNESS_LEVEL ]] && marker="►"
        local color="$RESET"
        case $i in
            1) color="$GREEN" ;;
            2) color="$CYAN" ;;
            3) color="$YELLOW" ;;
            4) color="$MAGENTA" ;;
            5) color="$RED" ;;
        esac
        printf "${YELLOW}║${RESET} ${color}%s [%d] %-52s${RESET}${YELLOW}║${RESET}\n" "$marker" "$i" "${ROBUSTNESS_DESC[$i]}"
    done
    
    echo -e "${YELLOW}║${RESET}                                                            ${YELLOW}║${RESET}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Get robustness level from user
select_robustness_level() {
    show_robustness_menu
    
    while true; do
        echo -ne "${CYAN}Enter robustness level [1-5] (current: $ROBUSTNESS_LEVEL): ${RESET}"
        read -r level
        
        # Use default if empty
        [[ -z "$level" ]] && level=$ROBUSTNESS_LEVEL
        
        if [[ "$level" =~ ^[1-5]$ ]]; then
            ROBUSTNESS_LEVEL=$level
            export ROBUSTNESS_LEVEL
            echo -e "${GREEN}✓ Robustness level set to: $ROBUSTNESS_LEVEL - ${ROBUSTNESS_DESC[$ROBUSTNESS_LEVEL]}${RESET}"
            return 0
        else
            echo -e "${RED}✗ Invalid input. Please enter a number between 1 and 5.${RESET}"
        fi
    done
}

# Display main menu
show_main_menu() {
    clear
    echo -e "${CYAN}"
    cat <<'EOF'
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
EOF
    echo -e "${RESET}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${WHITE}              Unified Reconnaissance Framework v2.0${RESET}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${RESET}"
    echo ""
    echo -e "${CYAN}Current Settings:${RESET}"
    echo -e "  Target: ${GREEN}${TARGET:-Not Set}${RESET}"
    echo -e "  Robustness Level: ${GREEN}$ROBUSTNESS_LEVEL${RESET} - ${ROBUSTNESS_DESC[$ROBUSTNESS_LEVEL]}"
    echo -e "  Mode: ${GREEN}${MODE:-normal}${RESET}"
    echo ""
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}║                      MAIN MENU                             ║${RESET}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}1.${RESET} Set Target Domain                                     ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}2.${RESET} Set Robustness Level (1-5)                            ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}3.${RESET} Toggle Bug Bounty Mode                                ${YELLOW}║${RESET}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${YELLOW}║${RESET}  ${CYAN}4.${RESET} Run Passive Reconnaissance                            ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${CYAN}5.${RESET} Run DNS Reconnaissance                                 ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${CYAN}6.${RESET} Run Active Reconnaissance                              ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${CYAN}7.${RESET} Run Web Reconnaissance                                 ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${CYAN}8.${RESET} Run Enumeration                                        ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${CYAN}9.${RESET} Run Vulnerability Scan                                 ${YELLOW}║${RESET}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${YELLOW}║${RESET}  ${MAGENTA}10.${RESET} Run Full Scan (All Modules)                           ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${MAGENTA}11.${RESET} Generate Report                                       ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${MAGENTA}12.${RESET} Export Report (Multiple Formats)                      ${YELLOW}║${RESET}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${YELLOW}║${RESET}  ${RED}0.${RESET}  Exit                                                  ${YELLOW}║${RESET}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Get target from user
get_target() {
    echo -ne "${CYAN}Enter target domain: ${RESET}"
    read -r target
    if [[ -n "$target" ]]; then
        TARGET="$target"
        export TARGET
        echo -e "${GREEN}✓ Target set to: $TARGET${RESET}"
    else
        echo -e "${RED}✗ No target provided${RESET}"
    fi
}

# Toggle bug bounty mode
toggle_bb_mode() {
    if [[ "$MODE" == "bugbounty" ]]; then
        MODE="normal"
        echo -e "${GREEN}✓ Switched to Normal mode${RESET}"
    else
        MODE="bugbounty"
        echo -e "${GREEN}✓ Switched to Bug Bounty mode (rate-limited, safe)${RESET}"
    fi
    export MODE
}

# Export format selection menu
show_export_menu() {
    echo -e "\n${YELLOW}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}║              SELECT EXPORT FORMAT                          ║${RESET}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}1.${RESET} Markdown (.md)                                        ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}2.${RESET} HTML (.html)                                          ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}3.${RESET} JSON (.json)                                          ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}4.${RESET} CSV (.csv)                                            ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}5.${RESET} PDF (.pdf)                                            ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${GREEN}6.${RESET} All Formats                                           ${YELLOW}║${RESET}"
    echo -e "${YELLOW}║${RESET}  ${RED}0.${RESET}  Cancel                                                ${YELLOW}║${RESET}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# Interactive menu loop
run_interactive_menu() {
    while true; do
        show_main_menu
        echo -ne "${CYAN}Select option: ${RESET}"
        read -r choice
        
        case $choice in
            1) get_target ;;
            2) select_robustness_level ;;
            3) toggle_bb_mode ;;
            4)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                passive_recon "$TARGET"
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            5)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                dns_recon "$TARGET"
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            6)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                active_recon "$TARGET"
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            7)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                web_recon "$TARGET"
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            8)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                enum_recon "$TARGET"
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            9)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                vuln_scan "$TARGET"
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            10)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                run_full_scan "$TARGET"
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            11)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                generate_report "$TARGET"
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            12)
                [[ -z "$TARGET" ]] && { echo -e "${RED}✗ Please set target first${RESET}"; sleep 2; continue; }
                ensure_logging
                show_export_menu
                echo -ne "${CYAN}Select format: ${RESET}"
                read -r format
                case $format in
                    1) export_report "$TARGET" "md" ;;
                    2) export_report "$TARGET" "html" ;;
                    3) export_report "$TARGET" "json" ;;
                    4) export_report "$TARGET" "csv" ;;
                    5) export_report "$TARGET" "pdf" ;;
                    6) export_report "$TARGET" "all" ;;
                    0) continue ;;
                    *) echo -e "${RED}✗ Invalid option${RESET}" ;;
                esac
                echo -e "\n${GREEN}Press Enter to continue...${RESET}"
                read -r
                ;;
            0)
                echo -e "${GREEN}Goodbye!${RESET}"
                exit 0
                ;;
            *)
                echo -e "${RED}✗ Invalid option${RESET}"
                sleep 1
                ;;
        esac
    done
}

# Run full scan with all modules
run_full_scan() {
    local target=$1
    log_section "FULL SCAN - $target"
    
    passive_recon "$target"
    dns_recon "$target"
    active_recon "$target"
    web_recon "$target"
    enum_recon "$target"
    vuln_scan "$target"
    generate_report "$target"
    
    log_success "Full scan completed for $target"
}

