#!/bin/bash

# ReconX Installer v2.0
# Installs dependencies, configures API keys, and sets up the environment.

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
INSTALL_DIR="$HOME/.reconx"
BIN_DIR="$HOME/.local/bin"
CONFIG_FILE="$INSTALL_DIR/config/tools.conf"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
log_info() { echo -e "${BLUE}[*] $1${NC}"; }
log_success() { echo -e "${GREEN}[+] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[!] $1${NC}"; }
log_error() { echo -e "${RED}[-] $1${NC}"; }

# -----------------------------------------------------------------------------
# Previous Installation Check and Removal
# -----------------------------------------------------------------------------
check_and_remove_previous_installation() {
    log_info "Checking for previous ReconX installations..."
    
    local found_previous=false
    local locations_to_check=(
        "$HOME/.reconx"
        "$HOME/.local/bin/reconx"
        "/usr/local/bin/reconx"
        "/opt/reconx"
    )
    
    # Check for existing installations
    for location in "${locations_to_check[@]}"; do
        if [[ -e "$location" ]]; then
            found_previous=true
            log_warn "Found previous installation: $location"
        fi
    done
    
    # If previous installation found, ask user if they want to remove it
    if $found_previous; then
        echo ""
        log_warn "Previous ReconX installation(s) detected."
        echo -e "${YELLOW}Do you want to completely remove all previous installations before proceeding? (y/N)${NC}"
        read -r remove_previous
        
        if [[ "$remove_previous" =~ ^[Yy]$ ]]; then
            log_info "Removing previous ReconX installations..."
            
            # Remove installation directories
            for location in "${locations_to_check[@]}"; do
                if [[ -e "$location" ]]; then
                    log_info "Removing: $location"
                    rm -rf "$location" 2>/dev/null || sudo rm -rf "$location" 2>/dev/null
                    
                    if [[ -e "$location" ]]; then
                        log_error "Failed to remove: $location (permission denied)"
                    else
                        log_success "Removed: $location"
                    fi
                fi
            done
            
            # Remove symlinks
            log_info "Removing symlinks..."
            local symlinks=(
                "$HOME/.local/bin/reconx"
                "/usr/local/bin/reconx"
                "/usr/bin/reconx"
            )
            
            for symlink in "${symlinks[@]}"; do
                if [[ -L "$symlink" ]]; then
                    log_info "Removing symlink: $symlink"
                    rm -f "$symlink" 2>/dev/null || sudo rm -f "$symlink" 2>/dev/null
                    log_success "Removed symlink: $symlink"
                fi
            done
            
            # Clean up PATH entries from shell rc files
            log_info "Cleaning up PATH entries from shell configuration files..."
            local shell_configs=(
                "$HOME/.bashrc"
                "$HOME/.zshrc"
                "$HOME/.profile"
            )
            
            for config in "${shell_configs[@]}"; do
                if [[ -f "$config" ]]; then
                    # Create backup
                    cp "$config" "${config}.reconx.backup" 2>/dev/null
                    
                    # Remove ReconX PATH entries
                    sed -i '/reconx/d' "$config" 2>/dev/null
                    sed -i '/ReconX/d' "$config" 2>/dev/null
                    
                    # Remove empty lines created by deletion
                    sed -i '/^$/N;/^\n$/D' "$config" 2>/dev/null
                fi
            done
            
            log_success "Previous ReconX installations removed successfully!"
            echo ""
        else
            log_info "Keeping previous installation. New installation will overwrite conflicting files."
            echo ""
        fi
    else
        log_success "No previous ReconX installations found."
        echo ""
    fi
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root. This is fine for installing packages, but some tools advise against running as root."
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

add_to_path() {
    local shell_rc=""
    case $SHELL in
        */zsh) shell_rc="$HOME/.zshrc" ;;
        */bash) shell_rc="$HOME/.bashrc" ;;
        *) shell_rc="$HOME/.bashrc" ;;
    esac

    if ! grep -q "$1" "$shell_rc"; then
        log_info "Adding $1 to PATH in $shell_rc"
        echo "export PATH=\$PATH:$1" >> "$shell_rc"
    fi
}

# -----------------------------------------------------------------------------
# Dependency Installation
# -----------------------------------------------------------------------------
install_system_deps() {
    log_info "Updating package lists..."
    sudo apt-get update -y

    local deps=(
        git curl wget unzip jq build-essential
        python3 python3-pip python3-venv
        libpcap-dev libssl-dev libffi-dev
        nmap masscan nikto sqlmap dnsenum fierce dnsrecon whois
        golang
    )

    log_info "Installing system packages: ${deps[*]}"
    sudo apt-get install -y "${deps[@]}"
}

install_go_tools() {
    if ! command_exists go; then
        log_error "Go is not installed. Skipping Go tools."
        return
    fi

    log_info "Installing Go tools..."
    export GOPATH="$HOME/go"
    export PATH=$PATH:$GOPATH/bin

    local tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/owasp-amass/amass/v3/cmd/amass@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/ffuf/ffuf@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/anew@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/tomnomnom/qsreplace@latest"
        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    )

    for tool in "${tools[@]}"; do
        local name=$(basename "$tool" | cut -d@ -f1)
        local is_installed=false
        if [[ "$name" == "httpx" ]]; then
            if [[ -x "$HOME/go/bin/httpx" ]] && "$HOME/go/bin/httpx" -version 2>&1 | grep -qi "projectdiscovery"; then
                is_installed=true
            fi
        elif command_exists "$name"; then
            is_installed=true
        fi

        if $is_installed; then
             log_success "$name is already installed."
        else
             log_info "Installing $name..."
             go install -v "$tool"
        fi
    done

    # Ensure Go bin is in PATH
    add_to_path "$HOME/go/bin"
}

install_python_tools() {
    log_info "Installing Python tools..."
    local tools=(wafw00f dirsearch sslyze arjun)

    for tool in "${tools[@]}"; do
        log_info "Installing $tool..."
        pip3 install "$tool" --break-system-packages 2>/dev/null || pip3 install "$tool"
    done
}

install_manual_tools() {
    # Install Findomain
    if ! command_exists findomain; then
        log_info "Installing Findomain..."
        curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
        unzip findomain-linux.zip
        chmod +x findomain
        sudo mv findomain /usr/local/bin/
        rm findomain-linux.zip 2>/dev/null
    fi

    # Install RustScan
    if ! command_exists rustscan; then
         log_info "Installing RustScan..."
         ARCH=$(uname -m)
         if [[ "$ARCH" == "x86_64" ]]; then
             wget -q https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
             sudo dpkg -i rustscan_2.0.1_amd64.deb 2>/dev/null
             rm rustscan_2.0.1_amd64.deb 2>/dev/null
         else
             log_warn "RustScan .deb not available for $ARCH. Skipping automatic installation. Please install manually."
         fi
    fi
    
    # Initialize Nuclei Templates
    if command_exists nuclei; then
        log_info "Updating Nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi
}

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
setup_api_keys() {
    log_info "Configuring API Keys..."

    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_warn "Config file not found at $CONFIG_FILE. Skipping API setup."
        return
    fi

    local keys=(
        "SHODAN_API_KEY"
        "VIRUSTOTAL_API_KEY"
        "BEVIGIL_API_KEY"
        "ALIENVAULT_API_KEY"
        "WPSCAN_API_TOKEN"
        "CHAOS_API_KEY"
        "SECURITYTRAILS_API_KEY"
        "CENSYS_API_ID"
        "CENSYS_API_SECRET"
    )

    for key in "${keys[@]}"; do
        # Check if key is already set (non-empty) in the file
        current_val=$(grep "^$key=" "$CONFIG_FILE" | cut -d'"' -f2)

        if [[ -z "$current_val" ]]; then
            echo -e "${YELLOW}Enter value for $key (or press Enter to skip):${NC}"
            read -r user_input
            if [[ -n "$user_input" ]]; then
                # Escape slashes if any
                safe_input=$(echo "$user_input" | sed 's/\//\\\//g')
                sed -i "s/^$key=\"\"/$key=\"$safe_input\"/" "$CONFIG_FILE"
                log_success "Updated $key"
            fi
        else
            log_success "$key is already configured."
        fi
    done
}

# -----------------------------------------------------------------------------
# Main Installation
# -----------------------------------------------------------------------------
main() {
    log_info "ReconX Installer Started"

    check_root
    
    # Check and remove previous installations
    check_and_remove_previous_installation

    # 1. Install Dependencies
    install_system_deps
    install_go_tools
    install_python_tools
    install_manual_tools

    # 2. Setup Directory Structure & Files
    log_info "Setting up ReconX files..."
    mkdir -p "$INSTALL_DIR" "$BIN_DIR"

    # Copy files (assuming we are running from the repo root)
    if [[ -d "modules" ]]; then
        cp -r modules utils wordlists web reconx.sh "$INSTALL_DIR" 2>/dev/null || cp -r modules utils wordlists reconx.sh "$INSTALL_DIR"

        # Handle config separately to preserve existing settings
        if [[ ! -d "$INSTALL_DIR/config" ]]; then
            cp -r config "$INSTALL_DIR"
        else
            # Update other config files but preserve tools.conf if it exists
            cp config/reconx.conf "$INSTALL_DIR/config/"
            cp config/wordlists.conf "$INSTALL_DIR/config/"
            if [[ ! -f "$INSTALL_DIR/config/tools.conf" ]]; then
                cp config/tools.conf "$INSTALL_DIR/config/"
            fi
        fi
    else
        log_error "Source files not found. Please run this script from the ReconX repository root."
        exit 1
    fi

    # 3. Permissions
    log_info "Setting permissions..."
    chmod +x "$INSTALL_DIR/reconx.sh"
    chmod +x "$INSTALL_DIR"/modules/*.sh
    chmod +x "$INSTALL_DIR"/utils/*.sh

    # 4. Symlink
    log_info "Creating symlink..."
    ln -sf "$INSTALL_DIR/reconx.sh" "$BIN_DIR/reconx"

    # 5. Interactive Configuration Wizard (Optional)
    echo ""
    log_info "Would you like to configure API keys now via the interactive wizard? (y/N)"
    read -r run_wizard
    if [[ "$run_wizard" =~ ^[Yy]$ ]]; then
        if [[ -f "$INSTALL_DIR/utils/config_wizard.sh" ]]; then
            export BASE_DIR="$INSTALL_DIR"
            source "$INSTALL_DIR/utils/config_wizard.sh"
            config_wizard
        else
            log_warn "Configuration wizard not found, skipping..."
        fi
    else
        log_info "Skipping API key setup. ReconX operates with built-in free OSINT engines."
    fi

    # 6. Final Path Check
    add_to_path "$BIN_DIR"

    log_success "ReconX installed successfully!"
    log_info "Please run 'source ~/.bashrc' (or your shell's rc file) to update PATH."
    log_info "Run 'reconx -h' to get started."
}

# -----------------------------------------------------------------------------
# Update Mode (-u / -U / --update)
# -----------------------------------------------------------------------------
update_reconx() {
    log_info "ReconX Updater"
    echo ""
    echo -e "${CYAN}Choose update method:${NC}"
    echo "1) Automatic (Check & pull latest git version, update installation) [Recommended]"
    echo "2) Manual (Instructions for manual cloning and updating)"
    echo ""
    echo -e "${YELLOW}Select option [1/2] (Default: 1):${NC}"
    read -r update_choice
    update_choice="${update_choice:-1}"

    if [[ "$update_choice" == "2" ]]; then
        echo ""
        log_info "Manual Update Instructions:"
        echo -e "${GREEN}1.${NC} Navigate to your local ReconX repository:"
        echo "   cd $(pwd)"
        echo -e "${GREEN}2.${NC} Pull the latest commits:"
        echo "   git pull origin main"
        echo -e "${GREEN}3.${NC} Run installer to update files and dependencies:"
        echo "   ./install.sh"
        echo ""
        exit 0
    fi

    # Automatic mode
    log_info "Running automatic update..."
    
    # Check if inside git repository
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        log_info "Fetching latest changes from remote git repository..."
        git fetch origin main 2>/dev/null || git fetch 2>/dev/null
        
        local local_head=$(git rev-parse HEAD 2>/dev/null)
        local remote_head=$(git rev-parse origin/main 2>/dev/null || git rev-parse '@{u}' 2>/dev/null)
        
        if [[ -n "$local_head" && -n "$remote_head" && "$local_head" == "$remote_head" ]]; then
            log_success "ReconX repository is already at the latest version ($local_head)."
        else
            log_info "Pulling latest commits from git..."
            git pull origin main 2>/dev/null || git pull
            log_success "Updated local repository to latest commit."
        fi
    else
        log_warn "Not currently inside a git repository. Updating installed files directly from current directory."
    fi

    # Sync updated files to INSTALL_DIR
    log_info "Updating files in $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR" "$BIN_DIR"
    cp -r modules utils wordlists web reconx.sh "$INSTALL_DIR" 2>/dev/null || cp -r modules utils wordlists reconx.sh "$INSTALL_DIR"
    
    # Update config files while preserving tools.conf
    mkdir -p "$INSTALL_DIR/config"
    cp config/reconx.conf "$INSTALL_DIR/config/" 2>/dev/null || true
    cp config/wordlists.conf "$INSTALL_DIR/config/" 2>/dev/null || true
    if [[ ! -f "$INSTALL_DIR/config/tools.conf" ]]; then
        cp config/tools.conf "$INSTALL_DIR/config/" 2>/dev/null || true
    fi

    # Refresh permissions and symlink
    chmod +x "$INSTALL_DIR/reconx.sh"
    chmod +x "$INSTALL_DIR"/modules/*.sh 2>/dev/null || true
    chmod +x "$INSTALL_DIR"/utils/*.sh 2>/dev/null || true
    ln -sf "$INSTALL_DIR/reconx.sh" "$BIN_DIR/reconx"

    # Update templates
    if command_exists nuclei; then
        log_info "Updating Nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || true
    fi

    log_success "ReconX has been successfully updated to the latest build!"
    log_info "Run 'reconx -v' or 'reconx -h' to get started."
    exit 0
}

show_install_help() {
    echo "ReconX Installer v2.0"
    echo ""
    echo "Usage:"
    echo "  ./install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -u, -U, --update   Update ReconX to the latest build (automatic or manual)"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Default (no options) runs full installation and setup wizard."
    exit 0
}

# Entrypoint argument check
case "$1" in
    -u|-U|--update)
        update_reconx
        ;;
    -h|--help)
        show_install_help
        ;;
    *)
        main "$@"
        ;;
esac

