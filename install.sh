#!/bin/bash

################################################
# TAPE Installation Script                     #
# TAPE - Tmux Automated Pentesting Enumeration #
# Chronos Security                             #
# https://chronos-security.ro                  #
# https://github.com/Chronos-Security          #
################################################

# Exit on error
set -e

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RESET="\033[0m"

# Banner
echo -e "${BLUE}TAPE Installation Script${RESET}"
echo -e "${GREEN}Installing necessary tools and dependencies...${RESET}"

# -----------------------------
# Define Tools and Dependencies
# -----------------------------

# Networking and enumeration tools
CORE_TOOLS=(
    "nmap"
    "hydra"
    "curl"
    "wget"
    "ftp"
    "netcat"
    "enum4linux"
    "dnsrecon"
    "dnsutils"
    "smbclient"
    "masscan"
    "rustscan"
)

# Web fuzzing and exploitation tools
WEB_TOOLS=(
    "gobuster"
    "wfuzz"
    "ffuf"
    "feroxbuster"
)

# Additional utilities
EXTRA_TOOLS=(
    "tmux"
    "python3"
    "python3-pip"
    "build-essential"
    "libssl-dev"
    "seclists"
    "ldap-utils"
)

# Metasploit dependencies
METASPLOIT=(
    "postgresql"
    "ruby"
    "libsqlite3-dev"
)

# All tools combined
ALL_TOOLS=("${CORE_TOOLS[@]}" "${WEB_TOOLS[@]}" "${EXTRA_TOOLS[@]}" "${METASPLOIT[@]}")

# -----------------------------
# Installation Functions
# -----------------------------

# Update package lists
function update_system {
    echo -e "${BLUE}[1/6] Updating system packages...${RESET}"
    sudo apt update -y
}

# Install tools
function install_tools {
    echo -e "${BLUE}[2/6] Installing tools and dependencies...${RESET}"
    for tool in "${ALL_TOOLS[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${GREEN}Installing: $tool${RESET}"
            sudo apt install -y "$tool"
        else
            echo -e "${GREEN}$tool is already installed.${RESET}"
        fi
    done
}

# Set up Metasploit
function setup_metasploit {
    echo -e "${BLUE}[3/6] Setting up Metasploit Framework...${RESET}"
    if ! command -v msfconsole &>/dev/null; then
        curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate | sudo bash
    else
        echo -e "${GREEN}Metasploit is already installed.${RESET}"
    fi
}

# Install Python tools
function setup_python {
    echo -e "${BLUE}[4/6] Setting up Python tools...${RESET}"

    # Check for virtual environment support
    if ! python3 -m ensurepip --upgrade; then
        echo -e "${YELLOW}Installing virtual environment tools...${RESET}"
        sudo apt install -y python3-venv
    fi

    # Create a virtual environment
    if [ ! -d "tape_env" ]; then
        echo -e "${BLUE}Creating a virtual environment for TAPE...${RESET}"
        python3 -m venv tape_env
    fi

    # Activate the virtual environment
    echo -e "${GREEN}Activating virtual environment...${RESET}"
    source tape_env/bin/activate

    # Install required Python packages
    python_packages=("ldap3" "dnspython" "impacket" "requests")
    for package in "${python_packages[@]}"; do
        echo -e "${GREEN}Installing Python package: $package${RESET}"
        pip install "$package"
    done

    echo -e "${GREEN}Python tools setup completed.${RESET}"
    deactivate
}

# Add TAPE to system PATH using a symlink
function setup_tape {
    echo -e "${BLUE}[5/6] Adding TAPE to system PATH...${RESET}"
    SCRIPT_SOURCE=$(realpath tape.py)
    SCRIPT_DEST="/usr/local/bin/tape"

    # Create a symbolic link pointing to the current script
    if [ -L "$SCRIPT_DEST" ]; then
        echo -e "${YELLOW}Updating existing TAPE symlink...${RESET}"
        sudo ln -sf "$SCRIPT_SOURCE" "$SCRIPT_DEST"
    else
        echo -e "${GREEN}Creating new TAPE symlink...${RESET}"
        sudo ln -s "$SCRIPT_SOURCE" "$SCRIPT_DEST"
    fi

    # Ensure the script is executable
    chmod +x "$SCRIPT_SOURCE"

    echo -e "${GREEN}TAPE is now accessible globally as 'tape'.${RESET}"
}

# Check for updates in the repository
function update_repository {
    echo -e "${BLUE}[6/6] Checking for updates in the repository...${RESET}"
    if git rev-parse --git-dir > /dev/null 2>&1; then
        git fetch origin
        LOCAL=$(git rev-parse HEAD)
        REMOTE=$(git rev-parse origin/main)
        if [ "$LOCAL" != "$REMOTE" ]; then
            echo -e "${YELLOW}Updates found. Pulling latest changes...${RESET}"
            git pull
        else
            echo -e "${GREEN}Repository is up to date.${RESET}"
        fi
    else
        echo -e "${RED}Not a git repository. Please clone the repository from GitHub.${RESET}"
        exit 1
    fi
}

# -----------------------------
# Execution
# -----------------------------

update_system
install_tools
setup_metasploit
setup_python
update_repository
setup_tape

echo -e "${GREEN}Installation completed successfully!${RESET}"
echo -e "${BLUE}You are now ready to use TAPE.${RESET}"
