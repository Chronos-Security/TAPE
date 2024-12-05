#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TAPE - Tmux Automated Pentesting Enumeration
Chronos Security
https://chronossec.site
https://github.com/ChronosPK
"""

import os
import sys
import argparse
import subprocess
from collections import defaultdict
from datetime import datetime

# -----------------------------
# Configurations and Variables
# -----------------------------

# Colors for output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
BRIGHT_YELLOW = '\033[1;33m'
NC = '\033[0m'  # No Color

# Additional Colors for Protocol, Actions, and Subactions
PROTOCOL_COLOR = '\033[1;31m'  # Bright Red
ACTION_COLOR = '\033[1;34m'    # Bright Blue
SUBACTION_COLOR = ACTION_COLOR  # Same color for action and subaction

# Directories
RECON_DIR = "recon"
VULNS_DIR = "vulns"
FILES_DIR = "files"
NOTES_DIR = "notes"

# Create necessary directories and files with proper permissions
directories = [VULNS_DIR, RECON_DIR, FILES_DIR, NOTES_DIR]
files = ["notes.txt", "users.txt", "passwords.txt", "hashes.txt", "creds.txt"]

def create_directories_and_files():
    # Get the original user's UID and GID
    original_uid = int(os.environ.get('SUDO_UID', os.getuid()))
    original_gid = int(os.environ.get('SUDO_GID', os.getgid()))

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        os.chown(directory, original_uid, original_gid)

    for filename in files:
        filepath = os.path.join(NOTES_DIR, filename)
        with open(filepath, 'a'):
            pass
        os.chown(filepath, original_uid, original_gid)

# Commands for each service and action
# Updated to support grouped commands
COMMANDS = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

# Services and their default ports
SERVICES = {
    "FTP": {"ports": [21], "transport": "TCP"},
    "SSH": {"ports": [22], "transport": "TCP"},
    "TELNET": {"ports": [23], "transport": "TCP"},
    "SMTP": {"ports": [25, 465, 587], "transport": "TCP"},
    "DNS": {"ports": [53], "transport": "TCP/UDP"},
    "TFTP": {"ports": [69], "transport": "UDP"},
    "HTTP": {"ports": [80, 443, 8080, 8000, 8008], "transport": "TCP"},
    "KERBEROS": {"ports": [88], "transport": "TCP/UDP"},
    "POP3": {"ports": [110, 995], "transport": "TCP"},
    "IMAP": {"ports": [143, 993], "transport": "TCP"},
    "LDAP": {"ports": [389, 636, 3268, 3269], "transport": "TCP"},
    "SMB": {"ports": [139, 445], "transport": "TCP"},
    "RDP": {"ports": [3389], "transport": "TCP"},
    "MYSQL": {"ports": [3306], "transport": "TCP"},
    "NFS": {"ports": [2049], "transport": "TCP/UDP"},
    "RPCBIND": {"ports": [111], "transport": "TCP/UDP"},
    "VNC": {"ports": [5900], "transport": "TCP"},
    "POSTGRES": {"ports": [5432], "transport": "TCP"},
    "REDIS": {"ports": [6379], "transport": "TCP"},
    "MONGODB": {"ports": [27017], "transport": "TCP"},
    "WINRM": {"ports": [5985, 5986], "transport": "TCP"},
}

# -----------------------------
# Function Definitions
# -----------------------------

# Argument Parser
parser = argparse.ArgumentParser(
    description="TAPE - Tmux Automated Pentesting Enumeration",
    formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=35)
)
parser.add_argument('-n', '--net', help='Set target network (e.g., 192.168.1.0/24)')
parser.add_argument('-i', '--ip', help='Set target IP address')
parser.add_argument('-d', '--domain', metavar='DOMAIN', help='Set target domain')
parser.add_argument('-x', '--execute', action='store_true', help='Execute the enumeration process')
parser.add_argument('-l', '--list-commands', action='store_true', help='List all available commands')
parser.add_argument('-s', '--service', help='Specify a service to list commands for')
parser.add_argument('-q', '--quiet', action='store_true', help='Suppress command output (commands are echoed by default)')
parser.add_argument('-f', '--force-recon', action='store_true', help='Force reconnaissance scans even if already done')
args = parser.parse_args()

def display_help():
    parser.print_help()

def is_root():
    return os.geteuid() == 0

def resolve_domain(domain):
    try:
        result = subprocess.check_output(['dig', '+short', domain], text=True)
        ip = result.strip().split('\n')[0]
        if ip:
            return ip
        else:
            return None
    except subprocess.CalledProcessError:
        return None

def format_command(command, variables):
    # Replace placeholders without braces
    for key, value in variables.items():
        command = command.replace(key, value)
    return command

def list_commands(commands, variables, service=None):
    services_to_list = [service.upper()] if service else sorted(commands.keys(), key=lambda x: SERVICES.get(x, {}).get('ports', [0])[0])
    for protocol in services_to_list:
        if protocol not in commands:
            continue
        actions = commands[protocol]
        if protocol in SERVICES:
            ports = ','.join(map(str, SERVICES[protocol]['ports']))
            transport = SERVICES[protocol]['transport']
        else:
            ports = 'N/A'
            transport = 'N/A'
        for action in actions:
            for subaction in actions[action]:
                action_subaction_title = f"{protocol} - {ports}/{transport} - {action} - {subaction}"
                print(f"{ACTION_COLOR}{action_subaction_title}{NC}")
                for cmd_group in actions[action][subaction]:
                    description = cmd_group['description']
                    cmds = cmd_group['commands']
                    if description:
                        print(f"{YELLOW}# {description}{NC}")
                    for cmd in cmds:
                        cmd_display = format_command(cmd, variables)
                        print(cmd_display)
                    print()

def main():
    if len(sys.argv) == 1:
        display_help()
        sys.exit(1)

    variables = {
        'IP': args.ip if args.ip else 'IP',
        'NET': args.net if args.net else 'NET',
        'DOMAIN': args.domain if args.domain else 'DOMAIN',
        'RECON_DIR': RECON_DIR,
        'USER': 'USER',
        'PASS': 'PASS',
    }

    # If both IP and domain are provided
    if args.ip and args.domain:
        resolved_ip = resolve_domain(args.domain)
        if resolved_ip:
            if resolved_ip != args.ip:
                print(f"{RED}[!] Error: Domain {args.domain} does not resolve to IP {args.ip}.{NC}")
                sys.exit(1)
            else:
                variables['IP'] = args.ip
                variables['DOMAIN'] = args.domain
        else:
            print(f"{RED}[!] Error: Unable to resolve domain {args.domain}.{NC}")
            sys.exit(1)
    elif args.domain:
        # Only domain is provided
        resolved_ip = resolve_domain(args.domain)
        if resolved_ip:
            variables['IP'] = resolved_ip
            variables['DOMAIN'] = args.domain
        else:
            print(f"{RED}[!] Error: Unable to resolve domain {args.domain}.{NC}")
            sys.exit(1)
    elif args.ip:
        # Only IP is provided
        variables['IP'] = args.ip
        variables['DOMAIN'] = 'DOMAIN'
    else:
        # Neither IP nor domain is provided
        variables['IP'] = 'IP'
        variables['DOMAIN'] = 'DOMAIN'

    # Prioritize domain over IP in URL
    variables['URL'] = f"http://{variables['DOMAIN'] if variables['DOMAIN'] != 'DOMAIN' else variables['IP']}"

    # Create directories and files with proper permissions
    create_directories_and_files()

    # Create commands for recon and for each service
    COMMANDS['RECON']['Network']['netdiscover'].append({
        'description': "",
        'commands': [
            "sudo netdiscover -i eth0 -r NET"
        ]
    })
    COMMANDS['RECON']['Network']['nmap'].append({
        'description': "",
        'commands': [
            "nmap -sn NET -oN recon/nmap.discovery",
            "cat recon/nmap.discovery | grep -i report | cut -d' ' -f5 > recon/hosts",
            "nmap -sC -sV -v -A -T4 -Pn -iL recon/hosts -n -p- -oN recon/nmap.network --open --max-retries 5"
        ]
    })
    COMMANDS['RECON']['Network']['fping + nmap'].append({
        'description': "",
        'commands': [
            "fping -a -g NET 2>/dev/null > recon/hosts",
            "nmap -sC -sV -v -A -T4 -Pn -iL recon/hosts -n -p- -oN recon/nmap.network --open --max-retries 5"
        ]
    })
    COMMANDS['RECON']['Network']['masscan'].append({
        'description': "",
        'commands': [
            "masscan NET –echo > recon/masscan.conf"
        ]
    })
    COMMANDS['RECON']['Network']['UDP'].append({
        'description': "",
        'commands': [
            "nmap -sU -sV --version-intensity 0 -F -n NET -oN recon/nmap.udp-net",
            "udp-proto-scanner.pl NET"
        ]
    })
    COMMANDS['RECON']['Network']['No man\'s land'].append({
        'description': "",
        'commands': [
            "for i in {1..254} ;do (ping -c 1 10.10.10.$i | grep 'bytes from' | awk '{print $4}' | cut -d ':' -f 1 &) ;done"
        ]
    })

#------------------------------------------------------------------------------------------------------------------

    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "Extract ports and run all-TCP scan",
        'commands': [
            "nmap -Pn -p- -v -T4 --max-retries 5 IP -oN recon/nmap.init",
            "cat recon/nmap.init | grep '/.*open' | cut -d '/' -f 1 | tr '\\n' ',' | sed 's/,$//g' > recon/ports",
            "sudo nmap -Pn -sS -sV -n -v -A -T4 -p $(cat recon/ports) IP -oN recon/nmap.alltcp"
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "Single TCP scan",
        'commands': [
            'sudo nmap -O -Pn -p- -T4 --max-retries 4 -v IP -oN recon/nmap.tcp'
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "VULN scan",
        'commands': [
            'nmap --script vulners -Pn -sC -sV -v -A -T4 -p- --max-retries 5 --open IP -oN recon/nmap.vuln'
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "UDP scan",
        'commands': [
            'nmap -sU -sV -sC -n -F -T4 IP -oN recon/nmap.udp'
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "Firewall evasion",
        'commands': [
            'sudo nmap -v -Pn -sS -sV -T4 --max-retries 3 --min-rate 450 --max-rtt-timeout 500ms --min-rtt-timeout 50ms -p- -f --source-port 53 --spoof-mac aa:bb:cc:dd:ee:ff IP'
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "Rustscan enumeration",
        'commands': [
            "rustscan -a IP --ulimit 5000 -- -sC -sV -v -oN recon/rustscan.init"
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "Autorecon enumeration",
        'commands': [
            "autorecon -v --heartbeat 10 IP"
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "Legion",
        'commands': [
            "sudo legion # GUI"
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "Zenmap",
        'commands': [
            "zenmap # GUI"
        ]
    })
    COMMANDS['RECON']['Single Host']['nmap'].append({
        'description': "No man's land",
        'commands': [
            "for port in {1..65535}; do echo 2>/dev/null > /dev/tcp/IP/$port && echo -e \"$port open\\n\"; done"
        ]
    })
#------------------------------------------------------------------------------------------------------------------
    COMMANDS['FTP']['Enumeration']['Anonymous Access'].append({
        'description': "Check for anonymous FTP login",
        'commands': [
            'nmap -p PORT --script ftp-anon IP -oN recon/ftp_anonymous.txt',
            '',
            'ftp -nv IP PORT',
        ]
    })
    COMMANDS['FTP']['Enumeration']['Banner Grabbing'].append({
        'description': "FTP Banner Grabbing",
        'commands': [
            'nmap -sV -p PORT IP -oN recon/ftp_banner.txt',
            'nc -nv IP PORT',
        ]
    })
    COMMANDS['FTP']['Enumeration']['Brute Force'].append({
        'description': "FTP Brute Force with Hydra",
        'commands': [
            'hydra -L users.txt -P passwords.txt ftp://IP -s PORT',
            'ftp-user-enum.pl -U /usr/share/seclists/Usernames/cirt-default-usernames.txt -t IP'
        ]
    })
    COMMANDS['FTP']['Access']['Read Permissions'].append({
        'description': "Routine checks after connecting",
        'commands': [
            'ls -lsa',
            'get FILENAME',
            'prompt; mget *',
            'wget -r ftp://USER:PASS@IP/',
            'quote PASV # enter a passive FTP session'
        ]
    })

#------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------------------------------



    # List Commands
    if args.list_commands:
        variables['PORT'] = 'PORT'
        list_commands(COMMANDS, variables, args.service)
        sys.exit(0)

    if not args.execute:
        variables['PORT'] = 'PORT'
        list_commands(COMMANDS, variables, args.service)
        sys.exit(0)

    if not is_root():
        print(f"{RED}[!] Please run as root.{NC}")
        sys.exit(1)

    # Proceed with execution
    # Check if recon has been done
    recon_done = os.path.exists('recon/nmap.init')
    if recon_done and not args.force_recon:
        print(f"{GREEN}[*] Reconnaissance scans already completed.")
        print(f"{YELLOW}[*] Use --force-recon to run reconnaissance scans again.{NC}")
    else:
        print(f"{GREEN}[*] Running reconnaissance scans...{NC}")
        variables['PORT'] = ''
        # Execute the first RECON command group
        recon_commands = COMMANDS['RECON']['Single Host']['nmap'][0]['commands']
        desc = COMMANDS['RECON']['Single Host']['nmap'][0]['description']
        if not args.quiet:
            print(f"{PROTOCOL_COLOR}RECON{NC} - {ACTION_COLOR}{desc}{NC}")
        for cmd in recon_commands:
            cmd_exec = format_command(cmd, variables)
            if not args.quiet:
                cmd_display = cmd_exec
                print(f"{BRIGHT_YELLOW}$ {cmd_display}{NC}")
            subprocess.call(cmd_exec, shell=True)

    # Continue with parsing open ports
    if os.path.exists('recon/nmap.init'):
        print(f"{GREEN}[*] Extracting open ports...{NC}")
        open_ports = []
        with open('recon/nmap.init', 'r') as f:
            for line in f:
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0].strip()
                    open_ports.append(port)
        if not open_ports:
            print(f"{RED}[!] No open ports found on {variables['IP']}.{NC}")
            sys.exit(1)
        variables['OPEN_PORTS'] = ','.join(open_ports)
        print(f"{GREEN}[*] Open ports: {YELLOW}{variables['OPEN_PORTS']}{NC}")
    else:
        print(f"{RED}[!] Reconnaissance scans did not produce expected output.{NC}")
        sys.exit(1)

    # Parse services from detailed Nmap output
    print(f"{GREEN}[*] Parsing services from Nmap output...{NC}")
    discovered_services = defaultdict(list)
    if os.path.exists('recon/nmap.alltcp'):
        with open('recon/nmap.alltcp', 'r') as f:
            for line in f:
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    port = parts[0].split('/')[0]
                    if len(parts) >= 3:
                        service = parts[2].upper()
                    else:
                        service = 'UNKNOWN'
                    discovered_services[service].append(port)
    else:
        print(f"{RED}[!] Detailed Nmap scan output not found.{NC}")
        sys.exit(1)
    if not discovered_services:
        print(f"{RED}[!] No services found.{NC}")
        sys.exit(1)

    # Filter commands based on discovered services
    commands_to_execute = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for service in discovered_services:
        if service in COMMANDS:
            for action in COMMANDS[service]:
                for subaction in COMMANDS[service][action]:
                    for cmd_group in COMMANDS[service][action][subaction]:
                        commands_to_execute[service][action][subaction].append(cmd_group)
        else:
            print(f"{YELLOW}[!] No commands found for service: {service}{NC}")

    # Update variables with URL
    variables['URL'] = f"http://{variables['DOMAIN'] if variables['DOMAIN'] != 'DOMAIN' else variables['IP']}"

    # Show commands unless quiet
    if not args.quiet:
        list_commands(commands_to_execute, variables)

    # Execute commands if -x is specified
    if args.execute:
        print(f"{GREEN}[*] Executing service enumeration commands in tmux...{NC}")
        execute_commands_with_tmux(commands_to_execute, variables, discovered_services)

def execute_commands_with_tmux(commands, variables, discovered_services):
    # Check if tmux is installed
    if subprocess.call(['which', 'tmux'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print(f"{RED}[!] tmux is not installed. Please install tmux.{NC}")
        sys.exit(1)

    session_name = f"TAPE_{int(datetime.now().timestamp())}"
    # Start tmux session
    subprocess.call(['tmux', 'new-session', '-d', '-s', session_name])

    window_index = 1
    for protocol in commands:
        if protocol not in discovered_services and protocol != 'RECON':
            continue  # Skip if protocol not in discovered services, except for RECON

        variables['PORT'] = ','.join(discovered_services.get(protocol, []))
        if protocol in SERVICES:
            ports = ','.join(discovered_services.get(protocol, SERVICES[protocol]['ports']))
            transport = SERVICES[protocol]['transport']
        else:
            ports = 'N/A'
            transport = 'N/A'
        for action in commands[protocol]:
            for subaction in commands[protocol][action]:
                # Create window name
                window_name = f"{protocol}_{action}_{subaction}"
                # Replace spaces with underscores and limit length
                window_name = window_name.replace(' ', '_')[:50]
                # Create a new window for each protocol-action-subaction
                subprocess.call(['tmux', 'new-window', '-t', session_name, '-n', window_name])
                protocol_title = f"{protocol} - {ports}/{transport}"
                tmux_cmd = f"echo -e '{PROTOCOL_COLOR}{protocol_title}{NC}'"
                subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", tmux_cmd, 'C-m'])
                action_subaction_title = f"{protocol} - {ports}/{transport} - {action} - {subaction}"
                tmux_cmd = f"echo -e '{ACTION_COLOR}{action_subaction_title}{NC}'"
                subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", tmux_cmd, 'C-m'])
                for cmd_group in commands[protocol][action][subaction]:
                    description = cmd_group['description']
                    cmds = cmd_group['commands']
                    if description:
                        tmux_cmd = f"echo -e '{YELLOW}# {description}{NC}'"
                        subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", tmux_cmd, 'C-m'])
                    for cmd in cmds:
                        # Replace variables
                        cmd_exec = format_command(cmd, variables)
                        # Display the command
                        cmd_display = cmd_exec
                        tmux_cmd = f"echo -e '{CYAN}$ {cmd_display}{NC}'"
                        subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", tmux_cmd, 'C-m'])
                        # Execute the command
                        subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", cmd_exec, 'C-m'])
                # Keep the window open
                subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", 'bash', 'C-m'])
                window_index += 1

    print(f"{GREEN}[*] Commands sent to tmux session.{NC}")
    print(f"{BLUE}[+] Attaching to tmux session: {session_name}{NC}")
    subprocess.call(['tmux', 'attach-session', '-t', session_name])

if __name__ == '__main__':
    main()
