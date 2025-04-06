#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################
# TAPE Installation Script                     #
# TAPE - Tmux Automated Pentesting Enumeration #
# Chronos Security                             #
# https://chronos-security.ro                  #
# https://github.com/Chronos-Security          #
################################################

import os
import sys
import re
import shutil
import requests
import argparse
import subprocess
import yaml
from collections import defaultdict
from datetime import datetime
from termcolor import cprint, colored
import colorama
from tabulate import tabulate

# -----------------------------
# Configurations and Variables
# -----------------------------

# Integrate Windows terminal coloring
colorama.init()

BASE_DIR = "/tmp/ctape"
RECON_DIR = os.path.join(BASE_DIR, "recon")
VULNS_DIR = os.path.join(BASE_DIR, "vulns")
FILES_DIR = os.path.join(BASE_DIR, "files")
NOTES_DIR = os.path.join(BASE_DIR, "notes")

directories = [VULNS_DIR, RECON_DIR, FILES_DIR, NOTES_DIR]
files = ["notes.txt", "users.txt", "passwords.txt", "hashes.txt", "creds.txt"]

def create_directories_and_files():
    is_windows = os.name == 'nt'
    os.makedirs(BASE_DIR, exist_ok=True)

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        if not is_windows:
            original_uid = int(os.environ.get('SUDO_UID', os.getuid()))
            original_gid = int(os.environ.get('SUDO_GID', os.getgid()))
            os.chown(directory, original_uid, original_gid)

    for filename in files:
        filepath = os.path.join(NOTES_DIR, filename)
        with open(filepath, 'a'):
            pass
        if not is_windows:
            os.chown(filepath, original_uid, original_gid)

# Updated to support grouped commands
COMMANDS = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
COMMANDS_NET = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

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
    # More will be added in the future
}

# -----------------------------
# Argparser
# -----------------------------

parser = argparse.ArgumentParser(
    description="TAPE - Tmux Automated Pentesting Enumeration",
    formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=35)
)

parser.add_argument('-e', '--env', action='store_true', help='Create the environment with appropriate files and directories')
parser.add_argument('-l', '--list-commands', action='store_true', help='List all available commands')
parser.add_argument('-ls', '--list-services', action='store_true', help='List all available services with their default ports and transport protocols')
parser.add_argument('-s', '--service', help='Specify a service to list commands for')
parser.add_argument('-i', '--ip', help='Set target IP address')
parser.add_argument('-d', '--domain', metavar='DOMAIN', help='Set target domain')
parser.add_argument('-n', '--net', help='Set target network (e.g., 192.168.1.0/24)')
parser.add_argument('-q', '--quiet', action='store_true', help='Suppress command output (commands are echoed by default)')
parser.add_argument('-x', '--execute', action='store_true', help='Execute the enumeration process')
parser.add_argument('-f', '--force-recon', action='store_true', help='Force reconnaissance scans even if already done')
parser.add_argument('-u', '--update', action='store_true', help='Update TAPE to the latest version')
parser.add_argument('--auto', action='store_true', help='Automatically scan all live hosts without confirmation (used with -n)')
args = parser.parse_args()


# -----------------------------
# Function Definitions
# -----------------------------

# YAML commands
def load_commands(yaml_path='commands.yml'):
    with open(yaml_path, 'r') as file:
        return yaml.safe_load(file)

def load_net_commands(yaml_path='commands_net.yml'):
    with open(yaml_path, 'r') as file:
        return yaml.safe_load(file)

COMMANDS_NET = load_net_commands()
COMMANDS = load_commands()


def is_root():
    return os.geteuid() == 0

# ctape -u
def update_script():
    cprint("[+] Checking for updates...", "blue")
    github_url = "https://raw.githubusercontent.com/Chronos-Security/TAPE/main/tape.py"
    try:
        response = requests.get(github_url, timeout=10)
        if response.status_code == 200:
            script_path = os.path.realpath(__file__)
            backup_path = script_path + ".bak"
            shutil.copy2(script_path, backup_path)
            with open(script_path, 'w', encoding='utf-8') as script_file:
                script_file.write(response.text)
            cprint("[+] TAPE has been updated to the latest version.", "green")
            cprint(f"[i] A backup is saved as {backup_path}.", "yellow")
        else:
            cprint(f"[!] Failed to download the latest version. HTTP Status Code: {response.status_code}", "red")
    except Exception as e:
        cprint(f"[!] An error occurred: {e}", "red")

#ctape -f bug
if args.force_recon and not (args.ip or args.domain or args.net):
    cprint("[!] You can't use --force-recon without a target.", "red")
    sys.exit(1)

#ctape -x bug
if args.execute and not (args.ip or args.domain or args.execute):
    cprint("[!] You can't use --execute without a target.", "red")
    sys.exit(1)

# ctape -h
def display_help():
    parser.print_help()

# ctape -i -d
def resolve_domain(domain):
    """Resolve a domain to an IP address using the 'dig' command."""
    if not shutil.which("dig"):
        raise EnvironmentError("The 'dig' command is not available. Please install it or use an alternative method.")
    
    try:
        result = subprocess.check_output(['dig', '+short', domain], text=True)
        ip = result.strip().split('\n')[0]
        if ip:
            return ip
        else:
            return None
    except subprocess.CalledProcessError as e:
        cprint(f"[!] Error resolving domain {domain}: {e}", "red")
        return None


def format_command(command, variables):
    # Replace placeholders without braces
    for key, value in variables.items():
        command = command.replace(key, value)
    return command

#ctape -ls
def list_services():
    """Lists all services with their default ports and transport protocols in a tabular format."""
    cprint("[+] Available Services:\n", "green")
    services_data = []
    for service, details in SERVICES.items():
        ports = ', '.join(map(str, details["ports"]))
        transport = details["transport"]
        services_data.append([service, ports, transport])

    table = tabulate(services_data, headers=["Service", "Ports", "Transport"], tablefmt="github")
    print(table)

# ctape -l
def list_commands(commands, variables, service=None):
    services_to_list = [service.upper()] if service else sorted(
        commands.keys(), key=lambda x: SERVICES.get(x, {}).get('ports', [0])[0]
    )
    for protocol in services_to_list:
        if protocol not in commands:
            continue
        actions = commands[protocol]
        ports = ','.join(map(str, SERVICES.get(protocol, {}).get('ports', ['N/A'])))
        transport = SERVICES.get(protocol, {}).get('transport', 'N/A')
        for action in actions:
            for subaction in actions[action]:
                action_subaction_title = f"{protocol} - {ports}/{transport} - {action} - {subaction}"
                cprint(action_subaction_title, "red", "on_cyan", attrs=["bold", "dark"])
                for cmd_group in actions[action][subaction]:
                    description = cmd_group.get('description', None)
                    cmds = cmd_group.get('commands', [])
                    if description:
                        cprint(f"# {description}", "cyan")
                    for cmd in cmds:
                        cmd_display = format_command(cmd, variables)
                        cprint(cmd_display, "light_grey")
                    print()
# ctape -n
def scan_network(net):
    cprint(f"[*] Scanning network {net} for active hosts...", "cyan")
    try:
        result = subprocess.check_output(
            f"nmap -sn {net}",
            shell=True,
            stderr=subprocess.DEVNULL,
            text=True
        )
        live_hosts = []
        for line in result.splitlines():
            if line.startswith("Nmap scan report for"):
                match = re.search(r'\(([\d\.]+)\)', line)  # caută IP între paranteze
                if match:
                    ip = match.group(1)
                else:
                    ip = line.split()[-1]               
                live_hosts.append(ip)

        if live_hosts:
            cprint(f"[+] Found {len(live_hosts)} active host(s):", "green")
            for ip in live_hosts:
                cprint(f"  └─ {ip}", "yellow")
        else:
            cprint("[!] No active hosts found in network.", "red")

        return live_hosts

    except Exception as e:
        cprint(f"[!] Error during network scan: {e}", "red")
        return []

def enumerate_single_host(ip, variables, COMMANDS):
    recon_path = os.path.join(RECON_DIR, f"{ip}.init")
    alltcp_path = os.path.join(RECON_DIR, f"{ip}.alltcp")

    # Recon
    if os.path.exists(recon_path) and not args.force_recon:
        cprint(f"[*] Reconnaissance already exists for {ip}.", "yellow")
    else:
        cprint(f"[*] Running reconnaissance for {ip}...", "green")
        for cmd in COMMANDS_NET['RECON']['Single Host']['nmap'][0]['commands']:
            cmd_exec = format_command(cmd.replace('IP', ip).replace('RECON_DIR', RECON_DIR), variables)
            if not args.quiet:
                cprint(f"$ {cmd_exec}", "light_yellow")
            run_command(cmd_exec, quiet=args.quiet)

    # Port extraction
    open_ports = []
    if os.path.exists(recon_path):
        with open(recon_path, 'r') as f:
            for line in f:
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0].strip()
                    open_ports.append(port)
    if not open_ports:
        cprint(f"[!] No open ports found on {ip}.", "red")
        return

    variables['OPEN_PORTS'] = ','.join(open_ports)
    cprint(f"[*] Open ports: {variables['OPEN_PORTS']}", "yellow")

    # Parse services
    discovered_services = defaultdict(list)
    if os.path.exists(alltcp_path):
        with open(alltcp_path, 'r') as f:
            for line in f:
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    port = parts[0].split('/')[0]
                    service = parts[2].upper() if len(parts) >= 3 else 'UNKNOWN'
                    discovered_services[service].append(port)
    else:
        cprint(f"[!] No detailed scan output for {ip}.", "red")
        return

    if not discovered_services:
        cprint(f"[!] No services detected for {ip}.", "red")
        return

    # Select commands to run
    commands_to_execute = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for service in discovered_services:
        if service in COMMANDS_NET:
            for action in COMMANDS_NET[service]:
                for subaction in COMMANDS_NET[service][action]:
                    for cmd_group in COMMANDS_NET[service][action][subaction]:
                        commands_to_execute[service][action][subaction].append(cmd_group)
        else:
            cprint(f"[!] No commands found for service: {service}", "yellow")

    # Execute
    if args.execute:
        cprint(f"[*] Executing commands for {ip}...", "green")
        for protocol in commands_to_execute:
            variables['PORT'] = ','.join(discovered_services.get(protocol, []))
            for action in commands_to_execute[protocol]:
                for subaction in commands_to_execute[protocol][action]:
                    title = f"{protocol} - {action} - {subaction}"
                    cprint(title, "red", "on_cyan", attrs=["bold", "dark"])
                    for cmd_group in commands_to_execute[protocol][action][subaction]:
                        desc = cmd_group.get("description")
                        if desc:
                            cprint(f"# {desc}", "cyan")
                        for cmd in cmd_group.get("commands", []):
                            cmd_exec = format_command(cmd, variables)
                            if not args.quiet:
                                cprint(f"$ {cmd_exec}", "light_yellow")
                            run_command(cmd_exec, quiet=args.quiet)


#ctape -q
def run_command(cmd, quiet=False):
    return subprocess.call(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None
    )

# ctape -e
def check_environment():
    if not all(os.path.exists(d) for d in directories):
        cprint("[!] Environment not found in /tmp/ctape", "red")
        cprint("[!] You need to run ctape -e", "yellow")
        sys.exit(1)


def main():
    if args.env:
        if os.path.exists(BASE_DIR) and all(os.path.exists(d) for d in directories):
            cprint("[i] Environment already exists at /tmp/ctape", "yellow")
        else:
            create_directories_and_files()
            cprint("[+] Directories and files have been created in /tmp/ctape", "green")
        sys.exit(0)

    if len(sys.argv) == 1 or any(arg in sys.argv for arg in ['-h', '--help']):
        parser.print_help()
        sys.exit(0)

    if not args.env:
        check_environment()

    variables = {
        'IP': args.ip if args.ip else 'IP',
        'NET': args.net if args.net else 'NET',
        'DOMAIN': args.domain if args.domain else 'DOMAIN',
        'RECON_DIR': RECON_DIR,
        'USER': 'USER',
        'PASS': 'PASS',
    }


    if args.list_services:
        list_services()
        sys.exit(0)

    if args.net:
        ips = scan_network(args.net)
        if not ips:
            sys.exit(1)

        ip_list_path = os.path.join(FILES_DIR, 'live_hosts.txt')
        with open(ip_list_path, 'w') as f:
            f.write('\n'.join(ips))
        cprint(f"[i] Active hosts saved to: {ip_list_path}", "cyan")

        if args.auto:
            selected_ips = ips
        else:
            print()
            cprint("[i] Do you want to scan ports for:", "cyan")
            cprint("  [y] All hosts", "yellow")
            cprint("  [n] None", "yellow")
            cprint("  [s] Select specific IPs", "yellow")

            choice = input("\nYour choice [n/y/s]: ").strip().lower()

            if choice == 'y':
                selected_ips = ips
            elif choice == 's':
                cprint("[?] Enter IPs separated by comma (ex: 192.168.1.10,192.168.1.25):", "cyan")
                user_input = input("IPs: ").strip()
                selected_ips = [ip.strip() for ip in user_input.split(',') if ip.strip() in ips]
                if not selected_ips:
                    cprint("[!] No valid IPs selected. Exiting.", "red")
                    sys.exit(1)
            else:
                cprint("[i] Skipping port scanning.", "cyan")
                sys.exit(0)

        for ip in selected_ips:
            cprint(f"\n[>] Starting enumeration for {ip}", "blue")
            args.ip = ip
            variables['IP'] = ip
            variables['DOMAIN'] = 'DOMAIN'
            variables['URL'] = f"http://{ip}"
            enumerate_single_host(ip, variables, COMMANDS_NET)

        sys.exit(0)

    if args.ip and args.domain:
        resolved_ip = resolve_domain(args.domain)
        if resolved_ip:
            if resolved_ip != args.ip:
                cprint(f"[!] Error: Domain {args.domain} does not resolve to IP {args.ip}.", "red")
                sys.exit(1)
            else:
                variables['IP'] = args.ip
                variables['DOMAIN'] = args.domain
        else:
            cprint(f"[!] Error: Unable to resolve domain {args.domain}.", "red")
            sys.exit(1)

    elif args.domain:
        try:
            resolved_ip = resolve_domain(args.domain)
            if resolved_ip:
                cprint(f"[+] Domain {args.domain} resolved to {resolved_ip}.", "green")
                variables['IP'] = resolved_ip 
                variables['DOMAIN'] = args.domain
            else:
                cprint(f"[!] Could not resolve domain {args.domain}.", "red")
                sys.exit(1)
        except EnvironmentError as e:
            cprint(f"[!] {e}", "red")
            sys.exit(1)

    elif args.ip:
        variables['IP'] = args.ip
        variables['DOMAIN'] = 'DOMAIN'
    else:
        variables['IP'] = 'IP'
        variables['DOMAIN'] = 'DOMAIN'

    if args.update:
        update_script()
        sys.exit(0)

    # Prioritize domain over IP in URL
    variables['URL'] = f"http://{variables['DOMAIN'] if variables['DOMAIN'] != 'DOMAIN' else variables['IP']}"

    # List Commands
    if args.list_commands:
        variables['PORT'] = 'PORT'
        list_commands(COMMANDS, variables, args.service)
        sys.exit(0)

    if args.service and not args.execute:
        variables['PORT'] = 'PORT'
        list_commands(COMMANDS, variables, args.service)
        sys.exit(0)

    if not args.execute:
        variables['PORT'] = 'PORT'
        cprint("[i] Execution flag (-x) not set.", "yellow")
        sys.exit(0)

    if not is_root():
        cprint(f"[!] Please run as root.", "red")
        sys.exit(1)

    # Proceed with execution
    # Check if recon has been done
    recon_done = os.path.exists(os.path.join(RECON_DIR, 'nmap.init'))

    if recon_done and not args.force_recon:
        cprint(f"[*] Reconnaissance scans already completed.", "green")
        cprint(f"[*] Use --force-recon to run reconnaissance scans again.", "yellow")
    else:
        cprint(f"[*] Running reconnaissance scans...", "green")
        variables['PORT'] = ''
        # Execute the first RECON command group
        recon_commands = COMMANDS['RECON']['Single Host']['nmap'][0]['commands']
        desc = COMMANDS['RECON']['Single Host']['nmap'][0]['description']
        if not args.quiet:
            cprint("RECON", "red")
            cprint(" - ")
            cprint(desc, "cyan")
        for cmd in recon_commands:
            cmd_exec = format_command(cmd, variables)
            if not args.quiet:
                cmd_display = cmd_exec
                cprint(f"$ {cmd_display}", "light_yellow")
            run_command(cmd_exec, quiet=args.quiet)

    # Continue with parsing open ports
    if os.path.exists(os.path.join(RECON_DIR, 'nmap.init')):
        cprint(f"[*] Extracting open ports...", "green")
        open_ports = []
        with open(os.path.join(RECON_DIR, 'nmap.init'), 'r') as f:
            for line in f:
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0].strip()
                    open_ports.append(port)
        if not open_ports:
            cprint(f"[!] No open ports found on {variables['IP']}.", "red")
            sys.exit(1)
        variables['OPEN_PORTS'] = ','.join(open_ports)
        cprint("[*] Open ports: ", "green", end="") 
        cprint(variables['OPEN_PORTS'], "yellow")
    else:
        cprint("[!] Reconnaissance scans did not produce expected output.", "red")
        sys.exit(1)

    # Parse services from detailed Nmap output
    cprint("[*] Parsing services from Nmap output...", "green")
    discovered_services = defaultdict(list)
    # if not os.path.exists(RECON_DIR, 'ports') or os.stat(RECON_DIR, 'ports').st_size == 0:
    #     cprint("[!] No ports found in initial scan. Exiting...", "red")
    #     sys.exit(1)
    if os.path.exists(os.path.join(RECON_DIR, 'nmap.init')):
        with open(os.path.join(RECON_DIR, 'nmap.init'), 'r') as f:
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
        cprint("[!] Detailed Nmap scan output not found.", "yellow")
        sys.exit(1)
    if not discovered_services:
        cprint(f"[!] No services found.", "red")
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
            cprint(f"[!] No commands found for service: {service}", "yellow")

    # Update variables with URL
    variables['URL'] = f"http://{variables['DOMAIN'] if variables['DOMAIN'] != 'DOMAIN' else variables['IP']}"

    # Show commands unless quiet
    if not args.quiet:
        list_commands(commands_to_execute, variables)

    if args.execute:
        cprint(f"[*] Executing service enumeration commands...", "green")
        for protocol in commands_to_execute:
            variables['PORT'] = ','.join(discovered_services.get(protocol, []))
            ports = ','.join(discovered_services.get(protocol, []))
            transport = SERVICES.get(protocol, {}).get('transport', 'N/A')

            for action in commands_to_execute[protocol]:
                for subaction in commands_to_execute[protocol][action]:
                    title = f"{protocol} - {ports}/{transport} - {action} - {subaction}"
                    cprint(title, "red", "on_cyan", attrs=["bold", "dark"])
                    for cmd_group in commands_to_execute[protocol][action][subaction]:
                        desc = cmd_group.get("description")
                        if desc:
                            cprint(f"# {desc}", "cyan")
                        for cmd in cmd_group.get("commands", []):
                            cmd_exec = format_command(cmd, variables)
                            if not args.quiet:
                                cprint(f"$ {cmd_exec}", "light_yellow")
                            run_command(cmd_exec, quiet=args.quiet)
                            
                    print()
if __name__ == '__main__':
    main()