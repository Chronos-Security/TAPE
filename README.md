# **TAPE (Tmux Automated Pentesting Enumeration)**

TAPE is a streamlined tool designed to organize and automate the reconnaissance and enumeration phases of penetration testing. Leveraging the power of `tmux`, TAPE simplifies command execution, output organization, and workflow management for pentesters. It's flexible, efficient, and highly customizable to fit your unique methodology.

---

## **Features**

- Automates reconnaissance and enumeration for various services and protocols.
- Organizes output in neatly structured tmux panes and windows for easier multitasking.
- Offers the flexibility to list commands, execute them selectively, or customize workflows.
- Supports commonly encountered protocols and services, with predefined commands for convenience.
- Allows users to easily add, modify, or extend command sets to match their preferences.

---

## **Installation**

Ensure your system has the required dependencies installed:

### **Prerequisites**
```bash
sudo apt update
sudo apt install -y git tmux seclists ldap-utils nmap hydra gobuster feroxbuster wfuzz curl rustscan
pip install -r requirements.txt
```

### Clone the Repository
```bash
git clone https://github.com/ChronosPK/TAPE.git
cd TAPE
sudo python3 tape.py -h
```

## Usage
TAPE is designed to be simple yet powerful. Below are some common use cases:

### Basic Usage
```bash
# Display help menu
sudo python3 tape.py -h
```

### List All Commands
```bash
sudo python3 tape.py -l
```

### Execute Enumeration
```bash
# Replace the placeholders IP, DOMAIN, or NET with your target specifics
sudo python3 tape.py -i <IP> -x

sudo python3 tape.py -i 10.10.11.14 -x
```

### List Commands for Specific Service
```bash
sudo python3 tape.py -l -s <SERVICE>

sudo python3 tape.py -l -s recon
sudo python3 tape.py -l -s ftp
sudo python3 tape.py -l -s ssh
```

## Customization

TAPE comes preloaded with useful commands for commonly encountered protocols and services. 
You can freely add, modify, or remove commands to match your personal pentesting workflow.

### To Modify Commands:
1. Open tape.py in your favorite text editor.
2. Locate the COMMANDS dictionary.
3. Add or edit the command sets for specific services, grouped by category.

## Example Scenarios

### Reconnaissance

Run an all-TCP scan followed by detailed service enumeration:
```bash
sudo python3 tape.py -i 192.168.1.1 -x
```

### Protocol-Specific Enumeration

List and run commands for FTP enumeration:
```bash
sudo python3 tape.py -s FTP -x
```

## Contribution

**Contributions are welcome!**
Feel free to fork the repository, add your favorite commands, or improve functionality. 
Submit a pull request when you're ready, and let's make TAPE even better together.


## Disclaimer

TAPE is intended for authorized testing and educational purposes only. 
Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical. 
Use responsibly.

### Happy Pentesting!