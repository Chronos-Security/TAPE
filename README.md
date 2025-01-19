# TAPE - Tmux Automated Pentesting Enumeration

TAPE is a powerful pentesting enumeration tool that automates reconnaissance and enumeration tasks, leveraging the flexibility of tmux to provide an efficient workflow for penetration testers. TAPE simplifies the process of running and managing multiple commands across a variety of services and protocols, all within a clean and customizable environment.

---

## Features

- **Automated Reconnaissance:** Automatically scans networks and extracts open ports.
- **Service Enumeration:** Supports multiple protocols and services, with predefined commands for various scenarios.
- **Command Listing:** View all commands globally or filter them by service or action.
- **Flexible Execution Options:** Run commands interactively or list them without execution.
- **Tmux Integration:** Automatically organizes tasks in tmux windows, categorized by protocol and action.

---

## Installation

### Prerequisites
Ensure you have the following tools installed on your system:
- Python 3.8+
- `pip` (Python package manager)
- `tmux` (Linux only, for terminal multiplexing)

### Installation Steps

1. **Clone the Repository**
    ```bash
    git clone https://github.com/ChronosPK/TAPE.git
    cd TAPE
    ```

2. **Run the Installation Script**
    Execute the `install.sh` script to automatically install dependencies and set up TAPE:
    ```bash
    sudo ./install.sh
    ```

    This script performs the following actions:
    - Updates system packages.
    - Installs required tools and dependencies (e.g., `tmux`, `nmap`, `gobuster`).
    - Sets up Python packages required for TAPE.
    - Adds TAPE to your system PATH for global usage.

3. **Verify Installation**
    After running the script, verify that TAPE is installed:
    ```bash
    tape -h
    ```

---

## Usage

### Command-line Arguments

```bash
tape

usage: tape [-h] [-e] [-l] [-ls] [-s SERVICE] [-i IP] [-d DOMAIN] [-n NET] [-q] [-x] [-f] [-u]

TAPE - Tmux Automated Pentesting Enumeration

options:
  -h, --help                     show this help message and exit
  -e, --env                      Create the environment with appropriate files and directories
  -l, --list-commands            List all available commands
  -ls, --list-services           List all available services with their default ports and transport protocols
  -s SERVICE, --service SERVICE  Specify a service to list commands for
  -i IP, --ip IP                 Set target IP address
  -d DOMAIN, --domain DOMAIN     Set target domain
  -n NET, --net NET              Set target network (e.g., 192.168.1.0/24)
  -q, --quiet                    Suppress command output (commands are echoed by default)
  -x, --execute                  Execute the enumeration process
  -f, --force-recon              Force reconnaissance scans even if already done
  -u, --update                   Update TAPE to the latest version
```

### Examples

1. **List All Commands**
    ```bash
    tape -l
    ```

2. **Run Reconnaissance on a Target IP**
    ```bash
    tape -i 192.168.1.1 -x
    ```

3. **Specify a Service for Enumeration**
    ```bash
    tape -s FTP -i 192.168.1.1
    ```

4. **Quiet Mode**
    Suppress command output during execution:
    ```bash
    tape -i 192.168.1.1 -x -q
    ```

5. **Combine IP and Domain for Verification**
    ```bash
    tape -i 192.168.1.1 -d example.com
    ```

6. **Force Reconnaissance**
    ```bash
    tape -i 192.168.1.1 -f
    ```

---

## Why Use TAPE?

TAPE provides a structured and streamlined approach to pentesting enumeration, addressing common challenges faced by security professionals:
- **Efficiency:** Automates repetitive tasks, saving time and effort.
- **Organization:** Leverages tmux to keep processes organized in separate windows.
- **Flexibility:** Allows users to customize commands and choose specific actions.
- **Cross-Platform Compatibility:** Works on Linux and Windows systems with appropriate dependencies.

---

## Supported Protocols and Services

TAPE includes predefined commands for the following:
- **Reconnaissance:** Nmap, Rustscan, Autorecon, etc.
- **FTP:** Anonymous login checks, brute force, directory listing.
- **HTTP/HTTPS:** Directory fuzzing, file fuzzing, parameter fuzzing.
- **SMB:** Share enumeration, user enumeration.
- **DNS:** Zone transfers, DNS enumeration.
- **MySQL:** Database brute force, SQL queries.

---

## Contribution

We welcome contributions from the community! If you have ideas for improvements or additional features, feel free to fork the repository and submit a pull request.

---

## License

TAPE is released under the MIT License. See the LICENSE file for details.

---

## Contact

For questions or support, please open an issue on the GitHub repository or contact the Chronos Security team.

Happy Hacking!
