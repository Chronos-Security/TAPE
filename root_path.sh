#!/bin/bash
# root_path.sh
# This script creates a sudoers drop-in file to append your venv's bin directory
# to secure_path for your user so that "sudo ctape" will work.
#
# Usage:
#   sudo ./root_path.sh /path/to/venv/bin
#
# It creates a file in /etc/sudoers.d/ named "ctape_venv"
# that sets a secure_path for your user (determined via logname).

set -e

# Must be run as root.
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (or via sudo)."
  exit 1
fi

if [ -z "$1" ]; then
  echo "Usage: $0 /path/to/venv/bin"
  exit 1
fi

VENV_BIN="$1"

# Ensure the provided directory exists.
if [ ! -d "$VENV_BIN" ]; then
  echo "Error: Directory '$VENV_BIN' does not exist."
  exit 1
fi

# Determine the original (non-root) user.
# 'logname' usually returns the user who invoked sudo.
ORIG_USER=$(logname 2>/dev/null || echo "$SUDO_USER")
if [ -z "$ORIG_USER" ]; then
  echo "Could not determine the original user."
  exit 1
fi

# Define a base secure_path (adjust if needed).
BASE_SECURE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# We create a drop-in file for sudoers for this user.
SUDOERS_FILE="/etc/sudoers.d/ctape_venv"

# Write the secure_path configuration. This sets the secure_path for only ORIG_USER.
echo "Defaults:${ORIG_USER} secure_path=\"${BASE_SECURE_PATH}:${VENV_BIN}\"" > "$SUDOERS_FILE"

# Set strict permissions (0440) for the sudoers file.
chmod 0440 "$SUDOERS_FILE"

# Validate the file syntax.
if visudo -cf "$SUDOERS_FILE"; then
  echo "Secure path updated for user '$ORIG_USER'."
  echo "New secure_path for sudo for $ORIG_USER is:"
  echo "${BASE_SECURE_PATH}:${VENV_BIN}"
  echo "Now, 'sudo ctape' should work."
else
  echo "Error: The updated sudoers file contains syntax errors. Please check $SUDOERS_FILE."
  exit 1
fi
