#!/bin/bash


# Using this is easy to mantain and add things then using the bash -e

# Enable error handling and pipefail option


# Function to log informational messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]: $1"
}

# Function to handle errors
error_handling() {
    local error_message="$1"
    local exit_code=${2-1}  # default exit code is 1
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR]: $error_message"
    exit "$exit_code"
}

# Function to check command success
check_success() {
    local message="$1"
    if [ $? -eq 0 ]; then
        log "$message succeeded"
    else
        error_handling "$message failed"
    fi
}

# Set USER variable to your user
USER="user" # Replace <your_user_here> with your username

# Installing Oh My Zsh
log "Installing Oh My Zsh"
if wget -q -O ohmyzsh-install.sh https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh; then
    bash ohmyzsh-install.sh > /dev/null || error_handling "Failed to install Oh My Zsh"
    rm ohmyzsh-install.sh
else
    error_handling "Failed to download Oh My Zsh install script"
fi

# Clone and setup Pwndbg
log "Installing Pwndbg"
if git clone --depth=1 https://github.com/pwndbg/pwndbg; then
    pushd pwndbg > /dev/null || error_handling "Failed to change directory to Pwndbg"
    chmod +x setup.sh
    echo 'y' | ./setup.sh || error_handling "Failed to setup Pwndbg"
    popd > /dev/null
    rm -rf pwndbg
else
    error_handling "Failed to clone Pwndbg"
fi

# Setup GEF
log "Installing GEF"
if bash -c "$(wget https://gef.blah.cat/sh -O -)"; then
    wget -q -O gef-extras.sh https://raw.githubusercontent.com/hugsy/gef/main/scripts/gef-extras.sh || error_handling "Failed to download GEF extras script"
    bash ./gef-extras.sh
    rm gef-extras.sh
else
    error_handling "Failed to install GEF"
fi

# Update PATH in .zshrc
log "Updating PATH in .zshrc"
echo "export PATH=/home/$USER/.local/bin/:${PATH}" >> /home/$USER/.zshrc || error_handling "Failed to update PATH in .zshrc"

log "Installation complete."
