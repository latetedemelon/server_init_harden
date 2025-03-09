#!/bin/sh
#
# init-linux-harden.sh - Linux Server Hardening Script v2.0
# This script automates security hardening for Linux servers.
# It hardens SSH, configures Fail2ban and UFW, creates new users,
# resets root password, and now optionally installs additional security tools.
#
# New options:
#    -m, --minio      Install Minio binary and update firewall/Fail2ban rules for it
#    -o, --ossec      Install and configure OSSEC (HIDS)
#    -l, --logwatch   Install Logwatch and schedule daily reports
#    -g, --glances    Install Glances and configure Discord notifications (requires DISCORD_WEBHOOK_URL env var)
#    -k, --kopia      Install and configure Kopia for backups to Backblaze B2 (requires B2_ACCOUNT_ID, B2_APPLICATION_KEY, KOPIA_REPO_PASSPHRASE)
#    -c, --chrony     Install and configure Chrony for time synchronization
#    -t, --optimize   Optimize apt repositories using netselect-apt
#
# Existing options:
#    -u USERNAME      Create a new sudo user
#    -r               Reset root password to a secure random value
#    -s               Show sensitive information (passwords, keys) in console output
#    -h, --help       Display this help message
#

SCRIPT_NAME=linux_init_harden
SCRIPT_VERSION=2.99
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
LOGFILE_NAME="${SCRIPT_NAME}_${TIMESTAMP}.log"
SHOW_CREDENTIALS=false
START_TIME=$(date +%s)

# Global variables for username and root-reset flag
USERNAME=""
RESET_ROOT=false

# New optional feature flags
INSTALL_MINIO=false
INSTALL_OSSEC=false
INSTALL_LOGWATCH=false
INSTALL_GLANCES=false
INSTALL_KOPIA=false
INSTALL_TIME_SYNC=false
OPTIMIZE_REPOS=false

#############################################
# Usage Information
#############################################
usage() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}
A script to harden Linux server security configurations

USAGE:
    $0 [OPTIONS]

DESCRIPTION:
    This script performs several security hardening operations on a Linux server:
      - Hardens SSH configuration (disables root login, password authentication)
      - Configures Fail2ban for intrusion prevention (including a recidive jail)
      - Creates a new user with sudo access (optional)
      - Generates secure SSH keys
      - Resets the root password (optional)
      - Sets up UFW firewall rules
      - Configures unattended-upgrades for automated security patches

Additional optional features:
      -m, --minio      Install Minio binary and update UFW & Fail2ban (Minio jail)
      -o, --ossec      Install and configure OSSEC (HIDS)
      -l, --logwatch   Install Logwatch and schedule daily reports
      -g, --glances    Install Glances and configure Discord notifications (requires DISCORD_WEBHOOK_URL)
      -k, --kopia      Install and configure Kopia for backups (requires B2_ACCOUNT_ID, B2_APPLICATION_KEY, KOPIA_REPO_PASSPHRASE)
      -c, --chrony     Install and configure Chrony for time synchronization
      -t, --optimize   Optimize apt repositories using netselect-apt

OPTIONS:
    -u USERNAME     Create a new sudo user with the specified username
    -r              Reset the root password to a secure random value
    -s              Show sensitive information (passwords, keys) in console output
    -h, --help      Display this help message

EXAMPLES:
    # Basic hardening (SSH, Fail2ban, UFW)
    $0

    # Create new sudo user during hardening
    $0 -u jay

    # Create new user and reset root password
    $0 -u jay -r

    # Enable additional security options (e.g., Minio, OSSEC, Logwatch, Glances, Kopia, Chrony, Optimize repos)
    $0 -m -o -l -g -k -c -t

LOGGING:
    All operations are logged to: ./${SCRIPT_NAME}_TIMESTAMP.log
    Sensitive information is logged to file by default (use -s flag to display in console)

NOTES:
    - Requires root/sudo privileges
    - Backs up modified configuration files
    - On failure, configurations may be reverted

For bug reports and contributions:
    https://github.com/pratiktri/server-init-harden
EOF
    exit 1
}

#############################################
# Command-line argument parsing
#############################################
parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
        -u|--username)
            if [ -n "$2" ] && echo "$2" | grep -qE '^[a-zA-Z][a-zA-Z0-9_-]*$'; then
                USERNAME="$2"
                shift 2
            else
                console_log "Error" "Invalid username format. Must start with a letter and contain only alphanumeric characters, hyphens, or underscores."
                exit 1
            fi
            ;;
        -r|--reset-root)
            RESET_ROOT=true
            shift
            ;;
        -s)
            SHOW_CREDENTIALS=true
            shift
            ;;
        -m|--minio)
            INSTALL_MINIO=true
            shift
            ;;
        -o|--ossec)
            INSTALL_OSSEC=true
            shift
            ;;
        -l|--logwatch)
            INSTALL_LOGWATCH=true
            shift
            ;;
        -g|--glances)
            INSTALL_GLANCES=true
            shift
            ;;
        -k|--kopia)
            INSTALL_KOPIA=true
            shift
            ;;
        -c|--chrony)
            INSTALL_TIME_SYNC=true
            shift
            ;;
        -t|--optimize)
            OPTIMIZE_REPOS=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            console_log "Error" "Unknown option: $1"
            exit 1
            ;;
        esac
    done
}

###########################################################################################
################################### HELPER FUNCTIONS ######################################
###########################################################################################

# Console logging function
console_log() {
    case "$1" in
    Success|SUCCESS)
        printf "[\033[0;32m  OK   \033[0m] %s\n" "$2" ;;
    Error|ERROR)
        printf "[\033[0;31m FAIL  \033[0m] %s\n" "$2" ;;
    Warning|WARNING)
        printf "[\033[0;33m WARN  \033[0m] %s\n" "$2" ;;
    Info|INFO)
        printf "[\033[0;34m INFO  \033[0m] %s\n" "$2" ;;
    CREDENTIALS)
        printf "[\033[0;30m CREDS \033[0m] %s\n" "$2" ;;
    *)
        printf "[     ] %s\n" "$2" ;;
    esac
}

# Create log file
create_logfile() {
    touch "$LOGFILE_NAME"
}

# Write a message to the log file with timestamp
file_log() {
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf "%s: %s\n" "$timestamp" "$1" >> "$LOGFILE_NAME"
}

# Log credentials to file and optionally to console
log_credentials() {
    message="$1"
    file_log "$message"
    if [ "$SHOW_CREDENTIALS" = true ]; then
        console_log "CREDENTIALS" "$message"
    fi
}

# Display log file information
show_log_info() {
    printf "\nLog file location: %s\n" "$LOGFILE_NAME"
    printf "To view the log file, try:\n  cat %s\n  tail -f %s\n\n" "$LOGFILE_NAME" "$LOGFILE_NAME"
}

# Format duration for display
format_duration() {
    duration=$1
    days=$((duration / 86400))
    hours=$(((duration % 86400) / 3600))
    minutes=$(((duration % 3600) / 60))
    seconds=$((duration % 60))
    if [ "$days" -gt 0 ]; then
        echo "${days}d ${hours}h ${minutes}m ${seconds}s"
    elif [ "$hours" -gt 0 ]; then
        echo "${hours}h ${minutes}m ${seconds}s"
    elif [ "$minutes" -gt 0 ]; then
        echo "${minutes}m ${seconds}s"
    else
        echo "${seconds}s"
    fi
}

# Helper function to manage services
manage_service() {
    service_name="$1"
    action="$2"
    if command -v systemctl >/dev/null 2>&1; then
        output=$(systemctl "$action" "$service_name" 2>&1)
        ret=$?
        [ -n "$output" ] && file_log "systemctl $action output: $output"
        return $ret
    elif command -v service >/dev/null 2>&1; then
        output=$(service "$service_name" "$action" 2>&1)
        ret=$?
        [ -n "$output" ] && file_log "service $action output: $output"
        return $ret
    else
        file_log "No suitable service manager found for $service_name"
        return 1
    fi
}

###########################################################################################
################################ NEW FEATURE FUNCTIONS ##################################
###########################################################################################

configure_unattended_upgrades() {
    echo -e "\n[+] Configuring unattended-upgrades for automated security updates..."
    sudo tee /etc/apt/apt.conf.d/50unattended-upgrades >/dev/null <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF
    file_log "Unattended-upgrades configured."
}

install_minio() {
    echo -e "\n[+] Installing Minio binary..."
    wget -qO /usr/local/bin/minio https://dl.min.io/server/minio/release/linux-amd64/minio
    sudo chmod +x /usr/local/bin/minio
    file_log "Minio installed at /usr/local/bin/minio."
}

update_firewall_minio() {
    echo -e "\n[+] Adding UFW rule for Minio on port ${MINIO_PORT}..."
    sudo ufw allow "${MINIO_PORT}/tcp"
    file_log "UFW rule for Minio added on port ${MINIO_PORT}."
}

configure_fail2ban_minio() {
    echo -e "\n[+] Adding Fail2Ban jail for Minio..."
    sudo sh -c "cat <<EOF >> /etc/fail2ban/jail.local

[minio]
enabled  = true
port     = ${MINIO_PORT}
filter   = minio
logpath  = /var/log/minio.log
maxretry = 5
bantime  = 2592000  # 30 days
EOF"
    if [ ! -f /etc/fail2ban/filter.d/minio.conf ]; then
        sudo sh -c "cat <<EOF > /etc/fail2ban/filter.d/minio.conf
[Definition]
failregex = .*minio.*authentication failure.*
ignoreregex =
EOF"
    fi
    file_log "Fail2Ban jail for Minio configured."
}

install_ossec() {
    echo -e "\n[+] Installing OSSEC HIDS..."
    install_package "ossec-hids"
    sudo cp /var/ossec/etc/ossec.conf.example /var/ossec/etc/ossec.conf
    file_log "OSSEC installed; review /var/ossec/etc/ossec.conf for alert settings."
}

install_logwatch() {
    echo -e "\n[+] Installing Logwatch..."
    install_package "logwatch"
    sudo sh -c 'cat <<EOF >/etc/cron.daily/logwatch
#!/bin/sh
/usr/sbin/logwatch --detail high --mailto root --service all --range today
EOF'
    sudo chmod +x /etc/cron.daily/logwatch
    file_log "Logwatch installed and daily report scheduled."
}

configure_glances_discord() {
    echo -e "\n[+] Installing Glances..."
    install_package "glances"
    if [ -z "$DISCORD_WEBHOOK_URL" ]; then
        file_log "DISCORD_WEBHOOK_URL not set; skipping Discord integration for Glances."
    else
        file_log "Configuring Discord notifications for Glances..."
        sudo sh -c 'cat <<EOF >/usr/local/bin/glances_discord.sh
#!/bin/sh
# Check load average and send Discord alert if load exceeds threshold (2.0)
LOAD=$(awk "{print \$1}" /proc/loadavg)
THRESHOLD=2.0
if [ $(echo "$LOAD > $THRESHOLD" | bc -l) -eq 1 ]; then
    curl -H "Content-Type: application/json" -X POST -d "{\"content\": \"Alert: High load average detected: \$LOAD\"}" "'"$DISCORD_WEBHOOK_URL"'"
fi
EOF'
        sudo chmod +x /usr/local/bin/glances_discord.sh
        (sudo crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/glances_discord.sh >/dev/null 2>&1") | sudo crontab -
        file_log "Glances with Discord notifications configured."
    fi
}

install_lynis() {
    echo -e "\n[+] Installing Lynis..."
    install_package "lynis"
    (sudo crontab -l 2>/dev/null; echo "0 3 * * 0 /usr/bin/lynis audit system --quiet") | sudo crontab -
    file_log "Lynis installed and weekly audit scheduled."
}

install_kopia() {
    echo -e "\n[+] Installing Kopia backup tool..."
    curl -sSL https://kopia.io/installer | sudo sh
    if [ -z "$B2_ACCOUNT_ID" ] || [ -z "$B2_APPLICATION_KEY" ] || [ -z "$KOPIA_REPO_PASSPHRASE" ]; then
        file_log "Backblaze B2 credentials or repository passphrase not set; please configure manually."
    else
        sudo -u "$(whoami)" kopia repository create b2 --b2-account-id "$B2_ACCOUNT_ID" --b2-application-key "$B2_APPLICATION_KEY" --path /var/backups/kopia --passphrase "$KOPIA_REPO_PASSPHRASE"
        file_log "Kopia repository created. Consider adding a cron job for regular backups."
    fi
}

configure_time_sync() {
    echo -e "\n[+] Installing and configuring Chrony for time synchronization..."
    install_package "chrony"
    sudo systemctl enable chrony
    sudo systemctl start chrony
    file_log "Chrony installed and running."
}

optimize_repos() {
    echo -e "\n[+] Optimizing apt repository mirrors..."
    install_package "netselect-apt"
    # Determine Ubuntu codename
    UBUNTU_CODENAME=$(. /etc/os-release && echo "$UBUNTU_CODENAME")
    sudo netselect-apt -n "$UBUNTU_CODENAME"
    if [ -f sources.list ]; then
        sudo mv sources.list /etc/apt/sources.list
        file_log "APT sources list updated to use the fastest mirror."
    else
        file_log "netselect-apt did not generate a new sources.list; please review manually."
    fi
}

###########################################################################################
################################### MAIN OPERATIONS #######################################
###########################################################################################

# Original helper functions: create_logfile, show_log_info, console_log, file_log, log_credentials, format_duration, manage_service, etc.
# (They remain unchanged from the original script.)

reset_root_password() {
    file_log "Attempting to reset root password"
    ROOT_PASSWORD=$(head -c 12 /dev/urandom | base64 | tr -dc "[:alnum:]" | head -c 15)
    output=$(printf "%s\n%s\n" "${ROOT_PASSWORD}" "${ROOT_PASSWORD}" | passwd root 2>&1)
    if [ $? -ne 0 ]; then
        console_log "Error" "Failed to reset root password"
        file_log "Failed to reset root password: $output"
        return 1
    fi
    log_credentials "New root password: $ROOT_PASSWORD"
    return 0
}

revert_create_user() {
    file_log "Attempting to remove user $USERNAME"
    if id "$USERNAME" >/dev/null 2>&1; then
        output=$(userdel -r "$USERNAME" 2>&1)
        if [ $? -eq 0 ]; then
            file_log "User $USERNAME removed successfully"
            return 0
        else
            file_log "Failed to remove user $USERNAME: $output"
            return 1
        fi
    else
        file_log "No user $USERNAME found to remove"
        return 0
    fi
}

create_user() {
    if id "$USERNAME" >/dev/null 2>&1; then
        file_log "User $USERNAME already exists"
        return 1
    fi
    USER_PASSWORD=$(head -c 12 /dev/urandom | base64 | tr -dc "[:alnum:]" | head -c 15)
    file_log "Creating user $USERNAME"
    output=$(printf '%s\n%s\n' "${USER_PASSWORD}" "${USER_PASSWORD}" | adduser "$USERNAME" -q --gecos "First Last,Room,Work,Home" 2>&1)
    if [ $? -ne 0 ]; then
        file_log "Failed to create user $USERNAME"
        return 1
    fi
    output=$(usermod -aG sudo "$USERNAME" 2>&1)
    file_log "User $USERNAME created and added to sudo group"
    log_credentials "$USERNAME's - Password: $USER_PASSWORD"
    return 0
}

generate_ssh_key() {
    target_user="$1"
    console_log "INFO" "Generating SSH key for user: $target_user..."
    file_log "Generating SSH key for user: $target_user"
    home_dir=$(eval echo "~$target_user")
    if [ ! -d "$home_dir" ]; then
        console_log "ERROR" "Home directory not found for user: $target_user"
        file_log "Home directory not found for user: $target_user"
        return 1
    fi
    ssh_dir="$home_dir/.ssh"
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        chown "$target_user:$target_user" "$ssh_dir"
        chmod 700 "$ssh_dir"
        file_log "Created .ssh directory: $ssh_dir"
    fi
    key_passphrase=$(head -c 12 /dev/urandom | base64 | tr -dc "[:alnum:]" | head -c 15)
    key_name="id_${target_user}_ed25519"
    key_path="$ssh_dir/$key_name"
    file_log "Generating SSH key for $target_user"
    if ! output=$(su -c "ssh-keygen -o -a 1000 -t ed25519 -f '$key_path' -N '$key_passphrase'" - "$target_user" 2>&1); then
        console_log "ERROR" "Failed to generate SSH key for user: $target_user"
        file_log "ssh-keygen failed: $output"
        return 1
    fi
    chmod 600 "$key_path"
    chmod 644 "$key_path.pub"
    authorized_keys="$ssh_dir/authorized_keys"
    cat "$key_path.pub" >> "$authorized_keys"
    chmod 400 "$authorized_keys"
    chown "$target_user:$target_user" "$authorized_keys"
    file_log "SSH key generated for $target_user at $key_path"
    console_log "Success" "SSH key generated for user: $target_user"
    log_credentials "SSH key details for $target_user:"
    log_credentials "Passphrase: $key_passphrase"
    log_credentials "Private key:" "$(cat "$key_path")"
    log_credentials "Public key:" "$(cat "$key_path.pub")"
    return 0
}

update_ssh_setting() {
    setting="$1"
    value="$2"
    sed -i "s/^${setting}/#${setting}/" "$SSHD_CONFIG"
    echo "${setting} ${value}" >> "$SSHD_CONFIG"
    file_log "Updated SSH setting: ${setting} ${value}"
}

harden_ssh_config() {
    console_log "INFO" "Hardening SSH configuration..."
    file_log "Starting SSH configuration hardening"
    SSHD_CONFIG="/etc/ssh/sshd_config"
    if [ ! -f "$SSHD_CONFIG" ]; then
        console_log "ERROR" "SSH config file not found at $SSHD_CONFIG"
        file_log "SSH config file not found at $SSHD_CONFIG"
        return 1
    fi
    BACKUP_FILE="${SSHD_CONFIG}.bak.${TIMESTAMP}"
    cp "$SSHD_CONFIG" "$BACKUP_FILE"
    file_log "Created backup of sshd_config at: $BACKUP_FILE"
    update_ssh_setting "PermitRootLogin" "no"
    update_ssh_setting "PasswordAuthentication" "no"
    update_ssh_setting "PubkeyAuthentication" "yes"
    update_ssh_setting "AuthorizedKeysFile" ".ssh/authorized_keys"
    console_log "Success" "SSH configuration hardening completed"
    file_log "SSH configuration hardening completed"
    if manage_service sshd restart || manage_service ssh restart; then
        console_log "Success" "SSH service restarted successfully"
        file_log "SSH service restarted successfully"
        return 0
    fi
    console_log "ERROR" "Failed to restart SSH service; reverting to backup..."
    cp "$BACKUP_FILE" "$SSHD_CONFIG"
    if manage_service sshd restart || manage_service ssh restart; then
        console_log "Success" "SSH service restarted with original configuration"
        file_log "SSH service restarted with original configuration"
        exit 1
    fi
    console_log "ERROR" "Failed to restart SSH service even with original configuration"
    file_log "Failed to restart SSH service even with original configuration"
    exit 1
}

install_package() {
    if [ $# -eq 0 ]; then
        file_log "No package specified for installation"
        return 1
    fi
    PACKAGE_NAME="$1"
    if [ -f /etc/debian_version ] || [ -f /etc/ubuntu_version ]; then
        file_log "Installing $PACKAGE_NAME using apt..."
        output=$(DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y $PACKAGE_NAME 2>&1)
        ret=$?
    elif [ -f /etc/fedora-release ]; then
        file_log "Installing $PACKAGE_NAME using dnf..."
        output=$(dnf makecache && dnf install -y $PACKAGE_NAME 2>&1)
        ret=$?
    elif [ -f /etc/freebsd-update.conf ]; then
        file_log "Installing $PACKAGE_NAME using pkg..."
        output=$(pkg update && pkg install -y $PACKAGE_NAME 2>&1)
        ret=$?
    else
        file_log "Unsupported operating system"
        return 1
    fi
    [ -n "$output" ] && file_log "Installation output: $output"
    if [ $ret -ne 0 ]; then
        file_log "Failed to install package: $PACKAGE_NAME"
        return 1
    fi
    file_log "Successfully installed package: $PACKAGE_NAME"
    return 0
}

configure_ufw() {
    console_log "INFO" "Configuring UFW firewall..."
    file_log "Starting UFW configuration"
    ufw allow ssh
    ufw allow http
    ufw allow https
    output=$(echo "y" | ufw enable 2>&1)
    file_log "ufw enable output: $output"
    output=$(ufw status 2>&1)
    file_log "ufw status: $output"
    echo "$output" | grep -q "Status: active" || {
        console_log "ERROR" "UFW did not enable properly"
        file_log "UFW did not enable properly"
        return 1
    }
    console_log "Success" "UFW configured successfully"
    file_log "UFW configuration completed successfully"
    return 0
}

set_jail_local_setting() {
    search_term="$1"
    new_value="$2"
    range_start="^\[DEFAULT\]$"
    range_end="^# JAILS$"
    if sed -n "/${range_start}/,/${range_end}/p" "$JAIL_LOCAL" | grep -q "^${search_term}[[:blank:]]*="; then
        sed -ri "/${range_start}/,/${range_end}/ s/^(${search_term}[[:blank:]]*=.*)/#\1/" "$JAIL_LOCAL"
        sed -ri "/${range_start}/,/${range_end}/ s/^#${search_term}[[:blank:]]*=.*/&\n${search_term} = ${new_value}/" "$JAIL_LOCAL"
    else
        sed -ri "/${range_start}/,/${range_end}/ s/^#${search_term}[[:blank:]]*=.*/&\n${search_term} = ${new_value}/" "$JAIL_LOCAL"
    fi
}

configure_fail2ban() {
    console_log "INFO" "Configuring Fail2ban..."
    file_log "Starting Fail2ban configuration"
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        file_log "Fail2ban not installed"
        return 1
    fi
    JAIL_LOCAL="/etc/fail2ban/jail.local"
    DEFAULT_JAIL_CONF="/etc/fail2ban/jail.conf"
    CUSTOM_JAILS="/etc/fail2ban/jail.d/custom-enabled.conf"
    if [ -f "$JAIL_LOCAL" ]; then
        JAIL_LOCAL_BACKUP="${JAIL_LOCAL}.bak.${TIMESTAMP}"
        cp "$JAIL_LOCAL" "$JAIL_LOCAL_BACKUP"
        file_log "Backup of jail.local created at $JAIL_LOCAL_BACKUP"
    else
        if [ -f "$DEFAULT_JAIL_CONF" ]; then
            cp "$DEFAULT_JAIL_CONF" "$JAIL_LOCAL"
            file_log "jail.local created from jail.conf"
        else
            console_log "ERROR" "No jail configuration file found"
            file_log "No jail configuration file found"
            return 1
        fi
    fi
    file_log "Attempting to determine server public IP"
    output=$(curl -s -4 ifconfig.me 2>&1 || curl -s -4 icanhazip.com 2>&1 || curl -s -4 ipinfo.io/ip 2>&1)
    if [ -z "$output" ]; then
        console_log "ERROR" "Could not determine public IP"
        file_log "Could not determine public IP"
        PUBLIC_IP=""
    else
        PUBLIC_IP="$output"
        file_log "Server public IP: $PUBLIC_IP"
    fi
    set_jail_local_setting "bantime" "5h"
    set_jail_local_setting "backend" "systemd"
    set_jail_local_setting "ignoreip" "127.0.0.1\/8 ::1 $PUBLIC_IP"
    file_log "Enabling jails in $CUSTOM_JAILS"
    cat <<FAIL2BAN >$CUSTOM_JAILS
[sshd]
enabled = true
filter = sshd
bantime = 1d
maxretry = 3

[nginx-http-auth]
enabled = true
logpath = /var/log/nginx/error.log
maxretry = 3

[recidive]
enabled = true
filter = recidive
findtime = 1d
bantime  = 30d
maxretry = 50
FAIL2BAN
    if ! manage_service fail2ban restart; then
        console_log "ERROR" "Failed to restart Fail2ban"
        file_log "Failed to restart Fail2ban"
        if [ -f "$JAIL_LOCAL_BACKUP" ]; then
            console_log "INFO" "Reverting jail.local to backup..."
            cp "$JAIL_LOCAL_BACKUP" "$JAIL_LOCAL"
        else
            rm -f "$JAIL_LOCAL"
        fi
        if [ -f "$CUSTOM_JAILS" ]; then
            rm -f "$CUSTOM_JAILS"
        fi
        if ! manage_service fail2ban restart; then
            console_log "ERROR" "Failed to restart Fail2ban with original configuration"
            file_log "Failed to restart Fail2ban with original configuration"
            exit 1
        fi
        console_log "INFO" "Fail2ban restarted with original configuration"
        file_log "Fail2ban restarted with original configuration"
        exit 1
    fi
    console_log "Success" "Fail2ban configured successfully"
    file_log "Fail2ban configuration completed successfully"
    return 0
}

###########################################################################################
#################################### MAIN EXECUTION #######################################
###########################################################################################

main() {
    parse_args "$@"
    create_logfile
    show_log_info
    console_log "INFO" "Starting ${SCRIPT_NAME} v${SCRIPT_VERSION}"
    file_log "Starting ${SCRIPT_NAME} v${SCRIPT_VERSION}"

    # Step 1: Reset root password if requested
    if [ "$RESET_ROOT" = true ]; then
        console_log "INFO" "Resetting root password..."
        reset_root_password
    fi

    # Step 2: Create new user if username is provided
    if [ -n "$USERNAME" ]; then
        console_log "INFO" "Creating new user..."
        create_user
    fi

    # Step 3: Generate SSH key for user (new or current)
    if [ -n "$USERNAME" ]; then
        if ! generate_ssh_key "$USERNAME"; then
            console_log "ERROR" "Failed to generate SSH key for user: $USERNAME"
            show_log_info
            exit 1
        fi
    else
        CURRENT_USER=$(whoami)
        if ! generate_ssh_key "$CURRENT_USER"; then
            console_log "ERROR" "Failed to generate SSH key for current user: $CURRENT_USER"
            show_log_info
            exit 1
        fi
    fi

    # Step 4: Harden SSH configuration
    if ! harden_ssh_config; then
        show_log_info
        exit 1
    fi

    # Step 5: Install required packages
    console_log "INFO" "Installing required packages..."
    file_log "Installing required packages..."
    if ! install_package "curl ufw fail2ban"; then
        console_log "ERROR" "Failed to install required packages"
        show_log_info
        exit 1
    fi
    console_log "Success" "Required packages installed"
    file_log "Required packages installed successfully"

    # Step 6: Configure UFW
    console_log "INFO" "Configuring UFW firewall..."
    file_log "Configuring UFW..."
    if ! configure_ufw; then
        console_log "ERROR" "Failed to configure UFW"
        show_log_info
        exit 1
    fi
    console_log "Success" "UFW configured successfully"
    file_log "UFW configuration completed successfully"

    # Step 7: Configure Fail2ban
    console_log "INFO" "Configuring Fail2ban..."
    file_log "Configuring Fail2ban..."
    if ! configure_fail2ban; then
        console_log "ERROR" "Failed to configure Fail2ban"
        show_log_info
        exit 1
    fi
    console_log "Success" "Fail2ban configured successfully"
    file_log "Fail2ban configuration completed successfully"

    # New Optional Features

    console_log "INFO" "Configuring unattended-upgrades..."
    configure_unattended_upgrades

    if [ "$INSTALL_MINIO" = true ]; then
        console_log "INFO" "Installing Minio and updating firewall and Fail2ban..."
        install_minio
        update_firewall_minio
        configure_fail2ban_minio
    fi

    if [ "$INSTALL_OSSEC" = true ]; then
        console_log "INFO" "Installing OSSEC HIDS..."
        install_ossec
    fi

    if [ "$INSTALL_LOGWATCH" = true ]; then
        console_log "INFO" "Installing Logwatch..."
        install_logwatch
    fi

    if [ "$INSTALL_GLANCES" = true ]; then
        console_log "INFO" "Installing Glances with Discord notifications..."
        configure_glances_discord
    fi

    if [ "$INSTALL_LYNIS" = true ]; then
        console_log "INFO" "Installing Lynis for security auditing..."
        install_lynis
    fi

    if [ "$INSTALL_KOPIA" = true ]; then
        console_log "INFO" "Installing Kopia for backups..."
        install_kopia
    fi

    if [ "$INSTALL_TIME_SYNC" = true ]; then
        console_log "INFO" "Installing Chrony for time synchronization..."
        configure_time_sync
    fi

    if [ "$OPTIMIZE_REPOS" = true ]; then
        console_log "INFO" "Optimizing apt repositories..."
        optimize_repos
    fi

    console_log "SUCCESS" "Script completed successfully"
    file_log "Script completed successfully"

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    FORMATTED_DURATION=$(format_duration "$DURATION")
    console_log "INFO" "Total execution time: $FORMATTED_DURATION"
    file_log "Total execution time: $FORMATTED_DURATION"

    show_log_info
    exit 0
}

main "$@"
