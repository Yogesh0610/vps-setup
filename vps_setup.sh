#!/bin/bash

# VPS Setup Script v2.5.0
# Author: Yogesh Gupta
# Email: yk68785@gmail.com
# GitHub: https://github.com/Yogesh0610
# Description: A user-friendly script to configure a VPS with web hosting, database, email, and security features.
# License: MIT License

# Constants
VERSION="2.5.0"
CONFIG_FILE="/etc/vps_setup.conf"
CREDENTIALS_FILE="/root/vps_credentials.txt"
LOG_FILE="/var/log/vps_setup.log"
TEMP_DIR="/tmp/vps_setup_$(date +%s)"
BACKUP_DIR="/backups"
SSH_PORT="2222"
WEB_USER="www-data"
WEB_GROUP="www-data"
GPG_RECIPIENT=""
WORDPRESS_INSTALL="no"
PHPMYADMIN_URL_PREFIX="dbadmin"
DOCKER_INSTALL="no"
MYSQL_CRED=""
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RESET='\033[0m'

# Global variables
rollback_actions=()
rollback_needed=false
summary=""

# Ensure script is run as root
if [ "$(id -u)" != "0" ]; then
    echo -e "${COLOR_RED}This script must be run as root. Use sudo.${COLOR_RESET}"
    exit 1
fi

# Create temporary directory
mkdir -p "$TEMP_DIR" || { echo -e "${COLOR_RED}Failed to create temporary directory $TEMP_DIR${COLOR_RESET}"; exit 1; }
trap 'rm -rf "$TEMP_DIR"' EXIT

# Logging function
log_action() {
    local message="$1"
    local level="${2:-info}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    case "$level" in
        err) echo -e "${COLOR_RED}[$timestamp] ERROR: $message${COLOR_RESET}" ;;
        warning) echo -e "${COLOR_YELLOW}[$timestamp] WARNING: $message${COLOR_RESET}" ;;
        *) echo -e "${COLOR_GREEN}[$timestamp] INFO: $message${COLOR_RESET}" ;;
    esac
    echo "[$timestamp] $level: $message" >> "$LOG_FILE"
    # Rotate log if size exceeds 10MB
    if [ -f "$LOG_FILE" ] && [ "$(stat -f %z "$LOG_FILE" 2>/dev/null || stat -c %s "$LOG_FILE")" -gt 10485760 ]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date +%s)"
    fi
}

# Safe execution wrapper
safe_exec() {
    local cmd="$1"
    if [ "$DRY_RUN" = "true" ]; then
        echo "[DRY-RUN] Would execute: $cmd" >> "/tmp/vps_setup_dry_run_$(date +%s).log"
        return 0
    fi
    eval "$cmd" >/dev/null 2>&1
    local status=$?
    if [ $status -ne 0 ]; then
        log_action "Command failed: $cmd" "err"
        return $status
    fi
    return 0
}

# Add rollback action
add_rollback_action() {
    local type="$1"
    local cmd="$2"
    rollback_actions+=("$type:$cmd")
}

# Execute rollback
execute_rollback() {
    if [ "$DRY_RUN" = "true" ]; then
        return
    fi
    log_action "Executing rollback due to failure"
    for action in "${rollback_actions[@]}"; do
        local type=$(echo "$action" | cut -d':' -f1)
        local cmd=$(echo "$action" | cut -d':' -f2-)
        log_action "Rolling back $type"
        safe_exec "$cmd" || log_action "Rollback failed for $type" "err"
    done
    rollback_actions=()
}

# Prompt for input with default
prompt_input() {
    local prompt="$1"
    local default="$2"
    local input
    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " input
        echo "${input:-$default}"
    else
        read -p "$prompt: " input
        echo "$input"
    fi
}

# Prompt for yes/no
prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local response
    read -p "$prompt [${default^^}/n]: " response
    response=${response:-$default}
    case "$response" in
        [Yy]*) return 0 ;;
        *) return 1 ;;
    esac
}

# Validate domain name
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
        log_action "Invalid domain format: $domain" "err"
        echo -e "${COLOR_RED}Error: Invalid domain format. Use example.com.${COLOR_RESET}"
        return 1
    fi
    return 0
}

# Validate username
validate_username() {
    local username="$1"
    if [[ ! "$username" =~ ^[a-zA-Z0-9_]{1,32}$ ]]; then
        log_action "Invalid username format: $username" "err"
        echo -e "${COLOR_RED}Error: Username must be alphanumeric and up to 32 characters.${COLOR_RESET}"
        return 1
    fi
    return 0
}

# Sanitize path
sanitize_path() {
    local path="$1"
    echo "$path" | sed 's/\.\.//g' | sed 's|//|/|g'
}

# Generate random password
generate_password() {
    local pass_file="$TEMP_DIR/pass_$(openssl rand -hex 8)"
    openssl rand -base64 12 > "$pass_file"
    echo "$pass_file"
}

# Cleanup password file
cleanup_password() {
    local pass_file="$1"
    [ -f "$pass_file" ] && rm -f "$pass_file"
}

# Check if package is installed
is_package_installed() {
    local pkg="$1"
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        dpkg -s "$pkg" >/dev/null 2>&1
    else
        rpm -q "$pkg" >/dev/null 2>&1
    fi
}

# Install packages
install_packages() {
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        safe_exec "apt-get update" || return 1
        safe_exec "apt-get install -y $*" || return 1
    else
        safe_exec "yum install -y $*" || return 1
    fi
    return 0
}

# Load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        while IFS='=' read -r key value; do
            case "$key" in
                ssh_port) SSH_PORT="$value" ;;
                web_user) WEB_USER="$value" ;;
                web_group) WEB_GROUP="$value" ;;
                gpg_recipient) GPG_RECIPIENT="$value" ;;
                wordpress_install) WORDPRESS_INSTALL="$value" ;;
                phpmyadmin_url_prefix) PHPMYADMIN_URL_PREFIX="$value" ;;
                docker_install) DOCKER_INSTALL="$value" ;;
            esac
        done < <(grep -v '^#' "$CONFIG_FILE")
        log_action "Loaded configuration from $CONFIG_FILE"
    else
        log_action "No configuration file found at $CONFIG_FILE, using defaults." "warning"
        echo -e "${COLOR_YELLOW}Tip: Create $CONFIG_FILE to set defaults (e.g., ssh_port=2222, wordpress_install=yes).${COLOR_RESET}"
    fi
    # Set default values if not defined
    WORDPRESS_INSTALL=${WORDPRESS_INSTALL:-"no"}
    PHPMYADMIN_URL_PREFIX=${PHPMYADMIN_URL_PREFIX:-"dbadmin"}
    DOCKER_INSTALL=${DOCKER_INSTALL:-"no"}
}

# Detect OS
detect_os() {
    if [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    else
        echo "unknown"
    fi
}

# Check internet connectivity
check_internet() {
    ping -c 1 8.8.8.8 >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_action "No internet connection" "err"
        echo -e "${COLOR_RED}Error: No internet connection. Please check your network.${COLOR_RESET}"
        return 1
    fi
    return 0
}

# Detect server IP
detect_server_ip() {
    local ip=$(curl -s ifconfig.me)
    if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_action "Failed to detect server IP" "err"
        echo -e "${COLOR_RED}Error: Could not detect server IP. Check internet or run 'curl ifconfig.me'.${COLOR_RESET}"
        return 1
    fi
    echo "$ip"
    return 0
}

# Validate DNS
validate_dns() {
    local domain="$1"
    local server_ip=$(detect_server_ip) || return 1
    local domain_ip=$(dig +short "$domain" A | head -n 1)
    if [ -z "$domain_ip" ]; then
        log_action "DNS resolution failed for $domain" "err"
        echo -e "${COLOR_RED}Error: DNS resolution failed for $domain. Check DNS settings with your provider (e.g., GoDaddy, Namecheap).${COLOR_RESET}"
        return 1
    fi
    if [ "$domain_ip" != "$server_ip" ]; then
        log_action "DNS for $domain resolves to $domain_ip, not server IP $server_ip" "err"
        echo -e "${COLOR_RED}Error: DNS for $domain resolves to $domain_ip, not this server ($server_ip).${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}Tip: Set an A record for $domain to point to $server_ip in your DNS settings.${COLOR_RESET}"
        return 1
    fi
    return 0
}

# Check dependencies
check_dependencies() {
    local deps=("mysql" "openssl" "gpg" "certbot" "ss" "systemctl" "curl" "dig" "git" "fail2ban" "htpasswd")
    local missing=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        log_action "Missing dependencies: ${missing[*]}" "warning"
        echo -e "${COLOR_YELLOW}The following tools are required:${COLOR_RESET}"
        echo "  mysql: Database client"
        echo "  openssl: Secure password generation"
        echo "  gpg: Credential encryption"
        echo "  certbot: SSL certificates"
        echo "  ss: Network port checking"
        echo "  systemctl: Service management"
        echo "  curl: IP detection"
        echo "  dig: DNS verification"
        echo "  git: Version control"
        echo "  fail2ban: Brute-force protection"
        echo "  htpasswd: HTTP authentication for phpMyAdmin"
        if prompt_yes_no "Install missing dependencies now?" "y"; then
            install_packages "${missing[@]}" || { log_action "Failed to install dependencies" "err"; exit 1; }
        else
            log_action "Dependencies missing. Please install: ${missing[*]}" "err"
            exit 1
        fi
    fi
    # Check MySQL installation
    if ! is_package_installed mysql-server && ! is_package_installed mariadb-server; then
        if prompt_yes_no "MySQL/MariaDB not installed. Install MariaDB now? (Recommended)" "y"; then
            install_packages mariadb-server || { log_action "Failed to install MariaDB" "err"; exit 1; }
            safe_exec "systemctl enable mariadb" || log_action "Failed to enable MariaDB" "err"
            safe_exec "systemctl start mariadb" && check_service_status "mariadb" || { log_action "Failed to start MariaDB" "err"; exit 1; }
            log_action "MariaDB installed and running"
            echo -e "${COLOR_YELLOW}Please run 'mysql_secure_installation' to set up MySQL root password and secure the database.${COLOR_RESET}"
        else
            log_action "MySQL/MariaDB required. Please install it manually." "err"
            exit 1
        fi
    fi
    MYSQL_CRED=$(check_mysql_access) || exit 1
}

# Check MySQL access
check_mysql_access() {
    local mysql_cred=""
    if [ -f /root/.my.cnf ]; then
        mysql_cred="-u root -p$(grep password /root/.my.cnf | cut -d'=' -f2 | tr -d ' ')"
    else
        local mysql_password=$(prompt_input "Enter MySQL root password (leave blank if none)" "")
        if [ -n "$mysql_password" ]; then
            mysql_cred="-u root -p$mysql_password"
        else
            mysql_cred="-u root"
        fi
    fi
    mysql $mysql_cred -e "SELECT 1" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_action "MySQL access failed" "err"
        echo -e "${COLOR_RED}Error: MySQL access failed. Install MySQL or check root credentials.${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}Tip: Run 'mysql -u root' to verify access or install MySQL with 'apt-get install mysql-server'.${COLOR_RESET}"
        return 1
    fi
    echo "$mysql_cred"
    return 0
}

# Check service status
check_service_status() {
    local service="$1"
    if ! systemctl is-active --quiet "$service"; then
        log_action "Service $service is not running" "err"
        echo -e "${COLOR_RED}Error: Service $service is not running. Check logs with 'journalctl -u $service'.${COLOR_RESET}"
        return 1
    fi
    return 0
}

# Install firewall
install_firewall() {
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        if ! is_package_installed ufw; then
            install_packages ufw || return 1
        fi
        safe_exec "ufw allow $SSH_PORT/tcp" || return 1
        safe_exec "ufw allow 80/tcp" || return 1
        safe_exec "ufw allow 443/tcp" || return 1
        safe_exec "ufw allow 21/tcp" || return 1
        safe_exec "ufw allow 25/tcp" || return 1
        safe_exec "ufw allow 587/tcp" || return 1
        safe_exec "ufw enable" || return 1
        log_action "Firewall configured with UFW"
    else
        if ! is_package_installed firewalld; then
            install_packages firewalld || return 1
        fi
        safe_exec "firewall-cmd --permanent --add-port=$SSH_PORT/tcp" || return 1
        safe_exec "firewall-cmd --permanent --add-service=http" || return 1
        safe_exec "firewall-cmd --permanent --add-service=https" || return 1
        safe_exec "firewall-cmd --permanent --add-service=ftp" || return 1
        safe_exec "firewall-cmd --permanent --add-service=smtp" || return 1
        safe_exec "firewall-cmd --reload" || return 1
        safe_exec "systemctl enable firewalld" || return 1
        safe_exec "systemctl start firewalld" && check_service_status "firewalld" || return 1
        log_action "Firewall configured with firewalld"
    fi
}

# Encrypt credentials incrementally
encrypt_credentials_incremental() {
    local file="$1"
    if [ -n "$GPG_RECIPIENT" ] && [ -s "$file" ]; then
        local encrypted_file="$file.gpg"
        safe_exec "gpg --encrypt --recipient $GPG_RECIPIENT $file" || return 1
        safe_exec "mv $encrypted_file $file" || return 1
        log_action "Credentials encrypted with GPG"
    fi
    return 0
}

# Configure domain
configure_domain() {
    local domain="$1"
    if [ -z "$domain" ]; then
        domain=$(prompt_input "Enter domain (e.g., example.com)" "")
        validate_domain "$domain" || return 1
        validate_dns "$domain" || return 1
    fi
    local document_root=$(sanitize_path "/var/www/$domain/html")
    local db_name="${domain//./_}"
    local db_user="${domain//./_}"
    local db_password_file=$(generate_password)
    local db_password=$(cat "$db_password_file")
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local php_version=$(cat /root/.php_version 2>/dev/null || echo "8.4")
    local php_socket=$(find /run/php /var/run/php -name "php${php_version}-fpm*.sock" 2>/dev/null | head -n 1)
    [ -z "$php_socket" ] && { log_action "PHP-FPM socket not found for version $php_version" "err"; return 1; }
    rollback_needed=false
    summary="Domain Setup Summary for $domain:\n"

    # Create document root
    if [ "$rollback_needed" = "false" ]; then
        safe_exec "mkdir -p $document_root" || rollback_needed=true
        safe_exec "chown $WEB_USER:$WEB_GROUP $document_root" || rollback_needed=true
        safe_exec "chmod 750 $document_root" || rollback_needed=true
        echo "<html><body><h1>Welcome to $domain</h1></body></html>" > "$document_root/index.html"
        add_rollback_action "document_root" "rm -rf /var/www/$domain"
    fi

    # Configure web server
    if [ "$rollback_needed" = "false" ]; then
        if [ "$web_server" = "apache" ]; then
            cat > "$TEMP_DIR/$domain.conf" <<EOF
<VirtualHost *:80>
    ServerName $domain
    ServerAlias www.$domain
    DocumentRoot $document_root
    <Directory $document_root>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog /var/log/apache2/$domain-error.log
    CustomLog /var/log/apache2/$domain-access.log combined
    <FilesMatch \.php$>
        SetHandler "proxy:unix:$php_socket|fcgi://localhost/"
    </FilesMatch>
</VirtualHost>
EOF
            safe_exec "mv $TEMP_DIR/$domain.conf /etc/apache2/sites-available/$domain.conf" || rollback_needed=true
            safe_exec "a2ensite $domain.conf" || rollback_needed=true
            safe_exec "systemctl reload apache2" && check_service_status "apache2" || rollback_needed=true
            add_rollback_action "apache_vhost" "a2dissite $domain.conf; rm -f /etc/apache2/sites-available/$domain.conf; systemctl reload apache2"
        else
            cat > "$TEMP_DIR/$domain.conf" <<EOF
server {
    listen 80;
    server_name $domain www.$domain;
    root $document_root;
    index index.html index.php;
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$php_socket;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    error_log /var/log/nginx/$domain-error.log;
    access_log /var/log/nginx/$domain-access.log;
}
EOF
            safe_exec "mv $TEMP_DIR/$domain.conf /etc/nginx/sites-available/$domain" || rollback_needed=true
            safe_exec "ln -s /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/" || rollback_needed=true
            safe_exec "systemctl reload nginx" && check_service_status "nginx" || rollback_needed=true
            add_rollback_action "nginx_vhost" "rm -f /etc/nginx/sites-enabled/$domain /etc/nginx/sites-available/$domain; systemctl reload nginx"
        fi
        summary="$summary  - Website folder: $document_root\n  - Website URL: https://$domain\n"
    fi

    # Setup SSL with Certbot
    if [ "$rollback_needed" = "false" ]; then
        local email=$(prompt_input "Enter admin email for SSL (Let's Encrypt)" "admin@$domain")
        if ! safe_exec "certbot --$web_server --agree-tos --email $email --no-eff-email -d $domain -d www.$domain"; then
            log_action "SSL setup failed for $domain" "err"
            rollback_needed=true
        else
            add_rollback_action "ssl" "certbot delete --cert-name $domain"
        fi
    fi

    # Create database
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Create a database for $domain?" "y"; then
        if ! safe_exec "mysql $MYSQL_CRED -e 'CREATE DATABASE $db_name;'" || \
           ! safe_exec "mysql $MYSQL_CRED -e 'CREATE USER \"$db_user\"@\"localhost\" IDENTIFIED BY \"$db_password\";'" || \
           ! safe_exec "mysql $MYSQL_CRED -e 'GRANT ALL PRIVILEGES ON $db_name.* TO \"$db_user\"@\"localhost\";'" || \
           ! safe_exec "mysql $MYSQL_CRED -e 'FLUSH PRIVILEGES;'"; then
            rollback_needed=true
        else
            add_rollback_action "database" "mysql $MYSQL_CRED -e 'DROP DATABASE $db_name; DROP USER \"$db_user\"@\"localhost\";'"
            summary="$summary  - Database: $db_name\n  - Database User: $db_user\n"
        fi
    fi

    # Create SFTP user
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Create an SFTP user for $domain? (Secure file uploads)" "y"; then
        ftp_user=$(prompt_input "Enter SFTP username" "${domain//./_}")
        validate_username "$ftp_user" || return 1
        local ftp_password_file=$(generate_password)
        local ftp_password=$(cat "$ftp_password_file")
        if ! safe_exec "useradd -m -d /var/www/$domain -s /bin/false -G $WEB_GROUP $ftp_user" || \
           ! safe_exec "echo $ftp_user:$ftp_password | chpasswd" || \
           ! safe_exec "chown -R $ftp_user:$WEB_GROUP /var/www/$domain" || \
           ! safe_exec "chmod -R 750 /var/www/$domain"; then
            rollback_needed=true
        else
            # Configure SFTP restrictions
            cat >> /etc/ssh/sshd_config <<EOF
Match User $ftp_user
    ChrootDirectory /var/www/$domain
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
EOF
            safe_exec "systemctl restart sshd" && check_service_status "sshd" || return 1
            add_rollback_action "sftp_config" "sed -i '/Match User $ftp_user/,+4d' /etc/ssh/sshd_config; systemctl restart sshd"
            if prompt_yes_no "Save SFTP credentials to $CREDENTIALS_FILE? (Recommended: Copy to a password manager)" "n"; then
                echo "SFTP user $ftp_user for $domain: $ftp_password" >> "$CREDENTIALS_FILE"
                encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
            else
                echo -e "${COLOR_YELLOW}Please save these credentials securely:${COLOR_RESET}"
                echo "SFTP user: $ftp_user"
                echo "SFTP password: $ftp_password"
            fi
            log_action "SFTP user $ftp_user created for $domain"
            add_rollback_action "ftp_user" "userdel -r $ftp_user"
            summary="$summary  - SFTP User: $ftp_user\n"
        fi
        cleanup_password "$ftp_password_file"
    fi

    # Create email account
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Create an email account for $domain?" "y"; then
        local email_user=$(prompt_input "Enter email username (e.g., info for info@$domain)" "info")
        validate_username "$email_user" || return 1
        local email_password_file=$(generate_password)
        local email_password=$(cat "$email_password_file")
        if ! safe_exec "useradd -m -s /bin/false $email_user@$domain" || \
           ! safe_exec "echo $email_user@$domain:$email_password | chpasswd"; then
            rollback_needed=true
        else
            if prompt_yes_no "Save email credentials to $CREDENTIALS_FILE? (Recommended: Copy to a password manager)" "n"; then
                echo "Email $email_user@$domain: $email_password" >> "$CREDENTIALS_FILE"
                encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
            else
                echo -e "${COLOR_YELLOW}Please save these credentials securely:${COLOR_RESET}"
                echo "Email: $email_user@$domain"
                echo "Email password: $email_password"
            fi
            log_action "Email account $email_user@$domain created"
            add_rollback_action "email_user" "userdel -r $email_user@$domain"
            summary="$summary  - Email Account: $email_user@$domain\n"
        fi
        cleanup_password "$email_password_file"
    fi

    # Install webmail
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Install webmail for $domain? (Access email via browser)" "y"; then
        if ! install_webmail "$domain"; then
            rollback_needed=true
        else
            summary="$summary  - Webmail URL: https://webmail.$domain\n"
        fi
    fi

    # Install WordPress
    if [ "$rollback_needed" = "false" ] && ([ "$WORDPRESS_INSTALL" = "yes" ] || prompt_yes_no "Install WordPress for $domain? (Includes database setup)" "y"); then
        if ! install_wordpress "$domain"; then
            rollback_needed=true
        else
            summary="$summary  - WordPress URL: https://$domain\n"
        fi
    fi

    # Set up Git repository
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Set up Git repository for $domain? (Enables automated deployments)" "y"; then
        if ! setup_git_repository "$domain"; then
            rollback_needed=true
        else
            summary="$summary  - Git Repository: /var/www/$domain/git\n"
        fi
    fi

    # Save database credentials
    if [ "$rollback_needed" = "false" ] && [ -n "$db_password" ] && prompt_yes_no "Save database credentials to $CREDENTIALS_FILE? (Recommended: Copy to a password manager)" "n"; then
        echo "Database $db_name with user $db_user for $domain: $db_password" >> "$CREDENTIALS_FILE"
        encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
    elif [ -n "$db_password" ]; then
        echo -e "${COLOR_YELLOW}Please save these credentials securely:${COLOR_RESET}"
        echo "Database: $db_name"
        echo "Database user: $db_user"
        echo "Database password: $db_password"
    fi
    cleanup_password "$db_password_file"

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}Domain setup failed for $domain. All changes rolled back.${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}Tip: Check logs at $LOG_FILE for details.${COLOR_RESET}"
        return 1
    fi

    log_action "Domain $domain configured successfully"
    echo -e "${COLOR_GREEN}$summary${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Note: Upload website files to $document_root and test at https://$domain.${COLOR_RESET}"
}

# Install webmail (Roundcube)
install_webmail() {
    local domain="$1"
    validate_domain "$domain" || return 1
    validate_dns "$domain" || return 1
    local webmail_domain="webmail.$domain"
    local document_root=$(sanitize_path "/var/www/$webmail_domain/html")
    local db_name="roundcube_${domain//./_}"
    local db_user="rc_${domain//./_}"
    local db_password_file=$(generate_password)
    local db_password=$(cat "$db_password_file")
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local php_version=$(cat /root/.php_version 2>/dev/null || echo "8.4")
    local php_socket=$(find /run/php /var/run/php -name "php${php_version}-fpm*.sock" 2>/dev/null | head -n 1)
    [ -z "$php_socket" ] && { log_action "PHP-FPM socket not found for version $php_version" "err"; return 1; }
    rollback_needed=false

    if [ -d "$document_root" ]; then
        log_action "Webmail is already installed for $domain"
        return 0
    fi

    # Install Roundcube
    if ! is_package_installed roundcube; then
        install_packages roundcube roundcube-mysql || return 1
    fi

    # Create document root
    safe_exec "mkdir -p $document_root" || rollback_needed=true
    safe_exec "ln -s /usr/share/roundcube $document_root/roundcube" || rollback_needed=true
    safe_exec "chown -R $WEB_USER:$WEB_GROUP $document_root" || rollback_needed=true
    safe_exec "chmod -R 750 $document_root" || rollback_needed=true
    add_rollback_action "webmail_document_root" "rm -rf /var/www/$webmail_domain"

    # Configure web server
    if [ "$rollback_needed" = "false" ]; then
        if [ "$web_server" = "apache" ]; then
            cat > "$TEMP_DIR/$webmail_domain.conf" <<EOF
<VirtualHost *:80>
    ServerName $webmail_domain
    DocumentRoot $document_root
    <Directory $document_root>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog /var/log/apache2/$webmail_domain-error.log
    CustomLog /var/log/apache2/$webmail_domain-access.log combined
    <FilesMatch \.php$>
        SetHandler "proxy:unix:$php_socket|fcgi://localhost/"
    </FilesMatch>
</VirtualHost>
EOF
            safe_exec "mv $TEMP_DIR/$webmail_domain.conf /etc/apache2/sites-available/$webmail_domain.conf" || rollback_needed=true
            safe_exec "a2ensite $webmail_domain.conf" || rollback_needed=true
            safe_exec "systemctl reload apache2" && check_service_status "apache2" || rollback_needed=true
            add_rollback_action "webmail_apache_vhost" "a2dissite $webmail_domain.conf; rm -f /etc/apache2/sites-available/$webmail_domain.conf; systemctl reload apache2"
        else
            cat > "$TEMP_DIR/$webmail_domain.conf" <<EOF
server {
    listen 80;
    server_name $webmail_domain;
    root $document_root;
    index index.php;
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:$php_socket;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    error_log /var/log/nginx/$webmail_domain-error.log;
    access_log /var/log/nginx/$webmail_domain-access.log;
}
EOF
            safe_exec "mv $TEMP_DIR/$webmail_domain.conf /etc/nginx/sites-available/$webmail_domain" || rollback_needed=true
            safe_exec "ln -s /etc/nginx/sites-available/$webmail_domain /etc/nginx/sites-enabled/" || rollback_needed=true
            safe_exec "systemctl reload nginx" && check_service_status "nginx" || rollback_needed=true
            add_rollback_action "webmail_nginx_vhost" "rm -f /etc/nginx/sites-enabled/$webmail_domain /etc/nginx/sites-available/$webmail_domain; systemctl reload nginx"
        fi
    fi

    # Setup SSL
    if [ "$rollback_needed" = "false" ]; then
        local email=$(prompt_input "Enter admin email for webmail SSL" "admin@$domain")
        if ! safe_exec "certbot --$web_server --agree-tos --email $email --no-eff-email -d $webmail_domain"; then
            log_action "SSL setup failed for $webmail_domain" "err"
            rollback_needed=true
        else
            add_rollback_action "webmail_ssl" "certbot delete --cert-name $webmail_domain"
        fi
    fi

    # Create database
    if [ "$rollback_needed" = "false" ]; then
        if ! safe_exec "mysql $MYSQL_CRED -e 'CREATE DATABASE $db_name;'" || \
           ! safe_exec "mysql $MYSQL_CRED -e 'CREATE USER \"$db_user\"@\"localhost\" IDENTIFIED BY \"$db_password\";'" || \
           ! safe_exec "mysql $MYSQL_CRED -e 'GRANT ALL PRIVILEGES ON $db_name.* TO \"$db_user\"@\"localhost\";'" || \
           ! safe_exec "mysql $MYSQL_CRED -e 'FLUSH PRIVILEGES;'"; then
            rollback_needed=true
        else
            safe_exec "mysql $MYSQL_CRED $db_name < /usr/share/roundcube/SQL/mysql.initial.sql" || rollback_needed=true
            add_rollback_action "webmail_database" "mysql $MYSQL_CRED -e 'DROP DATABASE $db_name; DROP USER \"$db_user\"@\"localhost\";'"
        fi
    fi

    # Configure Roundcube
    if [ "$rollback_needed" = "false" ]; then
        local config_file="/etc/roundcube/config.inc.php"
        safe_exec "sed -i \"s|mysql://roundcube:.*@localhost/roundcubemail|mysql://$db_user:$db_password@localhost/$db_name|\" $config_file" || rollback_needed=true
        safe_exec "sed -i \"s|\$config\['default_host'\] = .*;|\$config\['default_host'\] = 'localhost';|\" $config_file" || rollback_needed=true
        add_rollback_action "webmail_config" "sed -i \"s|mysql://$db_user:.*@localhost/$db_name|mysql://roundcube:pass@localhost/roundcubemail|\" $config_file"
    fi

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}Webmail setup failed for $domain. All changes rolled back.${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}Tip: Check logs at $LOG_FILE for details.${COLOR_RESET}"
        return 1
    fi

    log_action "Webmail installed for $domain at https://$webmail_domain"
    cleanup_password "$db_password_file"
    return 0
}

# Edit PHP settings
edit_php_ini() {
    local domain=$(prompt_input "Enter domain to edit PHP settings (e.g., example.com)" "")
    validate_domain "$domain" || return 1
    local php_version=$(cat /root/.php_version 2>/dev/null || echo "8.4")
    local php_ini="/etc/php/$php_version/fpm/pool.d/$domain.conf"
    if [ ! -f "$php_ini" ]; then
        cat > "$php_ini" <<EOF
[$domain]
user = $WEB_USER
group = $WEB_GROUP
listen = /run/php/php${php_version}-fpm-$domain.sock
listen.owner = $WEB_USER
listen.group = $WEB_GROUP
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
php_admin_value[memory_limit] = 128M
php_admin_value[upload_max_filesize] = 20M
php_admin_value[post_max_size] = 20M
php_admin_value[max_execution_time] = 30
EOF
        safe_exec "systemctl restart php${php_version}-fpm" && check_service_status "php${php_version}-fpm" || return 1
        add_rollback_action "php_ini" "rm -f $php_ini; systemctl restart php${php_version}-fpm"
    fi
    local memory_limit=$(prompt_input "Enter PHP memory_limit (e.g., 128M)" "128M")
    local upload_max=$(prompt_input "Enter upload_max_filesize (e.g., 20M)" "20M")
    local post_max=$(prompt_input "Enter post_max_size (e.g., 20M)" "20M")
    local max_time=$(prompt_input "Enter max_execution_time (e.g., 30)" "30")
    safe_exec "sed -i \"s|php_admin_value\[memory_limit\] = .*|php_admin_value[memory_limit] = $memory_limit|\" $php_ini" || return 1
    safe_exec "sed -i \"s|php_admin_value\[upload_max_filesize\] = .*|php_admin_value[upload_max_filesize] = $upload_max|\" $php_ini" || return 1
    safe_exec "sed -i \"s|php_admin_value\[post_max_size\] = .*|php_admin_value[post_max_size] = $post_max|\" $php_ini" || return 1
    safe_exec "sed -i \"s|php_admin_value\[max_execution_time\] = .*|php_admin_value[max_execution_time] = $max_time|\" $php_ini" || return 1
    safe_exec "systemctl restart php${php_version}-fpm" && check_service_status "php${php_version}-fpm" || return 1
    log_action "PHP settings updated for $domain"
    echo -e "${COLOR_GREEN}PHP Settings Updated for $domain:${COLOR_RESET}"
    echo "  - memory_limit: $memory_limit"
    echo "  - upload_max_filesize: $upload_max"
    echo "  - post_max_size: $post_max"
    echo "  - max_execution_time: $max_time"
}

# Delete domain
delete_domain() {
    local domain=$(prompt_input "Enter domain to delete (e.g., example.com)" "")
    validate_domain "$domain" || return 1
    if [ ! -d "/var/www/$domain" ]; then
        log_action "Domain $domain not found" "err"
        echo -e "${COLOR_RED}Error: Domain $domain not found.${COLOR_RESET}"
        return 1
    fi
    if ! prompt_yes_no "Are you sure you want to delete $domain and all its resources?" "n"; then
        return 0
    fi
    local backup_file="$BACKUP_DIR/$domain-$(date +%Y%m%d%H%M%S).tar.gz"
    mkdir -p "$BACKUP_DIR"
    safe_exec "tar -czf $backup_file /var/www/$domain" || log_action "Backup failed for $domain" "warning"
    log_action "Backup created at $backup_file"
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local php_version=$(cat /root/.php_version 2>/dev/null || echo "8.4")
    # Delete web server configuration
    if [ "$web_server" = "apache" ]; then
        safe_exec "a2dissite $domain.conf" || log_action "Failed to disable Apache site $domain" "warning"
        safe_exec "rm -f /etc/apache2/sites-available/$domain.conf" || log_action "Failed to remove Apache config" "warning"
        safe_exec "a2dissite webmail.$domain.conf" || log_action "Failed to disable webmail site" "warning"
        safe_exec "rm -f /etc/apache2/sites-available/webmail.$domain.conf" || log_action "Failed to remove webmail config" "warning"
        safe_exec "systemctl reload apache2" && check_service_status "apache2" || log_action "Failed to reload Apache" "warning"
    else
        safe_exec "rm -f /etc/nginx/sites-enabled/$domain /etc/nginx/sites-available/$domain" || log_action "Failed to remove Nginx config" "warning"
        safe_exec "rm -f /etc/nginx/sites-enabled/webmail.$domain /etc/nginx/sites-available/webmail.$domain" || log_action "Failed to remove webmail config" "warning"
        safe_exec "systemctl reload nginx" && check_service_status "nginx" || log_action "Failed to reload Nginx" "warning"
    fi
    # Delete SSL certificates
    safe_exec "certbot delete --cert-name $domain" || log_action "Failed to delete SSL certificate for $domain" "warning"
    safe_exec "certbot delete --cert-name webmail.$domain" || log_action "Failed to delete SSL certificate for webmail.$domain" "warning"
    # Delete database
    local db_name="${domain//./_}"
    local db_user="${domain//./_}"
    safe_exec "mysql $MYSQL_CRED -e 'DROP DATABASE $db_name; DROP USER \"$db_user\"@\"localhost\";'" || log_action "Failed to delete database $db_name" "warning"
    local rc_db="roundcube_${domain//./_}"
    local rc_user="rc_${domain//./_}"
    safe_exec "mysql $MYSQL_CRED -e 'DROP DATABASE $rc_db; DROP USER \"$rc_user\"@\"localhost\";'" || log_action "Failed to delete Roundcube database $rc_db" "warning"
    # Delete users
    safe_exec "userdel -r ${domain//./_}" || log_action "Failed to delete SFTP user" "warning"
    safe_exec "userdel -r info@$domain" || log_action "Failed to delete email user" "warning"
    # Remove SFTP config
    safe_exec "sed -i '/Match User ${domain//./_}/,+4d' /etc/ssh/sshd_config" || log_action "Failed to remove SFTP config" "warning"
    safe_exec "systemctl restart sshd" || log_action "Failed to restart SSH" "warning"
    # Delete files
    safe_exec "rm -rf /var/www/$domain /var/www/webmail.$domain" || log_action "Failed to delete domain files" "warning"
    safe_exec "rm -f /etc/php/$php_version/fpm/pool.d/$domain.conf" || log_action "Failed to delete PHP config" "warning"
    safe_exec "systemctl restart php${php_version}-fpm" || log_action "Failed to restart PHP-FPM" "warning"
    log_action "Domain $domain deleted successfully"
    echo -e "${COLOR_GREEN}Domain $domain deleted.${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Backup saved at $backup_file. Restore with 'tar -xzf $backup_file -C /'.${COLOR_RESET}"
}

# Install WordPress
install_wordpress() {
    local domain="$1"
    if [ -z "$domain" ]; then
        domain=$(prompt_input "Enter domain for WordPress (e.g., example.com)" "")
        validate_domain "$domain" || return 1
        validate_dns "$domain" || return 1
    fi
    if [ -d "/var/www/$domain/html/wp-admin" ]; then
        log_action "WordPress is already installed for $domain"
        return
    fi
    if ! prompt_yes_no "Install WordPress for $domain? (Includes database setup)" "y"; then
        return
    fi
    local document_root=$(sanitize_path "/var/www/$domain/html")
    local wp_db="wp_${domain//./_}"
    local wp_user="wp_${domain//./_}"
    local wp_password_file=$(generate_password)
    local wp_password=$(cat "$wp_password_file")
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local php_version=$(cat /root/.php_version 2>/dev/null || echo "8.4")
    local php_socket=$(find /run/php /var/run/php -name "php${php_version}-fpm*.sock" 2>/dev/null | head -n 1)
    [ -z "$php_socket" ] && { log_action "PHP-FPM socket not found for version $php_version" "err"; return 1; }
    
    # Docker option
    local use_docker="no"
    if [ "$DOCKER_INSTALL" = "yes" ] && prompt_yes_no "Use Docker for WordPress? (Runs in a container)" "y"; then
        use_docker="yes"
        install_docker || return 1
    fi
    
    if [ "$use_docker" = "yes" ]; then
        # Docker-based WordPress
        local docker_compose_file="$TEMP_DIR/docker-compose.yml"
        cat > "$docker_compose_file" <<EOF
version: '3.8'
services:
  wordpress:
    image: wordpress:latest
    ports:
      - "80:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_NAME: $wp_db
      WORDPRESS_DB_USER: $wp_user
      WORDPRESS_DB_PASSWORD: $wp_password
    volumes:
      - $document_root:/var/www/html
  db:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: $wp_db
      MYSQL_USER: $wp_user
      MYSQL_PASSWORD: $wp_password
      MYSQL_ROOT_PASSWORD: $(openssl rand -base64 16)
    volumes:
      - db_data:/var/lib/mysql
volumes:
  db_data:
EOF
        safe_exec "docker-compose -f $docker_compose_file up -d" || { log_action "Failed to start WordPress Docker containers" "err"; return 1; }
        add_rollback_action "wordpress_docker" "docker-compose -f $docker_compose_file down; rm -f $docker_compose_file"
    else
        # Standard WordPress installation
        safe_exec "mkdir -p $document_root" || return 1
        safe_exec "wget -q https://wordpress.org/latest.tar.gz -O $TEMP_DIR/wordpress.tar.gz" || { log_action "Failed to download WordPress" "err"; return 1; }
        safe_exec "tar -xzf $TEMP_DIR/wordpress.tar.gz -C $TEMP_DIR" || return 1
        safe_exec "mv $TEMP_DIR/wordpress/* $document_root/" || return 1
        safe_exec "chown -R $WEB_USER:$WEB_GROUP $document_root" || return 1
        safe_exec "chmod -R 750 $document_root" || return 1
        add_rollback_action "wordpress_files" "rm -rf $document_root"
    fi

    # Database setup
    safe_exec "mysql $MYSQL_CRED -e 'CREATE DATABASE $wp_db;'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'CREATE USER \"$wp_user\"@\"localhost\" IDENTIFIED BY \"$wp_password\";'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'GRANT ALL PRIVILEGES ON $wp_db.* TO \"$wp_user\"@\"localhost\";'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'FLUSH PRIVILEGES;'" || return 1
    add_rollback_action "wordpress_db" "mysql $MYSQL_CRED -e 'DROP DATABASE $wp_db; DROP USER \"$wp_user\"@\"localhost\";'"

    # Configure wp-config.php
    if [ "$use_docker" != "yes" ]; then
        safe_exec "cp $document_root/wp-config-sample.php $document_root/wp-config.php" || return 1
        safe_exec "sed -i \"s/database_name_here/$wp_db/\" $document_root/wp-config.php" || return 1
        safe_exec "sed -i \"s/username_here/$wp_user/\" $document_root/wp-config.php" || return 1
        safe_exec "sed -i \"s/password_here/$wp_password/\" $document_root/wp-config.php" || return 1
        safe_exec "sed -i \"s/localhost/localhost/\" $document_root/wp-config.php" || return 1
    fi

    # Save credentials
    if prompt_yes_no "Save WordPress credentials to $CREDENTIALS_FILE? (Recommended: Copy to a password manager)" "n"; then
        echo "WordPress database $wp_db with user $wp_user for $domain: $wp_password" >> "$CREDENTIALS_FILE"
        encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
    else
        echo -e "${COLOR_YELLOW}Please save these credentials securely:${COLOR_RESET}"
        echo "Database: $wp_db"
        echo "Database user: $wp_user"
        echo "Database password: $wp_password"
    fi
    cleanup_password "$wp_password_file"

    # Update virtual host
    if [ "$web_server" = "apache" ]; then
        safe_exec "a2ensite $domain.conf" || return 1
        safe_exec "systemctl reload apache2" && check_service_status "apache2" || return 1
    else
        safe_exec "systemctl reload nginx" && check_service_status "nginx" || return 1
    fi

    log_action "WordPress installed for $domain"
    echo -e "${COLOR_GREEN}WordPress Setup Summary for $domain:${COLOR_RESET}"
    echo "  - Website URL: https://$domain"
    echo "  - Admin URL: https://$domain/wp-admin"
    echo "  - Database: $wp_db"
    echo "  - Database User: $wp_user"
    echo -e "${COLOR_YELLOW}Note: Complete setup at https://$domain/wp-admin.${COLOR_RESET}"
}

# Setup Git repository
setup_git_repository() {
    local domain="$1"
    if [ -z "$domain" ]; then
        domain=$(prompt_input "Enter domain for Git repository (e.g., example.com)" "")
        validate_domain "$domain" || return 1
        validate_dns "$domain" || return 1
    fi
    if [ -d "/var/www/$domain/git" ]; then
        log_action "Git repository already exists for $domain"
        return
    fi
    if ! prompt_yes_no "Set up Git repository for $domain? (Enables automated deployments)" "y"; then
        return
    fi
    local document_root=$(sanitize_path "/var/www/$domain/html")
    local git_dir="/var/www/$domain/git"
    
    # Install Git
    if ! command -v git >/dev/null 2>&1; then
        install_packages git || return 1
    fi
    
    # Initialize repository
    safe_exec "mkdir -p $git_dir" || return 1
    safe_exec "cd $git_dir && git init --bare" || return 1
    safe_exec "chown -R $WEB_USER:$WEB_GROUP $git_dir" || return 1
    safe_exec "chmod -R 770 $git_dir" || return 1
    add_rollback_action "git_repo" "rm -rf $git_dir"

    # Create post-receive hook
    cat > "$git_dir/hooks/post-receive" <<EOF
#!/bin/bash
GIT_WORK_TREE=$document_root git checkout -f
chown -R $WEB_USER:$WEB_GROUP $document_root
chmod -R 750 $document_root
EOF
    safe_exec "chmod +x $git_dir/hooks/post-receive" || return 1

    log_action "Git repository set up for $domain at $git_dir"
    echo -e "${COLOR_GREEN}Git Setup Summary for $domain:${COLOR_RESET}"
    echo "  - Repository: $git_dir"
    echo "  - Deploy to: $document_root"
    echo -e "${COLOR_YELLOW}Note: Push to git@$domain:/var/www/$domain/git to deploy.${COLOR_RESET}"
}

# Install phpMyAdmin
install_phpmyadmin() {
    local domain="$1"
    if [ -z "$domain" ]; then
        domain=$(prompt_input "Enter domain for phpMyAdmin (e.g., example.com)" "")
        validate_domain "$domain" || return 1
        validate_dns "$domain" || return 1
    fi
    if [ -d "/usr/share/phpmyadmin" ]; then
        log_action "phpMyAdmin is already installed"
        return
    fi
    if ! prompt_yes_no "Install phpMyAdmin for $domain? (Secure database management)" "y"; then
        return
    fi
    local pma_path="/usr/share/${PHPMYADMIN_URL_PREFIX}_$(openssl rand -hex 4)"
    local pma_user="pma_$(openssl rand -hex 4)"
    local pma_password_file=$(generate_password)
    local pma_password=$(cat "$pma_password_file")
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local php_version=$(cat /root/.php_version 2>/dev/null || echo "8.4")
    local php_socket=$(find /run/php /var/run/php -name "php${php_version}-fpm*.sock" 2>/dev/null | head -n 1)
    [ -z "$php_socket" ] && { log_action "PHP-FPM socket not found for version $php_version" "err"; return 1; }

    # Install phpMyAdmin
    install_packages phpmyadmin || return 1
    safe_exec "mv /usr/share/phpmyadmin $pma_path" || return 1
    safe_exec "chown -R $WEB_USER:$WEB_GROUP $pma_path" || return 1
    safe_exec "find $pma_path -type d -exec chmod 750 {} \;" || return 1
    safe_exec "find $pma_path -type f -exec chmod 640 {} \;" || return 1
    add_rollback_action "phpmyadmin_files" "rm -rf $pma_path"

    # Configure HTTP authentication
    local htpasswd_file="/etc/phpmyadmin/.htpasswd"
    safe_exec "htpasswd -cb $htpasswd_file $pma_user $pma_password" || return 1
    add_rollback_action "phpmyadmin_htpasswd" "rm -f $htpasswd_file"

    # Configure web server
    if [ "$web_server" = "apache" ]; then
        cat > "$TEMP_DIR/phpmyadmin.conf" <<EOF
<VirtualHost *:80>
    ServerName $domain
    Alias /${PHPMYADMIN_URL_PREFIX}_$(basename $pma_path) $pma_path
    <Directory $pma_path>
        Options FollowSymLinks
        DirectoryIndex index.php
        AllowOverride All
        Require all granted
        AuthType Basic
        AuthName "phpMyAdmin Access"
        AuthUserFile $htpasswd_file
        Require valid-user
    </Directory>
    <FilesMatch \.php$>
        SetHandler "proxy:unix:$php_socket|fcgi://localhost/"
    </FilesMatch>
</VirtualHost>
EOF
        safe_exec "mv $TEMP_DIR/phpmyadmin.conf /etc/apache2/conf-available/phpmyadmin.conf" || return 1
        safe_exec "a2enconf phpmyadmin" || return 1
        safe_exec "systemctl reload apache2" && check_service_status "apache2" || return 1
        add_rollback_action "phpmyadmin_apache" "a2disconf phpmyadmin; rm -f /etc/apache2/conf-available/phpmyadmin.conf"
    else
        cat > "$TEMP_DIR/phpmyadmin_nginx.conf" <<EOF
server {
    listen 80;
    server_name $domain;
    location /${PHPMYADMIN_URL_PREFIX}_$(basename $pma_path) {
        root /usr/share;
        index index.php;
        auth_basic "phpMyAdmin Access";
        auth_basic_user_file $htpasswd_file;
        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:$php_socket;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
    }
}
EOF
        safe_exec "mv $TEMP_DIR/phpmyadmin_nginx.conf /etc/nginx/sites-available/phpmyadmin.$domain" || return 1
        safe_exec "ln -s /etc/nginx/sites-available/phpmyadmin.$domain /etc/nginx/sites-enabled/" || return 1
        safe_exec "systemctl reload nginx" && check_service_status "nginx" || return 1
        add_rollback_action "phpmyadmin_nginx" "rm -f /etc/nginx/sites-enabled/phpmyadmin.$domain /etc/nginx/sites-available/phpmyadmin.$domain"
    fi

    # Save credentials
    if prompt_yes_no "Save phpMyAdmin credentials to $CREDENTIALS_FILE? (Recommended: Copy to a password manager)" "n"; then
        echo "phpMyAdmin user $pma_user for $domain: $pma_password" >> "$CREDENTIALS_FILE"
        encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
    else
        echo -e "${COLOR_YELLOW}Please save these credentials securely:${COLOR_RESET}"
        echo "phpMyAdmin user: $pma_user"
        echo "phpMyAdmin password: $pma_password"
    fi
    cleanup_password "$pma_password_file"

    log_action "phpMyAdmin installed at https://$domain/${PHPMYADMIN_URL_PREFIX}_$(basename $pma_path)"
    echo -e "${COLOR_GREEN}phpMyAdmin Setup Summary for $domain:${COLOR_RESET}"
    echo "  - URL: https://$domain/${PHPMYADMIN_URL_PREFIX}_$(basename $pma_path)"
    echo "  - User: $pma_user"
    echo -e "${COLOR_YELLOW}Note: Access phpMyAdmin with HTTP authentication credentials.${COLOR_RESET}"
}

# Install Fail2ban
install_fail2ban() {
    if is_package_installed fail2ban; then
        log_action "Fail2ban is already installed"
        return
    fi
    if ! prompt_yes_no "Install Fail2ban? (Protects against brute-force attacks)" "y"; then
        return
    fi
    install_packages fail2ban || return 1
    safe_exec "systemctl enable fail2ban" || log_action "Failed to enable Fail2ban" "err"
    safe_exec "systemctl start fail2ban" && check_service_status "fail2ban" || return 1

    # Configure Fail2ban jails
    cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 5
bantime = 3600
findtime = 600

[vsftpd]
enabled = true
maxretry = 5
bantime = 3600
findtime = 600

[wordpress]
enabled = true
port = http,https
filter = wordpress
logpath = /var/log/apache2/*error.log
          /var/log/nginx/*error.log
maxretry = 5
bantime = 3600
findtime = 600
EOF
    # Create WordPress filter
    cat > /etc/fail2ban/filter.d/wordpress.conf <<EOF
[Definition]
failregex = ^<HOST>.*"POST /wp-login.php
            ^<HOST>.*"POST /xmlrpc.php
ignoreregex =
EOF
    safe_exec "fail2ban-client reload" || return 1
    add_rollback_action "fail2ban" "systemctl stop fail2ban; systemctl disable fail2ban; rm -f /etc/fail2ban/jail.local /etc/fail2ban/filter.d/wordpress.conf"

    log_action "Fail2ban installed and configured"
    echo -e "${COLOR_GREEN}Fail2ban Setup Summary:${COLOR_RESET}"
    echo "  - Jails: SSH, SFTP, WordPress"
    echo -e "${COLOR_YELLOW}Note: Check bans with 'fail2ban-client status sshd'.${COLOR_RESET}"
}

# Configure AppArmor/SELinux
configure_apparmor_selinux() {
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        if ! is_package_installed apparmor; then
            if prompt_yes_no "Install AppArmor? (Enhances application security)" "y"; then
                install_packages apparmor apparmor-profiles || return 1
                safe_exec "systemctl enable apparmor" || log_action "Failed to enable AppArmor" "err"
                safe_exec "systemctl start apparmor" && check_service_status "apparmor" || return 1
            else
                return
            fi
        fi
        # Enable profiles for Apache/Nginx
        if is_package_installed apache2; then
            safe_exec "aa-enforce /etc/apparmor.d/usr.sbin.apache2" || log_action "Failed to enforce Apache AppArmor profile" "warning"
        fi
        if is_package_installed nginx; then
            safe_exec "aa-enforce /etc/apparmor.d/usr.sbin.nginx" || log_action "Failed to enforce Nginx AppArmor profile" "warning"
        fi
        log_action "AppArmor configured"
    elif [ "$os" = "redhat" ]; then
        if ! is_package_installed selinux-policy; then
            if prompt_yes_no "Install SELinux? (Enhances application security)" "y"; then
                install_packages selinux-policy selinux-policy-targeted || return 1
                safe_exec "setenforce 1" || log_action "Failed to enable SELinux" "err"
                safe_exec "sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config" || log_action "Failed to configure SELinux" "err"
            else
                return
            fi
        fi
        # Restore contexts for web server
        safe_exec "restorecon -R /var/www" || log_action "Failed to restore SELinux contexts" "warning"
        log_action "SELinux configured"
    fi
    echo -e "${COLOR_GREEN}Security Setup Summary:${COLOR_RESET}"
    echo "  - $([ "$os" = "debian" ] && echo "AppArmor" || echo "SELinux") enabled"
    echo -e "${COLOR_YELLOW}Note: Check profiles with 'aa-status' (AppArmor) or 'getenforce' (SELinux).${COLOR_RESET}"
}

# Install Docker
install_docker() {
    if is_package_installed docker; then
        log_action "Docker is already installed"
        return
    fi
    if ! prompt_yes_no "Install Docker and Docker Compose? (Supports containerized apps)" "y"; then
        return
    fi
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        install_packages docker.io docker-compose || return 1
    else
        install_packages docker docker-compose || return 1
    fi
    safe_exec "systemctl enable docker" || log_action "Failed to enable Docker" "err"
    safe_exec "systemctl start docker" && check_service_status "docker" || return 1
    add_rollback_action "docker" "systemctl stop docker; systemctl disable docker; apt-get remove -y docker.io docker-compose || yum remove -y docker docker-compose"
    
    log_action "Docker and Docker Compose installed"
    echo -e "${COLOR_GREEN}Docker Setup Summary:${COLOR_RESET}"
    echo "  - Docker: Installed"
    echo "  - Docker Compose: Installed"
    echo -e "${COLOR_YELLOW}Note: Use 'docker ps' to check running containers.${COLOR_RESET}"
}

# Install Composer
install_composer() {
    if command -v composer >/dev/null 2>&1; then
        log_action "Composer is already installed"
        return
    fi
    if ! prompt_yes_no "Install PHP Composer? (Manages PHP dependencies)" "y"; then
        return
    fi
    safe_exec "php -r \"copy('https://getcomposer.org/installer', 'composer-setup.php');\"" || return 1
    safe_exec "php composer-setup.php --install-dir=/usr/local/bin --filename=composer" || return 1
    safe_exec "rm composer-setup.php" || return 1
    add_rollback_action "composer" "rm -f /usr/local/bin/composer"
    
    log_action "Composer installed"
    echo -e "${COLOR_GREEN}Composer Setup Summary:${COLOR_RESET}"
    echo "  - Composer: Installed globally"
    echo -e "${COLOR_YELLOW}Note: Run 'composer --version' to verify.${COLOR_RESET}"
}

# Setup wizard
setup_wizard() {
    echo -e "${COLOR_GREEN}Starting VPS Setup Wizard v$VERSION${COLOR_RESET}"
    echo "Checking system requirements..."
    # Check root access
    [ "$(id -u)" != "0" ] && { echo -e "${COLOR_RED}Error: Must run as root. Use sudo.${COLOR_RESET}"; exit 1; }
    # Check internet
    check_internet || exit 1
    # Detect OS
    local os=$(detect_os)
    if [ "$os" = "unknown" ]; then
        log_action "Unsupported OS" "err"
        echo -e "${COLOR_RED}Error: Unsupported OS. This script supports Ubuntu/Debian or CentOS/RHEL/Fedora.${COLOR_RESET}"
        exit 1
    fi
    log_action "Detected OS: $os"
    # Check server IP
    local server_ip=$(detect_server_ip) || exit 1
    echo -e "${COLOR_GREEN}Server IP: $server_ip${COLOR_RESET}"
    # Check dependencies
    check_dependencies || exit 1
    # Install firewall
    install_firewall || exit 1
    echo -e "${COLOR_GREEN}Setup Wizard completed successfully!${COLOR_RESET}"
}

# Display menu
display_menu() {
    echo -e "${COLOR_GREEN}VPS Setup Script v$VERSION${COLOR_RESET}"
    echo "Main Menu:"
    echo "1. Configure a new domain (set up website, SFTP, database, email)"
    echo "2. Install WordPress (with automated database setup)"
    echo "3. Set up Git repository (with deployment hooks)"
    echo "4. Install phpMyAdmin (secure database management)"
    echo "5. Install webmail (access email via browser)"
    echo "6. Edit PHP settings (adjust memory, file uploads)"
    echo "7. Configure security (Fail2ban, AppArmor/SELinux)"
    echo "8. Install Docker and Composer"
    echo "9. Delete a domain (remove all resources)"
    echo "10. Exit"
    read -p "Select an option [1-10]: " choice
    case "$choice" in
        1) configure_domain; display_menu ;;
        2) install_wordpress; display_menu ;;
        3) setup_git_repository; display_menu ;;
        4) install_phpmyadmin; display_menu ;;
        5) install_webmail "$(prompt_input "Enter domain for webmail (e.g., example.com)" "")"; display_menu ;;
        6) edit_php_ini; display_menu ;;
        7) install_fail2ban && configure_apparmor_selinux; display_menu ;;
        8) install_docker && install_composer; display_menu ;;
        9) delete_domain; display_menu ;;
        10) log_action "Exiting script"; exit 0 ;;
        *) log_action "Invalid option: $choice" "err"; echo -e "${COLOR_RED}Please enter a number between 1 and 10.${COLOR_RESET}"; display_menu ;;
    esac
}

# Process domains from file
process_domains_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        log_action "Domains file $file not found" "err"
        echo -e "${COLOR_RED}Error: File $file not found.${COLOR_RESET}"
        exit 1
    fi
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        validate_domain "$domain" || continue
        validate_dns "$domain" || continue
        configure_domain "$domain" || log_action "Failed to configure $domain" "err"
    done < "$file"
}

# Display help
display_help() {
    echo "VPS Setup Script v$VERSION"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --non-interactive    Run in non-interactive mode with defaults"
    echo "  --dry-run           Preview actions without executing them"
    echo "  --domains FILE      Process domains from FILE (one per line)"
    echo "  --config FILE       Use custom configuration file"
    echo "  --verbose           Enable verbose output"
    echo "  -h, --help          Display this help message"
    echo ""
    echo "Configuration File: $CONFIG_FILE"
    echo "  ssh_port=2222"
    echo "  web_user=www-data"
    echo "  web_group=www-data"
    echo "  gpg_recipient=admin@yourdomain.com"
    echo "  wordpress_install=yes"
    echo "  phpmyadmin_url_prefix=dbadmin"
    echo "  docker_install=yes"
    echo ""
    echo "Logs: $LOG_FILE"
    echo "Backups: $BACKUP_DIR"
    echo "Credentials: $CREDENTIALS_FILE (GPG-encrypted if gpg_recipient set)"
    echo ""
    echo "Example:"
    echo "  sudo $0                     # Interactive mode"
    echo "  sudo $0 --non-interactive   # Non-interactive with defaults"
    echo "  sudo $0 --domains domains.txt  # Process domains from file"
    echo "  sudo $0 --dry-run           # Preview actions"
}

# Main function
main() {
    DRY_RUN="false"
    VERBOSE="false"
    NON_INTERACTIVE="false"
    DOMAINS_FILE=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --non-interactive) NON_INTERACTIVE="true"; shift ;;
            --dry-run) DRY_RUN="true"; shift ;;
            --domains) DOMAINS_FILE="$2"; shift 2 ;;
            --config) CONFIG_FILE="$2"; shift 2 ;;
            --verbose) VERBOSE="true"; shift ;;
            -h|--help) display_help; exit 0 ;;
            *) echo -e "${COLOR_RED}Unknown option: $1${COLOR_RESET}"; display_help; exit 1 ;;
        esac
    done

    # Display author details
    echo "VPS Setup Script v$VERSION"
    echo "Author: Yogesh Gupta (yk68785@gmail.com)"
    echo "GitHub: https://github.com/Yogesh0610"
    echo "License: MIT License"
    echo ""

    # Load configuration
    load_config

    # Run setup wizard
    setup_wizard || exit 1

    if [ "$NON_INTERACTIVE" = "true" ]; then
        log_action "Running in non-interactive mode"
        if [ -n "$DOMAINS_FILE" ]; then
            process_domains_file "$DOMAINS_FILE"
        else
            configure_domain ""
        fi
    elif [ -n "$DOMAINS_FILE" ]; then
        process_domains_file "$DOMAINS_FILE"
    else
        display_menu
    fi
}

# Execute main
main "$@"
