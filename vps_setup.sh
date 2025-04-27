#!/bin/bash

# VPS Setup Script v2.7.0
# Author: Yogesh Gupta
# Email: yk68785@gmail.com
# GitHub: https://github.com/Yogesh0610
# Description: A user-friendly script to configure a VPS with web hosting, database, email, and security features.
# License: MIT License

# Constants
VERSION="2.7.0"
CONFIG_FILE="/etc/vps_setup.conf"
CREDENTIALS_FILE="/root/vps_credentials.txt"
LOG_FILE="/var/log/vps_setup.log"
TEMP_DIR="/tmp/vps_setup_$(date +%s)"
BACKUP_DIR="/backups"
SSH_PORT="${VPS_SSH_PORT:-2222}"
WEB_USER="www-data"
WEB_GROUP="www-data"
GPG_RECIPIENT="${VPS_GPG_RECIPIENT:-}"
WORDPRESS_INSTALL="${VPS_WORDPRESS_INSTALL:-no}"
PHPMYADMIN_URL_PREFIX="dbadmin"
DOCKER_INSTALL="${VPS_DOCKER_INSTALL:-no}"
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_RESET='\033[0m'

# Global variables
rollback_actions=()
rollback_needed=false
summary=""
DRY_RUN="false"
VERBOSE="false"
NON_INTERACTIVE="false"

# Ensure script is run as root
if [ "$(id -u)" != "0" ]; then
    echo -e "${COLOR_RED}This script must be run as root. Use sudo.${COLOR_RESET}"
    exit 1
fi

# Create temporary directory
mkdir -p "$TEMP_DIR" || { echo -e "${COLOR_RED}Failed to create temporary directory $TEMP_DIR${COLOR_RESET}"; exit 1; }
trap 'rm -rf "$TEMP_DIR" /tmp/vps_setup_dry_run_*.log' EXIT

# Logging function
log_action() {
    local message="$1"
    local level="${2:-info}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    if [ "$VERBOSE" = "true" ] || [ "$level" = "err" ]; then
        case "$level" in
            err) echo -e "${COLOR_RED}[$timestamp] ERROR: $message${COLOR_RESET}" ;;
            warning) echo -e "${COLOR_YELLOW}[$timestamp] WARNING: $message${COLOR_RESET}" ;;
            *) echo -e "${COLOR_GREEN}[$timestamp] INFO: $message${COLOR_RESET}" ;;
        esac
    fi
    echo "[$timestamp] $level: $message" >> "$LOG_FILE"
    # Rotate logs if size exceeds 5MB or keep max 5 logs
    if [ -f "$LOG_FILE" ] && [ "$(stat -f %z "$LOG_FILE" 2>/dev/null || stat -c %s "$LOG_FILE")" -gt 5242880 ]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date +%s)"
        find /var/log -name 'vps_setup.log.*' | sort -r | tail -n +5 | xargs -I {} rm -f {}
    fi
}

# Safe execution wrapper
safe_exec() {
    local cmd="$1"
    if [ "$DRY_RUN" = "true" ]; then
        echo "[DRY-RUN] Would execute: $cmd" >> "/tmp/vps_setup_dry_run_$(date +%s).log"
        return 0
    fi
    if [ "$VERBOSE" = "true" ]; then
        echo "[EXEC] $cmd"
    fi
    eval "$cmd" >/dev/null 2>&1
    local status=$?
    if [ $status -ne 0 ]; then
        log_action "Command failed: $cmd" "err"
        rollback_needed=true
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
    if [ "$NON_INTERACTIVE" = "true" ] && [ -n "$default" ]; then
        echo "$default"
        return 0
    fi
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
    if [ "$NON_INTERACTIVE" = "true" ]; then
        [ "$default" = "y" ] && return 0 || return 1
    fi
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

# Validate email
validate_email() {
    local email="$1"
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_action "Invalid email format: $email" "err"
        echo -e "${COLOR_RED}Error: Invalid email format.${COLOR_RESET}"
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

# Detect OS
detect_os() {
    if [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu) echo "debian" ;;
            centos) echo "redhat" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

# Check if package is installed
is_package_installed() {
    local pkg="$1"
    local os=$(detect_os)
    case "$os" in
        debian) dpkg -s "$pkg" >/dev/null 2>&1 ;;
        redhat) rpm -q "$pkg" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

# Install packages
install_packages() {
    local os=$(detect_os)
    case "$os" in
        debian)
            safe_exec "apt-get update" || return 1
            safe_exec "apt-get install -y $*" || return 1
            ;;
        redhat)
            safe_exec "yum install -y $*" || return 1
            ;;
        *)
            log_action "Unsupported OS for package installation" "err"
            return 1
            ;;
    esac
    return 0
}

# Check dependencies
check_dependencies() {
    local deps=("curl" "wget" "openssl" "mysql" "certbot" "git")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log_action "$dep not found, attempting to install" "warning"
            install_packages "$dep" || return 1
        fi
    done
    return 0
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
    local server_ip=$(prompt_input "Enter server IP (detected: $(detect_server_ip))" "$(detect_server_ip)") || return 1
    local domain_ip=$(dig +short "$domain" A | head -n 1)
    if [ -z "$domain_ip" ]; then
        log_action "DNS resolution failed for $domain" "err"
        echo -e "${COLOR_RED}Error: DNS resolution failed for $domain. Check DNS settings.${COLOR_RESET}"
        return 1
    fi
    if [ "$domain_ip" != "$server_ip" ]; then
        log_action "DNS for $domain resolves to $domain_ip, not server IP $server_ip" "err"
        echo -e "${COLOR_RED}Error: DNS for $domain resolves to $domain_ip, not this server ($server_ip).${COLOR_RESET}"
        return 1
    fi
    return 0
}

# Detect PHP version
detect_php_version() {
    local php_version=$(php -v 2>/dev/null | grep -oP 'PHP \K[0-9]+\.[0-9]+' | head -1)
    if [ -z "$php_version" ]; then
        log_action "PHP not installed, installing version 8.4" "warning"
        install_packages php8.4 php8.4-fpm php8.4-mysql || return 1
        php_version="8.4"
    fi
    if ! systemctl is-active --quiet "php${php_version}-fpm"; then
        log_action "PHP-FPM service not running" "err"
        return 1
    fi
    echo "$php_version"
}

# Check MySQL access
check_mysql_access() {
    local mysql_cred=""
    if mysql -u root -e "SELECT 1" >/dev/null 2>&1; then
        mysql_cred="-u root"
    elif [ -f /root/.my.cnf ]; then
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
        echo -e "${COLOR_RED}Error: MySQL access failed. Verify credentials or run 'mysql_secure_installation'.${COLOR_RESET}"
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
        [ -n "$(command -v vsftpd)" ] && safe_exec "ufw allow 21/tcp"
        [ -n "$(command -v postfix)" ] && safe_exec "ufw allow 25/tcp" && safe_exec "ufw allow 587/tcp"
        safe_exec "ufw enable" || return 1
        log_action "Firewall configured with UFW"
    else
        if ! is_package_installed firewalld; then
            install_packages firewalld || return 1
        fi
        safe_exec "firewall-cmd --permanent --add-port=$SSH_PORT/tcp" || return 1
        safe_exec "firewall-cmd --permanent --add-service=http" || return 1
        safe_exec "firewall-cmd --permanent --add-service=https" || return 1
        [ -n "$(command -v vsftpd)" ] && safe_exec "firewall-cmd --permanent --add-service=ftp"
        [ -n "$(command -v postfix)" ] && safe_exec "firewall-cmd --permanent --add-service=smtp"
        safe_exec "firewall-cmd --reload" || return 1
        safe_exec "systemctl enable firewalld" || return 1
        safe_exec "systemctl start firewalld" && check_service_status "firewalld" || return 1
        log_action "Firewall configured with firewalld"
    fi
}

# Encrypt credentials
encrypt_credentials_incremental() {
    local file="$1"
    if [ -n "$GPG_RECIPIENT" ] && [ -s "$file" ]; then
        if ! gpg --list-keys "$GPG_RECIPIENT" >/dev/null 2>&1; then
            log_action "GPG key for $GPG_RECIPIENT not found" "err"
            echo -e "${COLOR_RED}Error: GPG key for $GPG_RECIPIENT not found. Credentials not encrypted.${COLOR_RESET}"
            return 1
        fi
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
        domain=$(prompt_input "Enter domain (e.g., example.com)" "${VPS_DOMAIN:-}")
        validate_domain "$domain" || return 1
        validate_dns "$domain" || return 1
    fi
    local document_root=$(sanitize_path "/var/www/$domain/html")
    local db_name="${domain//./_}"
    local db_user="${domain//./_}"
    local db_password_file=$(generate_password)
    local db_password=$(cat "$db_password_file")
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local php_version=$(detect_php_version) || return 1
    local php_socket=$(find /run/php /var/run/php -name "php${php_version}-fpm*.sock" 2>/dev/null | head -n 1)
    [ -z "$php_socket" ] && { log_action "PHP-FPM socket not found for version $php_version" "err"; return 1; }
    rollback_needed=false
    summary="Domain Setup Summary for $domain:\n"

    safe_exec "mkdir -p $document_root" || return 1
    safe_exec "chown $WEB_USER:$WEB_GROUP $document_root" || return 1
    safe_exec "chmod 750 $document_root" || return 1
    echo "<html><body><h1>Welcome to $domain</h1></body></html>" > "$document_root/index.html"
    add_rollback_action "document_root" "rm -rf /var/www/$domain"

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
        safe_exec "mv $TEMP_DIR/$domain.conf /etc/apache2/sites-available/$domain.conf" || return 1
        safe_exec "a2ensite $domain.conf" || return 1
        safe_exec "systemctl reload apache2" && check_service_status "apache2" || return 1
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
        safe_exec "mv $TEMP_DIR/$domain.conf /etc/nginx/sites-available/$domain" || return 1
        safe_exec "ln -s /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/" || return 1
        safe_exec "systemctl reload nginx" && check_service_status "nginx" || return 1
        add_rollback_action "nginx_vhost" "rm -f /etc/nginx/sites-enabled/$domain /etc/nginx/sites-available/$domain; systemctl reload nginx"
    fi
    summary="$summary  - Website folder: $document_root\n  - Website URL: https://$domain\n"

    local email=$(prompt_input "Enter admin email for SSL" "${VPS_EMAIL:-admin@$domain}")
    validate_email "$email" || return 1
    safe_exec "certbot --$web_server --agree-tos --email $email --no-eff-email -d $domain -d www.$domain" || return 1
    add_rollback_action "ssl" "certbot delete --cert-name $domain"

    local MYSQL_CRED=$(check_mysql_access) || return 1
    if prompt_yes_no "Create a database for $domain?" "y"; then
        safe_exec "mysql $MYSQL_CRED -e 'CREATE DATABASE $db_name;'" || return 1
        safe_exec "mysql $MYSQL_CRED -e 'CREATE USER \"$db_user\"@\"localhost\" IDENTIFIED BY \"$db_password\";'" || return 1
        safe_exec "mysql $MYSQL_CRED -e 'GRANT ALL PRIVILEGES ON $db_name.* TO \"$db_user\"@\"localhost\";'" || return 1
        safe_exec "mysql $MYSQL_CRED -e 'FLUSH PRIVILEGES;'" || return 1
        add_rollback_action "database" "mysql $MYSQL_CRED -e 'DROP DATABASE $db_name; DROP USER \"$db_user\"@\"localhost\";'"
        summary="$summary  - Database: $db_name\n  - Database User: $db_user\n"
    fi

    if [ -n "$db_password" ] && prompt_yes_no "Save database credentials to $CREDENTIALS_FILE?" "n"; then
        echo "Database $db_name with user $db_user for $domain: $db_password" >> "$CREDENTIALS_FILE"
        safe_exec "chmod 600 $CREDENTIALS_FILE" || return 1
        encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
    fi
    cleanup_password "$db_password_file"

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}Domain setup failed for $domain. All changes rolled back.${COLOR_RESET}"
        return 1
    fi
    log_action "Domain $domain configured successfully"
    echo -e "${COLOR_GREEN}$summary${COLOR_RESET}"
}

# Install WordPress
install_wordpress() {
    local domain="$1"
    validate_domain "$domain" || return 1
    validate_dns "$domain" || return 1
    local document_root=$(sanitize_path "/var/www/$domain/html")
    local wp_db="wp_${domain//./_}"
    local wp_user="wp_${domain//./_}"
    local wp_password_file=$(generate_password)
    local wp_password=$(cat "$wp_password_file")
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local php_version=$(detect_php_version) || return 1
    local php_socket=$(find /run/php /var/run/php -name "php${php_version}-fpm*.sock" 2>/dev/null | head -n 1)
    [ -z "$php_socket" ] && { log_action "PHP-FPM socket not found for version $php_version" "err"; return 1; }
    rollback_needed=false

    safe_exec "mkdir -p $document_root" || return 1
    safe_exec "wget -q https://wordpress.org/latest.tar.gz -O $TEMP_DIR/wordpress.tar.gz" || return 1
    safe_exec "tar -xzf $TEMP_DIR/wordpress.tar.gz -C $TEMP_DIR" || return 1
    safe_exec "mv $TEMP_DIR/wordpress/* $document_root/" || return 1
    safe_exec "chown -R $WEB_USER:$WEB_GROUP $document_root" || return 1
    safe_exec "chmod -R 750 $document_root" || return 1
    safe_exec "find $document_root/wp-content -type d -exec chmod 755 {} \;" || return 1
    add_rollback_action "wordpress_files" "rm -rf $document_root"

    local MYSQL_CRED=$(check_mysql_access) || return 1
    safe_exec "mysql $MYSQL_CRED -e 'CREATE DATABASE $wp_db;'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'CREATE USER \"$wp_user\"@\"localhost\" IDENTIFIED BY \"$wp_password\";'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'GRANT ALL PRIVILEGES ON $wp_db.* TO \"$wp_user\"@\"localhost\";'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'FLUSH PRIVILEGES;'" || return 1
    add_rollback_action "wordpress_db" "mysql $MYSQL_CRED -e 'DROP DATABASE $wp_db; DROP USER \"$wp_user\"@\"localhost\";'"

    safe_exec "cp $document_root/wp-config-sample.php $document_root/wp-config.php" || return 1
    safe_exec "sed -i \"s/database_name_here/$wp_db/\" $document_root/wp-config.php" || return 1
    safe_exec "sed -i \"s/username_here/$wp_user/\" $document_root/wp-config.php" || return 1
    safe_exec "sed -i \"s/password_here/$wp_password/\" $document_root/wp-config.php" || return 1

    if prompt_yes_no "Save WordPress credentials to $CREDENTIALS_FILE?" "n"; then
        echo "WordPress database $wp_db with user $wp_user for $domain: $wp_password" >> "$CREDENTIALS_FILE"
        safe_exec "chmod 600 $CREDENTIALS_FILE" || return 1
        encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
    fi
    cleanup_password "$wp_password_file"

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}WordPress setup failed for $domain. All changes rolled back.${COLOR_RESET}"
        return 1
    fi
    log_action "WordPress installed for $domain"
    echo -e "${COLOR_GREEN}WordPress installed at https://$domain${COLOR_RESET}"
}

# Setup Git repository
setup_git_repository() {
    local domain="$1"
    validate_domain "$domain" || return 1
    validate_dns "$domain" || return 1
    local document_root=$(sanitize_path "/var/www/$domain/html")
    local git_dir="/var/www/$domain/git"
    rollback_needed=false

    if ! command -v git >/dev/null 2>&1; then
        install_packages git || return 1
    fi

    safe_exec "mkdir -p $git_dir" || return 1
    safe_exec "cd $git_dir && git init --bare" || return 1
    safe_exec "chown -R $WEB_USER:$WEB_GROUP $git_dir" || return 1
    safe_exec "chmod -R 770 $git_dir" || return 1
    add_rollback_action "git_repo" "rm -rf $git_dir"

    cat > "$git_dir/hooks/post-receive" <<EOF
#!/bin/bash
GIT_WORK_TREE=$document_root git checkout -f
chown -R $WEB_USER:$WEB_GROUP $document_root
chmod -R 750 $document_root
EOF
    safe_exec "chmod +x $git_dir/hooks/post-receive" || return 1

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}Git repository setup failed for $domain. All changes rolled back.${COLOR_RESET}"
        return 1
    fi
    log_action "Git repository set up for $domain"
    echo -e "${COLOR_GREEN}Git repository created at $git_dir${COLOR_RESET}"
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
    local php_version=$(detect_php_version) || return 1
    local php_socket=$(find /run/php /var/run/php -name "php${php_version}-fpm*.sock" 2>/dev/null | head -n 1)
    [ -z "$php_socket" ] && { log_action "PHP-FPM socket not found for version $php_version" "err"; return 1; }
    rollback_needed=false

    if ! is_package_installed roundcube; then
        install_packages roundcube roundcube-mysql || return 1
    fi

    safe_exec "mkdir -p $document_root" || return 1
    safe_exec "ln -s /usr/share/roundcube $document_root/roundcube" || return 1
    safe_exec "chown -R $WEB_USER:$WEB_GROUP $document_root" || return 1
    safe_exec "chmod -R 750 $document_root" || return 1
    add_rollback_action "webmail_document_root" "rm -rf /var/www/$webmail_domain"

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
        safe_exec "mv $TEMP_DIR/$webmail_domain.conf /etc/apache2/sites-available/$webmail_domain.conf" || return 1
        safe_exec "a2ensite $webmail_domain.conf" || return 1
        safe_exec "systemctl reload apache2" && check_service_status "apache2" || return 1
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
        safe_exec "mv $TEMP_DIR/$webmail_domain.conf /etc/nginx/sites-available/$webmail_domain" || return 1
        safe_exec "ln -s /etc/nginx/sites-available/$webmail_domain /etc/nginx/sites-enabled/" || return 1
        safe_exec "systemctl reload nginx" && check_service_status "nginx" || return 1
        add_rollback_action "webmail_nginx_vhost" "rm -f /etc/nginx/sites-enabled/$webmail_domain /etc/nginx/sites-available/$webmail_domain; systemctl reload nginx"
    fi

    local email=$(prompt_input "Enter admin email for webmail SSL" "${VPS_EMAIL:-admin@$domain}")
    validate_email "$email" || return 1
    safe_exec "certbot --$web_server --agree-tos --email $email --no-eff-email -d $webmail_domain" || return 1
    add_rollback_action "webmail_ssl" "certbot delete --cert-name $webmail_domain"

    local MYSQL_CRED=$(check_mysql_access) || return 1
    safe_exec "mysql $MYSQL_CRED -e 'CREATE DATABASE $db_name;'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'CREATE USER \"$db_user\"@\"localhost\" IDENTIFIED BY \"$db_password\";'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'GRANT ALL PRIVILEGES ON $db_name.* TO \"$db_user\"@\"localhost\";'" || return 1
    safe_exec "mysql $MYSQL_CRED -e 'FLUSH PRIVILEGES;'" || return 1
    safe_exec "mysql $MYSQL_CRED $db_name < /usr/share/roundcube/SQL/mysql.initial.sql" || return 1
    add_rollback_action "webmail_database" "mysql $MYSQL_CRED -e 'DROP DATABASE $db_name; DROP USER \"$db_user\"@\"localhost\";'"

    local config_file="/etc/roundcube/config.inc.php"
    safe_exec "sed -i \"s|mysql://roundcube:.*@localhost/roundcubemail|mysql://$db_user:$db_password@localhost/$db_name|\" $config_file" || return 1
    safe_exec "sed -i \"s|\$config\['default_host'\] = .*;|\$config\['default_host'\] = 'localhost';|\" $config_file" || return 1
    add_rollback_action "webmail_config" "sed -i \"s|mysql://$db_user:.*@localhost/$db_name|mysql://roundcube:pass@localhost/roundcubemail|\" $config_file"

    if prompt_yes_no "Save webmail credentials to $CREDENTIALS_FILE?" "n"; then
        echo "Webmail database $db_name with user $db_user for $domain: $db_password" >> "$CREDENTIALS_FILE"
        safe_exec "chmod 600 $CREDENTIALS_FILE" || return 1
        encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
    fi
    cleanup_password "$db_password_file"

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}Webmail setup failed for $domain. All changes rolled back.${COLOR_RESET}"
        return 1
    fi
    log_action "Webmail installed for $domain at https://$webmail_domain"
    echo -e "${COLOR_GREEN}Webmail installed at https://$webmail_domain${COLOR_RESET}"
}

# Install phpMyAdmin
install_phpmyadmin() {
    local domain="$1"
    validate_domain "$domain" || return 1
    validate_dns "$domain" || return 1
    local pma_path="/usr/share/${PHPMYADMIN_URL_PREFIX}_$(openssl rand -hex 4)"
    local pma_user="pma_$(openssl rand -hex 4)"
    local pma_password_file=$(generate_password)
    local pma_password=$(cat "$pma_password_file")
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local php_version=$(detect_php_version) || return 1
    local php_socket=$(find /run/php /var/run/php -name "php${php_version}-fpm*.sock" 2>/dev/null | head -n 1)
    [ -z "$php_socket" ] && { log_action "PHP-FPM socket not found for version $php_version" "err"; return 1; }
    rollback_needed=false

    install_packages phpmyadmin || return 1
    safe_exec "mv /usr/share/phpmyadmin $pma_path" || return 1
    safe_exec "chown -R $WEB_USER:$WEB_GROUP $pma_path" || return 1
    safe_exec "find $pma_path -type d -exec chmod 750 {} \;" || return 1
    safe_exec "find $pma_path -type f -exec chmod 640 {} \;" || return 1
    add_rollback_action "phpmyadmin_files" "rm -rf $pma_path"

    local htpasswd_file="/etc/phpmyadmin/.htpasswd"
    safe_exec "htpasswd -cb $htpasswd_file $pma_user $pma_password" || return 1
    add_rollback_action "phpmyadmin_htpasswd" "rm -f $htpasswd_file"

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

    if prompt_yes_no "Save phpMyAdmin credentials to $CREDENTIALS_FILE?" "n"; then
        echo "phpMyAdmin user $pma_user for $domain: $pma_password" >> "$CREDENTIALS_FILE"
        safe_exec "chmod 600 $CREDENTIALS_FILE" || return 1
        encrypt_credentials_incremental "$CREDENTIALS_FILE" || log_action "Failed to encrypt credentials" "err"
    fi
    cleanup_password "$pma_password_file"

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}phpMyAdmin setup failed for $domain. All changes rolled back.${COLOR_RESET}"
        return 1
    fi
    log_action "phpMyAdmin installed for $domain"
    echo -e "${COLOR_GREEN}phpMyAdmin installed at https://$domain/${PHPMYADMIN_URL_PREFIX}_$(basename $pma_path)${COLOR_RESET}"
}

# Install Fail2ban
install_fail2ban() {
    if is_package_installed fail2ban; then
        log_action "Fail2ban is already installed"
        return 0
    fi
    rollback_needed=false
    install_packages fail2ban || return 1
    safe_exec "systemctl enable fail2ban" || return 1
    safe_exec "systemctl start fail2ban" && check_service_status "fail2ban" || return 1

    cat > /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 5
bantime = 3600
findtime = 600
EOF
    safe_exec "fail2ban-client reload" || return 1
    add_rollback_action "fail2ban" "systemctl stop fail2ban; systemctl disable fail2ban; rm -f /etc/fail2ban/jail.local"

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}Fail2ban setup failed. All changes rolled back.${COLOR_RESET}"
        return 1
    fi
    log_action "Fail2ban installed"
    echo -e "${COLOR_GREEN}Fail2ban installed with SSH protection${COLOR_RESET}"
}

# Install Docker
install_docker() {
    if is_package_installed docker; then
        log_action "Docker is already installed"
        return 0
    fi
    rollback_needed=false
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        install_packages apt-transport-https ca-certificates gnupg lsb-release || return 1
        safe_exec "curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg" || return 1
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
        safe_exec "apt-get update" || return 1
        safe_exec "apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose" || return 1
    else
        install_packages docker docker-compose || return 1
    fi
    safe_exec "systemctl enable docker" || return 1
    safe_exec "systemctl start docker" && check_service_status "docker" || return 1
    add_rollback_action "docker" "systemctl stop docker; systemctl disable docker; apt-get remove -y docker-ce docker-ce-cli containerd.io docker-compose || yum remove -y docker docker-compose"

    if [ "$rollback_needed" = "true" ]; then
        execute_rollback
        echo -e "${COLOR_RED}Docker setup failed. All changes rolled back.${COLOR_RESET}"
        return 1
    fi
    log_action "Docker installed"
    echo -e "${COLOR_GREEN}Docker installed${COLOR_RESET}"
}

# Display menu
display_menu() {
    echo -e "${COLOR_GREEN}VPS Setup Script v$VERSION${COLOR_RESET}"
    echo "1. Configure domain"
    echo "2. Install WordPress"
    echo "3. Setup Git repository"
    echo "4. Install phpMyAdmin"
    echo "5. Install webmail"
    echo "6. Install Fail2ban"
    echo "7. Install Docker"
    echo "8. Exit"
    read -p "Select an option [1-8]: " choice
    case "$choice" in
        1) configure_domain ""; display_menu ;;
        2) install_wordpress "$(prompt_input "Enter domain for WordPress" "${VPS_DOMAIN:-}")"; display_menu ;;
        3) setup_git_repository "$(prompt_input "Enter domain for Git" "${VPS_DOMAIN:-}")"; display_menu ;;
        4) install_phpmyadmin "$(prompt_input "Enter domain for phpMyAdmin" "${VPS_DOMAIN:-}")"; display_menu ;;
        5) install_webmail "$(prompt_input "Enter domain for webmail" "${VPS_DOMAIN:-}")"; display_menu ;;
        6) install_fail2ban; display_menu ;;
        7) install_docker; display_menu ;;
        8) exit 0 ;;
        *) echo -e "${COLOR_RED}Invalid option${COLOR_RESET}"; display_menu ;;
    esac
}

# Main function
main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --non-interactive) NON_INTERACTIVE="true"; shift ;;
            --dry-run) DRY_RUN="true"; shift ;;
            --verbose) VERBOSE="true"; shift ;;
            -h|--help) echo "Usage: $0 [--non-interactive] [--dry-run] [--verbose]"; echo "Environment variables: VPS_DOMAIN, VPS_EMAIL, VPS_SSH_PORT, VPS_GPG_RECIPIENT"; exit 0 ;;
            *) echo -e "${COLOR_RED}Unknown option: $1${COLOR_RESET}"; exit 1 ;;
        esac
    done

    echo "VPS Setup Script v$VERSION by Yogesh Gupta"
    check_internet || exit 1
    check_dependencies || exit 1
    install_firewall || exit 1
    if [ "$NON_INTERACTIVE" = "true" ]; then
        configure_domain "${VPS_DOMAIN:-}"
    else
        display_menu
    fi
}

main "$@"
