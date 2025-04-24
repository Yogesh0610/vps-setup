#!/bin/bash

# Global variables
VERSION="2.1.1"
LOG_FILE="/var/log/vps_setup.log"
CREDENTIALS_FILE="/root/credentials.txt"
BACKUP_DIR="/backups"
CONFIG_FILE="/etc/vps_setup.conf"
DRY_RUN=false
INTERACTIVE=true

# Ensure script exits on errors
set -e

# Logging function
log_action() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
    echo "$message"
}

# Display author details
display_author_details() {
    cat <<EOF

============================================================
Author Details
============================================================
Name: Yogesh Gupta
Email: yk68785@gmail.com
GitHub: https://github.com/Yogesh0610
LinkedIn: https://www.linkedin.com/in/yogesh-gupta-64610a169/

About:
🚀 Software Engineer | PHP, React.js, React Native, Laravel

Passionate about crafting seamless web and mobile experiences. With a knack for PHP, React.js, React Native, and Laravel, I transform ideas into high-performance applications.

Key Skills:
- PHP: Proficient in building robust backend systems and APIs.
- React.js: Expertise in developing interactive and high-performance web applications.
- React Native: Skilled in creating cross-platform mobile apps with a seamless user experience.
- Laravel: Experienced in leveraging Laravel’s powerful features to build scalable and maintainable applications.

Philosophy:
Always learning, always innovating. I aim to exceed expectations and embrace challenges that push my technical boundaries.

Disclaimer:
The author, Yogesh Gupta, is not responsible for any damages, data loss, or issues arising from the use of this script. Use at your own risk and ensure you have backups and proper testing in place before running this script in a production environment.
============================================================

EOF
    log_action "Displayed author details."
}

# Safe execution with error logging
safe_exec() {
    local cmd="$1"
    local error_file="/tmp/cmd_error_$$"
    if [ "$DRY_RUN" = "true" ]; then
        log_action "[DRY RUN] Would execute: $cmd"
        return 0
    fi
    if ! $cmd 2>"$error_file"; then
        local error_msg
        error_msg=$(cat "$error_file")
        log_action "ERROR: Command failed: $cmd"
        log_action "ERROR Details: $error_msg"
        rm -f "$error_file"
        return 1
    fi
    rm -f "$error_file"
    return 0
}

# Secure password generation
generate_password() {
    local password
    password=$(openssl rand -base64 16 | head -c 20)
    echo "$password" > "/tmp/temp_pass_$$"
    chmod 600 "/tmp/temp_pass_$$"
    echo "/tmp/temp_pass_$$"
}

# Clean up temporary password files
cleanup_password() {
    local file="$1"
    [ -f "$file" ] && rm -f "$file"
}

# Input validation functions
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_action "Invalid domain name: $domain"
        return 1
    fi
    return 0
}

validate_php_version() {
    local version="$1"
    local valid_versions=("7.0" "7.1" "7.2" "7.3" "7.4" "8.0" "8.1" "8.2" "8.3" "8.4")
    for v in "${valid_versions[@]}"; do
        if [ "$v" = "$version" ]; then
            return 0
        fi
    done
    log_action "Invalid PHP version: $version"
    return 1
}

# Function to prompt user for yes/no input
prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local response
    if [ "$INTERACTIVE" = "false" ]; then
        return 0
    fi
    while true; do
        read -p "$prompt [Y/n]: " response
        response=${response:-$default}
        case $response in
            [Yy]* ) return 0 ;;
            [Nn]* ) return 1 ;;
            * ) echo "Please answer y or n." ;;
        esac
    done
}

# Function to prompt for input with a default value
prompt_input() {
    local prompt="$1"
    local default="$2"
    local input
    if [ "$INTERACTIVE" = "false" ]; then
        echo "$default"
        return
    fi
    read -p "$prompt [$default]: " input
    echo "${input:-$default}"
}

# Function to prompt for selection
prompt_select() {
    local prompt="$1"
    local options="$2"
    local default="$3"
    local selection
    if [ "$INTERACTIVE" = "false" ]; then
        echo "$default"
        return
    fi
    echo "$prompt"
    select selection in $options; do
        if [ -n "$selection" ]; then
            echo "$selection"
            return 0
        fi
        echo "Invalid selection."
    done
    echo "$default"
    return 1
}

# Detect operating system
detect_os() {
    if [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    else
        log_action "Unsupported OS."
        exit 1
    fi
}

# Check if a package is installed
is_package_installed() {
    local package="$1"
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        dpkg -l "$package" &> /dev/null
    else
        rpm -q "$package" &> /dev/null
    fi
    return $?
}

# Install package
install_package() {
    local package="$1"
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        safe_exec "apt-get install -y $package" || return 1
    else
        safe_exec "yum install -y $package" || return 1
    fi
    log_action "Installed $package."
}

# Check if a domain is already configured
is_domain_configured() {
    local domain="$1"
    local web_server="$2"
    if [ "$web_server" = "apache" ]; then
        [ -f "/etc/apache2/sites-available/$domain.conf" ]
    else
        [ -f "/etc/nginx/sites-available/$domain" ]
    fi
    return $?
}

# Get list of configured domains
get_configured_domains() {
    local web_server="$1"
    if [ "$web_server" = "apache" ]; then
        ls /etc/apache2/sites-available/*.conf 2>/dev/null | sed 's|/etc/apache2/sites-available/||;s|\.conf$||' || echo ""
    else
        ls /etc/nginx/sites-available/* 2>/dev/null | grep -v default | sed 's|/etc/nginx/sites-available/||' || echo ""
    fi
}

# Prompt for domain selection
select_domain() {
    local prompt="$1"
    local web_server="$2"
    local domains
    domains=$(get_configured_domains "$web_server")
    if [ -z "$domains" ]; then
        log_action "No domains configured."
        return 1
    fi
    echo "$prompt"
    select domain in $domains; do
        if [ -n "$domain" ]; then
            echo "$domain"
            return 0
        else
            echo "Invalid selection."
        fi
    done
    return 1
}

# Set secure permissions
set_secure_permissions() {
    local path="$1"
    safe_exec "chown -R www-data:www $path" || return 1
    safe_exec "find $path -type d -exec chmod 750 {} \;" || return 1
    safe_exec "find $path -type f -exec chmod 640 {} \;" || return 1
    log_action "Secure permissions set for $path."
}

# Setup www group and permissions
setup_www_group() {
    if getent group www >/dev/null; then
        log_action "www group already exists."
    else
        safe_exec "groupadd www" || return 1
        log_action "www group created."
    fi
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local web_user="www-data"
    safe_exec "usermod -a -G www $web_user" || return 1
    log_action "$web_user added to www group."
    if [ -d "/var/www" ]; then
        set_secure_permissions "/var/www" || return 1
    fi
}

# Harden SSH
harden_ssh() {
    if ! grep -q "Port 2222" /etc/ssh/sshd_config; then
        safe_exec "sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config" || return 1
        safe_exec "sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config" || return 1
        safe_exec "sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config" || return 1
        safe_exec "systemctl restart sshd" || return 1
        safe_exec "ufw allow 2222/tcp" || return 1
        log_action "SSH hardened: port changed to 2222, root login and password auth disabled."
    else
        log_action "SSH already hardened."
    fi
}

# Configure SSH 2FA
configure_ssh_2fa() {
    if prompt_yes_no "Do you want to configure 2FA for SSH?" "n"; then
        if ! is_package_installed libpam-google-authenticator; then
            install_package libpam-google-authenticator || return 1
            safe_exec "echo 'auth required pam_google_authenticator.so' >> /etc/pam.d/sshd" || return 1
            safe_exec "sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config" || return 1
            safe_exec "systemctl restart sshd" || return 1
            log_action "SSH 2FA configured. Run 'google-authenticator' for each user."
        else
            log_action "SSH 2FA already configured."
        fi
    fi
}

# Harden MySQL/MariaDB
harden_mysql() {
    local db_engine=$(cat /root/.db_engine 2>/dev/null || echo "mysql")
    safe_exec "mysql -e 'DELETE FROM mysql.user WHERE User=\"\";'" || return 1
    safe_exec "mysql -e 'DROP DATABASE IF EXISTS test;'" || return 1
    safe_exec "mysql -e 'FLUSH PRIVILEGES;'" || return 1
    if [ "$db_engine" = "mysql" ]; then
        safe_exec "sed -i '/\[mysqld\]/a bind-address=127.0.0.1' /etc/mysql/my.cnf" || return 1
        safe_exec "systemctl restart mysql" || return 1
    else
        safe_exec "sed -i '/\[mysqld\]/a bind-address=127.0.0.1' /etc/mariadb/my.cnf" || return 1
        safe_exec "systemctl restart mariadb" || return 1
    fi
    log_action "$db_engine hardened."
}

# Harden Apache
harden_apache() {
    if is_package_installed apache2; then
        safe_exec "sed -i 's/ServerTokens OS/ServerTokens Prod/' /etc/apache2/conf-available/security.conf" || return 1
        safe_exec "sed -i 's/ServerSignature On/ServerSignature Off/' /etc/apache2/conf-available/security.conf" || return 1
        cat > /tmp/apache_security.conf <<EOF
Header set X-Frame-Options DENY
Header set X-XSS-Protection "1; mode=block"
Header set Content-Security-Policy "default-src 'self'"
EOF
        safe_exec "cat /tmp/apache_security.conf >> /etc/apache2/conf-available/security.conf" || return 1
        rm -f /tmp/apache_security.conf
        safe_exec "systemctl reload apache2" || return 1
        log_action "Apache hardened."
    fi
}

# Harden Nginx
harden_nginx() {
    if is_package_installed nginx; then
        cat > /tmp/nginx_security.conf <<EOF
server_tokens off;
add_header X-Frame-Options DENY;
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'";
EOF
        safe_exec "mv /tmp/nginx_security.conf /etc/nginx/conf.d/security.conf" || return 1
        safe_exec "systemctl reload nginx" || return 1
        log_action "Nginx hardened."
    fi
}

# Configure AppArmor
configure_apparmor() {
    if prompt_yes_no "Do you want to configure AppArmor for services?" "n"; then
        if ! is_package_installed apparmor; then
            install_package apparmor apparmor-profiles || return 1
            safe_exec "aa-enforce /etc/apparmor.d/usr.sbin.apache2" 2>/dev/null || true
            safe_exec "aa-enforce /etc/apparmor.d/usr.sbin.mysqld" 2>/dev/null || true
            safe_exec "systemctl restart apparmor" || return 1
            log_action "AppArmor configured for Apache and MySQL."
        else
            log_action "AppArmor already configured."
        fi
    fi
}

# Install and configure firewall (ufw)
install_firewall() {
    if is_package_installed ufw && ufw status | grep -q "Status: active"; then
        log_action "Firewall (ufw) is already configured and active."
        return
    fi
    if prompt_yes_no "Do you want to install and configure the firewall (ufw)?" "y"; then
        install_package ufw || return 1
        safe_exec "ufw default deny incoming" || return 1
        safe_exec "ufw default allow outgoing" || return 1
        safe_exec "ufw allow 2222/tcp" || return 1
        safe_exec "ufw allow 80/tcp" || return 1
        safe_exec "ufw allow 443/tcp" || return 1
        if is_package_installed vsftpd; then
            safe_exec "ufw allow 20/tcp" || return 1
            safe_exec "ufw allow 21/tcp" || return 1
            safe_exec "ufw allow 40000:50000/tcp" || return 1
            log_action "Firewall rules added for FTP."
        fi
        if is_package_installed postfix; then
            safe_exec "ufw allow 25/tcp" || return 1
            safe_exec "ufw allow 110/tcp" || return 1
            safe_exec "ufw allow 143/tcp" || return 1
            log_action "Firewall rules added for email services."
        fi
        safe_exec "echo y | ufw enable" || return 1
        safe_exec "ufw status" || return 1
        log_action "Firewall (ufw) configured and enabled."
    fi
}

# Install Certbot
install_certbot() {
    if is_package_installed certbot; then
        log_action "Certbot is already installed."
        return
    fi
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        install_package certbot python3-certbot-apache python3-certbot-nginx || return 1
    else
        install_package certbot certbot-apache certbot-nginx || return 1
    fi
    log_action "Certbot installed."
}

# Configure SSL
configure_ssl() {
    local domain="$1"
    local web_server="$2"
    install_certbot || return 1
    if [ "$web_server" = "apache" ]; then
        safe_exec "certbot --apache -d $domain -d www.$domain --non-interactive --agree-tos -m admin@$domain" || true
        safe_exec "a2enmod ssl" || return 1
        safe_exec "systemctl reload apache2" || return 1
    else
        safe_exec "certbot --nginx -d $domain -d www.$domain --non-interactive --agree-tos -m admin@$domain" || true
        safe_exec "systemctl reload nginx" || return 1
    fi
    log_action "SSL configured for $domain."
}

# Install and configure Apache
install_apache() {
    if is_package_installed apache2; then
        log_action "Apache is already installed."
        return
    fi
    safe_exec "apt-get update" || return 1
    install_package apache2 || return 1
    safe_exec "systemctl enable apache2" || return 1
    safe_exec "systemctl start apache2" || return 1
    setup_www_group || return 1
    harden_apache || return 1
    log_action "Apache installed and started."
}

# Install and configure Nginx
install_nginx() {
    if is_package_installed nginx; then
        log_action "Nginx is already installed."
        return
    fi
    safe_exec "apt-get update" || return 1
    install_package nginx || return 1
    safe_exec "systemctl enable nginx" || return 1
    safe_exec "systemctl start nginx" || return 1
    setup_www_group || return 1
    harden_nginx || return 1
    log_action "Nginx installed and started."
}

# Install web server
install_web_server() {
    if is_package_installed apache2 || is_package_installed nginx; then
        log_action "Web server is already installed."
        setup_www_group || return 1
        return 0
    fi
    local web_server
    web_server=$(prompt_select "Which web server do you want to install?" "apache nginx" "apache")
    if [ "$web_server" = "apache" ]; then
        install_apache || return 1
    else
        install_nginx || return 1
    fi
    safe_exec "echo $web_server > /root/.web_server" || return 1
    log_action "Web server $web_server installed."
    return 0
}

# Install multiple PHP versions with extensions
install_php() {
    if is_package_installed php; then
        log_action "PHP is already installed."
        return
    fi
    if prompt_yes_no "Do you want to install multiple PHP versions (7.0 to 8.4)?" "y"; then
        local os=$(detect_os)
        if [ "$os" = "debian" ]; then
            install_package software-properties-common || return 1
            safe_exec "add-apt-repository -y ppa:ondrej/php" || return 1
            safe_exec "apt-get update" || return 1
        else
            install_package epel-release || return 1
        fi
        local extensions="bcmath bz2 curl dba enchant exif fileinfo ftp gd gettext gmp iconv imap imagick intl json ldap mbstring memcache mysql odbc opcache pdo pgsql posix pspell readline recode shmop snmp soap sockets sqlite3 sysvmsg sysvsem sysvshm tidy xml xmlreader xmlrpc xmlwriter xsl zip zlib"
        for version in 7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4; do
            install_package php$version php$version-fpm php$version-dev || continue
            for ext in $extensions; do
                install_package php$version-$ext 2>/dev/null || log_action "Extension $ext not available for PHP $version"
            done
        done
        if [ -f /root/.web_server ] && [ "$(cat /root/.web_server)" = "apache" ]; then
            safe_exec "a2enmod proxy_fcgi setenvif" || return 1
            safe_exec "systemctl restart apache2" || return 1
        else
            safe_exec "systemctl restart nginx" || return 1
        fi
        log_action "Multiple PHP versions and extensions installed."
    fi
}

# Install Composer
install_composer() {
    if [ -f "/usr/local/bin/composer" ]; then
        log_action "Composer is already installed."
        return
    fi
    if prompt_yes_no "Do you want to install Composer?" "y"; then
        install_package curl || return 1
        safe_exec "curl -sS https://getcomposer.org/installer | php" || return 1
        safe_exec "mv composer.phar /usr/local/bin/composer" || return 1
        safe_exec "chmod +x /usr/local/bin/composer" || return 1
        log_action "Composer installed globally."
    fi
}

# Install and configure MySQL
install_mysql() {
    if is_package_installed mysql-server; then
        log_action "MySQL is already installed."
        return
    fi
    install_package mysql-server || return 1
    safe_exec "systemctl enable mysql" || return 1
    safe_exec "systemctl start mysql" || return 1
    safe_exec "mysql_secure_installation" || return 1
    harden_mysql || return 1
    log_action "MySQL installed and secured."
}

# Install and configure MariaDB
install_mariadb() {
    if is_package_installed mariadb-server; then
        log_action "MariaDB is already installed."
        return
    fi
    install_package mariadb-server || return 1
    safe_exec "systemctl enable mariadb" || return 1
    safe_exec "systemctl start mariadb" || return 1
    safe_exec "mysql_secure_installation" || return 1
    harden_mysql || return 1
    log_action "MariaDB installed and secured."
}

# Install database server
install_database() {
    if is_package_installed mysql-server || is_package_installed mariadb-server; then
        log_action "Database server is already installed."
        return 0
    fi
    local db_engine
    db_engine=$(prompt_select "Which database engine do you want to install?" "mysql mariadb" "mysql")
    if [ "$db_engine" = "mysql" ]; then
        install_mysql || return 1
    else
        install_mariadb || return 1
    fi
    safe_exec "echo $db_engine > /root/.db_engine" || return 1
    log_action "Database engine $db_engine installed."
    return 0
}

# Install Docker
install_docker() {
    if is_package_installed docker; then
        log_action "Docker is already installed."
        return
    fi
    if prompt_yes_no "Do you want to install Docker and Docker Compose?" "y"; then
        local os=$(detect_os)
        if [ "$os" = "debian" ]; then
            install_package docker.io docker-compose || return 1
        else
            install_package docker docker-compose || return 1
        fi
        safe_exec "systemctl enable docker" || return 1
        safe_exec "systemctl start docker" || return 1
        log_action "Docker and Docker Compose installed."
    fi
}

# Install and configure Postfix for email
install_postfix() {
    if is_package_installed postfix; then
        log_action "Postfix is already installed."
        return
    fi
    if prompt_yes_no "Do you want to install Postfix for email services?" "y"; then
        install_package postfix || return 1
        log_action "Postfix installed. Please configure /etc/postfix/main.cf manually if needed."
    fi
}

# Configure DKIM
configure_dkim() {
    local domain="$1"
    if prompt_yes_no "Do you want to configure DKIM for $domain?" "y"; then
        install_package opendkim opendkim-tools || return 1
        safe_exec "mkdir -p /etc/opendkim/keys" || return 1
        safe_exec "opendkim-genkey -t -s mail -d $domain" || return 1
        safe_exec "mv mail.private /etc/opendkim/keys/$domain.private" || return 1
        safe_exec "mv mail.txt /etc/opendkim/keys/$domain.txt" || return 1
        cat > /tmp/opendkim.conf <<EOF
Domain $domain
KeyFile /etc/opendkim/keys/$domain.private
Selector mail
EOF
        safe_exec "cat /tmp/opendkim.conf >> /etc/opendkim.conf" || return 1
        rm -f /tmp/opendkim.conf
        safe_exec "systemctl restart opendkim postfix" || return 1
        log_action "DKIM configured for $domain. Add DNS TXT record from /etc/opendkim/keys/$domain.txt."
        echo "DKIM DNS record: $(cat /etc/opendkim/keys/$domain.txt)" >> "$CREDENTIALS_FILE"
    fi
}

# Configure Cloudflare DNS
configure_cloudflare_dns() {
    local domain="$1"
    if prompt_yes_no "Do you want to configure Cloudflare DNS for $domain?" "n"; then
        local api_token cf_zone_id
        api_token=$(prompt_input "Enter Cloudflare API token" "")
        cf_zone_id=$(prompt_input "Enter Cloudflare Zone ID" "")
        if [ -n "$api_token" ] && [ -n "$cf_zone_id" ]; then
            install_package curl || return 1
            safe_exec "curl -X POST 'https://api.cloudflare.com/client/v4/zones/$cf_zone_id/dns_records' -H 'Authorization: Bearer $api_token' -H 'Content-Type: application/json' --data '{\"type\":\"A\",\"name\":\"@\",\"content\":\"$(curl -s ifconfig.me)\",\"ttl\":3600,\"proxied\":true}'" || return 1
            log_action "DNS A record configured for $domain on Cloudflare."
        else
            log_action "Skipping Cloudflare DNS configuration: missing API token or Zone ID."
        fi
    fi
}

# Install and configure vsftpd for FTP
install_ftp() {
    if is_package_installed vsftpd; then
        log_action "vsftpd is already installed."
        return
    fi
    if prompt_yes_no "Do you want to install vsftpd for FTP services?" "y"; then
        install_package vsftpd || return 1
        safe_exec "systemctl enable vsftpd" || return 1
        safe_exec "systemctl start vsftpd" || return 1
        log_action "vsftpd installed and started."
    fi
}

# Install and configure Fail2ban
install_fail2ban() {
    if is_package_installed fail2ban; then
        log_action "Fail2ban is already installed."
        return
    fi
    if prompt_yes_no "Do you want to install Fail2ban for security monitoring?" "y"; then
        install_package fail2ban || return 1
        safe_exec "systemctl enable fail2ban" || return 1
        safe_exec "systemctl start fail2ban" || return 1
        local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
        cat > /tmp/fail2ban_jail.local <<EOF
[DEFAULT]
bantime  = 7200
findtime  = 600
maxretry = 5

[sshd]
enabled = true
port    = 2222
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5

[vsftpd]
enabled = true
port = ftp,ftp-data
filter = vsftpd
logpath = /var/log/vsftpd.log
maxretry = 5
bantime = 7200

[mysqld-auth]
enabled = true
port = 3306
filter = mysqld-auth
logpath = /var/log/mysql/error.log
maxretry = 5
bantime = 7200
EOF
        if [ "$web_server" = "apache" ]; then
            cat >> /tmp/fail2ban_jail.local <<EOF
[apache-auth]
enabled = true
port    = http,https
filter  = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 5
EOF
        else
            cat >> /tmp/fail2ban_jail.local <<EOF
[nginx-http-auth]
enabled = true
port    = http,https
filter  = nginx-http-auth
logpath = /var/log/nginx/*error.log
maxretry = 5
EOF
        fi
        safe_exec "mv /tmp/fail2ban_jail.local /etc/fail2ban/jail.local" || return 1
        safe_exec "systemctl restart fail2ban" || return 1
        log_action "Fail2ban installed and configured for SSH, FTP, MySQL, and $web_server."
    fi
}

# Secure phpMyAdmin
secure_phpmyadmin() {
    if [ -d "/usr/share/phpmyadmin" ]; then
        log_action "phpMyAdmin is already installed."
        return
    fi
    if prompt_yes_no "Do you want to install and secure phpMyAdmin?" "y"; then
        install_package phpmyadmin || return 1
        local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
        local pma_password_file=$(generate_password)
        local pma_password=$(cat "$pma_password_file")
        local pma_db="phpmyadmin"
        local pma_path="/pma_$(openssl rand -hex 4)"
        safe_exec "mysql -e 'CREATE DATABASE $pma_db;'" || return 1
        safe_exec "mysql -e 'CREATE USER \"pma\"@\"localhost\" IDENTIFIED BY \"$pma_password\";'" || return 1
        safe_exec "mysql -e 'GRANT ALL PRIVILEGES ON $pma_db.* TO \"pma\"@\"localhost\";'" || return 1
        safe_exec "mysql -e 'FLUSH PRIVILEGES;'" || return 1
        safe_exec "mysql $pma_db < /usr/share/phpmyadmin/sql/create_tables.sql" || return 1
        safe_exec "mv /usr/share/phpmyadmin /usr/share/$pma_path" || return 1
        safe_exec "ln -s /usr/share/$pma_path /var/www/html/$pma_path" || return 1
        if [ "$web_server" = "apache" ]; then
            cat > /tmp/phpmyadmin.conf <<EOF
Alias /$pma_path /usr/share/$pma_path
<Directory /usr/share/$pma_path>
    Options FollowSymLinks
    DirectoryIndex index.php
    AllowOverride All
    AuthType Basic
    AuthName "Restricted Area"
    AuthUserFile /etc/phpmyadmin/.htpasswd
    Require valid-user
</Directory>
EOF
            safe_exec "mv /tmp/phpmyadmin.conf /etc/apache2/conf-available/phpmyadmin.conf" || return 1
            safe_exec "htpasswd -cb /etc/phpmyadmin/.htpasswd pma_admin $pma_password" || return 1
            safe_exec "a2enconf phpmyadmin" || return 1
            safe_exec "systemctl reload apache2" || return 1
        else
            cat > /tmp/phpmyadmin_nginx.conf <<EOF
server {
    listen 80;
    server_name phpmyadmin.local;
    root /usr/share/$pma_path;
    index index.php;
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF
            safe_exec "mv /tmp/phpmyadmin_nginx.conf /etc/nginx/sites-available/phpmyadmin" || return 1
            safe_exec "ln -s /etc/nginx/sites-available/phpmyadmin /etc/nginx/sites-enabled/" || return 1
            safe_exec "systemctl reload nginx" || return 1
        fi
        echo "phpMyAdmin installed at /$pma_path with user 'pma' and password: $pma_password" >> "$CREDENTIALS_FILE"
        log_action "phpMyAdmin secured at /$pma_path with HTTP auth."
        cleanup_password "$pma_password_file"
    fi
}

# Install WordPress
install_wordpress() {
    local domain="$1"
    local document_root="/var/www/$domain/html"
    if prompt_yes_no "Do you want to install WordPress for $domain?" "n"; then
        install_package wget unzip || return 1
        safe_exec "wget https://wordpress.org/latest.zip -O /tmp/wordpress.zip" || return 1
        safe_exec "unzip /tmp/wordpress.zip -d $document_root" || return 1
        safe_exec "mv $document_root/wordpress/* $document_root/" || return 1
        safe_exec "rm -rf $document_root/wordpress /tmp/wordpress.zip" || return 1
        safe_exec "chown -R www-data:www $document_root" || return 1
        set_secure_permissions "$document_root" || return 1
        local db_name="${domain//./_}_wp"
        local db_user="${domain//./_}_wp"
        local db_password_file=$(generate_password)
        local db_password=$(cat "$db_password_file")
        safe_exec "mysql -e 'CREATE DATABASE $db_name;'" || return 1
        safe_exec "mysql -e 'CREATE USER \"$db_user\"@\"localhost\" IDENTIFIED BY \"$db_password\";'" || return 1
        safe_exec "mysql -e 'GRANT ALL PRIVILEGES ON $db_name.* TO \"$db_user\"@\"localhost\";'" || return 1
        safe_exec "mysql -e 'FLUSH PRIVILEGES;'" || return 1
        echo "WordPress database $db_name with user $db_user: $db_password" >> "$CREDENTIALS_FILE"
        log_action "WordPress installed for $domain at $document_root."
        cleanup_password "$db_password_file"
    fi
}

# Setup Git repository
setup_git_repo() {
    local domain="$1"
    if prompt_yes_no "Do you want to set up a Git repository for $domain?" "y"; then
        local repo_dir="/var/www/$domain/repo"
        safe_exec "mkdir -p $repo_dir" || return 1
        safe_exec "cd $repo_dir" || return 1
        safe_exec "git init --bare" || return 1
        cat > "$repo_dir/hooks/post-receive" <<EOF
#!/bin/bash
git --work-tree=/var/www/$domain/html --git-dir=$repo_dir checkout -f
EOF
        safe_exec "chmod +x $repo_dir/hooks/post-receive" || return 1
        set_secure_permissions "$repo_dir" || return 1
        log_action "Git repository set up for $domain at $repo_dir."
    fi
}

# Backup domain
backup_domain() {
    local domain="$1"
    local backup_dir="$BACKUP_DIR/$domain/$(date +%Y%m%d_%H%M%S)"
    safe_exec "mkdir -p $backup_dir" || return 1
    local backup_pass_file=$(generate_password)
    local backup_pass=$(cat "$backup_pass_file")
    safe_exec "tar -czf - /var/www/$domain | gpg --symmetric --passphrase $backup_pass > $backup_dir/site.tar.gz.gpg" || return 1
    safe_exec "mysqldump -u root ${domain//./_} | gpg --symmetric --passphrase $backup_pass > $backup_dir/db.sql.gpg" 2>/dev/null || true
    set_secure_permissions "$backup_dir" || return 1
    echo "Backup for $domain (passphrase: $backup_pass)" >> "$CREDENTIALS_FILE"
    log_action "Encrypted backup created for $domain at $backup_dir."
    cleanup_password "$backup_pass_file"
}

# Rollback domain configuration
rollback_domain() {
    local domain="$1"
    local web_server="$2"
    local ftp_user="$3"
    local db_name="$4"
    local db_user="$5"
    local email_user="$6"
    safe_exec "rm -rf /var/www/$domain" || true
    safe_exec "mysql -e 'DROP DATABASE IF EXISTS $db_name;'" || true
    safe_exec "mysql -e 'DROP USER IF EXISTS \"$db_user\"@\"localhost\";'" || true
    safe_exec "userdel -r $ftp_user" 2>/dev/null || true
    safe_exec "userdel -r $email_user" 2>/dev/null || true
    if [ "$web_server" = "apache" ]; then
        safe_exec "a2dissite $domain.conf" 2>/dev/null || true
        safe_exec "rm -f /etc/apache2/sites-available/$domain.conf" || true
        safe_exec "systemctl reload apache2" || true
    else
        safe_exec "rm -f /etc/nginx/sites-enabled/$domain /etc/nginx/sites-available/$domain" || true
        safe_exec "systemctl reload nginx" || true
    fi
    log_action "Rolled back configuration for $domain."
}

# Configure a new domain
configure_domain() {
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    local domain=$(prompt_input "Enter the domain name (e.g., example.com)" "$domain")
    validate_domain "$domain" || return 1
    if is_domain_configured "$domain" "$web_server"; then
        log_action "Domain $domain is already configured."
        return
    fi
    local document_root="/var/www/$domain/html"
    local php_version=$(prompt_input "Enter PHP version for $domain (7.0 to 8.4)" "${php_version:-8.4}")
    validate_php_version "$php_version" || return 1
    local ftp_user db_name db_user email_user
    local rollback_needed=false
    # Create document root
    if ! safe_exec "mkdir -p $document_root"; then
        rollback_needed=true
    else
        if ! set_secure_permissions "/var/www/$domain"; then
            rollback_needed=true
        fi
    fi
    # Create virtual host
    if [ "$web_server" = "apache" ]; then
        cat > "/tmp/$domain.conf" <<EOF
<VirtualHost *:80>
    ServerName $domain
    ServerAlias www.$domain
    DocumentRoot $document_root
    <Directory $document_root>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php$php_version-fpm.sock|fcgi://localhost/"
    </FilesMatch>
    ErrorLog \${APACHE_LOG_DIR}/$domain-error.log
    CustomLog \${APACHE_LOG_DIR}/$domain-access.log combined
</VirtualHost>
EOF
        if ! safe_exec "mv /tmp/$domain.conf /etc/apache2/sites-available/$domain.conf" || \
           ! safe_exec "a2ensite $domain.conf" || \
           ! safe_exec "systemctl reload apache2"; then
            rollback_needed=true
        fi
    else
        cat > "/tmp/$domain" <<EOF
server {
    listen 80;
    server_name $domain www.$domain;
    root $document_root;
    index index.php index.html;
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$php_version-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    error_log /var/log/nginx/$domain-error.log;
    access_log /var/log/nginx/$domain-access.log;
}
EOF
        if ! safe_exec "mv /tmp/$domain /etc/nginx/sites-available/$domain" || \
           ! safe_exec "ln -s /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/" || \
           ! safe_exec "systemctl reload nginx"; then
            rollback_needed=true
        fi
    fi
    if [ "$rollback_needed" = "false" ]; then
        log_action "Virtual host for $domain created."
    fi
    # Configure SSL
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Do you want to enable SSL for $domain?" "y"; then
        if ! configure_ssl "$domain" "$web_server"; then
            rollback_needed=true
        fi
    fi
    # Create FTP user
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Do you want to create an FTP user for $domain?" "y"; then
        ftp_user=$(prompt_input "Enter FTP username for $domain" "${domain//./_}")
        local ftp_password_file=$(generate_password)
        local ftp_password=$(cat "$ftp_password_file")
        if ! safe_exec "useradd -m -d /var/www/$domain -s /bin/bash -G www $ftp_user" || \
           ! safe_exec "echo $ftp_user:$ftp_password | chpasswd" || \
           ! set_secure_permissions "/var/www/$domain"; then
            rollback_needed=true
        else
            echo "FTP user $ftp_user for $domain: $ftp_password" >> "$CREDENTIALS_FILE"
            log_action "FTP user $ftp_user created for $domain."
        fi
        cleanup_password "$ftp_password_file"
    fi
    # Create database
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Do you want to create a database for $domain?" "y"; then
        db_name=$(prompt_input "Enter database name for $domain" "${domain//./_}")
        db_user=$(prompt_input "Enter database username for $domain" "${domain//./_}")
        local db_password_file=$(generate_password)
        local db_password=$(cat "$db_password_file")
        if ! safe_exec "mysql -e 'CREATE DATABASE $db_name;'" || \
           ! safe_exec "mysql -e 'CREATE USER \"$db_user\"@\"localhost\" IDENTIFIED BY \"$db_password\";'" || \
           ! safe_exec "mysql -e 'GRANT ALL PRIVILEGES ON $db_name.* TO \"$db_user\"@\"localhost\";'" || \
           ! safe_exec "mysql -e 'FLUSH PRIVILEGES;'"; then
            rollback_needed=true
        else
            echo "Database $db_name with user $db_user: $db_password" >> "$CREDENTIALS_FILE"
            log_action "Database $db_name created for $domain."
        fi
        cleanup_password "$db_password_file"
    fi
    # Create email account
    if [ "$rollback_needed" = "false" ] && prompt_yes_no "Do you want to create an email account for $domain?" "y"; then
        email_user=$(prompt_input "Enter email username (e.g., info for info@$domain)" "info")@$domain
        local email_password_file=$(generate_password)
        local email_password=$(cat "$email_password_file")
        if ! safe_exec "useradd -m -s /bin/false $email_user" || \
           ! safe_exec "echo $email_user:$email_password | chpasswd"; then
            rollback_needed=true
        else
            echo "Email account $email_user: $email_password" >> "$CREDENTIALS_FILE"
            log_action "Email account $email_user created."
            if ! configure_dkim "$domain"; then
                rollback_needed=true
            fi
        fi
        cleanup_password "$email_password_file"
    fi
    # Setup Git repository
    if [ "$rollback_needed" = "false" ]; then
        if ! setup_git_repo "$domain"; then
            rollback_needed=true
        fi
    fi
    # Install WordPress
    if [ "$rollback_needed" = "false" ]; then
        if ! install_wordpress "$domain"; then
            rollback_needed=true
        fi
    fi
    # Configure Cloudflare DNS
    if [ "$rollback_needed" = "false" ]; then
        if ! configure_cloudflare_dns "$domain"; then
            rollback_needed=true
        fi
    fi
    # Create backup
    if [ "$rollback_needed" = "false" ]; then
        if ! backup_domain "$domain"; then
            rollback_needed=true
        fi
    fi
    # Handle rollback if needed
    if [ "$rollback_needed" = "true" ]; then
        if [ "$INTERACTIVE" = "true" ] && prompt_yes_no "An error occurred. Roll back changes for $domain?" "y"; then
            rollback_domain "$domain" "$web_server" "$ftp_user" "$db_name" "$db_user" "$email_user"
            return 1
        elif [ "$INTERACTIVE" = "false" ]; then
            rollback_domain "$domain" "$web_server" "$ftp_user" "$db_name" "$db_user" "$email_user"
            return 1
        fi
    fi
}

# Change PHP version for an existing domain
change_php_version() {
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    if prompt_yes_no "Do you want to change the PHP version for an existing domain?" "y"; then
        local domain=$(select_domain "Select a domain to change PHP version:" "$web_server")
        if [ $? -ne 0 ]; then
            log_action "No domain selected."
            return
        fi
        local php_version=$(prompt_input "Enter new PHP version for $domain (7.0 to 8.4)" "8.4")
        validate_php_version "$php_version" || return 1
        local document_root="/var/www/$domain/html"
        if [ "$web_server" = "apache" ]; then
            cat > "/tmp/$domain.conf" <<EOF
<VirtualHost *:80>
    ServerName $domain
    ServerAlias www.$domain
    DocumentRoot $document_root
    <Directory $document_root>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php$php_version-fpm.sock|fcgi://localhost/"
    </FilesMatch>
    ErrorLog \${APACHE_LOG_DIR}/$domain-error.log
    CustomLog \${APACHE_LOG_DIR}/$domain-access.log combined
</VirtualHost>
EOF
            safe_exec "mv /tmp/$domain.conf /etc/apache2/sites-available/$domain.conf" || return 1
            safe_exec "systemctl reload apache2" || return 1
        else
            cat > "/tmp/$domain" <<EOF
server {
    listen 80;
    server_name $domain www.$domain;
    root $document_root;
    index index.php index.html;
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$php_version-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    error_log /var/log/nginx/$domain-error.log;
    access_log /var/log/nginx/$domain-access.log;
}
EOF
            safe_exec "mv /tmp/$domain /etc/nginx/sites-available/$domain" || return 1
            safe_exec "systemctl reload nginx" || return 1
        fi
        log_action "PHP version for $domain changed to $php_version."
    fi
}

# Create a new FTP account for an existing domain
create_ftp_account() {
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    if prompt_yes_no "Do you want to create a new FTP account for an existing domain?" "y"; then
        local domain=$(select_domain "Select a domain for the new FTP account:" "$web_server")
        if [ $? -ne 0 ]; then
            log_action "No domain selected."
            return
        fi
        local ftp_user=$(prompt_input "Enter FTP username for $domain" "${domain//./_}_ftp")
        local ftp_password_file=$(generate_password)
        local ftp_password=$(cat "$ftp_password_file")
        if ! safe_exec "useradd -m -d /var/www/$domain -s /bin/bash -G www $ftp_user" || \
           ! safe_exec "echo $ftp_user:$ftp_password | chpasswd" || \
           ! set_secure_permissions "/var/www/$domain"; then
            safe_exec "userdel -r $ftp_user" 2>/dev/null || true
            log_action "Failed to create FTP user $ftp_user for $domain."
            cleanup_password "$ftp_password_file"
            return 1
        fi
        echo "FTP user $ftp_user for $domain: $ftp_password" >> "$CREDENTIALS_FILE"
        log_action "FTP user $ftp_user created for $domain."
        cleanup_password "$ftp_password_file"
    fi
}

# Create a new email account for an existing domain
create_email_account() {
    local web_server=$(cat /root/.web_server 2>/dev/null || echo "apache")
    if prompt_yes_no "Do you want to create a new email account for an existing domain?" "y"; then
        local domain=$(select_domain "Select a domain for the new email account:" "$web_server")
        if [ $? -ne 0 ]; then
            log_action "No domain selected."
            return
        fi
        local email_user=$(prompt_input "Enter email username (e.g., info for info@$domain)" "info")@$domain
        local email_password_file=$(generate_password)
        local email_password=$(cat "$email_password_file")
        if ! safe_exec "useradd -m -s /bin/false $email_user" || \
           ! safe_exec "echo $email_user:$email_password | chpasswd"; then
            safe_exec "userdel -r $email_user" 2>/dev/null || true
            log_action "Failed to create email account $email_user."
            cleanup_password "$email_password_file"
            return 1
        fi
        echo "Email account $email_user: $email_password" >> "$CREDENTIALS_FILE"
        log_action "Email account $email_user created."
        cleanup_password "$email_password_file"
    fi
}

# Update system
update_system() {
    local os=$(detect_os)
    if [ "$os" = "debian" ]; then
        safe_exec "apt-get update" || return 1
        safe_exec "apt-get upgrade -y" || return 1
        safe_exec "apt-get autoremove -y" || return 1
    else
        safe_exec "yum update -y" || return 1
        safe_exec "yum autoremove -y" || return 1
    fi
    log_action "System updated and cleaned."
}

# Encrypt credentials
encrypt_credentials() {
    if [ -s "$CREDENTIALS_FILE" ]; then
        local pass_file=$(generate_password)
        local pass=$(cat "$pass_file")
        safe_exec "gpg --symmetric --passphrase $pass -o $CREDENTIALS_FILE.gpg $CREDENTIALS_FILE" || return 1
        safe_exec "rm -f $CREDENTIALS_FILE" || return 1
        echo "Credentials encrypted with passphrase: $pass" >> "$CREDENTIALS_FILE.pass"
        log_action "Credentials encrypted to $CREDENTIALS_FILE.gpg."
        cleanup_password "$pass_file"
    fi
}

# Generate report
generate_report() {
    local report_file="/root/vps_setup_report.txt"
    cat > "$report_file" <<EOF
VPS Setup Report - $(date)
-------------------------------
Version: $VERSION
Web Server: $(cat /root/.web_server 2>/dev/null || echo "Not installed")
Database: $(cat /root/.db_engine 2>/dev/null || echo "Not installed")
Domains: $(get_configured_domains "$(cat /root/.web_server 2>/dev/null || echo apache)")
Credentials: $CREDENTIALS_FILE.gpg
Logs: $LOG_FILE
Backups: $BACKUP_DIR
-------------------------------
EOF
    log_action "Setup report generated at $report_file."
}

# Load configuration file
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        log_action "Loaded configuration from $CONFIG_FILE."
        if [ -n "$non_interactive" ] && [ "$non_interactive" = "true" ]; then
            INTERACTIVE=false
        fi
    fi
}

# Display help
display_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --domain <domain>       Specify domain name (e.g., example.com)
  --web-server <server>   Specify web server (apache or nginx)
  --php-version <version> Specify PHP version (7.0 to 8.4)
  --dry-run               Simulate actions without applying changes
  --non-interactive       Run in non-interactive mode
  --help                  Display this help message

Description:
  This script automates the setup and management of a VPS for web hosting.
  It supports Apache/Nginx, PHP, MySQL/MariaDB, FTP, email, WordPress, and security features.
  Configuration can be specified in $CONFIG_FILE.

Example Config ($CONFIG_FILE):
  domain=example.com
  web_server=nginx
  php_version=8.4
  non_interactive=true
  enable_2fa=true
  enable_wordpress=true
EOF
    exit 0
}

# Parse command-line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain) domain="$2"; shift 2 ;;
            --web-server) web_server="$2"; shift 2 ;;
            --php-version) php_version="$2"; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --non-interactive) INTERACTIVE=false; shift ;;
            --help) display_help ;;
            *) log_action "Unknown option: $1"; exit 1 ;;
        esac
    done
}

# Main function
main() {
    if [ "$(id -u)" != "0" ]; then
        log_action "This script must be run as root."
        exit 1
    fi
    # Display author details
    display_author_details
    # Initialize logging and credentials file
    safe_exec "touch $LOG_FILE $CREDENTIALS_FILE" || exit 1
    safe_exec "chmod 600 $LOG_FILE $CREDENTIALS_FILE" || exit 1
    safe_exec "mkdir -p $BACKUP_DIR" || exit 1
    set_secure_permissions "$BACKUP_DIR" || exit 1
    # Parse command-line arguments
    parse_args "$@"
    # Load configuration file
    load_config
    # Perform initial setup
    if [ ! -f "/root/.vps_setup_done" ]; then
        log_action "Performing initial VPS setup..."
        if ! update_system || \
           ! install_web_server || \
           ! install_php || \
           ! install_composer || \
           ! install_database || \
           ! install_docker || \
           ! install_postfix || \
           ! install_ftp || \
           ! install_fail2ban || \
           ! install_firewall || \
           ! secure_phpmyadmin || \
           ! configure_apparmor || \
           ! configure_ssh_2fa || \
           ! harden_ssh || \
           ! harden_mysql || \
           ! harden_apache || \
           ! harden_nginx || \
           ! configure_domain; then
            log_action "Initial setup failed. Check $LOG_FILE for details."
            exit 1
        fi
        safe_exec "touch /root/.vps_setup_done" || exit 1
        log_action "Initial setup completed."
    else
        log_action "Initial setup already completed."
        if ! setup_www_group || \
           ! install_firewall; then
            log_action "Failed to update group or firewall settings."
            exit 1
        fi
        if prompt_yes_no "Do you want to add a new domain?" "y"; then
            if ! configure_domain; then
                log_action "Failed to configure new domain."
                exit 1
            fi
        fi
        if ! change_php_version || \
           ! create_ftp_account || \
           ! create_email_account; then
            log_action "Failed to perform additional configurations."
            exit 1
        fi
    fi
    encrypt_credentials || log_action "Failed to encrypt credentials."
    generate_report || log_action "Failed to generate report."
    log_action "Setup completed. Credentials saved to $CREDENTIALS_FILE.gpg."
}

# Execute main function
main "$@"