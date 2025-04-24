# VPS Setup Script

A robust Bash script to automate the setup and management of a VPS for web hosting, supporting a wide range of services and security features. Ideal for developers and system administrators looking to streamline VPS configuration with minimal effort.

## Features

- **Web Server**: Installs Apache or Nginx with automatic SSL/TLS configuration via Certbot.
- **PHP Support**: Installs multiple PHP versions (7.0 to 8.4) with extensive extensions for flexibility.
- **Database Management**: Configures MySQL or MariaDB with secure hardening.
- **Email Services**: Sets up Postfix, Dovecot, and OpenDKIM for secure email with DKIM support.
- **FTP Access**: Configures vsftpd for secure file transfers with per-domain users.
- **Security Enhancements**:
  - **Firewall**: Configures UFW to restrict incoming/outgoing traffic.
  - **Fail2ban**: Protects against brute-force attacks on SSH, FTP, and web services.
  - **SSH Hardening**: Changes SSH port, disables root login, and enables 2FA (optional).
  - **AppArmor/SELinux**: Applies mandatory access controls for Apache and MySQL (optional).
- **CMS Support**: Installs WordPress for domains with automatic database setup (optional).
- **Automated DNS**: Configures Cloudflare DNS records for domains (optional).
- **Cross-Distribution Compatibility**: Supports Debian-based (e.g., Ubuntu) and RedHat-based systems.
- **Git Integration**: Sets up Git repositories for domains with post-receive hooks.
- **Backup and Rollback**: Creates encrypted backups and automatically rolls back failed operations.
- **Logging**: Detailed logging of all actions to `/var/log/vps_setup.log`.
- **Additional Tools**: Installs Composer, phpMyAdmin, Docker, and Docker Compose.

## Author

- **Name**: Yogesh Gupta
- **Email**: yk68785@gmail.com
- **GitHub**: [Yogesh0610](https://github.com/Yogesh0610)
- **LinkedIn**: [Yogesh Gupta](https://www.linkedin.com/in/yogesh-gupta-64610a169/)

**About**:  
🚀 Software Engineer | PHP, React.js, React Native, Laravel  
Passionate about crafting seamless web and mobile experiences. With expertise in PHP, React.js, React Native, and Laravel, I transform ideas into high-performance applications.  

**Key Skills**:  
- **PHP**: Building robust backend systems and APIs.  
- **React.js**: Developing interactive, high-performance web applications.  
- **React Native**: Creating cross-platform mobile apps with seamless UX.  
- **Laravel**: Leveraging Laravel for scalable, maintainable applications.  

**Philosophy**:  
Always learning, always innovating. I aim to exceed expectations and tackle challenges that push technical boundaries.

**Disclaimer**:  
The author, Yogesh Gupta, is not responsible for any damages, data loss, or issues arising from the use of this script. Use at your own risk and ensure you have backups and proper testing in place before running in a production environment.

## Requirements

- **Operating System**: Debian-based (e.g., Ubuntu 20.04/22.04) or RedHat-based systems.
- **Root Access**: Must be run as root (`sudo`).
- **Internet Connection**: Required for downloading packages and dependencies.
- **Dependencies**: `bash`, `openssl`, `gpg` (installed automatically if missing).

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Yogesh0610/vps-setup.git
   cd vps-setup
   ```

2. **Make the Script Executable**:
   ```bash
   chmod +x vps_setup.sh
   ```

3. **Run the Script**:
   ```bash
   sudo ./vps_setup.sh
   ```

## Usage

The script supports both **interactive** and **non-interactive** modes, allowing flexibility for manual or automated setups.

### Interactive Mode
Run the script and follow the prompts to configure:
- Web server (Apache/Nginx)
- PHP version
- Database engine (MySQL/MariaDB)
- Domain setup with optional SSL, FTP, email, WordPress, and Cloudflare DNS
- Security features like 2FA, AppArmor, and Fail2ban

Example:
```bash
sudo ./vps_setup.sh
```

### Non-Interactive Mode
Create a configuration file at `/etc/vps_setup.conf` to predefine settings. Example configuration:
```bash
domain=example.com
web_server=nginx
php_version=8.4
non_interactive=true
enable_2fa=true
enable_wordpress=true
enable_cloudflare_dns=true
```

Run in non-interactive mode:
```bash
sudo ./vps_setup.sh --non-interactive
```

### Command-Line Options
```bash
--domain <domain>       Specify the domain name (e.g., example.com)
--web-server <server>   Choose web server (apache or nginx)
--php-version <version> Set PHP version (7.0 to 8.4)
--dry-run               Simulate actions without making changes
--non-interactive       Run without user prompts
--help                  Display help message
```

Example:
```bash
sudo ./vps_setup.sh --domain example.com --web-server apache --php-version 8.4
```

## Outputs

- **Logs**: All actions (success, errors, rollbacks) are logged to `/var/log/vps_setup.log`.
- **Credentials**: Stored encrypted in `/root/credentials.txt.gpg` with a passphrase in `/root/credentials.txt.pass`.
- **Report**: Setup summary saved to `/root/vps_setup_report.txt`.
- **Backups**: Encrypted backups stored in `/backups/<domain>/<timestamp>`.

## Security Features

- **Rollback Mechanism**: Automatically reverts changes (e.g., domain setup, user creation) if an operation fails.
- **Encryption**: Credentials and backups are encrypted using GPG.
- **Secure Permissions**: Sets restrictive permissions (e.g., 750 for directories, 640 for files) on web roots and backups.
- **2FA for SSH**: Optional Google Authenticator setup for enhanced SSH security.
- **AppArmor/SELinux**: Applies profiles to restrict Apache and MySQL processes (optional).
- **Fail2ban**: Monitors and bans malicious IPs targeting SSH, FTP, and web services.
- **UFW Firewall**: Configures rules to allow only necessary ports (e.g., 80, 443, 2222).

## Maintenance

- **Update the System**:
  ```bash
  sudo apt-get update && sudo apt-get upgrade
  ```
- **Check Logs**:
  ```bash
  cat /var/log/vps_setup.log
  ```
- **Renew SSL Certificates**:
  ```bash
  sudo certbot renew
  ```
- **View Credentials**:
  Decrypt credentials using the passphrase from `/root/credentials.txt.pass`:
  ```bash
  gpg -d /root/credentials.txt.gpg
  ```

## Troubleshooting

- **Permission Issues**: Ensure the script runs as root and check file permissions in `/var/www`.
- **Git Errors**: If pushing to GitHub fails, verify your credentials or Personal Access Token.
- **Package Installation Failures**: Check internet connectivity and update package lists (`apt-get update`).
- **Rollback Failures**: Review `/var/log/vps_setup.log` for details on failed operations.

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Report issues or suggest features on the [GitHub Issues page](https://github.com/Yogesh0610/vps-setup/issues).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with inspiration from open-source VPS management tools.
- Thanks to the community for feedback and contributions.