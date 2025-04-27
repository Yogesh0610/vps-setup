# VPS Setup Script

**Version**: 2.5.0  
**Last Updated**: April 27, 2025  
**Description**: A user-friendly Bash script to set up a Virtual Private Server (VPS) with web hosting, database, email, security, and development features. Designed for beginners and experts, it includes an interactive menu, guided setup wizard, and automation options.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Non-Interactive Mode](#non-interactive-mode)
  - [Batch Processing](#batch-processing)
  - [Dry-Run Mode](#dry-run-mode)
- [Configuration File](#configuration-file)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [Author](#author)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Overview
The VPS Setup Script simplifies configuring a VPS for hosting websites, databases, email accounts, and webmail, with additional support for development workflows like Git and Docker. Ideal for beginners setting up their first server or experts automating deployments, it offers:
- A **guided setup wizard** to verify and configure prerequisites.
- An **interactive menu** for easy navigation.
- **Clear prompts** with defaults for minimal input.
- **Actionable error messages** with troubleshooting tips.
- **Automation options** for advanced users.

The script supports Ubuntu/Debian and CentOS/RHEL/Fedora, with features like WordPress integration, Git repositories, SSL certificates, phpMyAdmin, and robust security via Fail2ban and AppArmor/SELinux.

## Features
- **Guided Setup Wizard**: Checks internet, OS, dependencies, and server IP; installs missing components (e.g., MariaDB, Apache).
- **Interactive Menu**: Configure domains, webmail, PHP settings, or delete resources with a simple numbered menu.
- **DNS Verification**: Ensures domains resolve to the server’s IP before configuration.
- **MySQL Support**: Detects credentials or prompts for a password, with optional MariaDB installation.
- **CMS Integration**: Optional WordPress installation with automated database setup, including database creation and user configuration.
- **Git Repositories**: Configures per-domain Git repositories with post-receive hooks for automated deployments.
- **phpMyAdmin**: Installs and secures phpMyAdmin with HTTP authentication and randomized URLs for safe database management.
- **SSL Certificates**: Automatically configures HTTPS using Certbot.
- **FTP and Email Accounts**: Creates secure FTP users (via SFTP for encryption) and email accounts with encrypted credentials.
- **Firewall and Security**:
  - **Fail2ban**: Monitors logs and bans IPs after repeated failed login attempts (e.g., SSH, FTP, WordPress).
  - **AppArmor/SELinux**: Enforces security profiles for applications, with automatic configuration during setup.
- **Docker Support**: Installs Docker and Docker Compose for containerized applications, with optional WordPress deployment via Docker.
- **Composer**: Installs PHP Composer for dependency management, supporting modern PHP applications.
- **Webmail**: Installs Roundcube for browser-based email access.
- **PHP Customization**: Adjusts memory limits, file upload sizes, and execution times per domain.
- **Rollback System**: Undoes partial configurations if errors occur.
- **Color-Coded Output**: Green for success, red for errors, yellow for tips/warnings.
- **Logging**: Saves detailed logs to `/var/log/vps_setup.log` with rotation.
- **Backups**: Creates backups before deleting domains, stored in `/backups`.
- **Automation Options**: Supports `--non-interactive`, `--dry-run`, and `--domains` for batch processing.
- **Secure Credential Handling**: Encourages manual storage in a password manager, with optional GPG encryption.

## Prerequisites
Before running the script, ensure:
1. **Operating System**: Ubuntu/Debian or CentOS/RHEL/Fedora.
2. **Root Access**: Run the script with `sudo`.
3. **Internet Connection**: Required for package installation, IP detection, and Git/Composer updates.
4. **DNS Setup**: Domains must point to your VPS’s IP address (check with your DNS provider, e.g., GoDaddy, Namecheap).
5. **Optional**: MySQL/MariaDB, Docker, or Git installed (the script can install these if needed).

**Tip**: To find your server’s IP, run `curl -s ifconfig.me` or check with your VPS provider.

## Installation
1. **Download the Script**:
   ```bash
   wget https://example.com/vps_setup.sh
   ```
   Replace `https://example.com/vps_setup.sh` with the actual download URL or copy the script manually.

2. **Make Executable**:
   ```bash
   chmod +x vps_setup.sh
   ```

3. **Run the Script**:
   ```bash
   sudo ./vps_setup.sh
   ```

   The script starts with a setup wizard to verify and configure your server, including Docker, Composer, and security tools.

## Usage
The script offers multiple modes to suit different needs. Below are the main ways to use it.

### Interactive Mode
Run the script without arguments to use the interactive menu:
```bash
sudo ./vps_setup.sh
```
- The wizard checks prerequisites and installs missing components (e.g., Docker, Composer, Fail2ban).
- A menu appears with options:
  ```
  VPS Setup Script v2.5.0
  Main Menu:
  1. Configure a new domain (set up website, FTP, database, email)
  2. Install WordPress (with automated database setup)
  3. Set up Git repository (with deployment hooks)
  4. Install phpMyAdmin (secure database management)
  5. Install webmail (access email via browser)
  6. Edit PHP settings (adjust memory, file uploads)
  7. Configure security (Fail2ban, AppArmor/SELinux)
  8. Install Docker and Composer
  9. Delete a domain (remove all resources)
  10. Exit
  Select an option [1-10]:
  ```
- Follow prompts to configure domains, WordPress, Git, or other features.
- Example output for WordPress installation:
  ```
  WordPress Setup Summary for example.com:
    - Website URL: https://example.com
    - Database: wp_example
    - Database User: wp_user
    - Admin URL: https://example.com/wp-admin
    - Git Repository: /var/www/example.com/git
    - phpMyAdmin URL: https://example.com/dbadmin_7f9a2b
  Note: Access WordPress at https://example.com and manage databases at https://example.com/dbadmin_7f9a2b (HTTP auth required).
  ```

### Non-Interactive Mode
For automation, use the `--non-interactive` flag to configure a domain with defaults:
```bash
sudo ./vps_setup.sh --non-interactive
```
- Skips prompts, uses defaults (e.g., `admin@example.com` for SSL email, randomized phpMyAdmin URL).
- Useful for scripts or CI/CD pipelines.

### Batch Processing
Process multiple domains from a file using the `--domains` flag:
```bash
echo -e "example.com\ntest.com" > domains.txt
sudo ./vps_setup.sh --domains domains.txt
```
- The file should list one domain per line.
- Each domain is configured with defaults, including Git repos and optional WordPress.

### Dry-Run Mode
Preview actions without making changes using the `--dry-run` flag:
```bash
sudo ./vps_setup.sh --dry-run
```
- Actions are logged to `/tmp/vps_setup_dry_run_*.log` instead of executed.
- Useful for testing WordPress, Git, or Docker setups.

### Other Options
- **Custom Configuration File**: Specify a config file with `--config`:
  ```bash
  sudo ./vps_setup.sh --config /path/to/custom.conf
  ```
- **Verbose Output**: Enable detailed debugging with `--verbose`:
  ```bash
  sudo ./vps_setup.sh --verbose
  ```
- **Help**: View detailed help with `-h` or `--help`:
  ```bash
  ./vps_setup.sh --help
  ```

## Configuration File
Create a configuration file at `/etc/vps_setup.conf` to set defaults and reduce prompts. Example:
```ini
ssh_port=2222
web_user=www-data
web_group=www-data
gpg_recipient=admin@yourdomain.com
wordpress_install=yes
phpmyadmin_url_prefix=dbadmin
docker_install=yes
```
- **ssh_port**: Custom SSH port (default: 2222).
- **web_user**: Web server user (e.g., www-data for Apache/Nginx).
- **web_group**: Web server group (e.g., www-data).
- **gpg_recipient**: Email for GPG encryption of credentials.
- **wordpress_install**: Set to `yes` to enable WordPress by default.
- **phpmyadmin_url_prefix**: Custom prefix for phpMyAdmin URLs (default: `dbadmin`).
- **docker_install**: Set to `yes` to install Docker and Composer.

The script loads this file automatically if it exists. If not, it uses defaults and informs you:
```
Warning: No configuration file found at /etc/vps_setup.conf, using defaults.
Tip: Create /etc/vps_setup.conf to set defaults (e.g., ssh_port=2222).
```

## Troubleshooting
If you encounter issues, try these steps:
1. **Check Logs**:
   - Logs are saved to `/var/log/vps_setup.log`.
   - Run `cat /var/log/vps_setup.log` to view details.
2. **Run in Verbose Mode**:
   ```bash
   sudo ./vps_setup.sh --verbose
   ```
   - Shows detailed output for debugging.
3. **Common Issues**:
   - **DNS Errors**: Ensure your domain’s A record points to your VPS’s IP (check with `dig example.com`).
     ```
     Error: DNS for example.com resolves to 203.0.113.1, not this server (192.0.2.1).
     Tip: Set an A record for example.com to point to 192.0.2.1 in your DNS settings.
     ```
   - **MySQL Access**: Verify MySQL root access with `mysql -u root`.
     ```
     Error: MySQL access failed. Install MySQL or check root credentials.
     Tip: Run 'mysql -u root' to verify access or install MySQL with 'apt-get install mysql-server'.
     ```
   - **Fail2ban Issues**: Check jail status with `fail2ban-client status sshd`.
     ```
     Error: Fail2ban failed to start.
     Tip: Run 'systemctl status fail2ban' and check logs in /var/log/fail2ban.log.
     ```
   - **Docker Errors**: Ensure Docker is running with `systemctl status docker`.
     ```
     Error: Docker service not running.
     Tip: Start Docker with 'systemctl start docker' or install it via the script.
     ```
   - **Git Hook Issues**: Verify post-receive hook permissions with `ls -l /var/www/example.com/git/hooks`.
     ```
     Error: Git deployment failed.
     Tip: Ensure hooks are executable with 'chmod +x /var/www/example.com/git/hooks/post-receive'.
     ```
   - **Dependencies Missing**: Install prompted dependencies or run `sudo apt-get install mysql openssl gpg certbot docker.io composer`.
   - **Service Failures**: Check service status with `systemctl status apache2` or `systemctl status nginx`.
4. **Restore Backups**:
   - Backups are saved in `/backups` (e.g., `/backups/example.com-20250427120000.tar.gz`).
   - Restore with:
     ```bash
     tar -xzf /backups/example.com-20250427120000.tar.gz -C /
     ```
5. **Get Help**:
   - Check the script’s `--help` output.
   - Search online for specific error messages or consult your system administrator.

## FAQ
**Q: Can I run this script on Ubuntu?**  
A: Yes, the script is fully compatible with Ubuntu 20.04 and 22.04. It’s also compatible with other Debian/RedHat-based systems.

**Q: Can I run this script on macOS?**  
A: No, it’s designed for Linux (e.g., Ubuntu). Use an Ubuntu VM or remote VPS for execution.

**Q: What happens if an operation fails?**  
A: The script triggers a rollback, removing partial configs. Check `/var/log/vps_setup.log` for details.

**Q: How do I add multiple domains?**  
A: In interactive mode, run the script multiple times or use the `--domains` option with a file containing one domain per line (e.g., `domains.txt`).

**Q: Is the script secure?**  
A: Yes, it includes Fail2ban, AppArmor/SELinux, encrypted SFTP, and secure phpMyAdmin access. Test in a non-production environment first, as per the [Author Disclaimer](#author).

## Changelog
**v2.5.0 (April 2025)**:
- Added WordPress installation with automated database setup.
- Implemented per-domain Git repositories with post-receive hooks.
- Added secure phpMyAdmin installation with HTTP authentication.
- Enhanced security with Fail2ban and AppArmor/SELinux configuration.
- Added Docker and Composer support for containerized apps and dependency management.
- Improved guided setup wizard and DNS verification.
- Enhanced user prompts with defaults and color-coded output.

**v2.1.1 (April 2025)**:
- Added author details display on script execution.
- Updated version tracking.

**v2.1.0**:
- Added AppArmor/SELinux support.
- Enhanced Cloudflare DNS automation.

**v2.0.0**:
- Introduced non-interactive mode and rollback mechanism.
- Added multiple PHP version support.

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository (if hosted on a platform like GitHub).
2. Create a feature branch (`git checkout -b feature/new-feature`).
3. Make changes and test thoroughly.
4. Submit a pull request with a clear description.

Please include:
- Detailed commit messages.
- Tests or examples demonstrating the change.
- Updates to this README if new features are added.

## Author
**Name**: Yogesh Gupta  
**Email**: yk68785@gmail.com  
**GitHub**: [Yogesh0610](https://github.com/Yogesh0610)  
**LinkedIn**: [Yogesh Gupta](https://www.linkedin.com/in/yogesh-gupta)  

**About**:  
🚀 Software Engineer | PHP, React.js, React Native, Laravel  
Passionate about crafting seamless web and mobile experiences. With expertise in PHP, React.js, React Native, and Laravel, I transform ideas into high-performance applications.

**Key Skills**:
- **PHP**: Proficient in building robust backend systems and APIs.
- **React.js**: Expertise in developing interactive, high-performance web applications.
- **React Native**: Skilled in creating cross-platform mobile apps with seamless UX.
- **Laravel**: Experienced in leveraging Laravel for scalable, maintainable applications.

**Philosophy**:  
Always learning, always innovating. I aim to exceed expectations and tackle challenges that push technical boundaries.

**Author Disclaimer**:  
The author, Yogesh Gupta, is not responsible for any damages, data loss, or issues arising from the use of this script. Use at your own risk and ensure backups and testing before running in a production environment.

## Acknowledgments
- Inspired by open-source VPS automation tools like Webmin and EasyEngine.
- Thanks to the Ubuntu community for robust package support.
- Built with ❤️ by Yogesh Gupta.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Happy Hosting!**  
If you have questions or need assistance, check the [Troubleshooting](#troubleshooting) or [FAQ](#faq) sections, or run `./vps_setup.sh --help`.
