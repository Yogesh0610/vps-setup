# VPS Setup Script

![GitHub](https://img.shields.io/github/license/Yogesh0610/vps-setup)
![GitHub last commit](https://img.shields.io/github/last-commit/Yogesh0610/vps-setup)

A powerful Bash script to **automate the setup and management of a Virtual Private Server (VPS)** for web hosting, specifically designed to run on **Ubuntu** (e.g., Ubuntu 20.04/22.04) and other Debian/RedHat-based systems. This script is ideal for developers, system administrators, and DevOps professionals who need a streamlined, secure, and production-ready VPS configuration for websites, applications, or development environments.

## 📖 Overview

The `vps_setup.sh` script simplifies the complex task of configuring a VPS by automating the installation and management of web servers, PHP, databases, email, FTP, and advanced security features. It is **fully compatible with Ubuntu**, making it an excellent choice for Ubuntu-based VPS instances (e.g., on AWS, DigitalOcean, or Linode). The script supports both interactive and non-interactive modes, ensuring flexibility for manual setups or automated deployments.

Key highlights:
- **Ubuntu Support**: Optimized for Ubuntu 20.04/22.04, with compatibility for other Debian/RedHat-based systems.
- **Comprehensive Features**: Includes web hosting, database management, email, DNS automation, and robust security.
- **Rollback Mechanism**: Automatically reverts changes if an operation fails.
- **Encrypted Outputs**: Secures credentials and backups with GPG encryption.

Use cases:
- Setting up a new Ubuntu VPS for hosting single or multiple websites.
- Automating secure server configurations for development or production.
- Deploying a WordPress site with SSL and email services on Ubuntu.

## ✨ Features

### Web Hosting
- **Web Servers**: Installs Apache or Nginx with virtual host configuration.
- **SSL/TLS**: Integrates Certbot for Let’s Encrypt SSL certificates.
- **PHP Support**: Installs multiple PHP versions (7.0 to 8.4) with extensions like `gd`, `curl`, `mysql`, and `imagick`.
- **CMS Integration**: Optional WordPress installation with automated database setup.
- **Git Repositories**: Configures per-domain Git repos with post-receive hooks for deployments.

### Database Management
- **Engines**: Supports MySQL or MariaDB with secure hardening (e.g., bind to localhost, remove test databases).
- **phpMyAdmin**: Installs and secures phpMyAdmin with HTTP authentication and randomized URLs.

### Email and DNS
- **Email Services**: Configures Postfix, Dovecot, and OpenDKIM for secure email with DKIM signatures.
- **Automated DNS**: Sets up Cloudflare DNS records for domains (optional).

### Security
- **Firewall**: Configures UFW to allow only necessary ports (e.g., 80, 443, 2222).
- **Fail2ban**: Protects against brute-force attacks on SSH, FTP, MySQL, and web services.
- **SSH Hardening**: Changes SSH port to 2222, disables root login, and enables 2FA (Google Authenticator).
- **AppArmor/SELinux**: Applies mandatory access controls for Apache and MySQL (optional).
- **Encrypted Backups**: Stores backups in `/backups` with GPG encryption.
- **Secure Permissions**: Sets `750` (directories) and `640` (files) on web roots and backups.

### Automation and Management
- **Non-Interactive Mode**: Supports configuration via `/etc/vps_setup.conf` for automated setups.
- **Rollback**: Reverts failed operations (e.g., domain setup, user creation).
- **Logging**: Detailed logs in `/var/log/vps_setup.log`.
- **Credentials**: Encrypts credentials in `/root/credentials.txt.gpg`.
- **Reporting**: Generates a setup summary in `/root/vps_setup_report.txt`.

### Additional Tools
- **Composer**: Installs PHP Composer for dependency management.
- **Docker**: Sets up Docker and Docker Compose for containerized applications.
- **FTP**: Configures vsftpd for secure file transfers with per-domain users.

## 👤 Author

- **Name**: Yogesh Gupta
- **Email**: yk68785@gmail.com
- **GitHub**: [Yogesh0610](https://github.com/Yogesh0610)
- **LinkedIn**: [Yogesh Gupta](https://www.linkedin.com/in/yogesh-gupta-64610a169/)

**About**:  
🚀 **Software Engineer | PHP, React.js, React Native, Laravel**  
Passionate about crafting seamless web and mobile experiences. With expertise in PHP, React.js, React Native, and Laravel, I transform ideas into high-performance applications.

**Key Skills**:  
- **PHP**: Proficient in building robust backend systems and APIs.  
- **React.js**: Expertise in developing interactive, high-performance web applications.  
- **React Native**: Skilled in creating cross-platform mobile apps with seamless UX.  
- **Laravel**: Experienced in leveraging Laravel for scalable, maintainable applications.  

**Philosophy**:  
Always learning, always innovating. I aim to exceed expectations and tackle challenges that push technical boundaries.

**Author Disclaimer**:  
The author, Yogesh Gupta, is **not responsible** for any damages, data loss, or issues arising from the use of this script. Use at your own risk and ensure backups and testing before running in a production environment.

## ⚠️ Disclaimer

This script is provided **as-is** without any warranties. The author, Yogesh Gupta, is **not liable** for any damages, data loss, system failures, or other issues resulting from the use of this script. Users are strongly advised to:
- Test the script in a non-production environment first.
- Maintain up-to-date backups of all critical data.
- Review the script’s actions (e.g., using `--dry-run`) before execution.
- Ensure compatibility with your system (e.g., Ubuntu 20.04/22.04) and configurations.

By using this script, you acknowledge that you are responsible for any consequences of its execution.

## 🛠️ Prerequisites

- **Operating System**: Ubuntu 20.04 or 22.04 (also compatible with other Debian/RedHat-based systems).
- **Root Access**: Must be run as root (`sudo`).
- **Internet Connection**: Required for downloading packages.
- **Dependencies**: `bash`, `openssl`, `gpg` (installed automatically if missing).

### macOS-Specific Setup (for Development)
If you’re developing or testing on macOS (e.g., Yogesh’s MacBook Air):
1. Install Homebrew:
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
2. Install Git:
   ```bash
   brew install git
   ```
3. Configure Git:
   ```bash
   git config --global user.name "Yogesh Gupta"
   git config --global user.email "yk68785@gmail.com"
   ```

**Note**: The script cannot run directly on macOS (it’s Linux-only). Use a Linux VM (e.g., Ubuntu via VirtualBox) or a remote Ubuntu VPS.

## 📥 Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Yogesh0610/vps-setup.git
   cd vps-setup
   ```

2. **Make the Script Executable**:
   ```bash
   chmod +x vps_setup.sh
   ```

3. **Run the Script on Ubuntu**:
   On an Ubuntu VPS (20.04/22.04), execute:
   ```bash
   sudo ./vps_setup.sh
   ```

**Note**: Ensure you’re running the script on an Ubuntu-based system or compatible Linux distribution. For macOS users, deploy to a remote Ubuntu VPS or use a local Ubuntu VM.

## 🚀 Usage

The script supports **interactive** and **non-interactive** modes for flexible configuration on Ubuntu systems.

### Interactive Mode
Run the script on Ubuntu and follow prompts to configure:
- Web server (Apache or Nginx)
- PHP version (7.0 to 8.4)
- Database engine (MySQL or MariaDB)
- Domain setup (virtual host, SSL, FTP, email, WordPress, Cloudflare DNS)
- Security features (2FA, AppArmor, Fail2ban)

Example:
```bash
sudo ./vps_setup.sh
```

### Non-Interactive Mode
Create a configuration file at `/etc/vps_setup.conf` for automated setups on Ubuntu.

**Example `/etc/vps_setup.conf`**:
```bash
domain=example.com
web_server=nginx
php_version=8.4
non_interactive=true
enable_2fa=true
enable_wordpress=true
enable_cloudflare_dns=true
enable_ftp=true
enable_fail2ban=true
```

Run in non-interactive mode:
```bash
sudo ./vps_setup.sh --non-interactive
```

**Multi-Domain Configuration Example**:
```bash
domain=example.com,blog.example.com
web_server=apache
php_version=8.4
non_interactive=true
enable_2fa=true
enable_wordpress=true
enable_cloudflare_dns=true
enable_git=true
enable_backup=true
```

### Command-Line Options
```bash
--domain <domain>       Specify domain name (e.g., example.com)
--web-server <server>   Choose web server (apache or nginx)
--php-version <version> Set PHP version (7.0 to 8.4)
--dry-run               Simulate actions without changes
--non-interactive       Run without prompts
--help                  Display help
```

Example:
```bash
sudo ./vps_setup.sh --domain example.com --web-server apache --php-version 8.4 --dry-run
```

## 📋 Outputs

- **Logs**: All actions logged to `/var/log/vps_setup.log` (e.g., successes, errors, rollbacks).
- **Credentials**: Encrypted in `/root/credentials.txt.gpg` with passphrase in `/root/credentials.txt.pass`.
- **Report**: Setup summary in `/root/vps_setup_report.txt`.
- **Backups**: Encrypted in `/backups/<domain>/<timestamp>`.

Example log entry:
```
2025-04-25 10:15:23 - Virtual host for example.com created.
2025-04-25 10:15:30 - SSL configured for example.com.
```

## 🔒 Security Features

- **Rollback**: Reverts changes (e.g., domain configs, users) if an operation fails.
- **Encryption**: Uses GPG for credentials and backups.
- **Secure Permissions**: Applies `750` (directories) and `640` (files) to web roots and backups.
- **SSH 2FA**: Optional Google Authenticator for SSH logins.
- **AppArmor/SELinux**: Restricts Apache and MySQL processes (optional).
- **Fail2ban**: Bans malicious IPs after failed login attempts.
- **UFW Firewall**: Allows only essential ports (e.g., 80, 443, 2222).

## 🛠️ Maintenance

- **Update Ubuntu System**:
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
- **Decrypt Credentials**:
  ```bash
  gpg -d /root/credentials.txt.gpg
  ```
  Use the passphrase from `/root/credentials.txt.pass`.

## 🐞 Troubleshooting

- **Git Push Errors (e.g., “src refspec main does not match any”)**:
  - Ensure changes are committed:
    ```bash
    git commit -m "Initial commit"
    ```
  - Verify the branch:
    ```bash
    git branch
    ```
  - Push again:
    ```bash
    git push -u origin main
    ```
- **Permission Denied (GitHub)**:
  - Use a Personal Access Token (repo scope) instead of a password.
  - Reset remote:
    ```bash
    git remote set-url origin https://github.com/Yogesh0610/vps-setup.git
    ```
- **Package Installation Fails on Ubuntu**:
  - Check internet connectivity and update package lists:
    ```bash
    sudo apt-get update
    ```
- **Rollback Issues**:
  - Check `/var/log/vps_setup.log` for details.
  - Manually remove failed configs (e.g., `/etc/apache2/sites-available/example.com.conf`).
- **macOS Compatibility**:
  - The script is Ubuntu/Linux-only. Test on an Ubuntu VM (e.g., via VirtualBox) or a remote Ubuntu VPS.

## ❓ FAQ

**Q: Can I run this script on Ubuntu?**  
A: Yes, the script is fully compatible with Ubuntu 20.04 and 22.04. It’s also compatible with other Debian/RedHat-based systems.

**Q: Can I run this script on macOS?**  
A: No, it’s designed for Linux (e.g., Ubuntu). Use an Ubuntu VM or remote VPS for execution.

**Q: What happens if an operation fails?**  
A: The script triggers a rollback, removing partial configs. Check `/var/log/vps_setup.log` for details.

**Q: How do I add multiple domains?**  
A: In interactive mode, run the script multiple times or specify multiple domains in `/etc/vps_setup.conf` (comma-separated).

**Q: Is the script secure?**  
A: Yes, it includes firewall, 2FA, encryption, and more. Test in a non-production environment first, as per the disclaimer.

## 📝 Changelog

- **v2.1.1** (April 2025):
  - Added author details display on script execution.
  - Updated version tracking.
- **v2.1.0**:
  - Added AppArmor/SELinux support.
  - Enhanced Cloudflare DNS automation.
- **v2.0.0**:
  - Introduced non-interactive mode and rollback mechanism.
  - Added multiple PHP version support.

## 🤝 Contributing

We welcome contributions! To contribute:
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```
3. Commit changes:
   ```bash
   git commit -m "Add your feature"
   ```
4. Push to the branch:
   ```bash
   git push origin feature/your-feature
   ```
5. Open a pull request with a clear description.

Please follow:
- Code style: Use consistent Bash formatting (e.g., 4-space indentation).
- Testing: Test changes on an Ubuntu VPS (non-production).
- Issues: Report bugs or suggest features on the [Issues page](https://github.com/Yogesh0610/vps-setup/issues).

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by open-source VPS automation tools like Webmin and EasyEngine.
- Thanks to the Ubuntu community for robust package support.
- Built with ❤️ by Yogesh Gupta.
