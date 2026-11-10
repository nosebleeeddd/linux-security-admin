# Linux Security & Administration

A practical Linux security administration reference covering system hardening, firewall configuration, access control, network monitoring, intrusion detection, logging, incident response, and forensic investigation.

Designed for Linux administrators, cybersecurity students, SOC analysts, and security researchers.

## Table of Contents

1. [Introduction](#introduction)
2. [Linux Security Fundamentals](#linux-security-fundamentals)
3. [User and Permission Management](#user-and-permission-management)
4. [Firewall Configuration](#firewall-configuration)
   - [UFW](#ufw-uncomplicated-firewall)
   - [iptables](#iptables)
   - [firewalld](#firewalld)
5. [System Hardening](#system-hardening)
6. [SSH Hardening](#ssh-hardening)
7. [Log Analysis and SIEM Integration](#log-analysis-and-siem-integration)
8. [Intrusion Detection Systems](#intrusion-detection-systems)
9. [Container Security](#container-security)
10. [Kernel Security and Mandatory Access Control](#kernel-security-and-mandatory-access-control)
11. [Network Security and Monitoring](#network-security-and-monitoring)
12. [Incident Response and Forensics](#incident-response-and-forensics)
13. [Backup and Recovery](#backup-and-recovery)
14. [Monitoring and Alerting](#monitoring-and-alerting)
15. [Security Automation](#security-automation)
16. [Compliance and Auditing](#compliance-and-auditing)
17. [Resources](#resources)

---

## Introduction

Linux security involves protecting operating systems, applications, services, users, and network infrastructure against unauthorized access and malicious activity.

A secure Linux environment requires multiple layers of protection.

### Key Objectives

- Defense in depth.
- Attack surface reduction.
- Least privilege.
- Network access control.
- Centralized logging.
- Continuous monitoring.
- Intrusion detection.
- Incident response.
- Configuration management.

## Linux Security Fundamentals

### Linux Security Architecture

Linux separates user-space applications from kernel-space operations.

```text
             USER SPACE
    ┌──────────────────────────┐
    │ Applications             │
    │ System Libraries         │
    │ Shells and Utilities     │
    │ System Calls             │
    └────────────┬─────────────┘
                 |
             KERNEL SPACE
    ┌────────────▼─────────────┐
    │ Process Management       │
    │ Memory Management        │
    │ Filesystem Management    │
    │ Network Stack            │
    │ Device Drivers           │
    └────────────┬─────────────┘
                 |
              HARDWARE
```

### Important Security Models

| Model | Description |
|---|---|
| DAC | Discretionary Access Control |
| MAC | Mandatory Access Control |
| ACL | Access Control Lists |
| Capabilities | Fine-grained Linux privileges |
| Namespaces | Process and resource isolation |
| cgroups | Resource usage control |

### System Information

```bash
# Kernel information
uname -a

# Distribution information
cat /etc/os-release

# Kernel version
cat /proc/version

# System uptime
uptime

# CPU information
lscpu

# Memory information
free -h

# Block devices
lsblk
```

### Security-Related System Information

```bash
# Check available security modules
ls /sys/kernel/security/

# View loaded kernel modules
lsmod

# View kernel parameters
sysctl -a

# Check installed security tools
dpkg -l | grep -E 'audit|apparmor|selinux|fail2ban'
```

## User and Permission Management

### User Management

Create a dedicated administrative or monitoring account:

```bash
sudo adduser analyst
```

Inspect users:

```bash
cat /etc/passwd
```

Inspect groups:

```bash
cat /etc/group
```

Inspect the current user's permissions:

```bash
id
groups
```

Lock and unlock an account:

```bash
# Lock
sudo usermod -L analyst

# Unlock
sudo usermod -U analyst
```

Disable interactive login:

```bash
sudo usermod -s /usr/sbin/nologin analyst
```

Review password aging:

```bash
sudo chage -l analyst
```

### Sudo Configuration

Edit sudo permissions safely:

```bash
sudo visudo
```

Example of restricting administrative access:

```text
analyst ALL=(root) /usr/bin/journalctl, /usr/bin/systemctl
```

Avoid granting unrestricted `NOPASSWD: ALL` privileges unless there is a clearly justified administrative requirement.

### File Permissions

Linux permissions consist of:

- Owner.
- Group.
- Others.

```bash
# Read, write, execute permissions
ls -la

# Restrict a sensitive file
chmod 600 sensitive.conf

# Restrict a private directory
chmod 700 private/

# Change file ownership
sudo chown analyst:analyst sensitive.conf
```

### Special Permissions

| Permission | Meaning |
|---|---|
| SUID | Executes with file owner's effective privileges |
| SGID | Executes with group privileges or inherits directory group |
| Sticky bit | Restricts deletion in shared directories |

Find SUID files:

```bash
sudo find / -type f -perm -4000 -ls 2>/dev/null
```

Find SGID files:

```bash
sudo find / -type f -perm -2000 -ls 2>/dev/null
```

### Access Control Lists

Install ACL utilities:

```bash
sudo apt install acl
```

Inspect ACLs:

```bash
getfacl /path/to/file
```

Grant a user read access:

```bash
sudo setfacl -m u:analyst:r-- /path/to/file
```

Remove a specific ACL:

```bash
sudo setfacl -x u:analyst /path/to/file
```

## Firewall Configuration

A firewall controls network traffic entering, leaving, and passing through a Linux system.

Common Linux firewall management options include:

- UFW.
- iptables.
- nftables.
- firewalld.

**Important:** Avoid running multiple firewall managers that modify the same ruleset without understanding their interaction.

### UFW (Uncomplicated Firewall)

UFW provides a simplified interface for managing Linux firewall rules.

Install:

```bash
sudo apt update
sudo apt install ufw
```

Inspect firewall status:

```bash
sudo ufw status verbose
```

Set default policies:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

Allow SSH:

```bash
sudo ufw allow 22/tcp
```

Allow HTTP and HTTPS:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

Restrict SSH to a trusted LAN:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
```

Allow access to an API from a specific computer:

```bash
sudo ufw allow from 192.168.1.100 to any port 8000 proto tcp
```

Enable UFW:

```bash
sudo ufw enable
```

Inspect numbered rules:

```bash
sudo ufw status numbered
```

Delete a rule:

```bash
sudo ufw delete allow 22/tcp
```

Disable UFW:

```bash
sudo ufw disable
```

**Important:** If connected over SSH, configure and verify the SSH allow rule before enabling UFW. Otherwise, you can lock yourself out.

### iptables

iptables is a Linux firewall administration utility that manages packet filtering rules.

#### Basic Concepts

| Chain | Purpose |
|---|---|
| INPUT | Traffic destined for the local machine |
| OUTPUT | Traffic originating from the local machine |
| FORWARD | Traffic routed through the machine |

Tables include:

- filter.
- nat.
- mangle.
- raw.
- security.

Inspect current rules:

```bash
sudo iptables -L -n -v
```

Display rules with line numbers:

```bash
sudo iptables -L -n -v --line-numbers
```

Save current rules:

```bash
sudo iptables-save
```

#### Basic Firewall Example

The following example is for a system that should accept SSH from a trusted LAN and allow established connections.

```bash
# Allow loopback traffic
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m conntrack \
--ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from trusted LAN
sudo iptables -A INPUT -p tcp \
-s 192.168.1.0/24 --dport 22 -j ACCEPT

# Drop other incoming traffic
sudo iptables -P INPUT DROP

# Allow outgoing connections
sudo iptables -P OUTPUT ACCEPT

# Prevent forwarding
sudo iptables -P FORWARD DROP
```

Replace the example subnet with your actual trusted network.

Apply firewall changes carefully, particularly on remotely managed systems. Use a recovery method or console access before changing default policies.

#### Rate Limiting

Example SSH connection rate limiting:

```bash
sudo iptables -A INPUT -p tcp --dport 22 \
-m conntrack --ctstate NEW \
-m limit --limit 5/minute --limit-burst 5 \
-j ACCEPT
```

This example is a basic rate limit, not a complete brute-force protection system.

#### Logging Dropped Packets

```bash
sudo iptables -A INPUT -m limit \
--limit 5/minute -j LOG \
--log-prefix "IPTABLES-DROP: "
```

#### Persistence

On Debian-based distributions:

```bash
sudo apt install iptables-persistent
```

Save rules:

```bash
sudo netfilter-persistent save
```

Restore rules:

```bash
sudo netfilter-persistent reload
```

### firewalld

firewalld provides zone-based firewall management.

Install:

```bash
sudo apt install firewalld
```

Start and enable:

```bash
sudo systemctl enable --now firewalld
```

Check status:

```bash
sudo firewall-cmd --state
```

Display active rules:

```bash
sudo firewall-cmd --list-all
```

Allow SSH:

```bash
sudo firewall-cmd --permanent --add-service=ssh
```

Allow HTTP and HTTPS:

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
```

Allow a custom port:

```bash
sudo firewall-cmd --permanent --add-port=8080/tcp
```

Apply changes:

```bash
sudo firewall-cmd --reload
```

### Firewall Troubleshooting

Useful commands:

```bash
# Listening TCP and UDP services
sudo ss -tulnp

# Current firewall rules
sudo iptables -L -n -v

# UFW status
sudo ufw status verbose

# Firewall service status
sudo systemctl status ufw

# Check local network configuration
ip addr
ip route
```

Remember that a firewall rule allowing a port does not automatically mean an application is listening on that port.

## System Hardening

System hardening reduces unnecessary services, permissions, and exposed interfaces.

### Kernel Security Parameters

Inspect existing kernel settings:

```bash
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.rp_filter
sysctl kernel.kptr_restrict
```

Example configuration:

Create:

```bash
sudo nano /etc/sysctl.d/99-security.conf
```

Example settings:

```text
# Enable reverse path filtering
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Disable accepting IPv4 redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Restrict kernel pointer visibility
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1
```

Apply settings:

```bash
sudo sysctl --system
```

Review the effects of individual parameters before applying them. Settings such as reverse path filtering and IP forwarding may need adjustment for routers, VPNs, and multi-homed systems.

### Service Hardening

List enabled services:

```bash
systemctl list-unit-files --type=service --state=enabled
```

List running services:

```bash
systemctl list-units --type=service --state=running
```

Inspect listening ports:

```bash
sudo ss -tulpn
```

Disable unnecessary services only after confirming they are not required:

```bash
sudo systemctl disable --now avahi-daemon
```

### Package Security

Update packages:

```bash
sudo apt update
sudo apt upgrade
```

Find packages with available updates:

```bash
apt list --upgradable
```

Remove unused dependencies:

```bash
sudo apt autoremove
```

## SSH Hardening

SSH is commonly used for remote administration and should be properly secured.

### Backup Configuration

```bash
sudo cp /etc/ssh/sshd_config \
/etc/ssh/sshd_config.backup
```

### Recommended Configuration

Edit:

```bash
sudo nano /etc/ssh/sshd_config
```

Example:

```text
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no

MaxAuthTries 3
LoginGraceTime 60

X11Forwarding no
PermitUserEnvironment no

AllowUsers analyst
```

Replace `analyst` with your actual authorized SSH account.

For systems that still require password authentication, keep it enabled only when necessary and use strong authentication controls.

Validate configuration:

```bash
sudo sshd -t
```

Restart SSH:

```bash
sudo systemctl restart ssh
```

Check service status:

```bash
sudo systemctl status ssh
```

**Important:** Keep an existing SSH session open and test a second login before closing it. Confirm your key authentication works before disabling password authentication.

## Log Analysis and SIEM Integration

System logs are essential for identifying suspicious activity, troubleshooting, and incident response.

### Important Linux Logs

| Log | Purpose |
|---|---|
| `/var/log/auth.log` | Authentication events on Debian |
| `/var/log/syslog` | General system events |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/audit/audit.log` | Audit events |
| `/var/log/dpkg.log` | Package management activity |

Log locations differ between distributions.

### Journalctl

Display recent system events:

```bash
sudo journalctl -n 100
```

Display SSH events:

```bash
sudo journalctl -u ssh
```

Display cron events:

```bash
sudo journalctl -u cron
```

Follow logs in real time:

```bash
sudo journalctl -f
```

Display events from the previous 24 hours:

```bash
sudo journalctl --since "24 hours ago"
```

### Authentication Log Analysis

Failed SSH attempts:

```bash
sudo grep "Failed password" /var/log/auth.log
```

Successful SSH authentication:

```bash
sudo grep "Accepted" /var/log/auth.log
```

Sudo activity:

```bash
sudo grep "sudo:" /var/log/auth.log
```

Recent login history:

```bash
last
```

Failed login history:

```bash
sudo lastb
```

### Rsyslog

Install:

```bash
sudo apt install rsyslog
```

Check status:

```bash
sudo systemctl status rsyslog
```

Rsyslog can forward logs to a centralized logging server or SIEM.

Example configuration:

```text
*.* @@192.168.1.100:514
```

Here, `@@` indicates TCP forwarding.

Configure the receiving server to accept the appropriate traffic and restrict access to trusted systems.

### SIEM Platforms

| Platform | Purpose |
|---|---|
| Wazuh | SIEM and endpoint monitoring |
| Elastic Stack | Log collection and analysis |
| Splunk | Security information and event management |
| Graylog | Centralized logging |
| Security Onion | Network security monitoring |

## Intrusion Detection Systems

Intrusion Detection Systems identify suspicious activity and generate alerts.

### AIDE

Advanced Intrusion Detection Environment monitors file integrity.

Install:

```bash
sudo apt install aide
```

Initialize the database:

```bash
sudo aideinit
```

Run a check:

```bash
sudo aide --check
```

AIDE can detect changes to:

- File contents.
- File permissions.
- Ownership.
- File metadata.
- System binaries.
- Configuration files.

The initial database should be created from a known-clean system and protected against unauthorized modification.

### Auditd

Auditd provides Linux kernel auditing capabilities.

Install:

```bash
sudo apt install auditd audispd-plugins
```

Enable:

```bash
sudo systemctl enable --now auditd
```

Check status:

```bash
sudo systemctl status auditd
```

Inspect audit events:

```bash
sudo ausearch -m USER_LOGIN
```

Review audit logs:

```bash
sudo tail -f /var/log/audit/audit.log
```

### Suricata

Suricata is a network IDS/IPS and network security monitoring platform.

Install:

```bash
sudo apt install suricata
```

Check version:

```bash
suricata --build-info
```

Update detection rules:

```bash
sudo suricata-update
```

Check configuration:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Start service:

```bash
sudo systemctl enable --now suricata
```

Inspect alerts:

```bash
sudo tail -f /var/log/suricata/fast.log
```

Inspect structured event data:

```bash
sudo tail -f /var/log/suricata/eve.json
```

### Snort

Snort is another widely used network intrusion detection system.

Useful concepts:

- Packet inspection.
- Detection signatures.
- Protocol analysis.
- Rule management.
- Alert generation.

Reference:

https://www.snort.org/

### Fail2ban

Fail2ban monitors log files and can temporarily block IP addresses associated with repeated suspicious authentication attempts.

Install:

```bash
sudo apt install fail2ban
```

Enable:

```bash
sudo systemctl enable --now fail2ban
```

Check status:

```bash
sudo fail2ban-client status
```

Inspect SSH protection:

```bash
sudo fail2ban-client status sshd
```

## Container Security

Containers introduce additional security considerations because they share the host kernel.

### Docker Security

Important practices:

- Avoid privileged containers.
- Use non-root users.
- Restrict Linux capabilities.
- Apply resource limits.
- Keep images updated.
- Scan images for vulnerabilities.
- Avoid unnecessary host mounts.
- Use trusted image sources.

Example:

```bash
# Run as a non-root user
docker run --user 1000:1000 nginx

# Use a read-only filesystem
docker run --read-only nginx

# Drop unnecessary capabilities
docker run --cap-drop=ALL nginx

# Apply memory limits
docker run -m 512m nginx
```

Inspect running containers:

```bash
docker ps
```

Inspect container configuration:

```bash
docker inspect <container_id>
```

### Container Image Scanning

Trivy can identify vulnerabilities in container images.

```bash
trivy image nginx:latest
```

### Kubernetes Security

Important security concepts:

- Role-Based Access Control (RBAC).
- Network Policies.
- Pod Security Standards.
- Secrets management.
- Namespace isolation.
- Container image verification.
- Resource limits.

Example network policy concept:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

This policy denies ingress traffic to selected pods unless additional policies permit it.

## Kernel Security and Mandatory Access Control

### SELinux

SELinux provides Mandatory Access Control to restrict what processes can access.

Check status:

```bash
sestatus
```

Check current mode:

```bash
getenforce
```

Inspect file contexts:

```bash
ls -Z /etc/
```

Inspect process contexts:

```bash
ps -eZ
```

Review SELinux denials:

```bash
sudo ausearch -m AVC
```

### AppArmor

AppArmor provides application-specific security profiles.

Check status:

```bash
sudo aa-status
```

Install utilities:

```bash
sudo apt install apparmor-utils
```

Inspect profiles:

```bash
ls /etc/apparmor.d/
```

AppArmor can restrict:

- Filesystem access.
- Network access.
- Process execution.
- Application capabilities.

Avoid disabling security profiles to resolve application problems without first investigating the denial.

## Network Security and Monitoring

Network monitoring provides visibility into traffic, services, and communication patterns.

### Network Interface Information

```bash
ip addr
ip link
ip route
```

### Listening Services

```bash
sudo ss -tulnp
```

### Active Connections

```bash
ss -tunap
```

### Packet Capture with tcpdump

Install:

```bash
sudo apt install tcpdump
```

Capture traffic:

```bash
sudo tcpdump -i eth0
```

Capture traffic without DNS resolution:

```bash
sudo tcpdump -i eth0 -nn
```

Capture HTTP traffic:

```bash
sudo tcpdump -i eth0 -nn port 80
```

Capture traffic to a file:

```bash
sudo tcpdump -i eth0 -w capture.pcap
```

Read a capture:

```bash
tcpdump -r capture.pcap
```

### Wireshark

Wireshark provides graphical packet inspection.

Install:

```bash
sudo apt install wireshark
```

Useful filters:

```text
ip.addr == 192.168.1.100
tcp.port == 22
dns
http
tls
icmp
```

### Network IDS Architecture

```text
             NETWORK
                 |
          ┌──────▼──────┐
          │ Monitoring  │
          │ Interface   │
          └──────┬──────┘
                 |
          ┌──────▼──────┐
          │ Suricata /  │
          │ Snort       │
          └──────┬──────┘
                 |
          ┌──────▼──────┐
          │ Alert Logs  │
          └──────┬──────┘
                 |
          ┌──────▼──────┐
          │ SIEM / SOC  │
          └─────────────┘
```

## Incident Response and Forensics

Incident response is the process of identifying, investigating, containing, and recovering from security incidents.

### Incident Response Phases

1. Preparation.
2. Identification.
3. Containment.
4. Eradication.
5. Recovery.
6. Lessons learned.

### Initial System Investigation

Collect basic system information:

```bash
date
hostname
uname -a
uptime
who
```

Inspect running processes:

```bash
ps auxf
```

Inspect network connections:

```bash
sudo ss -tulnp
```

Inspect recent logins:

```bash
last
```

Inspect mounted filesystems:

```bash
mount
df -h
```

### Evidence Preservation

Important forensic considerations:

- Record timestamps.
- Preserve original logs.
- Document investigative actions.
- Calculate file hashes.
- Maintain chain of custody.
- Avoid modifying evidence unnecessarily.

Calculate a SHA-256 hash:

```bash
sha256sum evidence.bin
```

### Disk Imaging

`dd` can create raw disk images. Use the correct source and destination devices, and ensure the evidence source is handled appropriately.

Example for an unmounted source device:

```bash
sudo dd if=/dev/sdX \
of=/mnt/evidence/disk-image.img \
bs=4M status=progress \
conv=noerror,sync
```

Verify the resulting image:

```bash
sha256sum /mnt/evidence/disk-image.img
```

For formal forensic acquisition, use appropriate write-blocking and evidence-handling procedures.

### Forensic Tools

| Tool | Purpose |
|---|---|
| Autopsy | Digital forensic analysis |
| The Sleuth Kit | Filesystem investigation |
| Volatility 3 | Memory forensics |
| Foremost | File carving |
| Binwalk | Firmware analysis |
| FTK Imager | Forensic acquisition |
| YARA | Pattern-based malware identification |

## Backup and Recovery

Backups are essential for restoring systems after hardware failures, ransomware, accidental deletion, and configuration errors.

### Important Backup Practices

- Maintain multiple backup copies.
- Keep an offline or isolated backup.
- Encrypt sensitive backups.
- Verify backup integrity.
- Perform regular restoration tests.
- Protect backup credentials.
- Document recovery procedures.

### rsync

Synchronize a directory:

```bash
rsync -avh /home/analyst/ /mnt/backup/analyst/
```

Use a dry run before performing changes:

```bash
rsync -avhn /home/analyst/ /mnt/backup/analyst/
```

### Backup Verification

```bash
sha256sum backup.tar.gz
```

Compare the resulting hash against a trusted recorded value.

## Monitoring and Alerting

Continuous monitoring helps identify unusual system behavior.

### Important Monitoring Categories

| Category | What to Monitor |
|---|---|
| Authentication | Failed and successful logins |
| Processes | Unexpected process execution |
| Network | Unusual connections and listening ports |
| Filesystem | Changes to critical files |
| Resources | CPU, RAM, and disk usage |
| Services | Unexpected service changes |
| Firewall | Dropped and unusual traffic |
| Privileges | Sudo and privilege changes |

### System Resource Monitoring

```bash
top
htop
free -h
df -h
iostat
```

Install additional utilities:

```bash
sudo apt install htop sysstat
```

### Process Monitoring

```bash
ps aux --sort=-%cpu | head
```

```bash
ps aux --sort=-%mem | head
```

### Service Monitoring

```bash
systemctl --failed
```

```bash
systemctl list-units --type=service
```

## Security Automation

Automation reduces repetitive administrative work and helps standardize security checks.

### Bash Security Inventory

```bash
#!/bin/bash

echo "===== SYSTEM INFORMATION ====="
date
hostname
uname -a

echo
echo "===== NETWORK INTERFACES ====="
ip addr

echo
echo "===== ROUTING TABLE ====="
ip route

echo
echo "===== LISTENING SERVICES ====="
sudo ss -tulnp

echo
echo "===== RUNNING PROCESSES ====="
ps aux

echo
echo "===== FAILED SERVICES ====="
systemctl --failed

echo
echo "===== RECENT LOGINS ====="
last -n 10

echo
echo "===== DISK USAGE ====="
df -h
```

Save as:

```text
security-inventory.sh
```

Make executable:

```bash
chmod +x security-inventory.sh
```

Execute:

```bash
./security-inventory.sh
```

This script provides basic system visibility and is not a replacement for a full security audit.

### Python Automation

Python can be used for:

- Log parsing.
- API integration.
- Firewall management.
- Alert generation.
- File integrity checks.
- Network monitoring.
- SIEM event processing.

Useful libraries:

| Library | Purpose |
|---|---|
| `subprocess` | Execute system utilities |
| `os` | Operating system interaction |
| `hashlib` | File hashing |
| `json` | Structured event handling |
| `socket` | Network communication |
| `logging` | Application logging |
| `requests` | HTTP API requests |

## Compliance and Auditing

Linux systems may need to comply with organizational and regulatory security requirements.

### Common Frameworks

- CIS Benchmarks.
- NIST Cybersecurity Framework.
- NIST SP 800-53.
- ISO 27001.
- PCI DSS.

### CIS Benchmark Areas

- Account management.
- Filesystem configuration.
- SSH configuration.
- Firewall settings.
- Logging.
- Kernel parameters.
- Network services.
- Access control.

### Security Auditing Tools

| Tool | Purpose |
|---|---|
| Lynis | Linux security auditing |
| OpenSCAP | Compliance assessment |
| CIS-CAT | CIS benchmark assessment |
| AIDE | File integrity monitoring |
| Auditd | System auditing |
| Wazuh | Security monitoring |

Install Lynis:

```bash
sudo apt install lynis
```

Run a system audit:

```bash
sudo lynis audit system
```

Review the findings and apply changes according to the system's requirements.

---

## Recommended Linux Security Lab

A small Linux lab can provide hands-on experience with firewall management, intrusion detection, log collection, and incident response.

### Example Architecture

```text
       HP LAPTOP
      Debian / Kali
           |
           | SSH / HTTPS
           |
      LOCAL NETWORK
           |
     ┌─────▼─────┐
     │ Raspberry │
     │ Pi 3 B    │
     │           │
     │ Debian 12 │
     ├───────────┤
     │ UFW       │
     │ SSH       │
     │ Python API│
     │ IDS       │
     │ Logs      │
     └───────────┘
```

### Suggested Components

| Component | Purpose |
|---|---|
| Raspberry Pi 3 B | Linux security server |
| UFW | Host firewall |
| SSH | Remote administration |
| Suricata or Snort | Network intrusion detection |
| Python | Automation and API development |
| SQLite | Local event storage |
| Wazuh | Security monitoring |
| tcpdump | Packet capture |
| AIDE | File integrity monitoring |

### Suggested Learning Projects

1. Configure a default-deny firewall.
2. Restrict SSH to a trusted LAN.
3. Build a Python-based security log parser.
4. Deploy Suricata and inspect IDS alerts.
5. Forward logs to a centralized server.
6. Monitor system changes using AIDE.
7. Build a dashboard for security events.
8. Test detection using controlled lab traffic.

## Resources

### Linux Documentation

- [Linux Manual Pages](https://man7.org/linux/man-pages/)
- [Debian Documentation](https://www.debian.org/doc/)
- [Arch Linux Security](https://wiki.archlinux.org/title/Security)
- [Ubuntu Security](https://ubuntu.com/security)

### Firewall Documentation

- [UFW](https://manpages.ubuntu.com/manpages/latest/en/man8/ufw.8.html)
- [iptables](https://netfilter.org/projects/iptables/)
- [nftables](https://netfilter.org/projects/nftables/)
- [firewalld](https://firewalld.org/documentation/)

### Security Tools

- [Wazuh](https://wazuh.com/)
- [Suricata](https://suricata.io/)
- [Snort](https://www.snort.org/)
- [AIDE](https://aide.github.io/)
- [Lynis](https://cisofy.com/lynis/)
- [Fail2ban](https://github.com/fail2ban/fail2ban)
- [Zeek](https://zeek.org/)

### Security Frameworks

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## Conclusion

Linux security administration requires a combination of secure configuration, access control, network protection, continuous monitoring, and incident response.

The most important principles are:

- Apply least privilege.
- Minimize exposed services.
- Configure firewalls carefully.
- Secure remote administration.
- Centralize and protect logs.
- Monitor system integrity.
- Keep software updated.
- Test backups and recovery procedures.
- Regularly audit security configurations.

**A secure Linux system is not achieved through one tool or configuration. It requires multiple layers of protection and continuous maintenance.**

---

*For educational purposes, authorized system administration, defensive security research, and laboratory testing.*
