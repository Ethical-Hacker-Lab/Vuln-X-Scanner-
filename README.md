# 🛡️ VulnScanner: Automated Website Vulnerability Scanner

> **Developer:** Shayan Javid | **Organization:** Ethical-Hacker-Lab

An advanced, automated security assessment tool for web applications. Built with Python and Kali Linux, it orchestrates industry-standard security tools to provide a consolidated vulnerability report in seconds.

## 🌟 Features
- **Automated Orchestration**: Runs Nmap, Nikto, and WhatWeb concurrently for maximum speed.
- **Deep Analysis**: Checks for missing security headers, SSL certificate issues, and open ports.
- **Severity Classification**: Findings are automatically categorized (Critical, High, Medium, Low, Informational).
- **Professional Reporting**: Generates both rich terminal output and a detailed HTML report for sharing.

## 🛠️ Technology Stack
- **Language**: Python 3.10+
- **OS**: Kali Linux (Recommended)
- **Tools**: Nmap, Nikto, WhatWeb
- **Libraries**: `requests`, `rich`

## 📦 Installation

### 1. Clone the Repository
```bash
sudo apt update && upgrade -y
sudo apt install php -y
install python3
git clone https://github.com/Ethical-Hacker-Lab/VulnScanner.git
cd VulnScanner
python3 main.py
