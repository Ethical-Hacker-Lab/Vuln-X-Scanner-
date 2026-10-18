import subprocess
import requests
from urllib.parse import urlparse
import concurrent.futures
import socket
import datetime

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = f"http://{self.target_url}"
        
        self.parsed = urlparse(self.target_url)
        self.host = self.parsed.netloc
        self.port = self.parsed.port or (443 if self.parsed.scheme == 'https' else 80)
        self.findings = []
        
    def _run_command(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error executing command: {e}"

    def _add_finding(self, category, severity, title, description, evidence, recommendation):
        self.findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation
        })

    def check_security_headers(self):
        headers = {
            "Content-Security-Policy": "Protects against XSS and data injection attacks.",
            "X-Frame-Options": "Prevents clickjacking attacks.",
            "X-Content-Type-Options": "Prevents MIME type sniffing.",
            "Strict-Transport-Security": "Enforces HTTPS communication.",
            "Referrer-Policy": "Controls how much referrer information is sent with requests."
        }
        try:
            response = requests.get(self.target_url, timeout=10, allow_redirects=True)
            for header, desc in headers.items():
                if header not in response.headers:
                    self._add_finding("Security Headers", "Medium", f"Missing {header} Header", desc, f"Response from {self.target_url} did not include {header}.", f"Add the {header} header to your web server configuration.")
        except requests.exceptions.RequestException as e:
            self._add_finding("Network", "High", "Connection Failed", "Could not reach the target.", str(e), "Check the target URL and network connectivity.")

    def check_ssl_certificate(self):
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.datetime.now():
                        self._add_finding("SSL/TLS", "High", "Expired SSL Certificate", "The SSL certificate is expired.", f"Certificate expired on {cert['notAfter']}", "Renew the SSL certificate immediately.")
        except Exception as e:
            self._add_finding("SSL/TLS", "Low", "SSL Check Skipped", "Could not verify SSL details.", str(e), "Ensure the server is listening on the correct SSL port.")

    def run_nmap_scan(self):
        cmd = f"nmap -sV -sC --top 100 {self.host}"
        output = self._run_command(cmd)
        for line in output.splitlines():
            if "open" in line and "tcp" in line:
                parts = line.split()
                if len(parts) > 3:
                    port = parts[1].split('/')[0]
                    service = parts[3] if len(parts) > 3 else "Unknown"
                    if port not in ['80', '443', '22']:
                        self._add_finding("Port Scan", "Informational", f"Open Port: {port}/{service}", f"Port {port} is open and running {service}.", f"Nmap Output: {line}", f"Ensure that port {port} is intentionally exposed. If not, close it via firewall.")
        return output

    def run_whatweb(self):
        cmd = f"whatweb -a 3 {self.target_url}"
        output = self._run_command(cmd)
        if "Unknown" not in output:
            self._add_finding("Technology", "Informational", "Detected Technologies", "The following technologies were detected on the target website.", output, "Keep software up to date to avoid known vulnerabilities.")
        return output

    def run_nikto(self):
        cmd = f"nikto -h {self.target_url}"
        output = self._run_command(cmd)
        for line in output.splitlines():
            if " Nikto " in line:
                continue
            if "vulnerability" in line.lower() or "vulnerable" in line.lower():
                self._add_finding("Web Server", "Medium", "Potential Web Vulnerability", "Nikto detected a potential vulnerability on the web server.", line.strip(), "Review the Nikto finding and apply the recommended patch or configuration change.")
        return output

    def run_full_scan(self):
        print(f"\n[*] Initiating deep scan for {self.target_url}...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.check_security_headers): "Security Headers",
                executor.submit(self.check_ssl_certificate): "SSL Check",
                executor.submit(self.run_nmap_scan): "Nmap",
                executor.submit(self.run_whatweb): "WhatWeb",
                executor.submit(self.run_nikto): "Nikto"
            }
            for future in concurrent.futures.as_completed(futures):
                task_name = futures[future]
                try:
                    future.result()
                    print(f"[+] {task_name} module completed.")
                except Exception as e:
                    print(f"[-] {task_name} module failed: {e}")
        print(f"[*] Scan finished. Total findings: {len(self.findings)}")
        return self.findings
