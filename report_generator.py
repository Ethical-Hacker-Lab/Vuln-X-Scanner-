import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class ReportGenerator:
    def __init__(self, target_url, findings, summary):
        self.target_url = target_url
        self.findings = findings
        self.summary = summary
        self.console = Console()

    def generate_console_report(self):
        self.console.print(Panel(f"[bold blue]Vulnerability Scan Report: {self.target_url}[/bold blue]", border_style="blue"))
        summary_table = Table(title="Scan Summary")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        for severity, count in self.summary.items():
            color = {"Critical": "red", "High": "yellow", "Medium": "green", "Low": "blue", "Informational": "white"}[severity]
            summary_table.add_row(severity, str(count), style=color)
        self.console.print(summary_table)

        findings_table = Table(title="Detailed Findings")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Category")
        findings_table.add_column("Title")
        findings_table.add_column("Recommendation")
        for finding in self.findings:
            color = {"Critical": "red", "High": "yellow", "Medium": "green", "Low": "blue", "Informational": "white"}[finding["severity"]]
            findings_table.add_row(finding["severity"], finding["category"], finding["title"], finding["recommendation"], style=color)
        self.console.print(findings_table)

    def generate_html_report(self, output_path="vulnerability_report.html"):
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Scan Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #2c3e50; color: white; }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #f39c12; font-weight: bold; }}
        .severity-medium {{ color: #27ae60; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Website Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> {self.target_url}</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <table>
            <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Recommendation</th></tr></thead>
            <tbody>
        """
        for finding in self.findings:
            html_content += f"<tr><td class='severity-{finding['severity'].lower()}'>{finding['severity']}</td><td>{finding['category']}</td><td>{finding['title']}</td><td>{finding['recommendation']}</td></tr>"
        html_content += "</tbody></table></div></body></html>"
        with open(output_path, 'w') as f:
            f.write(html_content)
        print(f"[+] HTML report generated: {os.path.abspath(output_path)}")
