import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from scanner import VulnerabilityScanner
from analyzer import Analyzer
from report_generator import ReportGenerator

console = Console()

def print_banner():
    banner = """
    
██║   ██║██║   ██║██║     ████╗  ██║    ╚██╗██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║     ╚███╔╝
╚██╗ ██╔╝╚██╗ ██╔╝██║     ██║╚██╗██║     ██╔██╗
 ╚████╔╝  ╚████╔╝ ███████╗██║ ╚████║    ██╔╝ ██╗
  ╚═══╝           ╚══════╝╚═╝  ╚═══╝    ╚═╝  ╚═╝

██╗  ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
╚██╗██╔╝     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ╚███╔╝      ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔██╗      ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██╔╝ ██╗     ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝     

    """
    console.print(Panel(Text(banner, style="bold magenta"), border_style="cyan", expand=False))
    console.print(Panel("[bold yellow]Developer: SHAYAN JAVAID[/bold yellow] | [bold green]Automated Website Vulnerability Scanner[/bold green]", border_style="blue", expand=False))

def get_user_input():
    console.print("\n[bold cyan]Enter the target website URL:[/bold cyan] (e.g., example.com)")
    url = input(">> ").strip()
    if not url:
        console.print("[red]Error: URL cannot be empty.[/red]")
        return get_user_input()
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    return url

def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    print_banner()
    
    while True:
        url = get_user_input()
        scanner = VulnerabilityScanner(url)
        findings = scanner.run_full_scan()
        analyzer = Analyzer(findings)
        analyzer.deduplicate()
        analyzer.sort_by_severity()
        summary = analyzer.get_summary()
        generator = ReportGenerator(url, analyzer.findings, summary)
        generator.generate_console_report()
        
        html_choice = input("\n[bold]Generate HTML report? (y/n): [/bold]").lower()
        if html_choice == 'y':
            generator.generate_html_report()
            
        scan_again = input("\n[bold]Scan another website? (y/n): [/bold]").lower()
        if scan_again != 'y':
            console.print("[bold red]Exiting VulnScanner. Goodbye![/bold red]")
            break

if __name__ == "__main__":
    main()
