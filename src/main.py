import os
import re
from urllib.parse import urlparse
try:
    from ml_detector import MLPhishingDetector
except ImportError:
    MLPhishingDetector = None

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def detect_obfuscation(email_content):
    score = 0
    findings = []
    # Check for zero-width spaces or other invisible character obfuscation commonly used to bypass scanners
    invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
    found_chars = [char for char in invisible_chars if char in email_content]
    if found_chars:
        score += 30
        findings.append("[bold red]?? Obfuscation:[/bold red] Invisible characters (e.g., zero-width spaces) found.")

    return score, findings

def analyze_urls(email_content):
    score = 0
    findings = []

    # Extract URLs
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)

    if not urls:
        return score, findings

    for url in urls:
        try:
            parsed = urlparse(url if url.startswith('http') else f"http://{url}")
            domain = parsed.netloc.lower()

            # 1. Suspicious IP Addresses
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                score += 40
                findings.append(f"[bold red]?? Suspicious URL:[/bold red] Uses IP instead of domain ([cyan]{url}[/cyan]).")
            
            # 2. URL Shorteners
            shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 'shorte.st']
            if any(shortener in domain for shortener in shorteners):
                score += 25
                findings.append(f"[bold yellow]?? Obfuscated URL:[/bold yellow] Uses shortener service ([cyan]{domain}[/cyan]).")
            
            # 3. Deep Subdomains
            if domain.count('.') > 3:
                score += 15
                findings.append(f"[bold yellow]?? Suspicious URL:[/bold yellow] High number of subdomains ([cyan]{domain}[/cyan]).")

        except Exception:
            pass

    return score, findings

def simple_scanner(email_content):
    score = 0
    findings = []

    # 1. Check for Social Engineering Keywords
    keywords = ['urgent', 'suspended', 'verify', 'login', 'bank', 'immediately', 'action required', 'account compromised', 'unauthorized access', 'validate your account']
    for word in keywords:
        if word in email_content.lower():
            score += 15
            findings.append(f"[bold yellow]?? Social Engineering:[/bold yellow] Threat keyword detected: '{word}'")
            
    # 2. Advanced Obfuscation Checks
    obf_score, obf_findings = detect_obfuscation(email_content)
    score += obf_score
    findings.extend(obf_findings)

    # 3. Advanced URL Analysis
    url_score, url_findings = analyze_urls(email_content)
    score += url_score
    findings.extend(url_findings)

    # 4. Check for typical phishing "Sense of Urgency"
    if "24 hours" in email_content or "limited time" in email_content:
        score += 20
        findings.append("[bold red]?? Urgency:[/bold red] Time-sensitive threat detected.")

    return score, findings

def run_project():
    console.print(Panel(Text("??? PhishGuard Enterprise: Command Line Interface ???", justify="center", style="bold cyan"), border_style="cyan"))

    # Path to your test data
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'sample_mail.txt')
    
    if not os.path.exists(data_path):
        console.print(f"[bold red]Error:[/bold red] Please create the file {data_path} first.")
        return

    with open(data_path, 'r', encoding='utf-8') as f:
        content = f.read()

    score = 0
    findings = []
    ml_verdict = "N/A"
    ml_prob = 0.0

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Running Heuristics Engine...", total=None)
        score, findings = simple_scanner(content)

    if MLPhishingDetector:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description="Loading ML Models...", total=None)
            ml_detector = MLPhishingDetector()
            
            if ml_detector.model_loaded:
                try:
                    prediction, ml_prob, _ = ml_detector.predict(content)
                    if prediction == 1:
                        ml_verdict = "[bold red]MALICIOUS PAYLOAD[/bold red]"
                        score += 50  
                        findings.append(f"[bold red]?? ML Engine:[/bold red] Content matches threat signatures (Conf: {ml_prob*100:.1f}%)")
                    elif prediction == 0:
                        ml_verdict = "[bold green]BENIGN COMMUNICATION[/bold green]"
                except Exception as e:
                    findings.append(f"[dim red]?? ML Engine Error:[/dim red] {e}")

    # Output Findings Table
    console.print(f"\n[bold blue]Scanning payload from:[/bold blue] [dim]{data_path}[/dim]")
    
    table = Table(show_header=True, header_style="bold magenta", border_style="magenta")
    table.add_column("Threat Indicator", style="dim")
    
    if findings:
        for finding in findings:
            table.add_row(finding)
    else:
        table.add_row("[bold green]? No suspicious indicators found in the scan.[/bold green]")
        
    console.print(table)

    # Final Risk Assessment Panel
    verdict_text = ""
    verdict_color = ""
    if score >= 50:
        verdict_text = f"CRITICAL RISK (Score: {score})"
        verdict_color = "red"
    elif score >= 20:
        verdict_text = f"MEDIUM RISK (Score: {score})"
        verdict_color = "yellow"
    else:
        verdict_text = f"LOW RISK (Score: {score})"
        verdict_color = "green"

    final_panel = f"""
[bold]Rule Engine Verdict:[/bold] [{verdict_color}]{verdict_text}[/{verdict_color}]
[bold]ML Engine Verdict:[/bold] {ml_verdict} ({ml_prob*100:.1f}%)
    """
    console.print(Panel(Text.from_markup(final_panel), title="[bold]Operation Summary[/bold]", border_style=verdict_color))

if __name__ == "__main__":
    run_project()
