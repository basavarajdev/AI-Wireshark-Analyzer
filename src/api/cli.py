"""
Command-Line Interface for AI-Wireshark-Analyzer
"""

import click
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich import print as rprint
import yaml
from loguru import logger

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.parsers.packet_parser import PacketParser
from src.preprocessing.cleaning import DataCleaner
from src.preprocessing.feature_engineering import FeatureEngineer
from src.core.model import IsolationForestModel, AutoencoderModel
from src.evaluation.visualization import NetworkVisualizer
from src.protocols.tcp_analyzer import TCPAnalyzer
from src.protocols.udp_analyzer import UDPAnalyzer
from src.protocols.dns_analyzer import DNSAnalyzer
from src.protocols.http_analyzer import HTTPAnalyzer
from src.protocols.https_analyzer import HTTPSAnalyzer
from src.protocols.icmp_analyzer import ICMPAnalyzer
from src.protocols.wlan_analyzer import WLANAnalyzer
from src.protocols.dhcp_analyzer import DHCPAnalyzer


console = Console()


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """AI-Wireshark-Analyzer - ML-powered network traffic analysis"""
    pass


@cli.command()
@click.option('--input', '-i', required=True, help='Input PCAP file')
@click.option('--protocol', '-p', type=click.Choice(['tcp', 'udp', 'dns', 'http', 'https', 'icmp', 'dhcp', 'all']),
              default='all', help='Protocol to analyze')
@click.option('--filter', '-f', 'display_filter', default=None,
              help='Wireshark display filter for IP-based filtering (e.g. "ip.addr==192.168.1.1", "ip.src==10.0.0.1", "ip.dst==10.0.0.2")')
@click.option('--visualize', '-v', is_flag=True, help='Generate visualizations')
@click.option('--output-dir', default='results', help='Output directory for results')
def analyze(input, protocol, display_filter, visualize, output_dir):
    """Analyze PCAP file"""
    console.print(f"[bold blue]Analyzing PCAP file:[/bold blue] {input}")
    
    if display_filter:
        console.print(f"[bold blue]Display filter:[/bold blue] {display_filter}")
    
    if not Path(input).exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {input}")
        return
    
    # Parse PCAP
    with console.status("[bold green]Parsing PCAP file..."):
        parser = PacketParser()
        df = parser.parse_pcap(input)
    
    if df.empty:
        console.print("[bold red]No packets found in PCAP file[/bold red]")
        return
    
    console.print(f"[green]✓[/green] Parsed {len(df)} packets")
    
    # Clean data
    with console.status("[bold green]Cleaning data..."):
        cleaner = DataCleaner()
        df = cleaner.clean(df)
    
    console.print(f"[green]✓[/green] Cleaned data: {len(df)} packets")
    
    # Basic statistics
    results = {
        "file": input,
        "total_packets": len(df),
        "protocols": df['protocol'].value_counts().to_dict() if 'protocol' in df.columns else {}
    }
    
    # Protocol-specific analysis
    if protocol != 'all':
        console.print(f"\n[bold cyan]Running {protocol.upper()} analysis...[/bold cyan]")
        results['protocol_analysis'] = _run_protocol_analysis(input, protocol, display_filter)
    else:
        console.print("\n[bold cyan]Running analysis for all protocols...[/bold cyan]")
        results['protocol_analysis'] = {}
        
        for proto in ['tcp', 'udp', 'dns', 'http', 'https', 'icmp', 'dhcp']:
            try:
                proto_results = _run_protocol_analysis(input, proto, display_filter)
                if 'error' not in proto_results:
                    results['protocol_analysis'][proto] = proto_results
            except Exception as e:
                logger.warning(f"Error analyzing {proto}: {e}")
    
    # Display critical issues
    _display_critical_issues(results)
    
    # Visualizations
    if visualize:
        console.print("\n[bold cyan]Generating visualizations...[/bold cyan]")
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        viz = NetworkVisualizer()
        viz.create_analysis_report(df, str(output_path))
        console.print(f"[green]✓[/green] Visualizations saved to {output_path}")
    
    # Auto-generate output paths from the pcap filename
    import re
    pcap_stem = Path(input).stem
    _suffix_parts = []
    if protocol != 'all':
        _suffix_parts.append(protocol)
    if display_filter:
        _suffix_parts.append(re.sub(r'[^a-zA-Z0-9]', '_', display_filter)[:40])
    if _suffix_parts:
        pcap_stem = f"{pcap_stem}_{'_'.join(_suffix_parts)}"
    output = str(Path(output_dir) / f"{pcap_stem}.json")
    html_report = str(Path(output_dir) / f"{pcap_stem}_report.html")

    # Save results
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, 'w') as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[green]✓[/green] Results saved to {output}")
    
    # Generate HTML report
    try:
        from src.reports.html_generator import HTMLReportGenerator
        console.print("\n[bold cyan]Generating HTML report...[/bold cyan]")
        generator = HTMLReportGenerator()
        report_path = generator.generate_report(
            results=results,
            pcap_file=input,
            output_file=html_report,
            protocol=protocol.upper()
        )
        console.print(f"[green]✓[/green] HTML Report: {report_path}")
        console.print(f"[blue]→[/blue] Open in browser: file://{Path(report_path).absolute()}")
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        console.print(f"[red]✗[/red] HTML report generation failed: {e}")


def _run_protocol_analysis(pcap_file: str, protocol: str, display_filter: str = None):
    """Run protocol-specific analysis"""
    analyzers = {
        'tcp': TCPAnalyzer,
        'udp': UDPAnalyzer,
        'dns': DNSAnalyzer,
        'http': HTTPAnalyzer,
        'https': HTTPSAnalyzer,
        'icmp': ICMPAnalyzer,
        'dhcp': DHCPAnalyzer,
    }
    
    if protocol in analyzers:
        analyzer = analyzers[protocol]()
        return analyzer.analyze(pcap_file, display_filter=display_filter)
    
    return {"error": f"Unsupported protocol: {protocol}"}


def _display_critical_issues(results):
    """Display critical issues in a table"""
    console.print("\n[bold yellow]Critical Issues Detected:[/bold yellow]")
    
    if 'protocol_analysis' not in results:
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Protocol", style="cyan")
    table.add_column("Issue Type", style="yellow")
    table.add_column("Severity", style="red")
    table.add_column("Details")
    
    issue_count = 0
    
    for protocol, analysis in results.get('protocol_analysis', {}).items():
        if not isinstance(analysis, dict):
            continue
        if 'threats' in analysis:
            for threat_name, threat_data in analysis['threats'].items():
                if not isinstance(threat_data, dict):
                    continue
                severity = threat_data.get('severity', 'unknown').upper()
                message = threat_data.get('message', 'No details')
                
                # Color based on severity
                severity_color = {
                    'CRITICAL': '[bold red]',
                    'HIGH': '[red]',
                    'MEDIUM': '[yellow]',
                    'LOW': '[green]'
                }.get(severity, '')
                
                table.add_row(
                    protocol.upper(),
                    threat_name.replace('_', ' ').title(),
                    f"{severity_color}{severity}[/]",
                    message
                )
                issue_count += 1
    
    if issue_count > 0:
        console.print(table)
        console.print(f"\n[bold red]Total critical issues found: {issue_count}[/bold red]")
    else:
        console.print("[green]No critical issues detected[/green]")


@cli.command('analyze-wlan')
@click.option('--input', '-i', required=True, help='Input PCAP file (WiFi capture)')
@click.option('--filter', '-f', 'display_filter', default=None,
              help='Wireshark display filter for WLAN filtering (e.g. "wlan.addr==aa:bb:cc:dd:ee:ff", "wlan.sa==aa:bb:cc:dd:ee:ff", "wlan.da==aa:bb:cc:dd:ee:ff")')
def analyze_wlan(input, display_filter):
    """Analyze WLAN/WiFi traffic (separate report)"""
    console.print(f"[bold blue]Analyzing WLAN/WiFi traffic:[/bold blue] {input}")

    if display_filter:
        console.print(f"[bold blue]Display filter:[/bold blue] {display_filter}")

    if not Path(input).exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {input}")
        return

    with console.status("[bold green]Parsing WLAN frames..."):
        analyzer = WLANAnalyzer()
        results = analyzer.analyze(input, display_filter=display_filter)

    if 'error' in results:
        console.print(f"[bold red]{results['error']}[/bold red]")
        return

    console.print(f"[green]✓[/green] Analyzed {results.get('total_packets', 0):,} WLAN frames")

    # Display summary
    stats = results.get('statistics', {})
    console.print(f"\n[bold cyan]WLAN Summary[/bold cyan]")
    console.print(f"  Management frames: {stats.get('management_frames', 0):,}")
    console.print(f"  Control frames:    {stats.get('control_frames', 0):,}")
    console.print(f"  Data frames:       {stats.get('data_frames', 0):,}")
    console.print(f"  Unique BSSIDs:     {stats.get('unique_bssids', 0)}")
    console.print(f"  Unique SSIDs:      {stats.get('unique_ssids', 0)}")
    if 'signal_mean_dbm' in stats:
        console.print(f"  Signal strength:   {stats['signal_min_dbm']} to {stats['signal_max_dbm']} dBm (avg {stats['signal_mean_dbm']})")

    # Display threats
    threats = results.get('threats', {})
    if threats:
        console.print(f"\n[bold yellow]WLAN Threats Detected:[/bold yellow]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Threat", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Details")

        for name, data in threats.items():
            sev = data.get('severity', 'info').upper()
            sev_color = {'CRITICAL': '[bold red]', 'HIGH': '[red]', 'MEDIUM': '[yellow]'}.get(sev, '')
            table.add_row(
                name.replace('_', ' ').title(),
                f"{sev_color}{sev}[/]",
                data.get('message', '')
            )

        console.print(table)
        console.print(f"\n[bold red]Total WLAN threats: {len(threats)}[/bold red]")
    else:
        console.print("\n[green]No WLAN threats detected[/green]")

    # Build full results structure for report/output
    full_results = {
        'file': input,
        'total_packets': results.get('total_packets', 0),
        'protocol_analysis': {'wlan': results},
    }

    # Auto-generate output paths from the pcap filename
    pcap_stem = Path(input).stem
    if display_filter:
        # Create a slug from the filter for unique filenames
        import re
        filter_slug = re.sub(r'[^a-zA-Z0-9]', '_', display_filter)[:40]
        pcap_stem = f"{pcap_stem}_{filter_slug}"
    output = f"results/{pcap_stem}.json"
    html_report = f"results/{pcap_stem}_report.html"

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, 'w') as f:
        json.dump(full_results, f, indent=2)
    console.print(f"\n[green]✓[/green] Results saved to {output}")

    try:
        from src.reports.html_generator import HTMLReportGenerator
        console.print("\n[bold cyan]Generating WLAN HTML report...[/bold cyan]")
        generator = HTMLReportGenerator()
        report_path = generator.generate_report(
            results=full_results,
            pcap_file=input,
            output_file=html_report,
            protocol="WLAN/WiFi"
        )
        console.print(f"[green]✓[/green] WLAN HTML Report: {report_path}")
        console.print(f"[blue]→[/blue] Open in browser: file://{Path(report_path).absolute()}")
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        console.print(f"[red]✗[/red] HTML report generation failed: {e}")


@cli.command()
@click.option('--input', '-i', required=True, help='Input PCAP file')
@click.option('--model', '-m', type=click.Choice(['isolation_forest', 'autoencoder']),
              default='isolation_forest', help='Model type')
@click.option('--output', '-o', help='Output JSON file')
def detect_anomalies(input, model, output):
    """Detect network anomalies"""
    console.print(f"[bold blue]Detecting anomalies in:[/bold blue] {input}")
    console.print(f"[bold]Model:[/bold] {model}")
    
    if not Path(input).exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {input}")
        return
    
    # Parse and process
    with console.status("[bold green]Processing PCAP file..."):
        parser = PacketParser()
        df = parser.parse_pcap(input)
        
        cleaner = DataCleaner()
        df = cleaner.clean(df)
        
        engineer = FeatureEngineer()
        df_features = engineer.engineer_features(df)
        X = engineer.get_ml_features(df_features)
    
    console.print(f"[green]✓[/green] Processed {len(X)} samples with {len(X.columns)} features")
    
    # Load or create model
    with console.status(f"[bold green]Loading {model} model..."):
        if model == 'isolation_forest':
            detector = IsolationForestModel()
            model_path = Path("models/isolation_forest.pkl")
            
            if model_path.exists():
                detector.load(str(model_path))
            else:
                console.print("[yellow]Training new model...[/yellow]")
                detector.train(X)
        else:
            detector = AutoencoderModel()
            model_path = Path("models/autoencoder.h5")
            
            if model_path.exists():
                detector.load(str(model_path))
            else:
                console.print("[yellow]Training new model...[/yellow]")
                detector.train(X)
    
    # Detect anomalies
    with console.status("[bold green]Detecting anomalies..."):
        predictions = detector.predict(X)
        scores = detector.score_samples(X)
    
    # Results
    anomaly_count = (predictions == -1).sum()
    anomaly_rate = anomaly_count / len(predictions)
    
    results = {
        "file": input,
        "model": model,
        "total_packets": len(predictions),
        "anomalies_detected": int(anomaly_count),
        "anomaly_rate": float(anomaly_rate),
        "score_statistics": {
            "min": float(scores.min()),
            "max": float(scores.max()),
            "mean": float(scores.mean()),
            "std": float(scores.std())
        }
    }
    
    # Display results
    console.print("\n[bold cyan]Anomaly Detection Results:[/bold cyan]")
    console.print(f"Total Packets: {results['total_packets']}")
    console.print(f"Anomalies Detected: [bold red]{results['anomalies_detected']}[/bold red]")
    console.print(f"Anomaly Rate: [bold yellow]{results['anomaly_rate']:.2%}[/bold yellow]")
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[green]✓[/green] Results saved to {output}")


@cli.command()
@click.option('--input', '-i', required=True, help='Input PCAP file')
@click.option('--output-dir', '-o', default='results/visualizations', help='Output directory')
def visualize(input, output_dir):
    """Generate visualizations from PCAP file"""
    console.print(f"[bold blue]Generating visualizations for:[/bold blue] {input}")
    
    if not Path(input).exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {input}")
        return
    
    # Parse PCAP
    with console.status("[bold green]Parsing PCAP file..."):
        parser = PacketParser()
        df = parser.parse_pcap(input)
        
        cleaner = DataCleaner()
        df = cleaner.clean(df)
    
    # Generate visualizations
    with console.status("[bold green]Creating visualizations..."):
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        viz = NetworkVisualizer()
        viz.create_analysis_report(df, str(output_path))
    
    console.print(f"[green]✓[/green] Visualizations saved to {output_path}")


@cli.command()
def info():
    """Display system information"""
    console.print("[bold cyan]AI-Wireshark-Analyzer[/bold cyan]")
    console.print("Version: 1.0.0")
    console.print("\n[bold]Supported Protocols:[/bold]")
    for protocol in ['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS', 'ICMP']:
        console.print(f"  • {protocol}")
    
    console.print("\n[bold]Available Models:[/bold]")
    console.print("  • Isolation Forest (anomaly detection)")
    console.print("  • Autoencoder (deep learning anomaly detection)")
    console.print("  • Random Forest (attack classification)")


def main():
    """Main entry point"""
    cli()


if __name__ == '__main__':
    main()
