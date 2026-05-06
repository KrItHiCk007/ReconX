import argparse
import asyncio
import sys
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from config import VERSION
from modules.subdomain import enumerate_subdomains
from modules.dns_resolver import resolve_domains
from modules.port_scanner import scan_ports
from modules.http_fingerprint import fingerprint_hosts
from modules.api_discovery import discover_api_endpoints
from modules.graphql_probe import probe_graphql
from modules.content_discovery import discover_content
from modules.summary import render_summary, export_json

console = Console()

BANNER = r"""
  ____                     __  __
 |  _ \ ___  ___ ___  _ __ \ \/ /
 | |_) / _ \/ __/ _ \| '_ \ \  /
 |  _ <  __/ (_| (_) | | | | /  \
 |_| \_\___|\___\___/|_| |_|/_/\_\
"""


def phase_header(num: str, name: str, start_time: float) -> None:
    elapsed = time.time() - start_time
    console.print()
    console.rule(
        f"[bold cyan] {num} [/bold cyan][dim]▸[/dim][bold] {name} [/bold]"
        f"[dim](+{elapsed:.1f}s)[/dim]"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="reconx",
        description=f"ReconX v{VERSION} — Web & API Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--threads", type=int, default=100, help="Concurrency (default: 100)")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout seconds (default: 5)")
    parser.add_argument(
        "--modules",
        nargs="+",
        default="all",
        help="Modules: subdomain dns ports http api graphql content (default: all)",
    )
    parser.add_argument("--output", "-o", help="Save results to JSON file")
    parser.add_argument("--no-brute", action="store_true", help="Skip subdomain brute force")
    parser.add_argument(
        "--max-subdomains",
        type=int,
        default=2000,
        help="Cap total subdomains before DNS phase (default: 2000, 0 = unlimited)",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    start_time = time.time()
    target = (
        args.target.strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
    )

    console.print(f"[bold cyan]{BANNER}[/bold cyan]", highlight=False)

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="dim")
    meta.add_column(style="bold white")
    meta.add_row("Version", f"v{VERSION}")
    meta.add_row("Target", f"[cyan]{target}[/cyan]")
    meta.add_row("Threads", str(args.threads))
    meta.add_row("Timeout", f"{args.timeout}s")
    meta.add_row("Brute force", "[dim]disabled[/dim]" if args.no_brute else "enabled")
    meta.add_row("Started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if args.output:
        meta.add_row("Output", args.output)

    console.print(
        Panel(meta, title="[bold cyan]ReconX[/bold cyan]", border_style="cyan", expand=False)
    )

    results: dict = {}
    max_subs = getattr(args, "max_subdomains", 2000)

    try:
        phase_header("01", "Subdomain Enumeration", start_time)
        subdomains = await enumerate_subdomains(
            target,
            threads=args.threads,
            no_brute=args.no_brute,
            max_subdomains=max_subs,
        )
        results["subdomains"] = subdomains

        phase_header("02", "DNS Resolution", start_time)
        live_hosts = await resolve_domains(subdomains, threads=args.threads)
        results["live_hosts"] = live_hosts

        if not live_hosts:
            console.print("[yellow]No live hosts — skipping remaining phases.[/yellow]")
        else:
            phase_header("03", "Port Scanning", start_time)
            ports = await scan_ports(live_hosts, timeout=args.timeout)
            results["open_ports"] = ports

            # Only pass hosts with at least one open web port to HTTP phases.
            # This drops SMTP/MX/NS/etc. hosts that will just timeout.
            ports_map = {p["host"]: p.get("open_ports", []) for p in ports}
            web_hosts = [h for h in live_hosts if ports_map.get(h["host"])]
            skipped = len(live_hosts) - len(web_hosts)
            if skipped:
                console.print(
                    f"[dim]  {skipped} host(s) with no open web ports — "
                    f"skipped for phases 4-7[/dim]"
                )

            phase_header("04", "HTTP Fingerprinting", start_time)
            fingerprints = await fingerprint_hosts(
                web_hosts, timeout=args.timeout, threads=args.threads
            )
            results["fingerprints"] = fingerprints

            phase_header("05", "API Endpoint Discovery", start_time)
            api_endpoints = await discover_api_endpoints(
                web_hosts, timeout=args.timeout, threads=args.threads
            )
            results["api_endpoints"] = api_endpoints

            phase_header("06", "GraphQL Detection", start_time)
            graphql = await probe_graphql(
                web_hosts, timeout=args.timeout, threads=args.threads
            )
            results["graphql"] = graphql

            phase_header("07", "Content Discovery", start_time)
            content = await discover_content(
                web_hosts, timeout=args.timeout, threads=args.threads
            )
            results["content"] = content

        total_time = time.time() - start_time
        console.print()
        console.rule(
            f"[bold green] COMPLETE [/bold green][dim]— {total_time:.1f}s total[/dim]"
        )
        render_summary(results, total_time=total_time)

        if args.output:
            export_json(results, args.output)
            console.print(f"\n[green]Results saved →[/green] {args.output}")

    except asyncio.CancelledError:
        _interrupted(results, start_time, args)


def _interrupted(results: dict, start_time: float, args: argparse.Namespace) -> None:
    elapsed = time.time() - start_time
    console.print(
        f"\n[bold yellow]Scan interrupted[/bold yellow] [dim]after {elapsed:.1f}s[/dim]"
    )
    if results:
        render_summary(results, total_time=elapsed)
        if getattr(args, "output", None):
            export_json(results, args.output)
            console.print(f"[green]Partial results saved →[/green] {args.output}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted.[/bold yellow]")
        sys.exit(0)
