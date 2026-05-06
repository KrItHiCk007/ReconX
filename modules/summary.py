import json
from datetime import datetime

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def _missing_badge(count: int) -> str:
    if count == 0:
        return "[green]0[/green]"
    if count <= 2:
        return f"[yellow]{count}[/yellow]"
    return f"[red]{count}[/red]"


def render_summary(results: dict, total_time: float = 0.0) -> None:
    console.print()

    # ── Live hosts ────────────────────────────────────────────────────────────
    hosts_table = Table(
        title="[bold cyan]Live Hosts[/bold cyan]",
        box=box.SIMPLE_HEAD,
        show_lines=False,
        header_style="bold cyan",
        border_style="dim",
        expand=False,
    )
    hosts_table.add_column("Host", style="cyan", no_wrap=True)
    hosts_table.add_column("IP", style="dim white")
    hosts_table.add_column("Open Ports", style="yellow")
    hosts_table.add_column("Server", style="white")
    hosts_table.add_column("WAF", style="magenta")
    hosts_table.add_column("Tech Stack", style="green")
    hosts_table.add_column("Miss. Headers", justify="right")

    fingerprints = {f["host"]: f for f in results.get("fingerprints", [])}
    ports_map = {p["host"]: p for p in results.get("open_ports", [])}

    for host_info in results.get("live_hosts", []):
        host = host_info["host"]
        fp = fingerprints.get(host, {})
        pt = ports_map.get(host, {})
        ports_str = " ".join(str(p) for p in pt.get("open_ports", [])) or "[dim]—[/dim]"
        hosts_table.add_row(
            host,
            host_info["ip"],
            ports_str,
            fp.get("server") or "[dim]?[/dim]",
            fp.get("waf") or "[dim]—[/dim]",
            ", ".join(fp.get("tech_stack", [])) or "[dim]—[/dim]",
            _missing_badge(len(fp.get("missing_security_headers", []))),
        )

    console.print(hosts_table)

    # ── API endpoints ─────────────────────────────────────────────────────────
    api_results = results.get("api_endpoints", {})
    if api_results:
        api_table = Table(
            title="[bold yellow]API Endpoints[/bold yellow]",
            box=box.SIMPLE_HEAD,
            show_lines=False,
            header_style="bold yellow",
            border_style="dim",
            expand=False,
        )
        api_table.add_column("Host", style="cyan", no_wrap=True)
        api_table.add_column("Swagger", justify="right")
        api_table.add_column("JS Extracted", justify="right")
        api_table.add_column("Fuzzed", justify="right")
        api_table.add_column("Unauthenticated", justify="right")

        for host, data in api_results.items():
            unauth = [e for e in data.get("fuzzed_endpoints", []) if e.get("unauthenticated")]
            sw = len(data.get("swagger_docs", []))
            js = len(data.get("js_extracted", []))
            fz = len(data.get("fuzzed_endpoints", []))
            api_table.add_row(
                host,
                f"[yellow]{sw}[/yellow]" if sw else "[dim]0[/dim]",
                str(js),
                str(fz),
                f"[bold red]{len(unauth)}[/bold red]" if unauth else "[green]0[/green]",
            )
        console.print(api_table)

    # ── GraphQL ───────────────────────────────────────────────────────────────
    graphql_results = results.get("graphql", [])
    gql_detected = [g for g in graphql_results if g.get("detected")]
    if gql_detected:
        gql_table = Table(
            title="[bold red]GraphQL Findings[/bold red]",
            box=box.SIMPLE_HEAD,
            show_lines=False,
            header_style="bold red",
            border_style="dim",
            expand=False,
        )
        gql_table.add_column("Host", style="cyan")
        gql_table.add_column("Introspection")
        gql_table.add_column("Types", justify="right")
        gql_table.add_column("Endpoint")
        for g in gql_detected:
            intro = (
                "[bold red]OPEN[/bold red]"
                if g["introspection_enabled"]
                else "[green]Disabled[/green]"
            )
            gql_table.add_row(
                g["host"],
                intro,
                str(len(g.get("types", []))),
                g.get("endpoints", [""])[0],
            )
        console.print(gql_table)

    # ── Critical findings ─────────────────────────────────────────────────────
    critical: list[str] = []
    for host, data in results.get("content", {}).items():
        for item in data.get("sensitive_paths", []):
            if item["status"] == 200:
                critical.append(f"[bold red]EXPOSED [/bold red] {item['url']}")

    for g in graphql_results:
        if g.get("introspection_enabled"):
            critical.append(
                f"[bold red]GRAPHQL [/bold red] {g['host']} — introspection open"
            )

    for host, data in api_results.items():
        for ep in data.get("fuzzed_endpoints", []):
            if ep.get("unauthenticated"):
                critical.append(
                    f"[bold yellow]UNAUTH  [/bold yellow] {ep['endpoint']}"
                )

    if critical:
        console.print(
            Panel(
                "\n".join(critical),
                title="[bold red]Critical Findings[/bold red]",
                border_style="red",
                expand=False,
            )
        )

    # ── Stats ─────────────────────────────────────────────────────────────────
    total_api = sum(
        len(v.get("swagger_docs", []))
        + len(v.get("js_extracted", []))
        + len(v.get("fuzzed_endpoints", []))
        for v in api_results.values()
    )
    total_ports = sum(
        len(p.get("open_ports", [])) for p in results.get("open_ports", [])
    )

    stats = Table.grid(padding=(0, 3))
    stats.add_column(style="dim")
    stats.add_column(style="bold white", justify="right")
    stats.add_row("Subdomains", str(len(results.get("subdomains", []))))
    stats.add_row("Live hosts", str(len(results.get("live_hosts", []))))
    stats.add_row("Open ports", str(total_ports))
    stats.add_row("API endpoints", str(total_api))
    stats.add_row(
        "Critical findings",
        f"[red]{len(critical)}[/red]" if critical else "[green]0[/green]",
    )
    if total_time:
        stats.add_row("Total time", f"{total_time:.1f}s")

    console.print(
        Panel(
            stats,
            title="[bold green]Scan Complete[/bold green]",
            border_style="green",
            expand=False,
        )
    )


def export_json(results: dict, path: str) -> None:
    def _serialize(obj):
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)

    output = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "results": {k: _serialize(v) for k, v in results.items()},
    }
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
