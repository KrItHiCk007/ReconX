import asyncio

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

console = Console()

TOP_PORTS = [
    80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9000,
    9090, 9443, 4443, 7443, 6443, 10000, 8008, 8181, 8800, 3001,
]


async def _scan_port(host: str, port: int, timeout: int = 2) -> int | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


async def _scan_host(host_info: dict, timeout: int = 2) -> dict:
    host = host_info["host"]
    ip = host_info["ip"]
    results = await asyncio.gather(*[_scan_port(ip, p, timeout) for p in TOP_PORTS])
    open_ports = [p for p in results if p is not None]
    if open_ports:
        console.print(
            f"[cyan]  {host}[/cyan] [dim]({ip})[/dim] → {open_ports}"
        )
    return {"host": host, "ip": ip, "open_ports": open_ports}


async def scan_ports(live_hosts: list[dict], timeout: int = 2) -> list[dict]:
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {len(live_hosts)} hosts × {len(TOP_PORTS)} ports...",
            total=len(live_hosts),
        )

        async def scan_and_track(h: dict) -> dict:
            result = await _scan_host(h, timeout)
            progress.advance(task)
            return result

        return list(await asyncio.gather(*[scan_and_track(h) for h in live_hosts]))
