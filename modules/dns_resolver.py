import asyncio

import dns.resolver
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


async def _resolve_single(
    domain: str,
    semaphore: asyncio.Semaphore,
    loop: asyncio.AbstractEventLoop,
) -> dict | None:
    async with semaphore:
        try:
            result = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(domain, "A")
            )
            return {"host": domain, "ip": str(result[0])}
        except Exception:
            return None


async def resolve_domains(subdomains: list[str], threads: int = 100) -> list[dict]:
    semaphore = asyncio.Semaphore(threads)
    loop = asyncio.get_event_loop()

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
            f"[cyan]Resolving {len(subdomains)} hosts...", total=len(subdomains)
        )

        async def resolve_and_track(domain: str) -> dict | None:
            result = await _resolve_single(domain, semaphore, loop)
            progress.advance(task)
            if result:
                console.print(
                    f"[green]  {result['host']}[/green] [dim]→[/dim] {result['ip']}"
                )
            return result

        results = await asyncio.gather(*[resolve_and_track(s) for s in subdomains])

    live = [r for r in results if r is not None]
    console.print(
        f"[bold green]  Live hosts:[/bold green] {len(live)} / {len(subdomains)}"
    )
    return live
