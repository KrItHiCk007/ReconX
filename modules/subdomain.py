import asyncio
import json
import shutil
from collections import Counter

import dns.resolver
import httpx
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

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
WORDLIST_PATH = "wordlists/subdomains.txt"


async def fetch_crtsh(domain: str) -> list[str]:
    url = CRTSH_URL.format(domain=f"%.{domain}")
    subdomains: set[str] = set()

    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=20, headers={"User-Agent": "ReconX/2.0"}) as client:
                r = await client.get(url)
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except json.JSONDecodeError:
                        data = json.loads(r.text)
                    for entry in data:
                        for sub in entry.get("name_value", "").splitlines():
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(domain):
                                subdomains.add(sub)
                    break
                if r.status_code in [429, 502, 503, 504]:
                    await asyncio.sleep(1 + attempt)
                else:
                    break
        except Exception as e:
            if attempt == 2:
                console.print(f"[red]  crt.sh error: {e}[/red]")
            await asyncio.sleep(1 + attempt)

    console.print(f"[green]  crt.sh[/green] → {len(subdomains)} subdomains")
    return list(subdomains)


async def brute_force_subdomains(domain: str, threads: int = 100) -> list[str]:
    try:
        with open(WORDLIST_PATH) as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[yellow]  Wordlist not found: {WORDLIST_PATH}[/yellow]")
        return []

    found: list[str] = []
    semaphore = asyncio.Semaphore(threads)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
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
        task = progress.add_task(f"[cyan]DNS brute force ({len(words)} words)...", total=len(words))

        async def check(word: str) -> None:
            subdomain = f"{word}.{domain}"
            async with semaphore:
                try:
                    await loop.run_in_executor(
                        None, lambda: resolver.resolve(subdomain, "A")
                    )
                    found.append(subdomain)
                    console.print(f"[cyan]  Found:[/cyan] {subdomain}")
                except Exception:
                    pass
                finally:
                    progress.advance(task)

        await asyncio.gather(*[check(w) for w in words])

    console.print(f"[green]  Brute force[/green] → {len(found)} subdomains")
    return found


def normalize_subdomain(name: str, domain: str) -> str | None:
    name = name.strip().lower().lstrip("*.")
    if not name or not name.endswith(domain):
        return None
    return name


async def run_external_tool(
    tool: str, args: list[str], domain: str, timeout: int = 90
) -> list[str]:
    if not shutil.which(tool):
        console.print(f"[dim]  {tool} not in PATH — skipped[/dim]")
        return []

    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            console.print(f"[yellow]  {tool} timed out after {timeout}s[/yellow]")
            return []

        if proc.returncode != 0 and stderr:
            snippet = stderr.decode(errors="ignore").strip()[:100]
            console.print(f"[yellow]  {tool} stderr:[/yellow] {snippet}")
            return []
        subs = [
            normalize_subdomain(line, domain)
            for line in stdout.decode(errors="ignore").splitlines()
        ]
        subs = [s for s in subs if s]
        console.print(f"[green]  {tool}[/green] → {len(subs)} subdomains")
        return subs
    except asyncio.CancelledError:
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                pass
        raise
    except Exception as e:
        console.print(f"[yellow]  {tool} error:[/yellow] {e}")
        return []


async def enumerate_external_tools(domain: str) -> list[str]:
    tools = [
        ("subfinder", ["subfinder", "-silent", "-d", domain]),
        ("findomain", ["findomain", "-t", domain, "-q"]),
        ("assetfinder", ["assetfinder", "--subs-only", domain]),
    ]
    results = await asyncio.gather(
        *[run_external_tool(name, cmd, domain) for name, cmd in tools]
    )
    return [sub for group in results for sub in group]


def _print_top_prefixes(subdomains: list[str], domain: str) -> None:
    prefixes = [
        sub.replace(f".{domain}", "").split(".", 1)[0]
        for sub in subdomains
        if sub != domain
    ]
    counts = Counter(prefixes)
    if counts:
        top = "  ".join(
            f"[cyan]{k}[/cyan][dim]({v})[/dim]" for k, v in counts.most_common(5)
        )
        console.print(f"[dim]  Top prefixes:[/dim] {top}")


async def enumerate_subdomains(
    domain: str,
    threads: int = 100,
    no_brute: bool = False,
    max_subdomains: int = 2000,
) -> list[str]:
    if no_brute:
        passive, external = await asyncio.gather(
            fetch_crtsh(domain),
            enumerate_external_tools(domain),
        )
        active: list[str] = []
    else:
        passive, active, external = await asyncio.gather(
            fetch_crtsh(domain),
            brute_force_subdomains(domain, threads=threads),
            enumerate_external_tools(domain),
        )

    all_names = passive + active + external + [domain]
    all_subs = list({n for raw in all_names if (n := normalize_subdomain(raw, domain))})

    if max_subdomains and len(all_subs) > max_subdomains:
        console.print(
            f"[yellow]  Capping {len(all_subs)} → {max_subdomains} subdomains "
            f"(use --max-subdomains 0 to disable)[/yellow]"
        )
        all_subs = all_subs[:max_subdomains]

    console.print(f"[bold green]  Total unique subdomains:[/bold green] {len(all_subs)}")
    _print_top_prefixes(all_subs, domain)
    return all_subs
