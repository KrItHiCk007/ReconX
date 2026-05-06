import asyncio

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

from config import USER_AGENT
from modules.utils import status_str

console = Console()

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
    "Akamai": ["akamai", "x-akamai-transformed"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
    "Imperva": ["x-iinfo", "incap_ses"],
    "F5 BIG-IP": ["bigipserver", "f5_st"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
}

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-json", "wordpress"],
    "Laravel": ["laravel_session", "x-powered-by: php"],
    "Django": ["csrftoken", "x-frame-options: sameorigin"],
    "Rails": ["x-request-id", "_rails_session"],
    "Express": ["x-powered-by: express"],
    "ASP.NET": ["x-aspnet-version", "x-powered-by: asp.net"],
    "Nginx": ["server: nginx"],
    "Apache": ["server: apache"],
}


async def _fingerprint_host(
    host_info: dict, client: httpx.AsyncClient, timeout: int = 5
) -> dict:
    host = host_info["host"]
    result: dict = {
        "host": host,
        "status_code": None,
        "server": None,
        "tech_stack": [],
        "waf": None,
        "missing_security_headers": [],
        "cookies": [],
        "redirect_url": None,
        "raw_headers": {},
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        try:
            r = await client.get(url, timeout=timeout)
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            result["status_code"] = r.status_code
            result["server"] = r.headers.get("Server", "Unknown")
            result["raw_headers"] = dict(r.headers)
            result["redirect_url"] = str(r.url) if str(r.url) != url else None

            for waf_name, sigs in WAF_SIGNATURES.items():
                if any(s in str(headers_lower) for s in sigs):
                    result["waf"] = waf_name
                    break

            body_lower = r.text.lower()
            for tech, sigs in TECH_SIGNATURES.items():
                if any(s in str(headers_lower) or s in body_lower for s in sigs):
                    result["tech_stack"].append(tech)

            for header in SECURITY_HEADERS:
                if header.lower() not in headers_lower:
                    result["missing_security_headers"].append(header)

            result["cookies"] = [
                {"name": k, "value": v[:30]} for k, v in r.cookies.items()
            ]

            waf_str = (
                f"[magenta]{result['waf']}[/magenta]"
                if result["waf"]
                else "[dim]—[/dim]"
            )
            tech_str = (
                "[green]" + ", ".join(result["tech_stack"]) + "[/green]"
                if result["tech_stack"]
                else "[dim]—[/dim]"
            )
            console.print(
                f"  [bold]{host}[/bold] {status_str(result['status_code'])} "
                f"[dim]server:[/dim] {result['server']}  "
                f"[dim]waf:[/dim] {waf_str}  "
                f"[dim]tech:[/dim] {tech_str}"
            )
            break
        except Exception as e:
            console.print(f"[red]  {host} — {type(e).__name__}[/red]")
            continue

    return result


async def fingerprint_hosts(
    live_hosts: list[dict], timeout: int = 5, threads: int = 50
) -> list[dict]:
    semaphore = asyncio.Semaphore(threads)
    limits = httpx.Limits(
        max_connections=threads, max_keepalive_connections=threads // 2
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        limits=limits,
        headers={"User-Agent": USER_AGENT},
    ) as client:
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
                f"[cyan]Fingerprinting {len(live_hosts)} hosts...",
                total=len(live_hosts),
            )

            async def fp_and_track(h: dict) -> dict:
                async with semaphore:
                    result = await _fingerprint_host(h, client, timeout)
                progress.advance(task)
                return result

            return list(
                await asyncio.gather(*[fp_and_track(h) for h in live_hosts])
            )
