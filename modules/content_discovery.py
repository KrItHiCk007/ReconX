import asyncio

import httpx
from rich.console import Console

from config import USER_AGENT
from modules.utils import status_str

console = Console()

WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
    "/.well-known/change-password",
]

SENSITIVE_PATHS = [
    "/admin", "/administrator", "/admin/login", "/wp-admin", "/wp-login.php",
    "/login", "/signin", "/dashboard", "/phpinfo.php", "/.env", "/.git/config",
    "/debug", "/actuator", "/actuator/health", "/console", "/_profiler",
    "/telescope", "/config.json", "/settings.json", "/app.json",
    "/api/admin", "/api/debug", "/api/config",
]

_SENSITIVE_KEYWORDS = {"admin", "api", "debug", "config"}


async def _fetch_robots(
    host: str, client: httpx.AsyncClient, timeout: int
) -> dict:
    result: dict = {"disallowed": [], "sitemap_urls": []}
    for scheme in ["https", "http"]:
        try:
            r = await client.get(
                f"{scheme}://{host}/robots.txt", timeout=timeout
            )
            if r.status_code == 200:
                for line in r.text.splitlines():
                    low = line.lower()
                    if low.startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["disallowed"].append(path)
                            if any(k in path.lower() for k in _SENSITIVE_KEYWORDS):
                                console.print(
                                    f"[yellow]  robots.txt:[/yellow] {host}{path}"
                                )
                    elif low.startswith("sitemap:"):
                        result["sitemap_urls"].append(line.split(":", 1)[1].strip())
                break
        except Exception:
            pass
    return result


async def _check_sensitive_paths(
    host: str, client: httpx.AsyncClient, timeout: int, threads: int
) -> list[dict]:
    found: list[dict] = []
    semaphore = asyncio.Semaphore(threads)

    async def check(path: str) -> None:
        async with semaphore:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}{path}"
                try:
                    r = await client.get(url, follow_redirects=False, timeout=timeout)
                    if r.status_code not in [404, 410]:
                        found.append({"path": path, "url": url, "status": r.status_code})
                        console.print(f"  {status_str(r.status_code)} {url}")
                    break
                except Exception:
                    pass

    await asyncio.gather(*[check(p) for p in SENSITIVE_PATHS])
    return found


async def _check_well_known(
    host: str, client: httpx.AsyncClient, timeout: int
) -> list[dict]:
    found: list[dict] = []
    for path in WELL_KNOWN_PATHS:
        try:
            r = await client.get(f"https://{host}{path}", timeout=timeout)
            if r.status_code == 200:
                found.append({"path": path, "status": r.status_code})
                console.print(f"[cyan]  .well-known:[/cyan] {host}{path}")
        except Exception:
            pass
    return found


async def _discover_content_host(
    host_info: dict,
    client: httpx.AsyncClient,
    timeout: int,
    threads: int,
) -> tuple[str, dict]:
    host = host_info["host"]
    robots, sensitive, well_known = await asyncio.gather(
        _fetch_robots(host, client, timeout),
        _check_sensitive_paths(host, client, timeout, threads),
        _check_well_known(host, client, timeout),
    )
    return host, {
        "robots": robots,
        "sensitive_paths": sensitive,
        "well_known": well_known,
    }


async def discover_content(
    live_hosts: list[dict], timeout: int = 5, threads: int = 50
) -> dict:
    per_host_threads = max(10, threads // max(len(live_hosts), 1))
    limits = httpx.Limits(
        max_connections=threads * 2, max_keepalive_connections=threads
    )
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=False,
        limits=limits,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        pairs = await asyncio.gather(
            *[
                _discover_content_host(h, client, timeout, per_host_threads)
                for h in live_hosts
            ]
        )
    return dict(pairs)
