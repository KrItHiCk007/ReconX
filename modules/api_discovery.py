import asyncio
import re

import httpx
from rich.console import Console

from config import USER_AGENT
from modules.utils import status_str

console = Console()

API_WORDLIST = "wordlists/api_paths.txt"

SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/api-docs", "/api/docs", "/openapi.json", "/openapi.yaml",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/.well-known/openapi", "/redoc", "/api/swagger",
]

JS_ENDPOINT_REGEX = re.compile(
    r"[\"\'\`](/api/[a-zA-Z0-9/_\-{}]+|/v\d+/[a-zA-Z0-9/_\-{}]+)[\"\'\`]"
)

_FALLBACK_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
    "/api/users", "/api/user", "/api/admin", "/api/health",
    "/api/status", "/api/login", "/api/register", "/api/token", "/api/auth",
]


async def _check_swagger(
    host: str, client: httpx.AsyncClient, timeout: int
) -> list[str]:
    found: list[str] = []
    semaphore = asyncio.Semaphore(10)

    async def check(path: str) -> None:
        url = f"https://{host}{path}"
        async with semaphore:
            try:
                r = await client.get(url, follow_redirects=True, timeout=timeout)
                if r.status_code in [200, 301, 302]:
                    found.append(url)
                    console.print(
                        f"  [bold yellow]Swagger:[/bold yellow] {url} {status_str(r.status_code)}"
                    )
            except Exception:
                pass

    await asyncio.gather(*[check(p) for p in SWAGGER_PATHS])
    return found


async def _extract_js_endpoints(
    host: str, client: httpx.AsyncClient, timeout: int
) -> list[str]:
    endpoints: set[str] = set()
    try:
        r = await client.get(f"https://{host}", follow_redirects=True, timeout=timeout)
        js_files = re.findall(
            r"src=[\"\']([^\"\']+\.js(?:\?[^\"\']*)?)[\"\']", r.text
        )
        semaphore = asyncio.Semaphore(5)

        async def fetch_js(js_path: str) -> None:
            if not js_path.startswith("http"):
                js_path = f"https://{host}/{js_path.lstrip('/')}"
            async with semaphore:
                try:
                    jr = await client.get(js_path, timeout=timeout)
                    endpoints.update(JS_ENDPOINT_REGEX.findall(jr.text))
                except Exception:
                    pass

        await asyncio.gather(*[fetch_js(p) for p in js_files[:15]])
    except Exception:
        pass

    if endpoints:
        console.print(f"[cyan]  JS endpoints:[/cyan] {len(endpoints)} from {host}")
    return list(endpoints)


async def _fuzz_api_paths(
    host: str, client: httpx.AsyncClient, timeout: int, threads: int
) -> list[dict]:
    try:
        with open(API_WORDLIST) as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        paths = _FALLBACK_PATHS

    found: list[dict] = []
    semaphore = asyncio.Semaphore(threads)

    async def check_path(path: str) -> None:
        async with semaphore:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}{path}"
                try:
                    r = await client.get(url, follow_redirects=False, timeout=timeout)
                    if r.status_code not in [404, 400, 502, 503]:
                        found.append({
                            "endpoint": url,
                            "status": r.status_code,
                            "unauthenticated": r.status_code == 200,
                        })
                        console.print(f"  {status_str(r.status_code)} {url}")
                    break
                except Exception:
                    pass

    await asyncio.gather(*[check_path(p) for p in paths])
    return found


async def _discover_api_host(
    host_info: dict,
    client: httpx.AsyncClient,
    timeout: int,
    threads: int,
) -> tuple[str, dict]:
    host = host_info["host"]
    try:
        swagger, js_endpoints, fuzzed = await asyncio.gather(
            _check_swagger(host, client, timeout),
            _extract_js_endpoints(host, client, timeout),
            _fuzz_api_paths(host, client, timeout, threads),
        )
    except Exception as e:
        console.print(f"[yellow]  API error on {host}:[/yellow] {e}")
        swagger, js_endpoints, fuzzed = [], [], []

    total = len(swagger) + len(js_endpoints) + len(fuzzed)
    if total:
        console.print(
            f"[dim]  {host} →[/dim] swagger={len(swagger)} "
            f"js={len(js_endpoints)} fuzzed={len(fuzzed)}"
        )
    return host, {
        "swagger_docs": swagger,
        "js_extracted": js_endpoints,
        "fuzzed_endpoints": fuzzed,
    }


async def discover_api_endpoints(
    live_hosts: list[dict], timeout: int = 5, threads: int = 50
) -> dict:
    limits = httpx.Limits(
        max_connections=threads * 2, max_keepalive_connections=threads
    )
    async with httpx.AsyncClient(
        verify=False,
        limits=limits,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        pairs = await asyncio.gather(
            *[_discover_api_host(h, client, timeout, threads) for h in live_hosts]
        )
    return dict(pairs)
