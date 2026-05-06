import asyncio

import httpx
from rich.console import Console

from config import USER_AGENT

console = Console()

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql",
    "/graphql/v1", "/gql", "/query", "/api/query",
]

_INTROSPECTION_QUERY = {
    "query": (
        "{ __schema { queryType { name } mutationType { name } "
        "types { name kind fields { name } } } }"
    )
}


async def _probe_host(
    host: str, client: httpx.AsyncClient, timeout: int
) -> dict:
    result: dict = {
        "host": host,
        "detected": False,
        "introspection_enabled": False,
        "endpoints": [],
        "types": [],
        "mutations": [],
    }

    for path in GRAPHQL_PATHS:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}{path}"
            try:
                r = await client.post(
                    url,
                    json=_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                    timeout=timeout,
                )
                if r.status_code == 200:
                    data = r.json()
                    if "data" in data and "__schema" in data.get("data", {}):
                        result["detected"] = True
                        result["introspection_enabled"] = True
                        result["endpoints"].append(url)
                        schema = data["data"]["__schema"]
                        result["types"] = [
                            t["name"]
                            for t in schema.get("types", [])
                            if not t["name"].startswith("__")
                        ]
                        console.print(
                            f"  [bold red]GraphQL introspection OPEN:[/bold red] {url} "
                            f"[dim]({len(result['types'])} types)[/dim]"
                        )
                    elif "errors" in data:
                        result["detected"] = True
                        result["endpoints"].append(url)
                        console.print(
                            f"  [yellow]GraphQL (introspection off):[/yellow] {url}"
                        )
            except Exception:
                pass

    return result


async def probe_graphql(
    live_hosts: list[dict], timeout: int = 5, threads: int = 50
) -> list[dict]:
    semaphore = asyncio.Semaphore(threads)
    limits = httpx.Limits(
        max_connections=threads, max_keepalive_connections=threads // 2
    )

    async with httpx.AsyncClient(
        verify=False,
        limits=limits,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        async def probe_with_sem(h: dict) -> dict:
            async with semaphore:
                return await _probe_host(h["host"], client, timeout)

        return list(
            await asyncio.gather(*[probe_with_sem(h) for h in live_hosts])
        )
