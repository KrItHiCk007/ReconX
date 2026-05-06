def status_color(code: int) -> str:
    if 200 <= code < 300:
        return "bold green"
    if 300 <= code < 400:
        return "bold yellow"
    if 400 <= code < 500:
        return "dim white"
    if 500 <= code < 600:
        return "bold red"
    return "white"


def status_str(code: int) -> str:
    color = status_color(code)
    return f"[{color}]{code}[/{color}]"
