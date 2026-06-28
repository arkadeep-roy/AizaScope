from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from typing import Iterable

from .models import AUTHOR, TOOL_NAME, VERSION

try:  # Rich is installed by pip install -e .; fallback keeps python -m usable from source.
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except Exception:  # pragma: no cover - exercised only when dependency is missing.
    Console = None  # type: ignore[assignment]
    Panel = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]

BANNER_LINES = [
    " █████╗ ██╗███████╗ █████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗",
    "██╔══██╗██║╚══███╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝",
    "███████║██║  ███╔╝ ███████║███████╗██║     ██║   ██║██████╔╝█████╗  ",
    "██╔══██║██║ ███╔╝  ██╔══██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  ",
    "██║  ██║██║███████╗██║  ██║███████║╚██████╗╚██████╔╝██║     ███████╗",
    "╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝",
]

COMPACT_BANNER = "AizaScope"
BANNER_STYLES = [
    "bold bright_cyan",
    "bold cyan",
    "bold blue",
    "bold bright_blue",
    "bold magenta",
    "dim white",
]


def rich_available() -> bool:
    return Console is not None


def _terminal_width(default: int = 100) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default


def print_missing_rich_hint() -> None:
    print(
        "[!] Optional terminal dependency 'rich' is not installed.\n"
        "    Install AizaScope properly with:\n"
        "      python -m pip install -e .\n"
        "    Or install just the missing dependency with:\n"
        "      python -m pip install rich\n",
        file=sys.stderr,
    )


def print_banner(*, silent: bool = False, jsonl_stdout: bool = False) -> None:
    if silent or jsonl_stdout:
        return
    if Console is None:
        print_missing_rich_hint()
        print(f"{TOOL_NAME} v{VERSION}")
        print(f"Made by {AUTHOR}")
        print("Google / Firebase API Key Exploitability Triage")
        print()
        return

    console = Console(color_system="auto", highlight=False)
    console.print()
    if _terminal_width() >= 86:
        for line, style in zip(BANNER_LINES, BANNER_STYLES):
            console.print(line, style=style)
    else:
        console.print(COMPACT_BANNER, style="bold bright_cyan")
    console.print()
    console.print("Google / Firebase API Key Exploitability Triage", style="bold white")
    console.print(f"Made by {AUTHOR}", style="bold bright_green")
    console.print(f"v{VERSION}", style="dim white")
    console.print()


def print_run_plan(*, mode: str, keys_count: int, concurrency: int, output: str, silent: bool = False, jsonl_stdout: bool = False) -> None:
    if silent or jsonl_stdout:
        return
    modules = "Firebase  Firestore  RTDB  Storage  Gemini  YouTube  Maps  Cloud AI  Safe Browsing"
    if Console is None:
        print("Run plan")
        print("========")
        print(f"Mode:        {mode}")
        print(f"Keys:        {keys_count}")
        print(f"Concurrency: {concurrency}")
        print(f"Output:      {output}")
        print(f"Modules:     {modules}")
        print()
        return
    console = Console(color_system="auto", highlight=False)
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column(style="white")
    table.add_row("Mode", mode)
    table.add_row("Keys", str(keys_count))
    table.add_row("Concurrency", str(concurrency))
    table.add_row("Output", output)
    table.add_row("Modules", modules)
    console.print(Panel(table, title="Run plan", border_style="cyan", expand=False))
    console.print()


def print_dependency_warning(message: str) -> None:
    if Console is None:
        print(f"[!] {message}", file=sys.stderr)
        return
    Console(stderr=True).print(f"[bold yellow][!][/bold yellow] {message}")
