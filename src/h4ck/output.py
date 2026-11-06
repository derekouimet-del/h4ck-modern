"""Output formatting: console (Rich) and JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.table import Table


@dataclass
class Finding:
    category: str
    target: str
    detail: str
    port: int | None = None
    status: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "target": self.target,
            "detail": self.detail,
            "port": self.port,
            "status": self.status,
            "extra": self.extra,
        }


class Reporter:
    def __init__(self, json_out: bool = False) -> None:
        self.json_out = json_out
        self.console = Console()
        self._findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)
        if self.json_out:
            return
        self.console.print(
            f"[bold cyan]{finding.category}[/bold cyan]  "
            f"{finding.target}"
            + (f":{finding.port}" if finding.port is not None else "")
            + f"  [green]{finding.detail}[/green]"
        )

    def summary(self) -> None:
        if self.json_out:
            self.console.print_json(data=[f.to_dict() for f in self._findings])
        else:
            self.console.print(f"\n[bold]Total findings:[/bold] {len(self._findings)}")

    @property
    def findings(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self._findings]


def make_table(title: str, columns: list[str]) -> Table:
    table = Table(title=title, show_lines=False)
    for col in columns:
        table.add_column(col, style="cyan", no_wrap=True)
    return table
