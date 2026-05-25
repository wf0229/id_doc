from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ClientConfig:
    name: str
    enabled: bool
    tokens: tuple[str, ...]
    allowed_ips: tuple[Any, ...]


def load_clients_config(path: str | Path) -> list[ClientConfig]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    clients = raw.get("clients", [])
    return [
        ClientConfig(
            name=str(item["name"]),
            enabled=bool(item.get("enabled", True)),
            tokens=tuple(str(token) for token in item.get("tokens", [])),
            allowed_ips=tuple(ip_network(value, strict=False) for value in item.get("allowed_ips", [])),
        )
        for item in clients
    ]
