from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml


@dataclass(frozen=True)
class ClientConfig:
    name: str
    enabled: bool
    tokens: tuple[str, ...]
    allowed_ips: tuple[Any, ...]


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    clients_config_path: str = "/app/config/clients.yml"
    trusted_proxies: str = "127.0.0.1/32"
    mongo_uri: str
    mongo_database: str
    mongo_collection: str
    sync_hour: int = 3
    sync_minute: int = 0
    sync_batch_size: int = 1000
    sync_timezone: str = "Asia/Shanghai"
    run_initial_sync: bool = False

    def trusted_proxy_networks(self) -> tuple[str, ...]:
        return tuple(value.strip() for value in self.trusted_proxies.split(",") if value.strip())


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
