from __future__ import annotations

import hmac
from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from school_status_api.config import ClientConfig


@dataclass(frozen=True)
class AuthError(Exception):
    status_code: int
    detail: str


def get_bearer_token(auth_header: str | None) -> str | None:
    if not auth_header:
        return None
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def authenticate_client(
    *,
    auth_header: str | None,
    peer_ip: str,
    forwarded_for: str | None,
    trusted_proxies: tuple[str, ...],
    clients: list[ClientConfig],
) -> ClientConfig:
    token = get_bearer_token(auth_header)
    if token is None:
        raise AuthError(status_code=401, detail="missing or invalid bearer token")

    client = _find_client_by_token(token, clients)
    if client is None:
        raise AuthError(status_code=401, detail="missing or invalid bearer token")

    request_ip = _request_ip(peer_ip, forwarded_for, trusted_proxies)
    if not any(request_ip in network for network in client.allowed_ips):
        raise AuthError(status_code=403, detail="source ip not allowed")

    return client


def _find_client_by_token(token: str, clients: list[ClientConfig]) -> ClientConfig | None:
    for client in clients:
        if not client.enabled:
            continue
        for candidate in client.tokens:
            if hmac.compare_digest(token, candidate):
                return client
    return None


def _request_ip(peer_ip: str, forwarded_for: str | None, trusted_proxies: tuple[str, ...]):
    peer = ip_address(peer_ip)
    trusted = tuple(ip_network(value, strict=False) for value in trusted_proxies)
    if forwarded_for and any(peer in network for network in trusted):
        first_forwarded = forwarded_for.split(",", maxsplit=1)[0].strip()
        return ip_address(first_forwarded)
    return peer
