from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from school_status_api.auth import AuthError, authenticate_client, get_bearer_token
from school_status_api.config import load_clients_config


def test_loads_enabled_clients_from_yaml(tmp_path):
    config_path = tmp_path / "clients.yml"
    config_path.write_text(
        """
clients:
  - name: example-system
    enabled: true
    tokens:
      - secret-token
    allowed_ips:
      - 192.0.2.10/32
""",
        encoding="utf-8",
    )

    clients = load_clients_config(config_path)

    assert clients[0].name == "example-system"
    assert clients[0].enabled is True
    assert clients[0].tokens == ("secret-token",)
    assert str(clients[0].allowed_ips[0]) == "192.0.2.10/32"


def test_get_bearer_token_extracts_token():
    assert get_bearer_token("Bearer secret-token") == "secret-token"


def test_get_bearer_token_rejects_missing_or_wrong_scheme():
    assert get_bearer_token(None) is None
    assert get_bearer_token("Basic secret-token") is None


def test_authenticates_matching_token_and_ip():
    clients = load_clients_config_from_text(
        """
clients:
  - name: example-system
    enabled: true
    tokens: [secret-token]
    allowed_ips: [192.0.2.0/24]
"""
    )

    client = authenticate_client(
        auth_header="Bearer secret-token",
        peer_ip="192.0.2.10",
        forwarded_for=None,
        trusted_proxies=(),
        clients=clients,
    )

    assert client.name == "example-system"


def test_rejects_missing_token():
    clients = load_clients_config_from_text(
        """
clients:
  - name: example-system
    enabled: true
    tokens: [secret-token]
    allowed_ips: [192.0.2.0/24]
"""
    )

    with pytest.raises(AuthError) as exc_info:
        authenticate_client(
            auth_header=None,
            peer_ip="192.0.2.10",
            forwarded_for=None,
            trusted_proxies=(),
            clients=clients,
        )

    assert exc_info.value.status_code == 401


def test_rejects_disallowed_ip():
    clients = load_clients_config_from_text(
        """
clients:
  - name: example-system
    enabled: true
    tokens: [secret-token]
    allowed_ips: [192.0.2.0/24]
"""
    )

    with pytest.raises(AuthError) as exc_info:
        authenticate_client(
            auth_header="Bearer secret-token",
            peer_ip="203.0.113.10",
            forwarded_for=None,
            trusted_proxies=(),
            clients=clients,
        )

    assert exc_info.value.status_code == 403


def test_rejects_invalid_peer_ip_without_internal_error():
    clients = load_clients_config_from_text(
        """
clients:
  - name: example-system
    enabled: true
    tokens: [secret-token]
    allowed_ips: [192.0.2.0/24]
"""
    )

    with pytest.raises(AuthError) as exc_info:
        authenticate_client(
            auth_header="Bearer secret-token",
            peer_ip="",
            forwarded_for=None,
            trusted_proxies=(),
            clients=clients,
        )

    assert exc_info.value.status_code == 403


def test_uses_forwarded_for_only_from_trusted_proxy():
    clients = load_clients_config_from_text(
        """
clients:
  - name: example-system
    enabled: true
    tokens: [secret-token]
    allowed_ips: [198.51.100.7/32]
"""
    )

    client = authenticate_client(
        auth_header="Bearer secret-token",
        peer_ip="127.0.0.1",
        forwarded_for="198.51.100.7",
        trusted_proxies=("127.0.0.1/32",),
        clients=clients,
    )

    assert client.name == "example-system"


def test_rejects_invalid_forwarded_for_without_internal_error():
    clients = load_clients_config_from_text(
        """
clients:
  - name: example-system
    enabled: true
    tokens: [secret-token]
    allowed_ips: [192.0.2.0/24]
"""
    )

    with pytest.raises(AuthError) as exc_info:
        authenticate_client(
            auth_header="Bearer secret-token",
            peer_ip="127.0.0.1",
            forwarded_for="garbage",
            trusted_proxies=("127.0.0.1/32",),
            clients=clients,
        )

    assert exc_info.value.status_code == 403


def test_forwarded_for_uses_nearest_untrusted_ip_from_trusted_proxy():
    clients = load_clients_config_from_text(
        """
clients:
  - name: example-system
    enabled: true
    tokens: [secret-token]
    allowed_ips: [192.0.2.10/32]
"""
    )

    with pytest.raises(AuthError) as exc_info:
        authenticate_client(
            auth_header="Bearer secret-token",
            peer_ip="127.0.0.1",
            forwarded_for="192.0.2.10, 203.0.113.77",
            trusted_proxies=("127.0.0.1/32",),
            clients=clients,
        )

    assert exc_info.value.status_code == 403


def load_clients_config_from_text(text):
    temp_dir = TemporaryDirectory()
    path = Path(temp_dir.name) / "clients.yml"
    path.write_text(text, encoding="utf-8")
    clients = load_clients_config(path)
    temp_dir.cleanup()
    return clients
