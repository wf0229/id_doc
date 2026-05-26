from __future__ import annotations

import logging

from school_status_api.config import AppSettings, load_clients_config
from school_status_api.database import build_engine, create_schema
from school_status_api.main import create_app
from school_status_api.repository import IdentityStatusRepository

logger = logging.getLogger(__name__)


def create_runtime_app():
    settings = AppSettings()
    engine = build_engine(settings.database_url)
    create_schema(engine)
    repository = IdentityStatusRepository(engine)
    clients = load_clients_config(settings.clients_config_path)
    app = create_app(
        repository=repository,
        clients=clients,
        trusted_proxies=settings.trusted_proxy_networks(),
    )
    app.state.settings = settings

    return app

app = create_runtime_app()
