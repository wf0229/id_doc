from __future__ import annotations

import asyncio
import logging

from school_status_api.auto_importer import auto_import_loop
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
    app.state.auto_import_task = None

    @app.on_event("startup")
    async def start_auto_importer():
        if settings.auto_import_interval_seconds <= 0:
            logger.info("identity status auto importer is disabled")
            return
        app.state.auto_import_task = asyncio.create_task(
            auto_import_loop(repository, settings.auto_import_interval_seconds)
        )

    @app.on_event("shutdown")
    async def stop_auto_importer():
        task = app.state.auto_import_task
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    return app

app = create_runtime_app()
