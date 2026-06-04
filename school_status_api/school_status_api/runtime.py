from __future__ import annotations

import logging

from sqlalchemy import text

from school_status_api.config import AppSettings, load_clients_config
from school_status_api.database import build_engine
from school_status_api.main import create_app
from school_status_api.repository import IdentityStatusRepository

logger = logging.getLogger(__name__)


def _verify_v_user(engine) -> None:
    """Confirm that the ``v_user`` view is queryable at startup."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1 FROM v_user WHERE 1 = 0"))
    except Exception as exc:
        raise RuntimeError(
            f"v_user view is not available — check database schema: {exc}"
        ) from exc


def create_runtime_app():
    settings = AppSettings()
    engine = build_engine(settings.database_url)
    _verify_v_user(engine)
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