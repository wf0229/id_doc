from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from pymongo import MongoClient

from school_status_api.config import AppSettings, load_clients_config
from school_status_api.database import build_engine, create_schema
from school_status_api.main import create_app
from school_status_api.repository import IdentityStatusRepository
from school_status_api.sync import sync_from_collection

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

    @app.on_event("startup")
    def start_scheduler() -> None:
        scheduler = BackgroundScheduler(timezone=settings.sync_timezone)
        scheduler.add_job(
            lambda: run_mongo_sync(settings, repository),
            trigger="cron",
            hour=settings.sync_hour,
            minute=settings.sync_minute,
            id="daily-mongo-sync",
            replace_existing=True,
        )
        scheduler.start()
        app.state.scheduler = scheduler
        if settings.run_initial_sync:
            run_mongo_sync(settings, repository)

    @app.on_event("shutdown")
    def stop_scheduler() -> None:
        scheduler = getattr(app.state, "scheduler", None)
        if scheduler is not None:
            scheduler.shutdown(wait=False)

    return app


def run_mongo_sync(settings: AppSettings, repository: IdentityStatusRepository):
    logger.info("starting mongo status sync")
    mongo_client = MongoClient(settings.mongo_uri)
    try:
        collection = mongo_client[settings.mongo_database][settings.mongo_collection]
        stats = sync_from_collection(collection, repository, settings.sync_batch_size)
        logger.info(
            "finished mongo status sync read=%s written=%s skipped=%s",
            stats.read_count,
            stats.written_count,
            stats.skipped_count,
        )
        return stats
    finally:
        mongo_client.close()


app = create_runtime_app()
