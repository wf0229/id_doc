from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


def import_ready_batches(repository) -> list[int]:
    return repository.import_ready_versions()


async def auto_import_loop(repository, interval_seconds: int) -> None:
    while True:
        try:
            imported_versions = import_ready_batches(repository)
            if imported_versions:
                logger.info("imported ready identity status batches: %s", imported_versions)
        except Exception:
            logger.exception("failed to auto import ready identity status batches")
        await asyncio.sleep(interval_seconds)
