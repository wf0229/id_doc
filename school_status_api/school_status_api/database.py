from __future__ import annotations

from sqlalchemy import create_engine


def build_engine(database_url: str):
    return create_engine(database_url, pool_pre_ping=True)