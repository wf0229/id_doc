from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, MetaData, String, Table, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    metadata = MetaData()


class IdentityStatusRow(Base):
    __tablename__ = "identity_status"
    __table_args__ = (
        Index("ix_identity_status_gid", "gid"),
        Index("ux_identity_status_gid_zjhm", "gid", "zjhm", unique=True),
    )

    zjhm: Mapped[str] = mapped_column(String, primary_key=True)
    gid: Mapped[str] = mapped_column(String, nullable=False)
    ryzxztdm: Mapped[str] = mapped_column(String, nullable=False)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


identity_status_table: Table = IdentityStatusRow.__table__


def build_engine(database_url: str):
    return create_engine(database_url, pool_pre_ping=True)


def create_schema(engine) -> None:
    Base.metadata.create_all(engine)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
