from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Index, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    metadata = MetaData()


class IdentityStatusRow(Base):
    __tablename__ = "identity_status"
    __table_args__ = (
        Index("ix_identity_status_gid", "gid"),
    )

    zjhm: Mapped[str] = mapped_column(String, primary_key=True)
    gid: Mapped[str] = mapped_column(String, nullable=False)
    ryzxztdm: Mapped[str] = mapped_column(String, nullable=False)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class IdentityStatusImportBatchRow(Base):
    __tablename__ = "identity_status_import_batch"

    version: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    status: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    row_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)


class IdentityStatusImportRow(Base):
    __tablename__ = "identity_status_import"
    __table_args__ = (
        Index("ix_identity_status_import_version_gid", "version", "gid"),
    )

    version: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    zjhm: Mapped[str] = mapped_column(String, primary_key=True)
    gid: Mapped[str] = mapped_column(String, nullable=False)
    ryzxztdm: Mapped[str] = mapped_column(String, nullable=False)
    pushed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


identity_status_table: Table = IdentityStatusRow.__table__
identity_status_import_batch_table: Table = IdentityStatusImportBatchRow.__table__
identity_status_import_table: Table = IdentityStatusImportRow.__table__


def build_engine(database_url: str):
    return create_engine(database_url, pool_pre_ping=True)


def create_schema(engine) -> None:
    Base.metadata.create_all(engine)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
