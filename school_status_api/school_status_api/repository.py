from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from school_status_api.database import (
    identity_status_import_batch_table,
    identity_status_import_table,
    identity_status_table,
    utc_now,
)


@dataclass(frozen=True)
class IdentityStatus:
    gid: str
    zjhm: str
    ryzxztdm: str


class IdentityStatusRepository:
    def __init__(self, engine):
        self.engine = engine

    def create_import_version(self, version: int) -> None:
        statement = self._insert_import_batch_statement(version)
        with self.engine.begin() as connection:
            connection.execute(statement)

    def stage_import_records(self, version: int, records: list[dict[str, str]]) -> int:
        if not records:
            return 0

        now = utc_now()
        rows = [
            {
                "version": version,
                "gid": record["gid"],
                "zjhm": record["zjhm"],
                "ryzxztdm": record["ryzxztdm"],
                "pushed_at": now,
            }
            for record in records
        ]
        statement = self._upsert_import_statement(rows)
        with self.engine.begin() as connection:
            result = connection.execute(statement)
        return result.rowcount or 0

    def mark_import_ready(self, version: int) -> None:
        now = utc_now()
        row_count = (
            select(func.count())
            .select_from(identity_status_import_table)
            .where(identity_status_import_table.c.version == version)
            .scalar_subquery()
        )
        statement = (
            update(identity_status_import_batch_table)
            .where(identity_status_import_batch_table.c.version == version)
            .values(status="ready", ready_at=now, row_count=row_count)
        )
        with self.engine.begin() as connection:
            connection.execute(statement)

    def import_ready_version(self, version: int) -> bool:
        now = utc_now()
        with self.engine.begin() as connection:
            batch = connection.execute(
                select(identity_status_import_batch_table.c.status).where(
                    identity_status_import_batch_table.c.version == version
                )
            ).first()
            if batch is None or batch.status != "ready":
                return False

            rows = connection.execute(
                select(
                    identity_status_import_table.c.gid,
                    identity_status_import_table.c.zjhm,
                    identity_status_import_table.c.ryzxztdm,
                ).where(identity_status_import_table.c.version == version)
            ).mappings().all()
            if not rows:
                return False

            connection.execute(self._upsert_status_statement(rows, now))
            connection.execute(
                update(identity_status_import_batch_table)
                .where(identity_status_import_batch_table.c.version == version)
                .values(status="imported", imported_at=now)
            )
            connection.execute(delete(identity_status_import_table).where(identity_status_import_table.c.version == version))
        return True

    def find_by_gid(self, gid: str) -> list[IdentityStatus]:
        statement = (
            select(
                identity_status_table.c.gid,
                identity_status_table.c.zjhm,
                identity_status_table.c.ryzxztdm,
            )
            .where(identity_status_table.c.gid == gid)
            .order_by(identity_status_table.c.zjhm)
        )
        with self.engine.begin() as connection:
            rows = connection.execute(statement).mappings().all()
        return [IdentityStatus(**row) for row in rows]

    def find_by_zjhm(self, zjhm: str) -> IdentityStatus | None:
        statement = select(
            identity_status_table.c.gid,
            identity_status_table.c.zjhm,
            identity_status_table.c.ryzxztdm,
        ).where(identity_status_table.c.zjhm == zjhm)
        with self.engine.begin() as connection:
            row = connection.execute(statement).mappings().first()
        if row is None:
            return None
        return IdentityStatus(**row)

    def find_by_zjhms(self, zjhms: list[str]) -> list[IdentityStatus]:
        if not zjhms:
            return []
        statement = (
            select(
                identity_status_table.c.gid,
                identity_status_table.c.zjhm,
                identity_status_table.c.ryzxztdm,
            )
            .where(identity_status_table.c.zjhm.in_(zjhms))
            .order_by(identity_status_table.c.zjhm)
        )
        with self.engine.begin() as connection:
            rows = connection.execute(statement).mappings().all()
        return [IdentityStatus(**row) for row in rows]

    def find_by_gids(self, gids: list[str]) -> list[IdentityStatus]:
        if not gids:
            return []
        statement = (
            select(
                identity_status_table.c.gid,
                identity_status_table.c.zjhm,
                identity_status_table.c.ryzxztdm,
            )
            .where(identity_status_table.c.gid.in_(gids))
            .order_by(identity_status_table.c.gid, identity_status_table.c.zjhm)
        )
        with self.engine.begin() as connection:
            rows = connection.execute(statement).mappings().all()
        return [IdentityStatus(**row) for row in rows]

    def _insert_import_batch_statement(self, version: int):
        values = {
            "version": version,
            "status": "writing",
            "created_at": utc_now(),
            "row_count": 0,
        }
        if self.engine.dialect.name == "postgresql":
            statement = postgres_insert(identity_status_import_batch_table).values(values)
        elif self.engine.dialect.name == "sqlite":
            statement = sqlite_insert(identity_status_import_batch_table).values(values)
        else:
            raise RuntimeError(f"unsupported database dialect: {self.engine.dialect.name}")
        return statement.on_conflict_do_update(
            index_elements=[identity_status_import_batch_table.c.version],
            set_={"status": "writing", "created_at": statement.excluded.created_at, "row_count": 0},
        )

    def _upsert_import_statement(self, rows: list[dict[str, str]]):
        if self.engine.dialect.name == "postgresql":
            statement = postgres_insert(identity_status_import_table).values(rows)
        elif self.engine.dialect.name == "sqlite":
            statement = sqlite_insert(identity_status_import_table).values(rows)
        else:
            raise RuntimeError(f"unsupported database dialect: {self.engine.dialect.name}")

        return statement.on_conflict_do_update(
            index_elements=[identity_status_import_table.c.version, identity_status_import_table.c.zjhm],
            set_={
                "gid": statement.excluded.gid,
                "ryzxztdm": statement.excluded.ryzxztdm,
                "pushed_at": statement.excluded.pushed_at,
            },
        )

    def _upsert_status_statement(self, rows, now):
        values = [
            {
                "gid": row["gid"],
                "zjhm": row["zjhm"],
                "ryzxztdm": row["ryzxztdm"],
                "synced_at": now,
            }
            for row in rows
        ]
        if self.engine.dialect.name == "postgresql":
            statement = postgres_insert(identity_status_table).values(values)
        elif self.engine.dialect.name == "sqlite":
            statement = sqlite_insert(identity_status_table).values(values)
        else:
            raise RuntimeError(f"unsupported database dialect: {self.engine.dialect.name}")
        return statement.on_conflict_do_update(
            index_elements=[identity_status_table.c.zjhm],
            set_={
                "gid": statement.excluded.gid,
                "ryzxztdm": statement.excluded.ryzxztdm,
                "synced_at": statement.excluded.synced_at,
            },
        )
