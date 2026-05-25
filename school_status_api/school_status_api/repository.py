from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from school_status_api.database import identity_status_table, utc_now


@dataclass(frozen=True)
class IdentityStatus:
    gid: str
    zjhm: str
    ryzxztdm: str


class IdentityStatusRepository:
    def __init__(self, engine):
        self.engine = engine

    def upsert_many(self, records: list[dict[str, str]]) -> int:
        if not records:
            return 0

        now = utc_now()
        rows = [
            {
                "gid": record["gid"],
                "zjhm": record["zjhm"],
                "ryzxztdm": record["ryzxztdm"],
                "synced_at": now,
            }
            for record in records
        ]
        statement = self._upsert_statement(rows)
        with self.engine.begin() as connection:
            result = connection.execute(statement)
        return result.rowcount or 0

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

    def _upsert_statement(self, rows: list[dict[str, str]]):
        if self.engine.dialect.name == "postgresql":
            statement = postgres_insert(identity_status_table).values(rows)
        elif self.engine.dialect.name == "sqlite":
            statement = sqlite_insert(identity_status_table).values(rows)
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
