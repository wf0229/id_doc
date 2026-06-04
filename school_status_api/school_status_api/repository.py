from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text

_SELECT = "SELECT gid, userid AS zjhm, zxzt AS ryzxztdm FROM v_user"


@dataclass(frozen=True)
class IdentityStatus:
    gid: str
    zjhm: str
    ryzxztdm: str


class IdentityStatusRepository:
    """Repository that queries the ``v_user`` view via raw SQL.

    All reads use ``engine.connect()`` (implicit transaction, rolled back
    on exit) — this is safe under PostgreSQL's default READ COMMITTED
    isolation where each statement sees the latest committed data.
    """

    def __init__(self, engine):
        self.engine = engine

    @staticmethod
    def _in_clause(values: list[str], prefix: str) -> tuple[str, dict[str, str]]:
        """Build a parameterised IN-clause fragment.

        Returns ``(placeholders_sql, params_dict)`` ready for interpolation
        into a ``text()`` query.  Empty *values* produce ``NULL`` so the
        resulting SQL is still valid and never matches any row.
        """
        if not values:
            return "NULL", {}
        placeholders = ", ".join(f":{prefix}_{i}" for i in range(len(values)))
        params = {f"{prefix}_{i}": v for i, v in enumerate(values)}
        return placeholders, params

    def _query(self, sql: str, params: dict[str, str] | None = None) -> list[IdentityStatus]:
        """Execute a SELECT and return all matching :class:`IdentityStatus` rows."""
        statement = text(sql)
        with self.engine.connect() as conn:
            rows = conn.execute(statement, params or {}).mappings().all()
        return [IdentityStatus(**row) for row in rows]

    def find_by_gid(self, gid: str) -> list[IdentityStatus]:
        return self.find_by_gids([gid])

    def find_by_zjhm(self, zjhm: str) -> IdentityStatus | None:
        results = self.find_by_zjhms([zjhm])
        return results[0] if results else None

    def find_by_gids(self, gids: list[str]) -> list[IdentityStatus]:
        if not gids:
            return []
        placeholders, params = self._in_clause(gids, "gid")
        return self._query(
            f"{_SELECT} WHERE gid IN ({placeholders}) ORDER BY gid, userid",
            params,
        )

    def find_by_zjhms(self, zjhms: list[str]) -> list[IdentityStatus]:
        if not zjhms:
            return []
        placeholders, params = self._in_clause(zjhms, "zjhm")
        return self._query(
            f"{_SELECT} WHERE userid IN ({placeholders}) ORDER BY userid",
            params,
        )