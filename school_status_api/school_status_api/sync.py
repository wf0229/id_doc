from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class StatusRepository(Protocol):
    def upsert_many(self, records: list[dict[str, str]]) -> int:
        ...


@dataclass(frozen=True)
class SyncStats:
    read_count: int
    written_count: int
    skipped_count: int


def sync_from_collection(collection, repository: StatusRepository, batch_size: int) -> SyncStats:
    read_count = 0
    written_count = 0
    skipped_count = 0
    batch: list[dict[str, str]] = []

    cursor = collection.find({}, {"gid": 1, "zjhm": 1, "ryzxztdm": 1, "_id": 0})
    for source_record in cursor:
        read_count += 1
        record = _normalize_record(source_record)
        if record is None:
            skipped_count += 1
            continue

        batch.append(record)
        if len(batch) >= batch_size:
            written_count += repository.upsert_many(batch)
            batch = []

    if batch:
        written_count += repository.upsert_many(batch)

    return SyncStats(read_count=read_count, written_count=written_count, skipped_count=skipped_count)


def _normalize_record(source_record) -> dict[str, str] | None:
    gid = source_record.get("gid")
    zjhm = source_record.get("zjhm")
    if not gid or not zjhm:
        return None

    return {
        "gid": str(gid),
        "zjhm": str(zjhm),
        "ryzxztdm": str(source_record.get("ryzxztdm", "")),
    }
