import pytest

from school_status_api.sync import SyncStats, sync_from_collection


def test_syncs_valid_records_in_batches():
    collection = FakeCollection(
        [
            {"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"},
            {"gid": "gid-2", "zjhm": "zjhm-2", "ryzxztdm": "0"},
            {"gid": "gid-3", "zjhm": "zjhm-3", "ryzxztdm": "1"},
        ]
    )
    repository = FakeRepository()

    stats = sync_from_collection(collection, repository, batch_size=2)

    assert stats == SyncStats(read_count=3, written_count=3, skipped_count=0)
    assert repository.batches == [
        [
            {"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"},
            {"gid": "gid-2", "zjhm": "zjhm-2", "ryzxztdm": "0"},
        ],
        [{"gid": "gid-3", "zjhm": "zjhm-3", "ryzxztdm": "1"}],
    ]
    assert collection.projection == {"gid": 1, "zjhm": 1, "ryzxztdm": 1, "_id": 0}


def test_skips_records_missing_gid_or_zjhm():
    collection = FakeCollection(
        [
            {"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"},
            {"zjhm": "missing-gid", "ryzxztdm": "1"},
            {"gid": "missing-zjhm", "ryzxztdm": "1"},
        ]
    )
    repository = FakeRepository()

    stats = sync_from_collection(collection, repository, batch_size=100)

    assert stats == SyncStats(read_count=3, written_count=1, skipped_count=2)
    assert repository.batches == [[{"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"}]]


def test_source_read_failure_does_not_write_any_batch():
    collection = FailingCollection()
    repository = FakeRepository()

    with pytest.raises(RuntimeError, match="mongo unavailable"):
        sync_from_collection(collection, repository, batch_size=2)

    assert repository.batches == []


class FakeCollection:
    def __init__(self, records):
        self.records = records
        self.projection = None

    def find(self, _filter, projection):
        self.projection = projection
        return iter(self.records)


class FailingCollection:
    def find(self, _filter, projection):
        raise RuntimeError("mongo unavailable")


class FakeRepository:
    def __init__(self):
        self.batches = []

    def upsert_many(self, records):
        self.batches.append(records)
        return len(records)
