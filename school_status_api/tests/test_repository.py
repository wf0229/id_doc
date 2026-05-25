from sqlalchemy import create_engine

from school_status_api.database import create_schema
from school_status_api.repository import IdentityStatusRepository


def test_upsert_and_find_multiple_records_by_gid():
    repository = make_repository()
    repository.upsert_many(
        [
            {"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"},
            {"gid": "gid-1", "zjhm": "zjhm-2", "ryzxztdm": "0"},
        ]
    )

    records = repository.find_by_gid("gid-1")

    assert [record.zjhm for record in records] == ["zjhm-1", "zjhm-2"]
    assert [record.ryzxztdm for record in records] == ["1", "0"]


def test_find_by_zjhm_returns_single_record():
    repository = make_repository()
    repository.upsert_many(
        [
            {"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"},
        ]
    )

    record = repository.find_by_zjhm("zjhm-1")

    assert record is not None
    assert record.gid == "gid-1"
    assert record.zjhm == "zjhm-1"
    assert record.ryzxztdm == "1"


def test_find_returns_empty_for_missing_values():
    repository = make_repository()

    assert repository.find_by_gid("missing") == []
    assert repository.find_by_zjhm("missing") is None


def test_upsert_updates_existing_zjhm():
    repository = make_repository()
    repository.upsert_many([{"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "0"}])
    repository.upsert_many([{"gid": "gid-2", "zjhm": "zjhm-1", "ryzxztdm": "1"}])

    record = repository.find_by_zjhm("zjhm-1")

    assert record is not None
    assert record.gid == "gid-2"
    assert record.ryzxztdm == "1"


def make_repository():
    engine = create_engine("sqlite:///:memory:")
    create_schema(engine)
    return IdentityStatusRepository(engine)
