from sqlalchemy import create_engine

from school_status_api.database import create_schema
from school_status_api.repository import IdentityStatusRepository


def test_upsert_and_find_multiple_records_by_gid():
    repository = make_repository()
    repository.create_import_version(2026052601)
    repository.stage_import_records(
        2026052601,
        [
            {"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"},
            {"gid": "gid-1", "zjhm": "zjhm-2", "ryzxztdm": "0"},
        ],
    )
    repository.mark_import_ready(2026052601)
    repository.import_ready_version(2026052601)

    records = repository.find_by_gid("gid-1")

    assert [record.zjhm for record in records] == ["zjhm-1", "zjhm-2"]
    assert [record.ryzxztdm for record in records] == ["1", "0"]


def test_find_by_zjhm_returns_single_record():
    repository = make_repository()
    import_records(repository, 2026052601, [{"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"}])

    record = repository.find_by_zjhm("zjhm-1")

    assert record is not None
    assert record.gid == "gid-1"
    assert record.zjhm == "zjhm-1"
    assert record.ryzxztdm == "1"


def test_find_returns_empty_for_missing_values():
    repository = make_repository()

    assert repository.find_by_gid("missing") == []
    assert repository.find_by_zjhm("missing") is None


def test_importing_new_version_switches_active_data_atomically():
    repository = make_repository()
    import_records(repository, 2026052601, [{"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "0"}])
    import_records(repository, 2026052602, [{"gid": "gid-2", "zjhm": "zjhm-1", "ryzxztdm": "1"}])

    record = repository.find_by_zjhm("zjhm-1")

    assert record is not None
    assert record.gid == "gid-2"
    assert record.ryzxztdm == "1"
    assert repository.find_by_gid("gid-1") == []


def test_import_rejects_version_that_is_not_ready():
    repository = make_repository()
    repository.create_import_version(2026052601)
    repository.stage_import_records(
        2026052601,
        [{"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"}],
    )

    assert repository.import_ready_version(2026052601) is False
    assert repository.find_by_zjhm("zjhm-1") is None


def make_repository():
    engine = create_engine("sqlite:///:memory:")
    create_schema(engine)
    return IdentityStatusRepository(engine)


def import_records(repository, version, records):
    repository.create_import_version(version)
    repository.stage_import_records(version, records)
    repository.mark_import_ready(version)
    assert repository.import_ready_version(version) is True
