from sqlalchemy import create_engine

from school_status_api.auto_importer import import_ready_batches
from school_status_api.database import create_schema
from school_status_api.repository import IdentityStatusRepository


def test_import_ready_batches_imports_ready_versions():
    engine = create_engine("sqlite:///:memory:")
    create_schema(engine)
    repository = IdentityStatusRepository(engine)
    repository.create_import_version(2026052601)
    repository.stage_import_records(
        2026052601,
        [{"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "10"}],
    )
    repository.mark_import_ready(2026052601)

    imported_versions = import_ready_batches(repository)

    assert imported_versions == [2026052601]
    assert repository.find_by_zjhm("zjhm-1").ryzxztdm == "10"
