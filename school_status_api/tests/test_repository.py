from sqlalchemy import create_engine, text

from school_status_api.repository import IdentityStatusRepository


def test_find_by_gid_returns_multiple_records():
    repository = make_repository()
    with repository.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO v_user (gid, userid, zxzt) VALUES "
                "('gid-1', 'zjhm-1', '1'), "
                "('gid-1', 'zjhm-2', '0')"
            )
        )

    records = repository.find_by_gid("gid-1")

    assert [r.zjhm for r in records] == ["zjhm-1", "zjhm-2"]
    assert [r.ryzxztdm for r in records] == ["1", "0"]


def test_find_by_zjhm_returns_single_record():
    repository = make_repository()
    with repository.engine.begin() as conn:
        conn.execute(
            text("INSERT INTO v_user (gid, userid, zxzt) VALUES ('gid-1', 'zjhm-1', '1')")
        )

    record = repository.find_by_zjhm("zjhm-1")

    assert record is not None
    assert record.gid == "gid-1"
    assert record.zjhm == "zjhm-1"
    assert record.ryzxztdm == "1"


def test_find_by_zjhms_returns_matching_records():
    repository = make_repository()
    with repository.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO v_user (gid, userid, zxzt) VALUES "
                "('gid-1', 'zjhm-1', '1'), "
                "('gid-2', 'zjhm-2', '0')"
            )
        )

    records = repository.find_by_zjhms(["zjhm-2", "missing", "zjhm-1"])

    assert [(r.zjhm, r.gid, r.ryzxztdm) for r in records] == [
        ("zjhm-1", "gid-1", "1"),
        ("zjhm-2", "gid-2", "0"),
    ]


def test_find_by_gids_returns_all_matching_identities():
    repository = make_repository()
    with repository.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO v_user (gid, userid, zxzt) VALUES "
                "('gid-1', 'zjhm-1', '1'), "
                "('gid-1', 'zjhm-2', '0'), "
                "('gid-2', 'zjhm-3', '1')"
            )
        )

    records = repository.find_by_gids(["gid-2", "missing", "gid-1"])

    assert [(r.gid, r.zjhm, r.ryzxztdm) for r in records] == [
        ("gid-1", "zjhm-1", "1"),
        ("gid-1", "zjhm-2", "0"),
        ("gid-2", "zjhm-3", "1"),
    ]


def test_find_returns_empty_for_missing_values():
    repository = make_repository()

    assert repository.find_by_gid("missing") == []
    assert repository.find_by_zjhm("missing") is None
    assert repository.find_by_gids(["missing"]) == []
    assert repository.find_by_zjhms(["missing"]) == []


def test_find_by_gids_returns_empty_for_empty_input():
    repository = make_repository()
    assert repository.find_by_gids([]) == []


def test_find_by_zjhms_returns_empty_for_empty_input():
    repository = make_repository()
    assert repository.find_by_zjhms([]) == []


def test_gid_not_unique_so_multiple_gids_can_map_to_same_userid():
    """v_user 中 userid 唯一，但 gid 不唯一——同一个 gid 下会有多个 userid"""
    repository = make_repository()
    with repository.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO v_user (gid, userid, zxzt) VALUES "
                "('gid-1', 'zjhm-1', '10'), "
                "('gid-1', 'zjhm-2', '20')"
            )
        )

    records = repository.find_by_gid("gid-1")

    assert len(records) == 2


def make_repository():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE v_user (gid TEXT NOT NULL, userid TEXT NOT NULL, zxzt TEXT NOT NULL)"
            )
        )
    return IdentityStatusRepository(engine)