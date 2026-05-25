from ipaddress import ip_network

from fastapi.testclient import TestClient

from school_status_api.config import ClientConfig
from school_status_api.main import create_app
from school_status_api.repository import IdentityStatus


def test_health_is_public():
    client = TestClient(create_app(repository=FakeRepository(), clients=[]))

    response = client.get("/doc/api/health")

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_by_gid_returns_multiple_items():
    app = create_app(repository=FakeRepository(), clients=clients())
    client = TestClient(app, client=("192.0.2.10", 50000))

    response = client.get(
        "/doc/api/status/by-gid/gid-1",
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "gid": "gid-1",
        "items": [
            {"zjhm": "zjhm-1", "ryzxztdm": "1"},
            {"zjhm": "zjhm-2", "ryzxztdm": "0"},
        ],
    }


def test_by_zjhm_returns_single_item():
    app = create_app(repository=FakeRepository(), clients=clients())
    client = TestClient(app, client=("192.0.2.10", 50000))

    response = client.get(
        "/doc/api/status/by-zjhm/zjhm-1",
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"gid": "gid-1", "zjhm": "zjhm-1", "ryzxztdm": "1"}


def test_by_gid_returns_404_when_missing():
    app = create_app(repository=FakeRepository(), clients=clients())
    client = TestClient(app, client=("192.0.2.10", 50000))

    response = client.get(
        "/doc/api/status/by-gid/missing",
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "gid not found"}


def test_rejects_missing_token():
    app = create_app(repository=FakeRepository(), clients=clients())
    client = TestClient(app, client=("192.0.2.10", 50000))

    response = client.get("/doc/api/status/by-zjhm/zjhm-1")

    assert response.status_code == 401


def test_rejects_disallowed_ip():
    app = create_app(repository=FakeRepository(), clients=clients())
    client = TestClient(app, client=("203.0.113.10", 50000))

    response = client.get(
        "/doc/api/status/by-zjhm/zjhm-1",
        headers={"Authorization": "Bearer secret-token"},
    )

    assert response.status_code == 403


def clients():
    return [
        ClientConfig(
            name="example-system",
            enabled=True,
            tokens=("secret-token",),
            allowed_ips=(ip_network("192.0.2.0/24"),),
        )
    ]


class FakeRepository:
    def find_by_gid(self, gid):
        if gid != "gid-1":
            return []
        return [
            IdentityStatus(gid="gid-1", zjhm="zjhm-1", ryzxztdm="1"),
            IdentityStatus(gid="gid-1", zjhm="zjhm-2", ryzxztdm="0"),
        ]

    def find_by_zjhm(self, zjhm):
        if zjhm != "zjhm-1":
            return None
        return IdentityStatus(gid="gid-1", zjhm="zjhm-1", ryzxztdm="1")
