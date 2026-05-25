from __future__ import annotations

from collections.abc import Sequence

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from school_status_api.auth import AuthError, authenticate_client
from school_status_api.config import ClientConfig


def create_app(*, repository, clients: list[ClientConfig], trusted_proxies: Sequence[str] = ()) -> FastAPI:
    app = FastAPI(title="School Status API")
    app.state.repository = repository
    app.state.clients = clients
    app.state.trusted_proxies = tuple(trusted_proxies)

    def require_client(
        request: Request,
        authorization: str | None = Header(default=None),
        x_forwarded_for: str | None = Header(default=None),
    ) -> ClientConfig:
        peer_ip = request.client.host if request.client else ""
        try:
            return authenticate_client(
                auth_header=authorization,
                peer_ip=peer_ip,
                forwarded_for=x_forwarded_for,
                trusted_proxies=app.state.trusted_proxies,
                clients=app.state.clients,
            )
        except AuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    @app.get("/doc/api/health")
    def health():
        return {"ok": True}

    @app.get("/doc/api/status/by-gid/{gid}")
    def by_gid(gid: str, _client: ClientConfig = Depends(require_client)):
        records = app.state.repository.find_by_gid(gid)
        if not records:
            raise HTTPException(status_code=404, detail="gid not found")
        return {
            "gid": gid,
            "items": [
                {
                    "zjhm": record.zjhm,
                    "ryzxztdm": record.ryzxztdm,
                }
                for record in records
            ],
        }

    @app.get("/doc/api/status/by-zjhm/{zjhm}")
    def by_zjhm(zjhm: str, _client: ClientConfig = Depends(require_client)):
        record = app.state.repository.find_by_zjhm(zjhm)
        if record is None:
            raise HTTPException(status_code=404, detail="zjhm not found")
        return {"gid": record.gid, "zjhm": record.zjhm, "ryzxztdm": record.ryzxztdm}

    return app
