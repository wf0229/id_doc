from __future__ import annotations

from collections.abc import Sequence

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from school_status_api.auth import AuthError, authenticate_client
from school_status_api.config import ClientConfig

MAX_BATCH_SIZE = 100
BATCH_LIMIT_MESSAGE = "一次最多查询100条；超过100条请联系数据中心获取中间表。"


class GidsRequest(BaseModel):
    gids: list[str] = Field(min_length=1)


class ZjhmsRequest(BaseModel):
    zjhms: list[str] = Field(min_length=1)


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

    @app.post("/doc/api/status/by-gids")
    def by_gids(request_body: GidsRequest, _client: ClientConfig = Depends(require_client)):
        gids = _normalize_values(request_body.gids)
        _enforce_batch_limit(gids)
        records = app.state.repository.find_by_gids(gids)
        found = {record.gid for record in records}
        return {
            "items": [_record_payload(record) for record in records],
            "not_found": [gid for gid in gids if gid not in found],
        }

    @app.post("/doc/api/status/by-zjhms")
    def by_zjhms(request_body: ZjhmsRequest, _client: ClientConfig = Depends(require_client)):
        zjhms = _normalize_values(request_body.zjhms)
        _enforce_batch_limit(zjhms)
        records = app.state.repository.find_by_zjhms(zjhms)
        found = {record.zjhm for record in records}
        return {
            "items": [_record_payload(record) for record in records],
            "not_found": [zjhm for zjhm in zjhms if zjhm not in found],
        }

    return app


def _normalize_values(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value.strip()))


def _enforce_batch_limit(values: list[str]) -> None:
    if len(values) > MAX_BATCH_SIZE:
        raise HTTPException(status_code=400, detail=BATCH_LIMIT_MESSAGE)


def _record_payload(record) -> dict[str, str]:
    return {"gid": record.gid, "zjhm": record.zjhm, "ryzxztdm": record.ryzxztdm}
