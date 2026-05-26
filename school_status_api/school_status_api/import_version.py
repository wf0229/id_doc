from __future__ import annotations

import argparse
import sys

from school_status_api.config import AppSettings
from school_status_api.database import build_engine, create_schema
from school_status_api.repository import IdentityStatusRepository


def import_version(repository: IdentityStatusRepository, version: int) -> bool:
    return repository.import_ready_version(version)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import a ready identity status version")
    parser.add_argument("version", type=int)
    args = parser.parse_args(argv)

    settings = AppSettings()
    engine = build_engine(settings.database_url)
    create_schema(engine)
    repository = IdentityStatusRepository(engine)
    if not import_version(repository, args.version):
        print(f"version {args.version} is not ready or has no rows", file=sys.stderr)
        return 1

    print(f"imported version {args.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
