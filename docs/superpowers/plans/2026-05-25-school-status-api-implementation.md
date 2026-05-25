# School Status API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Docker Compose deployable authenticated query API under `/doc/api/` that syncs `gid`, `zjhm`, and `ryzxztdm` from MongoDB into PostgreSQL and serves status lookups.

**Architecture:** Add a focused FastAPI application under `school_status_api/`. The app loads YAML client auth config, validates Bearer tokens plus IP/CIDR allowlists, stores synced rows in PostgreSQL through SQLAlchemy, and runs a daily MongoDB full-sync job with APScheduler. Tests cover config/auth, repository queries, sync behavior, and API routes.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy, psycopg, PyMongo, APScheduler, PyYAML, pytest, HTTPX, Docker Compose, PostgreSQL.

---

## File Structure

- `school_status_api/pyproject.toml`: package metadata and dependencies.
- `school_status_api/Dockerfile`: API container image.
- `school_status_api/school_status_api/config.py`: environment and YAML client config loading.
- `school_status_api/school_status_api/auth.py`: Bearer token and IP/CIDR validation.
- `school_status_api/school_status_api/database.py`: SQLAlchemy engine/session setup and schema creation helper.
- `school_status_api/school_status_api/repository.py`: query and upsert operations for `identity_status`.
- `school_status_api/school_status_api/sync.py`: MongoDB full-sync implementation.
- `school_status_api/school_status_api/main.py`: FastAPI app factory, routes, and scheduler startup.
- `school_status_api/tests/`: pytest suite.
- `school_status_api/config/clients.example.yml`: example static token/IP config.
- `school_status_api/.env.example`: example environment variables.
- `docker-compose.school-status.yml`: deployable API + PostgreSQL stack.

### Task 1: Package Skeleton

**Files:**
- Create: `school_status_api/pyproject.toml`
- Create: `school_status_api/school_status_api/__init__.py`
- Create: `school_status_api/tests/test_import.py`

- [ ] **Step 1: Write a failing import smoke test**

```python
def test_package_imports():
    import school_status_api

    assert school_status_api.__version__ == "0.1.0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd school_status_api && pytest tests/test_import.py -q`
Expected: FAIL because the package does not exist or has no `__version__`.

- [ ] **Step 3: Add package metadata and version**

Create `pyproject.toml` with pytest and runtime dependencies. Create `school_status_api/__init__.py` containing `__version__ = "0.1.0"`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd school_status_api && pytest tests/test_import.py -q`
Expected: PASS.

### Task 2: Client Config And Authentication

**Files:**
- Create: `school_status_api/school_status_api/config.py`
- Create: `school_status_api/school_status_api/auth.py`
- Create: `school_status_api/tests/test_auth.py`
- Create: `school_status_api/config/clients.example.yml`

- [ ] **Step 1: Write failing auth tests**

Cover YAML loading, valid token + IP, missing token, invalid token, and disallowed IP.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd school_status_api && pytest tests/test_auth.py -q`
Expected: FAIL because config and auth modules do not exist.

- [ ] **Step 3: Implement minimal config/auth code**

Implement `load_clients_config(path)`, `get_bearer_token(value)`, and `authenticate_client(auth_header, peer_ip, forwarded_for, trusted_proxies, clients)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd school_status_api && pytest tests/test_auth.py -q`
Expected: PASS.

### Task 3: Database Repository

**Files:**
- Create: `school_status_api/school_status_api/database.py`
- Create: `school_status_api/school_status_api/repository.py`
- Create: `school_status_api/tests/test_repository.py`

- [ ] **Step 1: Write failing repository tests**

Cover schema creation, upsert, lookup by `gid` returning multiple `zjhm`, lookup by `zjhm`, and updating an existing `zjhm`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd school_status_api && pytest tests/test_repository.py -q`
Expected: FAIL because database and repository modules do not exist.

- [ ] **Step 3: Implement minimal SQLAlchemy schema and repository**

Use a shared `identity_status` table with `gid`, `zjhm`, `ryzxztdm`, and `synced_at`. Use SQLAlchemy's dialect-specific upsert for PostgreSQL and SQLite test support.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd school_status_api && pytest tests/test_repository.py -q`
Expected: PASS.

### Task 4: Mongo Full Sync

**Files:**
- Create: `school_status_api/school_status_api/sync.py`
- Create: `school_status_api/tests/test_sync.py`

- [ ] **Step 1: Write failing sync tests**

Cover successful full-sync, skipping records missing `gid` or `zjhm`, and preserving old rows when source read fails.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd school_status_api && pytest tests/test_sync.py -q`
Expected: FAIL because sync module does not exist.

- [ ] **Step 3: Implement minimal sync code**

Implement `sync_from_collection(collection, repository, batch_size)` that reads only the three source fields and upserts valid records in batches.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd school_status_api && pytest tests/test_sync.py -q`
Expected: PASS.

### Task 5: FastAPI Routes

**Files:**
- Create: `school_status_api/school_status_api/main.py`
- Create: `school_status_api/tests/test_api.py`

- [ ] **Step 1: Write failing API tests**

Cover `/doc/api/health`, authenticated `by-gid`, authenticated `by-zjhm`, 404 responses, 401 missing token, and 403 disallowed IP.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd school_status_api && pytest tests/test_api.py -q`
Expected: FAIL because main app module does not exist.

- [ ] **Step 3: Implement minimal FastAPI app**

Create app factory with dependency-injected repository and client config. Mount routes exactly under `/doc/api/`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd school_status_api && pytest tests/test_api.py -q`
Expected: PASS.

### Task 6: Docker Compose Deployment

**Files:**
- Create: `school_status_api/Dockerfile`
- Create: `school_status_api/.env.example`
- Create: `docker-compose.school-status.yml`
- Modify: `school_status_api/school_status_api/main.py`

- [ ] **Step 1: Write a failing deployment smoke command**

Run: `docker compose -f docker-compose.school-status.yml config`
Expected: FAIL because the compose file does not exist.

- [ ] **Step 2: Add Dockerfile and compose stack**

Add `api` and `postgres` services. Use environment variables for database URL, MongoDB connection, sync schedule, trusted proxies, and client config path.

- [ ] **Step 3: Run deployment config validation**

Run: `docker compose -f docker-compose.school-status.yml config`
Expected: PASS.

### Task 7: Final Verification

**Files:**
- Modify as needed from previous tasks only.

- [ ] **Step 1: Run full test suite**

Run: `cd school_status_api && pytest -q`
Expected: PASS.

- [ ] **Step 2: Run compose validation**

Run: `docker compose -f docker-compose.school-status.yml config`
Expected: PASS.

- [ ] **Step 3: Check git status**

Run: `git status --short`
Expected: only intentional new API, compose, and plan files plus pre-existing untracked files.
