VULCAN Backend — ASVS 5.0.0 Level 1 Verification Engine
========================================================

This backend verifies a target codebase against the **70 OWASP ASVS 5.0.0
Level 1 requirements**, combining four independent detection modules into a
single per-control pass/fail/manual-review verdict:

| Detection module | Controls | What it checks |
|---|---|---|
| Taint engine + rule catalog (`semantic_engine/`, `queries/queries.json`) | 50 | AST/CFG/DFG static analysis and an 88-rule pattern catalog — injection, crypto, session/JWT handling, password policy, access control, etc. |
| Config Inspector (`app/domain/analysis/config_inspector.py`) | 5 | Parses `.env`, YAML, Dockerfile, and nginx/reverse-proxy config for HSTS, cookie flags, upload limits, charset, script-execution exposure |
| Dependency Scanner (`app/services/dependency_scanner.py`) | 1 | Parses manifests/lockfiles (requirements.txt, package.json, package-lock.json, Pipfile.lock, pyproject.toml) and queries the OSV.dev API against a documented remediation SLA |
| Dynamic Probe (`app/domain/analysis/dynamic_probe.py`) | 4 | Opt-in, live checks against a deployed URL: TLS version, HTTPS enforcement, certificate trust, live HSTS header, `.git`/`.svn` exposure |
| Manual Attestation (`app/api/routes/attestations.py`) | 10 | Human-submitted answers for architecture/business-logic/documentation controls with no automatable signal |

`app/services/asvs_service.py` merges all five sources into one
`ASVSControlResult` per control and aggregates them into the compliance
summary the frontend (ControlGate) consumes.

Quickstart (Windows PowerShell)
--------------------------------

1) Create venv and install dependencies

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt
```

2) Configure environment

Copy `.env` (already included) and adjust as needed:

```
ENV=dev
API_V1_STR=/api/v1
PROJECT_NAME=VULCAN API
BACKEND_CORS_ORIGINS=http://localhost:3000
DATABASE_URL=sqlite+aiosqlite:///./vulcan.db
# DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/vulcan
MONGO_HOST=localhost
MONGO_PORT=27017
MONGO_DB_NAME=vulcan
JWT_SECRET=change-me-super-secret
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_MINUTES=43200
DEFAULT_ADMIN_EMAIL=admin@vulcan.ai
DEFAULT_ADMIN_PASSWORD=admin123!
```

MongoDB is required — a `docker-compose.yml` with a ready `mongo:7` service
is included:

```powershell
docker compose up -d mongo
```

3) Run the server

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs. On startup the app seeds the 70-control
ASVS catalog into the `asvs_controls` collection automatically
(`app/db/seed_asvs.py`, sourced from `app/data/asvs_l1_controls.json`).

Default Credentials
-------------------

- Email: `admin@vulcan.ai`
- Password: `admin123!`

API Base Path
-------------

- All routes are under `/api/v1`.
- Health check: `GET /health`

Implemented Modules
-------------------

- **Auth**: register, login, logout, me, refresh (JWT bearer), OAuth (Google/GitHub)
- **Dashboard**: summary, recent scans, notifications
- **Repositories**: CRUD, branches, upload (ZIP/TAR up to 200MB)
- **Scans**: start (optionally with a live `target_url` to enable the Dynamic Probe), status, logs, summary, cancel
- **Graphs**: real AST/CFG/DFG/CPG evidence viewer, backed by the taint engine
- **ASVS Catalog** (`/asvs/*`): list controls, list chapters, get one control + its latest scan result
- **Attestations** (`/attestations`): submit/list manual attestation answers, upload evidence files
- **Reports**: list/get/export (JSON/CSV/SARIF/PDF), `/reports/{scan_id}/compliance?framework=asvs`, `/export/asvs-report` (PDF)

Out of scope (removed): patch generation, sandbox/exploit execution, attack
surface mapping, kill-chain/MITRE mapping, benchmark/leaderboard tooling, and
the old OWASP-Top10/PCI/SOC2 compliance mapper — none of these serve ASVS
verification. See `CLAUDE.md`-adjacent history for the cleanup rationale if
reviving any of this is ever considered.

Testing
-------

```powershell
pytest
```

Two things worth knowing before trusting a "failing" test:

1. **This repo's mongomock version doesn't support `await db.x.find_one(...)`**
   (it returns a plain dict, which raises under `await`), and the app's
   startup lifespan needs a reachable MongoDB. Any test that spins up a real
   `TestClient(app)` will fail in an environment with no MongoDB reachable —
   confirmed pre-existing, unrelated to the ASVS work. Tests added for the
   ASVS layer (`tests/unit/test_asvs_service.py`,
   `tests/integration/test_asvs_api.py`) route around this with a hand-rolled
   async-compatible fake DB and, for API routes, call the handler functions
   directly instead of going through the ASGI lifespan.
2. **`tests/integration/test_sample_app_scan.py`** runs the real pipeline
   against two curated fixture repos (`tests/fixtures/asvs_sample_apps/`) —
   one deliberately vulnerable, one clean — and is the test that actually
   exercises the whole detection stack together on a realistic multi-file
   app. It documents two known, accepted false-positive classes (client vs.
   server-side `fetch()` ambiguity in the SSRF rule; no in-function
   permission-guard awareness in the admin-route check) rather than masking
   them.

# vulcan-backend
Ye shall not cheat :(
