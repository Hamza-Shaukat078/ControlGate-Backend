ControlGate Backend - Secure, Compliant, Assured
================================================

ControlGate is an automated application security and compliance platform for
security teams that need continuous OWASP ASVS validation. This backend scans
repositories and optional live targets, correlates automated evidence with
manual attestations, and produces actionable compliance results for the
ControlGate frontend.

The ASVS engine verifies a target codebase against the **full OWASP ASVS
5.0.0 catalog - all 3 verification levels (L1/L2/L3), 345 controls across
17 chapters** (`app/data/asvs_l1_controls.json`, `asvs_l2_controls.json`,
`asvs_l3_controls.json`), combining five independent detection modules into
a single per-control pass/fail/manual-review verdict:

| Detection module | Controls | What it checks |
|---|---|---|
| Taint engine + rule catalog (`semantic_engine/`, `queries/queries.json`) | 195 | AST/CFG/DFG static analysis and an 88-rule pattern catalog - injection, crypto, session/JWT handling, password policy, access control, etc. |
| Manual Attestation (`app/api/routes/attestations.py`) | 109 | Human-submitted answers for architecture/business-logic/documentation controls with no automatable signal, many cross-checked against live DAST findings via the hybrid-attestation bridge |
| Config Inspector (`app/domain/analysis/config_inspector.py`) | 32 | Parses `.env`, YAML, Dockerfile, and nginx/reverse-proxy config for HSTS, cookie flags, upload limits, charset, script-execution exposure |
| Dynamic Probe (`app/domain/analysis/dynamic_probe.py` + `app/domain/analysis/dast/`) | 8 tagged (broader live-DAST coverage feeds into hybrid-attestation controls above) | Opt-in, live checks against a deployed URL/session: TLS/HSTS/cert trust, SSRF (out-of-band collaborator confirmation), IDOR/BOLA, mass assignment, race conditions, JWT alg-confusion forgery, DOM-XSS, stored-XSS, reflected-XSS, redirect warnings, request smuggling, timing side-channels, WebRTC (DTLS/SRTP), signaling-server WebSocket fuzzing, padding-oracle, plus target discovery via a same-origin crawler, headless-browser (Chromium) crawling for JS-rendered SPAs, and OpenAPI/Swagger spec-driven discovery for API-only targets |
| Dependency Scanner (`app/services/dependency_scanner.py`) | 1 | Parses manifests/lockfiles (requirements.txt, package.json, package-lock.json, Pipfile.lock, pyproject.toml) and queries the OSV.dev API against a documented remediation SLA |

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
playwright install chromium  # Track C2 — headless-browser DAST crawling/DOM-XSS probe
```

2) Configure environment

Copy `.env` (already included) and adjust as needed:

```
ENV=dev
API_V1_STR=/api/v1
PROJECT_NAME=ControlGate API
BACKEND_CORS_ORIGINS=http://localhost:3000
DATABASE_URL=sqlite+aiosqlite:///./controlgate.db
# DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/controlgate
MONGO_HOST=localhost
MONGO_PORT=27017
MONGO_DB_NAME=controlgate
JWT_SECRET=change-me-super-secret
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_MINUTES=43200
DEFAULT_ADMIN_EMAIL=admin@controlgate.ai
DEFAULT_ADMIN_PASSWORD=admin123!
```

MongoDB is required - a `docker-compose.yml` with a ready `mongo:7` service
is included:

```powershell
docker compose up -d mongo
```

3) Run the server

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs. On startup the app seeds the full 345-control
ASVS catalog (L1+L2+L3) into the `asvs_controls` collection automatically
(`app/db/seed_asvs.py`, sourced from `app/data/asvs_l1_controls.json`,
`asvs_l2_controls.json`, `asvs_l3_controls.json`).

Default Credentials
-------------------

- Email: `admin@controlgate.ai`
- Password: `admin123!`

API Base Path
-------------

- All routes are under `/api/v1`.
- Health check: `GET /health`

Implemented Modules
-------------------

- **Auth** (`/auth`): register, login/logout (httpOnly cookie + JWT bearer), me, refresh, OAuth (Google/GitHub), forgot/reset-password
- **Dashboard** (`/dashboard`): summary, recent scans, notifications
- **Repositories** (`/repositories`): CRUD, branches, file listing, upload (ZIP/TAR up to 200MB, zip-slip/symlink-safe extraction)
- **Scans** (`/scans`): start (optionally with a live `target_url` to enable the Dynamic Probe + full DAST engine), `/ws/{scan_id}` WebSocket progress stream, status, logs, summary, cancel, list, delete, `/diff-files` (changed-files-only scan input from two git refs), `/discover-probes` (auto-discovers IDOR/mass-assignment probe candidates before a real scan runs)
- **Legacy direct-scan endpoint** (`/scan`, singular - `app/api/routes/scan.py`): standalone code-snippet scan + `/scan/demo` + `/scan/health`, predates the `/scans` workflow above; kept for direct/ad-hoc use, not part of the repo-based ASVS flow
- **Graphs** (`/graphs`): real AST/CFG/DFG/CPG evidence viewer, backed by the taint engine
- **ASVS Catalog** (`/asvs`): list controls, list chapters, get one control + its latest scan result, `/asvs/portfolio` cross-repo compliance dashboard (latest snapshot + trend per repo, portfolio-wide attestation coverage, controls failing across the most repos)
- **Attestations** (`/attestations`): scan-scoped manual-attestation work queue (`GET /attestations/scan/{scan_id}`), submit/list answers, upload evidence files - proof (evidence URL or notes) is mandatory on every submission
- **Reports** (`/reports`): list/get/export (JSON/CSV/SARIF/PDF), `/reports/{scan_id}/compliance?framework=asvs`, `/reports/compare` (diff two scan reports)
- **Export** (`/export/asvs-report`): ASVS compliance report as PDF
- **Admin** (`/admin`, admin role only): list users, change a user's role

Out of scope (removed): patch generation, sandbox/exploit execution, attack
surface mapping, kill-chain/MITRE mapping, benchmark/leaderboard tooling, and
the old OWASP-Top10/PCI/SOC2 compliance mapper - none of these serve ASVS
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
   `TestClient(app)` will fail in an environment with no MongoDB reachable -
   confirmed pre-existing, unrelated to the ASVS work. Tests added for the
   ASVS layer (`tests/unit/test_asvs_service.py`,
   `tests/integration/test_asvs_api.py`) route around this with a hand-rolled
   async-compatible fake DB and, for API routes, call the handler functions
   directly instead of going through the ASGI lifespan.
2. **`tests/integration/test_sample_app_scan.py`** runs the real pipeline
   against two curated fixture repos (`tests/fixtures/asvs_sample_apps/`) -
   one deliberately vulnerable, one clean - and is the test that actually
   exercises the whole detection stack together on a realistic multi-file
   app. It documents two known, accepted false-positive classes (client vs.
   server-side `fetch()` ambiguity in the SSRF rule; no in-function
   permission-guard awareness in the admin-route check) rather than masking
   them.

# controlgate-backend
Secure, compliant, assured.
