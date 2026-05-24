# PackRakk

PackRakk is a software supply-chain security dashboard. Enter a Docker image,
PackRakk uses **Syft**, **Grype**, and **Trivy** to generate an SBOM, find
vulnerabilities, rank them by risk, and display everything in a React dashboard.

The MVP answers four questions for any container image:

1. What packages are inside?
2. Which packages have known CVEs?
3. Which CVEs are most urgent?
4. What should the user do to fix them?

## Architecture

```
+-----------+        POST /api/scans         +---------------------+
|  Browser  | -----------------------------> |    FastAPI backend  |
| React+TS  | <----- polls scan status ----- |  (BackgroundTasks)  |
+-----------+                                +---------+-----------+
                                                       |
                                  syft / grype / trivy | subprocess
                                                       v
                                              +---------------+
                                              |  storage/...  |
                                              |  raw JSONs    |
                                              +---------------+
                                                       |
                                                 parsers
                                                       v
                                              +---------------+
                                              |   Postgres    |
                                              +---------------+
```

## Prerequisites

- Python 3.11+
- Node 20+
- PostgreSQL reachable from the backend host
- Scanner CLIs in `PATH`:
  - [Syft](https://github.com/anchore/syft) — `syft --version`
  - [Grype](https://github.com/anchore/grype) — `grype --version`
  - [Trivy](https://github.com/aquasecurity/trivy) — `trivy --version`

Quick install (Linux/macOS):

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

## Connecting to PostgreSQL

PackRakk reads `DATABASE_URL` (SQLAlchemy URL). Default points at the example
host in `packrakk_plan.md`:

```
postgresql+psycopg://appuser:<password>@10.0.20.2:5432/appdb
```

Verify connectivity first:

```bash
psql -h 10.0.20.2 -U appuser -d appdb
```

Then copy the example env and edit the password:

```bash
cp .env.example backend/.env
# edit backend/.env and set the real password in DATABASE_URL
```

> **Note:** never commit the real password. Use env vars or a secret manager.

## Run the backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e .
# from backend/, with .env loaded:
alembic upgrade head
uvicorn app.main:app --reload
```

The API lives at `http://localhost:8000/api`.

## Run the frontend

```bash
cd frontend
cp .env.example .env  # adjust VITE_API_BASE_URL if backend is on another host
npm install
npm run dev
```

Open <http://localhost:5173>.

## Run a test scan

In the dashboard, enter a name and a Docker image, e.g.:

```
nginx:latest
python:3.12-slim
node:20-bookworm
```

The scan is enqueued as a FastAPI background task. The detail page polls
status until `completed` or `failed`. Raw JSON reports (SBOM, Grype, Trivy)
are downloadable from the detail page.

## Health check

```bash
curl http://localhost:8000/api/health
```

Returns DB status and whether each scanner CLI is present.

## Project layout

```
backend/
  app/
    main.py           FastAPI factory + CORS + routers
    config.py         pydantic settings
    database.py       SQLAlchemy engine/session
    models.py         ORM models
    schemas.py        Pydantic response models
    crud.py           query helpers / summary builders
    scanner.py        subprocess execution of syft/grype/trivy
    risk.py           per-vuln and scan-level risk scoring
    parsers/          syft (CycloneDX), grype, trivy JSON parsers
    routers/          health, scans, reports
  alembic/            migrations
frontend/
  src/
    api.ts            typed fetch wrappers
    types.ts          TS types
    components/       UI building blocks
    pages/            Dashboard + ScanDetail
```

## Troubleshooting

- **`syft: ok missing`** in `/api/health` — install the scanner CLIs (see above)
  and make sure they're in the same PATH as the user running uvicorn.
- **Scan stuck in `running`** — check `backend` logs. The most common cause is
  the scanner timing out on a large image; raise
  `PACKRAKK_SCANNER_TIMEOUT_SECONDS`.
- **`alembic upgrade head` fails** — confirm `DATABASE_URL` and that the
  Postgres user has CREATE privileges on the target database.
- **CORS errors in browser** — set `BACKEND_CORS_ORIGINS` to include the
  frontend origin.
- **Backend can't pull docker images** — when running inside the backend
  container, mount the host docker socket (already wired in
  `docker-compose.yml`).

## What's intentionally NOT in the MVP

Auth, k8s scanning, GitHub Actions gate, alerts, PDF export, AI remediation
summaries. The plan in `packrakk_plan.md` lists nice-to-haves for after the
core flow works.
