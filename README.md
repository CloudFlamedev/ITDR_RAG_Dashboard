# ITDR RAG Dashboard

An Identity Threat Detection and Response (ITDR) portfolio project that combines an interactive security dashboard with a retrieval-augmented generation (RAG) workflow for mapping threat narratives to MITRE ATT&CK techniques and surfacing related defensive knowledge from MITRE D3FEND.

The application is built with React/Vite, FastAPI, SQLAlchemy, PostgreSQL/Neon, pgvector, Hugging Face embeddings, Grok via xAI, and LangGraph.

> **Project status:** The repository contains the application code, knowledge-base ingestion scripts, database migration, tests, and design documentation. A successful local run or a passing test suite does not by itself prove that a production deployment, live AI-provider connection, or populated knowledge base is working. Follow the verification steps below before sharing a live demo.

## Contents

- [Architecture](#architecture)
- [Features](#features)
- [Technology stack](#technology-stack)
- [Repository structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Run locally](#run-locally)
- [Initialize the knowledge base](#initialize-the-knowledge-base)
- [Run tests](#run-tests)
- [API documentation](#api-documentation)
- [Deploy to Vercel](#deploy-to-vercel)
- [Security and demo-data notes](#security-and-demo-data-notes)
- [Troubleshooting](#troubleshooting)
- [Project documentation](#project-documentation)
- [Data sources and references](#data-sources-and-references)

## Architecture

```mermaid
flowchart TD
    User[Recruiter / Analyst] --> UI[React + Vite Dashboard]
    UI -->|HTTPS / JSON| API[FastAPI REST API]

    API --> Services[Domain Services]
    Services --> DB[(Neon PostgreSQL)]
    Services --> Graph[LangGraph Threat Analysis Workflow]

    subgraph KnowledgeIngestion[Knowledge-base initialization]
      ATTACK[MITRE ATT&CK STIX 2.1]
      D3FEND[MITRE D3FEND JSON-LD / @graph]
      Builder[Document Builder + Content Hash]
      Embed[Hugging Face Embedding API]
      ATTACK --> Builder
      D3FEND --> Builder
      Builder --> Embed
      Embed --> Vectors[(rag_documents + pgvector)]
      Builder --> DB
    end

    Graph --> Retrieval[Hybrid Retrieval]
    Retrieval --> Vectors
    Retrieval --> DB
    Graph -->|Grounded context and output schema| Grok[xAI Grok API]
    Grok --> Graph
    Graph -->|Report, citations, execution trace| DB
    Graph --> API
    API --> UI
```

### Threat-analysis flow

1. An analyst enters a threat advisory or selects a curated sample in the Threat Modeling Workspace.
2. FastAPI validates the request and invokes the LangGraph workflow.
3. The workflow extracts explicit ATT&CK/D3FEND identifiers and relevant indicators.
4. Retrieval combines exact ATT&CK-ID lookup, semantic search over indexed documents, and relational lookups for D3FEND mappings and detection coverage.
5. The workflow builds a prompt using retrieved context and asks Grok to generate a structured report.
6. The report is checked against a Pydantic schema and processed by the citation-validation stage.
7. The report, citations, and workflow trace are persisted in PostgreSQL and returned to React.

The application is designed to distinguish retrieved evidence, official mappings, environment-specific coverage records, and recommendations inferred by the model. Review the RAG walkthrough and validate real-provider behavior before relying on any generated analysis.

## Features

The frontend implements seven dashboard screens:

1. **Identity Resilience Dashboard** — coverage KPIs, tactic exposure, resilience visualization, and potential blind spots.
2. **ITDR Coverage Matrix** — identity/enterprise views, filters, mapped rules, and technique details.
3. **Identity Threat Exposure** — techniques grouped by attack phase and coverage status.
4. **Identity Threat Scenarios** — sample multi-stage scenarios and resilience indicators.
5. **Threat Intelligence Feeds** — bulletin listing and advisory ingestion.
6. **Threat Modeling Workspace** — advisory input, model options, workflow trace, report, and citations.
7. **Completed Intelligence Reports** — saved reports, detail view, and JSON/Markdown export.

Backend capabilities include:

- FastAPI routes with Pydantic request and response models.
- SQLAlchemy ORM models and Alembic schema migration.
- MITRE ATT&CK STIX and D3FEND ingestion services.
- Document construction with source metadata and SHA-256 content hashes.
- Hugging Face embedding generation and vector retrieval through PostgreSQL/pgvector.
- LangGraph stateful threat-analysis workflow with observable trace steps.
- Detection-rule coverage and report persistence.
- Health endpoints and API documentation.

## Technology stack

| Layer | Technology | Role |
|---|---|---|
| Frontend | React 18, JavaScript/JSX, Vite | Dashboard UI and client-side routing |
| Charts and icons | Recharts, Lucide React | Security visualizations and UI icons |
| API | Python 3.12, FastAPI, Pydantic v2 | HTTP endpoints and validation |
| ORM / migrations | SQLAlchemy 2.x, Alembic | Relational access and versioned schema |
| Database | Neon PostgreSQL | ATT&CK, D3FEND, feeds, rules, reports, and metadata |
| Vector search | pgvector | Embedding storage and cosine-distance retrieval |
| Embeddings | Hugging Face Inference API, `BAAI/bge-small-en-v1.5` | 384-dimensional document/query embeddings |
| LLM | xAI Grok via `langchain-xai` | Structured threat-report generation |
| Workflow | LangGraph | Stateful AI orchestration, conditional routing, and traceability |
| Tests | pytest | Backend tests for APIs, models, ingestion, retrieval, and workflow |

## Repository structure

```text
ITDR_RAG_Dashboard/
├── backend/
│   ├── alembic/                 # Database migrations
│   ├── app/
│   │   ├── ai/                  # LangGraph, nodes, prompts, output schemas and state
│   │   ├── api/                 # FastAPI routers
│   │   ├── core/                # Settings/configuration
│   │   ├── db/                  # SQLAlchemy base and session
│   │   ├── models/              # ORM models
│   │   └── services/            # Ingestion, dashboard, retrieval, embeddings, vector store
│   ├── data/                    # Local source files; raw JSON files are git-ignored
│   ├── scripts/
│   │   ├── sync_attack.py       # Loads a local ATT&CK STIX JSON file
│   │   ├── sync_d3fend.py       # Loads a local D3FEND JSON-LD file
│   │   ├── seed_demo_data.py    # Seeds demonstration coverage/scenario records
│   │   └── build_rag_index.py   # Builds/updates RAG documents and embeddings
│   ├── tests/                   # Backend pytest suite
│   ├── .env.example             # Backend configuration template
│   ├── alembic.ini
│   └── requirements.txt
├── docs/                        # Architecture, schema, API, RAG, LangGraph, interview docs
├── frontend/
│   ├── src/
│   │   ├── api/client.js        # Shared API client
│   │   ├── components/          # Reusable components
│   │   ├── context/             # Global filter/theme state
│   │   ├── screens/             # Seven dashboard screens
│   │   └── styles/              # CSS
│   ├── package.json
│   └── vite.config.js
├── .env.example                 # Root-level copy of the environment template
├── .gitignore
└── README.md
```

## Prerequisites

- Python 3.12 (Python 3.11 may also work with the declared dependencies; Python 3.12 is the intended version).
- Node.js 18 or newer and npm.
- A Neon PostgreSQL database for the hosted setup, or a compatible local PostgreSQL database for development.
- An xAI API key to call Grok.
- A Hugging Face token with access to the configured Inference API/provider for embeddings.
- Source files for ATT&CK and D3FEND before initializing the knowledge base.

## Configuration

Create the backend environment file:

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` and replace the placeholders:

```dotenv
APP_ENV=development
LOG_LEVEL=INFO
DEMO_MODE=true

# Neon PostgreSQL connection string; keep sslmode=require for Neon.
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@YOUR-NEON-HOST/DB_NAME?sslmode=require

# xAI Grok
XAI_API_KEY=your_xai_api_key
XAI_API_BASE=https://api.x.ai/v1
XAI_MODEL=grok-4.7
XAI_TIMEOUT_SECONDS=90

# Hugging Face embeddings
HF_TOKEN=your_huggingface_token
HF_EMBEDDING_MODEL=BAAI/bge-small-en-v1.5
EMBEDDING_DIMENSIONS=384
HF_TIMEOUT_SECONDS=60
EMBEDDING_BATCH_SIZE=16

# Paths are relative to the backend working directory.
ATTACK_STIX_FILE=./data/enterprise-attack.json
D3FEND_FILE=./data/d3fend.json
```

### Environment-variable notes

- `DATABASE_URL` must match the SQLAlchemy driver used by the project. The template expects `postgresql+psycopg://`.
- Confirm that the selected Grok model is available to your xAI API account. Change `XAI_MODEL` if your account or current API model catalog uses a different model identifier.
- `BAAI/bge-small-en-v1.5` is expected to produce 384-dimensional vectors. Keep `EMBEDDING_DIMENSIONS=384` consistent with the database schema and the embedding model.
- Keep API credentials exclusively in backend environment variables. Do not expose them as `VITE_*` variables.
- `.env` files are ignored by Git. Never commit real API keys, database passwords, or tokens.

## Run locally

### 1. Clone the repository

```bash
git clone https://github.com/CloudFlamedev/ITDR_RAG_Dashboard.git
cd ITDR_RAG_Dashboard
```

### 2. Set up the backend

```bash
cp backend/.env.example backend/.env
# Edit backend/.env with your credentials

cd backend
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Initialize PostgreSQL and apply migrations

For Neon, create/select your database in the Neon console and use its connection string in `backend/.env`. Enable pgvector using the Neon SQL Editor:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

Then, from the `backend/` directory with the virtual environment active:

```bash
alembic upgrade head
```

Use a disposable development database the first time you apply the migration. Do not run destructive schema operations against a database containing data you need to preserve.

### 4. Initialize the knowledge base

Follow [Initialize the knowledge base](#initialize-the-knowledge-base) to place the source files, then run the ingestion and indexing scripts.

### 5. Start FastAPI

From the `backend/` directory:

```bash
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

- API: <http://127.0.0.1:8000>
- Swagger UI: <http://127.0.0.1:8000/docs>
- ReDoc: <http://127.0.0.1:8000/redoc>
- Liveness: <http://127.0.0.1:8000/health>
- System status: <http://127.0.0.1:8000/api/system/status>

### 6. Start React/Vite

Open a second terminal at the repository root:

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server normally runs at <http://127.0.0.1:5173>. The existing Vite configuration proxies `/api` calls to `http://127.0.0.1:8000` during local development.

## Initialize the knowledge base

**Important:** The current `sync_attack.py` and `sync_d3fend.py` scripts read local files; they do not download source datasets automatically. Download or export the source files separately, validate them, then run the ingestion scripts. Raw JSON data is excluded from Git by `.gitignore` and should not be committed.

### 1. MITRE ATT&CK Enterprise STIX 2.1

Create the local data directory and download the official Enterprise ATT&CK bundle:

```bash
mkdir -p backend/data
curl -fL \
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json" \
  -o backend/data/enterprise-attack.json
```

Review the [official ATT&CK STIX data repository](https://github.com/mitre-attack/attack-stix-data) for release and format details. Record which release you used; object counts change as the dataset is updated.

### 2. MITRE D3FEND

Get the official D3FEND ontology/export from [MITRE D3FEND Resources](https://d3fend.mitre.org/resources/). The current importer expects a JSON/JSON-LD document whose top-level object contains an `@graph` array. Save a compatible export as:

```text
backend/data/d3fend.json
```

If the downloaded D3FEND resource uses a different format, transform it deliberately or update the importer before running ingestion. Do not rename an unrelated file to `d3fend.json` and assume it is compatible.

### 3. Run ingestion and indexing

From the backend directory with the virtual environment active:

```bash
cd backend
source .venv/bin/activate

python scripts/sync_attack.py
python scripts/sync_d3fend.py
python scripts/seed_demo_data.py
python scripts/build_rag_index.py
```

What each command does:

- `sync_attack.py` parses the local ATT&CK STIX bundle and upserts tactics, techniques, software/groups, procedures, and related records.
- `sync_d3fend.py` parses the local D3FEND JSON-LD graph and imports defensive techniques and supported ATT&CK-to-D3FEND relationships.
- `seed_demo_data.py` adds sample detection rules and threat scenarios for dashboard demonstration. These are not live integrations with security products.
- `build_rag_index.py` builds semantic documents and stores/reconciles their embeddings in `rag_documents`.

The index builder uses content hashes to avoid re-embedding unchanged documents. A first index build can make many Hugging Face requests and may take time or hit provider limits. Run it as a separate initialization task, not as part of FastAPI startup or a Vercel deployment build.

### 4. Verify the knowledge base

Open <http://127.0.0.1:8000/api/system/status> after the backend starts and confirm the database, pgvector, provider configuration, and knowledge-base counts. Also use the RAG search endpoint via Swagger UI to run a real retrieval query.

**Embedding warning:** The current embedding service can generate deterministic pseudo-embeddings when Hugging Face is not configured or repeated provider requests fail. These are a development fallback, not genuine semantic embeddings. For a valid RAG demonstration, configure Hugging Face successfully and rebuild the index with real embeddings. Do not mix fallback pseudo-embeddings and genuine model embeddings in the same searchable index.

## Run tests

The backend test suite is under `backend/tests/`. Run it from the backend directory:

```bash
cd backend
source .venv/bin/activate
pytest -v
```

Build the frontend separately:

```bash
cd frontend
npm install
npm run build
```

Run these commands locally or in CI and inspect the actual output. Tests using mocked providers or local fixtures do not validate live xAI/Hugging Face access, deployed routing, or the full state of a production Neon database.

## API documentation

The interactive API reference is available at `/docs` when FastAPI is running. Main route groups include:

- `GET /health` — lightweight liveness check.
- `GET /api/system/status` — database, pgvector, provider configuration, and knowledge-base telemetry.
- `/api/reports/*` — dashboard metrics and threat exposure/scenarios.
- `/api/coverage-matrix` — coverage matrix and technique detail.
- `/api/identity/*` and `/api/twin/feeds/ingest` — feed/bulletin features.
- `/api/threats/*` — samples, threat analysis, and saved reports.
- `/api/rag/*` — retrieval diagnostics and RAG health.

Consult [`docs/API_CONTRACTS.md`](docs/API_CONTRACTS.md) and Swagger UI for the exact request/response schemas. Swagger UI is the source of truth for the routes registered by the running application.

## Deploy to Vercel

Vercel supports FastAPI through its Python runtime. For this repository layout, the simplest Vercel setup to manage is **two Vercel projects connected to the same GitHub repository**: one project for `frontend/` and one for `backend/`. This lets each part keep its own build settings and environment variables. See the official [FastAPI on Vercel guide](https://vercel.com/kb/guide/ship-a-fastapi-app-on-vercel) and [Python runtime docs](https://vercel.com/docs/functions/runtimes/python).

> **Deployment readiness:** The current frontend API client uses a relative base URL and the local Vite proxy. Before deploying the frontend as its own Vercel project, update `frontend/src/api/client.js` to support a configured production API base URL (for example, `import.meta.env.VITE_API_BASE_URL`). The current backend CORS configuration also allows all origins with credentials; change it to an allowlist containing the deployed frontend origin before exposing the backend publicly.

### A. Deploy the backend

1. Import `CloudFlamedev/ITDR_RAG_Dashboard` into Vercel as a new project.
2. Set the project's **Root Directory** to `backend`.
3. Vercel should detect FastAPI from `requirements.txt` and the exported `app` in `app/main.py`. Confirm the build/runtime logs identify the FastAPI application correctly.
4. Add the server-side environment variables listed in [Configuration](#configuration) in the Vercel project settings: `DATABASE_URL`, `XAI_API_KEY`, `XAI_API_BASE`, `XAI_MODEL`, `HF_TOKEN`, `HF_EMBEDDING_MODEL`, `EMBEDDING_DIMENSIONS`, `HF_TIMEOUT_SECONDS`, `XAI_TIMEOUT_SECONDS`, `APP_ENV`, `DEMO_MODE`, and `LOG_LEVEL`.
5. Set source-file path variables only if the files are included and available at runtime. The standard serverless deployment should not depend on local mutable files for persistence; store ingested knowledge in Neon.
6. Deploy, then verify `/health`, `/docs`, and `/api/system/status` on the backend URL.

### B. Deploy the frontend

1. Create another Vercel project from the same repository.
2. Set the project's **Root Directory** to `frontend` and use the Vite framework preset.
3. Build command: `npm run build`. Output directory: `dist`.
4. Add `VITE_API_BASE_URL` set to the deployed backend origin, for example `https://your-itdr-api.vercel.app`, **after** the frontend API client has been updated to read this variable.
5. Deploy and open the frontend URL. Verify every screen, browser console, network requests, and direct navigation/refresh on React routes.

### C. Production checks

- Configure FastAPI CORS to allow the exact frontend origin(s). Do not combine `allow_origins=["*"]` with `allow_credentials=True` for a public deployment.
- Keep Grok, Hugging Face, and Neon secrets only in backend environment variables.
- Apply Alembic migrations to the intended Neon database and verify that pgvector is enabled and the `rag_documents` column/index use a consistent vector type.
- Populate the knowledge base before demonstrating semantic RAG; don't run large ingestion/indexing batches during normal API startup.
- Test the complete threat-analysis endpoint with a small advisory, and verify response time against Vercel's function duration limits. External LLM and embedding calls can make a workflow exceed serverless limits.
- Add access controls and rate limits before allowing unrestricted public use of endpoints that invoke paid API services or write to the database.
- If analysis regularly exceeds Vercel's request duration limits, move the long-running workflow to a background worker or conventional web service while keeping the frontend on Vercel.

## Security and demo-data notes

- `DEMO_MODE=true` is the default. Check the UI and API output to distinguish demonstration records from actual security telemetry.
- `seed_demo_data.py` inserts example rules/scenarios. These do not mean CrowdStrike, Defender for Identity, Okta, Wiz, or other products are connected to live production accounts.
- The feed-source list currently contains configured/static demonstration entries. Do not present the listed statuses as live synchronization proof unless real connectors have been implemented and verified.
- Feed URL validation includes SSRF checks, but validate and test all external-fetch behavior before exposing feed ingestion publicly.
- The report generation flow has fallback synthesis behavior when the Grok key is missing or a provider call fails. Inspect the returned `model_provider` and trace metadata so a synthesized fallback is not described as a live Grok response.
- Review citation validation before describing it as a strict zero-hallucination guarantee. The current implementation should be tested to ensure every output citation ID is checked against the retrieved source set.
- `.env` and raw source data are excluded from Git. Confirm with `git status` before committing changes.

## Troubleshooting

### Database connection fails

- Verify the Neon hostname, role, password, database name, and `sslmode=require`.
- Confirm the URL prefix matches the configured driver, typically `postgresql+psycopg://`.
- Check that the database is reachable and credentials have not been rotated.

### pgvector shows as unavailable

Run this in the target Neon database:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
SELECT extname FROM pg_extension WHERE extname = 'vector';
```

Confirm migrations have been applied to the same database referenced by `DATABASE_URL`.

### ATT&CK or D3FEND ingestion fails

- Confirm the files exist at `backend/data/enterprise-attack.json` and `backend/data/d3fend.json`.
- Run the commands from the `backend/` directory, because the configured file paths are relative to the current working directory.
- Check the expected formats: ATT&CK STIX bundle with a `type: "bundle"` and `objects` array; D3FEND JSON-LD with an `@graph` array.

### RAG returns poor results

- Confirm Hugging Face provider access is valid and its model output dimensions match 384.
- Rebuild the index after the real embedding provider is configured.
- Confirm the stored embeddings were produced by the same model configured for queries.
- Check the RAG search response and source metadata before changing thresholds.

### Frontend displays API/network errors

- Locally, confirm FastAPI runs on port 8000 and Vite on port 5173.
- In Vercel, confirm the frontend API base URL points to the deployed backend and is read by the API client.
- Verify CORS origins and inspect browser Network/Console messages.

## Project documentation

- [System Architecture](docs/ARCHITECTURE.md) — component responsibilities and request/data flow.
- [Database Schema](docs/DATABASE_SCHEMA.md) — ORM entities, relationships, and schema details.
- [API Contracts](docs/API_CONTRACTS.md) — endpoints and payload contracts.
- [RAG Retrieval Walkthrough](docs/RAG_WALKTHROUGH.md) — document construction, embeddings, retrieval, and grounding.
- [LangGraph Workflow](docs/LANGGRAPH_FLOW.md) — state, nodes, routing, and trace behavior.
- [Implementation Plan](docs/IMPLEMENTATION_PLAN.md) — phased implementation notes.
- [Interview Preparation Guide](docs/INTERVIEW_GUIDE.md) — topics for explaining the platform.

## Data sources and references

- [MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
- [Official ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data)
- [MITRE D3FEND Resources](https://d3fend.mitre.org/resources/)
- [xAI API Documentation](https://docs.x.ai/)
- [Hugging Face Inference Providers](https://huggingface.co/docs/inference-providers/index)
- [Neon PostgreSQL](https://neon.tech/docs)
- [pgvector](https://github.com/pgvector/pgvector)
- [FastAPI on Vercel](https://vercel.com/kb/guide/ship-a-fastapi-app-on-vercel)
- [Vercel Python Runtime](https://vercel.com/docs/functions/runtimes/python)

## License

The repository indicates an MIT License. Review and include the corresponding `LICENSE` file in the repository so the license terms are distributed with the source.
