# 🛡️ ITDR RAG Dashboard
### Enterprise Identity Threat Detection & Response with Agentic RAG

[![Frontend Deployment](https://img.shields.io/badge/Vercel-Frontend_Live-black?logo=vercel)](https://itdr-rag-dashboard.vercel.app)
[![Backend API](https://img.shields.io/badge/Render-FastAPI_Live-46e3b7?logo=render)](https://itdr-rag-dashboard.onrender.com/docs)
[![Database](https://img.shields.io/badge/Neon-PostgreSQL_+_pgvector-00e599?logo=postgresql)](https://neon.tech)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Project Overview

### What is this project?
The **ITDR RAG Dashboard** is an enterprise cybersecurity intelligence platform that ingests raw, unstructured cyber threat narratives (such as CISA advisories, incident notes, or security blogs) and **automatically extracts attack techniques, maps them to MITRE ATT&CK®, and recommends verified defensive countermeasures from MITRE D3FEND™**.

### Why is this needed?
When a new threat or security incident occurs, Security Operations Center (SOC) analysts and threat hunters face three critical questions:
1. **"What techniques is the attacker using?"** *(e.g., Kerberoasting, Token Theft, MFA Fatigue)*
2. **"Are our current detection rules covering these techniques?"**
3. **"What specific countermeasures should we implement right now to stop them?"**

Manually reading lengthy threat reports to map techniques and research defenses takes **hours**. Moreover, asking general-purpose AI (like standard ChatGPT) often leads to **hallucinated attack IDs and generic advice**.

This platform solves both challenges by combining **LangGraph Agentic workflows** with **authoritative, real-time vector retrieval (`pgvector`)** over **868 MITRE ATT&CK techniques** and **466 MITRE D3FEND countermeasures** stored in PostgreSQL.

---

### How It Works (In 3 Simple Steps)

```
  1. INPUT ANY ADVISORY              2. RETRIEVE & GROUND                 3. ACTIONABLE DEFENSE
┌─────────────────────────┐        ┌─────────────────────────────┐      ┌─────────────────────────────┐
│ Paste any raw incident  │  ────► │ Semantic search & vector    │ ───► │ Instant structured report:  │
│ report, blog, or CISA   │        │ retrieval via pgvector;     │      │ - MITRE ATT&CK mappings     │
│ advisory (even without  │        │ cross-encoder reranks the   │      │ - Mapped D3FEND defenses    │
│ explicit TTP IDs)       │        │ top defensive techniques    │      │ - Coverage gap analysis     │
└─────────────────────────┘        └─────────────────────────────┘      │ - Step-by-step mitigations  │
                                                                        └─────────────────────────────┘
```

- 🎯 **No TTP IDs Required**: Even if an advisory never mentions technique IDs (e.g. *"attackers requested Kerberos TGS tickets for offline password cracking"*), the semantic search engine immediately identifies **`T1558.003 (Kerberoasting)`**.
- 🛡️ **Zero-Hallucination Grounding**: Every recommended defense is strictly linked to verified MITRE D3FEND ontology components and database citations.
- 📱 **Mobile & Desktop SOC Dashboard**: Includes a complete interactive dashboard with 7 security views (Resilience, Matrix, Threat Exposure, Scenarios, Feeds, Modeling Workspace, and Reports) and a responsive mobile slide-out navigation drawer.

---

## 🚀 Live Deployments

| Component | Platform | Status | Live Link |
| :--- | :--- | :---: | :--- |
| **Frontend Web App** | Vercel | 🟢 Live | [itdr-rag-dashboard.vercel.app](https://itdr-rag-dashboard.vercel.app) |
| **Backend REST API** | Render | 🟢 Live | [itdr-rag-dashboard.onrender.com](https://itdr-rag-dashboard.onrender.com) |
| **Interactive API Docs** | Swagger UI | 🟢 Live | [itdr-rag-dashboard.onrender.com/docs](https://itdr-rag-dashboard.onrender.com/docs) |
| **Database & Vector Store** | Neon Cloud | 🟢 Active | PostgreSQL 16 + native `pgvector(384)` |

---

## Contents

- [Project Overview](#-project-overview)
- [Live Deployments](#-live-deployments)
- [System Architecture](#️-system-architecture)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Run Locally](#run-locally)
- [Initialize the Knowledge Base](#initialize-the-knowledge-base)
- [Run Tests](#run-tests)
- [API Documentation](#api-documentation)
- [Cloud Deployment](#cloud-deployment-architecture)
- [Security and Demo-Data Notes](#security-and-demo-data-notes)
- [Troubleshooting](#troubleshooting)
- [Project Documentation](#project-documentation)
- [Data Sources and References](#data-sources-and-references)

---

## 🏗️ System Architecture

### High-Level Architecture Overview

The system is organized into four clean, decoupled tiers:

```mermaid
flowchart TD
    %% TIER 1: CLIENT & DASHBOARD
    subgraph Tier1 ["1. Presentation Layer (Vercel)"]
        User["👤 Security Analyst"]
        Dashboard["💻 React 18 + Vite SPA<br/><i>(Interactive Security Dashboard & Mobile Drawer)</i>"]
        User <-->|HTTPS| Dashboard
    end

    %% TIER 2: BACKEND & ORCHESTRATION
    subgraph Tier2 ["2. API & Orchestration Layer (Render)"]
        API["⚡ FastAPI REST Gateway"]
        Workflow["🧠 LangGraph Threat Engine<br/><i>(Extraction → Retrieval → Rerank → Synthesis)</i>"]
        Dashboard <-->|REST API / JSON| API
        API <--> Workflow
    end

    %% TIER 3: AI SERVICES
    subgraph Tier3 ["3. External AI Services"]
        Embedder["🔍 Jina AI / Hugging Face<br/><i>(Embeddings & Cross-Encoder Reranker)</i>"]
        LLM["🤖 Groq / xAI LLM<br/><i>(Fast Structured Report Synthesis)</i>"]
    end

    %% TIER 4: DATABASE & KNOWLEDGE BASE
    subgraph Tier4 ["4. Knowledge Base & Vector Store (Neon Cloud)"]
        RelationalDB[("🗄️ PostgreSQL Relational DB<br/><i>(Detection Rules, Feeds, Incident Reports)</i>")]
        VectorStore[("📐 pgvector Vector Store (384-dim)<br/><i>(868 MITRE ATT&CK + 466 MITRE D3FEND)</i>")]
    end

    %% FLOW CONNECTIONS
    Workflow <-->|Generate Query Embedding| Embedder
    Workflow <-->|Cosine Similarity Search| VectorStore
    Workflow <-->|Fetch Rules & D3FEND Mappings| RelationalDB
    Workflow <-->|Grounded Context & Prompt| LLM
```

### 🔄 Threat-Analysis Pipeline (How It Works)

When an analyst submits a threat narrative, it flows through a 5-step automated pipeline:

```mermaid
flowchart LR
    A["📄 1. Input<br/><i>Raw Threat Narrative</i>"] 
    --> B["🔍 2. Hybrid Retrieval<br/><i>Exact TTP IDs + pgvector search</i>"]
    --> C["⚖️ 3. Reranking<br/><i>Cross-encoder scores top defenses</i>"]
    --> D["🤖 4. LLM Synthesis<br/><i>Grounded in retrieved MITRE data</i>"]
    --> E["📊 5. Verified Output<br/><i>Structured report with citations</i>"]

    style A fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc
    style B fill:#1e293b,stroke:#06b6d4,stroke-width:2px,color:#f8fafc
    style C fill:#1e293b,stroke:#818cf8,stroke-width:2px,color:#f8fafc
    style D fill:#1e293b,stroke:#a855f7,stroke-width:2px,color:#f8fafc
    style E fill:#1e293b,stroke:#10b981,stroke-width:2px,color:#f8fafc
```

1. **Input Ingestion**: The analyst pastes a security advisory or selects a pre-loaded threat narrative (e.g., Midnight Blizzard, Scatter Swine).
2. **Hybrid Retrieval**: The engine extracts explicit MITRE IDs (`Txxxx`) and simultaneously performs semantic vector search via `pgvector` to catch behaviors described without formal IDs.
3. **Cross-Encoder Reranking**: Jina AI reranks the retrieved ATT&CK techniques and D3FEND countermeasures to ensure only the most relevant security knowledge is passed to the LLM.
4. **Grounded Synthesis**: The LLM (Groq / xAI) receives the verified context and generates a structured report following strict Pydantic schemas.
5. **Validation & Persistence**: Every citation is verified against the database before saving the report to PostgreSQL and streaming it back to the dashboard.

---

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
- Hugging Face / Jina embedding generation and vector retrieval through PostgreSQL/pgvector.
- LangGraph stateful threat-analysis workflow with observable trace steps.
- Detection-rule coverage and report persistence.
- Health endpoints and API documentation.

## Technology stack

| Layer | Technology | Role |
| :--- | :--- | :--- |
| **Frontend UI** | React 18, Vite, Lucide React, Recharts | Responsive SOC analyst dashboard with mobile drawer |
| **Frontend Hosting** | Vercel | Global Edge CDN hosting for Single Page Application |
| **API Backend** | Python 3.12, FastAPI, Pydantic v2 | High-concurrency REST endpoints and schema validation |
| **Backend Hosting** | Render Web Service | Cloud container runtime for FastAPI backend |
| **Orchestration** | LangGraph, LangChain | Stateful multi-stage AI reasoning workflow & execution trace |
| **LLM Inference** | Groq / xAI (`qwen/qwen3.8-27b`, Grok) | Ultra-fast structured security report generation |
| **Embeddings & Reranking** | Jina AI / Hugging Face (`bge-small-en-v1.5`) | 384-dimensional vector embeddings and cross-encoder |
| **Relational Database** | Neon Serverless PostgreSQL | Relational storage for 868 ATT&CK, 466 D3FEND, rules & reports |
| **Vector Search** | `pgvector` extension | Fast cosine-distance vector similarity search |
| **Testing** | pytest | Comprehensive automated backend test suite |

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

## Cloud Deployment Architecture

The platform uses a production-ready, decoupled multi-cloud architecture:

```
┌──────────────────────────────────────┐       ┌──────────────────────────────────────────────┐
│           Vercel (Frontend)          │       │           Render (Backend API)               │
│  - React 18 + Vite (SPA)             │       │  - Python 3.12 + FastAPI + Uvicorn           │
│  - Instant Global Edge CDN           │ ───►  │  - LangGraph Threat Engine                   │
│  - Environment: VITE_API_URL         │ HTTP  │  - Jina AI Cross-Encoder + Groq LLM          │
└──────────────────────────────────────┘       └──────────────────────┬───────────────────────┘
                                                                      │ TLS (sslmode=require)
                                                                      ▼
                                                       ┌──────────────────────────────┐
                                                       │    Neon Cloud PostgreSQL     │
                                                       │  - Native pgvector(384)      │
                                                       │  - 868 ATT&CK + 466 D3FEND   │
                                                       └──────────────────────────────┘
```

### A. Deploy Backend to Render (1-Click or Web Service)

1. Create a new **Web Service** on [Render](https://render.com) connected to your GitHub repository.
2. The repository includes a root `render.yaml` blueprint. If configuring manually:
   - **Root Directory**: `backend`
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
3. Configure Environment Variables in Render:
   - `DATABASE_URL`: `postgresql+psycopg://...neon.tech/neondb?sslmode=require`
   - `XAI_API_KEY`: *(your Groq or xAI API key)*
   - `XAI_API_BASE`: `https://api.groq.com/openai/v1`
   - `XAI_MODEL`: `qwen/qwen3.8-27b`
   - `JINA_API_KEY`: *(your Jina AI key)*
   - `JINA_EMBEDDING_MODEL`: `jina-embeddings-v5-text-small`
   - `JINA_RERANK_MODEL`: `jina-reranker-v2-base-multilingual`
   - `RERANK_ENABLED`: `true`
   - `EMBEDDING_DIMENSIONS`: `384`
   - `APP_ENV`: `production`
   - `DEMO_MODE`: `false`
4. Deploy and verify the live API at `https://your-api.onrender.com/docs`.

### B. Deploy Frontend to Vercel

1. Import `CloudFlamedev/ITDR_RAG_Dashboard` into [Vercel](https://vercel.com) as a new project.
2. Configure project settings:
   - **Root Directory**: `frontend`
   - **Framework Preset**: `Vite`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
3. In **Environment Variables**, add:
   - **`VITE_API_URL`**: `https://your-api.onrender.com`
4. Click **Deploy**. Vercel will build the frontend and serve it globally on high-speed CDN edges.

### C. Free-Tier Keep-Alive Ping (Optional)

To eliminate Render's 15-minute inactivity cold-starts on the free tier:
- Set up a free 10-minute automated ping on [cron-job.org](https://cron-job.org) targeting `GET https://your-api.onrender.com/health`.


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
