# Identity Threat Detection & Response (ITDR) Platform

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.4-646CFF?logo=vite&logoColor=white)](https://vitejs.dev)
[![PostgreSQL / Neon](https://img.shields.io/badge/Neon-pgvector-00E599?logo=postgresql&logoColor=white)](https://neon.tech)
[![xAI Grok](https://img.shields.io/badge/xAI-Grok--4.7-000000?logo=x&logoColor=white)](https://docs.x.ai)
[![Hugging Face](https://img.shields.io/badge/Hugging%20Face-bge--small--en--v1.5-FFD21E?logo=huggingface&logoColor=black)](https://huggingface.co)
[![LangGraph](https://img.shields.io/badge/LangGraph-11--Node%20Workflow-FF4F00?logo=diagram-project&logoColor=white)](https://langchain-ai.github.io/langgraph/)
[![Tests](https://img.shields.io/badge/Tests-21%20Passed-brightgreen)](tests/)

An enterprise-grade, interview-ready **Identity Threat Detection & Response (ITDR)** platform built to quantify defensive coverage, ingest cyber threat intelligence (CTI), and perform explainable, grounded threat modeling.

Developed according to the **ITDR Functional Specification Document v2.0**, featuring official **MITRE ATT&CK® Enterprise STIX 2.1** and **MITRE D3FEND™** ontology ingestion, **Neon PostgreSQL + pgvector** vector storage, and an **11-Node LangGraph GenAI Agent** powered by **xAI Grok-4.7**.

---

## Architecture Highlights

```
┌────────────────────────────────────────────────────────────────────────┐
│                   React 18 + Vite Web Application                      │
│       7 Screens • Global Filter Context • Accessible Dark/Light Mode   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ REST / JSON (Central API Client)
┌───────────────────────────────────▼────────────────────────────────────┐
│                       FastAPI Application Layer                        │
│   • /health & /api/system/status Telemetry                             │
│   • /api/reports/identity-resilience & threat-exposure                 │
│   • /api/coverage-matrix (Identity vs. Enterprise, Tool Toggles)       │
│   • /api/identity/bulletins & /api/twin/feeds/ingest (SSRF Protected)  │
│   • /api/threats/analyze (Stateful GenAI Threat Modeling)              │
│   • /api/rag/search (Hybrid Indicator + Semantic Vector Diagnostics)   │
└──────────────┬───────────────────────────────┬─────────────────────────┘
               │                               │
┌──────────────▼──────────────┐ ┌──────────────▼─────────────────────────┐
│     Hybrid Retrieval        │ │      11-Node LangGraph Workflow        │
│  • Regex T-ID Extraction    │ │  1. Input Validation                   │
│  • Exact ID 1.0 Score Boost │ │  2. Indicator Extraction               │
│  • PgVector Cosine (<=>)    │ │  3. Retrieval Query Synthesis          │
│  • Relational D3FEND Joins  │ │  4. ATT&CK Context Retrieval           │
│  • Confidence Gating        │ │  5. D3FEND Countermeasure Retrieval    │
└──────────────┬──────────────┘ │  6. Score Fusion & Deduplication       │
               │                │  7. Grounded Prompt Assembly           │
┌──────────────▼──────────────┐ │  8. Grok-4.7 Structured Generation     │
│   Neon PostgreSQL + pgvector│ │  9. Anti-Hallucination Verification    │
│  • 17 Relational Tables     │ │ 10. Resilient Degraded Exception Node  │
│  • 1,679 RAG Chunks         │ │ 11. Transactional DB Persistence       │
│  • 384-dim HNSW Cosine Index│ └────────────────────────────────────────┘
└─────────────────────────────┘
```

---

## Specification Screens Implemented

1. **Identity Resilience Dashboard** (`/`):
   - Executive Identity Coverage Ring Gauge.
   - ATT&CK Tactic Exposure Bars (Covered vs. Exposed technique counts).
   - Resilience 2D Quadrant Scatter Plot (Impact vs. Likelihood).
   - Critical Blind Spots (high-risk techniques without mapped detection rules).
   - Dynamic KPIs derived live from PostgreSQL records.

2. **ITDR Coverage Matrix** (`/coverage-matrix`):
   - Switchable **Identity View** (identity-relevant TTPs) vs. **Enterprise View** (full ATT&CK catalogue).
   - Tool Toggles (**CrowdStrike**, **Defender for Identity**, **Okta**, **Wiz**, **In-House**, **Third-Party**).
   - Technique Status Filter (`All`, `Covered`, `Uncovered`).
   - Interactive Slide-Out **Technique Detail Drawer** displaying mapped rules, query syntax, detection depth, and D3FEND countermeasures.

3. **Identity Threat Exposure** (`/threat-exposure`):
   - Sighted TTPs grouped by Attack Phase (Initial Access, Credential Dumping, Privilege Escalation).
   - Ratio of sighted techniques actively covered by production rules.

4. **Identity Threat Scenarios** (`/threat-scenarios`):
   - Composite multi-stage identity attack scenarios (e.g. *Scattered Spider Session Hijacking*, *DCSync Domain Compromise*).
   - Scenario resilience scoring with interactive card list and quadrant mapping.

5. **Threat Intelligence Feeds** (`/feeds`):
   - Real-time CTI Bulletin table with severity badges and extracted T-IDs.
   - Manual feed synchronization trigger (`POST /api/identity/feeds/sync`).
   - **SSRF-Protected Ingestion Modal** (`POST /api/twin/feeds/ingest`) preventing loops, private IP traversal, and cloud metadata theft.

6. **Threat Modeling Workspace** (`/threat-modeling`):
   - **3-Step AI Analysis Journey**:
     1. Advisory Input (custom narrative or 1-click curated samples).
     2. Model Selection (Grok-4.7, temperature, retrieval parameters).
     3. Execution & Telemetry (interactive 11-step **Trace Stepper** + Structured Threat Report).
   - Executive summary, identified TTPs, recommended D3FEND defenses, and verified citations.

7. **Completed Intelligence Reports** (`/completed-reports`):
   - Searchable, auditable library of generated threat intelligence reports.
   - Comprehensive detail modal with full citation audit and trace logs.
   - Single-click **Markdown and JSON export**.

---

## Technology Stack

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Frontend** | React 18 + Vite | Vanilla JSX, CSS custom properties, responsive desktop/laptop layout |
| **Charts** | Recharts | Responsive Pie/Gauge rings, Tactic bar charts, 2D Scatter Quadrants |
| **Icons** | Lucide React | Minimalist, professional security operations iconography |
| **Backend API** | FastAPI + Pydantic v2 | Python 3.12, strict schema validation, async lifespan management |
| **ORM & DB** | SQLAlchemy 2.0 + Alembic | Declarative 17-table schema, transactional migration versioning |
| **Database** | Neon PostgreSQL + pgvector | Hosted PostgreSQL with native 384-dimensional vector cosine HNSW index |
| **LLM Provider** | xAI Grok (`grok-4.7`) | Structured threat modeling via `langchain-xai` (`ChatXAI`) |
| **Embeddings** | Hugging Face Inference API | `BAAI/bge-small-en-v1.5` (384-dimensional embeddings) |
| **Orchestration** | LangGraph 0.2+ | 11-node stateful workflow with explicit observable telemetry |
| **Testing** | pytest | 21 unit and integration tests covering API, models, RAG, and LangGraph |

---

## Quickstart & Local Setup

### Prerequisites
- Python 3.11 or 3.12
- Node.js 18+ and npm
- PostgreSQL 15+ (local) OR a free [Neon](https://neon.tech) cloud PostgreSQL database.

---

### Step 1: Clone and Configure Environment

```bash
git clone <repository_url> itdr-platform
cd itdr-platform

# Copy the backend environment template
cp backend/.env.example backend/.env
```

Edit `backend/.env` with your credentials:
```ini
# Database Connection (Neon or local PostgreSQL)
DATABASE_URL=postgresql+psycopg://postgres:postgres123@localhost:5432/itdr_platform

# xAI Grok API Configuration (https://docs.x.ai)
XAI_API_KEY=xai-your-api-key-here
XAI_MODEL=grok-4.7

# Hugging Face Inference API Configuration (https://huggingface.co/settings/tokens)
HF_TOKEN=hf_your_token_here
HF_EMBEDDING_MODEL=BAAI/bge-small-en-v1.5
EMBEDDING_DIMENSIONS=384

# Application Configuration
APP_ENV=development
DEMO_MODE=true
```

> [!NOTE]
> If `XAI_API_KEY` or `HF_TOKEN` are not provided, the platform automatically engages its **resilient offline synthesis mode**. The system clearly labels simulated records as `DEMO DATA` and reports provider status honestly in `GET /api/system/status`.

---

### Step 2: Backend Setup & Migrations

```bash
cd backend

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Alembic database migrations
alembic upgrade head
```

---

### Step 3: Ingest Knowledge Base & Build RAG Index

Run the synchronization scripts to ingest official MITRE ATT&CK STIX 2.1 data, D3FEND countermeasures, demo rules, and build the 1,679-document vector index:

```bash
# Ingest official Enterprise MITRE ATT&CK STIX 2.1 (867 techniques, 17k procedures)
python scripts/sync_attack.py

# Ingest official MITRE D3FEND ontology & defensive mappings
python scripts/sync_d3fend.py

# Seed enterprise detection rules (CrowdStrike, MDI, Okta, Wiz) and threat scenarios
python scripts/seed_demo_data.py

# Build the semantic RAG index into PostgreSQL / Neon
python scripts/build_rag_index.py
```

---

### Step 4: Run Tests

Execute the automated test suite to verify database schemas, STIX ingestion, hybrid retrieval, LangGraph execution, and API endpoints:

```bash
pytest -v
# Output: 21 passed in ~3.6s
```

---

### Step 5: Start Backend & Frontend

#### Terminal 1: Backend API
```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
*API Swagger Documentation*: [http://localhost:8000/docs](http://localhost:8000/docs)  
*System Health Telemetry*: [http://localhost:8000/api/system/status](http://localhost:8000/api/system/status)

#### Terminal 2: Frontend UI
```bash
cd frontend
npm install
npm run dev
```
*Web Application*: [http://localhost:5173](http://localhost:5173)

---

## Production Deployment to Neon

To deploy against a managed **Neon PostgreSQL** database with native **pgvector**:
1. Create a project in [Neon Console](https://console.neon.tech).
2. Enable pgvector in SQL Editor:
   ```sql
   CREATE EXTENSION IF NOT EXISTS vector;
   ```
3. Update `DATABASE_URL` in `backend/.env` with your Neon connection string (ensure `sslmode=require` is present).
4. Run `alembic upgrade head` and `python scripts/build_rag_index.py`.
5. The API detects Neon and automatically switches to native HNSW `<=>` cosine distance acceleration.

---

## In-Depth Documentation

For detailed architectural specifications, interview guides, and engineering deep dives, review the documentation in [`docs/`](docs/):

- 📐 [**System Architecture (`docs/ARCHITECTURE.md`)**](docs/ARCHITECTURE.md): Component diagrams, layer separation, data flow, and sequence diagrams.
- 🗄️ [**Database Schema (`docs/DATABASE_SCHEMA.md`)**](docs/DATABASE_SCHEMA.md): Complete ER diagram, 17 table specifications, and pgvector HNSW indexing.
- 🔌 [**API Contracts (`docs/API_CONTRACTS.md`)**](docs/API_CONTRACTS.md): Full REST endpoint specifications, request/response models, and SSRF security rules.
- 🔍 [**RAG Retrieval Walkthrough (`docs/RAG_WALKTHROUGH.md`)**](docs/RAG_WALKTHROUGH.md): Domain chunking, BGE-small embeddings, hybrid retrieval, and anti-hallucination engine.
- 🔄 [**LangGraph Workflow (`docs/LANGGRAPH_FLOW.md`)**](docs/LANGGRAPH_FLOW.md): 11-node state machine, state schema, observable telemetry, and exception handling.
- 🎯 [**Interview Preparation Guide (`docs/INTERVIEW_GUIDE.md`)**](docs/INTERVIEW_GUIDE.md): Q&A covering ITDR principles, Active Directory attack paths, pgvector vs. dedicated vector databases, and LLM grounding.

---

## License
MIT License. Built for enterprise cyber defense engineering and technical interview demonstration.
