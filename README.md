# 🛡️ ITDR RAG Dashboard
### Enterprise Identity Threat Detection & Response with Agentic RAG

[![Frontend Deployment](https://img.shields.io/badge/Vercel-Frontend_Live-black?logo=vercel)](https://itdr-rag-dashboard.vercel.app)
[![Backend API](https://img.shields.io/badge/Render-FastAPI_Live-46e3b7?logo=render)](https://itdr-rag-dashboard.onrender.com/docs)
[![Database](https://img.shields.io/badge/Neon-PostgreSQL_+_pgvector-00e599?logo=postgresql)](https://neon.tech)
[![AI Orchestration](https://img.shields.io/badge/LangGraph-Stateful_Agents-blueviolet)](https://github.com/langchain-ai/langgraph)
[![Observability](https://img.shields.io/badge/Langfuse-v3+_Telemetry-orange?logo=langfuse)](https://langfuse.com)
[![Evaluation](https://img.shields.io/badge/RAGAS-0.4.4_Collections-blue)](https://github.com/explodinggradients/ragas)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Project Overview

### What is this project?
The **ITDR RAG Dashboard** is an enterprise cybersecurity intelligence and threat response platform that ingests raw, unstructured cyber threat narratives (such as CISA advisories, incident response notes, or threat intelligence bulletins) and **automatically extracts adversary attack techniques, maps them to MITRE ATT&CK®, and recommends verified defensive countermeasures from MITRE D3FEND™**.

### Why is this needed?
When a critical identity incident occurs, Security Operations Center (SOC) analysts and threat hunters face three critical questions:
1. **"What techniques is the attacker using?"** *(e.g., Kerberoasting, Token Theft, MFA Fatigue, Golden SAML)*
2. **"Are our current detection rules covering these techniques?"**
3. **"What specific countermeasures should we implement right now to stop them?"**

Manually reading lengthy threat reports to map techniques and research defenses takes **hours**. Moreover, asking general-purpose AI (like standard ChatGPT) often leads to **hallucinated attack IDs and generic advice**.

This platform solves both challenges by combining **LangGraph Agentic workflows** with **authoritative, real-time vector retrieval (`pgvector`)** over **868 MITRE ATT&CK techniques** and **466 MITRE D3FEND countermeasures** stored in PostgreSQL, cross-encoder reranking, and continuous evaluation monitoring.

---

### How It Works (In 3 Simple Steps)

```text
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
- 📐 **Authoritative Taxonomy Validation**: Parent technique IDs do not automatically validate sub-technique support; every cited technique is verified against live database records.
- 📱 **Mobile & Desktop SOC Dashboard**: Includes an interactive dashboard with 8 security views (Resilience, Matrix, Threat Exposure, Scenarios, Feeds, Modeling Workspace, Reports, and Governance) with a responsive mobile navigation drawer.

---

## 🚀 Live Deployments

| Component | Platform | Status | Live Link |
| :--- | :--- | :---: | :--- |
| **Frontend Web App** | Vercel | 🟢 Live | [itdr-rag-dashboard.vercel.app](https://itdr-rag-dashboard.vercel.app) |
| **Backend REST API** | Render | 🟢 Live | [itdr-rag-dashboard.onrender.com](https://itdr-rag-dashboard.onrender.com) |
| **Interactive API Docs** | Swagger UI | 🟢 Live | [itdr-rag-dashboard.onrender.com/docs](https://itdr-rag-dashboard.onrender.com/docs) |
| **Database & Vector Store** | Neon Cloud | 🟢 Active | PostgreSQL 16 + native `pgvector(384)` |
| **Telemetry & Traces** | Langfuse Cloud | 🟢 Active | Distributed RAG tracing & span metrics |

---

## 📑 Contents

- [Project Overview](#-project-overview)
- [Live Deployments](#-live-deployments)
- [System Architecture](#️-system-architecture)
- [Three-Layer Evaluation & Observability Architecture](#-three-layer-evaluation--observability-architecture)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Run Locally](#run-locally)
- [Initialize the Knowledge Base](#initialize-the-knowledge-base)
- [Run Tests](#run-tests)
- [Run the Evaluation Pipeline](#run-the-evaluation-pipeline)
- [CI/CD & GitHub Actions Workflows](#cicd--github-actions-workflows)
- [API Documentation](#api-documentation)
- [Cloud Deployment](#cloud-deployment-architecture)
- [Security and Demo-Data Notes](#security-and-demo-data-notes)
- [Troubleshooting](#troubleshooting)
- [Project Documentation](#project-documentation)
- [License](#license)

---

## 🏗️ System Architecture

### High-Level Architecture Overview

The system is organized into four decoupled tiers with integrated evaluation and observability:

```mermaid
flowchart TD
    %% TIER 1: CLIENT & DASHBOARD
    subgraph Tier1 ["1. Presentation Layer (Vercel)"]
        User["👤 Security Analyst / Admin"]
        Dashboard["💻 React 18 + Vite SPA<br/><i>(Interactive SOC Dashboard & Mobile Drawer)</i>"]
        User <-->|HTTPS / Session Cookie| Dashboard
    end

    %% TIER 2: BACKEND & ORCHESTRATION
    subgraph Tier2 ["2. API & Orchestration Layer (Render / FastAPI)"]
        API["⚡ FastAPI REST Gateway<br/><i>(Argon2id, Session Store, HMAC CSRF, RBAC)</i>"]
        Workflow["🧠 LangGraph Threat Engine<br/><i>(Extraction → Hybrid Retrieval → Rerank → Synthesis)</i>"]
        Telemetry["📡 Langfuse v3+ Client<br/><i>(Masked telemetry, latency, token tracking)</i>"]
        Dashboard <-->|REST API / JSON| API
        API <--> Workflow
        Workflow --> Telemetry
    end

    %% TIER 3: AI SERVICES
    subgraph Tier3 ["3. AI & Model Providers"]
        Embedder["🔍 Jina AI / Hugging Face<br/><i>(384-dim Embeddings & Cross-Encoder Reranker)</i>"]
        LLM["🤖 Groq / xAI LLM<br/><i>(Qwen 2.5, GPT-OSS, Grok 4.7)</i>"]
        RAGAS["📊 RAGAS Collections Evaluator<br/><i>(Context Precision/Recall, Faithfulness, Relevancy)</i>"]
    end

    %% TIER 4: DATABASE & KNOWLEDGE BASE
    subgraph Tier4 ["4. Knowledge Base & Vector Store (Neon Cloud)"]
        RelationalDB[("🗄️ PostgreSQL 16 Relational DB<br/><i>(Users, Sessions, Audit Logs, Detection Rules, Reports)</i>")]
        VectorStore[("📐 pgvector (384-dim)<br/><i>(868 MITRE ATT&CK + 466 MITRE D3FEND)</i>")]
    end

    %% FLOW CONNECTIONS
    Workflow <-->|Generate Query Embedding| Embedder
    Workflow <-->|Cosine Similarity Search| VectorStore
    Workflow <-->|Fetch Rules & Mappings| RelationalDB
    Workflow <-->|Grounded Context & Prompt| LLM
    RAGAS <-->|Evaluate Quality| LLM
```

### 🔄 Threat-Analysis Pipeline Workflow

When an analyst submits a threat narrative, it flows through a 5-step automated LangGraph pipeline:

```mermaid
flowchart LR
    A["📄 1. Input<br/><i>Advisory Text</i>"] 
    --> B["🔍 2. Hybrid Retrieval<br/><i>Exact TTP IDs + pgvector</i>"]
    --> C["⚖️ 3. Cross-Encoder Rerank<br/><i>Jina Reranker scores candidates</i>"]
    --> D["🤖 4. LLM Synthesis<br/><i>Grounded structured report</i>"]
    --> E["📊 5. Verified Output<br/><i>Citations checked against DB</i>"]

    style A fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc
    style B fill:#1e293b,stroke:#06b6d4,stroke-width:2px,color:#f8fafc
    style C fill:#1e293b,stroke:#818cf8,stroke-width:2px,color:#f8fafc
    style D fill:#1e293b,stroke:#a855f7,stroke-width:2px,color:#f8fafc
    style E fill:#1e293b,stroke:#10b981,stroke-width:2px,color:#f8fafc
```

1. **Input Ingestion**: The analyst submits raw threat advisory text or selects a pre-loaded threat narrative.
2. **Hybrid Retrieval**: The engine extracts explicit MITRE IDs (`Txxxx`) and simultaneously executes semantic vector search via `pgvector` to identify unlabelled attack patterns.
3. **Cross-Encoder Reranking**: Jina AI cross-encoder (`jina-reranker-v2-base-multilingual`) scores candidate techniques and countermeasures, keeping `vector_score` and `rerank_score` strictly independent.
4. **Grounded Synthesis**: The LLM generates a structured report following strict Pydantic schemas, with fallback handling if quota or connectivity limits are reached.
5. **Taxonomy & Citation Verification**: Every citation and technique ID is verified against authoritative PostgreSQL records (sub-techniques do not inherit validation automatically). In normal production mode, reports and traces are persisted to PostgreSQL. In evaluation mode (`evaluation_mode=True`), database writes and quota consumption are bypassed.

---

## 🔬 Three-Layer Evaluation & Observability Architecture

To ensure enterprise reliability, safety, and continuous regression detection, the platform implements a **three-layer evaluation architecture**:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   THREE-LAYER EVALUATION ARCHITECTURE                  │
├────────────────────────────────┬───────────────────────────────────────┤
│ Layer 1: Deterministic Metrics │ • Precision@5 and Recall@5            │
│ (Golden Dataset: 35 Cases)     │ • Explicit ATT&CK ID vs Semantic split│
│                                │ • Missing & unexpected ID detection   │
├────────────────────────────────┼───────────────────────────────────────┤
│ Layer 2: RAGAS Agentic RAG     │ • Context Precision & Context Recall  │
│ (Collections API: ragas 0.4.4) │ • Faithfulness (excludes fallbacks)   │
│                                │ • Answer Relevancy & Factual Correct  │
│                                │ • Explicit empty-context handling     │
├────────────────────────────────┼───────────────────────────────────────┤
│ Layer 3: Langfuse v3+ Realtime │ • Distributed trace instrumentation   │
│ Observability & Telemetry      │ • Vector similarity & rerank scores   │
│                                │ • Sensitive metadata masking          │
└────────────────────────────────┴───────────────────────────────────────┘
```

### 1. Golden Evaluation Dataset
- Located at [`backend/evaluation/datasets/itdr_eval.jsonl`](backend/evaluation/datasets/itdr_eval.jsonl).
- Contains **35 curated enterprise ITDR test cases** covering Kerberoasting, AS-REP Roasting, DCSync, Token Theft, Pass-the-Hash, MFA Bypass, Out-of-Scope narratives, and Insufficient Evidence queries.
- Versioned as `v2.0.0`.

### 2. Evaluator Components
- **Deterministic Retrieval Metrics** ([`backend/evaluation/retrieval_metrics.py`](backend/evaluation/retrieval_metrics.py)): Computes `Precision@K` and `Recall@K` across ATT&CK and D3FEND IDs, segmenting explicit queries from purely semantic descriptions.
- **RAGAS Evaluator** ([`backend/evaluation/ragas_evaluator.py`](backend/evaluation/ragas_evaluator.py)): Built using the modern collections-based API (`ragas.metrics.collections`). Evaluates:
  - `ContextPrecision`: Measures signal-to-noise ratio in retrieved context.
  - `ContextRecall`: Measures whether retrieved context contains all reference facts.
  - `Faithfulness`: Verifies every claim in the report is grounded in retrieved evidence (fallback responses excluded).
  - `AnswerRelevancy`: Evaluates relevance to the user's input query.
  - `FactualCorrectness`: Compares factual assertions against reference answers.
  - Configured with `max_tokens=600`, exponential backoff on HTTP 429 rate limits, and inter-sample pacing.
- **Regression Monitor**: Compares current runs against an approved baseline with a configurable tolerance (default: 10%). Evaluates to four clear statuses:
  - `PASSED`: All metrics meet or exceed baseline within tolerance.
  - `FAILED`: One or more metrics dropped beyond allowed tolerance.
  - `NOT_BASELINED`: No approved baseline found; flags that baseline generation requires manual review.
  - `EVALUATION_ERROR`: Technical failure prevented evaluation (cannot exit CI with success).

---

## ✨ Features

### SOC Dashboard Views
1. **Identity Resilience Dashboard** — Coverage KPIs, tactic exposure, resilience radar charts, and potential blind spots.
2. **ITDR Coverage Matrix** — Identity vs enterprise views, filters, mapped detection rules, and technique details.
3. **Identity Threat Exposure** — Techniques grouped by attack phase and coverage status.
4. **Identity Threat Scenarios** — Multi-stage threat scenario walkthroughs and resilience indicators.
5. **Threat Intelligence Feeds** — Bulletin ingestion and automated threat advisory parsing (RBAC: `feeds:ingest`).
6. **Threat Modeling Workspace** — Advisory input, model selection, workflow traces, structured reports, and citations (RBAC: `threats:analyze`).
7. **Completed Intelligence Reports** — Historical reports, detailed findings, and JSON/Markdown export.
8. **Identity Governance & Access (Admin)** — User provisioning, role assignments, account deactivation, and security audit trail.

### Enterprise Security & Governance
- **Zero-Trust Default-Deny**: All operational API endpoints require authenticated sessions and verified permissions.
- **Enterprise Password Authentication**: Argon2id password hashing with timing-attack resistant dummy calculations and sliding window rate limiting.
- **Social Login / Single Sign-On**: Google OpenID Connect (OIDC with RFC 7636 PKCE S256) and GitHub OAuth 2.0 with verified primary email enforcement.
- **Server-Managed Session Store**: Stateful sessions in Neon PostgreSQL (`user_sessions` with SHA-256 token hashing), `HttpOnly` + `Secure` + `SameSite=Lax` cookies, sliding inactivity expiration (30 mins), and absolute expiration (12 hrs).
- **HMAC CSRF Defense**: Double-submit cookie + HMAC-SHA256 signed CSRF tokens on all mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
- **3-Tier RBAC**: `Admin` (full access & governance), `Security Analyst` (threat modeling & feeds), and `Viewer` (read-only dashboards).
- **Immutable Security Audit Trail**: Comprehensive logging of logins, throttles, identity linkages, and administrative events in `audit_logs`.
- **Dedicated Read-Only Evaluation Role**: Safe evaluation execution via `itdr_eval_readonly` with SELECT permissions only.

---

## 🛠️ Technology Stack

| Layer | Technology | Role |
| :--- | :--- | :--- |
| **Frontend UI** | React 18, Vite, Lucide React, Recharts | Responsive SOC analyst dashboard with mobile drawer |
| **Frontend Hosting** | Vercel | Global Edge CDN hosting for Single Page Application |
| **API Backend** | Python 3.12, FastAPI, Pydantic v2 | High-concurrency REST endpoints and schema validation |
| **Backend Hosting** | Render Web Service | Cloud container runtime for FastAPI backend |
| **AI Orchestration** | LangGraph, LangChain | Stateful multi-stage AI reasoning workflow & execution trace |
| **LLM Inference** | Groq (`qwen/qwen3.8-27b`, `openai/gpt-oss-120b`) / xAI (`grok-4.7`) | High-speed structured security report generation |
| **Embeddings & Reranking** | Jina AI (`jina-embeddings-v3`, `jina-reranker-v2-base-multilingual`) | 384-dim vector embeddings and cross-encoder reranker |
| **Relational Database** | Neon Serverless PostgreSQL 16 | Relational storage for 868 ATT&CK, 466 D3FEND, rules & reports |
| **Vector Store** | `pgvector` extension | High-performance cosine distance similarity search |
| **RAG Evaluation** | RAGAS (v0.4.4 Collections API) | Context Precision, Context Recall, Faithfulness, Relevancy |
| **Observability** | Langfuse v3+ | Real-time distributed traces, span scoring, and latency telemetry |
| **Testing** | pytest, pytest-asyncio | Full backend unit, integration, and evaluation test suite |

---

## 📂 Repository Structure

```text
ITDR_RAG_Dashboard/
├── .github/
│   └── workflows/
│       ├── ci.yml                     # Backend CI: 115 tests + RAGAS smoke check (SQLite in-memory)
│       ├── production-eval.yml        # Production evaluation gate (requires PROD_READONLY_DATABASE_URL)
│       └── keep-alive.yml             # Periodic endpoint health ping
├── backend/
│   ├── alembic/                       # Database migrations
│   ├── app/
│   │   ├── ai/                        # LangGraph threat analysis graph, nodes, and schemas
│   │   │   ├── nodes/                 # Extraction, retrieval, rerank, synthesis, validation nodes
│   │   │   └── graph.py               # Compiled StateGraph workflow
│   │   ├── api/                       # FastAPI route endpoints (auth, threats, reports, system)
│   │   ├── core/                      # Configuration, settings, security & CORS
│   │   ├── db/                        # SQLAlchemy engine, session, and SQLite/PostgreSQL compatibility
│   │   ├── models/                    # ORM models (ATT&CK, D3FEND, rules, users, sessions, audit)
│   │   └── services/                  # Retrieval, embeddings, reranker, telemetry, auth services
│   ├── data/                          # Source datasets (enterprise-attack.json, d3fend.json)
│   ├── evaluation/                    # 3-Layer Evaluation Architecture
│   │   ├── datasets/                  # Golden dataset (itdr_eval.jsonl, 35 cases)
│   │   ├── results/                   # JSON and CSV evaluation reports
│   │   ├── ragas_evaluator.py         # RAGAS collections API wrapper with rate-limit backoff
│   │   ├── retrieval_metrics.py       # Precision@K and Recall@K calculation
│   │   ├── run_evaluation.py          # Complete evaluation runner and regression checker
│   │   └── baseline.json              # Approved regression baseline (when generated)
│   ├── scripts/                       # Knowledge base sync and seed utilities
│   ├── tests/                         # Complete backend test suite (115 tests)
│   ├── requirements.txt               # Production dependencies
│   ├── requirements-eval.txt          # Pinned evaluation dependencies (ragas==0.4.4)
│   └── .env.example                   # Environment configuration template
├── frontend/
│   ├── src/
│   │   ├── api/client.js              # Shared API client with CSRF and credentials
│   │   ├── components/                # Reusable UI cards, tables, modals, mobile drawer
│   │   ├── context/                   # Global auth and filter context
│   │   └── screens/                   # 8 SOC Dashboard screens
│   ├── package.json
│   └── vite.config.js
└── README.md
```

---

## ⚙️ Prerequisites

- **Python 3.12**
- **Node.js 18+** and npm
- **Neon PostgreSQL** database with `pgvector` extension enabled
- **Groq API Key** (or xAI API key) for LLM report synthesis and RAGAS evaluation
- **Jina AI API Key** for embeddings and cross-encoder reranking

---

## 🔧 Configuration

Create the backend environment file:

```bash
cp backend/.env.example backend/.env
```

Configure the following essential environment variables:

```dotenv
APP_ENV=development
LOG_LEVEL=INFO
DEMO_MODE=true

# Database: Neon PostgreSQL connection string (sslmode=require)
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@YOUR-NEON-HOST/neondb?sslmode=require

# Dedicated read-only database user for safe evaluation (SELECT-only)
PROD_READONLY_DATABASE_URL=postgresql+psycopg://itdr_eval_readonly:PASSWORD@YOUR-NEON-HOST/neondb?sslmode=require

# LLM Providers (Groq / xAI)
GROQ_API_KEY=gsk_your_groq_api_key
GROQ_API_KEY_NEW_FOR_TESTING=gsk_your_testing_key
EVALUATOR_LLM_MODEL=qwen/qwen3.8-27b
XAI_MODEL=qwen/qwen3.8-27b
XAI_API_BASE=https://api.groq.com/openai/v1

# Jina AI Embeddings & Reranker
JINA_API_KEY=jina_your_jina_key
JINA_EMBEDDING_MODEL=jina-embeddings-v3
JINA_RERANK_MODEL=jina-reranker-v2-base-multilingual
RERANK_ENABLED=true
EMBEDDING_DIMENSIONS=384

# Langfuse Observability (Optional)
LANGFUSE_PUBLIC_KEY=pk-lf-your_public_key
LANGFUSE_SECRET_KEY=sk-lf-your_secret_key
LANGFUSE_HOST=https://cloud.langfuse.com
LANGFUSE_ENABLED=true
```

---

## 💻 Run Locally

### 1. Backend Setup

```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-eval.txt
```

### 2. Apply Database Migrations

Enable the `vector` extension in Neon SQL editor:
```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

Run Alembic migrations:
```bash
alembic upgrade head
```

### 3. Initialize Knowledge Base & Seed Demo Data

```bash
python scripts/sync_attack.py
python scripts/sync_d3fend.py
python scripts/seed_demo_data.py
python scripts/build_rag_index.py
```

### 4. Start FastAPI Backend

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Gateway: <http://127.0.0.1:8000>
- Swagger Docs: <http://127.0.0.1:8000/docs>
- Health Check: <http://127.0.0.1:8000/health>

### 5. Start React Frontend

In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```
Dashboard will be available at <http://127.0.0.1:5173>.

---

## 🧪 Run Tests

Execute the complete backend test suite:

```bash
cd backend
source .venv/bin/activate
DATABASE_URL="sqlite:///:memory:" pytest tests/ -v
```

This runs all **115 automated tests** across authentication, RBAC, session management, CSRF defense, MITRE ingestion, hybrid retrieval, cross-encoder reranking, LangGraph state transitions, Langfuse telemetry masking, and RAGAS collections evaluation.

---

## 📊 Run the Evaluation Pipeline

To execute the complete 3-layer evaluation suite against the 35-case golden dataset:

```bash
cd backend
source .venv/bin/activate

python -m evaluation.run_evaluation \
  --dataset evaluation/datasets/itdr_eval.jsonl \
  --baseline evaluation/baseline.json \
  --output-dir evaluation/results
```

### Safety & Isolation Guarantees
- **`evaluation_mode=True`**: Threat analysis nodes bypass report persistence and quota consumption.
- **Dedicated Read-Only Role**: Connects using `PROD_READONLY_DATABASE_URL` (`itdr_eval_readonly`), which strictly forbids `INSERT`, `UPDATE`, `DELETE`, or DDL commands.
- **Strict Isolation**: Retrieval metrics and generation metrics remain decoupled; empty contexts receive explicit 0.0 penalties without placeholder strings.

### Generating or Updating the Approved Baseline
Once evaluation results have been reviewed and approved, generate the baseline file:

```bash
python -m evaluation.run_evaluation \
  --dataset evaluation/datasets/itdr_eval.jsonl \
  --baseline evaluation/baseline.json \
  --generate-baseline
```
*Note: Guardrails prevent generating a baseline if any RAGAS metric returned `null` or failed.*

---

## 🔄 CI/CD & GitHub Actions Workflows

The repository includes two distinct GitHub Actions workflows:

### 1. Backend CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
- **Triggers**: Pull requests and pushes to `main` and `feature/**` branches.
- **Scope**:
  - Installs dependencies from `requirements.txt` and `requirements-eval.txt`.
  - Runs the RAGAS collections import and metric initialization smoke test.
  - Executes all 115 tests using in-memory SQLite (`StaticPool`).
- **Security**: **Does not require production database credentials**. Supports `GROQ_API_KEY_NEW_FOR_TESTING` or falls back to mock credentials for PR verification.

### 2. Production Evaluation & Regression Gate ([`.github/workflows/production-eval.yml`](.github/workflows/production-eval.yml))
- **Triggers**: Weekly schedule (Sundays at 02:00 UTC) and manual `workflow_dispatch`.
- **Scope**:
  - Connects to production knowledge base via mandatory secret `PROD_READONLY_DATABASE_URL`.
  - Runs full 35-case evaluation with RAGAS metrics and regression checks against `baseline.json`.
  - Uploads JSON and CSV evaluation reports as 60-day GitHub artifacts.

---

## 🔒 Security & Database Permissions

### Dedicated PostgreSQL Read-Only Role
To configure the dedicated read-only role on Neon PostgreSQL for safe evaluation:

```sql
-- 1. Create the dedicated read-only user
CREATE ROLE itdr_eval_readonly WITH LOGIN PASSWORD 'YOUR_STRONG_PASSWORD';

-- 2. Grant connect and schema usage
GRANT CONNECT ON DATABASE neondb TO itdr_eval_readonly;
GRANT USAGE ON SCHEMA public TO itdr_eval_readonly;

-- 3. Grant SELECT privileges strictly on all tables
GRANT SELECT ON ALL TABLES IN SCHEMA public TO itdr_eval_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO itdr_eval_readonly;

-- 4. Verify that write privileges are completely absent:
-- Under NO circumstances grant INSERT, UPDATE, DELETE, TRUNCATE, or CREATE to this role.
```

---

## ☁️ Cloud Deployment Architecture

```text
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

### Backend on Render
1. Create a Web Service pointing to `backend/`.
2. Set build command: `pip install -r requirements.txt`.
3. Set start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
4. Configure environment variables (`DATABASE_URL`, `GROQ_API_KEY`, `JINA_API_KEY`, etc.).

### Frontend on Vercel
1. Import repository to Vercel with root directory `frontend/`.
2. Framework Preset: `Vite`.
3. Set environment variable `VITE_API_URL` to your Render API domain.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
MITRE ATT&CK® and MITRE D3FEND™ are registered trademarks of The MITRE Corporation.
