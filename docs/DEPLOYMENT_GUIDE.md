# ITDR Platform Production Deployment Guide

This guide details how to deploy the ITDR Platform to production using **Vercel** for the frontend and **Render / Railway** for the FastAPI backend.

---

## Architecture Overview

```
┌──────────────────────────────────────┐       ┌─────────────────────────────────────────┐
│           Vercel (Frontend)          │       │         Render / Railway (Backend)      │
│  - React 18 + Vite (SPA)             │       │  - Python 3.12 + FastAPI + Uvicorn      │
│  - Global CDN, Instant Edge Caching  │ ───►  │  - LangGraph 11-node Workflow           │
│  - Environment: VITE_API_URL         │ HTTP  │  - Jina AI Reranker + Groq LLM          │
└──────────────────────────────────────┘       └────────────────────┬────────────────────┘
                                                                    │ TLS (sslmode=require)
                                                                    ▼
                                                       ┌─────────────────────────┐
                                                       │   Neon Cloud PostgreSQL │
                                                       │  - Native pgvector(384) │
                                                       │  - 868 ATT&CK Techniques│
                                                       │  - 466 D3FEND Measures  │
                                                       └─────────────────────────┘
```

---

## Part 1: Deploying the Frontend to Vercel

### Option A: Using the Vercel Web Dashboard (Recommended)

1. **Push your code to GitHub / GitLab**.
2. Go to [vercel.com](https://vercel.com) and click **"Add New Project"**.
3. Import your GitHub repository.
4. In the **Configure Project** screen:
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click `Edit` and select `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`
5. **Environment Variables**:
   Add the following variable:
   - `VITE_API_URL`: Your deployed backend URL (e.g. `https://itdr-api.onrender.com`).
     *(Note: If left empty, requests default to the same origin `/api`)*.
6. Click **Deploy**. Vercel will build the frontend and provide your live URL (e.g., `https://itdr-platform.vercel.app`).

### Option B: Using the Vercel CLI

```bash
# 1. Install Vercel CLI
npm install -g vercel

# 2. Deploy from the frontend directory
cd frontend
vercel

# Follow prompts:
# ? Set up and deploy? Yes
# ? Which scope? (your account)
# ? Link to existing project? No
# ? What's your project's name? itdr-platform
# ? In which directory is your code located? ./
```

---

## Part 2: Deploying the Backend (Render / Railway / Koyeb)

Since our backend runs a long-running, stateful LangGraph threat modeling workflow with Groq LLM synthesis, a persistent Python container without 10-second serverless execution limits is required.

### Deploying on Render (Free / Web Service)

1. Go to [render.com](https://render.com) and click **New +** -> **Web Service**.
2. Connect your GitHub repository.
3. Configure the service:
   - **Name**: `itdr-platform-api`
   - **Region**: Oregon or Frankfurt (pick closest to your Neon DB region)
   - **Root Directory**: `backend`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. In **Environment Variables**, add:
   ```env
   APP_ENV=production
   DEMO_MODE=false
   DATABASE_URL=postgresql+psycopg://YOUR_NEON_CONNECTION_STRING?sslmode=require
   
   # LLM Provider (Groq or xAI)
   XAI_API_KEY=gsk_your_groq_api_key_here
   XAI_API_BASE=https://api.groq.com/openai/v1
   XAI_MODEL=qwen/qwen3.8-27b
   
   # Embeddings & Reranker Provider (Jina AI)
   JINA_API_KEY=jina_your_api_key_here
   JINA_EMBEDDING_MODEL=jina-embeddings-v5-text-small
   JINA_RERANK_MODEL=jina-reranker-v2-base-multilingual
   RERANK_ENABLED=true
   EMBEDDING_DIMENSIONS=384
   ```
5. Click **Create Web Service**. Once deployed, copy your Render URL (e.g., `https://itdr-api.onrender.com`).

---

## Part 3: Connecting Frontend and Backend

Once the backend is live on Render/Railway:
1. Go back to your **Vercel Project Dashboard** -> **Settings** -> **Environment Variables**.
2. Set `VITE_API_URL` to your backend URL (e.g. `https://itdr-api.onrender.com`).
3. Click **Redeploy** on Vercel.

---

## Part 4: Verification Checklist

| Check | URL / Command | Expected Result |
| :--- | :--- | :--- |
| **Backend Health** | `GET https://itdr-api.../health` | `{"status": "healthy"}` |
| **System Telemetry** | `GET https://itdr-api.../api/system/status` | DB: `Online`, pgvector: `Enabled`, Reranker: `Online` |
| **Frontend UI** | `https://itdr-platform.vercel.app` | Dashboard loads with KPIs and active coverage ring |
| **Threat Modeling** | Submit sample in Workspace | Generates grounded report with citations and trace |
