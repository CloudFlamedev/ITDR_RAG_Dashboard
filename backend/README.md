---
title: ITDR Platform Backend API
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# ITDR Platform Backend API (FastAPI + LangGraph + Jina AI + Neon pgvector)

High-performance Identity Threat Detection & Response (ITDR) backend API powering explainable threat modeling, MITRE ATT&CK & D3FEND retrieval, and Groq LLM threat analysis.

## Subsystems & Features
- **FastAPI**: Asynchronous high-throughput REST API with interactive Swagger docs at `/docs`.
- **LangGraph**: 11-node stateful workflow for explainable, grounded security advisory analysis.
- **Neon Cloud PostgreSQL + pgvector**: Vectorized knowledge base with 868 techniques, 466 D3FEND countermeasures, and native 384-dimensional cosine similarity search.
- **Jina AI**:
  - `jina-embeddings-v5-text-small` (384-dim dense embeddings)
  - `jina-reranker-v2-base-multilingual` (Cross-encoder deep attention reranking)
- **Groq LLM**: `qwen/qwen3.8-27b` structured reasoning with strict MITRE citation verification.

## API Documentation
- Interactive Swagger UI: [`/docs`](/docs)
- Alternative ReDoc: [`/redoc`](/redoc)
- Health Probe: [`/health`](/health)
- Telemetry & Subsystems: [`/api/system/status`](/api/system/status)
