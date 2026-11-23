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
- **LangGraph**: 11-node stateful workflow for explainable, grounded security advisory analysis with conditional guardrail routing:
  - Input Screening: Direct prompt injection & jailbreak detection (`screen_input_for_injection`)
  - Context Screening: Indirect injection detection with dynamic chunk quarantine (`screen_retrieved_context`)
  - Output Safety: Secret & credential leak prevention, destructive payload blocking (`validate_output_safety`)
  - Fail-Closed Routing: Safe diversion of flagged inputs/outputs to security analyst review (`handle_security_review`)
- **Neon Cloud PostgreSQL + pgvector**: Vectorized knowledge base with 868 ATT&CK techniques, 466 D3FEND countermeasures, and native 384-dimensional cosine similarity search.
- **Calibrated Semantic Retrieval & Evidence Gating**:
  - Cosine distance filtering (`RETRIEVAL_MIN_SIMILARITY_THRESHOLD=0.55`, `RETRIEVAL_MIN_D3FEND_SCORE=0.35`)
  - Cross-encoder rerank admission gating (`RETRIEVAL_MIN_RERANK_THRESHOLD=0.20`)
  - Hard evidence gating achieving **0.0% False Positive Rate** on benign queries.
- **Jina AI**:
  - `jina-embeddings-v3` (384-dim dense embeddings)
  - `jina-reranker-v2-base-multilingual` (Cross-encoder deep attention reranking)
- **Groq LLM**: `qwen/qwen3.8-27b` structured reasoning with strict MITRE citation verification and offline fallback resilience.
- **Comprehensive Test Suite**: 186 automated tests across unit, integration, retrieval, and guardrail workflows.

## Four-Tier Evaluation Suite
- **Tier 1 (Quality & RAGAS)**: `python -m evaluation.run_evaluation --dataset evaluation/datasets/itdr_eval.jsonl`
- **Tier 2 (AI Security - Mock)**: `python -m evaluation.run_security_evaluation --dataset evaluation/datasets/itdr_security_eval.jsonl`
- **Tier 2 (AI Security - Live)**: `python -m evaluation.run_security_evaluation --dataset evaluation/datasets/itdr_security_eval.jsonl --live-llm`
- **Tier 3 (Live pgvector Retrieval)**: `python -m evaluation.run_retrieval_evaluation --dataset evaluation/datasets/itdr_retrieval_eval.jsonl --max-negative-fpr 0.0`
- **Tier 4 (Observability)**: Langfuse v3+ distributed tracing with sensitive credential masking.

## API Documentation
- Interactive Swagger UI: [`/docs`](/docs)
- Alternative ReDoc: [`/redoc`](/redoc)
- Health Probe: [`/health`](/health)
- Telemetry & Subsystems: [`/api/system/status`](/api/system/status)
